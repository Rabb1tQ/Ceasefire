<template>
  <div class="network-activity">
    <!-- 服务连接横幅：轮询失败静默刷新时，只在顶部提示一次，不弹 toast 刷屏 -->
    <el-alert
      v-if="!serviceConnected"
      title="服务未连接"
      type="error"
      :description="serviceError || '无法连接到 Ceasefire 服务，列表数据可能已过期。'"
      show-icon
      :closable="false"
      class="service-alert"
    />
    <div class="header">
      <h1>网络活动</h1>
      <div class="header-actions">
        <!--
          统计口径说明：
          - 主视图（进程列表）始终以 network_history 表的 DB 聚合（get_app_traffic_stats，按 hours 窗口）
            为权威口径；连接跟踪器中"尚未落入 DB 聚合"的进程会并入列表（仅补充条目，
            不修改 DB 聚合出的流量/连接数数值），即跟踪器数据只做增量展示。
          - 下钻层：连接记录，来自 network_history（get_network_history + HistoryFilters 服务端
            分页/筛选，按 process_path 过滤，绝不在前端全量拉取后自行分页）。驱动事件落库无缓冲，
            历史记录天然秒级新鲜，打开期间每 5 秒轮询刷新当前页。
        -->
        <el-button
          v-for="h in [1, 6, 24, 168]"
          :key="h"
          :type="statsHours === h ? 'primary' : ''"
          size="default"
          style="margin-right: 4px"
          @click="setStatsHours(h)"
        >
          {{ h === 1 ? '1小时' : h === 6 ? '6小时' : h === 24 ? '24小时' : '7天' }}
        </el-button>
        <el-input
          v-model="searchText"
          placeholder="搜索进程名称或路径"
          clearable
          style="width: 220px; margin-right: 8px"
          size="default"
        />
        <el-select v-model="filterAction" placeholder="行为筛选" clearable style="width: 120px; margin-right: 12px" size="default">
          <el-option label="允许" value="Allow" />
          <el-option label="阻止" value="Block" />
          <el-option label="无规则" value="None" />
        </el-select>
        <el-button @click="loadProcesses()" :loading="loading">刷新</el-button>
      </div>
    </div>

    <!-- 主视图：进程级聚合（口径 = DB 聚合，见文件顶部注释） -->
    <el-table
      :data="paginatedProcesses"
      stripe
      style="width: 100%"
      :height="tableHeight"
      :default-sort="{ prop: '_downBps', order: 'descending' }"
      highlight-current-row
      @row-click="handleRowClick"
      @row-dblclick="handleRowDoubleClick"
      @row-contextmenu="handleRowContextMenu"
    >
      <el-table-column prop="process_name" label="进程" min-width="260" sortable>
        <template #default="{ row }">
          <div class="process-cell">
            <div class="process-main">
              <el-icon v-if="row.action === 'Block'" color="#f56c6c"><CircleClose /></el-icon>
              <el-icon v-else-if="row.action === 'Allow'" color="#67c23a"><CircleCheck /></el-icon>
              <el-icon v-else color="#909399"><QuestionFilled /></el-icon>
              <span :title="row.process_name">{{ row.process_name || '未知进程' }}</span>
              <el-tag v-if="row.action === 'Allow'" type="success" size="small">允许</el-tag>
              <el-tag v-else-if="row.action === 'Block'" type="danger" size="small">阻止</el-tag>
              <el-tag v-else type="info" size="small">无规则</el-tag>
              <el-tag v-if="row.liveOnly" type="warning" size="small">实时新增</el-tag>
            </div>
            <div class="process-sub mono truncate" :title="row.process_path">{{ row.process_path }}</div>
          </div>
        </template>
      </el-table-column>
      <el-table-column
        prop="_downBps"
        label="↓ 速度"
        width="110"
        sortable
        :sort-method="(a: any, b: any) => a._downBps - b._downBps"
      >
        <template #default="{ row }">{{ formatSpeed(row._downBps) }}</template>
      </el-table-column>
      <el-table-column
        prop="_upBps"
        label="↑ 速度"
        width="110"
        sortable
        :sort-method="(a: any, b: any) => a._upBps - b._upBps"
      >
        <template #default="{ row }">{{ formatSpeed(row._upBps) }}</template>
      </el-table-column>
      <el-table-column
        prop="bytes_received"
        label="下载"
        width="110"
        sortable
        :sort-method="(a: any, b: any) => a.bytes_received - b.bytes_received"
      >
        <template #default="{ row }">{{ formatBytes(row.bytes_received) }}</template>
      </el-table-column>
      <el-table-column
        prop="bytes_sent"
        label="上传"
        width="110"
        sortable
        :sort-method="(a: any, b: any) => a.bytes_sent - b.bytes_sent"
      >
        <template #default="{ row }">{{ formatBytes(row.bytes_sent) }}</template>
      </el-table-column>
      <el-table-column prop="connection_count" label="连接数" width="100" sortable />
      <el-table-column prop="last_seen" label="最后活动" width="180" sortable>
        <template #default="{ row }">{{ formatTimestamp(row.last_seen) }}</template>
      </el-table-column>
    </el-table>

    <el-pagination
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :total="filteredProcesses.length"
      :page-sizes="[10, 20, 50, 100]"
      layout="total, sizes, prev, pager, next, jumper"
      style="margin-top: 16px; justify-content: center"
    />

    <!-- 下钻：选中进程的连接记录（network_history，打开期间自动轮询刷新当前页） -->
    <el-drawer
      v-model="drawerVisible"
      :title="drawerTitle"
      size="70%"
      :destroy-on-close="true"
      @closed="stopDrawerPolling"
    >
      <div class="drawer-toolbar">
        <el-select
          v-model="historyFilters.action"
          placeholder="动作"
          clearable
          style="width: 110px; margin-right: 8px"
          @change="reloadDrawer"
        >
          <el-option label="允许" value="Allow" />
          <el-option label="阻止" value="Block" />
        </el-select>
        <el-select
          v-model="historyFilters.protocol"
          placeholder="协议"
          clearable
          style="width: 110px; margin-right: 8px"
          @change="reloadDrawer"
        >
          <el-option label="TCP" value="Tcp" />
          <el-option label="UDP" value="Udp" />
          <el-option label="ICMP" value="Icmp" />
        </el-select>
        <el-select
          v-model="historyFilters.direction"
          placeholder="方向"
          clearable
          style="width: 110px; margin-right: 8px"
          @change="reloadDrawer"
        >
          <el-option label="入站" value="Inbound" />
          <el-option label="出站" value="Outbound" />
        </el-select>
        <el-button size="default" style="margin-right: 4px" @click="exportHistory" :disabled="drawerLoading">导出</el-button>
      </div>

      <!--
        服务端排序 + 服务端分页（Element Plus 标准模式）：列 sortable="custom"，
        @sort-change 把 prop/order 写进 historyFilters 下发（白名单见服务端
        get_network_history），排序变化重置回第 1 页。表格常驻 + v-loading，
        不再 v-if 整表销毁重建（那会丢失排序状态、轮询时闪烁）。
        default-sort(timestamp desc) 与服务端默认（sort_by 缺省 → timestamp DESC）一致。
      -->
      <el-table
        v-loading="drawerLoading"
        :data="drawerHistory"
        stripe
        size="small"
        :default-sort="{ prop: 'timestamp', order: 'descending' }"
        @sort-change="handleDrawerSortChange"
      >
        <el-table-column prop="timestamp" label="时间" width="170" sortable="custom">
          <template #default="{ row }">{{ formatTimestamp(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="action" label="动作" width="80">
          <template #default="{ row }">
            <el-tag :type="row.action === 'Allow' ? 'success' : 'danger'" size="small">
              {{ row.action === 'Allow' ? '允许' : '阻止' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="direction" label="方向" width="80" />
        <el-table-column prop="remote_addr" label="远程地址" min-width="180" sortable="custom">
          <template #default="{ row }">
            <span class="mono">{{ row.remote_addr }}:{{ row.remote_port }}</span>
            <el-tag v-if="onlineIps.has(row.remote_addr)" type="success" size="small" style="margin-left: 6px">在线</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="域名" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">{{ domains[row.remote_addr] || '-' }}</template>
        </el-table-column>
        <el-table-column prop="bytes_sent" label="上传" width="100" sortable="custom">
          <template #default="{ row }">{{ formatBytes(row.bytes_sent) }}</template>
        </el-table-column>
        <el-table-column prop="bytes_received" label="下载" width="100" sortable="custom">
          <template #default="{ row }">{{ formatBytes(row.bytes_received) }}</template>
        </el-table-column>
        <el-table-column prop="rule_id" label="规则ID" width="80">
          <template #default="{ row }">{{ row.rule_id || '-' }}</template>
        </el-table-column>
      </el-table>
      <div v-if="!drawerLoading && drawerHistory.length === 0" class="empty-state">该进程暂无连接记录</div>
      <!--
        服务端分页：每页请求 pageSize 条（多取 1 条探测 hasMore），total 无法从
        GetNetworkHistory 精确获得，用 offset+已取条数(+1页) 估算以保证"下一页"
        可用性，这是无 count 接口下的常见做法，不是全量拉取。
        轮询刷新时保留当前页码，只更新当前页数据。
      -->
      <el-pagination
        v-model:current-page="historyPage"
        v-model:page-size="historyPageSize"
        :total="historyTotal"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next, jumper"
        style="margin-top: 12px; justify-content: center"
        @current-change="loadDrawerData"
        @size-change="handleHistoryPageSizeChange"
      />
    </el-drawer>

    <!-- 右键菜单 -->
    <teleport to="body">
      <div
        ref="contextMenuRef"
        v-show="contextMenuVisible"
        class="context-menu"
        :style="{ left: contextMenuPosition.x + 'px', top: contextMenuPosition.y + 'px' }"
        @click.stop
      >
        <div class="context-menu-item" @click="handleAllow" v-if="selectedProcess?.action !== 'Allow'">
          <el-icon><CircleCheck /></el-icon>
          <span>允许</span>
        </div>
        <div class="context-menu-item" @click="handleBlock" v-if="selectedProcess?.action !== 'Block'">
          <el-icon><CircleClose /></el-icon>
          <span>阻止</span>
        </div>
        <div class="context-menu-divider" v-if="selectedProcess?.action !== 'None'"></div>
        <div class="context-menu-item" @click="handleRemoveRule" v-if="selectedProcess?.action !== 'None'">
          <el-icon><Delete /></el-icon>
          <span>删除规则</span>
        </div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" @click="handleKillProcess">
          <el-icon><Close /></el-icon>
          <span>终止进程</span>
        </div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" @click="handleAddToGroup">
          <el-icon><FolderAdd /></el-icon>
          <span>添加到应用分组</span>
        </div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" @click="handleCopyPath">
          <el-icon><DocumentCopy /></el-icon>
          <span>复制路径</span>
        </div>
        <div class="context-menu-item" @click="handleOpenFolder">
          <el-icon><Folder /></el-icon>
          <span>打开文件夹</span>
        </div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" @click="handleViewDetails">
          <el-icon><View /></el-icon>
          <span>查看详情</span>
        </div>
      </div>
    </teleport>

    <!-- 进程详情对话框 -->
    <el-dialog
      v-model="detailsDialogVisible"
      :title="`进程详情 - ${selectedProcess?.process_name || '未知'}`"
      width="80%"
      top="5vh"
    >
      <ProcessDetails v-if="selectedProcess" :key="selectedProcess.process_path" :process="selectedProcess" />
    </el-dialog>

    <!-- 添加到应用分组对话框 -->
    <el-dialog v-model="addToGroupDialogVisible" title="添加到应用分组" width="500px">
      <el-form label-width="100px">
        <el-form-item label="选择分组">
          <el-select v-model="selectedGroupId" placeholder="请选择应用分组" style="width: 100%">
            <el-option v-for="group in appGroups" :key="group.id" :label="group.name" :value="group.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addToGroupDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="confirmAddToGroup">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, nextTick, watch } from 'vue'
import { useRoute } from 'vue-router'
import { invoke } from '@tauri-apps/api/core'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  CircleCheck,
  CircleClose,
  QuestionFilled,
  Delete,
  Close,
  FolderAdd,
  DocumentCopy,
  Folder,
  View
} from '@element-plus/icons-vue'
import ProcessDetails from '../components/ProcessDetails.vue'
import { normalizePathForCompare } from '../utils/path'

interface ProcessInfo {
  process_name: string
  process_path: string
  process_id?: number
  action: 'Allow' | 'Block' | 'None'
  rule_id?: number
  connection_count: number
  bytes_sent: number
  bytes_received: number
  first_seen: string
  last_seen: string
  /** 该进程来自连接跟踪器，尚未出现在 DB 聚合中 */
  liveOnly?: boolean
  /** 前端派生：下载/上传速率（B/s），仅用于展示与排序，不参与搜索/行为筛选 */
  _downBps?: number
  _upBps?: number
}

interface AppGroup {
  id: number
  name: string
  description: string
  enabled: boolean
}

// 与 RuleManager.vue 的 Rule 形状保持一致（此处只读 action/id/process_path
// 做徽标匹配，其余字段收窄为可选以兼容后端 serde 序列化）
interface Rule {
  id?: number
  name: string
  action: 'Allow' | 'Block'
  process_path?: string | null
}

interface RulePage {
  total: number
  rules: Rule[]
}

interface Connection {
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  protocol: string
  process_id?: number
  process_name?: string
  process_path?: string
  direction: string
  bytes_sent: number
  bytes_received: number
  packets_sent: number
  packets_received: number
  state: string
  first_seen: string
  last_seen: string
}

interface HistoryFilters {
  limit?: number
  offset?: number
  hours?: number
  action?: string
  protocol?: string
  process_path?: string
  remote_addr?: string
  direction?: string
  /** 服务端排序字段（白名单：timestamp/bytes_sent/bytes_received/remote_addr/process_name） */
  sort_by?: string
  /** 服务端排序方向：ascending / descending */
  sort_order?: 'ascending' | 'descending'
}

interface NetworkHistoryRecord {
  id?: number
  timestamp: string
  action: 'Allow' | 'Block'
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  protocol: string
  direction: string
  process_id?: number
  process_name?: string
  process_path?: string
  bytes_sent: number
  bytes_received: number
  rule_id?: number
}

const processes = ref<ProcessInfo[]>([])
const loading = ref(false)
const searchText = ref('')
const filterAction = ref<string>('')
const currentPage = ref(1)
const pageSize = ref(10)
// 时间窗口：既驱动主列表聚合，也作为 hours 下发到抽屉的历史查询
const statsHours = ref(24)

const contextMenuVisible = ref(false)
const contextMenuPosition = ref({ x: 0, y: 0 })
const contextMenuRef = ref<HTMLElement | null>(null)
const selectedProcess = ref<ProcessInfo | null>(null)
const detailsDialogVisible = ref(false)
const addToGroupDialogVisible = ref(false)
const appGroups = ref<AppGroup[]>([])
const selectedGroupId = ref<number | null>(null)
const tableHeight = ref(600)
let refreshInterval: number | null = null

// ---- 下钻（drawer）状态 ----
const drawerVisible = ref(false)
const drawerLoading = ref(false)
const drawerHistory = ref<NetworkHistoryRecord[]>([])
const historyPage = ref(1)
const historyPageSize = ref(10)
const historyTotal = ref(0)
const historyFilters = ref<HistoryFilters>({
  action: undefined,
  protocol: undefined,
  direction: undefined
})
let drawerPollInterval: number | null = null

// 抽屉内远程地址当前仍在连接跟踪器里的 IP（"在线"角标）
const onlineIps = ref<Set<string>>(new Set())
// IP → 域名（来自服务端 DNS 缓存，随记录列表一起刷新）
const domains = ref<Record<string, string>>({})
// IP → 域名缓存，跨轮询复用。未命中（null）带时间戳做 30 秒短 TTL：
// DNS 缓存可能稍后才写入该映射，null 不应被永久缓存导致域名永远查不到。
interface DomainCacheEntry {
  domain: string | null
  cachedAt: number
}
const DOMAIN_MISS_TTL_MS = 30_000
const domainCache = new Map<string, DomainCacheEntry>()

const isCacheHit = (ip: string, now: number): boolean => {
  const entry = domainCache.get(ip)
  if (!entry) return false
  if (entry.domain === null) {
    return now - entry.cachedAt < DOMAIN_MISS_TTL_MS
  }
  return true
}

const filteredProcesses = computed(() => {
  let result = processes.value

  if (searchText.value) {
    const search = searchText.value.toLowerCase()
    result = result.filter(p =>
      p.process_name.toLowerCase().includes(search) ||
      p.process_path.toLowerCase().includes(search)
    )
  }

  if (filterAction.value) {
    result = result.filter(p => p.action === filterAction.value)
  }

  return result
})

const paginatedProcesses = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  const end = start + pageSize.value
  return filteredProcesses.value.slice(start, end)
})

// 搜索词/行为筛选变化后结果集变小，若停留在高页码切片会越界显示空表，
// 统一重置回第 1 页
watch([searchText, filterAction], () => {
  currentPage.value = 1
})

const drawerTitle = computed(() =>
  `连接记录 - ${selectedProcess.value?.process_name || '未知进程'}`
)

const formatBytes = (bytes: number): string => {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

const formatTimestamp = (timestamp?: string): string => {
  if (!timestamp) return '-'
  return new Date(timestamp).toLocaleString('zh-CN')
}

const formatSpeed = (bps?: number): string => {
  if (!bps || bps <= 0) return '0 B/s'
  const k = 1024
  const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s']
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bps) / Math.log(k)))
  return `${(bps / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

/**
 * 速率计算的上轮快照（模块级，key = process_path）。
 * 每次 loadProcesses 成功后用本次累计字节差 / 间隔秒数得出速率；
 * 进程首次出现（无上轮快照）速率为 0；累计字节回退（进程重启计数归零）
 * 时速率置 0，不显示负值。
 */
interface TrafficSnapshot {
  sent: number
  received: number
  t: number
}
const lastTrafficSnapshot = new Map<string, TrafficSnapshot>()

const attachRates = (list: ProcessInfo[]) => {
  const now = Date.now()
  const seen = new Set<string>()
  for (const p of list) {
    seen.add(p.process_path)
    const prev = lastTrafficSnapshot.get(p.process_path)
    if (prev) {
      const dt = (now - prev.t) / 1000
      if (dt > 0) {
        p._downBps = Math.max(0, (p.bytes_received - prev.received) / dt)
        p._upBps = Math.max(0, (p.bytes_sent - prev.sent) / dt)
      }
    }
    lastTrafficSnapshot.set(p.process_path, { sent: p.bytes_sent, received: p.bytes_received, t: now })
  }
  // 清掉已从列表消失的进程，避免快照无界增长
  for (const key of lastTrafficSnapshot.keys()) {
    if (!seen.has(key)) lastTrafficSnapshot.delete(key)
  }
}

// 请求序列号守卫：轮询 / 手动刷新 / 时间窗切换并发时，只有最新一次请求的
// 响应才允许写入页面状态，旧响应后到直接丢弃（避免时间窗切回后旧数据覆盖）
let loadProcessesRequestId = 0

// 服务连接状态：参照 Dashboard 的 serviceConnected 横幅做法。
// 轮询失败不弹 toast（服务一停会 10 秒一次无限刷屏），只更新横幅。
const serviceConnected = ref(true)
const serviceError = ref<string | null>(null)

/**
 * 主视图数据。
 * 权威口径始终是 get_app_traffic_stats（network_history 的 DB 聚合，窗口 statsHours）。
 * 额外拉取连接跟踪器，仅用于把"有活动连接但 DB 聚合还没覆盖"的进程
 * 并入列表（liveOnly 标记，数值列显示跟踪器当前值）；已出现在 DB 聚合中的进程
 * 不叠加跟踪器数值，避免双计。
 *
 * @param silent 轮询/自动刷新传 true：失败只更新顶部服务状态横幅，不弹 toast
 */
const loadProcesses = async (silent = false) => {
  const requestId = ++loadProcessesRequestId
  if (!silent) loading.value = true
  try {
    const stats = await invoke<any[]>('get_app_traffic_stats', { hours: statsHours.value })
    // list_rules 已改为分页签名 list_rules(offset, limit) 返回 RulePage；
    // 此处只需全量规则做进程徽标匹配，limit 取 u32::MAX 一次取完
    const rulePage = await invoke<RulePage>('list_rules', { offset: 0, limit: 4294967295, search: null })
    const rules = rulePage.rules
    if (requestId !== loadProcessesRequestId) return

    const result: ProcessInfo[] = stats.map(stat => {
      // 徽标比较用 utils/path.ts 的归一化（小写+反斜杠，与服务端同口径）：
      // 服务端规则路径与统计路径写法（大小写/分隔符）可能不同，严格相等
      // 会误标"无规则"。仅用于比较，不修改展示值。
      const statPath = normalizePathForCompare(stat.processPath)
      const rule = rules.find(r => normalizePathForCompare(r.process_path) === statPath)
      // 服务端 AppTrafficStats 以 camelCase 序列化，这里统一转成页面使用的 snake_case
      return {
        process_name: stat.processName,
        process_path: stat.processPath,
        process_id: stat.processId ?? undefined,
        action: rule ? rule.action : 'None',
        rule_id: rule?.id,
        connection_count: stat.connectionCount,
        bytes_sent: stat.bytesSent,
        bytes_received: stat.bytesReceived,
        // 来自服务端历史记录聚合的真实时间
        first_seen: stat.lastSeen || '',
        last_seen: stat.lastSeen || ''
      }
    })

    // 增量补充：只并入 DB 聚合中没有的进程，不修改已有进程的统计数值
    try {
      const conns = await invoke<Connection[]>('get_connections')
      if (requestId !== loadProcessesRequestId) return
      const known = new Set(result.map(p => p.process_path))
      const byPath = new Map<string, Connection[]>()
      for (const c of conns) {
        if (!c.process_path) continue
        const list = byPath.get(c.process_path) || []
        list.push(c)
        byPath.set(c.process_path, list)
      }
      for (const [path, list] of byPath) {
        if (known.has(path)) continue
        const first = list[0]
        if (!first) continue
        result.push({
          process_name: first.process_name || '未知进程',
          process_path: path,
          process_id: first.process_id,
          action: 'None',
          connection_count: list.length,
          bytes_sent: list.reduce((s, c) => s + c.bytes_sent, 0),
          bytes_received: list.reduce((s, c) => s + c.bytes_received, 0),
          first_seen: first.first_seen,
          last_seen: list.reduce((m, c) => (c.last_seen > m ? c.last_seen : m), first.last_seen),
          liveOnly: true
        })
      }
    } catch (error) {
      // 连接跟踪器失败不影响 DB 聚合主列表
      console.error('拉取实时连接失败:', error)
    }

    if (requestId !== loadProcessesRequestId) return
    attachRates(result)
    processes.value = result
    serviceConnected.value = true
    serviceError.value = null
  } catch (error) {
    if (requestId !== loadProcessesRequestId) return
    // 轮询失败静默：只更新顶部横幅；手动刷新（silent=false）才弹 toast
    serviceConnected.value = false
    serviceError.value = error?.toString() || 'Unknown error'
    console.error('加载进程列表失败:', error)
    if (!silent) {
      ElMessage.error('加载进程列表失败')
    }
  } finally {
    // 非 silent（手动刷新）请求无条件复位 loading：序列号守卫只用于数据
    // 写入判断——手动请求被后到的轮询顶掉序号时若再判 requestId，loading
    // 永远不会复位（卡死转圈）
    if (!silent) {
      loading.value = false
    }
  }
}

const setStatsHours = (hours: number) => {
  statsHours.value = hours
  // 抽屉历史查询的时间窗口跟随同一个 hours
  historyFilters.value.hours = hours
  loadProcesses()
  if (drawerVisible.value) reloadDrawer()
}

const loadAppGroups = async () => {
  try {
    appGroups.value = await invoke('list_app_groups')
  } catch (error) {
    console.error('加载应用分组失败:', error)
  }
}

// ---- 下钻 ----

const handleRowClick = (row: ProcessInfo) => {
  selectedProcess.value = row
  historyPage.value = 1
  drawerVisible.value = true
  reloadDrawer()
}

const reloadDrawer = () => {
  historyPage.value = 1
  loadDrawerData()
}

const handleHistoryPageSizeChange = () => {
  historyPage.value = 1
  loadDrawerData()
}

// 服务端排序（Element Plus standard：sortable="custom" + @sort-change）。
// 取消排序（order === null）时清空排序字段，回到默认 timestamp DESC；
// 排序变化一律重置回第 1 页。翻页/轮询自动携带当前排序。
const handleDrawerSortChange = ({ prop, order }: { prop: string; order: 'ascending' | 'descending' | null }) => {
  if (order === null) {
    historyFilters.value.sort_by = undefined
    historyFilters.value.sort_order = undefined
  } else {
    historyFilters.value.sort_by = prop
    historyFilters.value.sort_order = order
  }
  historyPage.value = 1
  loadDrawerData()
}

const loadDrawerData = async () => {
  if (!selectedProcess.value) return
  await loadDrawerHistory()
  refreshOnlineIps()
  // 打开期间 5 秒轮询：刷新当前页数据 + 在线角标，不重置页码
  stopDrawerPolling()
  drawerPollInterval = window.setInterval(pollDrawerData, 5000)
}

const pollDrawerData = async () => {
  await loadDrawerHistory(true)
  refreshOnlineIps()
}

// silent=true 供轮询使用：不触发 loading 态（表格常驻 + v-loading，静默刷新
// 不会闪 loading 遮罩，排序状态由服务端分页参数保留，不会被打断）
const loadDrawerHistory = async (silent = false) => {
  if (!selectedProcess.value) return
  // 抽屉竞态守卫：连点两个进程行时旧进程的响应可能后到。发起时记住
  // process_path，回来与当前选中进程不符则整个丢弃，不覆盖抽屉数据。
  const requestedPath = selectedProcess.value.process_path
  if (!silent) drawerLoading.value = true
  try {
    // 服务端分页：按当前页请求 pageSize 条，process_path / hours / 动作 /
    // 协议 / 方向全部随 HistoryFilters 下发；总数走独立的 COUNT 接口（
    // get_network_history_count），分页器显示真实"共 N 条"，
    // 不再前端估算
    const filters: HistoryFilters = {
      ...historyFilters.value,
      hours: historyFilters.value.hours ?? statsHours.value,
      process_path: selectedProcess.value.process_path,
      limit: historyPageSize.value,
      offset: (historyPage.value - 1) * historyPageSize.value
    }
    const [records, count] = await Promise.all([
      invoke<NetworkHistoryRecord[]>('get_network_history', { filters }),
      invoke<number>('get_network_history_count', {
        filters: { ...filters, limit: undefined, offset: undefined }
      })
    ])
    // 响应期间用户可能已切换到另一个进程：过期响应整体丢弃
    if (selectedProcess.value?.process_path !== requestedPath) return
    drawerHistory.value = records.slice(0, historyPageSize.value)
    historyTotal.value = count

    // 反查域名（DNS 缓存）。带 IP→域名缓存，只查询本轮新增的 IP，
    // 避免每次轮询都对全部 IP 重复走管道往返
    const uniqueIps = [...new Set(drawerHistory.value.map(r => r.remote_addr))]
    const now = Date.now()
    const newIps = uniqueIps.filter(ip => !isCacheHit(ip, now))
    if (newIps.length > 0) {
      await Promise.all(
        newIps.map(async ip => {
          let domain: string | null = null
          try {
            domain = await invoke<string | null>('lookup_domain', { ip })
          } catch {
            domain = null
          }
          domainCache.set(ip, { domain, cachedAt: Date.now() })
        })
      )
    }
    const map: Record<string, string> = {}
    for (const ip of uniqueIps) {
      const domain = domainCache.get(ip)?.domain
      if (domain) map[ip] = domain
    }
    // 域名反查有网络往返，同样受抽屉竞态守卫约束
    if (selectedProcess.value?.process_path !== requestedPath) return
    domains.value = map
  } catch (error) {
    if (!silent) ElMessage.error(`加载连接记录失败: ${error}`)
    console.error(error)
  } finally {
    if (!silent) drawerLoading.value = false
  }
}

/**
 * "在线"角标：取连接跟踪器中该进程当前活动连接的远程地址集合。
 * 拿不到（服务不可用等）静默跳过，不影响记录列表。
 */
const refreshOnlineIps = () => {
  if (!selectedProcess.value) return
  invoke<Connection[]>('get_connections')
    .then(conns => {
      const path = selectedProcess.value!.process_path
      onlineIps.value = new Set(conns.filter(c => c.process_path === path).map(c => c.remote_addr))
    })
    .catch(() => {})
}

const stopDrawerPolling = () => {
  if (drawerPollInterval) {
    clearInterval(drawerPollInterval)
    drawerPollInterval = null
  }
}

const exportHistory = async () => {
  try {
    const filters: HistoryFilters = {
      ...historyFilters.value,
      hours: statsHours.value,
      // 导出当前筛选（不按进程），沿用旧网络历史页的导出口径
      process_path: undefined,
      limit: undefined,
      offset: undefined
    }
    const data = await invoke<number[]>('export_network_history', { filters, format: 'json' })
    const text = new TextDecoder().decode(new Uint8Array(data))
    const blob = new Blob([text], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `network_history_${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('历史记录导出成功')
  } catch (error) {
    ElMessage.error('导出历史记录失败')
    console.error(error)
  }
}

// ---- 右键菜单 / 进程操作（沿用原进程管理页逻辑） ----

const handleRowDoubleClick = (row: ProcessInfo) => {
  selectedProcess.value = row
  detailsDialogVisible.value = true
}

const handleRowContextMenu = (row: ProcessInfo, _column: any, event: MouseEvent) => {
  event.preventDefault()
  // 阻止事件冒泡到 document 的单例关闭监听，否则菜单刚打开就会被关掉
  event.stopPropagation()
  selectedProcess.value = row
  contextMenuPosition.value = { x: event.clientX, y: event.clientY }
  contextMenuVisible.value = true
  // 菜单 teleport 到 body 且 fixed 定位，先按鼠标点摆位，下一帧测出实际
  // 尺寸后翻边：底部放不下就上翻、右侧放不下就左移（贴 4px 边距），否则
  // 右键表格最后几行时菜单下半截会被屏幕底边裁掉
  nextTick(() => {
    const el = contextMenuRef.value
    if (!el) return
    const x = Math.max(4, Math.min(contextMenuPosition.value.x, window.innerWidth - el.offsetWidth - 4))
    const y = Math.max(4, Math.min(contextMenuPosition.value.y, window.innerHeight - el.offsetHeight - 4))
    contextMenuPosition.value = { x, y }
  })
}

// 关闭监听（冒泡阶段）：菜单容器自带 @click.stop，点击菜单项不会触发；
// 行右键处理器已 stopPropagation。组件挂载时注册、卸载时移除，
// 避免每次右键 addEventListener 叠加泄漏，也避免页面切换后残留。
const closeMenu = () => {
  contextMenuVisible.value = false
}

const handleAllow = async () => {
  if (!selectedProcess.value) return
  contextMenuVisible.value = false

  if (!selectedProcess.value.process_path || selectedProcess.value.process_path === 'Unknown') {
    ElMessage.warning('无法为未知进程创建规则')
    return
  }

  try {
    await invoke('create_rule', {
      rule: {
        name: `允许 ${selectedProcess.value.process_name}`,
        description: `自动创建的允许规则`,
        enabled: true,
        priority: 100,
        action: 'Allow',
        direction: 'Both',
        process_path: selectedProcess.value.process_path
      }
    })
    ElMessage.success('已创建允许规则')
    loadProcesses()
  } catch (error) {
    ElMessage.error('创建规则失败')
    console.error(error)
  }
}

const handleBlock = async () => {
  if (!selectedProcess.value) return
  contextMenuVisible.value = false

  if (!selectedProcess.value.process_path || selectedProcess.value.process_path === 'Unknown') {
    ElMessage.warning('无法为未知进程创建规则')
    return
  }

  try {
    await invoke('create_rule', {
      rule: {
        name: `阻止 ${selectedProcess.value.process_name}`,
        description: `自动创建的阻止规则`,
        enabled: true,
        priority: 100,
        action: 'Block',
        direction: 'Both',
        process_path: selectedProcess.value.process_path
      }
    })
    ElMessage.success('已创建阻止规则')
    loadProcesses()
  } catch (error) {
    ElMessage.error('创建规则失败')
    console.error(error)
  }
}

const handleRemoveRule = async () => {
  if (!selectedProcess.value?.rule_id) return
  contextMenuVisible.value = false

  try {
    await ElMessageBox.confirm(
      `确定要删除 ${selectedProcess.value.process_name} 的规则吗？`,
      '确认删除',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' }
    )

    await invoke('delete_rule', { id: selectedProcess.value.rule_id })
    ElMessage.success('规则已删除')
    loadProcesses()
  } catch (error: any) {
    // 'cancel'=点取消，'close'=ESC/点关闭按钮，均为用户主动放弃而非失败
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error('删除规则失败')
      console.error(error)
    }
  }
}

const handleKillProcess = async () => {
  if (!selectedProcess.value) return
  contextMenuVisible.value = false

  try {
    await ElMessageBox.confirm(
      `确定要终止进程 ${selectedProcess.value.process_name} 吗？`,
      '确认终止',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' }
    )

    // 直接使用当前选中行的 PID（来自服务端统计中的最近进程 ID）
    const pid = selectedProcess.value.process_id
    if (pid) {
      await invoke('kill_process', { pid })
      ElMessage.success('进程已终止')
      loadProcesses()
    } else {
      ElMessage.warning('该进程没有已知的活动实例（统计期间无进程 ID 记录）')
    }
  } catch (error: any) {
    // 'cancel'=点取消，'close'=ESC/点关闭按钮，均为用户主动放弃而非失败
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error('终止进程失败: ' + error)
      console.error(error)
    }
  }
}

const handleAddToGroup = () => {
  if (!selectedProcess.value) return
  contextMenuVisible.value = false
  loadAppGroups()
  addToGroupDialogVisible.value = true
}

const confirmAddToGroup = async () => {
  if (!selectedProcess.value || !selectedGroupId.value) {
    ElMessage.warning('请选择应用分组')
    return
  }

  try {
    await invoke('add_app_group_member', {
      groupId: selectedGroupId.value,
      processPath: selectedProcess.value.process_path,
      processName: selectedProcess.value.process_name
    })
    ElMessage.success('已添加到应用分组')
    addToGroupDialogVisible.value = false
    selectedGroupId.value = null
  } catch (error) {
    ElMessage.error('添加到应用分组失败')
    console.error(error)
  }
}

const handleCopyPath = () => {
  if (!selectedProcess.value) return
  contextMenuVisible.value = false

  navigator.clipboard.writeText(selectedProcess.value.process_path)
    .then(() => ElMessage.success('路径已复制到剪贴板'))
    .catch(() => ElMessage.error('复制失败'))
}

const handleOpenFolder = async () => {
  if (!selectedProcess.value) return
  contextMenuVisible.value = false

  try {
    await invoke('open_process_folder', { path: selectedProcess.value.process_path })
  } catch (error) {
    ElMessage.error('打开文件夹失败')
    console.error(error)
  }
}

const handleViewDetails = () => {
  if (!selectedProcess.value) return
  contextMenuVisible.value = false
  detailsDialogVisible.value = true
}

const updateTableHeight = () => {
  nextTick(() => {
    // 计算表格高度：视口高度 - 主布局padding(40) - 页面标题区域(60) - 分页器(60)
    tableHeight.value = window.innerHeight - 160
  })
}

// 路由 query 带入的进程过滤（Dashboard 应用排行点击跳转）：
// searchText 同时匹配进程名与路径，填完整路径即可精确收敛到该应用
const route = useRoute()

onMounted(() => {
  document.addEventListener('click', closeMenu)
  document.addEventListener('contextmenu', closeMenu)
  const queryProcess = route.query.process
  if (typeof queryProcess === 'string' && queryProcess) {
    searchText.value = queryProcess
  }
  historyFilters.value.hours = statsHours.value
  loadProcesses()
  updateTableHeight()
  window.addEventListener('resize', updateTableHeight)
  refreshInterval = window.setInterval(() => loadProcesses(true), 10000) // 10秒刷新一次（失败静默，只更新顶部横幅）
})

onUnmounted(() => {
  document.removeEventListener('click', closeMenu)
  document.removeEventListener('contextmenu', closeMenu)
  stopDrawerPolling()
  if (refreshInterval) clearInterval(refreshInterval)
  window.removeEventListener('resize', updateTableHeight)
})
</script>

<style scoped>
.network-activity {
  padding: 0;
}

.service-alert {
  margin-bottom: 16px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 8px;
}

.header h1 {
  margin: 0;
  color: #1f1f1f;
}

.header-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
}

/* 进程列两行结构（与通知页进程信息观感一致）：主行名称+标签，副行灰色小字路径 */
.process-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.process-main {
  display: flex;
  align-items: center;
  gap: 8px;
}

.process-main .el-icon {
  flex-shrink: 0;
}

.process-sub {
  font-size: 11px;
  color: #605e5c;
}

.truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mono {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 12px;
}

.empty-state {
  text-align: center;
  padding: 32px;
  color: #605e5c;
  font-size: 13px;
}

.drawer-toolbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

/* 自定义排序图标样式 */
:deep(.el-table .caret-wrapper) {
  height: 20px;
  width: 20px;
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

:deep(.el-table .sort-caret) {
  width: 0;
  height: 0;
  border: 5px solid transparent;
  position: absolute;
  left: 5px;
}

:deep(.el-table .sort-caret.ascending) {
  border-bottom-color: #c0c4cc;
  top: 2px;
}

:deep(.el-table .sort-caret.descending) {
  border-top-color: #c0c4cc;
  bottom: 2px;
}

:deep(.el-table .ascending .sort-caret.ascending) {
  border-bottom-color: #409eff;
}

:deep(.el-table .descending .sort-caret.descending) {
  border-top-color: #409eff;
}

/* 右键菜单样式 */
.context-menu {
  position: fixed;
  background: white;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
  z-index: 9999;
  padding: 4px 0;
  min-width: 160px;
}

.context-menu-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  cursor: pointer;
  font-size: 14px;
  color: #606266;
  transition: background-color 0.2s;
}

.context-menu-item:hover {
  background-color: #f5f7fa;
}

.context-menu-item .el-icon {
  font-size: 16px;
}

.context-menu-divider {
  height: 1px;
  background-color: #e4e7ed;
  margin: 4px 0;
}
</style>
