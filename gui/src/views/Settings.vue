<template>
  <div class="settings">
    <h1>设置</h1>

    <div class="settings-layout">
      <div class="settings-nav">
        <div
          v-for="group in groups"
          :key="group.key"
          class="nav-item"
          :class="{ active: activeGroup === group.key }"
          @click="activeGroup = group.key"
        >
          <el-icon><component :is="group.icon" /></el-icon>
          <span>{{ group.label }}</span>
        </div>
      </div>

      <div class="settings-content">
        <!-- 通知与交互 -->
        <el-card v-show="activeGroup === 'general'">
          <template #header>
            <span>通知与交互</span>
          </template>
          <el-form :model="settings" label-width="150px">
            <el-form-item label="启用通知">
              <el-switch v-model="settings.notifications_enabled" />
              <div class="form-tip">是否显示防火墙通知</div>
            </el-form-item>

            <el-form-item label="询问连接">
              <el-switch v-model="settings.ask_to_connect_enabled" />
              <div class="form-tip">配合"默认拦截"使用：未知程序联网时弹窗询问</div>
            </el-form-item>

            <el-form-item label="记住决策">
              <el-switch v-model="settings.remember_decisions" />
              <div class="form-tip">记住您的连接决策（24小时）</div>
            </el-form-item>
          </el-form>
        </el-card>

        <!-- 防护策略 -->
        <el-card v-show="activeGroup === 'protection'">
          <template #header>
            <span>防护策略</span>
          </template>
          <el-form :model="settings" label-width="150px">
            <el-form-item label="默认允许未匹配连接">
              <el-switch v-model="settings.default_allow" />
              <div class="form-tip">关闭后未匹配任何规则的连接将被拦截（白名单模式）；关闭前请确认已放行所需程序，系统进程可由内置豁免规则放行</div>
            </el-form-item>

            <el-form-item label="系统豁免规则">
              <el-switch v-model="settings.system_rules_enabled" />
              <div class="form-tip">默认拦截模式下自动安装 [System] 前缀的内置放行规则（svchost、DNS、DHCP、lsass、Windows Update 等），可在规则页查看或停用</div>
            </el-form-item>

            <el-form-item label="服务未运行时保护">
              <el-switch v-model="settings.protect_when_not_running" />
              <div class="form-tip">开启后安装 WFP 持久化拦截过滤器：即使服务/驱动通信中断（重启、崩溃、卸载前），所有联网仍被拦截（类似 kill-switch）；卸载服务时自动移除</div>
            </el-form-item>
          </el-form>
        </el-card>

        <!-- 带宽限制（原带宽管理页整页并入：全局 + 进程限速同一份数据同一页面） -->
        <el-card v-show="activeGroup === 'bandwidth'">
          <template #header>
            <span>带宽限制</span>
          </template>
          <el-form :model="settings" label-width="150px">
            <el-form-item label="全局带宽限制">
              <el-switch v-model="settings.global_bandwidth_limit_enabled" />
              <div class="form-tip">启用全局带宽限制</div>
            </el-form-item>

            <el-form-item label="上传限制">
              <el-input-number
                v-model="settings.global_upload_limit_kbps"
                :min="0"
                :disabled="!settings.global_bandwidth_limit_enabled"
                :step="100"
              />
              <span class="unit">Kbps</span>
              <div class="form-tip">0 表示不限制</div>
            </el-form-item>

            <el-form-item label="下载限制">
              <el-input-number
                v-model="settings.global_download_limit_kbps"
                :min="0"
                :disabled="!settings.global_bandwidth_limit_enabled"
                :step="100"
              />
              <span class="unit">Kbps</span>
              <div class="form-tip">0 表示不限制；下载限速仅对 TCP 连接生效，内核逐包整形不丢数据</div>
            </el-form-item>
          </el-form>

          <!-- 进程限速：即时生效语义（沿用 set/delete IPC），不纳入统一保存按钮 -->
          <h3 class="bw-section-title">
            进程带宽限制
            <el-tag size="small" type="info" style="margin-left: 8px">修改即时生效，不经下方保存按钮</el-tag>
          </h3>
          <el-alert
            type="info"
            :closable="false"
            show-icon
            title="限速语义：上传/下载双向均强制整形；下载限速仅对 TCP 连接生效"
            description="上传/下载方向均在内核按令牌桶真实限流。下载限速采用内核扣留-定时放行（pacing）：包一个不丢、连接零 RST，任意速率稳定生效。下载限速仅对 TCP 连接生效：UDP 无拥塞反馈机制，故 UDP 流量不受下载限制约束。"
            style="margin-bottom: 12px"
          />
          <div class="bw-toolbar">
            <el-button type="primary" @click="showAddDialog = true">添加限制</el-button>
            <el-button @click="loadLimits">刷新</el-button>
          </div>
          <div class="limits-table">
            <table>
              <thead>
                <tr>
                  <th>进程名称</th>
                  <th>进程路径</th>
                  <th>上传限制 (Kbps)</th>
                  <th>下载限制 (Kbps)</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="limit in limits" :key="limit.process_path">
                  <td>{{ limit.process_name || '未知' }}</td>
                  <td class="truncate" :title="limit.process_path">{{ limit.process_path }}</td>
                  <td>{{ limit.upload_limit_kbps || '-' }}</td>
                  <td>{{ limit.download_limit_kbps || '-' }}</td>
                  <td>
                    <span :class="limit.enabled ? 'status-enabled' : 'status-disabled'">
                      {{ limit.enabled ? '启用' : '禁用' }}
                    </span>
                  </td>
                  <td>
                    <el-button size="small" @click="editLimit(limit)">编辑</el-button>
                    <el-button size="small" type="danger" @click="deleteLimit(limit)">删除</el-button>
                  </td>
                </tr>
              </tbody>
            </table>
            <div v-if="limits.length === 0" class="bw-empty">暂无带宽限制</div>
          </div>
        </el-card>

        <!-- 驱动诊断（手动刷新，不做轮询） -->
        <el-card v-show="activeGroup === 'diags'" class="diags-card">
          <template #header>
            <div class="diags-header">
              <span>驱动诊断</span>
              <el-button size="small" :loading="diagsLoading" @click="loadDiags">刷新</el-button>
            </div>
          </template>

          <template v-if="diags">
            <h3 class="diags-section-title">Callout 注册状态</h3>
            <el-table :data="diags.callouts" size="small" border>
              <el-table-column prop="name" label="名称" min-width="220" />
              <el-table-column label="注册状态" width="200">
                <template #default="{ row }">
                  <span v-if="row.reg_status === 0" class="status-ok">OK</span>
                  <el-tooltip
                    v-else-if="row.reg_status === 0x80320009"
                    content="僵尸注册（FWP_E_ALREADY_EXISTS）：该层本会话不会生效，需重启 VM 自愈"
                    placement="top"
                  >
                    <span class="status-zombie">僵尸注册（需重启 VM 自愈）</span>
                  </el-tooltip>
                  <span v-else class="status-err">错误 0x{{ row.reg_status.toString(16).toUpperCase() }}</span>
                </template>
              </el-table-column>
              <el-table-column label="CalloutId" width="120">
                <template #default="{ row }">
                  <span>{{ row.callout_id === 0 ? '—' : row.callout_id }}</span>
                </template>
              </el-table-column>
            </el-table>

            <h3 class="diags-section-title">分类/关联计数器</h3>
            <el-table :data="counterRows" size="small" border>
              <el-table-column prop="label" label="计数器" min-width="200" />
              <el-table-column label="V4" min-width="140">
                <template #default="{ row }">{{ formatCounter(row.v4) }}</template>
              </el-table-column>
              <el-table-column label="V6" min-width="140">
                <template #default="{ row }">{{ formatCounter(row.v6) }}</template>
              </el-table-column>
            </el-table>

            <!-- diag v3：限速表进程生命周期清理（老驱动/老服务无此字段时占位） -->
            <h3 class="diags-section-title">限速清理</h3>
            <el-table v-if="(diags.diag_version ?? 0) >= 3" :data="throttleRows" size="small" border>
              <el-table-column prop="label" label="指标" min-width="200" />
              <el-table-column prop="value" label="数值" min-width="140" />
            </el-table>
            <el-empty
              v-else
              description="当前驱动不支持限速清理诊断（需 diag v3）"
              :image-size="48"
            />

            <!-- diag v5：kernel pacing（下载限速执行引擎） -->
            <h3 class="diags-section-title">下载限速内核整形（Pacing）</h3>
            <el-table v-if="(diags.diag_version ?? 0) >= 5" :data="pacingRows" size="small" border>
              <el-table-column prop="label" label="指标" min-width="200" />
              <el-table-column prop="value" label="数值" min-width="140" />
            </el-table>
            <el-empty
              v-else
              description="当前驱动不支持 Pacing 诊断（需 diag v5）"
              :image-size="48"
            />
          </template>

          <el-empty v-else-if="!diagsLoading && diagsLoaded" description="驱动不支持诊断 IOCTL（旧版驱动）" :image-size="72" />
          <div v-else-if="!diagsLoading" class="diags-tip">点击「刷新」获取驱动诊断快照</div>
        </el-card>

        <div class="actions">
          <el-button v-show="activeGroup !== 'diags'" type="primary" @click="saveSettings" :loading="saving">
            保存设置
          </el-button>
        </div>
      </div>
    </div>

    <!-- 进程限速添加/编辑对话框（原带宽管理页迁移，修改即时生效） -->
    <el-dialog
      v-model="showAddDialog"
      :title="editingLimit ? '编辑限制' : '添加带宽限制'"
      width="480px"
      @close="closeDialog"
    >
      <el-form label-width="150px">
        <el-form-item label="进程路径">
          <el-input v-model="formData.process_path" placeholder="C:\Program Files\app.exe" />
        </el-form-item>
        <el-form-item label="进程名称 (可选)">
          <el-input v-model="formData.process_name" placeholder="app.exe" />
        </el-form-item>
        <el-form-item label="上传限制 (Kbps)">
          <el-input-number v-model="formData.upload_limit_kbps" :min="0" :step="100" />
        </el-form-item>
        <el-form-item label="下载限制 (Kbps)">
          <el-input-number v-model="formData.download_limit_kbps" :min="0" :step="100" />
          <div class="form-tip">仅对 TCP 连接生效</div>
        </el-form-item>
        <el-form-item label="启用限制">
          <el-switch v-model="formData.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="closeDialog">取消</el-button>
        <el-button type="primary" @click="saveLimit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Bell, Lock, DataLine, Cpu } from '@element-plus/icons-vue'

interface Settings {
  notifications_enabled: boolean
  ask_to_connect_enabled: boolean
  remember_decisions: boolean
  global_bandwidth_limit_enabled: boolean
  global_upload_limit_kbps?: number
  global_download_limit_kbps?: number
  default_allow?: boolean
  system_rules_enabled?: boolean
  protect_when_not_running?: boolean
}

interface ProcessBandwidthLimit {
  id?: number
  process_path: string
  process_name?: string
  upload_limit_kbps?: number
  download_limit_kbps?: number
  enabled: boolean
  created_at?: string
  updated_at?: string
}

const groups = [
  { key: 'general', label: '通知与交互', icon: Bell },
  { key: 'protection', label: '防护策略', icon: Lock },
  { key: 'bandwidth', label: '带宽限制', icon: DataLine },
  { key: 'diags', label: '驱动诊断', icon: Cpu },
] as const

const activeGroup = ref<(typeof groups)[number]['key']>('general')

const settings = ref<Settings>({
  notifications_enabled: true,
  ask_to_connect_enabled: false,
  remember_decisions: true,
  global_bandwidth_limit_enabled: false,
  global_upload_limit_kbps: undefined,
  global_download_limit_kbps: undefined,
  default_allow: true,
  system_rules_enabled: true,
  protect_when_not_running: false
})
const saving = ref(false)

// 本页加载时的设置快照：保存时用于判断"用户在本页实际改了哪些字段"，
// 只提交这些字段，避免整份旧副本覆盖其他页面的并发修改
const loadedSnapshot = ref<Settings | null>(null)

const loadSettings = async () => {
  try {
    const result = await invoke<Settings>('get_settings')
    // 旧版服务可能缺新字段，未返回时保持默认值
    settings.value = {
      ...settings.value,
      ...result,
      default_allow: result.default_allow ?? true,
      system_rules_enabled: result.system_rules_enabled ?? true,
      protect_when_not_running: result.protect_when_not_running ?? false,
    }
    loadedSnapshot.value = JSON.parse(JSON.stringify(settings.value))
  } catch (error) {
    ElMessage.error('加载设置失败')
    console.error(error)
  }
}

// update_settings 不触发 kernel_throttle，全局带宽三字段绝不能混进那条路，
// 保存时先剥离走专用 set_global_bandwidth_limit（持久化 + 同步内核条目）
const BANDWIDTH_KEYS: (keyof Settings)[] = [
  'global_bandwidth_limit_enabled',
  'global_upload_limit_kbps',
  'global_download_limit_kbps'
]

const saveSettings = async () => {
  // 开关开启校验：至少一个限值 > 0，否则不发任何请求直接提示
  if (settings.value.global_bandwidth_limit_enabled) {
    if ((settings.value.global_upload_limit_kbps ?? 0) <= 0 && (settings.value.global_download_limit_kbps ?? 0) <= 0) {
      ElMessage.warning('已开启全局带宽限制，请先填写至少一个大于 0 的限值再保存')
      return
    }
  }

  saving.value = true
  try {
    // ---- 第 1 步：全局带宽走专用 IPC ----
    // 开关关闭时仅关开关/摘除内核条目，限值原样随请求持久化（重开无需重填）
    const up = settings.value.global_upload_limit_kbps ?? 0
    const down = settings.value.global_download_limit_kbps ?? 0
    await invoke('set_global_bandwidth_limit', {
      uploadLimitKbps: up > 0 ? up : null,
      downloadLimitKbps: down > 0 ? down : null,
      enabled: settings.value.global_bandwidth_limit_enabled
    })

    // ---- 第 2 步：其余设置走 update_settings ----
    // 重新拉取服务端最新设置（此时已包含第 1 步刚写入的带宽值），只把本页
    // 实际修改过的非带宽字段合并进去提交；带宽三字段回传最新原值，防止整份
    // 覆盖把第 1 步刚写入的值回滚
    const fresh = await invoke<Settings>('get_settings')
    const merged: Settings = { ...fresh }
    const base = loadedSnapshot.value
    if (base) {
      const changed = (Object.keys(settings.value) as (keyof Settings)[])
        .filter(key => !BANDWIDTH_KEYS.includes(key))
        .filter(key => JSON.stringify(settings.value[key]) !== JSON.stringify(base[key]))
      for (const key of changed) {
        ;(merged as any)[key] = settings.value[key]
      }
    }
    await invoke('update_settings', { settings: merged })
    loadedSnapshot.value = JSON.parse(JSON.stringify(settings.value))
    ElMessage.success('设置保存成功')
  } catch (error) {
    ElMessage.error('保存设置失败')
    console.error(error)
    // 任一请求失败：重新回显服务端真实状态，避免界面停留在从未生效的值上
    await loadSettings()
  } finally {
    saving.value = false
  }
}

// ---- 进程带宽限制（原带宽管理页迁移，修改即时生效） ----
const limits = ref<ProcessBandwidthLimit[]>([])
const showAddDialog = ref(false)
const editingLimit = ref<ProcessBandwidthLimit | null>(null)
const formData = ref<ProcessBandwidthLimit>(emptyForm())

function emptyForm(): ProcessBandwidthLimit {
  return {
    process_path: '',
    process_name: '',
    upload_limit_kbps: undefined,
    download_limit_kbps: undefined,
    enabled: true
  }
}

const loadLimits = async () => {
  try {
    const result = await invoke('list_process_bandwidth_limits') as ProcessBandwidthLimit[]
    limits.value = result
  } catch (error) {
    ElMessage.error('加载带宽限制失败')
    console.error('加载带宽限制失败:', error)
  }
}

const editLimit = (limit: ProcessBandwidthLimit) => {
  editingLimit.value = limit
  formData.value = { ...limit }
  showAddDialog.value = true
}

const saveLimit = async () => {
  if (!formData.value.process_path.trim()) {
    ElMessage.warning('请填写进程路径')
    return
  }
  try {
    await invoke('set_process_bandwidth_limit', { limit: { ...formData.value } })
    ElMessage.success(editingLimit.value ? '带宽限制已更新' : '带宽限制已添加')
    await loadLimits()
    closeDialog()
  } catch (error) {
    ElMessage.error('保存带宽限制失败')
    console.error('保存带宽限制失败:', error)
  }
}

// 真正的删除：走 delete_process_bandwidth_limit（清数据库记录 + 解除内存限流）
const deleteLimit = async (limit: ProcessBandwidthLimit) => {
  // 原生 confirm() 在 Tauri WebView2 中不渲染且恒返回 falsy，删除按钮会
  // 完全失效；改用项目统一的 ElMessageBox。取消（'cancel'）与 ESC/点关闭
  // （'close'）都按用户主动放弃处理，不弹错误提示。
  try {
    await ElMessageBox.confirm(
      `确定删除进程 ${limit.process_name || limit.process_path} 的带宽限制吗？`,
      '确认删除',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' }
    )
  } catch {
    return
  }
  try {
    await invoke('delete_process_bandwidth_limit', { processPath: limit.process_path })
    ElMessage.success('带宽限制已删除')
    await loadLimits()
  } catch (error) {
    ElMessage.error('删除带宽限制失败')
    console.error('删除带宽限制失败:', error)
  }
}

const closeDialog = () => {
  showAddDialog.value = false
  editingLimit.value = null
  formData.value = emptyForm()
}

// ---- 驱动诊断 ----
// 字段名与服务侧 DriverDiagnostics 一致（snake_case JSON，下标 [0]=V4 [1]=V6）
interface DriverCalloutDiag {
  name: string
  reg_status: number
  callout_id: number
  unreg_status?: number
  unreg_retries?: number
}

interface DriverDiagnostics {
  callouts: DriverCalloutDiag[]
  classify_stream: number[] | [number, number]
  classify_flow_est: number[] | [number, number]
  assoc_ok: number[] | [number, number]
  assoc_fail: number[] | [number, number]
  flow_delete: number[] | [number, number]
  stream_bytes_counted: number[] | [number, number]
  // diag v3：老版服务不返回时保持 undefined，占位逻辑按版本门控
  diag_version?: number
  throttle_active_entries?: number
  throttle_notify_removes?: number
  // diag v4：入站传输层（下载限速）计数器，下标 [0]=V4 [1]=V6
  in_transport_classify?: number[] | [number, number]
  in_transport_permit?: number[] | [number, number]
  in_transport_block?: number[] | [number, number]
  // diag v5：kernel pacing（克隆-扣留-定时注入）
  pacing_held?: number
  pacing_injected?: number
  pacing_inject_fail?: number
  pacing_queue_drop?: number
  pacing_queue_depth_max?: number
  pacing_timer_ticks?: number
}

const diags = ref<DriverDiagnostics | null>(null)
const diagsLoading = ref(false)
const diagsLoaded = ref(false)

const counterRows = computed(() => {
  const d = diags.value
  if (!d) return []
  const pair = (a?: number[] | [number, number]) => [a?.[0] ?? 0, a?.[1] ?? 0] as const
  const [cs4, cs6] = pair(d.classify_stream)
  const [cf4, cf6] = pair(d.classify_flow_est)
  const [ao4, ao6] = pair(d.assoc_ok)
  const [af4, af6] = pair(d.assoc_fail)
  const [fd4, fd6] = pair(d.flow_delete)
  const [sb4, sb6] = pair(d.stream_bytes_counted)
  const [itc4, itc6] = pair(d.in_transport_classify)
  const [itp4, itp6] = pair(d.in_transport_permit)
  const [itb4, itb6] = pair(d.in_transport_block)
  const rows = [
    { label: 'classify（stream 层）', v4: cs4, v6: cs6 },
    { label: 'classify（flow-established 层）', v4: cf4, v6: cf6 },
    { label: 'PID 关联成功', v4: ao4, v6: ao6 },
    { label: 'PID 关联失败', v4: af4, v6: af6 },
    { label: 'flow 删除', v4: fd4, v6: fd6 },
    { label: '累计计入字节', v4: sb4, v6: sb6 },
  ]
  // diag v4 计数器：老驱动/老服务无值时保持 0，不单独占位
  rows.push(
    { label: 'classify（入站传输层，下载限速）', v4: itc4, v6: itc6 },
    { label: '入站 PERMIT（下载限速）', v4: itp4, v6: itp6 },
    { label: '入站 BLOCK（下载限速）', v4: itb4, v6: itb6 },
  )
  return rows
})

// diag v3：限速表进程生命周期清理两行
const throttleRows = computed(() => {
  const d = diags.value
  if (!d) return []
  return [
    { label: '限速活跃条目', value: String(d.throttle_active_entries ?? 0) },
    { label: '进程退出清理次数', value: String(d.throttle_notify_removes ?? 0) },
  ]
})

// diag v5：kernel pacing（克隆-扣留-定时注入）计数行（版本门控）
const pacingRows = computed(() => {
  const d = diags.value
  if (!d) return []
  return [
    { label: '扣留包数 (held)', value: String(d.pacing_held ?? 0) },
    { label: '注入成功 (injected)', value: String(d.pacing_injected ?? 0) },
    { label: '注入失败 (injectFail)', value: String(d.pacing_inject_fail ?? 0) },
    { label: '超限丢弃 (queueDrop)', value: String(d.pacing_queue_drop ?? 0) },
    { label: '扣留峰值字节 (queueDepthMax)', value: formatCounter(d.pacing_queue_depth_max ?? 0) },
    { label: '放行定时器触发 (timerTicks)', value: String(d.pacing_timer_ticks ?? 0) },
  ]
})

const formatCounter = (v: number) => {
  if (v >= 1024 * 1024 * 1024) return `${(v / 1024 / 1024 / 1024).toFixed(2)} GB`
  if (v >= 1024 * 1024) return `${(v / 1024 / 1024).toFixed(2)} MB`
  if (v >= 1024) return `${(v / 1024).toFixed(2)} KB`
  return String(v)
}

// 每次点击发一次 GetDriverDiags，不做轮询
const loadDiags = async () => {
  diagsLoading.value = true
  try {
    const result = await invoke<DriverDiagnostics | null>('get_driver_diags')
    diags.value = result
  } catch (error) {
    ElMessage.error('获取驱动诊断失败')
    console.error(error)
  } finally {
    diagsLoading.value = false
    diagsLoaded.value = true
  }
}

// 首次切到诊断页时拉一次快照（仅此一次，之后靠手动刷新，不做轮询）
watch(activeGroup, (g) => {
  if (g === 'diags' && !diagsLoaded.value) loadDiags()
})

onMounted(() => {
  loadSettings()
  loadLimits()
})
</script>

<style scoped>
.settings {
  padding: 0;
  max-width: 900px;
}

.settings h1 {
  color: #1f1f1f;
  margin: 0 0 16px 0;
}

.settings-layout {
  display: flex;
  gap: 16px;
  align-items: flex-start;
}

.settings-nav {
  width: 160px;
  flex-shrink: 0;
  background-color: #ffffff;
  border: 1px solid #d9d9d9;
  border-radius: 4px;
  padding: 8px 0;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  cursor: pointer;
  color: #1f1f1f;
  font-size: 14px;
  border-left: 3px solid transparent;
  transition: background-color 0.2s;
}

.nav-item:hover {
  background-color: #f5f5f5;
}

.nav-item.active {
  background-color: #ecf5ff;
  border-left-color: #409eff;
  color: #409eff;
  font-weight: 600;
}

.settings-content {
  flex: 1;
  min-width: 0;
}

.form-tip {
  font-size: 11px;
  color: #605e5c;
  margin-top: 4px;
}

.unit {
  margin-left: 8px;
  color: #605e5c;
  font-size: 13px;
}

.actions {
  margin-top: 16px;
  text-align: right;
}

/* ---- 进程带宽限制（原带宽管理页迁移样式） ---- */
.bw-section-title {
  font-size: 15px;
  font-weight: 600;
  color: #1f1f1f;
  margin: 16px 0 12px;
}

.bw-toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.limits-table table {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid #d9d9d9;
}

.limits-table th,
.limits-table td {
  padding: 8px 12px;
  text-align: left;
  border-bottom: 1px solid #e0e0e0;
  border-right: 1px solid #e0e0e0;
  font-size: 13px;
}

.limits-table th {
  background: #f3f3f3;
  font-weight: 600;
  color: #1f1f1f;
}

.limits-table th:last-child,
.limits-table td:last-child {
  border-right: none;
}

.limits-table .truncate {
  max-width: 260px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.status-enabled {
  color: #107c10;
  font-weight: 500;
}

.status-disabled {
  color: #d13438;
  font-weight: 500;
}

.bw-empty {
  text-align: center;
  padding: 32px;
  color: #605e5c;
  font-size: 13px;
}

.diags-card :deep(.el-card__header) {
  padding: 12px 16px;
}

.diags-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.diags-section-title {
  font-size: 13px;
  font-weight: 600;
  color: #1f1f1f;
  margin: 12px 0 8px;
}

.diags-section-title:first-of-type {
  margin-top: 0;
}

.status-ok {
  color: #67c23a;
  font-weight: 600;
}

.status-zombie {
  color: #e6a23c;
  font-weight: 600;
}

.status-err {
  color: #f56c6c;
  font-weight: 600;
}

.diags-tip {
  color: #605e5c;
  font-size: 13px;
  padding: 24px 0;
  text-align: center;
}
</style>
