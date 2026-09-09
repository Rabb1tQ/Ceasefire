<template>
  <div class="rule-manager">
    <div class="header">
      <h1>规则管理</h1>
      <div class="header-actions">
        <el-input
          v-model="searchText"
          placeholder="搜索规则名/描述/进程路径"
          clearable
          style="width: 260px"
          @input="onSearchInput"
          @keyup.enter="triggerSearch"
          @clear="triggerSearch"
        />
        <el-button :loading="loading" @click="loadRules">刷新</el-button>
        <el-button @click="exportRules" :loading="exporting">导出</el-button>
        <el-button @click="triggerImportFile">导入</el-button>
        <input ref="importFileInput" type="file" accept=".json,application/json" style="display: none" @change="onImportFile" />
        <el-button type="primary" @click="openAddDialog">添加规则</el-button>
      </div>
    </div>

    <el-table :data="rules" stripe style="width: 100%" v-loading="loading">
      <el-table-column prop="priority" label="优先级" width="100" />
      <el-table-column label="状态" width="80">
        <template #default="{ row }">
          <el-switch :model-value="row.enabled" @change="toggleRule(row)" />
        </template>
      </el-table-column>
      <el-table-column prop="name" label="名称" min-width="140" show-overflow-tooltip />
      <el-table-column label="动作" width="80">
        <template #default="{ row }">
          <el-tag :type="row.action === 'Allow' ? 'success' : 'danger'">
            {{ row.action === 'Allow' ? '允许' : '阻止' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="process_path" label="进程路径" min-width="200" show-overflow-tooltip>
        <template #default="{ row }">
          <span v-if="row.process_path">{{ row.process_path }}</span>
          <el-tag v-else-if="row.app_group_id" type="warning" size="small">
            分组: {{ groupName(row.app_group_id) }}
          </el-tag>
          <span v-else>任意进程</span>
        </template>
      </el-table-column>
      <el-table-column label="协议" width="80">
        <template #default="{ row }">
          {{ protocolText(row.protocol) }}
        </template>
      </el-table-column>
      <el-table-column label="远程地址/域名" width="160" show-overflow-tooltip>
        <template #default="{ row }">{{ row.remote_domain || row.remote_addr || '任意' }}</template>
      </el-table-column>
      <el-table-column label="远程端口" width="120">
        <template #default="{ row }">{{ portRangeText(row.remote_port) }}</template>
      </el-table-column>
      <el-table-column label="本地端口" width="120">
        <template #default="{ row }">{{ portRangeText(row.local_port) }}</template>
      </el-table-column>
      <el-table-column label="方向" width="80">
        <template #default="{ row }">{{ directionText(row.direction) }}</template>
      </el-table-column>
      <el-table-column label="网络区域" width="100">
        <template #default="{ row }">{{ zoneText(row.network_zone) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="150" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="editRule(row)">编辑</el-button>
          <el-button link type="danger" @click="deleteRule(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="total"
        background
        layout="total, sizes, prev, pager, next"
        @current-change="loadRules"
        @size-change="onSizeChange"
      />
    </div>

    <el-dialog v-model="dialogVisible" :title="editingId != null ? '编辑规则' : '添加规则'" width="640px" class="rule-dialog">
      <el-form :model="form" label-width="120px">
        <el-tabs>
          <el-tab-pane label="基本">
            <el-form-item label="名称" required>
              <el-input v-model="form.name" placeholder="规则名称" />
            </el-form-item>
            <el-form-item label="描述" required>
              <el-input v-model="form.description" placeholder="规则描述" />
            </el-form-item>
            <el-form-item label="优先级">
              <el-input-number v-model="form.priority" :min="0" :max="999" />
            </el-form-item>
            <el-form-item label="启用">
              <el-switch v-model="form.enabled" />
            </el-form-item>
            <el-form-item label="动作">
              <el-radio-group v-model="form.action">
                <el-radio value="Allow">允许</el-radio>
                <el-radio value="Block">阻止</el-radio>
              </el-radio-group>
            </el-form-item>
          </el-tab-pane>
          <el-tab-pane label="匹配条件">
            <el-form-item label="进程路径">
              <el-input v-model="form.process_path" placeholder="例如: C:\\Windows\\System32\\svchost.exe（留空表示任意进程）" />
              <div class="form-tip">与应用分组二选一：填写了进程路径时按路径匹配，选择分组时按分组成员展开匹配</div>
            </el-form-item>
            <el-form-item label="应用分组">
              <el-select v-model="form.app_group_id" placeholder="不按分组匹配" clearable style="width: 100%">
                <el-option v-for="g in groups" :key="g.id" :value="g.id" :label="g.name" />
              </el-select>
              <div class="form-tip">选择后该规则对分组内所有成员进程生效（下发内核时按成员展开）</div>
            </el-form-item>
            <el-form-item label="连接方向">
              <el-select v-model="form.direction">
                <el-option value="Both" label="全部" />
                <el-option value="Inbound" label="入站" />
                <el-option value="Outbound" label="出站" />
              </el-select>
            </el-form-item>
            <el-form-item label="协议">
              <el-select v-model="form.protocol" placeholder="任意" clearable>
                <el-option value="Any" label="任意" />
                <el-option value="Tcp" label="TCP" />
                <el-option value="Udp" label="UDP" />
                <el-option value="Icmp" label="ICMP" />
                <el-option value="Icmpv6" label="ICMPv6" />
              </el-select>
            </el-form-item>
            <el-form-item label="网络区域">
              <el-select v-model="form.network_zone" placeholder="任意" clearable>
                <el-option value="Localhost" label="本机" />
                <el-option value="Lan" label="局域网" />
                <el-option value="Internet" label="互联网" />
              </el-select>
            </el-form-item>
          </el-tab-pane>
          <el-tab-pane label="网络与限速">
            <el-form-item label="远程地址">
              <el-input v-model="form.remote_addr" placeholder="例如: 192.168.1.0 或 2001:db8::1（IPv4/IPv6，留空表示任意）" />
            </el-form-item>
            <el-form-item label="远程地址掩码">
              <el-input-number v-model="form.remote_addr_mask" :min="0" :max="128" placeholder="24（IPv6 可到 128）" style="width: 100%" :disabled="!!form.remote_domain" />
            </el-form-item>
            <el-form-item label="远程域名">
              <el-input v-model="form.remote_domain" placeholder="例如: example.com 或 *.cdn.example（与远程地址互斥，DNS 命中时按 IP 自动展开）" />
            </el-form-item>
            <el-form-item label="远程端口">
              <div class="port-edit">
                <el-select v-model="remotePort.mode" style="width: 100px">
                  <el-option value="any" label="任意" />
                  <el-option value="single" label="单端口" />
                  <el-option value="range" label="范围" />
                </el-select>
                <el-input-number v-if="remotePort.mode === 'single'" v-model="remotePort.single" :min="0" :max="65535" />
                <template v-if="remotePort.mode === 'range'">
                  <el-input-number v-model="remotePort.start" :min="0" :max="65535" />
                  <span>-</span>
                  <el-input-number v-model="remotePort.end" :min="0" :max="65535" />
                </template>
              </div>
            </el-form-item>
            <el-form-item label="本地端口">
              <div class="port-edit">
                <el-select v-model="localPort.mode" style="width: 100px">
                  <el-option value="any" label="任意" />
                  <el-option value="single" label="单端口" />
                  <el-option value="range" label="范围" />
                </el-select>
                <el-input-number v-if="localPort.mode === 'single'" v-model="localPort.single" :min="0" :max="65535" />
                <template v-if="localPort.mode === 'range'">
                  <el-input-number v-model="localPort.start" :min="0" :max="65535" />
                  <span>-</span>
                  <el-input-number v-model="localPort.end" :min="0" :max="65535" />
                </template>
              </div>
            </el-form-item>
          </el-tab-pane>
        </el-tabs>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveRule">保存</el-button>
      </template>
    </el-dialog>

  <!-- 导入预览：展示条数与冲突统计，确认后按所选模式执行 -->
  <el-dialog v-model="importDialogVisible" title="导入规则" width="480px">
    <p v-if="importPreview">
      共解析到 <strong>{{ importPreview.total }}</strong> 条规则
      <template v-if="importPreview.conflicts > 0">
        ，其中 <strong style="color: var(--el-color-warning)">{{ importPreview.conflicts }}</strong> 条与现有规则重名（同名且同进程路径）
      </template>
      。
    </p>
    <el-form label-width="90px">
      <el-form-item label="导入模式">
        <el-radio-group v-model="importMode">
          <el-radio value="Merge">合并（跳过重复）</el-radio>
          <el-radio value="Replace">替换（清空现有用户规则）</el-radio>
        </el-radio-group>
      </el-form-item>
    </el-form>
    <p v-if="importMode === 'Replace'" class="import-warning">
      替换模式将删除全部现有用户规则（内置系统规则不受影响），且不可撤销。
    </p>
    <template #footer>
      <el-button @click="importDialogVisible = false">取消</el-button>
      <el-button type="primary" :loading="importing" @click="confirmImport">确认导入</el-button>
    </template>
  </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { ElMessage, ElMessageBox } from 'element-plus'

// 与后端 Rule 模型对齐：
// PortRange 序列化为 {"Single": port} 或 {"Range": [start, end]}（serde 外部标签元组体）
type PortRange = { Single: number } | { Range: [number, number] }

interface PortEdit {
  mode: 'any' | 'single' | 'range'
  single: number
  start: number
  end: number
}

interface Rule {
  id?: number
  name: string
  description: string
  enabled: boolean
  priority: number
  action: 'Allow' | 'Block'
  direction: 'Inbound' | 'Outbound' | 'Both'
  protocol?: 'Tcp' | 'Udp' | 'Icmp' | 'Icmpv6' | 'Any' | null
  process_id?: number | null
  process_path?: string | null
  remote_addr?: string | null
  remote_domain?: string | null
  remote_addr_mask?: number | null
  remote_port?: PortRange | null
  local_addr?: string | null
  local_addr_mask?: number | null
  local_port?: PortRange | null
  network_zone?: 'Localhost' | 'Lan' | 'Internet' | null
  app_group_id?: number | null
  created_at?: string | null
  updated_at?: string | null
}

interface RulePage {
  total: number
  rules: Rule[]
}

const rules = ref<Rule[]>([])
const groups = ref<AppGroupOption[]>([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const loading = ref(false)
const searchText = ref('')
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const saving = ref(false)

interface AppGroupOption {
  id: number
  name: string
}

const emptyForm = (): Rule => ({
  name: '',
  description: '',
  enabled: true,
  priority: 100,
  action: 'Allow',
  direction: 'Both',
  protocol: null,
  process_path: null,
  app_group_id: null,
  remote_addr: null,
  remote_domain: null,
  remote_addr_mask: null,
  remote_port: null,
  local_port: null,
  network_zone: null
})

// 精确域名或前导 "*. " 通配（与服务端 validate_domain 一致的前端预检）
const domainRulePattern = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/

const form = ref<Rule>(emptyForm())
const remotePort = reactive<PortEdit>({ mode: 'any', single: 0, start: 0, end: 0 })
const localPort = reactive<PortEdit>({ mode: 'any', single: 0, start: 0, end: 0 })

const portToEdit = (p?: PortRange | null): PortEdit => {
  if (!p) return { mode: 'any', single: 0, start: 0, end: 0 }
  if ('Single' in p) return { mode: 'single', single: p.Single, start: p.Single, end: p.Single }
  return { mode: 'range', single: p.Range[0], start: p.Range[0], end: p.Range[1] }
}

const editToPort = (e: PortEdit): PortRange | null => {
  if (e.mode === 'any') return null
  if (e.mode === 'single') return { Single: Number(e.single) || 0 }
  return { Range: [Number(e.start) || 0, Number(e.end) || 0] }
}

const protocolText = (p?: string | null): string => {
  const map: Record<string, string> = { Tcp: 'TCP', Udp: 'UDP', Icmp: 'ICMP', Icmpv6: 'ICMPv6', Any: '任意' }
  return p ? (map[p] || p) : '任意'
}
const directionText = (d?: string | null): string => {
  const map: Record<string, string> = { Inbound: '入站', Outbound: '出站', Both: '全部' }
  return d ? (map[d] || d) : '全部'
}
const zoneText = (z?: string | null): string => {
  const map: Record<string, string> = { Localhost: '本机', Lan: '局域网', Internet: '互联网' }
  return z ? (map[z] || z) : '任意'
}
const portRangeText = (p?: PortRange | null): string => {
  if (!p) return '任意'
  if ('Single' in p) return String(p.Single)
  return `${p.Range[0]}-${p.Range[1]}`
}

const fetchPage = (): Promise<RulePage> =>
  invoke<RulePage>('list_rules', {
    offset: (currentPage.value - 1) * pageSize.value,
    limit: pageSize.value,
    // 空串归一为 null，服务端视为无搜索条件
    search: searchText.value.trim() || null
  })

// 请求序列号守卫（同 Dashboard.loadStatistics）：size 切换会同时触发
// current-change + size-change、删除末页唯一规则回退时会连拉两次——旧响应
// 后到不得把 rules.value 写成与 currentPage 不匹配的页
let rulesRequestId = 0

const loadRules = async () => {
  const req = ++rulesRequestId
  loading.value = true
  try {
    let page = await fetchPage()
    if (req !== rulesRequestId) return
    // 删除/保存后当前页可能超出总页数，回退到最后一页再拉（守卫天然
    // 消除旧的双重拉取竞态）
    const totalPages = Math.max(1, Math.ceil(page.total / pageSize.value))
    if (currentPage.value > totalPages) {
      currentPage.value = totalPages
      page = await fetchPage()
      if (req !== rulesRequestId) return
    }
    total.value = page.total
    rules.value = page.rules
  } catch (error) {
    ElMessage.error('加载规则失败')
    console.error(error)
  } finally {
    // 只有仍是最新请求才复位 loading，避免被顶掉的旧请求提前熄灯
    if (req === rulesRequestId) {
      loading.value = false
    }
  }
}

const onSizeChange = () => {
  // 页码归位到 1 并显式拉取：el-pagination 的 current-change 只在内部页码
  // 实际变化时触发，页码本就是 1 时不会触发，必须显式调用兜底；若组件
  // 额外触发了 current-change 造成并发，靠 loadRules 的序号守卫去重
  currentPage.value = 1
  loadRules()
}

// 搜索：300ms 防抖，回车/清空立即触发；触发时页码归 1 再拉取
let searchTimer: number | null = null
const onSearchInput = () => {
  if (searchTimer !== null) window.clearTimeout(searchTimer)
  searchTimer = window.setTimeout(triggerSearch, 300)
}
const triggerSearch = () => {
  if (searchTimer !== null) {
    window.clearTimeout(searchTimer)
    searchTimer = null
  }
  currentPage.value = 1
  loadRules()
}

onUnmounted(() => {
  if (searchTimer !== null) window.clearTimeout(searchTimer)
})

const loadGroups = async () => {
  try {
    groups.value = await invoke<AppGroupOption[]>('list_app_groups')
  } catch (error) {
    console.error('加载应用分组失败:', error)
  }
}

const groupName = (id: number): string =>
  groups.value.find((g) => g.id === id)?.name ?? String(id)

const openAddDialog = () => {
  editingId.value = null
  form.value = emptyForm()
  Object.assign(remotePort, portToEdit(null))
  Object.assign(localPort, portToEdit(null))
  dialogVisible.value = true
}

const editRule = (rule: Rule) => {
  editingId.value = rule.id ?? null
  form.value = JSON.parse(JSON.stringify(rule))
  Object.assign(remotePort, portToEdit(rule.remote_port))
  Object.assign(localPort, portToEdit(rule.local_port))
  dialogVisible.value = true
}

// ---------- 导入/导出 ----------
const exporting = ref(false)
const importing = ref(false)
const importDialogVisible = ref(false)
const importMode = ref<'Merge' | 'Replace'>('Merge')
const importFileInput = ref<HTMLInputElement | null>(null)
const importPreview = ref<{ total: number; conflicts: number; rules: ExportedRule[] } | null>(null)

// 与后端 service/src/models.rs 的 RULE_EXPORT_SCHEMA 保持一致
const RULE_EXPORT_SCHEMA = 1

interface ExportedRule {
  name: string
  description: string
  enabled: boolean
  priority: number
  action: 'Allow' | 'Block'
  direction: 'Inbound' | 'Outbound' | 'Both'
  protocol?: string | null
  process_path?: string | null
  remote_addr?: string | null
  remote_addr_mask?: number | null
  remote_domain?: string | null
  remote_port?: PortRange | null
  local_addr?: string | null
  local_addr_mask?: number | null
  local_port?: PortRange | null
  network_zone?: string | null
  group?: string | null
}

const exportRules = async () => {
  exporting.value = true
  try {
    const json = await invoke<string>('export_rules')
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ceasefire-rules-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('规则已导出')
  } catch (error) {
    ElMessage.error('导出规则失败')
    console.error(error)
  } finally {
    exporting.value = false
  }
}

const triggerImportFile = () => {
  importFileInput.value?.click()
}

const onImportFile = async (ev: Event) => {
  const input = ev.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  try {
    const text = await file.text()
    const parsed = JSON.parse(text)
    // schema 版本校验必须与服务端 service/src/models.rs 的 RULE_EXPORT_SCHEMA
    // 对应：版本不符整批拒绝，不做任何兜底解析（老格式/裸数组一律不收）
    if (parsed.schema === undefined) {
      ElMessage.error('缺少 schema 字段，可能不是 Ceasefire 导出文件')
      return
    }
    if (parsed.schema !== RULE_EXPORT_SCHEMA) {
      ElMessage.error(`不支持的导出文件版本：${parsed.schema}（当前支持 ${RULE_EXPORT_SCHEMA}）`)
      return
    }
    const rules: ExportedRule[] = parsed.rules
    if (!Array.isArray(rules) || rules.length === 0) {
      ElMessage.warning('文件中没有可导入的规则')
      return
    }
    // 冲突预览：同名且同进程路径视为重复（与 Merge 模式判重口径一致）
    const existing = await invoke<RulePage>('list_rules', { offset: 0, limit: 100000, search: null })
    const conflicts = rules.filter((r) =>
      existing.rules.some((e) => e.name === r.name && (e.process_path ?? null) === (r.process_path ?? null))
    ).length
    importPreview.value = { total: rules.length, conflicts, rules }
    importMode.value = 'Merge'
    importDialogVisible.value = true
  } catch (error) {
    ElMessage.error('解析导入文件失败：不是有效的规则导出文件')
    console.error(error)
  }
}

const confirmImport = async () => {
  if (!importPreview.value) return
  importing.value = true
  try {
    const stats = await invoke<{ imported: number; skipped: number; groups_created: number }>('import_rules', {
      rules: importPreview.value.rules,
      mode: importMode.value
    })
    importDialogVisible.value = false
    ElMessage.success(`导入完成：新增 ${stats.imported} 条，跳过 ${stats.skipped} 条，新建分组 ${stats.groups_created} 个`)
    await loadRules()
  } catch (error) {
    ElMessage.error(String(error) || '导入失败')
    console.error(error)
  } finally {
    importing.value = false
  }
}

const saveRule = async () => {
  if (!form.value.name.trim() || !form.value.description.trim()) {
    ElMessage.warning('名称和描述为必填项')
    return
  }
  const domain = (form.value.remote_domain || '').trim()
  form.value.remote_domain = domain || null
  if (domain && form.value.remote_addr) {
    ElMessage.warning('远程域名与远程地址互斥，请只填其一')
    return
  }
  if (domain && !domainRulePattern.test(domain)) {
    ElMessage.warning('域名格式无效（支持精确域名或前导 *. 通配）')
    return
  }
  if (domain) {
    form.value.remote_addr = null
    form.value.remote_addr_mask = null
  }
  saving.value = true
  try {
    form.value.remote_port = editToPort(remotePort)
    form.value.local_port = editToPort(localPort)
    // 进程路径与分组二选一：清空分组时 select 会给 ''，归一为 null
    if (form.value.app_group_id == null || (form.value.app_group_id as unknown) === '') {
      form.value.app_group_id = null
    }
    if (editingId.value != null) {
      await invoke('update_rule', { id: editingId.value, rule: form.value })
      ElMessage.success('规则更新成功')
    } else {
      await invoke('create_rule', { rule: form.value })
      ElMessage.success('规则创建成功')
    }
    dialogVisible.value = false
    await loadRules()
  } catch (error) {
    ElMessage.error('保存规则失败')
    console.error(error)
  } finally {
    saving.value = false
  }
}

const deleteRule = async (rule: Rule) => {
  try {
    await ElMessageBox.confirm(`确定要删除规则 "${rule.name}" 吗？`, '确认', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
    await invoke('delete_rule', { id: rule.id })
    ElMessage.success('规则删除成功')
    await loadRules()
  } catch (error) {
    // 'cancel'=点取消，'close'=ESC/点关闭按钮，均为用户主动放弃而非失败
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error('删除规则失败')
      console.error(error)
    }
  }
}

const toggleRule = async (rule: Rule) => {
  try {
    await invoke('toggle_rule', { id: rule.id })
    ElMessage.success('规则状态已更新')
    await loadRules()
  } catch (error) {
    ElMessage.error('更新规则状态失败')
    console.error(error)
  }
}

onMounted(() => {
  loadRules()
  loadGroups()
})
</script>

<style scoped>
.rule-manager {
  padding: 0;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.header h1 {
  margin: 0;
  color: #1f1f1f;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}

.port-edit {
  display: flex;
  gap: 8px;
  align-items: center;
}

.form-tip {
  color: #909399;
  font-size: 12px;
  line-height: 1.4;
  width: 100%;
}

/* 弹窗内容可滚动，保证底部保存/取消按钮始终可见 */
.rule-dialog :deep(.el-dialog__body) {
  max-height: 60vh;
  overflow: auto;
}
</style>
