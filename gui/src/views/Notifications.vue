<template>
  <div class="notifications">
    <div class="header">
      <h1>通知</h1>
      <div class="header-actions">
        <el-button @click="loadAll" :loading="loading">刷新</el-button>
      </div>
    </div>

    <!-- 最近被拦截的连接：回溯处理 -->
    <el-card class="blocked-card">
      <template #header>
        <div>
          <span>最近被拦截的程序</span>
          <div class="description">
            默认拦截模式下被拦下的未知程序连接。可批量放行（生成允许规则）或明确阻止（生成阻止规则）。
          </div>
        </div>
      </template>

      <div v-if="loading" class="loading-text">加载中...</div>
      <div v-else-if="groupedBlocked.length === 0" class="empty-text">暂无被拦截的连接记录</div>
      <el-table v-else :data="groupedBlocked" stripe style="width: 100%">
        <el-table-column label="程序" min-width="220">
          <template #default="{ row }">
            <div class="process-info">
              <div class="process-name">{{ row.process_name || '-' }}</div>
              <div class="process-path font-mono truncate" :title="row.process_path">
                {{ row.process_path || '-' }}
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="count" label="拦截次数" width="90" sortable />
        <el-table-column label="最近目标" min-width="180">
          <template #default="{ row }">
            <span class="font-mono">{{ row.last_remote }}</span>
          </template>
        </el-table-column>
        <el-table-column label="最近时间" width="170">
          <template #default="{ row }">{{ formatTimestamp(row.last_seen) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="success" @click="batchProcess(row, 'Allow')">放行</el-button>
            <el-button link type="danger" @click="batchProcess(row, 'Block')">阻止</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { ElMessage, ElMessageBox } from 'element-plus'

interface HistoryRecord {
  id?: number
  timestamp: string
  action: string
  remote_addr: string
  remote_port: number
  direction: string
  process_name?: string | null
  process_path?: string | null
}

interface BlockedGroup {
  process_path: string
  process_name: string | null
  count: number
  last_remote: string
  last_seen: string
}

const loading = ref(false)
const blocked = ref<HistoryRecord[]>([])

const groupedBlocked = computed<BlockedGroup[]>(() => {
  const map = new Map<string, BlockedGroup>()
  for (const r of blocked.value) {
    const path = r.process_path || '(未知进程)'
    const entry = map.get(path)
    const remote = `${r.remote_addr}:${r.remote_port}`
    if (!entry) {
      map.set(path, {
        process_path: path,
        process_name: r.process_name || null,
        count: 1,
        last_remote: remote,
        last_seen: r.timestamp
      })
    } else {
      entry.count += 1
      if (r.timestamp > entry.last_seen) {
        entry.last_seen = r.timestamp
        entry.last_remote = remote
      }
    }
  }
  return [...map.values()].sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1))
})

const loadAll = async () => {
  loading.value = true
  try {
    blocked.value = await invoke<HistoryRecord[]>('get_network_history', {
      filters: { limit: 500, offset: 0, hours: 24, action: 'Block' }
    })
  } catch (error) {
    ElMessage.error('加载通知数据失败')
    console.error(error)
  } finally {
    loading.value = false
  }
}

// 批量处理：为被拦程序生成 Allow/Block 规则（按进程路径）
const batchProcess = async (group: BlockedGroup, action: 'Allow' | 'Block') => {
  const verb = action === 'Allow' ? '放行' : '阻止'
  try {
    await ElMessageBox.confirm(
      `确定${verb}程序 ${group.process_name || group.process_path} 的全部网络连接？将生成一条按进程路径匹配的${verb}规则。`,
      '确认',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' }
    )
    if (group.process_path === '(未知进程)') {
      ElMessage.warning('该记录没有进程路径，无法生成规则')
      return
    }
    await invoke('create_rule', {
      rule: {
        name: `[通知] ${group.process_name || '程序'} - ${verb}`,
        description: `从通知页批量处理：${verb} ${group.process_path}`,
        enabled: true,
        priority: 50,
        action,
        direction: 'Both',
        protocol: null,
        process_path: group.process_path,
        remote_port: null,
        local_port: null
      }
    })
    ElMessage.success(`已${verb} ${group.process_name || group.process_path}`)
  } catch (error) {
    // 'cancel'=点取消，'close'=ESC/点关闭按钮，均为用户主动放弃而非失败
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error('生成规则失败')
      console.error(error)
    }
  }
}

const formatTimestamp = (timestamp?: string): string => {
  if (!timestamp) return '-'
  return new Date(timestamp).toLocaleString('zh-CN')
}

onMounted(loadAll)
</script>

<style scoped>
.notifications {
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

.blocked-card {
  margin-bottom: 16px;
}

.description {
  color: #605e5c;
  font-size: 12px;
  margin-top: 4px;
}

.loading-text,
.empty-text {
  text-align: center;
  padding: 32px 20px;
  color: #605e5c;
  font-size: 13px;
}

.process-info {
  display: flex;
  flex-direction: column;
}

.process-name {
  font-size: 13px;
  color: #1f1f1f;
  font-weight: 600;
}

.process-path {
  font-size: 11px;
  color: #605e5c;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.font-mono {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 12px;
}
</style>
