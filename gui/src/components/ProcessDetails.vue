<template>
  <div class="process-details">
    <el-tabs v-model="activeTab">
      <!-- 基本信息 -->
      <el-tab-pane label="基本信息" name="basic">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="进程名称">{{ process.process_name }}</el-descriptions-item>
          <el-descriptions-item label="当前行为">
            <el-tag v-if="process.action === 'Allow'" type="success" size="small">允许</el-tag>
            <el-tag v-else-if="process.action === 'Block'" type="danger" size="small">阻止</el-tag>
            <el-tag v-else type="info" size="small">无规则</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="文件路径" :span="2">{{ process.process_path }}</el-descriptions-item>
          <el-descriptions-item label="连接数">{{ process.connection_count }}</el-descriptions-item>
          <el-descriptions-item label="规则ID">{{ process.rule_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="上传流量">{{ formatBytes(process.bytes_sent) }}</el-descriptions-item>
          <el-descriptions-item label="下载流量">{{ formatBytes(process.bytes_received) }}</el-descriptions-item>
          <el-descriptions-item label="总流量">{{ formatBytes(process.bytes_sent + process.bytes_received) }}</el-descriptions-item>
          <el-descriptions-item label="最后活动">{{ formatTimestamp(process.last_seen) }}</el-descriptions-item>
        </el-descriptions>
      </el-tab-pane>

      <!-- 网络历史 -->
      <el-tab-pane label="网络历史" name="history">
        <div v-if="loadingHistory" class="loading-text">加载中...</div>
        <div v-else-if="networkHistory.length === 0" class="empty-text">暂无历史记录</div>
        <el-table v-else :data="networkHistory" stripe style="width: 100%" max-height="400">
          <el-table-column prop="timestamp" label="时间" width="180">
            <template #default="{ row }">
              {{ formatTimestamp(row.timestamp) }}
            </template>
          </el-table-column>
          <el-table-column prop="action" label="动作" width="100">
            <template #default="{ row }">
              <el-tag :type="row.action === 'Allow' ? 'success' : 'danger'" size="small">
                {{ row.action === 'Allow' ? '允许' : '阻止' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="protocol" label="协议" width="100" />
          <el-table-column prop="direction" label="方向" width="100" />
          <el-table-column prop="remote_addr" label="远程地址" min-width="180">
            <template #default="{ row }">
              {{ row.remote_addr }}:{{ row.remote_port }}
            </template>
          </el-table-column>
          <el-table-column prop="bytes_sent" label="上传" width="120">
            <template #default="{ row }">
              {{ formatBytes(row.bytes_sent) }}
            </template>
          </el-table-column>
          <el-table-column prop="bytes_received" label="下载" width="120">
            <template #default="{ row }">
              {{ formatBytes(row.bytes_received) }}
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 远程地址统计 -->
      <el-tab-pane label="远程地址" name="remotes">
        <div v-if="loadingHistory" class="loading-text">加载中...</div>
        <div v-else-if="remoteAddresses.length === 0" class="empty-text">暂无数据</div>
        <el-table v-else :data="remoteAddresses" stripe style="width: 100%" max-height="400">
          <el-table-column prop="address" label="远程地址" min-width="180" />
          <el-table-column prop="count" label="连接次数" width="120" sortable />
          <el-table-column prop="bytes_sent" label="上传" width="120" sortable>
            <template #default="{ row }">
              {{ formatBytes(row.bytes_sent) }}
            </template>
          </el-table-column>
          <el-table-column prop="bytes_received" label="下载" width="120" sortable>
            <template #default="{ row }">
              {{ formatBytes(row.bytes_received) }}
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { invoke } from '@tauri-apps/api/core'

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
}

interface NetworkHistoryRecord {
  timestamp: string
  action: 'Allow' | 'Block'
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  protocol: string
  direction: string
  bytes_sent: number
  bytes_received: number
}

const props = defineProps<{
  process: ProcessInfo
}>()

const activeTab = ref('basic')
const networkHistory = ref<NetworkHistoryRecord[]>([])
const loadingHistory = ref(false)

const remoteAddresses = computed(() => {
  const addressMap = new Map<string, { address: string; count: number; bytes_sent: number; bytes_received: number }>()
  
  networkHistory.value.forEach(record => {
    const key = `${record.remote_addr}:${record.remote_port}`
    const existing = addressMap.get(key)
    
    if (existing) {
      existing.count++
      existing.bytes_sent += record.bytes_sent
      existing.bytes_received += record.bytes_received
    } else {
      addressMap.set(key, {
        address: key,
        count: 1,
        bytes_sent: record.bytes_sent,
        bytes_received: record.bytes_received
      })
    }
  })
  
  return Array.from(addressMap.values()).sort((a, b) => b.count - a.count)
})

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

const formatTimestamp = (timestamp: string): string => {
  return new Date(timestamp).toLocaleString('zh-CN')
}

const loadNetworkHistory = async () => {
  loadingHistory.value = true
  try {
    const filters = {
      process_path: props.process.process_path,
      hours: 24,
      limit: 100
    }
    networkHistory.value = await invoke('get_network_history', { filters })
  } catch (error) {
    console.error('加载网络历史失败:', error)
  } finally {
    loadingHistory.value = false
  }
}

onMounted(() => {
  loadNetworkHistory()
})
</script>

<style scoped>
.process-details {
  min-height: 400px;
}

.loading-text,
.empty-text {
  text-align: center;
  padding: 32px;
  color: #909399;
  font-size: 14px;
}
</style>
