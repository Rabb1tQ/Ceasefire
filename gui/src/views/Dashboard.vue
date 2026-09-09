<template>
  <div class="dashboard">
    <!-- Service Connection Warning -->
    <el-alert
      v-if="!serviceConnected"
      title="服务未连接"
      type="error"
      :description="serviceError || '无法连接到 Ceasefire 服务。请确保服务正在运行。'"
      show-icon
      :closable="false"
      class="service-alert"
    />

    <div class="dashboard-header">
      <h1>仪表盘</h1>
      <div class="header-controls">
        <el-select v-model="timeRange" size="default">
          <el-option label="1小时" :value="1" />
          <el-option label="24小时" :value="24" />
          <el-option label="7天（按天聚合）" :value="168" />
        </el-select>
        <el-button @click="loadStatistics" type="primary">刷新</el-button>
      </div>
    </div>

    <!-- Summary Stats -->
        <el-row :gutter="20" class="stats-cards">
          <el-col :xs="24" :sm="12" :md="8" :lg="4">
            <el-card class="stat-card">
              <div class="stat-value">{{ ensureNumber(stats.activeConnections) }}</div>
              <div class="stat-label">活动连接</div>
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="4">
            <el-card class="stat-card">
              <div class="stat-value">{{ formatBytes(ensureNumber(stats.totalBytesSent)) }}</div>
              <div class="stat-label">总上传</div>
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="4">
            <el-card class="stat-card">
              <div class="stat-value">{{ formatBytes(ensureNumber(stats.totalBytesReceived)) }}</div>
              <div class="stat-label">总下载</div>
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="4">
            <el-card class="stat-card blocked">
              <div class="stat-value">{{ ensureNumber(stats.blockedConnections) }}</div>
              <div class="stat-label">已阻止</div>
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="4">
            <el-card class="stat-card allowed">
              <div class="stat-value">{{ ensureNumber(stats.allowedConnections) }}</div>
              <div class="stat-label">已允许</div>
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="4">
            <el-card class="stat-card suspicious">
              <div class="stat-value">{{ ensureNumber(stats.suspiciousConnections) }}</div>
              <div class="stat-label">可疑连接</div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 按应用堆叠流量时序 + 放行/拦截趋势 -->
        <el-row :gutter="20" class="charts">
          <el-col :span="14" class="equal-height-col">
            <el-card class="fill-card">
              <template #header>
                <div class="card-header">
                  <span>应用流量时序（Top 8 + 其他）</span>
                </div>
              </template>
              <AppStackedAreaChart :points="timelinePoints" :range-hours="timeRange" />
            </el-card>
          </el-col>
          <el-col :span="10" class="equal-height-col">
            <el-card class="fill-card">
              <template #header>
                <div class="card-header">
                  <span>放行 / 拦截趋势</span>
                </div>
              </template>
              <ActionTrendChart :points="actionPoints" :range-hours="timeRange" />
            </el-card>
          </el-col>
        </el-row>

        <!-- Top Applications + Protocol Stats -->
        <el-row :gutter="20" class="charts">
          <el-col :span="14" class="equal-height-col">
            <el-card class="fill-card">
              <template #header>
                <div class="card-header">
                  <span>数据使用排行榜 (Top 10)</span>
                </div>
              </template>
              <AppRankBarChart :apps="appStats" @select="goProcessActivity" />
              <p class="chart-hint">点击条形可跳转到网络活动页查看该应用的连接明细</p>
            </el-card>
          </el-col>

          <!-- Protocol Stats -->
          <el-col :span="10" class="equal-height-col">
            <el-card class="fill-card">
              <template #header>
                <div class="card-header">
                  <span>按协议分类</span>
                </div>
              </template>
              <div class="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>协议</th>
                      <th>上传</th>
                      <th>下载</th>
                      <th>连接数</th>
                      <th>占比</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="stat in protocolStats" :key="stat.protocol">
                      <td>
                        <span class="protocol-badge" :class="stat.protocol.toLowerCase()">
                          {{ stat.protocol }}
                        </span>
                      </td>
                      <td>{{ formatBytes(stat.bytes_sent) }}</td>
                      <td>{{ formatBytes(stat.bytes_received) }}</td>
                      <td>{{ stat.connection_count }}</td>
                      <td>
                        <div class="progress-bar">
                          <div 
                            class="progress-fill" 
                            :style="{ width: getProtocolPercentage(stat) + '%' }"
                          ></div>
                          <span class="percentage">{{ getProtocolPercentage(stat).toFixed(1) }}%</span>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-if="protocolStats.length === 0" class="empty-state">暂无协议数据</div>
              </div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 目标主机排行 -->
        <el-row :gutter="20" class="charts">
          <el-col :span="24">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>目标主机排行 (Top 10)</span>
                </div>
              </template>
              <el-row :gutter="20">
                <el-col :xs="24" :md="selectedHost ? 14 : 24">
                  <TopHostsBarChart :hosts="topHosts" @select="selectHost" />
                  <p class="chart-hint">点击条形展开该主机的连接明细</p>
                </el-col>
                <el-col v-if="selectedHost" :xs="24" :md="10">
                  <div class="host-details">
                    <div class="host-details-header">
                      <strong class="mono">{{ selectedHost.domain || selectedHost.remote_addr }}</strong>
                      <el-tag v-if="selectedHost.domain" size="small" class="mono">{{ selectedHost.remote_addr }}</el-tag>
                      <el-button size="small" text @click="closeHostDetails">收起</el-button>
                    </div>
                    <el-descriptions v-if="hostDetails" :column="1" border size="small">
                      <el-descriptions-item label="总流量">{{ formatBytes(hostDetails.bytes_sent + hostDetails.bytes_received) }}</el-descriptions-item>
                      <el-descriptions-item label="上传 / 下载">
                        {{ formatBytes(hostDetails.bytes_sent) }} / {{ formatBytes(hostDetails.bytes_received) }}
                      </el-descriptions-item>
                      <el-descriptions-item label="连接数">{{ hostDetails.connection_count }}</el-descriptions-item>
                      <el-descriptions-item label="协议">{{ hostDetails.protocols.join('、') || '-' }}</el-descriptions-item>
                      <el-descriptions-item label="本地端口">{{ hostDetails.local_ports.join('、') || '-' }}</el-descriptions-item>
                      <el-descriptions-item label="远程端口">{{ hostDetails.remote_ports.join('、') || '-' }}</el-descriptions-item>
                      <el-descriptions-item label="首次出现">{{ hostDetails.first_seen || '-' }}</el-descriptions-item>
                      <el-descriptions-item label="最近出现">{{ hostDetails.last_seen || '-' }}</el-descriptions-item>
                    </el-descriptions>
                    <div v-else v-loading="hostDetailsLoading" class="host-details-loading">加载明细中…</div>
                  </div>
                </el-col>
              </el-row>
            </el-card>
          </el-col>
        </el-row>

        <!-- Country Stats -->
        <el-row :gutter="20" class="charts">
          <el-col :span="24">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>按目标国家分类 (Top 10)</span>
                </div>
              </template>
              <div class="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>国家/地区</th>
                      <th>上传</th>
                      <th>下载</th>
                      <th>总流量</th>
                      <th>连接数</th>
                      <th>占比</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="stat in topCountryStats" :key="stat.country_code">
                      <td>
                        <span class="flag">{{ getFlag(stat.country_code) }}</span>
                        {{ stat.country_name }}
                        <span class="country-code">({{ stat.country_code }})</span>
                      </td>
                      <td>{{ formatBytes(stat.bytes_sent) }}</td>
                      <td>{{ formatBytes(stat.bytes_received) }}</td>
                      <td>{{ formatBytes(stat.bytes_sent + stat.bytes_received) }}</td>
                      <td>{{ stat.connection_count }}</td>
                      <td>
                        <div class="progress-bar">
                          <div 
                            class="progress-fill" 
                            :style="{ width: getCountryPercentage(stat) + '%' }"
                          ></div>
                          <span class="percentage">{{ getCountryPercentage(stat).toFixed(1) }}%</span>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-if="countryStats.length === 0" class="empty-state">暂无国家数据</div>
              </div>
            </el-card>
          </el-col>
        </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { useRouter } from 'vue-router'
import AppStackedAreaChart from '../components/charts/AppStackedAreaChart.vue'
import ActionTrendChart from '../components/charts/ActionTrendChart.vue'
import AppRankBarChart from '../components/charts/AppRankBarChart.vue'
import TopHostsBarChart from '../components/charts/TopHostsBarChart.vue'
import type { TimelinePoint, ActionTrendRawPoint } from '../utils/dashboardTransform'

const router = useRouter()

interface GlobalStats {
  activeConnections: number
  totalBytesSent: number
  totalBytesReceived: number
  totalPacketsSent: number
  totalPacketsReceived: number
  blockedConnections: number
  allowedConnections: number
  suspiciousConnections: number
}

interface AppTrafficStats {
  process_name: string
  process_path: string
  bytes_sent: number
  bytes_received: number
  connection_count: number
}

// 服务端 AppTrafficStats 以 camelCase 序列化，加载时归一化为页面使用的 snake_case
const normalizeAppStat = (s: any): AppTrafficStats => ({
  process_name: s.processName ?? s.process_name ?? '',
  process_path: s.processPath ?? s.process_path ?? '',
  bytes_sent: s.bytesSent ?? s.bytes_sent ?? 0,
  bytes_received: s.bytesReceived ?? s.bytes_received ?? 0,
  connection_count: s.connectionCount ?? s.connection_count ?? 0
})

// ProtocolTrafficStats / CountryTrafficStats 同样是 camelCase 序列化
const normalizeProtocolStat = (s: any): ProtocolTrafficStats => ({
  protocol: s.protocol ?? '',
  bytes_sent: s.bytesSent ?? 0,
  bytes_received: s.bytesReceived ?? 0,
  connection_count: s.connectionCount ?? 0
})

const normalizeCountryStat = (s: any): CountryTrafficStats => ({
  country_code: s.countryCode ?? '',
  country_name: s.countryName ?? '',
  bytes_sent: s.bytesSent ?? 0,
  bytes_received: s.bytesReceived ?? 0,
  connection_count: s.connectionCount ?? 0
})

interface ProtocolTrafficStats {
  protocol: string
  bytes_sent: number
  bytes_received: number
  connection_count: number
}

interface CountryTrafficStats {
  country_code: string
  country_name: string
  bytes_sent: number
  bytes_received: number
  connection_count: number
}

const timeRange = ref(24)
const stats = ref<GlobalStats>({
  activeConnections: 0,
  totalBytesSent: 0,
  totalBytesReceived: 0,
  totalPacketsSent: 0,
  totalPacketsReceived: 0,
  blockedConnections: 0,
  allowedConnections: 0,
  suspiciousConnections: 0
})

// Ensure stats values are always numbers
const ensureNumber = (value: any): number => {
  const num = Number(value)
  return isNaN(num) ? 0 : num
}

const serviceConnected = ref(true)
const serviceError = ref<string | null>(null)

const appStats = ref<AppTrafficStats[]>([])
const protocolStats = ref<ProtocolTrafficStats[]>([])
const countryStats = ref<CountryTrafficStats[]>([])

// 图表增强数据：堆叠时序 / 放行拦截趋势 / 目标主机排行
const timelinePoints = ref<TimelinePoint[]>([])
const actionPoints = ref<ActionTrendRawPoint[]>([])
const topHosts = ref<{ remote_addr: string; domain?: string | null; bytes_sent: number; bytes_received: number; connection_count: number }[]>([])

let refreshInterval: number | null = null

// 占比分母用各自列表的流量总和：协议/国家统计与 appStats 是不同接口，
// appStats 为空时用它当分母会导致占比恒为 0
const protocolTrafficTotal = computed(() => {
  return protocolStats.value.reduce((sum, stat) =>
    sum + stat.bytes_sent + stat.bytes_received, 0
  )
})

const countryTrafficTotal = computed(() => {
  return countryStats.value.reduce((sum, stat) =>
    sum + stat.bytes_sent + stat.bytes_received, 0
  )
})

const topCountryStats = computed(() => {
  return [...countryStats.value].slice(0, 10)
})

const formatBytes = (bytes: number | undefined | null): string => {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return '0 B'
  if (bytes === 0) return '0 B'
  
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.max(0, Math.min(Math.floor(Math.log(Math.abs(bytes)) / Math.log(k)), sizes.length - 1))
  const value = Math.round(bytes / Math.pow(k, i) * 100) / 100
  const unit = sizes[i] || 'B'
  
  return `${value}\u00A0${unit}`
}

const loadStats = async () => {
  try {
    const result = await invoke<GlobalStats>('get_global_stats')
    // Ensure all numeric fields are valid numbers
    stats.value = {
      activeConnections: ensureNumber(result.activeConnections),
      totalBytesSent: ensureNumber(result.totalBytesSent),
      totalBytesReceived: ensureNumber(result.totalBytesReceived),
      totalPacketsSent: ensureNumber(result.totalPacketsSent),
      totalPacketsReceived: ensureNumber(result.totalPacketsReceived),
      blockedConnections: ensureNumber(result.blockedConnections),
      allowedConnections: ensureNumber(result.allowedConnections),
      suspiciousConnections: ensureNumber(result.suspiciousConnections)
    }
    serviceConnected.value = true
    serviceError.value = null
  } catch (error: any) {
    serviceConnected.value = false
    const errorMsg = error?.toString() || 'Unknown error'
    serviceError.value = errorMsg
    
    // Don't spam the console with repeated errors
    if (!loadStats.lastErrorTime || Date.now() - loadStats.lastErrorTime > 30000) {
      console.warn('Service connection issue:', errorMsg)
      loadStats.lastErrorTime = Date.now()
    }
  }
}
// Add error tracking property
loadStats.lastErrorTime = 0

// 请求序列号守卫：手动刷新 / 时间窗切换 / 并发轮询下，旧响应后到直接丢弃，
// 避免旧时间窗的数据覆盖新选中的时间窗
let loadStatisticsRequestId = 0

const loadStatistics = async () => {
  const requestId = ++loadStatisticsRequestId
  try {
    const [apps, protocols, countries] = await Promise.all([
      invoke('get_app_traffic_stats', { hours: timeRange.value }) as Promise<AppTrafficStats[]>,
      invoke('get_protocol_traffic_stats', { hours: timeRange.value }) as Promise<ProtocolTrafficStats[]>,
      invoke('get_country_traffic_stats', { hours: timeRange.value }) as Promise<CountryTrafficStats[]>
    ])
    // 响应期间时间窗可能已被再次切换，过期响应整体丢弃
    if (requestId !== loadStatisticsRequestId) return

    appStats.value = apps.map(normalizeAppStat).sort((a, b) => {
      const trafficA = a.bytes_sent + a.bytes_received
      const trafficB = b.bytes_sent + b.bytes_received
      return trafficB - trafficA
    })
    
    protocolStats.value = protocols.map(normalizeProtocolStat).sort((a, b) => {
      const trafficA = a.bytes_sent + a.bytes_received
      const trafficB = b.bytes_sent + b.bytes_received
      return trafficB - trafficA
    })
    
    countryStats.value = countries.map(normalizeCountryStat).sort((a, b) => {
      const trafficA = a.bytes_sent + a.bytes_received
      const trafficB = b.bytes_sent + b.bytes_received
      return trafficB - trafficA
    })
  } catch (error) {
    console.error('加载统计数据失败:', error)
  }
}

// 图表加载请求序列号守卫：快速切时间窗时旧响应后到不得覆盖新数据
let chartsRequestId = 0

const loadCharts = async () => {
  const requestId = ++chartsRequestId
  try {
    const [timeline, actions, hosts] = await Promise.all([
      invoke<TimelinePoint[]>('get_app_traffic_timeline', { hours: timeRange.value }),
      invoke<ActionTrendRawPoint[]>('get_action_trend', { hours: timeRange.value }),
      invoke<{ remote_addr: string; domain?: string | null; bytes_sent: number; bytes_received: number; connection_count: number }[]>('get_top_hosts', { hours: timeRange.value, limit: 10 })
    ])
    if (requestId !== chartsRequestId) return
    timelinePoints.value = timeline
    actionPoints.value = actions
    topHosts.value = hosts
    // 主机排行变化后旧明细可能已不在榜上：过期即收起
    if (selectedHost.value && !hosts.some((h) => h.remote_addr === selectedHost.value!.remote_addr)) {
      closeHostDetails()
    }
  } catch (error) {
    console.error('加载图表数据失败:', error)
  }
}

// 目标主机明细展开（反查域名由 top_hosts 填充，明细走独立 IPC）
interface RemoteHostDetails {
  remote_addr: string
  connection_count: number
  bytes_sent: number
  bytes_received: number
  first_seen?: string | null
  last_seen?: string | null
  protocols: string[]
  local_ports: number[]
  remote_ports: number[]
}

const selectedHost = ref<{ remote_addr: string; domain?: string | null } | null>(null)
const hostDetails = ref<RemoteHostDetails | null>(null)
const hostDetailsLoading = ref(false)
let hostDetailsRequestId = 0

const selectHost = async (host: { remote_addr: string; domain?: string | null }) => {
  // 重复点击同一主机 = 收起
  if (selectedHost.value?.remote_addr === host.remote_addr) {
    closeHostDetails()
    return
  }
  selectedHost.value = host
  hostDetails.value = null
  const requestId = ++hostDetailsRequestId
  hostDetailsLoading.value = true
  try {
    const details = await invoke<RemoteHostDetails | null>('get_remote_host_details', {
      remoteAddr: host.remote_addr,
      hours: timeRange.value
    })
    if (requestId !== hostDetailsRequestId) return
    if (selectedHost.value?.remote_addr !== host.remote_addr) return
    hostDetails.value = details
  } catch (error) {
    console.error('加载主机明细失败:', error)
  } finally {
    if (requestId === hostDetailsRequestId) {
      hostDetailsLoading.value = false
    }
  }
}

const closeHostDetails = () => {
  selectedHost.value = null
  hostDetails.value = null
  hostDetailsRequestId++
}

// 应用排行点击：跳网络活动页并按进程路径过滤
const goProcessActivity = (processPath: string) => {
  router.push({ path: '/network-activity', query: { process: processPath } })
}

const getProtocolPercentage = (stat: ProtocolTrafficStats): number => {
  if (protocolTrafficTotal.value === 0) return 0
  return ((stat.bytes_sent + stat.bytes_received) / protocolTrafficTotal.value) * 100
}

const getCountryPercentage = (stat: CountryTrafficStats): number => {
  if (countryTrafficTotal.value === 0) return 0
  return ((stat.bytes_sent + stat.bytes_received) / countryTrafficTotal.value) * 100
}

const getFlag = (countryCode: string): string => {
  const flagMap: Record<string, string> = {
    'US': '🇺🇸',
    'CN': '🇨🇳',
    'JP': '🇯🇵',
    'DE': '🇩🇪',
    'GB': '🇬🇧',
    'FR': '🇫🇷',
    'KR': '🇰🇷',
    'IN': '🇮🇳',
    'RU': '🇷🇺',
    'BR': '🇧🇷',
    'AU': '🇦🇺',
    'CA': '🇨🇦',
    'SG': '🇸🇬',
    'HK': '🇭🇰',
    'TW': '🇹🇼',
    'NL': '🇳🇱',
    'IT': '🇮🇹',
    'ES': '🇪🇸',
    'MX': '🇲🇽',
    'ID': '🇮🇩'
  }
  return flagMap[countryCode] || '🌍'
}

watch(timeRange, () => {
  loadStatistics()
  loadCharts()
  // 时间窗切换后旧明细不再对应新窗口
  closeHostDetails()
})

onMounted(async () => {
  await loadStats()
  await loadStatistics()
  await loadCharts()

  refreshInterval = window.setInterval(() => {
    loadStats()
    loadCharts()
  }, 5000) // Update every 5 seconds
})

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
  }
})
</script>

<style scoped>
.dashboard {
  padding: 0;
}

.service-alert {
  margin-bottom: 16px;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.dashboard-header h1 {
  color: #1f1f1f;
  margin: 0;
  font-size: 24px;
  line-height: 1.3;
}

.header-controls {
  display: flex;
  gap: 12px;
  align-items: center;
}

.stats-cards {
  margin-bottom: 16px;
}

.stat-card {
  text-align: center;
  border: 1px solid #d9d9d9;
  min-height: 100px;
  height: 100%;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.stat-card.blocked {
  border-left: 4px solid #d13438;
}

.stat-card.allowed {
  border-left: 4px solid #107c10;
}

.stat-card.suspicious {
  border-left: 4px solid #ca5010;
}

.stat-value {
  font-size: clamp(18px, 3vw, 28px);
  font-weight: 600;
  color: #0078d4;
  margin-bottom: 8px;
  font-family: 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif;
  white-space: nowrap;
  line-height: 1.2;
  padding: 0 8px;
}

.stat-card.blocked .stat-value {
  color: #d13438;
}

.stat-card.allowed .stat-value {
  color: #107c10;
}

.stat-card.suspicious .stat-value {
  color: #ca5010;
}

.stat-label {
  font-size: clamp(11px, 1.5vw, 13px);
  color: #605e5c;
  font-weight: 400;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 0 8px;
}

.chart-hint {
  margin: 4px 0 0;
  font-size: 12px;
  color: #8a8886;
}

.host-details {
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  padding: 12px;
  height: 100%;
}

.host-details-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}

.host-details-loading {
  min-height: 120px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #8a8886;
}

.mono {
  font-family: Consolas, 'Courier New', monospace;
}

/* 响应式布局调整 */
@media (max-width: 1200px) {
  .stat-card {
    min-height: 90px;
  }
}

@media (max-width: 768px) {
  .stat-card {
    min-height: 85px;
  }
  
  .stats-cards {
    margin-bottom: 12px;
  }
  
  .stats-cards :deep(.el-col) {
    margin-bottom: 8px;
  }
  
  .stats-cards :deep(.el-col:last-child) {
    margin-bottom: 0;
  }
}

.controls {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px;
  background-color: #ffffff;
  border: 1px solid #d9d9d9;
}

.filter-group {
  display: flex;
  align-items: center;
  gap: 8px;
}

.filter-group label {
  font-weight: 500;
  font-size: 13px;
  color: #1f1f1f;
}

.charts {
  margin-top: 16px;
}

.card-header {
  font-weight: 600;
  color: #1f1f1f;
  font-size: 14px;
}

.top-list {
  display: flex;
  flex-direction: column;
}

.top-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-bottom: 1px solid #e0e0e0;
  transition: background-color 0.1s;
}

.top-item:hover {
  background-color: #f3f3f3;
}

.rank {
  width: 28px;
  height: 28px;
  background-color: #0078d4;
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  font-size: 13px;
  flex-shrink: 0;
}

.top-item:nth-child(1) .rank {
  background-color: #ffca28;
  color: #1f1f1f;
}

.top-item:nth-child(2) .rank {
  background-color: #cfd8dc;
  color: #1f1f1f;
}

.top-item:nth-child(3) .rank {
  background-color: #bcaaa4;
  color: #1f1f1f;
}

.app-info {
  flex: 1;
  min-width: 0;
}

.app-name {
  font-weight: 600;
  margin-bottom: 3px;
  font-size: 13px;
  color: #1f1f1f;
}

.app-path {
  font-size: 11px;
  color: #605e5c;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.app-traffic {
  text-align: right;
  flex-shrink: 0;
}

.traffic-value {
  font-size: 13px;
  font-weight: 600;
  color: #0078d4;
  margin-bottom: 3px;
}

.traffic-detail {
  font-size: 11px;
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.upload {
  color: #107c10;
}

.download {
  color: #0078d4;
}

/* 同行卡片等高：el-row 已 flex+stretch，让卡片填满 el-col 并随内容自然撑高 */
.equal-height-col {
  display: flex;
}

.fill-card {
  width: 100%;
  display: flex;
  flex-direction: column;
}

.fill-card :deep(.el-card__body) {
  flex: 1;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 8px 12px;
  text-align: left;
  border-bottom: 1px solid #e0e0e0;
  font-size: 13px;
}

th {
  background: #f3f3f3;
  font-weight: 600;
  position: sticky;
  top: 0;
  color: #1f1f1f;
}

.flag {
  font-size: 14px;
  margin-right: 6px;
}

.country-code {
  color: #605e5c;
  font-size: 11px;
}

.progress-bar {
  position: relative;
  height: 16px;
  background: #f3f3f3;
  overflow: hidden;
  width: 80px;
}

.progress-fill {
  height: 100%;
  background: #0078d4;
  transition: width 0.2s ease;
}

.percentage {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  font-size: 10px;
  font-weight: 600;
  color: #1f1f1f;
  text-shadow: 0 0 2px rgba(255,255,255,0.8);
}

.protocol-badge {
  display: inline-block;
  padding: 3px 8px;
  font-size: 11px;
  font-weight: 600;
  background-color: #f3f3f3;
  color: #1f1f1f;
}

.protocol-badge.tcp {
  background-color: #eff6fc;
  color: #0078d4;
}

.protocol-badge.udp {
  background-color: #fdf4ec;
  color: #d83b01;
}

.protocol-badge.icmp {
  background-color: #fde7e9;
  color: #a80000;
}

.protocol-badge.any {
  background-color: #f3f2f1;
  color: #323130;
}

.empty-state {
  text-align: center;
  padding: 32px;
  color: #605e5c;
  font-size: 13px;
}
</style>