<script setup lang="ts">
/** 放行/拦截趋势双序列面积图 */
import { computed } from 'vue'
import BaseChart from './BaseChart.vue'
import { buildActionTrendSeries, formatTrendLabel, type ActionTrendRawPoint } from '../../utils/dashboardTransform'

const props = defineProps<{
  points: ActionTrendRawPoint[]
  rangeHours: number
}>()

const option = computed(() => {
  const series = buildActionTrendSeries(props.points)
  if (series.timestamps.length === 0) return null
  const labels = series.timestamps.map((t) => formatTrendLabel(t, props.rangeHours))
  return {
    tooltip: {
      trigger: 'axis',
      confine: true,
      valueFormatter: (value: number) => formatBytesLabel(value ?? 0),
    },
    legend: { top: 0, data: ['放行', '拦截'] },
    grid: { top: 36, left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: labels,
      axisLabel: { rotate: props.rangeHours > 24 ? 0 : 45, interval: 'auto' },
    },
    yAxis: {
      type: 'value',
      axisLabel: { formatter: (v: number) => formatBytesLabel(v) },
      min: 0,
    },
    series: [
      {
        name: '放行',
        type: 'line',
        smooth: true,
        data: series.allowed,
        areaStyle: { opacity: 0.3 },
        itemStyle: { color: '#107c10' },
      },
      {
        name: '拦截',
        type: 'line',
        smooth: true,
        data: series.blocked,
        areaStyle: { opacity: 0.3 },
        itemStyle: { color: '#d13438' },
      },
    ],
  }
})

const hasData = computed(() => props.points.some((p) => p.allowed_bytes > 0 || p.blocked_bytes > 0))

function formatBytesLabel(bytes: number): string {
  if (!bytes || isNaN(bytes)) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.max(0, Math.min(Math.floor(Math.log(Math.abs(bytes)) / Math.log(k)), sizes.length - 1))
  return `${Math.round((bytes / Math.pow(k, i)) * 100) / 100} ${sizes[i]}`
}
</script>

<template>
  <BaseChart :option="option" :has-data="hasData" empty-text="暂无趋势数据" height="320px" />
</template>
