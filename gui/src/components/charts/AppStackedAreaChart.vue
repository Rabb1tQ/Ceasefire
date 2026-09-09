<script setup lang="ts">
/** 按应用堆叠的流量时序面积图（Top8 + 其他） */
import { computed } from 'vue'
import BaseChart from './BaseChart.vue'
import {
  aggregateTimeline,
  buildStackedTrafficSeries,
  formatTrendLabel,
  type TimelinePoint,
} from '../../utils/dashboardTransform'

const props = defineProps<{
  points: TimelinePoint[]
  rangeHours: number
}>()

const PALETTE = [
  '#0078d4', '#107c10', '#ca5010', '#5c2d91',
  '#008272', '#e3008c', '#018574', '#744da9', '#8a8886',
]

const option = computed(() => {
  // 时间轴对齐按视图桶宽做（7 天视图按天聚合）
  const agg = aggregateTimeline(props.points, props.rangeHours)
  const stacked = buildStackedTrafficSeries(agg, 8)
  if (stacked.timestamps.length === 0) return null
  const labels = stacked.timestamps.map((t) => formatTrendLabel(t, props.rangeHours))
  return {
    tooltip: {
      trigger: 'axis',
      confine: true,
      valueFormatter: (value: number) => formatBytesLabel(value ?? 0),
    },
    legend: { top: 0, type: 'scroll' },
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
    series: stacked.series.map((s, i) => ({
      name: s.name,
      type: 'line',
      stack: 'total',
      smooth: true,
      data: s.data,
      areaStyle: { opacity: 0.4 },
      itemStyle: { color: PALETTE[i % PALETTE.length] },
    })),
  }
})

function formatBytesLabel(bytes: number): string {
  if (!bytes || isNaN(bytes)) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.max(0, Math.min(Math.floor(Math.log(Math.abs(bytes)) / Math.log(k)), sizes.length - 1))
  return `${Math.round((bytes / Math.pow(k, i)) * 100) / 100} ${sizes[i]}`
}

const hasData = computed(() => {
  return props.points.some((p) => (p.bytes_sent || 0) + (p.bytes_received || 0) > 0)
})
</script>

<template>
  <BaseChart :option="option" :has-data="hasData" empty-text="暂无流量数据" height="320px" />
</template>
