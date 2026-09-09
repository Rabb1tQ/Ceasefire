<script setup lang="ts">
/** 应用流量排行横向条形图；点击应用跳网络活动页（父层处理路由） */
import { computed } from 'vue'
import BaseChart from './BaseChart.vue'

export interface AppRankItem {
  process_name: string
  process_path: string
  bytes_sent: number
  bytes_received: number
}

const props = defineProps<{
  apps: AppRankItem[]
  topN?: number
}>()

const emit = defineEmits<{ (e: 'select', processPath: string): void }>()

let chartRef: { getZr?: () => { on: (ev: string, cb: (params: unknown) => void) => void } } | null = null

const total = (a: AppRankItem) => (a.bytes_sent || 0) + (a.bytes_received || 0)

const ranked = computed(() =>
  [...props.apps].sort((a, b) => total(b) - total(a)).slice(0, props.topN ?? 10).reverse()
)

const option = computed(() => {
  if (ranked.value.length === 0) return null
  return {
    tooltip: {
      confine: true,
      formatter: (params: { name: string; value: number }) =>
        `${params.name}<br/>总流量：${formatBytesLabel(params.value)}`,
    },
    grid: { top: 8, left: '3%', right: '6%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { formatter: (v: number) => formatBytesLabel(v) },
    },
    yAxis: {
      type: 'category',
      data: ranked.value.map((a) => a.process_name || a.process_path),
      axisLabel: {
        width: 110,
        overflow: 'truncate',
        fontSize: 11,
      },
    },
    series: [
      {
        type: 'bar',
        data: ranked.value.map((a) => total(a)),
        barMaxWidth: 18,
        itemStyle: { color: '#0078d4', borderRadius: [0, 3, 3, 0] },
        cursor: 'pointer',
      },
    ],
  }
})

// 点击条形 → 选中对应应用（按 name 反查进程路径）
const onChart = (chart: unknown) => {
  chartRef = chart as typeof chartRef
  const zr = chartRef?.getZr?.()
  zr?.on('click', (params: unknown) => {
    const p = params as { offsetY?: number }
    const chartAny = chart as {
      convertFromPixel?: ({ yAxisIndex }: { yAxisIndex: number[] }, pixel: number[]) => number[]
    }
    if (!chartAny.convertFromPixel || p.offsetY === undefined) return
    const index = chartAny.convertFromPixel({ yAxisIndex: [0] }, [0, p.offsetY])[1] ?? -1
    const app = ranked.value[Math.round(index)]
    if (app) emit('select', app.process_path)
  })
}

function formatBytesLabel(bytes: number): string {
  if (!bytes || isNaN(bytes)) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.max(0, Math.min(Math.floor(Math.log(Math.abs(bytes)) / Math.log(k)), sizes.length - 1))
  return `${Math.round((bytes / Math.pow(k, i)) * 100) / 100} ${sizes[i]}`
}
</script>

<template>
  <BaseChart :option="option" :has-data="apps.length > 0" empty-text="暂无应用数据" height="320px" @chart="onChart" />
</template>
