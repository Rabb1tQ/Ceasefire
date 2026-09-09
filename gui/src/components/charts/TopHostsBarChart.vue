<script setup lang="ts">
/** 目标主机排行横向条形图（域名反查由父层填充进 host.domain）；点击展开明细 */
import { computed } from 'vue'
import BaseChart from './BaseChart.vue'

export interface TopHostItem {
  remote_addr: string
  domain?: string | null
  bytes_sent: number
  bytes_received: number
  connection_count: number
}

const props = defineProps<{
  hosts: TopHostItem[]
  topN?: number
}>()

const emit = defineEmits<{ (e: 'select', host: TopHostItem): void }>()

let chartRef: { getZr?: () => { on: (ev: string, cb: (params: unknown) => void) => void } } | null = null

const total = (h: TopHostItem) => (h.bytes_sent || 0) + (h.bytes_received || 0)

const ranked = computed(() =>
  [...props.hosts].sort((a, b) => total(b) - total(a)).slice(0, props.topN ?? 10).reverse()
)

const label = (h: TopHostItem) => h.domain || h.remote_addr

const option = computed(() => {
  if (ranked.value.length === 0) return null
  return {
    tooltip: {
      confine: true,
      formatter: (params: { dataIndex: number }) => {
        const h = ranked.value[params.dataIndex]
        if (!h) return ''
        return [
          `<b>${label(h)}</b>`,
          h.domain ? h.remote_addr : '',
          `总流量：${formatBytesLabel(total(h))}`,
          `上传：${formatBytesLabel(h.bytes_sent)} / 下载：${formatBytesLabel(h.bytes_received)}`,
          `连接数：${h.connection_count}`,
        ]
          .filter(Boolean)
          .join('<br/>')
      },
    },
    grid: { top: 8, left: '3%', right: '6%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { formatter: (v: number) => formatBytesLabel(v) },
    },
    yAxis: {
      type: 'category',
      data: ranked.value.map(label),
      axisLabel: { width: 130, overflow: 'truncate', fontSize: 11 },
    },
    series: [
      {
        type: 'bar',
        data: ranked.value.map((h) => total(h)),
        barMaxWidth: 18,
        itemStyle: { color: '#5c2d91', borderRadius: [0, 3, 3, 0] },
        cursor: 'pointer',
      },
    ],
  }
})

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
    const host = ranked.value[Math.round(index)]
    if (host) emit('select', host)
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
  <BaseChart :option="option" :has-data="hosts.length > 0" empty-text="暂无主机数据" height="320px" @chart="onChart" />
</template>
