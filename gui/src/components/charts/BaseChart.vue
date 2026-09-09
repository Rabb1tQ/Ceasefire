<script setup lang="ts">
/**
 * 图表基座：统一 echarts 初始化 / resize / dispose / isDisposed 守卫，
 * 子组件只负责把 props 数据转成 option。
 */
import { ref, onMounted, onUnmounted, watch } from 'vue'
import * as echarts from 'echarts'

const props = withDefaults(
  defineProps<{
    height?: string
    /** 置空字符串表示无数据占位 */
    emptyText?: string
    /** 有数据才渲染 option；false 时显示 emptyText 占位 */
    hasData?: boolean
    option?: Record<string, unknown> | null
  }>(),
  { height: '300px', emptyText: '暂无数据', hasData: true, option: null }
)

const emit = defineEmits<{ (e: 'chart', chart: echarts.ECharts | null): void }>()

const el = ref<HTMLElement>()
let chart: echarts.ECharts | null = null
let resizeObserver: ResizeObserver | null = null

const applyOption = () => {
  // 卸载后在途的 props 变更不得操作已 dispose 的实例
  if (!chart || chart.isDisposed()) return
  if (props.hasData && props.option) {
    chart.setOption(props.option, true)
  }
}

onMounted(() => {
  if (!el.value) return
  chart = echarts.init(el.value)
  emit('chart', chart)
  applyOption()
  resizeObserver = new ResizeObserver(() => {
    if (chart && !chart.isDisposed()) chart.resize()
  })
  resizeObserver.observe(el.value)
})

watch(() => props.option, applyOption, { deep: true })

onUnmounted(() => {
  resizeObserver?.disconnect()
  chart?.dispose()
  chart = null
  emit('chart', null)
})
</script>

<template>
  <div class="base-chart">
    <div ref="el" :style="{ width: '100%', height }"></div>
    <div v-if="!hasData" class="chart-empty">{{ emptyText }}</div>
  </div>
</template>

<style scoped>
.base-chart {
  position: relative;
}

.chart-empty {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #999;
  font-size: 14px;
  pointer-events: none;
}
</style>
