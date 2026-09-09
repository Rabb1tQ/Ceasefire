/**
 * Dashboard 图表数据转换纯函数（vitest 覆盖）。
 *
 * 服务端的时序聚合（aggregate_app_timeline / aggregate_action_trend）只做
 * SQL 侧分桶，不做空桶填充、不做 Top-N 截断；这些展示层的整理工作全部
 * 收敛到本文件的纯函数里，方便单测。
 */

export interface TimelinePoint {
  timestamp: string
  process_path: string
  process_name?: string | null
  bytes_sent: number
  bytes_received: number
}

export interface ActionTrendRawPoint {
  timestamp: string
  allowed_bytes: number
  blocked_bytes: number
  allowed_count: number
  blocked_count: number
}

export interface StackedSeries {
  /** 对齐后的时间轴（ISO 字符串，升序去重） */
  timestamps: string[]
  /** 每个系列一条；Top-N 之外的进程合并进"其他" */
  series: { name: string; path: string; data: (number | null)[] }[]
}

/** 三档时间范围对应的显示桶宽（毫秒）。7 天视图按天聚合（页面需注明）。 */
export function bucketMsFor(rangeHours: number): number {
  if (rangeHours <= 1) return 5 * 60 * 1000
  if (rangeHours <= 24) return 60 * 60 * 1000
  return 24 * 60 * 60 * 1000
}

/** RFC3339 → 毫秒；解析失败返回 null（坏行由调用方丢弃） */
export function parseTimestampMs(iso: string): number | null {
  const ms = Date.parse(iso)
  return Number.isNaN(ms) ? null : ms
}

/** 把任意粒度的点按 rangeHours 对应的桶宽重新聚合（同桶字节求和） */
export function aggregateTimeline(
  points: TimelinePoint[],
  rangeHours: number
): TimelinePoint[] {
  const bucketMs = bucketMsFor(rangeHours)
  const merged = new Map<string, TimelinePoint>()
  for (const p of points) {
    const ms = parseTimestampMs(p.timestamp)
    if (ms === null) continue
    const bucket = Math.floor(ms / bucketMs) * bucketMs
    const key = `${bucket}\u0000${p.process_path}`
    const existing = merged.get(key)
    if (existing) {
      existing.bytes_sent += p.bytes_sent || 0
      existing.bytes_received += p.bytes_received || 0
    } else {
      merged.set(key, {
        timestamp: new Date(bucket).toISOString(),
        process_path: p.process_path,
        process_name: p.process_name ?? null,
        bytes_sent: p.bytes_sent || 0,
        bytes_received: p.bytes_received || 0,
      })
    }
  }
  return [...merged.values()].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
}

/**
 * 构建按应用堆叠的时序系列：总流量（上传+下载）前 topN 名进程各一条系列，
 * 其余合并为"其他"。时间轴取全部点的并集；某进程在某桶无数据时补 0。
 */
export function buildStackedTrafficSeries(
  points: TimelinePoint[],
  topN = 8
): StackedSeries {
  if (points.length === 0) return { timestamps: [], series: [] }

  // 时间轴并集（升序去重）
  const timeSet = new Set<string>()
  for (const p of points) timeSet.add(p.timestamp)
  const timestamps = [...timeSet].sort(
    (a, b) => Date.parse(a) - Date.parse(b)
  )
  const timeIndex = new Map(timestamps.map((t, i) => [t, i]))

  // 每进程总量排名
  const totals = new Map<string, { name: string; total: number }>()
  for (const p of points) {
    const entry = totals.get(p.process_path) ?? {
      name: p.process_name || p.process_path,
      total: 0,
    }
    entry.total += (p.bytes_sent || 0) + (p.bytes_received || 0)
    totals.set(p.process_path, entry)
  }
  const ranked = [...totals.entries()].sort((a, b) => b[1].total - a[1].total)

  const top = ranked.slice(0, topN)
  const rest = ranked.slice(topN)

  // 每条系列按时间轴对齐，缺桶补 0
  const makeData = (path: string | null): (number | null)[] => {
    const data: (number | null)[] = timestamps.map(() => 0)
    for (const p of points) {
      if (path !== null && p.process_path !== path) continue
      if (path === null && totals.has(p.process_path) && top.some(([tp]) => tp === p.process_path)) continue
      if (path === null && !rest.some(([rp]) => rp === p.process_path)) continue
      const idx = timeIndex.get(p.timestamp)
      if (idx === undefined) continue
      data[idx] = (data[idx] ?? 0) + (p.bytes_sent || 0) + (p.bytes_received || 0)
    }
    return data
  }

  const series = top.map(([path, entry]) => ({
    name: entry.name,
    path,
    data: makeData(path),
  }))
  if (rest.length > 0) {
    series.push({ name: `其他（${rest.length}）`, path: '__others__', data: makeData(null) })
  }
  return { timestamps, series }
}

/** 放行/拦截趋势：返回按时间对齐的双序列（字节已含上下行之和） */
export function buildActionTrendSeries(points: ActionTrendRawPoint[]): {
  timestamps: string[]
  allowed: number[]
  blocked: number[]
} {
  const sorted = [...points].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
  return {
    timestamps: sorted.map((p) => p.timestamp),
    allowed: sorted.map((p) => p.allowed_bytes || 0),
    blocked: sorted.map((p) => p.blocked_bytes || 0),
  }
}

/** 时间轴标签格式化：1 小时/24 小时显示 HH:mm，7 天（按天聚合）显示 MM-DD */
export function formatTrendLabel(iso: string, rangeHours: number): string {
  const ms = parseTimestampMs(iso)
  if (ms === null) return iso
  const date = new Date(ms)
  if (rangeHours <= 24) {
    const hh = String(date.getHours()).padStart(2, '0')
    const mm = String(date.getMinutes()).padStart(2, '0')
    return `${hh}:${mm}`
  }
  const MM = String(date.getMonth() + 1).padStart(2, '0')
  const dd = String(date.getDate()).padStart(2, '0')
  return `${MM}-${dd}`
}
