import { describe, it, expect } from 'vitest'
import {
  bucketMsFor,
  parseTimestampMs,
  aggregateTimeline,
  buildStackedTrafficSeries,
  buildActionTrendSeries,
  formatTrendLabel,
  type TimelinePoint,
} from './dashboardTransform'

const HOUR = 3600 * 1000
const base = Date.UTC(2026, 8, 9, 12, 0, 0)

const pt = (
  offsetMs: number,
  path: string,
  sent: number,
  received = 0,
  name?: string
): TimelinePoint => ({
  timestamp: new Date(base + offsetMs).toISOString(),
  process_path: path,
  process_name: name ?? null,
  bytes_sent: sent,
  bytes_received: received,
})

describe('bucketMsFor', () => {
  it('picks 5min / 1h / 1d buckets for the three ranges', () => {
    expect(bucketMsFor(1)).toBe(5 * 60 * 1000)
    expect(bucketMsFor(24)).toBe(60 * 60 * 1000)
    expect(bucketMsFor(168)).toBe(24 * 60 * 60 * 1000)
  })
})

describe('parseTimestampMs', () => {
  it('returns null for garbage timestamps', () => {
    expect(parseTimestampMs('not-a-date')).toBeNull()
    expect(parseTimestampMs('2026-09-09T12:00:00Z')).toBe(base)
  })
})

describe('aggregateTimeline', () => {
  it('returns empty for empty input', () => {
    expect(aggregateTimeline([], 24)).toEqual([])
  })

  it('drops rows with unparseable timestamps', () => {
    const out = aggregateTimeline(
      [{ ...pt(0, 'a.exe', 10), timestamp: 'garbage' }],
      24
    )
    expect(out).toEqual([])
  })

  it('merges same-process points into one bucket per range', () => {
    // 1h 视图：5 分钟一桶，相隔 4 分钟的两点合并
    const out = aggregateTimeline([pt(0, 'a.exe', 10, 5), pt(4 * 60 * 1000, 'a.exe', 20)], 1)
    expect(out).toHaveLength(1)
    expect(out[0]!.bytes_sent).toBe(30)
    expect(out[0]!.bytes_received).toBe(5)

    // 7d 视图：按天聚合，同日不同小时的两点合并成一天
    const day = aggregateTimeline(
      [pt(0, 'a.exe', 1), pt(3 * HOUR, 'a.exe', 2), pt(26 * HOUR, 'a.exe', 4)],
      168
    )
    expect(day).toHaveLength(2)
    expect(day[0]!.bytes_sent).toBe(3)
    expect(day[1]!.bytes_sent).toBe(4)
  })

  it('keeps distinct processes apart in the same bucket', () => {
    const out = aggregateTimeline([pt(0, 'a.exe', 1), pt(0, 'b.exe', 2)], 24)
    expect(out.map((p) => p.process_path).sort()).toEqual(['a.exe', 'b.exe'])
  })
})

describe('buildStackedTrafficSeries', () => {
  it('returns empty series for empty data', () => {
    expect(buildStackedTrafficSeries([])).toEqual({ timestamps: [], series: [] })
  })

  it('aligns a single app with a single point', () => {
    const out = buildStackedTrafficSeries([pt(0, 'a.exe', 7, 3, 'App A')])
    expect(out.timestamps).toHaveLength(1)
    expect(out.series).toHaveLength(1)
    expect(out.series[0]).toMatchObject({ name: 'App A', path: 'a.exe', data: [10] })
  })

  it('fills zero buckets for apps missing at some timestamps', () => {
    const out = buildStackedTrafficSeries([
      pt(0, 'a.exe', 1),
      pt(HOUR, 'a.exe', 2),
      pt(HOUR, 'b.exe', 5),
    ])
    expect(out.timestamps).toHaveLength(2)
    const a = out.series.find((s) => s.path === 'a.exe')!
    expect(a.data).toEqual([1, 2])
    const b = out.series.find((s) => s.path === 'b.exe')!
    expect(b.data).toEqual([0, 5])
  })

  it('collapses apps beyond topN into 其他', () => {
    const points: TimelinePoint[] = []
    for (let i = 0; i < 10; i++) {
      // 进程 i 流量 = i+1，保证确定排名（a0 最小）
      points.push(pt(0, `app${i}.exe`, i + 1, 0, `App${i}`))
    }
    const out = buildStackedTrafficSeries(points, 8)
    expect(out.series).toHaveLength(9) // 8 + 其他
    const others = out.series.find((s) => s.path === '__others__')!
    expect(others).toBeDefined()
    expect(others.data[0]).toBe(1 + 2) // 排名 9、10 的两个进程
    expect(out.series[0]!.name).toBe('App9') // 总量最大者排第一
  })
})

describe('buildActionTrendSeries', () => {
  it('returns empty arrays for empty data', () => {
    expect(buildActionTrendSeries([])).toEqual({ timestamps: [], allowed: [], blocked: [] })
  })

  it('sorts by timestamp and splits allowed/blocked', () => {
    const out = buildActionTrendSeries([
      { timestamp: new Date(base + HOUR).toISOString(), allowed_bytes: 1, blocked_bytes: 2, allowed_count: 1, blocked_count: 1 },
      { timestamp: new Date(base).toISOString(), allowed_bytes: 10, blocked_bytes: 0, allowed_count: 2, blocked_count: 0 },
    ])
    expect(out.timestamps).toHaveLength(2)
    expect(out.timestamps[0]).toBe(new Date(base).toISOString())
    expect(out.allowed).toEqual([10, 1])
    expect(out.blocked).toEqual([0, 2])
  })
})

describe('formatTrendLabel', () => {
  it('shows HH:mm for short ranges and MM-DD for the 7d daily view', () => {
    const iso = new Date(base).toISOString()
    expect(formatTrendLabel(iso, 1)).toMatch(/^\d{2}:\d{2}$/)
    expect(formatTrendLabel(iso, 24)).toMatch(/^\d{2}:\d{2}$/)
    expect(formatTrendLabel(iso, 168)).toBe('09-09')
  })
})
