import { useEffect, useMemo, useState } from 'react'
import { Card, Select, Space } from 'antd'
import ReactECharts from 'echarts-for-react'
import { createPortal } from 'react-dom'
import { useLocation } from 'react-router-dom'
import { anomalyWindows, type Severity } from './mocks/data'

const severityWeight: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const severityLabel: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const sourceOptions = Array.from(new Set(anomalyWindows.flatMap((item) => item.sourceTypes)))

function toHour(value: string) {
  const [hour, minute, second] = value.split(':').map(Number)
  return hour + minute / 60 + second / 3600
}

function timeLabel(value: number) {
  const hour = Math.floor(value)
  const minute = Math.round((value - hour) * 60)
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`
}

export default function AnomalyTimelineEnhancer() {
  const location = useLocation()
  const [host, setHost] = useState<HTMLDivElement | null>(null)
  const [range, setRange] = useState('24')
  const [severities, setSeverities] = useState<Severity[]>(['critical', 'high', 'medium', 'low'])
  const [sources, setSources] = useState<string[]>(sourceOptions)
  const [phase, setPhase] = useState(0)

  useEffect(() => {
    if (!location.pathname.startsWith('/anomalies')) {
      setHost(null)
      return
    }

    const content = document.querySelector('.content-wrap')
    const toolbar = content?.querySelector('.toolbar-card')
    if (!content || !toolbar) return

    let slot = document.getElementById('anomaly-timeline-slot') as HTMLDivElement | null
    if (!slot) {
      slot = document.createElement('div')
      slot.id = 'anomaly-timeline-slot'
      content.insertBefore(slot, toolbar)
    }
    setHost(slot)

    return () => {
      slot?.remove()
    }
  }, [location.pathname])

  useEffect(() => {
    if (!location.pathname.startsWith('/anomalies')) return
    const timer = window.setInterval(() => setPhase((value) => value + 1), 1400)
    return () => window.clearInterval(timer)
  }, [location.pathname])

  const option = useMemo(() => {
    const selectedWindows = anomalyWindows.filter((item) => (
      severities.includes(item.severity) && item.sourceTypes.some((source) => sources.includes(source))
    ))

    const rangeHours = Number(range)
    const observedMax = selectedWindows.length
      ? Math.max(...selectedWindows.map((item) => toHour(item.end)))
      : 24
    const endHour = rangeHours >= 24 ? 24 : observedMax
    const startHour = rangeHours >= 24 ? 0 : Math.max(0, endHour - rangeHours)
    const pointCount = Math.max(24, Math.round((endHour - startHour) * 4))
    const times = Array.from({ length: pointCount + 1 }, (_, index) => startHour + ((endHour - startHour) * index) / pointCount)

    const lines = Array.from({ length: 7 }, (_, lineIndex) => ({
      name: `轨迹 ${lineIndex + 1}`,
      type: 'line',
      smooth: 0.16,
      symbol: 'none',
      silent: true,
      lineStyle: {
        width: lineIndex === 0 ? 1.8 : 1,
        opacity: lineIndex === 0 ? 0.72 : 0.28 + lineIndex * 0.045,
      },
      emphasis: { disabled: true },
      data: times.map((time) => {
        let disturbance = 0
        selectedWindows.forEach((item) => {
          const middle = (toHour(item.start) + toHour(item.end)) / 2
          const distance = Math.abs(time - middle)
          if (distance < 1.15) {
            disturbance += severityWeight[item.severity] * (1 - distance / 1.15) * 8.5
          }
        })

        const base = 42
          + Math.sin(time * 1.8 + lineIndex * 0.72 + phase * 0.1) * 3.8
          + Math.cos(time * 0.82 + lineIndex * 1.31) * 2.2
        const jitter = Math.sin(time * 37.7 + lineIndex * 19.3 + phase * 0.93)
          * (2 + disturbance * (0.22 + lineIndex * 0.055))
        const crossNoise = Math.cos(time * 71.3 - lineIndex * 8.1 + phase * 0.37)
          * disturbance * 0.12

        return Number((base + jitter + crossNoise).toFixed(2))
      }),
    }))

    const anomalyScatter = selectedWindows
      .map((item) => ({
        hour: (toHour(item.start) + toHour(item.end)) / 2,
        severity: item.severity,
        title: item.title,
      }))
      .filter((item) => item.hour >= startHour && item.hour <= endHour)
      .map((item) => ({
        value: [item.hour, 42],
        itemStyle: {
          color: item.severity === 'critical'
            ? '#d92d20'
            : item.severity === 'high'
              ? '#f79009'
              : item.severity === 'medium'
                ? '#eaaa08'
                : '#2e90fa',
        },
        name: item.title,
      }))

    return {
      animationDurationUpdate: 750,
      grid: { left: 42, right: 24, top: 24, bottom: 44 },
      tooltip: {
        trigger: 'axis',
        formatter: (params: Array<{ axisValue: number }>) => timeLabel(Number(params?.[0]?.axisValue || 0)),
      },
      xAxis: {
        type: 'value',
        min: startHour,
        max: endHour,
        axisLabel: { formatter: (value: number) => timeLabel(value), color: '#667085' },
        axisLine: { lineStyle: { color: '#d0d5dd' } },
        splitLine: { lineStyle: { color: '#f0f2f5' } },
      },
      yAxis: {
        type: 'value',
        min: 12,
        max: 78,
        axisLabel: { show: false },
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      series: [
        ...lines,
        {
          name: '异常窗口',
          type: 'scatter',
          symbolSize: 9,
          data: anomalyScatter,
          z: 20,
          tooltip: { show: false },
        },
      ],
    }
  }, [phase, range, severities, sources])

  if (!host) return null

  return createPortal(
    <Card
      className="anomaly-disturbance-card"
      title="异常时序变化"
      extra={(
        <Space size={8} wrap>
          <Select
            value={range}
            onChange={setRange}
            style={{ width: 108 }}
            options={[
              { value: '6', label: '近 6 小时' },
              { value: '12', label: '近 12 小时' },
              { value: '24', label: '近 24 小时' },
            ]}
          />
          <Select
            mode="multiple"
            maxTagCount="responsive"
            value={severities}
            onChange={(value) => setSeverities(value as Severity[])}
            style={{ minWidth: 190 }}
            options={(Object.keys(severityLabel) as Severity[]).map((value) => ({ value, label: severityLabel[value] }))}
          />
          <Select
            mode="multiple"
            maxTagCount="responsive"
            value={sources}
            onChange={setSources}
            style={{ minWidth: 220 }}
            options={sourceOptions.map((value) => ({ value, label: value }))}
          />
        </Space>
      )}
    >
      <ReactECharts option={option} notMerge lazyUpdate style={{ height: 270 }} />
    </Card>,
    host,
  )
}
