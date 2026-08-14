import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Select, Slider, Space, Typography } from 'antd'
import ReactECharts from 'echarts-for-react'
import { createPortal } from 'react-dom'
import { useLocation } from 'react-router-dom'
import { anomalyWindows, type AnomalyWindow, type Severity } from './mocks/data'
import { normalActivityEvents } from './mocks/normalActivity'

const { Text } = Typography

const severityWeight: Record<Severity, number> = {
  info: 0,
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const severityLabel: Record<Severity, string> = {
  info: '正常',
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const sourceOptions = Array.from(new Set(anomalyWindows.flatMap((item) => item.sourceTypes)))

function toSecond(value: string) {
  const [hour, minute, second] = value.split(':').map(Number)
  return hour * 3600 + minute * 60 + second
}

function timeLabel(value: number) {
  const normalized = Math.max(0, Math.min(86399, Math.round(value)))
  const hour = Math.floor(normalized / 3600)
  const minute = Math.floor((normalized % 3600) / 60)
  const second = normalized % 60
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}:${String(second).padStart(2, '0')}`
}

function windowMatches(item: AnomalyWindow, severities: Severity[], sources: string[]) {
  return severities.includes(item.severity) && item.sourceTypes.some((source) => sources.includes(source))
}

export default function AnomalyTimelineEnhancer() {
  const location = useLocation()
  const [host, setHost] = useState<HTMLDivElement | null>(null)
  const [selectedId, setSelectedId] = useState<string>('all')
  const [severities, setSeverities] = useState<Severity[]>(['critical', 'high', 'medium', 'low', 'info'])
  const [sources, setSources] = useState<string[]>(sourceOptions)
  const [progress, setProgress] = useState(0)
  const [playing, setPlaying] = useState(true)

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

    return () => slot?.remove()
  }, [location.pathname])

  const filteredWindows = useMemo(
    () => anomalyWindows.filter((item) => windowMatches(item, severities, sources)),
    [severities, sources],
  )

  useEffect(() => {
    if (selectedId !== 'all' && !filteredWindows.some((item) => item.id === selectedId)) {
      setSelectedId('all')
    }
  }, [filteredWindows, selectedId])

  useEffect(() => {
    if (!location.pathname.startsWith('/anomalies') || !playing) return
    const timer = window.setInterval(() => {
      setProgress((value) => {
        if (value >= 100) {
          setPlaying(false)
          return 100
        }
        return Math.min(100, value + 1)
      })
    }, 100)
    return () => window.clearInterval(timer)
  }, [location.pathname, playing])

  const selectedWindows = useMemo(() => {
    if (selectedId === 'all') return filteredWindows
    return filteredWindows.filter((item) => item.id === selectedId)
  }, [filteredWindows, selectedId])

  const playbackBounds = useMemo(() => {
    if (!selectedWindows.length) return { start: 0, end: 24 * 3600 - 1 }
    const start = Math.min(...selectedWindows.map((item) => toSecond(item.start)))
    const end = Math.max(...selectedWindows.map((item) => toSecond(item.end)))
    return { start, end: Math.max(end, start + 60) }
  }, [selectedWindows])

  const currentTime = playbackBounds.start + ((playbackBounds.end - playbackBounds.start) * progress) / 100

  const option = useMemo(() => {
    const { start, end } = playbackBounds
    const duration = Math.max(end - start, 60)
    const pointCount = selectedId === 'all' ? 220 : 120
    const times = Array.from({ length: pointCount + 1 }, (_, index) => start + (duration * index) / pointCount)
    const playhead = start + duration * (progress / 100)

    const lines = Array.from({ length: 9 }, (_, lineIndex) => ({
      name: `轨迹 ${lineIndex + 1}`,
      type: 'line',
      smooth: 0.12,
      symbol: 'none',
      silent: true,
      connectNulls: false,
      lineStyle: {
        width: lineIndex < 2 ? 1.7 : 1,
        opacity: lineIndex < 2 ? 0.7 : 0.23 + lineIndex * 0.045,
      },
      emphasis: { disabled: true },
      data: times.map((time) => {
        if (time > playhead) return [time, null]

        let disturbance = 0
        let overlap = 0
        selectedWindows.forEach((item) => {
          const itemStart = toSecond(item.start)
          const itemEnd = toSecond(item.end)
          const span = Math.max(itemEnd - itemStart, 1)
          const padding = selectedId === 'all' ? 700 : span * 0.35
          if (time >= itemStart - padding && time <= itemEnd + padding) {
            const middle = (itemStart + itemEnd) / 2
            const distance = Math.abs(time - middle) / Math.max(span / 2 + padding, 1)
            disturbance += severityWeight[item.severity] * Math.max(0, 1 - distance) * 8.5
          }
          if (time >= itemStart && time <= itemEnd) overlap += 1
        })

        const normalized = (time - start) / duration
        const evolvingPhase = progress * 0.13
        const baseline = 44
          + Math.sin(normalized * 18 + lineIndex * 0.73 + evolvingPhase) * 3.2
          + Math.cos(normalized * 31 + lineIndex * 1.37) * 2.1
        const irregular = Math.sin(normalized * 157 + lineIndex * 21.7 + evolvingPhase * 2.1)
          * (1.6 + disturbance * (0.18 + lineIndex * 0.035))
        const crossNoise = Math.cos(normalized * 283 - lineIndex * 11.2 + progress * 0.08)
          * (disturbance * 0.11 + overlap * 2.4)
        const overlapBreak = overlap > 1
          ? Math.sin(normalized * 421 + lineIndex * 8.4) * overlap * 3.2
          : 0

        return [time, Number((baseline + irregular + crossNoise + overlapBreak).toFixed(2))]
      }),
    }))

    const normalScatter = normalActivityEvents
      .map((item, index) => ({
        time: toSecond(item.time),
        value: 35 + ((index * 13) % 18),
        name: `${item.host} · ${item.action}`,
      }))
      .filter((item) => item.time >= start && item.time <= playhead)
      .map((item) => ({
        value: [item.time, item.value],
        name: item.name,
        itemStyle: { color: '#98a2b3', opacity: 0.55 },
      }))

    const anomalyScatter = selectedWindows
      .filter((item) => toSecond(item.start) <= playhead)
      .map((item) => ({
        value: [(toSecond(item.start) + toSecond(item.end)) / 2, 44],
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
      animation: false,
      grid: { left: 42, right: 24, top: 22, bottom: 42 },
      tooltip: {
        trigger: 'axis',
        formatter: (params: Array<{ axisValue: number }>) => timeLabel(Number(params?.[0]?.axisValue || start)),
      },
      xAxis: {
        type: 'value',
        min: start,
        max: end,
        axisLabel: { formatter: (value: number) => timeLabel(value).slice(0, 5), color: '#667085' },
        axisLine: { lineStyle: { color: '#d0d5dd' } },
        splitLine: { lineStyle: { color: '#f0f2f5' } },
      },
      yAxis: {
        type: 'value',
        min: 6,
        max: 84,
        axisLabel: { show: false },
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      series: [
        ...lines,
        {
          name: '正常活动',
          type: 'scatter',
          symbolSize: 5,
          data: normalScatter,
          z: 8,
          tooltip: { show: false },
        },
        {
          name: '异常窗口',
          type: 'scatter',
          symbolSize: 10,
          data: anomalyScatter,
          z: 20,
          tooltip: { show: false },
        },
        {
          name: '播放位置',
          type: 'line',
          symbol: 'none',
          silent: true,
          data: [[playhead, 8], [playhead, 82]],
          lineStyle: { width: 2, color: '#344054', opacity: 0.62, type: 'dashed' },
          z: 30,
        },
      ],
    }
  }, [playbackBounds, progress, selectedId, selectedWindows])

  const switchWindow = (value: string) => {
    setSelectedId(value)
    setProgress(0)
    setPlaying(true)
  }

  const restart = () => {
    setProgress(0)
    setPlaying(true)
  }

  if (!host) return null

  return createPortal(
    <Card
      className="anomaly-disturbance-card"
      title="异常时序变化"
      extra={(
        <Space size={8} wrap>
          <Select
            value={selectedId}
            onChange={switchWindow}
            style={{ width: 270 }}
            options={[
              { value: 'all', label: '全部异常窗口' },
              ...filteredWindows.map((item) => ({ value: item.id, label: `${item.start} · ${item.title}` })),
            ]}
          />
          <Select
            mode="multiple"
            maxTagCount="responsive"
            value={severities}
            onChange={(value) => {
              setSeverities(value as Severity[])
              setProgress(0)
              setPlaying(false)
            }}
            style={{ minWidth: 180 }}
            options={(Object.keys(severityLabel) as Severity[]).map((value) => ({ value, label: severityLabel[value] }))}
          />
          <Select
            mode="multiple"
            maxTagCount="responsive"
            value={sources}
            onChange={(value) => {
              setSources(value)
              setProgress(0)
              setPlaying(false)
            }}
            style={{ minWidth: 210 }}
            options={sourceOptions.map((value) => ({ value, label: value }))}
          />
        </Space>
      )}
    >
      <ReactECharts option={option} notMerge lazyUpdate style={{ height: 275 }} />
      <div className="timeline-playback">
        <Space size={8}>
          <Button type="primary" onClick={() => setPlaying((value) => !value)}>{playing ? '暂停' : '播放'}</Button>
          <Button onClick={restart}>重播</Button>
        </Space>
        <Slider
          className="timeline-slider"
          min={0}
          max={100}
          step={0.1}
          value={progress}
          tooltip={{ open: false }}
          onChange={(value) => {
            setPlaying(false)
            setProgress(Number(value))
          }}
        />
        <Text className="timeline-clock">{timeLabel(currentTime)}</Text>
      </div>
    </Card>,
    host,
  )
}
