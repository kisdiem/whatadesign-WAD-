import ReactECharts from 'echarts-for-react'
import type { CSSProperties } from 'react'

export default function EChartsView({
  option,
  style,
  onEvents,
}: {
  option: unknown
  style?: CSSProperties
  onEvents?: Record<string, (...args: any[]) => void>
}) {
  return <ReactECharts option={option as never} style={style} onEvents={onEvents} />
}
