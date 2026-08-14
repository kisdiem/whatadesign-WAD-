import ReactECharts from 'echarts-for-react'
import type { CSSProperties } from 'react'

export default function EChartsView({
  option,
  style,
  onEvents,
}: {
  option: unknown
  style?: CSSProperties
  onEvents?: Record<string, (params: { data?: { id?: string; name?: string } }) => void>
}) {
  return <ReactECharts option={option as never} style={style} onEvents={onEvents} />
}
