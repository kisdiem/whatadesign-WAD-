import ReactECharts from 'echarts-for-react'
import type { CSSProperties } from 'react'

export default function EChartsView({
  option,
  style,
}: {
  option: unknown
  style?: CSSProperties
}) {
  return <ReactECharts option={option as never} style={style} />
}
