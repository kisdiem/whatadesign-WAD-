import { useEffect, useMemo, useState } from 'react'
import { Card, Col, Row } from 'antd'
import ReactECharts from 'echarts-for-react'
import { createPortal } from 'react-dom'
import { useLocation } from 'react-router-dom'
import { anomalyWindows } from './mocks/data'
import { normalActivityEvents, type AssetGroup } from './mocks/normalActivity'

const assetOrder: AssetGroup[] = ['终端工作站', 'Windows 服务器', 'Linux 服务器', '数据库资产', '网络设备', '安全设备']

function classifyAsset(host?: string): AssetGroup {
  const value = (host || '').toUpperCase()
  if (value.startsWith('DB-') || value.includes('SRV-DB')) return '数据库资产'
  if (value.startsWith('DC-')) return 'Windows 服务器'
  if (value.startsWith('APP-') || value.startsWith('SRV-')) return 'Linux 服务器'
  if (value.startsWith('SW-')) return '网络设备'
  if (value.startsWith('FW-')) return '安全设备'
  return '终端工作站'
}

function countGroups(groups: AssetGroup[]) {
  return assetOrder.map((name) => ({
    name,
    value: groups.filter((item) => item === name).length,
  })).filter((item) => item.value > 0)
}

function pieOption(data: { name: string; value: number }[]) {
  return {
    tooltip: { trigger: 'item', formatter: '{b}<br/>{d}% · {c} 次' },
    legend: {
      type: 'scroll',
      orient: 'vertical',
      right: 12,
      top: 'middle',
      itemWidth: 10,
      itemHeight: 10,
      textStyle: { color: '#667085', fontSize: 12 },
    },
    series: [{
      type: 'pie',
      radius: ['45%', '70%'],
      center: ['36%', '50%'],
      avoidLabelOverlap: true,
      itemStyle: { borderColor: '#ffffff', borderWidth: 2 },
      label: { formatter: '{b}\n{d}%', color: '#475467', fontSize: 11 },
      labelLine: { length: 10, length2: 7 },
      data,
    }],
  }
}

export default function AssetPieEnhancer() {
  const location = useLocation()
  const [host, setHost] = useState<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!location.pathname.startsWith('/overview')) {
      setHost(null)
      return
    }

    const content = document.querySelector('.content-wrap')
    const metricRow = content?.querySelector('.metric-row')
    if (!content || !metricRow) return

    let slot = document.getElementById('asset-pie-slot') as HTMLDivElement | null
    if (!slot) {
      slot = document.createElement('div')
      slot.id = 'asset-pie-slot'
      metricRow.parentNode?.insertBefore(slot, metricRow.nextSibling)
    }
    setHost(slot)

    return () => slot?.remove()
  }, [location.pathname])

  const allAssetData = useMemo(() => {
    const normalGroups = normalActivityEvents.map((event) => event.assetGroup)
    const abnormalGroups = anomalyWindows.flatMap((window) => (
      window.events.map((event) => classifyAsset(event.host || window.hosts[0]))
    ))
    return countGroups([...normalGroups, ...abnormalGroups])
  }, [])

  const anomalyAssetData = useMemo(() => countGroups(
    anomalyWindows.flatMap((window) => window.events.map((event) => classifyAsset(event.host || window.hosts[0]))),
  ), [])

  if (!host) return null

  return createPortal(
    <Row gutter={[14, 14]} className="asset-pie-row">
      <Col xs={24} xl={12}>
        <Card title="资产在全部日志中的出现占比" className="panel-card asset-pie-card">
          <ReactECharts option={pieOption(allAssetData)} style={{ height: 280 }} />
        </Card>
      </Col>
      <Col xs={24} xl={12}>
        <Card title="资产在异常日志中的出现占比" className="panel-card asset-pie-card">
          <ReactECharts option={pieOption(anomalyAssetData)} style={{ height: 280 }} />
        </Card>
      </Col>
    </Row>,
    host,
  )
}
