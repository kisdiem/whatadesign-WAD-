import { Suspense, lazy, useMemo, useState } from 'react'
import { Card, Col, List, Row, Select, Space, Statistic, Typography } from 'antd'
import type { Investigation } from '../mocks/data'
import type { CaseBoard, FindingRecord } from '../services/investigationDomain'
import {
  ChartFallback,
  HelpTitle,
  PageTitle,
  RiskBadge,
  SeverityTag,
  filterRowsBySourceTimeRange,
  isManualInvestigation,
} from './shared'

const { Text } = Typography
const EChartsView = lazy(() => import('../EChartsView'))

function overviewBucketKey(value: string, timeRange: string) {
  const normalized = value.includes('T') ? value : value.replace(' ', 'T')
  const parsed = Date.parse(normalized.endsWith('Z') ? normalized : `${normalized}:00Z`)
  if (Number.isNaN(parsed)) return value
  const timestamp = new Date(parsed)
  timestamp.setUTCSeconds(0, 0)
  if (timeRange === '1h') timestamp.setUTCMinutes(Math.floor(timestamp.getUTCMinutes() / 5) * 5)
  else if (timeRange === '24h') timestamp.setUTCMinutes(0)
  else if (timeRange === '7d') {
    timestamp.setUTCMinutes(0)
    timestamp.setUTCHours(Math.floor(timestamp.getUTCHours() / 6) * 6)
  } else {
    timestamp.setUTCMinutes(0)
    timestamp.setUTCHours(0)
  }
  return timestamp.toISOString().slice(0, 16).replace('T', ' ')
}

export default function OverviewPage({
  findings: inputFindings,
  cases: inputCases,
  caseBoards,
  timeRange,
  inputOverviewSeries,
}: {
  findings: FindingRecord[]
  cases: Investigation[]
  caseBoards: Record<string, CaseBoard>
  timeRange: string
  inputOverviewSeries: Array<{ time: string; logs: number; anomalies: number; source?: string }>
}) {
  const [source, setSource] = useState('all')
  const findings = useMemo(
    () => source === 'all' ? inputFindings : inputFindings.filter((finding) => finding.sourceTypes.includes(source)),
    [inputFindings, source],
  )
  const findingIds = useMemo(() => new Set(findings.map((finding) => finding.id)), [findings])
  const cases = useMemo(
    () => inputCases.map((item) => ({ ...item, windowIds: item.windowIds.filter((id) => findingIds.has(id)) })).filter((item) => item.windowIds.length > 0),
    [findingIds, inputCases],
  )
  const visibleSeries = useMemo(() => {
    const sourceRows = source === 'all'
      ? inputOverviewSeries
      : inputOverviewSeries.filter((item) => item.source === source)
    const rangedRows = timeRange === '30d' ? sourceRows : filterRowsBySourceTimeRange(sourceRows, timeRange)
    const byScale = new Map<string, { logs: number; anomalies: number }>()
    rangedRows.forEach((item) => {
      const bucket = overviewBucketKey(item.time, timeRange)
      const current = byScale.get(bucket) || { logs: 0, anomalies: 0 }
      current.logs += item.logs
      current.anomalies += item.anomalies
      byScale.set(bucket, current)
    })
    const ordered = Array.from(byScale.entries())
      .map(([time, values]) => ({ time, ...values }))
      .sort((left, right) => left.time.localeCompare(right.time))
    return ordered
  }, [inputOverviewSeries, source, timeRange])

  const rawEvents = visibleSeries.reduce((sum, item) => sum + item.logs, 0)
  const anomalousFindings = findings.length
  const correlatedFindingIds = new Set(cases.flatMap((item) => item.windowIds))
  const manualCases = cases.filter(isManualInvestigation)
  const reviewedFindingIds = new Set(manualCases.flatMap((item) => item.windowIds.filter((findingId) => findingId in (caseBoards[item.id] || {}))))
  const correlatedFindings = correlatedFindingIds.size
  const reviewed = reviewedFindingIds.size
  const mainChainEvidence = new Set(manualCases.flatMap((item) => Object.entries(caseBoards[item.id] || {}).filter(([findingId, stage]) => stage === 'main' && findingIds.has(findingId)).map(([findingId]) => findingId))).size
  const reviewReduction = rawEvents > 0 ? ((rawEvents - reviewed) / rawEvents) * 100 : 0

  const sourceOption = useMemo(() => ({
    tooltip: { trigger: 'axis' },
    grid: { left: 56, right: 18, top: 20, bottom: 30, containLabel: true },
    xAxis: { type: 'category', data: visibleSeries.map((item) => item.time), axisLabel: { color: '#64748b' } },
    yAxis: { type: 'value', axisLabel: { color: '#64748b', margin: 12 }, splitLine: { lineStyle: { color: '#eef2f7' } } },
    series: [
      { name: '原始事件', type: 'line', smooth: true, showSymbol: false, data: visibleSeries.map((item) => item.logs) },
      { name: '异常发现', type: 'bar', barMaxWidth: 18, data: visibleSeries.map((item) => item.anomalies) },
    ],
  }), [visibleSeries])

  const distributionOption = useMemo(() => ({
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      radius: ['48%', '72%'],
      data: Array.from(new Set(findings.flatMap((finding) => finding.sourceTypes))).map((name) => ({
        name,
        value: findings.filter((finding) => finding.sourceTypes.includes(name)).length,
      })),
      label: { formatter: '{b}: {c}' },
    }],
  }), [findings])

  return (
    <>
      <PageTitle title="总览" subtitle={`${timeRange} 多尺度上下文 · 当前窗口自动重构事件、实体与长周期关联`} extra={<Select value={source} onChange={setSource} style={{ width: 170 }} options={[{ value: 'all', label: '全部日志源' }, ...Array.from(new Set(inputFindings.flatMap((finding) => finding.sourceTypes))).map((value) => ({ value, label: value }))]} />} />
      <Row gutter={[12, 12]} className="mc-summary-row">
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="原始事件" value={rawEvents} /></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="异常发现" value={anomalousFindings} /></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="进入人工研判" value={reviewed} /></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="研判压缩" value={reviewReduction} precision={3} suffix="%" /></Card></Col>
      </Row>

      <Row gutter={[12, 12]}>
        <Col xs={24} xl={16}>
          <Card title={<HelpTitle title="研判漏斗" description="展示日志从原始事件到人工研判的逐层收敛过程，用于了解筛选规模。" />} className="mc-panel">
            <Row gutter={[12, 12]}>
              <Col xs={24} md={10}>
                <div className="mc-funnel-list">
                  {[
                    { label: '事件', value: rawEvents },
                    { label: '异常发现', value: anomalousFindings },
                    { label: `候选链证据（${cases.length} 条链）`, value: correlatedFindings },
                    { label: `进入人工研判（${manualCases.length} 个案件）`, value: reviewed },
                    { label: '主链证据', value: mainChainEvidence },
                  ].map((item, index) => (
                    <div key={item.label} className="mc-setting-row">
                      <div>
                        <strong>{item.label}</strong>
                        <div><Text type="secondary">L{index + 1}</Text></div>
                      </div>
                      <Text strong>{item.value}</Text>
                    </div>
                  ))}
                </div>
              </Col>
              <Col xs={24} md={14}>
                <Suspense fallback={<ChartFallback height={280} />}>
                  <EChartsView option={sourceOption} style={{ height: 280 }} />
                </Suspense>
              </Col>
            </Row>
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title={<HelpTitle title="数据源分布" description="展示当前筛选范围内，各日志源贡献的异常发现数量。" />} className="mc-panel">
            <Suspense fallback={<ChartFallback height={280} />}>
              <EChartsView option={distributionOption} style={{ height: 280 }} />
            </Suspense>
          </Card>
        </Col>
        <Col span={24}>
          <Card title={<HelpTitle title="高风险发现" description="按综合风险从高到低展示优先核查的异常发现。风险分数可点击查看阈值。" />} className="mc-panel">
            <List
              dataSource={[...findings].sort((a, b) => b.risk - a.risk).slice(0, 5)}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={<Space><Text strong>{item.title}</Text><SeverityTag value={item.severity} /></Space>}
                    description={`${item.id} · ${item.entity} · ${item.start}`}
                  />
                  <Space size={20}>
                    <div><Text type="secondary">综合</Text><div><RiskBadge value={item.risk} /></div></div>
                    <div><Text type="secondary">长程</Text><div><RiskBadge value={item.longScore} /></div></div>
                  </Space>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col span={24}>
          <Card title={<HelpTitle title="分析链路" description="展示跨源语义统一、实体关系联合建模、多尺度主动检索和跨时间窗口长周期关联的完整链路。" />} className="mc-panel">
            <Row gutter={[10, 10]}>
              {[
                ['M0', '解析'],
                ['M1', '跨源语义'],
                ['M2', '实体关系'],
                ['M3', '多尺度上下文'],
                ['M4', '主动检索'],
                ['M5', '长周期关联'],
                ['M6', '风险融合'],
              ].map(([stage, label]) => (
                <Col xs={12} md={8} xl={3} key={stage}>
                  <Card className="mc-summary-card mc-chain-card">
                    <Statistic title={stage} value={label} />
                  </Card>
                </Col>
              ))}
            </Row>
          </Card>
        </Col>
      </Row>
    </>
  )
}
