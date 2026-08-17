import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Button, Card, Col, Descriptions, Drawer, List, Row, Segmented, Space, Table, Tag, Typography } from 'antd'
import { CheckCircleFilled, ClockCircleOutlined, DeleteOutlined, RobotOutlined } from '@ant-design/icons'
import type { Investigation } from '../mocks/data'
import type { AssistantContext } from '../services/api'
import {
  buildAttackChainGraph,
  layoutAttackChainByTactic,
  limitGraphExplanation,
  type M3GraphSnapshot,
} from '../services/caseGraphs'
import { inferEntityType, type CaseBoard, type EvidenceRecord, type FindingRecord, type FindingStage } from '../services/investigationDomain'
import InteractiveCaseGraph from '../InteractiveCaseGraph'
import {
  ChartFallback,
  ExplainableText,
  HelpTitle,
  PageTitle,
  RiskBadge,
  investigationQueueMeta,
  investigationQueueStatus,
  isManualInvestigation,
  readableAction,
  readableEntityType,
  readableStage,
  severityLabel,
} from './shared'

const { Text, Title, Paragraph } = Typography

function caseDataset(item: Investigation): 'short' | 'long' | 'other' {
  if (item.windowIds.some((id) => id.startsWith('WIN-SHORT-'))) return 'short'
  if (item.windowIds.some((id) => id.startsWith('WIN-LONG-'))) return 'long'
  if (item.title.startsWith('Short')) return 'short'
  if (item.title.startsWith('Long')) return 'long'
  return 'other'
}

export default function InvestigationsPage({
  cases,
  findings,
  evidenceByFinding,
  caseBoards,
  activeFindingIds,
  timeRange,
  onSetFindingStage,
  onOpenAssistant,
  onSubmitBatch,
  onGenerateReport,
  onExplain,
  onOpenEntity,
  m3GraphSnapshots,
  onDeleteCase,
  onEscalateCase,
}: {
  cases: Investigation[]
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  caseBoards: Record<string, CaseBoard>
  activeFindingIds: Set<string>
  timeRange: string
  onSetFindingStage: (caseId: string, findingId: string, stage: FindingStage) => void
  onOpenAssistant: (investigation: Investigation) => void
  onSubmitBatch: (prompt: string, context: AssistantContext) => void
  onGenerateReport: (prompt: string, context: AssistantContext, report: { caseId: string; caseTitle: string }) => void
  onExplain: (excerpt: string, context: AssistantContext) => void
  onOpenEntity: (entityId: string) => void
  m3GraphSnapshots: Record<string, M3GraphSnapshot>
  onDeleteCase: (caseId: string) => void
  onEscalateCase: (caseId: string) => void
}) {
  const location = useLocation()
  const [selectedId, setSelectedId] = useState(cases[0]?.id || '')
  const [queueFilter, setQueueFilter] = useState<'manual' | 'auto' | 'resolved' | 'all'>('manual')
  const [datasetFilter, setDatasetFilter] = useState<'all' | 'short' | 'long'>('all')
  const [graphDetail, setGraphDetail] = useState<{ title: string; kind: string; description: string; relation?: string; evidence?: string; explanation?: string; boundary?: string; originalName?: string; details?: string[]; source?: string; target?: string; prompt?: string } | null>(null)
  const [graphPositions, setGraphPositions] = useState<Record<string, Record<string, { x: number; y: number }>>>(() => {
    try {
      return JSON.parse(window.localStorage.getItem('wad-demo-graph-positions-v5') || '{}') as Record<string, Record<string, { x: number; y: number }>>
    } catch {
      return {}
    }
  })
  const attackChartRef = useRef<any>(null)
  const m3ChartRef = useRef<any>(null)
  const requestedCase = useMemo(() => new URLSearchParams(location.search).get('case') || '', [location.search])
  // 先按数据集（Short/Long）收窄，队列分类的计数与列表都基于收窄后的案件。
  const casesByDataset = useMemo(() => cases.filter((item) => {
    if (datasetFilter === 'short' && caseDataset(item) !== 'short') return false
    if (datasetFilter === 'long' && caseDataset(item) !== 'long') return false
    return true
  }), [cases, datasetFilter])
  const visibleCases = useMemo(() => casesByDataset.filter((item) => {
    const queue = investigationQueueStatus(item)
    if (queueFilter === 'manual') return queue === 'manual_review'
    if (queueFilter === 'auto') return queue === 'auto_observe' || queue === 'suppressed' || queue === 'merged'
    if (queueFilter === 'resolved') return queue === 'resolved'
    return true
  }), [casesByDataset, queueFilter])
  const datasetCounts = useMemo(() => ({
    short: cases.filter((item) => caseDataset(item) === 'short').length,
    long: cases.filter((item) => caseDataset(item) === 'long').length,
  }), [cases])
  const queueCounts = useMemo(() => ({
    manual: casesByDataset.filter((item) => investigationQueueStatus(item) === 'manual_review').length,
    auto: casesByDataset.filter((item) => ['auto_observe', 'suppressed', 'merged'].includes(investigationQueueStatus(item))).length,
    resolved: casesByDataset.filter((item) => investigationQueueStatus(item) === 'resolved').length,
  }), [casesByDataset])
  useEffect(() => {
    if (requestedCase) {
      setSelectedId(requestedCase)
      const requested = cases.find((item) => item.id === requestedCase)
      if (requested) setQueueFilter(isManualInvestigation(requested) ? (investigationQueueStatus(requested) === 'resolved' ? 'resolved' : 'manual') : 'auto')
    }
  }, [cases, requestedCase])
  useEffect(() => {
    if (!visibleCases.some((item) => item.id === selectedId)) {
      setSelectedId(visibleCases[0]?.id || '')
    }
  }, [selectedId, visibleCases])
  const selected = visibleCases.find((item) => item.id === selectedId) || visibleCases[0]
  const related = selected ? findings.filter((finding) => selected.windowIds.includes(finding.id)) : []
  const activeRelatedCount = related.filter((finding) => activeFindingIds.has(finding.id)).length
  const board = selected ? caseBoards[selected.id] || {} : {}
  const main = related.filter((finding) => board[finding.id] === 'main')
  const candidate = related.filter((finding) => board[finding.id] === 'candidate')
  const excluded = related.filter((finding) => board[finding.id] === 'excluded')
  const entities = Array.from(new Set(related.flatMap((finding) => finding.entities))).slice(0, 8)
  const graphFindings = related.filter((finding) => board[finding.id] !== 'excluded')
  const datasetName = selected ? (caseDataset(selected) === 'short' ? 'Short' : caseDataset(selected) === 'long' ? 'Long' : '') : ''
  // 攻击链图以当前案件时间窗口为核心，聚合同一数据集内同时段的相关发现，
  // 使图包含更多技术节点。Short 短时突发只取其时间邻域；Long 覆盖整条
  // 7 天战役范围，保证长程链呈现完整攻击链、链路显著长于短程。
  const attackGraphFindings = useMemo(() => {
    if (!datasetName) return graphFindings
    const relatedTimes = related.flatMap((finding) => finding.events.map((event) => Date.parse(event.time))).filter(Number.isFinite)
    if (!relatedTimes.length) return graphFindings
    const minT = Math.min(...relatedTimes)
    const maxT = Math.max(...relatedTimes)
    const pad = datasetName === 'Short' ? 10 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000
    return findings.filter((finding) =>
      finding.sourceTypes.includes(datasetName)
      && finding.events.some((event) => {
        const time = Date.parse(event.time)
        return Number.isFinite(time) && time >= minT - pad && time <= maxT + pad
      }),
    )
  }, [datasetName, findings, graphFindings, related])
  const graphEntities = Array.from(new Set(graphFindings.flatMap((finding) => finding.entities))).slice(0, 8)
  const savedM3Graphs = related.flatMap((finding) => m3GraphSnapshots[finding.id] ? [m3GraphSnapshots[finding.id]] : [])
  const attackChainGraph = useMemo(() => {
    // 窗口随数据集语义变化：Short 覆盖 24 小时、Long 覆盖 7 天，长程链因此包含更多阶段技术。
    const windowHours = datasetName === 'Long' ? 7 * 24 : 24
    const chain = buildAttackChainGraph(attackGraphFindings, { windowHours })
    // 力导向散开布局：节点按时间流向自然散布，边牵引相邻技术，突出攻击演进路径。
    return layoutAttackChainByTactic(chain.nodes, chain.links)
  }, [attackGraphFindings, datasetName])
  const activeM3Graph = savedM3Graphs[0]
  const saveInteractiveGraphPositions = (graphId: string, positions: Record<string, { x: number; y: number }>) => {
    setGraphPositions((current) => {
      const next = { ...current, [graphId]: positions }
      window.localStorage.setItem('wad-demo-graph-positions-v5', JSON.stringify(next))
      return next
    })
  }
  const rememberGraphPosition = (graphId: string, params: { data?: { id?: string; x?: number; y?: number } }) => {
    const node = params.data
    if (!node?.id || typeof node.x !== 'number' || typeof node.y !== 'number') return
    setGraphPositions((current) => {
      const next = { ...current, [graphId]: { ...(current[graphId] || {}), [node.id as string]: { x: node.x as number, y: node.y as number } } }
      window.localStorage.setItem('wad-demo-graph-positions-v5', JSON.stringify(next))
      return next
    })
  }
  const rememberChartPositions = (graphId: string, chart: any) => {
    const positions: Record<string, { x: number; y: number }> = {}
    const series = chart?.getModel?.()?.getSeriesByIndex?.(0)
    const data = series?.getData?.()
    const optionData = chart?.getOption?.().series?.[0]?.data || []
    if (data?.count && data?.getItemLayout && data?.getId) {
      for (let index = 0; index < data.count(); index += 1) {
        const layout = data.getItemLayout(index)
        // ECharts may assign an internal data id. Always prefer the business id
        // from the option item so persisted positions survive rerenders.
        const itemModel = data.getItemModel?.(index)
        const id = optionData[index]?.id || itemModel?.option?.id || data.getId(index)
        if (id && typeof layout?.x === 'number' && typeof layout?.y === 'number') positions[id] = { x: layout.x, y: layout.y }
      }
    }
    if (!Object.keys(positions).length) {
      optionData.forEach((node: { id?: string; x?: number; y?: number }) => {
        if (node.id && typeof node.x === 'number' && typeof node.y === 'number') positions[node.id] = { x: node.x, y: node.y }
      })
    }
    if (!Object.keys(positions).length) return
    setGraphPositions((current) => {
      const next = { ...current, [graphId]: { ...(current[graphId] || {}), ...positions } }
      window.localStorage.setItem('wad-demo-graph-positions-v5', JSON.stringify(next))
      return next
    })
  }
  const rememberAfterDrag = (graphId: string, chart: any) => {
    window.setTimeout(() => rememberChartPositions(graphId, chart), 120)
  }
  const rememberDragEvent = (graphId: string, params: any, chart: any) => {
    // Save the dragged item's business id immediately. The delayed full
    // snapshot below also captures any neighboring layout updates.
    const node = params?.data
    if (node?.id && typeof node.x === 'number' && typeof node.y === 'number') {
      rememberGraphPosition(graphId, { data: { id: node.id, x: node.x, y: node.y } })
    }
    rememberAfterDrag(graphId, chart)
  }
  const prepareNodeDrag = (params: any, chart: any) => {
    const node = params?.data
    if (!chart || params?.dataType !== 'node' || !node?.id) return
    // Force layout keeps persisted nodes fixed. Temporarily release only the
    // node under the pointer so it can be dragged, then dragend pins it again.
    const currentData = chart.getOption?.().series?.[0]?.data || []
    const nextData = currentData.map((item: any) => item.id === node.id ? { ...item, fixed: false } : item)
    chart.setOption({ series: [{ data: nextData }] })
  }
  const entityStats = entities.map((entity) => {
    const linked = related.filter((finding) => finding.entities.includes(entity))
    return {
      entity,
      type: readableEntityType(inferEntityType(entity)),
      findingCount: linked.length,
      eventCount: linked.reduce((sum, finding) => sum + finding.events.length, 0),
      hosts: Array.from(new Set(linked.map((finding) => finding.host).filter(Boolean))).slice(0, 2),
    }
  })

  const submitCase = (asReport = false) => {
    const snapshot = related.map((finding) => {
      const stage = readableStage(board[finding.id] || 'candidate')
      const evidence = evidenceByFinding[finding.id]?.map((item) => item.statement).filter(Boolean).join('; ') || finding.summary
      const events = finding.events.map((event) => `${event.time} ${readableAction(event.action)} ${event.actor || ''} ${event.host || ''} ${event.process || event.ip || ''}`.trim()).join(' | ')
      return `stage=${stage}; time=${finding.start}; finding_id=${finding.id}; finding=${finding.title}; entity=${finding.entity}; host=${finding.host || 'unresolved'}; risk=${finding.risk}; summary=${finding.summary}; evidence=${evidence}; events=${events}`
    }).join('\n')
    const task = asReport
      ? `[WAD_REPORT_SNAPSHOT]\n请仅基于下面的案件快照生成一份中文攻击链分析报告。必须完整使用以下模板，不能省略章节、不能只给一句建议。每个章节 2-4 条简短且具体的内容；关键证据至少列出 3 条有时间、实体或行为依据的内容。候选和排除项必须放在“不确定项”，风险分数只是线索，除非快照已证明，否则不得写成“已确认入侵”。不要使用表格，也不要添加额外章节。\n\n# 攻击链分析报告\n## 概况\n- 案件：\n- 分析范围：\n- 当前判断：\n## 链路判断\n1. \n2. \n## 关键证据\n- \n- \n- \n## 不确定项\n- \n## 处置建议\n1. \n2. \n\n案件快照：\n${snapshot}`
      : `This is the complete attack-chain investigation snapshot for case ${selected.id} (${selected.title}). It includes main-chain evidence, candidates, excluded items, evidence statements, and normalized events. Explain in concise Chinese: what the current chain is, which steps have evidence support, what remains only a candidate, and the next verification point. Do not call it a confirmed attack unless the supplied evidence proves it.\n\n${snapshot}`
    const context = { caseId: selected.id, windowIds: selected.windowIds, entityIds: entities, timeRange: '7d' }
    if (asReport) {
      onGenerateReport(task, context, { caseId: selected.id, caseTitle: selected.title })
      return
    }
    onSubmitBatch(task, context)
  }

  const graphOption = useMemo(() => ({
    tooltip: {},
    series: [{
      type: 'graph',
      layout: 'none',
      roam: true,
      categories: [{ name: '主链证据' }, { name: '候选证据' }, { name: '关联实体' }],
      legend: { top: 8, textStyle: { color: '#c6d4e4' } },
      data: [
        ...graphFindings.map((finding, index) => {
          const stage = board[finding.id] === 'main' ? 'main' : 'candidate'
          const active = activeFindingIds.has(finding.id)
          return {
          id: finding.id,
          name: finding.title,
          category: stage === 'main' ? 0 : 1,
          symbolSize: stage === 'main' ? 52 : 44,
          x: 140 + index * 160,
          y: 150 + (index % 2) * 80,
          itemStyle: {
            color: stage === 'main' ? '#e5484d' : '#f59e0b',
            borderColor: '#ffd8bf',
            borderWidth: 1.5,
            opacity: active ? (stage === 'main' ? 1 : 0.82) : 0.34,
          },
          label: { show: true, formatter: finding.title, fontSize: 11, color: '#f8fbff' },
          }
        }),
        ...graphEntities.map((entity, index) => ({
          id: entity,
          name: entity,
          category: 2,
          symbolSize: 34,
          x: 120 + index * 110,
          y: 350 + (index % 2) * 40,
          itemStyle: {
            color: '#f59e0b',
            borderColor: '#fde68a',
            borderWidth: 1.3,
          },
          label: { show: true, formatter: entity, fontSize: 11, color: '#f8fbff' },
        })),
      ],
      links: graphFindings.flatMap((finding) => finding.entities.filter((entity) => graphEntities.includes(entity)).slice(0, 2).map((entity) => ({
        source: finding.id,
        target: entity,
        lineStyle: activeFindingIds.has(finding.id)
          ? (board[finding.id] === 'main' ? { type: 'solid', width: 2.1, color: '#e87979' } : { type: 'dashed', width: 1.2, color: '#f4bf64' })
          : { type: 'dashed', width: 1, color: '#94a3b8', opacity: 0.32 },
      }))),
      lineStyle: { width: 1.3, opacity: 0.75, color: '#7ea6dc' },
      emphasis: { focus: 'adjacency' },
    }],
  }), [activeFindingIds, board, graphEntities, graphFindings])

  // Keep every hook above this guard: cases arrive asynchronously in replay mode.
  if (!selected) return null
  const selectedQueue = investigationQueueStatus(selected)
  const selectedQueueMeta = investigationQueueMeta[selectedQueue]
  const updateFindingStage = (findingId: string, stage: FindingStage) => {
    if (selectedQueue === 'auto_observe') setQueueFilter('manual')
    onSetFindingStage(selected.id, findingId, stage)
  }

  const renderStage = (stage: FindingStage, items: FindingRecord[]) => {
    const stageTitle = stage === 'main' ? '主链证据' : stage === 'candidate' ? '候选证据' : '已排除'
    const stageDescription = stage === 'main' ? '已纳入当前攻击链的证据' : stage === 'candidate' ? '暂时保留，等待进一步核验' : '当前不纳入攻击链'
    const StageIcon = stage === 'main' ? CheckCircleFilled : stage === 'candidate' ? ClockCircleOutlined : DeleteOutlined
    return (
      <Col span={24}>
        <Card
          title={<HelpTitle title={stageTitle} description={stageDescription} />}
          extra={<Tag>{items.length} 条</Tag>}
          className={`mc-panel mc-stage-card mc-stage-${stage}`}
        >
          <div className="mc-stage-caption">{stageDescription}</div>
          {items.length === 0 ? (
            <div className="mc-stage-empty">暂无条目</div>
          ) : (
            <div className="mc-stage-list">
              {items.map((item, index) => (
                <div className="mc-stage-item" key={item.id}>
                  <div className="mc-stage-item-marker">
                    <StageIcon />
                    {stage === 'main' && <span>{index + 1}</span>}
                  </div>
                  <div className="mc-stage-item-content">
                    <div className="mc-stage-item-head">
                      <div>
                        <Text strong className="mc-stage-item-title">
                          <ExplainableText fallback={item.title} context={{ caseId: selected.id, windowIds: [item.id], entityIds: [item.entity] }} onExplain={onExplain}>{item.title}</ExplainableText>
                        </Text>
                        <div className="mc-row-id">{item.id} · {item.start}</div>
                      </div>
                      <RiskBadge value={item.risk} />
                    </div>
                    <Paragraph className="mc-stage-item-summary">
                      <ExplainableText fallback={item.summary} context={{ caseId: selected.id, windowIds: [item.id], entityIds: [item.entity] }} onExplain={onExplain}>{item.summary}</ExplainableText>
                    </Paragraph>
                    <Space size={[6, 6]} wrap className="mc-stage-item-meta">
                      <Tag>{readableEntityType(item.entityType)} · {item.entity}</Tag>
                      <Tag color={activeFindingIds.has(item.id) ? 'green' : 'default'}>{activeFindingIds.has(item.id) ? `${timeRange} 当前窗口` : '历史锚点'}</Tag>
                      <Text type="secondary">{item.events.length} 条事件</Text>
                      <Text type="secondary">{item.host || '主机未解析'}</Text>
                    </Space>
                    <Space size={4} wrap className="mc-stage-item-actions">
                      {stage !== 'main' && <Button type="link" size="small" onClick={() => updateFindingStage(item.id, 'main')}>加入主链</Button>}
                      {stage !== 'candidate' && <Button type="link" size="small" onClick={() => updateFindingStage(item.id, 'candidate')}>保留候选</Button>}
                      {stage !== 'excluded' && <Button type="link" size="small" danger onClick={() => updateFindingStage(item.id, 'excluded')}>排除</Button>}
                    </Space>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </Col>
    )
  }

  return (
    <>
      <PageTitle title="链路与案件调查" subtitle="M5 长程关联将相关异常窗口聚类为攻击候选链，由分析员逐条核验主链证据并完成研判处置。" extra={<Space>{selectedQueue === 'auto_observe' && <Button type="primary" onClick={() => { setQueueFilter('manual'); onEscalateCase(selected.id) }}>升级人工案件</Button>}<Button onClick={() => onOpenAssistant(selected)}>分析当前链路</Button><Button icon={<RobotOutlined />} onClick={() => submitCase(false)}>提交给小影</Button><Button type="primary" icon={<RobotOutlined />} onClick={() => submitCase(true)}>生成分析报告</Button><Button danger icon={<DeleteOutlined />} onClick={() => onDeleteCase(selected.id)}>删除</Button></Space>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={6}>
          <Card title="链路队列" className="mc-investigation-list">
            <Segmented
              block
              value={datasetFilter}
              onChange={(value) => setDatasetFilter(value as typeof datasetFilter)}
              options={[
                { value: 'all', label: `全部 ${cases.length}` },
                { value: 'short', label: `Short ${datasetCounts.short}` },
                { value: 'long', label: `Long ${datasetCounts.long}` },
              ]}
              style={{ marginBottom: 8 }}
            />
            <Segmented
              block
              value={queueFilter}
              onChange={(value) => setQueueFilter(value as typeof queueFilter)}
              options={[
                ...[{ value: 'manual', label: `待研判 ${queueCounts.manual}` }, { value: 'auto', label: `自动 ${queueCounts.auto}` }, { value: 'resolved', label: `完成 ${queueCounts.resolved}` }]
                  .filter((option) => queueCounts[option.value as keyof typeof queueCounts] > 0),
                { value: 'all', label: `全部 ${casesByDataset.length}` },
              ]}
              style={{ marginBottom: 12 }}
            />
            <List
              dataSource={visibleCases}
              renderItem={(item) => (
                <List.Item className={item.id === selected?.id ? 'active' : ''} onClick={() => setSelectedId(item.id)} actions={[<Button key="delete" danger type="text" size="small" icon={<DeleteOutlined />} aria-label={`删除案件 ${item.title}`} onClick={(event) => { event.stopPropagation(); onDeleteCase(item.id) }} />]}>
                  <List.Item.Meta title={<Text strong>{item.title}</Text>} description={<Space size={4} wrap><Text type="secondary">{item.id}</Text><Tag color={investigationQueueMeta[investigationQueueStatus(item)].color}>{investigationQueueMeta[investigationQueueStatus(item)].label}</Tag></Space>} />
                  <Tag color={item.severity === 'critical' ? 'red' : 'orange'}>{severityLabel[item.severity]}</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={18}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3}>{selected.title}</Title>
                <Space size={6} wrap><Text type="secondary">{selected.id} · {selected.owner}</Text><Tag color={selectedQueueMeta.color}>{selectedQueueMeta.label}</Tag>{typeof selected.escalationScore === 'number' && <Tag color="geekblue">升级评分 {selected.escalationScore}</Tag>}</Space>
                <Paragraph style={{ margin: '8px 0 0' }}>{selected.summary}</Paragraph>
                <Space size={[6, 6]} wrap>
                  <Tag color="blue">多尺度上下文主动检索</Tag>
                  <Tag color="geekblue">跨时间窗口长周期关联</Tag>
                  <Tag color="cyan">跨源语义与实体关系建模</Tag>
                  {(selected.escalationReasons || []).slice(0, 3).map((reason) => <Tag key={reason}>{reason}</Tag>)}
                </Space>
              </div>
              <Space direction="vertical" align="end" size={4}>
                <Tag color="processing">锚点 {related[0]?.entity || '—'}</Tag>
                <Text type="secondary">完整链路 {related.length} 阶段 · {timeRange} 当前窗口 {activeRelatedCount} 阶段</Text>
              </Space>
            </div>
          </Card>

          <Row gutter={[12, 12]}>
            <Col span={24}>
              {datasetName && <Card title={<HelpTitle title={`${datasetName} · ${datasetName === 'Long' ? '7天' : '24小时'} ATT&CK 攻击链路`} description={`展示该日志最新事件向前 ${datasetName === 'Long' ? '7天' : '24小时'} 内可由日志事实串联的 ATT&CK 技术节点。节点名称是技术类型，点击节点查看全部相关事件、实体和原始日志；连线表示技术证据的时间顺序，不代表已确认攻击。${datasetName === 'Long' ? '长程窗口覆盖整条攻击链各阶段，链路通常比短程更长。' : ''}`} />} className="mc-panel">
                <InteractiveCaseGraph
                  key={`attack:${selected.id}`}
                  nodes={attackChainGraph.nodes}
                  links={attackChainGraph.links}
                  height={Math.max(420, Math.min(760, (Math.max(0, ...attackChainGraph.nodes.map((node) => node.y || 0)) + 150)))}
                  positions={graphPositions[`attack:${selected.id}`] || {}}
                  onPositionsChange={(positions) => saveInteractiveGraphPositions(`attack:${selected.id}`, positions)}
                  onNodeClick={(node) => {
                    const prompt = `你是安全分析助手。请解释这个 ATT&CK 技术节点，说明技术名称和战术阶段，并根据节点详情概括关键事件、实体、时间和原始日志依据。不要把候选技术映射写成已确认攻击。节点：${node.name}。说明：${node.description || '暂无补充说明'}。详情：${(node.details || []).join('；')}`
                    setGraphDetail({ title: node.name, kind: node.kind === 'technique' ? 'ATT&CK 技术节点' : node.kind === 'window' ? '关联窗口' : '事件或实体', description: node.description || '暂无补充说明', originalName: node.originalName, details: node.details, source: node.timestamp, prompt })
                  }}
                  onEdgeClick={(edge) => {
                    const sourceNode = attackChainGraph.nodes.find((node) => node.id === edge.source)
                    const targetNode = attackChainGraph.nodes.find((node) => node.id === edge.target)
                    const sourceName = sourceNode?.name || String(edge.source || '')
                    const targetName = targetNode?.name || String(edge.target || '')
                    const explanation = edge.explanation || `技术“${sourceName}”与“${targetName}”按日志时间顺序建立关联。建边依据：${edge.evidence || '暂无'}。`
                    const prompt = `你是安全分析助手。请解释 ATT&CK 技术边的前后技术、时间间隔、共享实体和原始日志依据。明确说明这只是证据顺序，不要写成已确认攻击。边：${explanation} 日志：${edge.evidence || '暂无'}。`
                    setGraphDetail({ title: 'ATT&CK 技术关联边', kind: '技术证据顺序', description: explanation, relation: edge.relation, evidence: edge.evidence, explanation, boundary: edge.boundary, source: sourceName, target: targetName, prompt })
                  }}
                />
              </Card>}
              <Card title={<HelpTitle title="M3 事件关联图" description="仅展示已保存的当前事件 30 分钟事实窗口：事件、实体、时间先后和涉及关系。该图不承担 ATT&CK 阶段判断。" />} className="mc-panel">
                <Space wrap>
                  <Text type="secondary">{savedM3Graphs.length ? `已保存 ${savedM3Graphs.length} 个 30 分钟 M3 窗口，当前展示最早保存的窗口。` : '请在发现或日志检索中选择事件并保存其 30 分钟 M3 关联图。'}</Text>
                </Space>
                {activeM3Graph ? (
                  <InteractiveCaseGraph
                    key={`m3:${activeM3Graph.findingId}`}
                    nodes={activeM3Graph.nodes}
                    links={activeM3Graph.links}
                    height={420}
                    positions={graphPositions[`m3:${activeM3Graph.findingId}`] || {}}
                    onPositionsChange={(positions) => saveInteractiveGraphPositions(`m3:${activeM3Graph.findingId}`, positions)}
                    onNodeClick={(node) => {
                      const prompt = `你是安全分析助手。请解释这个M3节点的实际含义，控制在120字以内。实体要说明原始名称，事件要说明具体行为和时间，不要使用空泛套话。节点：${node.name}。说明：${node.description || '暂无补充说明'}。`
                      setGraphDetail({ title: node.name, kind: node.kind === 'entity' ? '实体节点' : '事件节点', description: node.description || '暂无补充说明', originalName: node.originalName, details: node.details, source: node.timestamp, prompt })
                    }}
                    onEdgeClick={(edge) => {
                      const source = activeM3Graph.nodes.find((node) => node.id === edge.source)
                      const target = activeM3Graph.nodes.find((node) => node.id === edge.target)
                      const sourceMeaning = source?.details?.find((item) => item.startsWith('事件含义：')) || `事件“${source?.name || edge.source}”的具体行为需要结合原始日志核对。`
                      const targetMeaning = target?.details?.find((item) => item.startsWith('事件含义：')) || `事件“${target?.name || edge.target}”的具体行为需要结合原始日志核对。`
                      const explanation = edge.explanation || limitGraphExplanation(edge.relation === '时间先后'
                        ? `${sourceMeaning} 后一事件：${targetMeaning} 两者按时间戳先后连接。建边日志依据：${edge.evidence || '事件时间字段'}。该关系用于还原行为顺序，不单独证明因果或攻击。`
                        : `${sourceMeaning} 日志中出现实体“${target?.originalName || target?.name || edge.target}”，因此建立事件与实体的事实关系。建边日志依据：${edge.evidence || '事件实体字段'}。该关系说明事实归属，不代表实体已被判定为攻击者。`)
                      const prompt = `你是安全分析助手。请解释这条M3事件边的具体含义，控制在120字以内。说明两个节点的事件行为、实体角色、时间或日志依据，不要使用空泛套话，也不要把事实关联写成攻击结论。解释：${explanation} 日志：${edge.evidence || '暂无'}。`
                      setGraphDetail({ title: 'M3 事件关联边', kind: edge.relation || '事件关系', description: explanation, relation: edge.relation, evidence: edge.evidence, explanation, boundary: edge.boundary, source: source?.name, target: target?.name, prompt })
                    }}
                  />
                ) : <ChartFallback height={320} />}
              </Card>
            </Col>
          </Row>

          <Row gutter={[12, 12]}>
            {renderStage('main', main)}
            {renderStage('candidate', candidate)}
            {renderStage('excluded', excluded)}
          </Row>

          <Row gutter={[12, 12]}>
            <Col xs={24} lg={14}>
              <Card title={<HelpTitle title="证据时间线" description="按发生时间排列案件中的关键事件，便于核对先后关系和调查状态。" />} className="mc-panel">
                <Table
                  rowKey="id"
                  size="small"
                  pagination={{ pageSize: 6, hideOnSinglePage: true }}
                  columns={[
                    { title: '发生时间', dataIndex: 'start', key: 'start', width: 165 },
                    { title: '发生了什么', dataIndex: 'title', key: 'title', width: 220 },
                    { title: '涉及实体', dataIndex: 'entity', key: 'entity', width: 145 },
                    { title: '证据说明', key: 'statement', render: (_: unknown, row: FindingRecord) => evidenceByFinding[row.id]?.[0]?.statement || row.summary },
                    { title: '窗口归属', key: 'scope', width: 105, render: (_: unknown, row: FindingRecord) => <Tag color={activeFindingIds.has(row.id) ? 'green' : 'default'}>{activeFindingIds.has(row.id) ? timeRange : '历史锚点'}</Tag> },
                    { title: '调查状态', key: 'stage', width: 105, render: (_: unknown, row: FindingRecord) => <Tag color={board[row.id] === 'main' ? 'blue' : board[row.id] === 'candidate' ? 'orange' : 'default'}>{readableStage(board[row.id] || 'candidate')}</Tag> },
                  ]}
                  dataSource={[...related].sort((a, b) => a.start.localeCompare(b.start))}
                  locale={{ emptyText: '当前案件暂无可展示证据' }}
                  scroll={{ x: 880 }}
                />
                {/*
                  items={related.map((finding) => {
                    const stage = board[finding.id]
                    const dot = stage === 'main'
                      ? <CheckCircleFilled style={{ color: '#1677ff' }} />
                      : stage === 'candidate'
                        ? <ClockCircleOutlined style={{ color: '#f59e0b' }} />
                        : <span style={{ color: '#94a3b8' }}>×</span>
                    return {
                      dot,
                      children: (
                        <div>
                          <strong>{finding.start} · {finding.title}</strong>
                          <div><Text type="secondary">{finding.id} · {finding.entity} · {stage}</Text></div>
                          <div><Text>{evidenceByFinding[finding.id]?.[0]?.statement || finding.summary}</Text></div>
                        </div>
                      ),
                    }
                  })}
                */}
              </Card>
            </Col>
            <Col xs={24} lg={10}>
              <Card title={<HelpTitle title="实体枢轴" description="汇总案件中反复出现的用户、主机、进程和地址，用于快速切换调查对象。" />} className="mc-panel">
                <List
                  dataSource={entityStats}
                  renderItem={(item) => (
                    <List.Item actions={[<a key="open" onClick={() => onOpenEntity(item.entity)}>查看实体</a>]}>
                      <List.Item.Meta title={<Text strong>{item.entity}</Text>} description={`${item.type} · 参与 ${item.findingCount} 个发现 · ${item.eventCount} 条事件 · ${item.hosts.join('、') || '主机未解析'}`} />
                    </List.Item>
                  )}
                />
              </Card>
            </Col>
          </Row>
        </Col>
      </Row>
      <Drawer open={Boolean(graphDetail)} onClose={() => setGraphDetail(null)} width={420} title={graphDetail?.title}>
        {graphDetail && (
          <>
          <Descriptions bordered size="small" column={1}>
            <Descriptions.Item label="节点/边类型">{graphDetail.kind}</Descriptions.Item>
            <Descriptions.Item label="关联依据">{graphDetail.description}</Descriptions.Item>
            {graphDetail.evidence && <Descriptions.Item label="日志证据">{graphDetail.evidence}</Descriptions.Item>}
            {graphDetail.relation && <Descriptions.Item label="关系类型">{graphDetail.relation}</Descriptions.Item>}
            {graphDetail.source && <Descriptions.Item label="来源或起点">{graphDetail.source}</Descriptions.Item>}
            {graphDetail.target && <Descriptions.Item label="终点">{graphDetail.target}</Descriptions.Item>}
          </Descriptions>
          <Card size="small" title="解释详情" style={{ marginTop: 12 }}>
            {graphDetail.explanation && <Paragraph>{graphDetail.explanation}</Paragraph>}
            {graphDetail.boundary && <Paragraph type="secondary">判断边界：{graphDetail.boundary}</Paragraph>}
            {graphDetail.originalName && <Paragraph>原始实体名：{graphDetail.originalName}</Paragraph>}
            {graphDetail.details?.map((detail) => <Paragraph key={detail} style={{ marginBottom: 4 }}>{detail}</Paragraph>)}
          </Card>
          </>
        )}
      </Drawer>
    </>
  )
}
