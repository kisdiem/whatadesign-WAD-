import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Button, Card, Col, Descriptions, Drawer, List, Row, Segmented, Space, Table, Tag, Typography } from 'antd'
import { CheckCircleFilled, ClockCircleOutlined, DeleteOutlined, RobotOutlined } from '@ant-design/icons'
import type { Investigation } from '../mocks/data'
import type { AssistantContext } from '../services/api'
import {
  buildM3GraphSnapshot,
  layoutForceDirected,
  limitGraphExplanation,
  type CaseGraphLink,
  type CaseGraphNode,
  type M3GraphSnapshot,
} from '../services/caseGraphs'
import { extractAutoAttackChain, type ModuleScoresMap } from '../services/autoAttackChain'
import { inferEntityType, type CaseBoard, type EvidenceRecord, type FindingRecord, type FindingStage } from '../services/investigationDomain'
import InteractiveCaseGraph, { type CaseGraphLegendItem, type CaseGraphNodeLegendItem } from '../InteractiveCaseGraph'
import {
  ChartFallback,
  ExplainableText,
  HelpTitle,
  PageTitle,
  RiskBadge,
  investigationQueueMeta,
  investigationQueueStatus,
  readableAction,
  readableEntityType,
  readableStage,
  severityLabel,
} from './shared'

const { Text, Title, Paragraph } = Typography

function caseDataset(item: Investigation): 'short' | 'long' | 'apt' | 'other' {
  // 保存 M3 关联图会新建 CASE-WIN-<数据集> 案件；其 id 也携带数据集前缀，需一并识别。
  if (item.id.startsWith('CASE-WIN-SHORT-')) return 'short'
  if (item.id.startsWith('CASE-WIN-LONG-')) return 'long'
  if (item.id.startsWith('CASE-WIN-APT-')) return 'apt'
  if (item.id.startsWith('APT-')) return 'apt'
  if (item.windowIds.some((id) => id.startsWith('WIN-SHORT-'))) return 'short'
  if (item.windowIds.some((id) => id.startsWith('WIN-LONG-'))) return 'long'
  if (item.windowIds.some((id) => id.startsWith('WIN-APT-'))) return 'apt'
  if (item.title.startsWith('Short')) return 'short'
  if (item.title.startsWith('Long')) return 'long'
  if (item.title.startsWith('APT')) return 'apt'
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
  onInsertEvidence,
  onExcludeEvidence,
  onSubmitBatch,
  onExplain,
  onOpenEntity,
  m3GraphSnapshots,
  moduleScoresByEvent,
  onDeleteCase,
  onCompleteCase,
  onReopenCase,
}: {
  cases: Investigation[]
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  caseBoards: Record<string, CaseBoard>
  activeFindingIds: Set<string>
  timeRange: string
  onSetFindingStage: (caseId: string, findingId: string, stage: FindingStage) => void
  onInsertEvidence: (caseId: string, findingId: string, afterId: string) => void
  onExcludeEvidence: (caseId: string, findingId: string) => void
  onSubmitBatch: (prompt: string, context: AssistantContext) => void
  onExplain: (excerpt: string, context: AssistantContext) => void
  onOpenEntity: (entityId: string) => void
  m3GraphSnapshots: Record<string, M3GraphSnapshot>
  moduleScoresByEvent?: ModuleScoresMap
  onDeleteCase: (caseId: string) => void
  onCompleteCase: (caseId: string) => void
  onReopenCase: (caseId: string) => void
}) {
  const location = useLocation()
  const [selectedId, setSelectedId] = useState(cases[0]?.id || '')
  const [queueFilter, setQueueFilter] = useState<'manual' | 'resolved' | 'all'>('manual')
  const [datasetFilter, setDatasetFilter] = useState<'all' | 'short' | 'long' | 'apt' | 'other'>('all')
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
    if (datasetFilter === 'apt' && caseDataset(item) !== 'apt') return false
    if (datasetFilter === 'other' && caseDataset(item) !== 'other') return false
    return true
  }), [cases, datasetFilter])
  const visibleCases = useMemo(() => casesByDataset.filter((item) => {
    const queue = investigationQueueStatus(item)
    if (queueFilter === 'manual') return ['manual_review', 'auto_observe', 'suppressed', 'merged'].includes(queue)
    if (queueFilter === 'resolved') return queue === 'resolved'
    return true
  }), [casesByDataset, queueFilter])
  const datasetCounts = useMemo(() => ({
    short: cases.filter((item) => caseDataset(item) === 'short').length,
    long: cases.filter((item) => caseDataset(item) === 'long').length,
    apt: cases.filter((item) => caseDataset(item) === 'apt').length,
    other: cases.filter((item) => caseDataset(item) === 'other').length,
  }), [cases])
  const queueCounts = useMemo(() => ({
    manual: casesByDataset.filter((item) => ['manual_review', 'auto_observe', 'suppressed', 'merged'].includes(investigationQueueStatus(item))).length,
    resolved: casesByDataset.filter((item) => investigationQueueStatus(item) === 'resolved').length,
  }), [casesByDataset])
  useEffect(() => {
    if (requestedCase) {
      setSelectedId(requestedCase)
      const requested = cases.find((item) => item.id === requestedCase)
      if (requested) {
        setQueueFilter(investigationQueueStatus(requested) === 'resolved' ? 'resolved' : 'manual')
      }
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
  // 证据缺口：待补全的真证据 + 干扰项混合，已补入主链的从中移除。
  const gapCandidateIds = selected
    ? [...(selected.gapEvidenceIds || []), ...(selected.gapDistractorIds || [])].filter((id) => !selected.windowIds.includes(id))
    : []
  const gapFindings = findings.filter((finding) => gapCandidateIds.includes(finding.id))
  // 证据链研判图：主链按 windowIds 顺序构成单向链，水平单行排列、超出画布自动换行；
  // 候选证据（真证据 + 干扰项混合）作为独立黄色节点在下方自由池待研判。
  const mainOrdered = selected
    ? selected.windowIds.map((id) => findings.find((finding) => finding.id === id)).filter((finding): finding is FindingRecord => Boolean(finding))
    : []
  const candidateIdSet = new Set(gapFindings.map((finding) => finding.id))
  const CHAIN_ORIGIN_X = 110
  const CHAIN_ORIGIN_Y = 90
  const CHAIN_STEP_X = 160
  const CHAIN_STEP_Y = 115
  const CHAIN_MAX_X = 960
  const chainPositions = new Map<string, { x: number; y: number }>()
  let chainX = CHAIN_ORIGIN_X
  let chainY = CHAIN_ORIGIN_Y
  mainOrdered.forEach((finding) => {
    if (chainX + CHAIN_STEP_X > CHAIN_MAX_X) { chainX = CHAIN_ORIGIN_X; chainY += CHAIN_STEP_Y }
    chainPositions.set(finding.id, { x: chainX, y: chainY })
    chainX += CHAIN_STEP_X
  })
  const candidateOriginY = chainY + CHAIN_STEP_Y + 34
  const assemblyNodes: CaseGraphNode[] = [
    ...mainOrdered.map((finding) => {
      const pos = chainPositions.get(finding.id)!
      return {
        id: finding.id,
        name: finding.title.length > 18 ? `${finding.title.slice(0, 18)}…` : finding.title,
        category: 0,
        kind: 'window' as const,
        timestamp: finding.start,
        description: finding.summary,
        x: pos.x,
        y: pos.y,
      }
    }),
    ...gapFindings.map((finding, index) => {
      const row = Math.floor(index / 5)
      const col = index % 5
      return {
        id: finding.id,
        name: finding.title.length > 18 ? `${finding.title.slice(0, 18)}…` : finding.title,
        category: 2,
        kind: 'window' as const,
        timestamp: finding.start,
        description: finding.summary,
        x: CHAIN_ORIGIN_X + col * CHAIN_STEP_X,
        y: candidateOriginY + row * CHAIN_STEP_Y,
      }
    }),
  ]
  // 主链边：windowIds 相邻节点依次连接，构成单向链。
  const assemblyLinks: CaseGraphLink[] = []
  for (let index = 0; index < mainOrdered.length - 1; index += 1) {
    assemblyLinks.push({ source: mainOrdered[index].id, target: mainOrdered[index + 1].id, relation: '时间先后', label: '' })
  }
  const graphFindings = related.filter((finding) => board[finding.id] !== 'excluded')
  const datasetName = selected ? (caseDataset(selected) === 'short' ? 'Short' : caseDataset(selected) === 'long' ? 'Long' : caseDataset(selected) === 'apt' ? 'APT' : '') : ''
  // 攻击链图以当前案件时间窗口为核心，聚合同一数据集内同时段的相关发现，
  // 使图包含更多技术节点。Short 短时突发只聚焦案件窗口本身；Long 覆盖整条
  // 7 天战役范围，保证长程链呈现完整攻击链、链路显著长于短程。
  const attackGraphFindings = useMemo(() => {
    if (!datasetName) return graphFindings
    // Short 短时突发只聚焦当前案件窗口本身（不向四周扩展背景事件）；
    // Long 长程关联扩展全 7 天，恢复完整攻击链，使长程链明显长于短程。
    if (datasetName === 'Short') return graphFindings
    const relatedTimes = related.flatMap((finding) => finding.events.map((event) => Date.parse(event.time))).filter(Number.isFinite)
    if (!relatedTimes.length) return graphFindings
    const minT = Math.min(...relatedTimes)
    const maxT = Math.max(...relatedTimes)
    const pad = 7 * 24 * 60 * 60 * 1000
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
  // 自动攻击链提取：与链图同源（attackGraphFindings），额外输出阶段覆盖与链级罕见度。
  const autoChain = useMemo(
    () => extractAutoAttackChain(attackGraphFindings, moduleScoresByEvent),
    [attackGraphFindings, moduleScoresByEvent],
  )
  // 优先展示已保存的 M3 快照；没有时用案件窗口内第一条 finding 就地构建一张，
  // 保证待研判/已定案案件打开即有 M3 关联图，而不是空面板。
  const activeM3Graph = useMemo(() => {
    if (savedM3Graphs[0]) return savedM3Graphs[0]
    const first = related[0]
    return first ? buildM3GraphSnapshot(first) : undefined
  }, [savedM3Graphs, related])
  // 无坐标的 M3 快照（旧数据）在会话内补一次力导向布局；新保存的快照已带布局坐标。
  const m3GraphLayout = useMemo(() => {
    if (!activeM3Graph) return null
    const hasLayout = activeM3Graph.nodes.some((node) => node.x !== undefined && node.y !== undefined)
    return hasLayout ? { nodes: activeM3Graph.nodes, links: activeM3Graph.links } : layoutForceDirected(activeM3Graph.nodes, activeM3Graph.links)
  }, [activeM3Graph])
  const m3Legend: CaseGraphLegendItem[] = [
    { style: 'solid', color: '#b91c1c', label: '涉及：事件包含该实体' },
    { style: 'dashed', color: '#2563eb', label: '先于：按日志时间先后' },
    { style: 'dotted', color: '#94a3b8', label: '共同参与：同一事件实体' },
  ]
  const m3NodeLegend: CaseGraphNodeLegendItem[] = [
    { color: '#2563eb', label: '事件节点：30 分钟内日志事实' },
    { color: '#64748b', label: '实体节点：用户/主机/进程/IP' },
  ]
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

  const submitCase = () => {
    const snapshot = related.map((finding) => {
      const stage = readableStage(board[finding.id] || 'candidate')
      const evidence = evidenceByFinding[finding.id]?.map((item) => item.statement).filter(Boolean).join('; ') || finding.summary
      const events = finding.events.map((event) => `${event.time} ${readableAction(event.action)} ${event.actor || ''} ${event.host || ''} ${event.process || event.ip || ''}`.trim()).join(' | ')
      return `stage=${stage}; time=${finding.start}; finding_id=${finding.id}; finding=${finding.title}; entity=${finding.entity}; host=${finding.host || 'unresolved'}; risk=${finding.risk}; summary=${finding.summary}; evidence=${evidence}; events=${events}`
    }).join('\n')
    const task = `This is the complete attack-chain investigation snapshot for case ${selected.id} (${selected.title}). It includes main-chain evidence, candidates, excluded items, evidence statements, and normalized events. Explain in concise Chinese: what the current chain is, which steps have evidence support, what remains only a candidate, and the next verification point. Do not call it a confirmed attack unless the supplied evidence proves it.\n\n${snapshot}`
    onSubmitBatch(task, { caseId: selected.id, windowIds: selected.windowIds, entityIds: entities, timeRange: '7d' })
  }

  const sendChainReconstruction = () => {
    const mainSnapshot = mainOrdered.map((finding, index) =>
      `${index + 1}. ${finding.title}（${finding.id}）[实体:${finding.entity}][风险:${finding.risk}][${finding.start}] ${finding.summary}`,
    ).join('\n')
    const candidateSnapshot = gapFindings.map((finding, index) =>
      `候选${index + 1}. ${finding.title}（${finding.id}）[实体:${finding.entity}][风险:${finding.risk}][${finding.start}] ${finding.summary}`,
    ).join('\n')
    const prompt = `请基于当前攻击链路研判图，辅助判断如何还原完整攻击链。\n\n当前已确认主链（按时间先后）：\n${mainSnapshot || '（空）'}\n\n候选证据池（尚未纳入主链）：\n${candidateSnapshot || '（空）'}\n\n请给出：1）最可能的完整攻击链顺序——列出应纳入主链的候选及其插入位置（插到哪个已确认节点之前/之后）；2）每条建议的依据（时间先后、实体、行为）；3）建议排除的候选及原因。用简洁中文分点回答，除非证据已证明，否则不要写成“已确认入侵”。`
    onSubmitBatch(prompt, { caseId: selected.id, windowIds: selected.windowIds, entityIds: entities, timeRange })
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
          name: `${index + 1}. ${readableAction(finding.anchorEvent.action)}`,
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
          label: { show: true, formatter: `${index + 1}. ${readableAction(finding.anchorEvent.action)}`, fontSize: 11, color: '#f8fbff' },
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
                        <div className="mc-row-id">{item.start}</div>
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
      <PageTitle title="链路与案件调查" subtitle="M5 长程关联将相关异常窗口聚类为攻击候选链，由分析员逐条核验主链证据并完成研判处置。" extra={<Space>{(selectedQueue === 'resolved' ? <Button onClick={() => { setQueueFilter('manual'); onReopenCase(selected.id) }}>移回待研判</Button> : <Button type="primary" onClick={() => { setQueueFilter('resolved'); onCompleteCase(selected.id) }}>完成研判</Button>)}<Button type="primary" icon={<RobotOutlined />} onClick={submitCase}>小影</Button><Button danger icon={<DeleteOutlined />} onClick={() => onDeleteCase(selected.id)}>删除</Button></Space>} />
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
                ...(datasetCounts.apt > 0 ? [{ value: 'apt' as const, label: `APT ${datasetCounts.apt}` }] : []),
                ...(datasetCounts.other > 0 ? [{ value: 'other' as const, label: `其他 ${datasetCounts.other}` }] : []),
              ]}
              style={{ marginBottom: 8 }}
            />
            <Segmented
              block
              value={queueFilter}
              onChange={(value) => setQueueFilter(value as typeof queueFilter)}
              options={[
                ...[{ value: 'manual', label: `待研判 ${queueCounts.manual}` }, { value: 'resolved', label: `已定案 ${queueCounts.resolved}` }]
                  .filter((option) => queueCounts[option.value as keyof typeof queueCounts] > 0),
                { value: 'all', label: `全部 ${casesByDataset.length}` },
              ]}
              style={{ marginBottom: 12 }}
            />
            <List
              dataSource={visibleCases}
              renderItem={(item) => (
                <List.Item className={item.id === selected?.id ? 'active' : ''} onClick={() => setSelectedId(item.id)} actions={[<Button key="delete" danger type="text" size="small" icon={<DeleteOutlined />} aria-label={`删除案件 ${item.title}`} onClick={(event) => { event.stopPropagation(); onDeleteCase(item.id) }} />]}>
                  <List.Item.Meta title={<Text strong>{item.title}</Text>} description={<Space size={4} wrap><Text type="secondary">{item.createdAt}</Text><Tag color={investigationQueueMeta[investigationQueueStatus(item)].color}>{investigationQueueMeta[investigationQueueStatus(item)].label}</Tag></Space>} />
                  <span className={`mc-severity-chip ${item.severity}`}>{severityLabel[item.severity]}</span>
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
                <Space size={6} wrap><span className={`mc-severity-chip ${selected.severity}`}>{severityLabel[selected.severity]}</span><Tag color={selectedQueueMeta.color}>{selectedQueueMeta.label}</Tag><Text type="secondary">负责人：{selected.owner}</Text></Space>
                <Paragraph className="mc-case-summary">{selected.summary}</Paragraph>
                <Space size={[6, 6]} wrap className="mc-case-priority-row">
                  <Tag color="red">主链 {main.length} 步</Tag>
                  <Tag color="orange">候选 {candidate.length} 步</Tag>
                  <Tag color="blue">关联事件 {related.length} 条</Tag>
                  {typeof selected.escalationScore === 'number' && <Tag color="volcano">升级评分 {selected.escalationScore}</Tag>}
                </Space>
              </div>
              <Space direction="vertical" align="end" size={4}>
                <Tag color="processing">锚点：{related[0]?.entity || '—'}</Tag>
                <Text type="secondary">当前窗口 {activeRelatedCount} / {related.length} 条</Text>
              </Space>
            </div>
          </Card>

          <Row gutter={[12, 12]}>
            <Col span={24}>
              {datasetName && <Card title={<HelpTitle title={`${datasetName} · 攻击链路研判`} description={`上方红色为已确认的主链证据窗口，按时间顺序构成单向链。下方黄色虚线为候选证据自由池，等待人工核验。拖拽候选到主链任意节点前后即可插入，拖到右上角排除区即可移除。${datasetName === 'Long' ? 'Long 长程窗口主链更长、候选更多，体现长周期关联能召回短窗口看不到的早期阶段。' : ''}`} />} extra={<Button type="primary" icon={<RobotOutlined />} size="small" onClick={sendChainReconstruction}>小影</Button>} className="mc-panel">
                {autoChain && (
                  <div style={{ marginBottom: 12 }}>
                    <Space wrap size={6}>
                      <Tag color="green">系统自动提取</Tag>
                      <Text strong>链罕见度 {Math.round(autoChain.rarity * 100)}% · {autoChain.rarityLabel}</Text>
                      <Text type="secondary">{autoChain.eventsCount} 条证据 · 覆盖 {autoChain.coverage} 个战术阶段 · 跨度 {autoChain.spanHours >= 24 ? `${(autoChain.spanHours / 24).toFixed(1)} 天` : autoChain.spanHours >= 1 ? `${autoChain.spanHours.toFixed(1)} 小时` : `${Math.max(1, Math.round(autoChain.spanHours * 60))} 分钟`}</Text>
                      <Text type="secondary">案件基准链 {related.length} 阶段</Text>
                    </Space>
                    <div style={{ display: 'flex', gap: 8, overflowX: 'auto', marginTop: 10, paddingBottom: 4 }}>
                      {autoChain.stages.map((stage, index) => (
                        <div key={stage.tactic} style={{ flex: '0 0 auto', minWidth: 168, padding: '8px 12px', border: '1px solid #dbe4ee', borderRadius: 8, background: index % 2 === 0 ? '#f8fafc' : '#ffffff' }}>
                          <div style={{ fontSize: 11, color: '#64748b' }}>{index + 1} · {stage.tactic}</div>
                          <div style={{ fontWeight: 600, fontSize: 13, margin: '2px 0' }}>{stage.techniqueIds.join(' / ') || '—'}</div>
                          <div style={{ fontSize: 11, color: '#94a3b8' }}>{stage.events.length} 条证据 · {stage.events[0]?.time.slice(5, 16).replace('T', ' ') || '—'}</div>
                        </div>
                      ))}
                    </div>
                    <Paragraph type="secondary" style={{ margin: '8px 0 0', fontSize: 12 }}>
                      {autoChain.summary} {autoChain.extractionNote}
                    </Paragraph>
                  </div>
                )}
                <InteractiveCaseGraph
                  key={`chain:${selected.id}`}
                  nodes={assemblyNodes}
                  links={assemblyLinks}
                  height={420}
                  positions={graphPositions[`chain:${selected.id}`] || {}}
                  onPositionsChange={(positions) => saveInteractiveGraphPositions(`chain:${selected.id}`, positions)}
                  candidateIds={candidateIdSet}
                  onInsertAtGap={(sourceId, afterId) => onInsertEvidence(selected.id, sourceId, afterId)}
                  onExcludeNode={(nodeId) => onExcludeEvidence(selected.id, nodeId)}
                  nodeLegend={[
                    { color: '#dc2626', label: '已确认主链' },
                    { color: '#f59e0b', label: '候选证据（待研判）' },
                  ]}
                  onNodeClick={(node) => {
                    setGraphDetail({ title: node.name, kind: candidateIdSet.has(node.id) ? '候选证据' : '主链证据窗口', description: node.description || '暂无补充说明', details: node.details, source: node.timestamp })
                  }}
                  onEdgeClick={(edge) => {
                    const sourceNode = assemblyNodes.find((node) => node.id === edge.source)
                    const targetNode = assemblyNodes.find((node) => node.id === edge.target)
                    setGraphDetail({ title: '证据先后', kind: '时间先后', description: `“${sourceNode?.name || edge.source}”按日志时间先于“${targetNode?.name || edge.target}”发生，用于还原攻击演进顺序，不代表因果关系。`, source: sourceNode?.name, target: targetNode?.name })
                  }}
                />
              </Card>}
              <Card title={<HelpTitle title="M3 事件关联图" description="展示当前案件的 30 分钟事实窗口：事件、实体、时间先后和涉及关系。优先使用已保存快照；未保存时按案件窗口自动构建。该图不承担 ATT&CK 阶段判断。" />} className="mc-panel">
                <Space wrap>
                  <Text type="secondary">{savedM3Graphs.length ? `已保存 ${savedM3Graphs.length} 个 30 分钟 M3 窗口，当前展示最早保存的窗口。` : `当前为按案件窗口自动构建的 M3 关联图（锚点 ${related[0]?.id || '—'}）；可在发现或日志检索中选择事件并保存固定快照。`}</Text>
                </Space>
                {activeM3Graph && m3GraphLayout ? (
                  <InteractiveCaseGraph
                    key={`m3:${activeM3Graph.findingId}`}
                    nodes={m3GraphLayout.nodes}
                    links={m3GraphLayout.links}
                    height={420}
                    positions={graphPositions[`m3:${activeM3Graph.findingId}`] || {}}
                    onPositionsChange={(positions) => saveInteractiveGraphPositions(`m3:${activeM3Graph.findingId}`, positions)}
                    legend={m3Legend}
                    nodeLegend={m3NodeLegend}
                    staticView
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
                    { title: '发生了什么', key: 'title', width: 220, render: (_: unknown, row: FindingRecord) => <div><Text strong>{readableAction(`${row.anchorEvent.action} ${row.anchorEvent.raw || ''}`)}</Text><div className="mc-row-id">{row.entity}</div></div> },
                    { title: '涉及实体', dataIndex: 'entity', key: 'entity', width: 145 },
                    { title: '证据摘要', key: 'statement', render: (_: unknown, row: FindingRecord) => <span className="mc-evidence-summary">{evidenceByFinding[row.id]?.[0]?.statement || row.summary}</span> },
                    { title: '调查状态', key: 'stage', width: 105, render: (_: unknown, row: FindingRecord) => <Tag color={board[row.id] === 'main' ? 'red' : board[row.id] === 'candidate' ? 'orange' : 'default'}>{readableStage(board[row.id] || 'candidate')}</Tag> },
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
                          <div><Text type="secondary">{finding.entity} · {stage}</Text></div>
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
            <Descriptions.Item label="对象类型">{graphDetail.kind}</Descriptions.Item>
            {graphDetail.relation && <Descriptions.Item label="关系类型">{graphDetail.relation}</Descriptions.Item>}
            {graphDetail.source && <Descriptions.Item label="来源或起点">{graphDetail.source}</Descriptions.Item>}
            {graphDetail.target && <Descriptions.Item label="终点">{graphDetail.target}</Descriptions.Item>}
          </Descriptions>
          <div className="mc-evidence-sections">
            <div className="mc-evidence-section">
              <Text strong>事实</Text>
              <Paragraph>{graphDetail.evidence || graphDetail.details?.find((detail) => /原始日志|原始事件|日志/.test(detail)) || graphDetail.originalName || '当前节点或关系暂无原始日志事实。'}</Paragraph>
            </div>
            <div className="mc-evidence-section">
              <Text strong>判断</Text>
              <Paragraph>{graphDetail.explanation || graphDetail.description || '当前没有额外的模型判断。'}</Paragraph>
              {graphDetail.originalName && <Text type="secondary">原始名称：{graphDetail.originalName}</Text>}
            </div>
            <div className="mc-evidence-section">
              <Text strong>关联证据</Text>
              <Paragraph>{graphDetail.relation
                ? `${graphDetail.source || '来源节点'} 与 ${graphDetail.target || '目标节点'} 通过“${graphDetail.relation}”建立关联。`
                : graphDetail.boundary || '该节点属于当前 30 分钟调查窗口，需结合时间、实体和相邻事件核对。'}</Paragraph>
              {graphDetail.details?.filter((detail) => !/原始日志|原始事件|日志/.test(detail)).map((detail) => <Paragraph key={detail} style={{ marginBottom: 4 }}>{detail}</Paragraph>)}
            </div>
          </div>
          </>
        )}
      </Drawer>
    </>
  )
}
