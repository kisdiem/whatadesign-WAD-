import { Suspense, lazy, useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Drawer,
  Input,
  Layout,
  List,
  Menu,
  Progress,
  Row,
  Segmented,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Timeline,
  Upload,
  Typography,
  message,
} from 'antd'
import {
  ApartmentOutlined,
  CheckCircleFilled,
  ClockCircleOutlined,
  FileSearchOutlined,
  InboxOutlined,
  ReloadOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SendOutlined,
  ThunderboltOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import {
  anomalyWindows,
  investigations,
  logSources,
  overviewSeries,
  type Investigation,
  type LogSource,
  type SecurityEvent,
  type Severity,
} from './mocks/data'
import {
  askAssistant,
  getSecurityBaseline,
  getSecurityEntity,
  getSecurityEntityHistory,
  getLogSources,
  getInvestigations,
  getDetectionManifest,
  getEvaluationReport,
  getScaleReport,
  getCapacitySimulation,
  getLogIndexMetadata,
  getLogIndexOverview,
  getWindows,
  isUsingLocalData,
  searchSecurityLogs,
  type AssistantAnswer,
  type AssistantContext,
  type AssistantStructuredItem,
  type AssistantStructuredResult,
  type AssistantVerificationSummary,
  type SecurityBaselineRecord,
  type SecurityEntityRecord,
  type SecurityLogRecord,
  type DetectionManifest,
  type EvaluationReport,
  type ScaleReport,
  type CapacitySimulation,
  type LogIndexMetadata,
  type LogIndexOverview,
} from './services/api'
import {
  buildEntityProfiles,
  buildEvidence,
  buildFindings,
  inferEntityType,
  initialCaseBoards,
  type CaseBoard,
  type EntityProfile,
  type EvidenceRecord,
  type FindingRecord,
  type FindingStage,
  type FindingStatus,
} from './services/investigationDomain'

const { Header, Sider, Content } = Layout
const { Title, Text, Paragraph } = Typography
const { Dragger } = Upload
const PREFER_DEMO_DATA = import.meta.env.VITE_PREFER_DEMO_DATA === 'true'
const EChartsView = lazy(() => import('./EChartsView'))

type EventRow = {
  id: string
  time: string
  source: string
  action: string
  actor?: string
  host?: string
  process?: string
  ip?: string
  raw: string
  rawLogRef?: string
  originalTimestamp?: string
  entities?: string[]
  findingId?: string
  findingTitle: string
  risk?: number
  evidenceIds: string[]
}

type UploadSourceEntry = {
  uid: string
  name: string
  size: number
}

type ImportTask = {
  id: string
  name: string
  kind: string
  size: number
  progress: number
  status: 'queued' | 'parsing' | 'indexed' | 'ready'
  result: string
}

type ChatItem = {
  role: 'user' | 'assistant'
  content: string
  evidence?: AssistantAnswer['evidence']
  verified?: boolean
  confidence?: number
  structured?: AssistantStructuredResult
  verification?: AssistantVerificationSummary
}

type AssistantQuickAction = {
  key: string
  label: string
  onClick: () => void
}

const assistantGreeting = '你好，我是小影。'

function ChartFallback({ height }: { height: number }) {
  return <div style={{ height, borderRadius: 14, background: 'rgba(128, 165, 210, 0.12)' }} />
}

const severityLabel: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const statusLabel: Record<FindingStatus, string> = {
  new: '新建',
  reviewing: '待处理',
  investigating: '调查中',
  ignored: '已排除',
  closed: '已关闭',
}

function scoreTone(value: number) {
  if (value >= 80) return 'exception'
  if (value >= 60) return 'active'
  return 'normal'
}

function RiskBadge({ value }: { value: number }) {
  return <span className={`mc-risk-score ${value >= 80 ? 'critical' : value >= 65 ? 'high' : value >= 40 ? 'medium' : 'low'}`}>{value}</span>
}

function formatBytes(bytes: number) {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

function inferSourceKind(filename: string) {
  const extension = filename.split('.').pop()?.toLowerCase()
  if (!extension) return 'FILE'
  if (extension === 'evtx') return 'EVTX'
  if (extension === 'jsonl') return 'JSONL'
  if (extension === 'json') return 'JSON'
  if (extension === 'csv') return 'CSV'
  if (extension === 'log' || extension === 'txt') return 'LOG'
  return extension.toUpperCase()
}

function extractDatePrefix(value: string) {
  const match = value.trim().match(/^(\d{4}-\d{2}-\d{2})/)
  return match?.[1] || null
}

function parseWindowDateTime(value: string, referenceDate: string) {
  const trimmed = value.trim()
  const direct = Date.parse(trimmed.replace(' ', 'T'))
  if (!Number.isNaN(direct)) return direct

  const fallback = Date.parse(`${referenceDate}T${trimmed}`)
  return Number.isNaN(fallback) ? 0 : fallback
}

function rangeToMilliseconds(range: string) {
  if (range === '1h') return 60 * 60 * 1000
  if (range === '24h') return 24 * 60 * 60 * 1000
  if (range === '7d') return 7 * 24 * 60 * 60 * 1000
  return 30 * 24 * 60 * 60 * 1000
}

function parseAbsoluteDateTime(value?: string) {
  if (!value) return 0
  const parsed = Date.parse(value.replace(' ', 'T'))
  return Number.isNaN(parsed) ? 0 : parsed
}

function filterRowsByTimeRange<T extends { time: string }>(rows: T[], timeRange: string) {
  const timestamps = rows.map((row) => parseAbsoluteDateTime(row.time)).filter((value) => value > 0)
  if (!timestamps.length) return rows
  const cutoff = Math.max(...timestamps) - rangeToMilliseconds(timeRange)
  return rows.filter((row) => {
    const timestamp = parseAbsoluteDateTime(row.time)
    return timestamp === 0 || timestamp >= cutoff
  })
}

function normalizeEntityType(value?: string, fallback = 'Unknown'): EntityProfile['type'] {
  if (!value) return inferEntityType(fallback)
  if (value.toLowerCase() === 'user') return 'User'
  if (value.toLowerCase() === 'host') return 'Host'
  if (value.toLowerCase() === 'process') return 'Process'
  if (value.toLowerCase() === 'ip') return 'IP'
  return inferEntityType(fallback)
}

function inferLogParticipants(entities: string[] = []) {
  const actor = entities.find((item) => inferEntityType(item) === 'User')
  const host = entities.find((item) => inferEntityType(item) === 'Host')
  const process = entities.find((item) => inferEntityType(item) === 'Process')
  const ip = entities.find((item) => inferEntityType(item) === 'IP')
  return { actor, host, process, ip }
}

function summarizeLogAction(row: SecurityLogRecord) {
  if (row.labels?.length) return row.labels.slice(0, 2).join(' / ')
  return row.source_type || row.source || 'RAW_EVENT'
}

function toEventRow(row: SecurityLogRecord): EventRow {
  const entities = row.entities || []
  const { actor, host, process, ip } = inferLogParticipants(entities)
  return {
    id: row.event_id || row.id || row.raw_log_ref || 'unknown',
    time: row.time || row.timestamp || '—',
    source: row.source_type || row.source || 'Unknown',
    action: summarizeLogAction(row),
    actor,
    host,
    process,
    ip,
    raw: row.text || JSON.stringify(row, null, 2),
    rawLogRef: row.raw_log_ref || [row.path, row.event_id || row.id].filter(Boolean).join(':'),
    originalTimestamp: row.original_timestamp,
    entities,
    findingTitle: row.labels?.join(' / ') || 'Repository Event',
    evidenceIds: [],
  }
}

function extractTimePart(value?: string) {
  if (!value) return '—'
  const match = value.match(/(\d{2}:\d{2}(?::\d{2})?)$/)
  return match?.[1] || value
}

function deriveUsualActivity(events: SecurityLogRecord[]) {
  const hours = events
    .map((event) => parseAbsoluteDateTime(event.time || event.timestamp))
    .filter((value) => value > 0)
    .map((value) => new Date(value).getHours())
  if (!hours.length) return '—'
  return `${String(Math.min(...hours)).padStart(2, '0')}:00-${String(Math.max(...hours)).padStart(2, '0')}:59`
}

function deriveHostHistory(entityId: string, events: SecurityLogRecord[], fallbackHosts: EntityProfile['hostHistory'] = []) {
  const counts = new Map<string, number>()
  for (const event of events) {
    for (const item of event.entities || []) {
      if (item === entityId || inferEntityType(item) !== 'Host') continue
      counts.set(item, (counts.get(item) || 0) + 1)
    }
  }
  const derived = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([host, count], index) => ({ host, count, isNew: index >= 1 || count <= 2 }))
  return derived.length ? derived : fallbackHosts
}

function buildBaselineRows(
  entityId: string,
  entity: SecurityEntityRecord | null,
  baseline: SecurityBaselineRecord | null,
  hosts: EntityProfile['hostHistory'],
  fallback: EntityProfile['baseline'] = [],
) {
  const rarityScore = baseline?.rarity_score ?? ((entity?.risk || 0) / 100)
  const rows = [
    {
      feature: 'Event Count',
      current: String(entity?.event_count ?? 0),
      baseline: baseline?.activity_count != null ? String(baseline.activity_count) : '—',
      deviation: Math.max(0.08, Math.min(0.98, rarityScore || 0.12)),
    },
    {
      feature: 'Source Diversity',
      current: String(entity?.source_count ?? entity?.sources?.length ?? 0),
      baseline: baseline?.source_diversity != null ? String(baseline.source_diversity) : '—',
      deviation: Math.max(0.06, Math.min(0.95, (baseline?.source_diversity || 1) / Math.max(entity?.source_count || 1, 1))),
    },
    {
      feature: '当前主机',
      current: hosts.length ? hosts.map((item) => item.host).join(', ') : '—',
      baseline: baseline?.baseline_window || '30d',
      deviation: Math.max(0.1, Math.min(0.97, 0.35 + (hosts.filter((item) => item.isNew).length * 0.18))),
    },
    {
      feature: '稀有度',
      current: rarityScore ? rarityScore.toFixed(3) : '—',
      baseline: baseline?.baseline_window || '30d',
      deviation: Math.max(0.05, Math.min(0.99, rarityScore || 0.1)),
    },
  ].filter((item) => item.current !== '0' || item.baseline !== '—')
  return rows.length ? rows : fallback
}

function useRepositoryPresentation() {
  return !isUsingLocalData() && !PREFER_DEMO_DATA
}

function PageTitle({ title, subtitle, extra }: { title: string; subtitle?: string; extra?: ReactNode }) {
  return (
    <div className="mc-page-title">
      <div>
        <Title level={2}>{title}</Title>
        {subtitle && <Text type="secondary">{subtitle}</Text>}
      </div>
      {extra}
    </div>
  )
}

function StructuredSection({
  title,
  items,
}: {
  title: string
  items: AssistantStructuredItem[]
}) {
  if (!items.length) return null

  const visibleEvidenceIds = (evidenceIds: string[]) =>
    evidenceIds.filter((evidenceId) => /^[A-Z]+[-_]/.test(evidenceId))

  return (
    <Card size="small" title={title} style={{ marginTop: 12 }}>
      <List
        size="small"
        dataSource={items}
        renderItem={(item) => (
          <List.Item>
            <div style={{ width: '100%' }}>
              <Paragraph style={{ marginBottom: 8 }}>{item.text}</Paragraph>
              {visibleEvidenceIds(item.evidence_ids).length > 0 && (
                <Space size={[4, 4]} wrap>
                  {visibleEvidenceIds(item.evidence_ids).map((evidenceId) => <Tag key={`${title}-${evidenceId}`}>{evidenceId}</Tag>)}
                </Space>
              )}
            </div>
          </List.Item>
        )}
      />
    </Card>
  )
}

function buildAssistantKickoff(context: AssistantContext) {
  const entityIds = context.entityIds || []
  const findingIds = context.windowIds || []
  const timeRange = context.timeRange || '24h'

  if (context.caseId) {
    return {
      prompt: `请基于当前案件上下文，直接给出一轮起手分析，不要先反问用户。重点输出：1）案件当前攻击链概览；2）最值得关注的 2-4 个风险点或证据锚点；3）你可能想问。请尽量结合当前案件、Finding、Entity 和 Evidence，上下文时间范围为 ${timeRange}。`,
    }
  }

  if (entityIds.length) {
    const entitySummary = entityIds.slice(0, 3).join(', ')
    return {
      prompt: `请基于当前实体上下文，先做一轮自动分析，不要先反问用户。重点输出：1）该实体当前为何值得关注；2）它和哪些 Finding 或异常行为最相关；3）是否存在基线偏离或新关系；4）你可能想问。请尽量结合当前实体、相关 Finding 和 Evidence，上下文时间范围为 ${timeRange}。`,
    }
  }

  if (findingIds.length) {
    const findingSummary = findingIds.slice(0, 3).join(', ')
    return {
      prompt: `请基于当前 Finding 上下文，先做一轮自动分析，不要先反问用户。重点输出：1）这条 Finding 为什么被标记为异常；2）当前已有证据支持什么、不支持什么；3）还缺哪些关键信息；4）你可能想问。请尽量结合当前 Finding、Entity 和 Evidence，上下文时间范围为 ${timeRange}。`,
    }
  }

  return null
}

function hasAssistantContext(context: AssistantContext) {
  return Boolean(context.caseId || context.entityIds?.length || context.windowIds?.length)
}

const assistantPresets = [
  { label: '证据整理', prompt: '根据当前上下文整理攻击时间线，区分 facts、assessments 和 uncertainties。' },
  { label: '关联检查', prompt: '检查当前 Finding 是否有足够证据属于同一活动，并给出支持或反对的证据。' },
  { label: '缺口分析', prompt: '找出当前 Investigation 仍缺少的关键证据，并给出 recommended_queries。' },
]

export default function MissionControlApp() {
  const navigate = useNavigate()
  const location = useLocation()
  const [assistantContext, setAssistantContext] = useState<AssistantContext>({})
  const [assistantChat, setAssistantChat] = useState<ChatItem[]>([])
  const [assistantQuestion, setAssistantQuestion] = useState('')
  const [assistantSending, setAssistantSending] = useState(false)
  const [assistantDockCollapsed, setAssistantDockCollapsed] = useState(false)
  const [timeRange, setTimeRange] = useState('24h')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [windowItems, setWindowItems] = useState(() => isUsingLocalData() ? anomalyWindows : [])
  const [caseItems, setCaseItems] = useState(() => isUsingLocalData() ? investigations : [])
  const [caseBoards, setCaseBoards] = useState<Record<string, CaseBoard>>(() => initialCaseBoards(isUsingLocalData() ? investigations : []))
  const [sourceItems, setSourceItems] = useState(() => isUsingLocalData() ? logSources : [])
  const [dashboardError, setDashboardError] = useState<string | null>(null)

  const referenceDate = useMemo(() => {
    const datedValues = windowItems.flatMap((item) => [item.start, item.end].map(extractDatePrefix).filter(Boolean) as string[])
    return datedValues.sort().slice(-1)[0] || '2026-08-09'
  }, [windowItems])

  const latestWindowTimestamp = useMemo(
    () => windowItems.reduce((latest, item) => Math.max(
      latest,
      parseWindowDateTime(item.start, referenceDate),
      parseWindowDateTime(item.end, referenceDate),
    ), 0),
    [referenceDate, windowItems],
  )

  const filteredWindowItems = useMemo(() => {
    const cutoff = latestWindowTimestamp - rangeToMilliseconds(timeRange)
    return windowItems.filter((item) => parseWindowDateTime(item.end || item.start, referenceDate) >= cutoff)
  }, [latestWindowTimestamp, referenceDate, timeRange, windowItems])

  const filteredWindowIds = useMemo(() => new Set(filteredWindowItems.map((item) => item.id)), [filteredWindowItems])

  const filteredCaseItems = useMemo(
    () => caseItems
      .map((item) => ({
        ...item,
        windowIds: item.windowIds.filter((windowId) => filteredWindowIds.has(windowId)),
      }))
      .filter((item) => item.windowIds.length > 0),
    [caseItems, filteredWindowIds],
  )

  const findings = useMemo(() => buildFindings(filteredWindowItems, filteredCaseItems), [filteredCaseItems, filteredWindowItems])
  const evidenceByFinding = useMemo(() => buildEvidence(findings), [findings])
  const entityProfiles = useMemo(() => buildEntityProfiles(findings), [findings])
  const onlineSources = sourceItems.filter((source) => source.status === 'online').length
  const assistantVisible = location.pathname !== '/assistant' && (assistantSending || assistantChat.length > 0)
  const assistantPreview = [...assistantChat].reverse().find((item) => item.role === 'assistant')?.content
    || [...assistantChat].reverse()[0]?.content
    || (assistantSending ? '正在分析…' : '')

  useEffect(() => {
    let active = true
    const refreshDashboard = async () => {
      try {
        const [windows, cases] = await Promise.all([getWindows(), getInvestigations()])
        if (!active) return
        setWindowItems(windows)
        setCaseItems(cases)
        setDashboardError(null)
      } catch (error) {
        if (!active) return
        setWindowItems([])
        setCaseItems([])
        setDashboardError(error instanceof Error ? error.message : '真实检测 API 不可用')
      }
    }
    void refreshDashboard()
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    setCaseBoards((current) => {
      const next = initialCaseBoards(caseItems)
      for (const [caseId, board] of Object.entries(current)) {
        if (!next[caseId]) continue
        for (const [findingId, stage] of Object.entries(board)) {
          if (findingId in next[caseId]) next[caseId][findingId] = stage
        }
      }
      return next
    })
  }, [caseItems])

  useEffect(() => {
    let active = true
    const refreshSources = async () => {
      try {
        const items = await getLogSources()
        if (active) setSourceItems(items)
      } catch (error) {
        if (active) {
          setSourceItems([])
          setDashboardError(error instanceof Error ? error.message : '日志源 API 不可用')
        }
      }
    }

    refreshSources()
    const handle = () => { void refreshSources() }
    window.addEventListener('wad-log-sources-updated', handle)
    return () => {
      active = false
      window.removeEventListener('wad-log-sources-updated', handle)
    }
  }, [])

  const selectedMenu = ['/overview', '/findings', '/entities', '/investigations', '/logs', '/sources', '/assistant', '/evaluation']
    .find((key) => location.pathname.startsWith(key)) || '/overview'

  const runAssistant = async (
    text: string,
    context: AssistantContext,
    options?: { appendUserMessage?: boolean },
  ) => {
    const trimmed = text.trim()
    if (!trimmed || assistantSending) return
    if (options?.appendUserMessage !== false) {
      setAssistantChat((current) => [...current, { role: 'user', content: trimmed }])
    }
    setAssistantSending(true)
    try {
      const answer = await askAssistant(trimmed, context)
      setAssistantChat((current) => [...current, {
        role: 'assistant',
        content: answer.answer,
        evidence: answer.evidence,
        verified: answer.verified,
        confidence: answer.confidence,
        structured: answer.structured,
        verification: answer.verification,
      }])
    } catch {
      setAssistantChat((current) => [...current, { role: 'assistant', content: '小影暂时不可用。' }])
    } finally {
      setAssistantSending(false)
    }
  }

  const openAssistantWithContext = (nextContext: AssistantContext) => {
    const kickoff = buildAssistantKickoff(nextContext)
    setAssistantContext(nextContext)
    setAssistantQuestion('')
    setAssistantDockCollapsed(false)
    navigate('/assistant')
    if (!kickoff) {
      setAssistantChat([{ role: 'assistant', content: assistantGreeting }])
      return
    }
    setAssistantChat([{ role: 'assistant', content: assistantGreeting }])
    void runAssistant(kickoff.prompt, nextContext, { appendUserMessage: false })
  }

  const openFindingAssistant = (finding: FindingRecord) => {
    openAssistantWithContext({ windowIds: [finding.id], entityIds: [finding.entity], timeRange })
  }

  const openCaseAssistant = (investigation: Investigation) => {
    const entityIds = Array.from(new Set(findings.filter((finding) => investigation.windowIds.includes(finding.id)).map((finding) => finding.entity)))
    openAssistantWithContext({ caseId: investigation.id, windowIds: investigation.windowIds, entityIds, timeRange })
  }

  const openEntityAssistant = (entity: EntityProfile) => {
    openAssistantWithContext({ entityIds: [entity.id], windowIds: entity.findingIds, timeRange })
  }

  const runAssistantNavigation = (
    path: string,
    nextContext: AssistantContext,
    prompt: string,
  ) => {
    setAssistantContext(nextContext)
    setAssistantQuestion('')
    setAssistantDockCollapsed(false)
    navigate(path)
    void runAssistant(prompt, nextContext, { appendUserMessage: false })
  }

  const assistantActions = useMemo<AssistantQuickAction[]>(() => {
    const actions: AssistantQuickAction[] = []
    if (assistantContext.caseId) {
      actions.push({
        key: `case-${assistantContext.caseId}`,
        label: '查看案件',
        onClick: () => runAssistantNavigation(
          `/investigations?case=${encodeURIComponent(assistantContext.caseId || '')}`,
          assistantContext,
          `我已打开案件 ${assistantContext.caseId}。请基于当前案件上下文继续分析，直接给出：1）当前最关键的链路判断；2）下一步最值得查看的 2 个点；3）一句简短结论。`,
        ),
      })
    }
    for (const entityId of (assistantContext.entityIds || []).slice(0, 2)) {
      actions.push({
        key: `entity-${entityId}`,
        label: `打开 ${entityId}`,
        onClick: () => runAssistantNavigation(
          `/entities?entity=${encodeURIComponent(entityId)}`,
          { ...assistantContext, entityIds: [entityId] },
          `我已打开实体 ${entityId}。请基于当前实体上下文继续分析，直接说明：1）这个实体为什么关键；2）最异常的关系或行为；3）建议下一步优先查什么。`,
        ),
      })
    }
    if (assistantContext.windowIds?.length) {
      actions.push({
        key: 'findings',
        label: '查看发现',
        onClick: () => runAssistantNavigation(
          '/findings',
          assistantContext,
          '我已打开发现列表。请结合当前上下文，直接指出最值得优先看的发现，以及它最主要的风险依据。',
        ),
      })
    }
    const searchSeed = assistantContext.entityIds?.[0] || assistantContext.windowIds?.[0]
    if (searchSeed) {
      actions.push({
        key: `logs-${searchSeed}`,
        label: '检索日志',
        onClick: () => runAssistantNavigation(
          `/logs?q=${encodeURIComponent(searchSeed)}`,
          assistantContext,
          `我已打开日志检索并定位到 ${searchSeed}。请基于当前上下文继续分析，直接说清：1）应该重点看哪些日志特征；2）下一步最值得补查的线索。`,
        ),
      })
    }
    return actions.slice(0, 4)
  }, [assistantContext, navigate])

  useEffect(() => {
    if (location.pathname !== '/assistant' || assistantChat.length || assistantSending) return
    if (hasAssistantContext(assistantContext)) {
      const kickoff = buildAssistantKickoff(assistantContext)
      if (kickoff) {
        setAssistantChat([{ role: 'assistant', content: assistantGreeting }])
        void runAssistant(kickoff.prompt, assistantContext, { appendUserMessage: false })
        return
      }
    }
    setAssistantChat([{ role: 'assistant', content: assistantGreeting }])
  }, [assistantChat.length, assistantContext, assistantSending, location.pathname])

  const registerImportedSources = (files: UploadSourceEntry[]) => {
    if (!files.length) return
    const now = new Date().toLocaleString('zh-CN', { hour12: false })
    setSourceItems((current) => [
      ...files.map((file) => ({
        id: `SRC-UP-${Date.now()}-${file.uid}`,
        name: file.name,
        path: `local://${file.name}`,
        kind: inferSourceKind(file.name),
        status: 'warning' as const,
        size: formatBytes(file.size),
        lastRead: `${now} · 待导入`,
      })),
      ...current,
    ])
  }

  const setFindingStage = (caseId: string, findingId: string, stage: FindingStage) => {
    setCaseBoards((current) => ({
      ...current,
      [caseId]: {
        ...(current[caseId] || {}),
        [findingId]: stage,
      },
    }))
  }

  return (
    <Layout className="mc-shell">
      <Sider width={236} className="mc-sidebar" breakpoint="lg" collapsedWidth={72}>
        <div className="mc-brand">
          <div className="mc-brand-mark"><SafetyCertificateOutlined /></div>
          <div className="mc-brand-copy">
            <strong>链影寻踪</strong>
            <span>M0-M6 Hybrid Detection</span>
          </div>
        </div>

        <Menu
          mode="inline"
          selectedKeys={[selectedMenu]}
          onClick={({ key }) => navigate(key)}
          className="mc-menu"
          items={[
            { key: '/overview', icon: <ThunderboltOutlined />, label: '总览' },
            { key: '/findings', icon: <SafetyCertificateOutlined />, label: '发现' },
            { key: '/entities', icon: <UserOutlined />, label: '实体调查' },
            { key: '/investigations', icon: <ApartmentOutlined />, label: '案件调查' },
            { key: '/logs', icon: <FileSearchOutlined />, label: '日志检索' },
            { key: '/sources', icon: <ReloadOutlined />, label: '数据源' },
  { key: '/assistant', icon: <RobotOutlined />, label: '小影' },
            { key: '/evaluation', icon: <CheckCircleFilled />, label: '评测' },
          ]}
        />

        <div className="mc-sidebar-health">
          <div><Badge status="processing" /> 检测服务运行中</div>
          <div><Badge status={onlineSources === sourceItems.length ? 'success' : 'warning'} /> {onlineSources}/{sourceItems.length} 日志源在线</div>
          <div><Badge status="success" /> 证据状态库已启用</div>
        </div>
      </Sider>

      <Layout className="mc-workspace">
        <Header className="mc-topbar">
          <div className="mc-topbar-title">链影寻踪 · M0-M6 攻击链调查台</div>
          <Space size={10} wrap>
            <Select
              value={timeRange}
              onChange={setTimeRange}
              style={{ width: 126 }}
              options={[
                { value: '1h', label: '过去 1 小时' },
                { value: '24h', label: '过去 24 小时' },
                { value: '7d', label: '过去 7 天' },
                { value: '30d', label: '过去 30 天' },
              ]}
            />
            <Button icon={<ReloadOutlined />}>刷新</Button>
            <Space size={5}><Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} /><Text type="secondary">自动刷新</Text></Space>
          </Space>
        </Header>

        <Content className="mc-content">
          {dashboardError && (
            <Card style={{ marginBottom: 12, borderColor: '#ff4d4f' }}>
              <Text type="danger">真实检测数据加载失败：{dashboardError}。系统未回退到 Mock，请先生成检测产物并启动后端。</Text>
            </Card>
          )}
          <Routes>
            <Route path="/overview" element={<OverviewPage findings={findings} cases={filteredCaseItems} caseBoards={caseBoards} timeRange={timeRange} />} />
            <Route path="/findings" element={<FindingsPage findings={findings} evidenceByFinding={evidenceByFinding} onOpenAssistant={openFindingAssistant} onOpenEntity={(entityId) => navigate(`/entities?entity=${encodeURIComponent(entityId)}`)} onOpenInvestigation={() => navigate('/investigations')} />} />
            <Route path="/entities" element={<EntityInvestigationPage profiles={entityProfiles} findings={findings} timeRange={timeRange} onOpenAssistant={openEntityAssistant} onOpenFinding={() => navigate('/findings')} />} />
            <Route path="/investigations" element={<InvestigationsPage cases={filteredCaseItems} findings={findings} evidenceByFinding={evidenceByFinding} caseBoards={caseBoards} onSetFindingStage={setFindingStage} onOpenAssistant={openCaseAssistant} onOpenEntity={(entityId) => navigate(`/entities?entity=${encodeURIComponent(entityId)}`)} />} />
            <Route path="/logs" element={<LogsPage findings={findings} evidenceByFinding={evidenceByFinding} timeRange={timeRange} />} />
            <Route path="/sources" element={<SourcesPage sources={sourceItems} onRefresh={async () => {
              try {
                setSourceItems(await getLogSources())
              } catch (error) {
                setSourceItems([])
                setDashboardError(error instanceof Error ? error.message : '日志源 API 不可用')
              }
            }} onRegisterImportedSources={registerImportedSources} />} />
            <Route
              path="/assistant"
              element={(
                <AssistantPage
                  context={assistantContext}
                  chat={assistantChat}
                  actions={assistantActions}
                  sending={assistantSending}
                  question={assistantQuestion}
                  onQuestionChange={setAssistantQuestion}
                  onSubmit={(value) => {
                    const next = value.trim()
                    if (!next) return
                    setAssistantQuestion('')
                    void runAssistant(next, assistantContext)
                  }}
                />
              )}
            />
            <Route path="/evaluation" element={<EvaluationPage />} />
            <Route path="/mission-control" element={<Navigate to="/overview" replace />} />
            <Route path="/anomalies" element={<Navigate to="/findings" replace />} />
            <Route path="/settings" element={<Navigate to="/evaluation" replace />} />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Routes>
        </Content>

        {assistantVisible && (
          <AssistantDock
            preview={assistantPreview}
            sending={assistantSending}
            collapsed={assistantDockCollapsed}
            onOpen={() => navigate('/assistant')}
            onToggleCollapsed={() => setAssistantDockCollapsed((current) => !current)}
          />
        )}
      </Layout>
    </Layout>
  )
}

function OverviewPage({
  findings,
  cases,
  caseBoards,
  timeRange,
}: {
  findings: FindingRecord[]
  cases: Investigation[]
  caseBoards: Record<string, CaseBoard>
  timeRange: string
}) {
  const useRepositoryData = useRepositoryPresentation()
  const [overview, setOverview] = useState<LogIndexOverview | null>(null)
  const [scale, setScale] = useState<ScaleReport | null>(null)
  useEffect(() => {
    if (!useRepositoryData) return
    getLogIndexOverview(timeRange).then(setOverview).catch(() => setOverview(null))
    getScaleReport().then(setScale).catch(() => setScale(null))
  }, [timeRange, useRepositoryData])

  const visibleSeries = useMemo(() => {
    if (useRepositoryData && overview?.timeline?.length) {
      return overview.timeline.map((item) => ({ time: item.time, logs: item.events, anomalies: 0 }))
    }
    if (timeRange === '1h') return overviewSeries.slice(-2)
    if (timeRange === '24h') return overviewSeries
    return overviewSeries
  }, [overview, timeRange, useRepositoryData])

  const embeddedRiskEvents = findings.reduce((sum, item) => sum + item.events.length, 0)
  const rawEvents = overview?.event_count ?? embeddedRiskEvents
  const riskCandidates = scale?.candidate_count ?? embeddedRiskEvents
  const anomalousFindings = findings.length
  const correlatedFindings = cases.reduce((sum, item) => sum + item.windowIds.length, 0)
  const reviewed = cases.reduce((sum, item) => sum + item.windowIds.filter((findingId) => findingId in (caseBoards[item.id] || {})).length, 0)
  const mainChainEvidence = cases.reduce((sum, item) => sum + Object.entries(caseBoards[item.id] || {}).filter(([, stage]) => stage === 'main').length, 0)
  const reviewReduction = rawEvents > 0 ? ((rawEvents - riskCandidates) / rawEvents) * 100 : 0

  const sourceOption = useMemo(() => ({
    tooltip: { trigger: 'axis' },
    grid: { left: 56, right: 18, top: 20, bottom: 30, containLabel: true },
    xAxis: { type: 'category', data: visibleSeries.map((item) => item.time), axisLabel: { color: '#64748b' } },
    yAxis: { type: 'value', axisLabel: { color: '#64748b', margin: 12 }, splitLine: { lineStyle: { color: '#eef2f7' } } },
    series: [
      { name: 'Raw Events', type: 'line', smooth: true, showSymbol: false, data: visibleSeries.map((item) => item.logs) },
      { name: 'Findings', type: 'bar', barMaxWidth: 18, data: visibleSeries.map((item) => item.anomalies) },
    ],
  }), [visibleSeries])

  const distributionOption = useMemo(() => ({
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      radius: ['48%', '72%'],
      data: overview?.source_type_counts
        ? Object.entries(overview.source_type_counts).slice(0, 12).map(([name, value]) => ({ name, value }))
        : Array.from(new Set(findings.flatMap((finding) => finding.sourceTypes))).map((name) => ({
            name,
            value: findings.filter((finding) => finding.sourceTypes.includes(name)).length,
          })),
      label: { formatter: '{b}: {c}' },
    }],
  }), [findings, overview])

  return (
    <>
      <PageTitle title="Overview" />
      <Row gutter={[12, 12]} className="mc-summary-row">
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="原始事件" value={rawEvents} /></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="异常发现" value={anomalousFindings} /></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="人工研判" value={reviewed} /></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="研判压缩" value={reviewReduction} precision={3} suffix="%" /></Card></Col>
      </Row>

      <Row gutter={[12, 12]}>
        <Col xs={24} xl={16}>
          <Card title="研判漏斗" className="mc-panel">
            <Row gutter={[12, 12]}>
              <Col xs={24} md={10}>
                <div className="mc-funnel-list">
                  {[
                    { label: '事件', value: rawEvents },
                    { label: '异常发现', value: anomalousFindings },
                    { label: '关联发现', value: correlatedFindings },
                    { label: '人工研判', value: reviewed },
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
          <Card title="数据源分布" className="mc-panel">
            <Suspense fallback={<ChartFallback height={280} />}>
              <EChartsView option={distributionOption} style={{ height: 280 }} />
            </Suspense>
          </Card>
        </Col>
        <Col span={24}>
          <Card title="高风险发现" className="mc-panel">
            <List
              dataSource={[...findings].sort((a, b) => b.risk - a.risk).slice(0, 5)}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={<Space><Text strong>{item.title}</Text><Tag color={item.severity === 'critical' ? 'red' : item.severity === 'high' ? 'orange' : 'gold'}>{severityLabel[item.severity]}</Tag></Space>}
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
          <Card title="分析链路" className="mc-panel">
            <Row gutter={[10, 10]}>
              {[
                ['M0', '解析'],
                ['M1', '语义编码'],
                ['M2', '实体解析'],
                ['M3', '时序关系'],
                ['M4', '短程分析'],
                ['M5', '长程关联'],
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

function FindingsPage({
  findings,
  evidenceByFinding,
  onOpenAssistant,
  onOpenEntity,
  onOpenInvestigation,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  onOpenAssistant: (finding: FindingRecord) => void
  onOpenEntity: (entityId: string) => void
  onOpenInvestigation: () => void
}) {
  const [selected, setSelected] = useState<FindingRecord | null>(null)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [source, setSource] = useState('all')

  const filtered = findings.filter((finding) => {
    const haystack = [finding.id, finding.title, finding.entity, finding.host, finding.source, finding.reasons.join(' ')].join(' ').toLowerCase()
    return haystack.includes(query.toLowerCase())
      && (severity === 'all' || finding.severity === severity)
      && (source === 'all' || finding.source.includes(source))
  })

  useEffect(() => {
    if (!filtered.length) {
      setSelected(null)
      return
    }
    if (selected && !filtered.some((item) => item.id === selected.id)) {
      setSelected(null)
    }
  }, [filtered, selected])

  const columns = [
    { title: 'Finding', dataIndex: 'title', key: 'title', render: (value: string, row: FindingRecord) => <div><Text strong>{value}</Text><div className="mc-row-id">{row.id}</div></div> },
    { title: '实体', dataIndex: 'entity', key: 'entity', width: 140, render: (value: string, row: FindingRecord) => <div><div>{value}</div><Text type="secondary">{row.entityType}</Text></div> },
    { title: '综合风险', dataIndex: 'risk', key: 'risk', width: 100, render: (value: number) => <RiskBadge value={value} /> },
    { title: '事件异常', dataIndex: 'eventScore', key: 'eventScore', width: 120, render: (value: number) => <Progress percent={value} size="small" status={scoreTone(value)} /> },
    { title: '局部上下文', dataIndex: 'localScore', key: 'localScore', width: 120, render: (value: number) => <Progress percent={value} size="small" status={scoreTone(value)} /> },
    { title: '长程关联', dataIndex: 'longScore', key: 'longScore', width: 120, render: (value: number) => <Progress percent={value} size="small" status={scoreTone(value)} /> },
    { title: '理由', dataIndex: 'reasons', key: 'reasons', render: (value: string[]) => <Space size={[4, 4]} wrap>{value.map((item) => <Tag key={item}>{item}</Tag>)}</Space> },
  ]

  return (
    <>
      <PageTitle title="Findings" />
      <Card className="mc-queue-card">
        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 Finding / 实体 / Host / 理由" className="mc-search" />
          <Select value={severity} onChange={setSeverity} style={{ width: 120 }} options={[{ value: 'all', label: '全部风险' }, ...(['critical', 'high', 'medium', 'low'] as Severity[]).map((value) => ({ value, label: severityLabel[value] }))]} />
          <Select value={source} onChange={setSource} style={{ width: 150 }} options={[{ value: 'all', label: '全部日志源' }, ...Array.from(new Set(findings.flatMap((finding) => finding.sourceTypes))).map((value) => ({ value, label: value }))]} />
        </div>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={filtered}
          pagination={{ pageSize: 8, showSizeChanger: false }}
          scroll={{ x: 1100 }}
          onRow={(row) => ({ onClick: () => setSelected(row) })}
          rowClassName="mc-queue-row"
        />
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} width={680} title={selected?.title} extra={selected && <RiskBadge value={selected.risk} />}>
        {selected && (
          <div className="mc-detail-drawer">
            <Card size="small" title="调查锚点" className="mc-drawer-card">
              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label="Finding">{selected.id}</Descriptions.Item>
                <Descriptions.Item label="Entity">{selected.entity}</Descriptions.Item>
                <Descriptions.Item label="Host">{selected.host}</Descriptions.Item>
                <Descriptions.Item label="Anchor Event">{selected.anchorEvent.action}</Descriptions.Item>
                <Descriptions.Item label="Investigation Range">过去 1 小时</Descriptions.Item>
                <Descriptions.Item label="Model Context">过去 30 分钟</Descriptions.Item>
              </Descriptions>
            </Card>

            <Card size="small" title="M6 风险融合" className="mc-drawer-card">
              <Row gutter={[8, 8]}>
                <Col span={8}><Statistic title="综合风险" value={selected.risk} /></Col>
                <Col span={8}><Statistic title="事件自身异常" value={selected.eventScore} /></Col>
                <Col span={8}><Statistic title="局部上下文" value={selected.localScore} /></Col>
                <Col span={24}><Statistic title="长程关联" value={selected.longScore} /></Col>
              </Row>
            </Card>

            <Card size="small" title="远程候选" className="mc-drawer-card">
              <List
                dataSource={selected.relatedCandidates}
                locale={{ emptyText: '暂无远程候选' }}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta title={<Text strong>{item.title}</Text>} description={`${item.id} · ${item.time}`} />
                    <Space size={[4, 4]} wrap>{item.reasons.map((reason) => <Tag key={`${item.id}-${reason}`}>{reason}</Tag>)}</Space>
                  </List.Item>
                )}
              />
            </Card>

            <Card size="small" title="M5 关联依据" className="mc-drawer-card">
              <Descriptions size="small" column={2}>
                <Descriptions.Item label="Association Confidence">{selected.association.confidence.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="Shared Anchor">{selected.association.sharedAnchor}</Descriptions.Item>
                <Descriptions.Item label="Anchor Strength">{selected.association.anchorStrength}</Descriptions.Item>
                <Descriptions.Item label="Entity Rarity">{selected.association.entityRarity.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="Action Compatibility">{selected.association.actionCompatibility.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="Graph Similarity">{selected.association.graphSimilarity.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="Time Gap" span={2}>{selected.association.timeGap}</Descriptions.Item>
              </Descriptions>
              <Divider />
              <List size="small" dataSource={selected.association.summary} renderItem={(item) => <List.Item>{item}</List.Item>} />
            </Card>

            <Card size="small" title="Evidence" className="mc-drawer-card">
              <List
                dataSource={evidenceByFinding[selected.id]}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta title={<Text strong>{item.statement}</Text>} description={`${item.id} · ${item.rawLogRef}`} />
                  </List.Item>
                )}
              />
            </Card>

            <Space wrap>
              <Button onClick={() => onOpenEntity(selected.entity)}>实体画像</Button>
              <Button onClick={onOpenInvestigation}>案件调查</Button>
                <Button type="primary" icon={<RobotOutlined />} onClick={() => onOpenAssistant(selected)}>小影</Button>
            </Space>
          </div>
        )}
      </Drawer>
    </>
  )
}

function EntityInvestigationPage({
  profiles,
  findings,
  timeRange,
  onOpenAssistant,
  onOpenFinding,
}: {
  profiles: EntityProfile[]
  findings: FindingRecord[]
  timeRange: string
  onOpenAssistant: (entity: EntityProfile) => void
  onOpenFinding: () => void
}) {
  const location = useLocation()
  const useRepositoryData = useRepositoryPresentation()
  const [selectedId, setSelectedId] = useState(profiles[0]?.id || '')
  const [query, setQuery] = useState('')
  const [remoteEntity, setRemoteEntity] = useState<SecurityEntityRecord | null>(null)
  const [remoteHistory, setRemoteHistory] = useState<SecurityLogRecord[]>([])
  const [remoteBaseline, setRemoteBaseline] = useState<SecurityBaselineRecord | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const requestedEntity = useMemo(() => new URLSearchParams(location.search).get('entity') || '', [location.search])
  useEffect(() => {
    if (requestedEntity) {
      setSelectedId(requestedEntity)
    }
  }, [requestedEntity])
  useEffect(() => {
    if (!selectedId) {
      setSelectedId(profiles[0]?.id || '')
    }
  }, [profiles, selectedId])
  useEffect(() => {
    if (!useRepositoryData || !selectedId) {
      setRemoteEntity(null)
      setRemoteHistory([])
      setRemoteBaseline(null)
      setLoadError('')
      return
    }
    let active = true
    const loadEntityContext = async () => {
      setLoading(true)
      setLoadError('')
      const [entityResult, historyResult, baselineResult] = await Promise.allSettled([
        getSecurityEntity(selectedId),
        getSecurityEntityHistory(selectedId, timeRange),
        getSecurityBaseline(selectedId, '30d'),
      ])
      if (!active) return
      if (entityResult.status === 'fulfilled') {
        setRemoteEntity(entityResult.value)
      } else {
        setRemoteEntity(null)
        setLoadError(entityResult.reason instanceof Error ? entityResult.reason.message : '实体详情加载失败。')
      }
      setRemoteHistory(historyResult.status === 'fulfilled' ? historyResult.value.events : [])
      setRemoteBaseline(baselineResult.status === 'fulfilled' ? baselineResult.value : null)
      setLoading(false)
    }
    void loadEntityContext()
    return () => {
      active = false
    }
  }, [selectedId, timeRange, useRepositoryData])
  const localSelected = profiles.find((item) => item.id === selectedId) || profiles[0]
  const remoteSelected = useMemo<EntityProfile | null>(() => {
    if (!remoteEntity) return null
    const entityId = remoteEntity.entity_id || remoteEntity.id
    const fallback = localSelected
    const hostHistory = deriveHostHistory(entityId, remoteHistory, fallback?.hostHistory)
    const newRelations = hostHistory.filter((item) => item.isNew).length
    return {
      id: entityId,
      type: normalizeEntityType(remoteEntity.type, entityId),
      firstSeen: remoteEntity.first_seen || fallback?.firstSeen || '—',
      lastSeen: remoteEntity.last_seen || fallback?.lastSeen || '—',
      thirtyDayEvents: remoteEntity.event_count || remoteHistory.length || fallback?.thirtyDayEvents || 0,
      normalLoginHosts: Math.max(hostHistory.length - newRelations, 0),
      currentLoginHosts: hostHistory.length || fallback?.currentLoginHosts || 0,
      newHostRelations: newRelations,
      rareRelations: Math.max(1, Math.round((remoteBaseline?.rarity_score ?? (remoteEntity.risk || 0) / 100) * 4)),
      usualLogin: deriveUsualActivity(remoteHistory) || fallback?.usualLogin || '—',
      currentActivity: extractTimePart(remoteEntity.last_seen),
      hostHistory,
      baseline: buildBaselineRows(entityId, remoteEntity, remoteBaseline, hostHistory, fallback?.baseline),
      findingIds: fallback?.findingIds || [],
    }
  }, [localSelected, remoteBaseline, remoteEntity, remoteHistory])
  const availableProfiles = useMemo(
    () => (remoteSelected && !profiles.some((item) => item.id === remoteSelected.id) ? [remoteSelected, ...profiles] : profiles),
    [profiles, remoteSelected],
  )
  const selected = availableProfiles.find((item) => item.id === selectedId) || remoteSelected || availableProfiles[0]
  const filtered = availableProfiles.filter((item) => `${item.id} ${item.type}`.toLowerCase().includes(query.toLowerCase()))
  const relatedFindings = findings.filter((finding) => selected && (selected.findingIds.includes(finding.id) || finding.entities.includes(selected.id)))

  if (!selected) return null

  return (
    <>
      <PageTitle title="Entity Investigation" extra={<Space><Button onClick={onOpenFinding}>Findings</Button><Button type="primary" icon={<RobotOutlined />} onClick={() => onOpenAssistant(selected)}>分析</Button></Space>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={7}>
          <Card title="实体列表" className="mc-investigation-list">
            <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索实体" className="mc-search" />
            <Divider />
            <List
              dataSource={filtered}
              renderItem={(item) => (
                <List.Item className={item.id === selected.id ? 'active' : ''} onClick={() => setSelectedId(item.id)}>
                  <List.Item.Meta title={<Text strong>{item.id}</Text>} description={`${item.type} · ${item.lastSeen}`} />
                  <Tag color={item.rareRelations >= 2 ? 'red' : 'blue'}>{item.rareRelations} rare</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={17}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3}>{selected.id}</Title>
                <Text type="secondary">{selected.type} · First Seen {selected.firstSeen} · Last Seen {selected.lastSeen}</Text>
              </div>
              <Tag color="processing">Current Activity {selected.currentActivity}</Tag>
            </div>
            {useRepositoryData && (
              <div style={{ marginTop: 10 }}>
                <Text type="secondary">{loading ? '正在从真实数据层加载实体画像...' : loadError || `已接入真实实体数据 · ${timeRange} 历史窗口`}</Text>
              </div>
            )}
          </Card>

          <Row gutter={[12, 12]}>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="30d Events" value={selected.thirtyDayEvents} /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="Normal Hosts" value={selected.normalLoginHosts} /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="Current Hosts" value={selected.currentLoginHosts} /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="New Relations" value={selected.newHostRelations} /></Card></Col>
          </Row>

          <Row gutter={[12, 12]}>
            <Col xs={24} lg={12}>
              <Card title="主机历史" className="mc-panel">
                <List
                  dataSource={selected.hostHistory}
                  renderItem={(item) => (
                    <List.Item>
                      <div style={{ width: '100%' }}>
                        <div className="mc-setting-row">
                          <strong>{item.host}</strong>
                          <Space><Text>{item.count}</Text>{item.isNew && <Tag color="orange">NEW</Tag>}</Space>
                        </div>
                        <Progress percent={Math.min(item.count, 100)} showInfo={false} />
                      </div>
                    </List.Item>
                  )}
                />
              </Card>
            </Col>
            <Col xs={24} lg={12}>
              <Card title="基线对比" className="mc-panel">
                <Table
                  rowKey="feature"
                  pagination={false}
                  size="small"
                  columns={[
                    { title: '特征', dataIndex: 'feature', key: 'feature' },
                    { title: 'Current', dataIndex: 'current', key: 'current' },
                    { title: 'Baseline', dataIndex: 'baseline', key: 'baseline' },
                    { title: 'Deviation', dataIndex: 'deviation', key: 'deviation', render: (value: number) => <Progress percent={Math.round(value * 100)} size="small" status={value >= 0.8 ? 'exception' : 'normal'} /> },
                  ]}
                  dataSource={selected.baseline}
                />
              </Card>
            </Col>
            <Col span={24}>
              <Card title="7d Related Findings" className="mc-panel">
                <Timeline items={relatedFindings.map((finding) => ({
                  dot: <ClockCircleOutlined />,
                  children: <div><strong>{finding.start}</strong><div>{finding.title}</div><Text type="secondary">{finding.id} · {finding.host}</Text></div>,
                }))} />
              </Card>
            </Col>
          </Row>
        </Col>
      </Row>
    </>
  )
}

function InvestigationsPage({
  cases,
  findings,
  evidenceByFinding,
  caseBoards,
  onSetFindingStage,
  onOpenAssistant,
  onOpenEntity,
}: {
  cases: Investigation[]
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  caseBoards: Record<string, CaseBoard>
  onSetFindingStage: (caseId: string, findingId: string, stage: FindingStage) => void
  onOpenAssistant: (investigation: Investigation) => void
  onOpenEntity: (entityId: string) => void
}) {
  const location = useLocation()
  const [selectedId, setSelectedId] = useState(cases[0]?.id || '')
  const requestedCase = useMemo(() => new URLSearchParams(location.search).get('case') || '', [location.search])
  useEffect(() => {
    if (requestedCase) {
      setSelectedId(requestedCase)
    }
  }, [requestedCase])
  useEffect(() => {
    if (!cases.some((item) => item.id === selectedId)) {
      setSelectedId(cases[0]?.id || '')
    }
  }, [cases, selectedId])
  const selected = cases.find((item) => item.id === selectedId) || cases[0]
  if (!selected) return null
  const related = findings.filter((finding) => selected?.windowIds.includes(finding.id))
  const board = caseBoards[selected.id] || {}
  const main = related.filter((finding) => board[finding.id] === 'main')
  const candidate = related.filter((finding) => board[finding.id] === 'candidate')
  const excluded = related.filter((finding) => board[finding.id] === 'excluded')
  const entities = Array.from(new Set(related.flatMap((finding) => finding.entities))).slice(0, 8)

  const graphOption = ({
    tooltip: {},
    series: [{
      type: 'graph',
      layout: 'none',
      roam: true,
      categories: [{ name: 'Finding' }, { name: 'Entity' }],
      data: [
        ...related.map((finding, index) => ({
          id: finding.id,
          name: finding.title,
          category: 0,
          symbolSize: 48,
          x: 140 + index * 160,
          y: 150 + (index % 2) * 80,
          itemStyle: {
            color: finding.severity === 'critical' ? '#d9363e' : finding.severity === 'high' ? '#f05a24' : '#fa8c16',
            borderColor: '#ffd8bf',
            borderWidth: 1.5,
          },
          label: { show: true, formatter: finding.title, fontSize: 10, color: '#f8fbff' },
        })),
        ...entities.map((entity, index) => ({
          id: entity,
          name: entity,
          category: 1,
          symbolSize: 34,
          x: 120 + index * 110,
          y: 350 + (index % 2) * 40,
          itemStyle: {
            color: '#f59e0b',
            borderColor: '#fde68a',
            borderWidth: 1.3,
          },
          label: { show: true, formatter: entity, fontSize: 10, color: '#f8fbff' },
        })),
      ],
      links: related.flatMap((finding) => finding.entities.filter((entity) => entities.includes(entity)).slice(0, 2).map((entity) => ({
        source: finding.id,
        target: entity,
      }))),
      lineStyle: { width: 1.3, opacity: 0.75, color: '#7ea6dc' },
      emphasis: { focus: 'adjacency' },
    }],
  })

  const renderStage = (title: string, stage: FindingStage, items: FindingRecord[]) => (
    <Col xs={24} lg={8}>
      <Card title={title} className="mc-panel">
        <List
          dataSource={items}
          locale={{ emptyText: '暂无条目' }}
          renderItem={(item) => (
            <List.Item
              actions={[
                stage !== 'main' ? <a key="main" onClick={() => onSetFindingStage(selected.id, item.id, 'main')}>加入主链</a> : null,
                stage !== 'candidate' ? <a key="candidate" onClick={() => onSetFindingStage(selected.id, item.id, 'candidate')}>保留候选</a> : null,
                stage !== 'excluded' ? <a key="excluded" onClick={() => onSetFindingStage(selected.id, item.id, 'excluded')}>排除</a> : null,
              ].filter(Boolean)}
            >
              <List.Item.Meta title={<Text strong>{item.title}</Text>} description={`${item.id} · ${item.entity} · 风险 ${item.risk}`} />
            </List.Item>
          )}
        />
      </Card>
    </Col>
  )

  return (
    <>
      <PageTitle title="Investigation" extra={<Button type="primary" icon={<RobotOutlined />} onClick={() => onOpenAssistant(selected)}>小影</Button>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={7}>
          <Card title="案件" className="mc-investigation-list">
            <List
              dataSource={cases}
              renderItem={(item) => (
                <List.Item className={item.id === selected.id ? 'active' : ''} onClick={() => setSelectedId(item.id)}>
                  <List.Item.Meta title={<Text strong>{item.title}</Text>} description={`${item.id} · ${item.owner}`} />
                  <Tag color={item.severity === 'critical' ? 'red' : 'orange'}>{severityLabel[item.severity]}</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={17}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3}>{selected.title}</Title>
                <Text type="secondary">{selected.id} · {selected.owner} · {statusLabel[selected.status === 'contained' ? 'closed' : selected.status]}</Text>
              </div>
              <Tag color="processing">锚点 {related[0]?.entity || '—'}</Tag>
            </div>
          </Card>

          <Row gutter={[12, 12]}>
            <Col span={24}>
              <Card title="攻击链图" className="mc-panel">
                <Suspense fallback={<ChartFallback height={360} />}>
                  <EChartsView option={graphOption} style={{ height: 360 }} />
                </Suspense>
              </Card>
            </Col>
          </Row>

          <Row gutter={[12, 12]}>
            {renderStage('主链', 'main', main)}
            {renderStage('候选', 'candidate', candidate)}
            {renderStage('排除', 'excluded', excluded)}
          </Row>

          <Row gutter={[12, 12]}>
            <Col xs={24} lg={14}>
              <Card title="证据时间线" className="mc-panel">
                <Timeline
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
                />
              </Card>
            </Col>
            <Col xs={24} lg={10}>
              <Card title="实体枢轴" className="mc-panel">
                <List
                  dataSource={entities}
                  renderItem={(item) => (
                    <List.Item actions={[<a key="open" onClick={() => onOpenEntity(item)}>查看画像</a>]}>
                      <List.Item.Meta title={<Text strong>{item}</Text>} description={inferEntityType(item)} />
                    </List.Item>
                  )}
                />
              </Card>
            </Col>
          </Row>
        </Col>
      </Row>
    </>
  )
}

function LogsPage({
  findings,
  evidenceByFinding,
  timeRange,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  timeRange: string
}) {
  const location = useLocation()
  const useRepositoryData = useRepositoryPresentation()
  const [query, setQuery] = useState('')
  const [source, setSource] = useState('all')
  const [selected, setSelected] = useState<EventRow | null>(null)
  const [remoteEvents, setRemoteEvents] = useState<EventRow[]>([])
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [indexMetadata, setIndexMetadata] = useState<LogIndexMetadata | null>(null)
  const [simulation, setSimulation] = useState<CapacitySimulation | null>(null)
  const requestedQuery = useMemo(() => new URLSearchParams(location.search).get('q') || '', [location.search])
  useEffect(() => {
    if (requestedQuery) {
      setQuery(requestedQuery)
    }
  }, [requestedQuery])

  useEffect(() => {
    if (!useRepositoryData) return
    getLogIndexMetadata().then(setIndexMetadata).catch(() => setIndexMetadata(null))
    const refreshSimulation = () => getCapacitySimulation().then(setSimulation).catch(() => setSimulation(null))
    refreshSimulation()
    const handle = window.setInterval(refreshSimulation, 3000)
    return () => window.clearInterval(handle)
  }, [useRepositoryData])

  useEffect(() => setPage(1), [query, source, timeRange])

  const events = useMemo<EventRow[]>(() => findings.flatMap((finding) => finding.events.map((event) => ({
    ...event,
    findingId: finding.id,
    findingTitle: finding.title,
    risk: finding.risk,
    evidenceIds: (evidenceByFinding[finding.id] || []).filter((item) => item.eventId === event.id).map((item) => item.id),
  }))), [findings, evidenceByFinding])
  useEffect(() => {
    if (!useRepositoryData) {
      setRemoteEvents([])
      setLoadError('')
      return
    }
    let active = true
    const handle = window.setTimeout(async () => {
      setLoading(true)
      setLoadError('')
      try {
        const result = await searchSecurityLogs({
          sourceTypes: source === 'all' ? [] : [source],
          keywords: query.trim() ? query.trim().split(/\s+/).slice(0, 6) : [],
          timeRange,
          limit: 50,
          offset: (page - 1) * 50,
        })
        if (!active) return
        setRemoteEvents(result.events.map(toEventRow))
        setTotal(result.count)
      } catch (error) {
        if (!active) return
        setRemoteEvents([])
        setLoadError(error instanceof Error ? error.message : '真实日志查询失败。')
      } finally {
        if (active) setLoading(false)
      }
    }, 220)
    return () => {
      active = false
      window.clearTimeout(handle)
    }
  }, [query, source, page, timeRange, useRepositoryData])

  const filtered = !useRepositoryData ? events.filter((event) => {
    const haystack = [event.id, event.action, event.actor, event.host, event.process, event.ip, event.source, event.raw, event.findingTitle].join(' ').toLowerCase()
    return haystack.includes(query.toLowerCase()) && (source === 'all' || event.source === source)
  }) : remoteEvents

  const columns = [
    { title: '时间', dataIndex: 'time', key: 'time', width: 110 },
    { title: '日志源', dataIndex: 'source', key: 'source', width: 140, render: (value: string) => <Tag>{value}</Tag> },
    { title: 'Normalized Event', dataIndex: 'action', key: 'action', width: 170, render: (value: string) => <Text strong>{value}</Text> },
    { title: 'Actor', dataIndex: 'actor', key: 'actor', width: 120, render: (value?: string) => value || '—' },
    { title: 'Host', dataIndex: 'host', key: 'host', width: 120, render: (value?: string) => value || '—' },
    { title: 'Process / IP', key: 'target', width: 160, render: (_: unknown, row: EventRow) => row.process || row.ip || '—' },
    { title: 'Finding', dataIndex: 'findingTitle', key: 'findingTitle', width: 220 },
  ]

  return (
    <>
      <PageTitle title="Log Search" />
      {useRepositoryData && (
        <Row gutter={[12, 12]} style={{ marginBottom: 12 }}>
          <Col xs={24} xl={14}>
            <Card className="mc-summary-card">
              <Row gutter={12}>
                <Col span={8}><Statistic title="真实已索引日志" value={indexMetadata?.indexed_records || 0} /></Col>
                <Col span={8}><Statistic title="真实日志源" value={indexMetadata?.source_count || 0} /></Col>
                <Col span={8}><Statistic title="检测读取标签" value={indexMetadata?.labels_accessed ? '是' : '否'} /></Col>
              </Row>
            </Card>
          </Col>
          <Col xs={24} xl={10}>
            <Card className="mc-summary-card" title={<Space><Tag color="gold">容量仿真</Tag><Text>{simulation?.label || '非真实扫描'}</Text></Space>}>
              <Statistic title="仿真后台累计 / 目标" value={(simulation?.processed_bytes || 0) / 1e12} precision={2} suffix={`/ ${((simulation?.target_bytes || 0) / 1e12).toFixed(1)} TB`} />
              <Progress percent={Math.min(100, (simulation?.progress || 0) * 100)} status="active" />
              <Text type="secondary">{simulation?.purpose}</Text>
            </Card>
          </Col>
        </Row>
      )}
      <Card className="mc-queue-card">
        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索用户 / Host / IP / Process / 原始日志" className="mc-search" />
          <Select value={source} onChange={setSource} style={{ width: 190 }} options={[
            { value: 'all', label: '全部日志源' },
            ...(useRepositoryData && indexMetadata
              ? indexMetadata.source_types.map((value) => ({ value, label: value }))
              : Array.from(new Set(events.map((event) => event.source))).map((value) => ({ value, label: value }))),
          ]} />
        </div>
        {useRepositoryData ? (
          <div style={{ marginBottom: 12 }}>
            <Text type="secondary">{loading ? '正在查询真实日志数据...' : loadError || `真实日志模式 · 当前展示 ${filtered.length} 条 ${timeRange} 范围内结果`}</Text>
          </div>
        ) : (
          <div style={{ marginBottom: 12 }}>
            <Text type="secondary">演示优先模式 · 当前页面保持 mock 叙事和展示稳定性</Text>
          </div>
        )}
        <Table rowKey={(row) => `${row.id}-${row.rawLogRef}`} loading={loading} columns={columns} dataSource={filtered}
          pagination={useRepositoryData ? { current: page, pageSize: 50, total, showSizeChanger: false, showQuickJumper: true, onChange: setPage } : { pageSize: 10, showSizeChanger: false }}
          scroll={{ x: 1100 }} onRow={(row) => ({ onClick: () => setSelected(row) })} />
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} width={620} title={selected?.id}>
        {selected && (
          <Tabs
            items={[
              {
                key: 'normalized',
                label: 'Normalized',
                children: (
                  <Descriptions bordered size="small" column={1}>
                    <Descriptions.Item label="action">{selected.action}</Descriptions.Item>
                    <Descriptions.Item label="actor">{selected.actor || '—'}</Descriptions.Item>
                    <Descriptions.Item label="source_host">{selected.host || '—'}</Descriptions.Item>
                    <Descriptions.Item label="process">{selected.process || '—'}</Descriptions.Item>
                    <Descriptions.Item label="ip">{selected.ip || '—'}</Descriptions.Item>
                    <Descriptions.Item label="finding">{selected.findingTitle}</Descriptions.Item>
                    <Descriptions.Item label="entities">{selected.entities?.join(', ') || '—'}</Descriptions.Item>
                    <Descriptions.Item label="evidence_ids">{selected.evidenceIds.join(', ') || '—'}</Descriptions.Item>
                  </Descriptions>
                ),
              },
              {
                key: 'raw',
                label: 'Raw',
                children: (
                  <>
                    <Descriptions bordered size="small" column={1}>
                      <Descriptions.Item label="source">{selected.source}</Descriptions.Item>
                      <Descriptions.Item label="raw_log_ref">{selected.rawLogRef || `${selected.source}:${selected.id}`}</Descriptions.Item>
                      <Descriptions.Item label="time_mode">{selected.originalTimestamp ? '场景回放时间（原始证据时间保留）' : '原始采集时间'}</Descriptions.Item>
                      {selected.originalTimestamp && <Descriptions.Item label="original_timestamp">{selected.originalTimestamp}</Descriptions.Item>}
                    </Descriptions>
                    <Divider />
                    <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{selected.raw}</pre>
                  </>
                ),
              },
            ]}
          />
        )}
      </Drawer>
    </>
  )
}

function SourcesPage({
  sources,
  onRefresh,
  onRegisterImportedSources,
}: {
  sources: LogSource[]
  onRefresh: () => Promise<void>
  onRegisterImportedSources: (files: UploadSourceEntry[]) => void
}) {
  const [refreshing, setRefreshing] = useState(false)
  const [queue, setQueue] = useState<UploadSourceEntry[]>([])
  const [tasks, setTasks] = useState<ImportTask[]>([])

  useEffect(() => {
    if (!tasks.some((task) => task.status !== 'ready')) return

    const timer = window.setInterval(() => {
      setTasks((current) => current.map((task) => {
        if (task.status === 'ready') return task
        const nextProgress = Math.min(task.progress + (task.status === 'queued' ? 18 : task.status === 'parsing' ? 14 : 10), 100)
        if (nextProgress >= 100) {
          return {
            ...task,
            progress: 100,
            status: 'ready',
            result: '已完成事件提取与索引登记',
          }
        }
        if (nextProgress >= 78) {
          return {
            ...task,
            progress: nextProgress,
            status: 'indexed',
            result: '正在建立事件索引与调查映射',
          }
        }
        if (nextProgress >= 28) {
          return {
            ...task,
            progress: nextProgress,
            status: 'parsing',
            result: '正在解析事件、实体和时间字段',
          }
        }
        return {
          ...task,
          progress: nextProgress,
          status: 'queued',
          result: '已加入导入队列',
        }
      }))
    }, 800)

    return () => window.clearInterval(timer)
  }, [tasks])

  const refresh = async () => {
    setRefreshing(true)
    try {
      await onRefresh()
    } finally {
      setRefreshing(false)
    }
  }

  const columns = [
    { title: '日志源', dataIndex: 'name', key: 'name', render: (value: string) => <Text strong>{value}</Text> },
    { title: '接入点', dataIndex: 'path', key: 'path', render: (value: string) => <Text code>{value}</Text> },
    { title: '类型', dataIndex: 'kind', key: 'kind', render: (value: string) => <Tag>{value}</Tag> },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (value: LogSource['status']) => (
        <Badge status={value === 'online' ? 'success' : value === 'warning' ? 'warning' : 'error'} text={value === 'online' ? '在线' : value === 'warning' ? '延迟' : '离线'} />
      ),
    },
    { title: '最后读取', dataIndex: 'lastRead', key: 'lastRead' },
    { title: '数据量', dataIndex: 'size', key: 'size' },
  ]

  const taskColumns = [
    { title: '任务', dataIndex: 'name', key: 'name', render: (value: string) => <Text strong>{value}</Text> },
    { title: '类型', dataIndex: 'kind', key: 'kind', width: 96, render: (value: string) => <Tag>{value}</Tag> },
    { title: '大小', dataIndex: 'size', key: 'size', width: 110, render: (value: number) => formatBytes(value) },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      width: 180,
      render: (value: number, record: ImportTask) => (
        <Progress
          percent={value}
          size="small"
          status={record.status === 'ready' ? 'success' : record.status === 'indexed' ? 'active' : 'normal'}
        />
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (value: ImportTask['status']) => (
        <Badge
          status={value === 'ready' ? 'success' : value === 'indexed' ? 'processing' : value === 'parsing' ? 'warning' : 'default'}
          text={value === 'ready' ? '已就绪' : value === 'indexed' ? '索引中' : value === 'parsing' ? '解析中' : '排队中'}
        />
      ),
    },
    { title: '结果', dataIndex: 'result', key: 'result' },
  ]

  const importFiles = () => {
    if (!queue.length) {
      message.info('请先选择要登记的日志文件。')
      return
    }
    setTasks((current) => [
      ...queue.map((file, index) => ({
        id: `TASK-${Date.now()}-${file.uid}`,
        name: file.name,
        kind: inferSourceKind(file.name),
        size: file.size,
        progress: 6 + index * 4,
        status: 'queued' as const,
        result: '已加入导入队列',
      })),
      ...current,
    ])
    onRegisterImportedSources(queue)
    setQueue([])
    message.success(`已登记 ${queue.length} 个日志文件。`)
  }

  const queuedCount = tasks.filter((task) => task.status === 'queued').length
  const runningCount = tasks.filter((task) => task.status === 'parsing' || task.status === 'indexed').length
  const readyCount = tasks.filter((task) => task.status === 'ready').length

  return (
    <>
      <PageTitle title="数据源管理" extra={<Button icon={<ReloadOutlined />} loading={refreshing} onClick={refresh}>刷新</Button>} />
      <Card className="mc-panel" title="文件导入">
        <Dragger
          multiple
          accept=".evtx,.log,.txt,.json,.jsonl,.csv"
          beforeUpload={() => false}
          fileList={queue.map((file) => ({
            uid: file.uid,
            name: file.name,
            size: file.size,
            status: 'done' as const,
          }))}
          onChange={({ fileList }) => {
            setQueue(fileList.map((file) => ({
              uid: file.uid,
              name: file.name,
              size: file.size || 0,
            })))
          }}
          onRemove={(file) => {
            setQueue((current) => current.filter((item) => item.uid !== file.uid))
          }}
        >
          <p className="ant-upload-drag-icon"><InboxOutlined /></p>
          <p className="ant-upload-text">拖拽或选择日志文件</p>
          <p className="ant-upload-hint">支持 EVTX / LOG / JSON / JSONL / CSV</p>
        </Dragger>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginTop: 12, flexWrap: 'wrap' }}>
          <Text type="secondary">建议导入样本集或分片日志</Text>
          <Button type="primary" onClick={importFiles}>加入数据源</Button>
        </div>
      </Card>
      <Row gutter={[12, 12]} className="mc-summary-row">
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="排队中" value={queuedCount} /></Card></Col>
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="处理中" value={runningCount} /></Card></Col>
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="已就绪" value={readyCount} /></Card></Col>
      </Row>
      <Card className="mc-panel" title="导入任务">
        <Table rowKey="id" columns={taskColumns} dataSource={tasks} pagination={false} locale={{ emptyText: '当前没有导入任务。' }} scroll={{ x: 920 }} />
      </Card>
      <Card className="mc-queue-card">
        <Table rowKey="id" columns={columns} dataSource={sources} pagination={false} scroll={{ x: 960 }} />
      </Card>
    </>
  )
}

function AssistantPage({
  context,
  chat,
  actions,
  sending,
  question,
  onQuestionChange,
  onSubmit,
}: {
  context: AssistantContext
  chat: ChatItem[]
  actions: AssistantQuickAction[]
  sending: boolean
  question: string
  onQuestionChange: (value: string) => void
  onSubmit: (value: string) => void
}) {
  return (
    <>
      <PageTitle title="小影" />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={17}>
          <Card className="mc-chat-card">
            <Space wrap style={{ marginBottom: 12 }}>
              {assistantPresets.map((item) => <Button key={item.label} onClick={() => onSubmit(item.prompt)}>{item.label}</Button>)}
            </Space>
            <div className="mc-chat-stream">
              {chat.map((item, index) => (
                <div className={`mc-chat-row ${item.role}`} key={`${item.role}-${index}`}>
                  <div className="mc-chat-avatar">{item.role === 'assistant' ? <RobotOutlined /> : <UserOutlined />}</div>
                  <div className="mc-chat-bubble">
                    <Paragraph>{item.content}</Paragraph>
                    {item.evidence && <Space size={[4, 4]} wrap>{item.evidence.map((evidence) => <Tag key={`${evidence.ref}-${evidence.label}`}>{evidence.label}</Tag>)}</Space>}
                    {item.structured && (
                      <>
                        <StructuredSection title="事实" items={item.structured.facts} />
                        <StructuredSection title="判断" items={item.structured.assessments} />
                        <StructuredSection title="待确认" items={item.structured.uncertainties} />
                        <StructuredSection title="你可能想问" items={item.structured.recommended_queries} />
                      </>
                    )}
                    {(item.verified !== undefined || item.confidence !== undefined) && (
                      <div style={{ marginTop: 8 }}>
                        {item.verified !== undefined && <Tag color={item.verified ? 'success' : 'warning'}>{item.verified ? '已核验' : '待确认'}</Tag>}
                        {item.confidence !== undefined && <Tag>置信 {Math.round(item.confidence * 100)}%</Tag>}
                        {item.verification && (
                          <>
                            <Tag>证据 {item.verification.totalItems}</Tag>
                            <Tag color={item.verification.downgradedItems > 0 ? 'warning' : 'success'}>
                              降级 {item.verification.downgradedItems}
                            </Tag>
                          </>
                        )}
                      </div>
                    )}
                    {item.role === 'assistant' && index === chat.length - 1 && actions.length > 0 && (
                      <Space wrap className="mc-chat-actions">
                        {actions.map((action) => (
                          <Button key={action.key} size="small" onClick={action.onClick}>
                            {action.label}
                          </Button>
                        ))}
                      </Space>
                    )}
                  </div>
                </div>
              ))}
              {sending && <div><Badge status="processing" /> 小影处理中…</div>}
            </div>
            <div className="mc-chat-composer">
              <Input.TextArea value={question} onChange={(event) => onQuestionChange(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); onSubmit(question) } }} autoSize={{ minRows: 2, maxRows: 5 }} placeholder="输入调查问题" />
              <Button type="primary" icon={<SendOutlined />} loading={sending} onClick={() => onSubmit(question)}>发送</Button>
            </div>
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title="当前上下文" className="mc-panel">
            <Space wrap size={[6, 6]}>
              <Tag>{context.caseId || '未选择案件'}</Tag>
              {(context.windowIds || []).slice(0, 3).map((windowId) => <Tag key={windowId}>{windowId}</Tag>)}
              {(context.entityIds || []).slice(0, 3).map((entityId) => <Tag key={entityId}>{entityId}</Tag>)}
              {context.timeRange && <Tag>{context.timeRange}</Tag>}
            </Space>
          </Card>
        </Col>
      </Row>
    </>
  )
}

function AssistantDock({
  preview,
  sending,
  collapsed,
  onOpen,
  onToggleCollapsed,
}: {
  preview: string
  sending: boolean
  collapsed: boolean
  onOpen: () => void
  onToggleCollapsed: () => void
}) {
  if (collapsed) {
    return (
      <div className="mc-assistant-dock-collapsed" onClick={onToggleCollapsed}>
        <RobotOutlined />
        <span>小影</span>
        {sending && <Badge status="processing" />}
      </div>
    )
  }

  return (
    <Card className="mc-assistant-dock">
      <div className="mc-assistant-dock-head">
        <Space size={8}>
          <RobotOutlined />
          <Text strong>小影</Text>
          {sending && <Badge status="processing" text="处理中" />}
        </Space>
        <Space size={6}>
          <Button size="small" onClick={onOpen}>打开</Button>
          <Button size="small" onClick={onToggleCollapsed}>收起</Button>
        </Space>
      </div>
      <Paragraph ellipsis={{ rows: 3, expandable: false }} style={{ marginBottom: 0 }}>
        {preview || '小影会话已保留。'}
      </Paragraph>
    </Card>
  )
}

function EvaluationPage() {
  const [report, setReport] = useState<EvaluationReport | null>(null)
  const [manifest, setManifest] = useState<DetectionManifest | null>(null)
  const [scale, setScale] = useState<ScaleReport | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([getEvaluationReport(), getDetectionManifest(), getScaleReport()])
      .then(([nextReport, nextManifest, nextScale]) => {
        setReport(nextReport)
        setManifest(nextManifest)
        setScale(nextScale)
        setError(null)
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : '评测报告加载失败'))
  }, [])

  if (error) return <><PageTitle title="Evaluation" /><Card><Text type="danger">{error}</Text></Card></>
  if (!report || !manifest || !scale) return <><PageTitle title="Evaluation" /><Card loading /></>

  const metricCards = [
    { title: 'PR-AUC', value: report.metrics.pr_auc * 100, suffix: '%', precision: 1 },
    { title: 'Recall', value: report.metrics.recall * 100, suffix: '%', precision: 1 },
    { title: 'FPR', value: report.metrics.fpr * 100, suffix: '%', precision: 1 },
    { title: 'Chain Recovery', value: report.metrics.chain_recovery * 100, suffix: '%', precision: 1 },
    { title: 'EPS', value: report.throughput.median_events_per_second, suffix: '', precision: 0 },
    { title: 'Scale TB/day', value: scale.projected_decimal_tb_per_day, suffix: '', precision: 3 },
  ]
  const ablationRows = Object.entries(report.ablations).map(([variant, value]) => ({
    key: variant,
    variant,
    recall: `${(value.recall * 100).toFixed(1)}%`,
    fpr: `${(value.fpr * 100).toFixed(1)}%`,
    prauc: value.pr_auc.toFixed(3),
    chain: `${(value.chain_recovery * 100).toFixed(1)}%`,
  }))

  return (
    <>
      <PageTitle title="Evaluation" subtitle="真实 API 加载的可复现演示集指标" />
      <Row gutter={[12, 12]}>
        {metricCards.map((item) => (
          <Col xs={12} md={8} xl={4} key={item.title}>
            <Card className="mc-summary-card"><Statistic title={item.title} value={item.value} precision={item.precision} suffix={item.suffix} /></Card>
          </Col>
        ))}
        <Col xs={24}>
          <Card title="真实数据规模与有界内存压测" className="mc-panel">
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }} size="small">
              <Descriptions.Item label="实测输入">{scale.input_count.toLocaleString()} 条 / {(scale.bytes_read / 1_000_000).toFixed(1)} MB</Descriptions.Item>
              <Descriptions.Item label="并行度">{scale.worker_count} 个隔离 worker</Descriptions.Item>
              <Descriptions.Item label="吞吐">{(scale.source_bytes_per_second / 1_000_000).toFixed(2)} MB/s</Descriptions.Item>
              <Descriptions.Item label="日处理能力">{scale.projected_decimal_tb_per_day.toFixed(3)} TB/日</Descriptions.Item>
              <Descriptions.Item label="峰值工作集">{(scale.aggregate_peak_sampled_working_set_bytes / 1024 / 1024).toFixed(1)} MiB</Descriptions.Item>
              <Descriptions.Item label="标签隔离">{scale.labels_accessed ? '失败：检测读取了标签' : '通过：labels_accessed=false'}</Descriptions.Item>
              <Descriptions.Item label="内存契约">{scale.memory_contract.state_grows_with_input ? '状态随输入增长' : '固定草图 + Top-K，状态不随输入增长'}</Descriptions.Item>
              <Descriptions.Item label="执行模式">{scale.execution_mode}</Descriptions.Item>
              <Descriptions.Item label="风险聚合">{scale.candidate_count} 个候选 / {scale.finding_count} 个窗口</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col xs={24}>
          <Card title="可复现消融实验" className="mc-panel">
            <Table rowKey="key" pagination={false} columns={[
              { title: '版本', dataIndex: 'variant', key: 'variant' },
              { title: 'Recall', dataIndex: 'recall', key: 'recall' },
              { title: 'FPR', dataIndex: 'fpr', key: 'fpr' },
              { title: 'PR-AUC', dataIndex: 'prauc', key: 'prauc' },
              { title: 'Chain Recovery', dataIndex: 'chain', key: 'chain' },
            ]} dataSource={ablationRows} />
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card title="误报分析" className="mc-panel">
            <List size="small" dataSource={[
              `完整方案 FP=${report.metrics.fp} / TN=${report.metrics.tn}`,
              `每百万正常日志误报数=${report.metrics.false_positives_per_million.toFixed(0)}`,
              `无监督误报事件：${report.ablations.unsupervised_only?.false_positive_event_ids?.join(', ') || '无'}`,
              '内置小型演示集仅验证评测链路，不代表生产数据性能。',
            ]} renderItem={(item) => <List.Item>{item}</List.Item>} />
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card title="实验与标签边界" className="mc-panel">
            <Descriptions column={1} size="small">
              <Descriptions.Item label="真实日志输入">{manifest.input_count} 条，SHA256 {manifest.input_sha256.slice(0, 12)}…</Descriptions.Item>
              <Descriptions.Item label="检测阶段读取标签">{manifest.labels_accessed ? '是' : '否'}</Descriptions.Item>
              <Descriptions.Item label="标签用于训练">{report.labels_used_for_training ? '是' : '否'}</Descriptions.Item>
              <Descriptions.Item label="标签读取时机">预测写出后独立评测</Descriptions.Item>
              <Descriptions.Item label="复现命令"><Text code>{report.reproduce_command}</Text></Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>
    </>
  )
}

function LegacyEvaluationPage({ findings: _findings, caseBoards }: { findings: FindingRecord[]; caseBoards: Record<string, CaseBoard> }) {
  const rawEvents = overviewSeries.reduce((sum, item) => sum + item.logs, 0)
  const reviewed = Object.values(caseBoards).reduce((sum, board) => sum + Object.keys(board).length, 0)
  const analystReduction = ((rawEvents - reviewed) / rawEvents) * 100
  const metrics = [
    { title: 'PR-AUC', value: 85.0, suffix: '%' },
    { title: 'Recall@1%FPR', value: 80.0, suffix: '%' },
    { title: '3-day Chain Recovery', value: 72.6, suffix: '%' },
    { title: 'EPS', value: 15435, suffix: '' },
    { title: 'Analyst Reduction', value: analystReduction, suffix: '%' },
  ]

  const ablationRows = [
    { key: 'full', variant: 'Full System', recall: '84.2%', linkF1: '78.8%', chain: '72.6%' },
    { key: 'm2', variant: 'w/o Entity Resolution', recall: '76.3%', linkF1: '61.9%', chain: '54.8%' },
    { key: 'm4', variant: 'w/o M4 Q-Former', recall: '79.1%', linkF1: '70.4%', chain: '60.7%' },
    { key: 'm5', variant: 'w/o M5 Long-term', recall: '80.4%', linkF1: '58.3%', chain: '41.2%' },
    { key: 'baseline', variant: 'w/o Baseline / Rarity', recall: '78.6%', linkF1: '64.1%', chain: '55.9%' },
  ]

  return (
    <>
      <PageTitle title="Evaluation" />
      <Row gutter={[12, 12]}>
        {metrics.map((item) => (
          <Col xs={12} md={8} xl={4} key={item.title}>
            <Card className="mc-summary-card"><Statistic title={item.title} value={item.value} precision={item.suffix === '%' ? 1 : 0} suffix={item.suffix} /></Card>
          </Col>
        ))}
        <Col xs={24} xl={24}>
          <Card title="消融实验" className="mc-panel">
            <Table
              rowKey="key"
              pagination={false}
              columns={[
                { title: '版本', dataIndex: 'variant', key: 'variant' },
                { title: 'Recall@1%FPR', dataIndex: 'recall', key: 'recall' },
                { title: 'Link F1', dataIndex: 'linkF1', key: 'linkF1' },
                { title: '3-day Chain Recovery', dataIndex: 'chain', key: 'chain' },
              ]}
              dataSource={ablationRows}
            />
          </Card>
        </Col>
        <Col xs={24} xl={14}>
          <Card title="错误案例" className="mc-panel">
            <List
              size="small"
              dataSource={['backup_admin', 'FS-02', '稀有账号-主机关系', '非工作时段', 'SMB 访问', '已批准维护工单', '已排除']}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="源域对比" className="mc-panel">
            <Table
              rowKey="method"
              size="small"
              pagination={false}
              columns={[
                { title: '方法', dataIndex: 'method', key: 'method' },
                { title: 'PR-AUC', dataIndex: 'prauc', key: 'prauc' },
                { title: 'F1', dataIndex: 'f1', key: 'f1' },
                { title: 'Recall@1%FPR', dataIndex: 'recall', key: 'recall' },
              ]}
              dataSource={[
                { method: 'DeepLog', prauc: '0.80', f1: '0.74', recall: '0.58' },
                { method: 'LogBERT', prauc: '0.85', f1: '0.80', recall: '0.67' },
                { method: 'NeuralLog', prauc: '0.90', f1: '0.85', recall: '0.76' },
                { method: '本系统', prauc: '0.85', f1: '0.84', recall: '0.80' },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </>
  )
}
