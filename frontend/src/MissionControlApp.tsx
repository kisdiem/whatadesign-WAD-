import { Suspense, lazy, useEffect, useMemo, useRef, useState } from 'react'
import {
  Badge,
  Button,
  Card,
  Input,
  Layout,
  Menu,
  Select,
  Space,
  Switch,
  Typography,
  message,
} from 'antd'
import {
  ApartmentOutlined,
  CheckCircleFilled,
  FileSearchOutlined,
  ReloadOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SendOutlined,
  ThunderboltOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import {
  type AnomalyWindow,
  type Investigation,
  type LogSource,
  type SecurityEvent,
} from './mocks/data'
import { loadDemoDataset, type DemoDatasetId } from './services/demoData'
import { deleteIngestedSource, getIngestionSnapshot, uploadLogFile, type IngestResult } from './services/ingestion'
import { downloadAttackChainReport } from './services/attackChainReport'
import {
  askAssistant,
  getInvestigations,
  getWindows,
  type AssistantContext,
} from './services/api'
import {
  buildEntityProfiles,
  buildEvidence,
  buildFindings,
  initialCaseBoards,
  type CaseBoard,
  type EntityProfile,
  type FindingRecord,
  type FindingStage,
} from './services/investigationDomain'
import {
  buildM3GraphSnapshot,
  loadM3GraphSnapshots,
  persistM3GraphSnapshot,
  removeM3GraphSnapshot,
  type M3GraphSnapshot,
} from './services/caseGraphs'
import {
  investigationQueueStatus,
  rangeToMilliseconds,
  type AssistantQuickAction,
  type ChatItem,
  type DemoReplayEvent,
  type UploadSourceEntry,
} from './pages/shared'

const OverviewPage = lazy(() => import('./pages/OverviewPage'))
const FindingsPage = lazy(() => import('./pages/FindingsPage'))
const EntityInvestigationPage = lazy(() => import('./pages/EntityInvestigationPage'))
const InvestigationsPage = lazy(() => import('./pages/InvestigationsPage'))
const LogsPage = lazy(() => import('./pages/LogsPage'))
const SourcesPage = lazy(() => import('./pages/SourcesPage'))
const AssistantPage = lazy(() => import('./pages/AssistantPage'))
const EvaluationPage = lazy(() => import('./pages/EvaluationPage'))

const { Header, Sider, Content } = Layout
const { Text, Paragraph } = Typography
const PERSISTED_CASES_KEY = 'wad-demo-case-items-v5'
const PERSISTED_CASE_BOARDS_KEY = 'wad-demo-case-boards-v4'

function readPersistedCases() {
  try { return JSON.parse(window.localStorage.getItem(PERSISTED_CASES_KEY) || '[]') as Investigation[] } catch { return [] }
}

function readPersistedCaseBoards() {
  try { return JSON.parse(window.localStorage.getItem(PERSISTED_CASE_BOARDS_KEY) || '{}') as Record<string, CaseBoard> } catch { return {} }
}

function mergePersistedCases(baseCases: Investigation[]) {
  const merged = new Map(baseCases.map((item) => [item.id, item]))
  readPersistedCases()
    .filter((item) => item.id !== 'CASE-XLOG-30D-001')
    .forEach((item) => {
      const base = merged.get(item.id)
      merged.set(item.id, base ? {
        ...base,
        ...item,
        title: base.title,
        queueStatus: item.queueStatus || base.queueStatus,
        escalationScore: item.escalationScore ?? base.escalationScore,
        escalationReasons: item.escalationReasons || base.escalationReasons,
        decisionSource: item.decisionSource || base.decisionSource,
      } : item)
    })
  return Array.from(merged.values()).filter((item) => !item.id.startsWith('CASE-XLOG-'))
}

const preparedDemoSources: LogSource[] = [
  { id: 'DEMO-SHORT', name: 'Short', path: 'stream://short', kind: '事件流', status: 'online', size: '2,570 条事件 / 30 天窗口', lastRead: '2026-07-11 - 2026-08-09（UTC）' },
  { id: 'DEMO-LONG', name: 'Long', path: 'stream://long', kind: '事件流', status: 'online', size: '44,175 条事件 / 30 天窗口', lastRead: '2026-07-11 - 2026-08-09（UTC）' },
]

function eventStreamText(value?: string) {
  return String(value || '')
    .replace('实时上传 · M0-M6', '事件流')
    .replace(/^实时上传\//, '事件流/')
    .replace('由实时上传文件经过', '由文件接入事件流经过')
}

function presentEventStreamSource(source: LogSource): LogSource {
  if (!source.id.startsWith('UPLOAD-') && !source.path.startsWith('upload://')) return source
  return {
    ...source,
    path: `stream://${source.name}`,
    kind: '事件流',
  }
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

function uploadedOverviewSeries(events: DemoReplayEvent[]) {
  const buckets = new Map<string, { time: string; logs: number; anomalies: number; source: string }>()
  events.forEach((event) => {
    const timestamp = new Date(event.time)
    if (Number.isNaN(timestamp.getTime())) return
    timestamp.setUTCSeconds(0, 0)
    timestamp.setUTCMinutes(Math.floor(timestamp.getUTCMinutes() / 5) * 5)
    const time = timestamp.toISOString().slice(0, 16).replace('T', ' ')
    const key = `${event.dataset}|${time}`
    const current = buckets.get(key) || { time, logs: 0, anomalies: 0, source: event.dataset }
    current.logs += 1
    if ((event as SecurityEvent & { score?: number }).score! >= 0.55) current.anomalies += 1
    buckets.set(key, current)
  })
  return Array.from(buckets.values())
}

const assistantGreeting = '你好，我是小影。'

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

export default function MissionControlApp() {
  const navigate = useNavigate()
  const location = useLocation()
  const [assistantContext, setAssistantContext] = useState<AssistantContext>({})
  const [assistantChat, setAssistantChat] = useState<ChatItem[]>([])
  const [assistantQuestion, setAssistantQuestion] = useState('')
  const [assistantSending, setAssistantSending] = useState(false)
  const [assistantDockCollapsed, setAssistantDockCollapsed] = useState(false)
  // Long replay intentionally spans a week; opening it in a 24-hour filter
  // made the source appear to contain only its last handful of findings.
  const [timeRange, setTimeRange] = useState('7d')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [windowItems, setWindowItems] = useState<AnomalyWindow[]>([])
  const [demoOverviewSeries, setDemoOverviewSeries] = useState<Array<{ time: string; logs: number; anomalies: number; source?: string }>>([])
  const [demoEvents, setDemoEvents] = useState<DemoReplayEvent[]>([])
  const [caseItems, setCaseItems] = useState<Investigation[]>(() => readPersistedCases())
  const [caseBoards, setCaseBoards] = useState<Record<string, CaseBoard>>(() => readPersistedCaseBoards())
  const [m3GraphSnapshots, setM3GraphSnapshots] = useState<Record<string, M3GraphSnapshot>>(() => loadM3GraphSnapshots())
  const [sourceItems, setSourceItems] = useState(preparedDemoSources)
  const [ingestionRevision, setIngestionRevision] = useState(0)
  const [dashboardLoading, setDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState('')

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

  const latestPreparedTimestamps = useMemo(() => {
    const latest = new Map<DemoDatasetId, number>()
    for (const item of windowItems) {
      for (const dataset of ['Short', 'Long'] as DemoDatasetId[]) {
        if (!item.sourceTypes.includes(dataset)) continue
        const timestamp = parseWindowDateTime(item.end || item.start, extractDatePrefix(item.end || item.start) || referenceDate)
        latest.set(dataset, Math.max(latest.get(dataset) || 0, timestamp))
      }
    }
    return latest
  }, [referenceDate, windowItems])

  const filteredWindowItems = useMemo(() => {
    const cutoff = latestWindowTimestamp - rangeToMilliseconds(timeRange)
    return windowItems.filter((item) => {
      const preparedSource = (['Short', 'Long'] as DemoDatasetId[]).find((dataset) => item.sourceTypes.includes(dataset))
      if (preparedSource) {
        const timestamp = parseWindowDateTime(item.end || item.start, extractDatePrefix(item.end || item.start) || referenceDate)
        return timestamp >= (latestPreparedTimestamps.get(preparedSource) || timestamp) - rangeToMilliseconds(timeRange)
      }
      return parseWindowDateTime(item.end || item.start, referenceDate) >= cutoff
    })
  }, [latestPreparedTimestamps, latestWindowTimestamp, referenceDate, timeRange, windowItems])

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

  const allFindings = useMemo(() => buildFindings(windowItems, caseItems), [caseItems, windowItems])
  const allEvidenceByFinding = useMemo(() => buildEvidence(allFindings), [allFindings])
  const findings = useMemo(() => allFindings.filter((finding) => filteredWindowIds.has(finding.id)), [allFindings, filteredWindowIds])
  const evidenceByFinding = useMemo(() => buildEvidence(findings), [findings])
  const entityProfiles = useMemo(() => buildEntityProfiles(allFindings, demoEvents), [allFindings, demoEvents])
  const onlineSources = sourceItems.filter((source) => source.status === 'online').length
  const saveM3Graph = (finding: FindingRecord) => {
    const anchorTimestamp = Date.parse(finding.anchorEvent?.time || finding.start)
    const sourceTypes = new Set(finding.sourceTypes)
    const timeContextEvents = demoEvents.filter((event) => {
      const eventTimestamp = Date.parse(event.time)
      return Number.isFinite(anchorTimestamp) && Number.isFinite(eventTimestamp)
        && eventTimestamp >= anchorTimestamp - 30 * 60 * 1000
        && eventTimestamp <= anchorTimestamp
    })
    const sourceContextEvents = timeContextEvents.filter((event) => sourceTypes.size === 0 || sourceTypes.has(event.dataset) || sourceTypes.has(event.source))
    const contextEvents = sourceContextEvents.length ? sourceContextEvents : timeContextEvents
    const enrichedFinding = contextEvents.length
      ? { ...finding, events: contextEvents }
      : finding
    const next = persistM3GraphSnapshot(buildM3GraphSnapshot(enrichedFinding))
    setM3GraphSnapshots(next)
    setCaseItems((current) => {
      const existingIndex = current.findIndex((item) => item.id === finding.caseId || item.windowIds.includes(finding.id))
      if (existingIndex >= 0) {
        const nextCases = [...current]
        const existing = nextCases[existingIndex]
        if (!existing.windowIds.includes(finding.id)) nextCases[existingIndex] = { ...existing, windowIds: [...existing.windowIds, finding.id] }
        return nextCases
      }
      return [...current, {
        id: `CASE-${finding.id}`,
        title: `${finding.title} · 30分钟调查窗口`,
        severity: finding.severity,
        status: 'investigating',
        windowIds: [finding.id],
        owner: 'WAD 分析台',
        createdAt: finding.start,
        summary: `以事件 ${finding.id} 为锚点建立的 30 分钟调查窗口：${finding.summary}`,
      }]
    })
    message.success(`已将 ${finding.id} 加入案件，并保存其前 30 分钟 M3 事件关联图`)
  }
  const assistantVisible = location.pathname !== '/assistant' && (assistantSending || assistantChat.length > 0)
  const assistantPreview = [...assistantChat].reverse().find((item) => item.role === 'assistant')?.content
    || [...assistantChat].reverse()[0]?.content
    || (assistantSending ? '正在分析…' : '')

  useEffect(() => {
    let active = true
    const refreshDashboard = async () => {
      setDashboardLoading(true)
      setDashboardError('')
      try {
        const datasets: DemoDatasetId[] = ['Short', 'Long']
        const loaded = await Promise.all(datasets.map((dataset) => loadDemoDataset(dataset).then((data) => ({
          ...data,
          dataset,
          // Dataset names are the only selectable log sources. Raw file names remain on events as evidence.
          anomalyWindows: data.anomalyWindows.map((window) => ({ ...window, sourceTypes: [dataset] })),
        }))))
        let realtime: Awaited<ReturnType<typeof getIngestionSnapshot>> | null = null
        try {
          realtime = await getIngestionSnapshot()
        } catch {
          // The historical replay stays available when the live ingestion service is offline.
        }
        const realtimeEvents: DemoReplayEvent[] = (realtime?.events || []).map((event) => ({
          ...event,
          dataset: eventStreamText(event.source_type || event.source) || '事件流',
          source: event.source || event.source_type || '事件流',
        }))
        const realtimeWindows = (realtime?.windows || []).map((window) => ({
          ...window,
          sourceTypes: window.sourceTypes.map((sourceType) => eventStreamText(sourceType)),
          summary: eventStreamText(window.summary),
        }))
        const realtimeInvestigations = (realtime?.investigations || []).map((investigation) => ({
          ...investigation,
          summary: eventStreamText(investigation.summary),
          queueStatus: investigation.queueStatus || 'auto_observe' as const,
          decisionSource: investigation.decisionSource || 'system' as const,
        }))
        const windows = [
          ...loaded.flatMap((data) => data.anomalyWindows),
          ...realtimeWindows,
        ]
        const cases = mergePersistedCases([
          ...loaded.flatMap((data) => data.investigations),
          ...realtimeInvestigations,
        ])
        const deletedCaseIds = new Set<string>(JSON.parse(window.localStorage.getItem('wad-deleted-case-ids-v1') || '[]'))
        const deletedWindowIds = new Set(cases.filter((item) => deletedCaseIds.has(item.id)).flatMap((item) => item.windowIds))
        if (!active) return
        setWindowItems(windows.filter((item) => !deletedWindowIds.has(item.id) && !item.id.startsWith('WIN-XLOG-')))
        setCaseItems(cases.filter((item) => !deletedCaseIds.has(item.id)))
        setDemoEvents([
          ...loaded.flatMap((data) => data.events.map((event) => ({ ...event, dataset: data.dataset }))),
          ...realtimeEvents,
        ])
        setDemoOverviewSeries([
          ...loaded.flatMap((data) => data.overviewSeries.map((item) => ({ ...item, source: data.dataset }))),
          ...uploadedOverviewSeries(realtimeEvents),
        ])
        setSourceItems([...(realtime?.sources || []).map(presentEventStreamSource), ...preparedDemoSources])
      } catch (demoError) {
        if (!active) return
        try {
          const [windows, cases] = await Promise.all([getWindows(), getInvestigations()])
          const deletedCaseIds = new Set<string>(JSON.parse(window.localStorage.getItem('wad-deleted-case-ids-v1') || '[]'))
          const deletedWindowIds = new Set(cases.filter((item) => deletedCaseIds.has(item.id)).flatMap((item) => item.windowIds))
          setWindowItems(windows.filter((item) => !deletedWindowIds.has(item.id) && !item.id.startsWith('WIN-XLOG-')))
          setCaseItems(cases.filter((item) => !deletedCaseIds.has(item.id)))
          setDemoEvents([])
          setDemoOverviewSeries([])
        } catch (apiError) {
          setWindowItems([])
          setCaseItems([])
          setDemoEvents([])
          setDemoOverviewSeries([])
          const replayMessage = demoError instanceof Error ? demoError.message : '事件流数据加载失败'
          const apiMessage = apiError instanceof Error ? apiError.message : '检测 API 不可用'
          setDashboardError(`${replayMessage}；${apiMessage}`)
        }
      } finally {
        if (active) setDashboardLoading(false)
      }
    }
    void refreshDashboard()
    return () => {
      active = false
    }
  }, [ingestionRevision])

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
    if (caseItems.length) window.localStorage.setItem(PERSISTED_CASES_KEY, JSON.stringify(caseItems))
  }, [caseItems])

  useEffect(() => {
    window.localStorage.setItem(PERSISTED_CASE_BOARDS_KEY, JSON.stringify(caseBoards))
  }, [caseBoards])

  useEffect(() => {
    let active = true
    const refreshSources = async () => {
      if (active) setSourceItems((current) => current)
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

  const submitBatchToAssistant = (prompt: string, nextContext: AssistantContext) => {
    setAssistantContext(nextContext)
    setAssistantQuestion('')
    setAssistantDockCollapsed(false)
    setAssistantChat([{ role: 'user', content: '已提交当前页面的完整筛选结果，请小影归纳分析。' }])
    navigate('/assistant')
    void runAssistant(prompt, nextContext, { appendUserMessage: false })
  }

  const generateAttackChainReport = async (
    prompt: string,
    nextContext: AssistantContext,
    report: { caseId: string; caseTitle: string },
  ) => {
    if (assistantSending) return
    setAssistantContext(nextContext)
    setAssistantQuestion('')
    setAssistantDockCollapsed(false)
    setAssistantChat([{ role: 'user', content: `正在生成案件 ${report.caseId} 的攻击链分析报告。` }])
    navigate('/assistant')
    setAssistantSending(true)
    try {
      let answer = await askAssistant(prompt, nextContext)
      const requiredSections = ['概况', '链路判断', '关键证据', '不确定项', '处置建议']
      if (!requiredSections.every((section) => answer.answer.includes(section))) {
        answer = await askAssistant(
          `${prompt}\n\n你的上一版没有完整按模板输出。现在只输出五个必需章节，并在“关键证据”中给出至少三条来自案件快照的具体证据。`,
          nextContext,
        )
      }
      if (!requiredSections.every((section) => answer.answer.includes(section))) {
        throw new Error('小影未返回完整报告模板，未生成下载文件。')
      }
      setAssistantChat((current) => [...current, {
        role: 'assistant',
        content: answer.answer,
        evidence: answer.evidence,
        verified: answer.verified,
        confidence: answer.confidence,
        structured: answer.structured,
        verification: answer.verification,
      }])
      await downloadAttackChainReport({ caseId: report.caseId, caseTitle: report.caseTitle, content: answer.answer })
      message.success('攻击链分析报告已生成并下载。')
    } catch (error) {
      const detail = error instanceof Error ? error.message : '未知错误'
      setAssistantChat((current) => [...current, { role: 'assistant', content: `报告生成失败：${detail}` }])
      message.error('攻击链分析报告生成失败。')
    } finally {
      setAssistantSending(false)
    }
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

  const explainWithAssistant = (excerpt: string, nextContext: AssistantContext) => {
    const text = excerpt.trim()
    if (!text) return
    const prompt = `请解释以下安全日志或调查片段在当前上下文中的具体含义。先说明它描述的事实，再说明它为何值得关注或为何可能正常；不要把推测当作结论。片段：${text}`
    setAssistantContext(nextContext)
    setAssistantQuestion('')
    setAssistantDockCollapsed(false)
    setAssistantChat([{ role: 'user', content: `解释：${text}` }])
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

  const importLogFile = async (entry: UploadSourceEntry): Promise<IngestResult> => {
    if (!entry.file) throw new Error(`无法读取 ${entry.name} 的浏览器文件对象。`)
    const result = await uploadLogFile(entry.file)
    const normalizedResult = { ...result, source: presentEventStreamSource(result.source) }
    setSourceItems((current) => [normalizedResult.source, ...current.filter((source) => source.id !== normalizedResult.source.id)])
    setIngestionRevision((current) => current + 1)
    return normalizedResult
  }

  const deleteLogSource = async (sourceId: string) => {
    const result = await deleteIngestedSource(sourceId)
    setSourceItems((current) => current.filter((source) => source.id !== sourceId))
    setIngestionRevision((current) => current + 1)
    message.success(`已删除 ${result.name} 及其关联事件、发现和案件。`)
  }

  const deleteCase = (caseId: string) => {
    const target = caseItems.find((item) => item.id === caseId)
    if (!target) return
    const deletedCaseIds = new Set<string>(JSON.parse(window.localStorage.getItem('wad-deleted-case-ids-v1') || '[]'))
    deletedCaseIds.add(caseId)
    window.localStorage.setItem('wad-deleted-case-ids-v1', JSON.stringify(Array.from(deletedCaseIds)))
    setCaseItems((current) => current.filter((item) => item.id !== caseId))
    setWindowItems((current) => current.filter((item) => !target.windowIds.includes(item.id)))
    setCaseBoards((current) => {
      const next = { ...current }
      delete next[caseId]
      return next
    })
    target.windowIds.forEach((findingId) => setM3GraphSnapshots((current) => removeM3GraphSnapshot(findingId)))
    message.success(`已删除案件 ${target.title} 及其 30 分钟窗口数据。`)
  }

  const escalateInvestigation = (caseId: string) => {
    setCaseItems((current) => current.map((item) => item.id === caseId ? {
      ...item,
      queueStatus: 'manual_review',
      decisionSource: 'analyst',
      decisionAt: new Date().toISOString(),
      owner: item.owner === 'M5 自动关联' || item.owner === 'm0-m6-ingestion' ? '待分配分析员' : item.owner,
    } : item))
    message.success('候选链已升级为人工研判案件')
  }

  const setFindingStage = (caseId: string, findingId: string, stage: FindingStage) => {
    setCaseItems((current) => current.map((item) => item.id === caseId && investigationQueueStatus(item) === 'auto_observe' ? {
      ...item,
      queueStatus: 'manual_review',
      decisionSource: 'analyst',
      decisionAt: new Date().toISOString(),
      owner: '待分配分析员',
    } : item))
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
            <span>M0-M6 混合检测</span>
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
          <div><Badge status="processing" /> 多源日志检测服务运行中</div>
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
          {dashboardLoading && <Card style={{ marginBottom: 12 }}><Badge status="processing" /> 正在加载多源日志数据与实时检测结果…</Card>}
          {dashboardError && <Card style={{ marginBottom: 12, borderColor: '#ff4d4f' }}><Text type="danger">数据加载失败：{dashboardError}。</Text></Card>}
          <Suspense fallback={<div style={{ padding: 24 }}>加载中…</div>}>
            <Routes>
              <Route path="/overview" element={<OverviewPage findings={findings} cases={filteredCaseItems} caseBoards={caseBoards} timeRange={timeRange} inputOverviewSeries={demoOverviewSeries} />} />
              <Route path="/findings" element={<FindingsPage findings={findings} evidenceByFinding={evidenceByFinding} onOpenAssistant={openFindingAssistant} onOpenEntity={(entityId) => navigate(`/entities?entity=${encodeURIComponent(entityId)}`)} onOpenInvestigation={() => navigate('/investigations')} onSaveM3Graph={saveM3Graph} />} />
              <Route path="/entities" element={<EntityInvestigationPage profiles={entityProfiles} findings={findings} timeRange={timeRange} onOpenAssistant={openEntityAssistant} onSubmitBatch={submitBatchToAssistant} onExplain={explainWithAssistant} onOpenFinding={() => navigate('/findings')} />} />
              <Route path="/investigations" element={<InvestigationsPage cases={caseItems} findings={allFindings} evidenceByFinding={allEvidenceByFinding} caseBoards={caseBoards} activeFindingIds={filteredWindowIds} timeRange={timeRange} m3GraphSnapshots={m3GraphSnapshots} onDeleteCase={deleteCase} onEscalateCase={escalateInvestigation} onSetFindingStage={setFindingStage} onOpenAssistant={openCaseAssistant} onSubmitBatch={submitBatchToAssistant} onGenerateReport={generateAttackChainReport} onExplain={explainWithAssistant} onOpenEntity={(entityId) => navigate(`/entities?entity=${encodeURIComponent(entityId)}`)} />} />
              <Route path="/logs" element={<LogsPage findings={findings} evidenceByFinding={evidenceByFinding} demoEvents={demoEvents} timeRange={timeRange} onSubmitBatch={submitBatchToAssistant} onExplain={explainWithAssistant} onSaveM3Graph={saveM3Graph} />} />
              <Route path="/sources" element={<SourcesPage sources={sourceItems} onDeleteSource={deleteLogSource} onRefresh={async () => setIngestionRevision((current) => current + 1)} onImportFile={importLogFile} />} />
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
              <Route path="/evaluation" element={<EvaluationPage findings={findings} cases={caseItems} caseBoards={caseBoards} rawEvents={demoEvents.length} />} />
              <Route path="/mission-control" element={<Navigate to="/overview" replace />} />
              <Route path="/anomalies" element={<Navigate to="/findings" replace />} />
              <Route path="/settings" element={<Navigate to="/evaluation" replace />} />
              <Route path="*" element={<Navigate to="/overview" replace />} />
            </Routes>
          </Suspense>
        </Content>

        {assistantVisible && (
          <AssistantDock
            preview={assistantPreview}
            sending={assistantSending}
            collapsed={assistantDockCollapsed}
            onOpen={() => navigate('/assistant')}
            onSubmit={(question) => { void runAssistant(question, assistantContext) }}
            onToggleCollapsed={() => setAssistantDockCollapsed((current) => !current)}
          />
        )}
      </Layout>
    </Layout>
  )
}

function AssistantDock({
  preview,
  sending,
  collapsed,
  onOpen,
  onSubmit,
  onToggleCollapsed,
}: {
  preview: string
  sending: boolean
  collapsed: boolean
  onOpen: () => void
  onSubmit: (question: string) => void
  onToggleCollapsed: () => void
}) {
  const [question, setQuestion] = useState('')
  const [position, setPosition] = useState({ right: 24, bottom: 24 })
  const [dragging, setDragging] = useState(false)
  const dragRef = useRef<{ x: number; y: number; right: number; bottom: number } | null>(null)
  const draggedRef = useRef(false)

  useEffect(() => {
    if (!dragging) return undefined
    const onMove = (event: PointerEvent) => {
      const start = dragRef.current
      if (!start) return
      if (Math.abs(event.clientX - start.x) + Math.abs(event.clientY - start.y) > 4) draggedRef.current = true
      const right = Math.max(8, Math.min(window.innerWidth - 120, start.right - (event.clientX - start.x)))
      const bottom = Math.max(8, Math.min(window.innerHeight - 70, start.bottom - (event.clientY - start.y)))
      setPosition({ right, bottom })
    }
    const onUp = () => {
      setDragging(false)
      dragRef.current = null
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
    return () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
    }
  }, [dragging])

  const startDragging = (event: React.PointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest('button, a, input, textarea')) return
    event.preventDefault()
    draggedRef.current = false
    dragRef.current = { x: event.clientX, y: event.clientY, ...position }
    setDragging(true)
  }

  const toggleCollapsed = () => {
    if (draggedRef.current) {
      draggedRef.current = false
      return
    }
    onToggleCollapsed()
  }

  const submitQuestion = () => {
    const trimmed = question.trim()
    if (!trimmed || sending) return
    onSubmit(trimmed)
    setQuestion('')
  }

  if (collapsed) {
    return (
      <div className="mc-assistant-dock-collapsed" style={position} onPointerDown={startDragging} onClick={toggleCollapsed}>
        <RobotOutlined />
        <span>小影</span>
        {sending && <Badge status="processing" />}
      </div>
    )
  }

  return (
    <Card className="mc-assistant-dock" style={position}>
      <div className={`mc-assistant-dock-head ${dragging ? 'is-dragging' : ''}`} onPointerDown={startDragging}>
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
      <Paragraph ellipsis={{ rows: 6, expandable: true, symbol: '展开' }} style={{ marginBottom: 0 }}>
        {preview || '小影会话已保留。'}
      </Paragraph>
      <div className="mc-assistant-dock-input">
        <Input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); submitQuestion() } }}
          placeholder="输入问题"
          disabled={sending}
        />
        <Button type="primary" icon={<SendOutlined />} onClick={submitQuestion} loading={sending} aria-label="发送问题" />
      </div>
    </Card>
  )
}
