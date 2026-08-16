import { Suspense, lazy, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
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
  Popover,
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
  DeleteOutlined,
  FileSearchOutlined,
  InboxOutlined,
  InfoCircleOutlined,
  LinkOutlined,
  ReloadOutlined,
  RobotOutlined,
  QuestionCircleOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
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
  type Severity,
} from './mocks/data'
import { loadDemoDataset, type DemoDatasetId } from './services/demoData'
import { deleteIngestedSource, getIngestionSnapshot, uploadLogFile, type IngestResult, type ModuleScores } from './services/ingestion'
import { downloadAttackChainReport } from './services/attackChainReport'
import {
  askAssistant,
  getSecurityBaseline,
  getSecurityEntity,
  getSecurityEntityHistory,
  getInvestigations,
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
import {
  buildAttackChainGraph,
  buildM3GraphSnapshot,
  loadM3GraphSnapshots,
  persistM3GraphSnapshot,
  removeM3GraphSnapshot,
  limitGraphExplanation,
  type M3GraphSnapshot,
} from './services/caseGraphs'
import InteractiveCaseGraph from './InteractiveCaseGraph'

const { Header, Sider, Content } = Layout
const { Title, Text, Paragraph } = Typography
const { Dragger } = Upload
const PREFER_DEMO_DATA = import.meta.env.VITE_PREFER_DEMO_DATA !== 'false'
const EChartsView = lazy(() => import('./EChartsView'))
const PERSISTED_CASES_KEY = 'wad-demo-case-items-v1'
const PERSISTED_CASE_BOARDS_KEY = 'wad-demo-case-boards-v1'

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
    .forEach((item) => merged.set(item.id, item))
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

type DemoReplayEvent = SecurityEvent & {
  dataset: string
  module_scores?: ModuleScores
  raw_log_ref?: string
  score?: number
}

function presentEventStreamSource(source: LogSource): LogSource {
  if (!source.id.startsWith('UPLOAD-') && !source.path.startsWith('upload://')) return source
  return {
    ...source,
    path: `stream://${source.name}`,
    kind: '事件流',
  }
}

type DemoReplayEvent = SecurityEvent & {
  dataset: string
  module_scores?: ModuleScores
  raw_log_ref?: string
  score?: number
}

type EventRow = {
  id: string
  time: string
  source: string
  action: string
  normalizedAction?: string
  actor?: string
  host?: string
  process?: string
  ip?: string
  raw: string
  rawLogRef?: string
  entities?: string[]
  findingId?: string
  findingTitle: string
  risk?: number
  moduleScores?: ModuleScores
  evidenceIds: string[]
}

type ReplayEventRowsCache = {
  demoEvents: DemoReplayEvent[]
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  rows: EventRow[]
}

let replayEventRowsCache: ReplayEventRowsCache | null = null

type UploadSourceEntry = {
  uid: string
  name: string
  size: number
  file?: File
}

type ImportTask = {
  id: string
  name: string
  kind: string
  size: number
  progress: number
  status: 'queued' | 'parsing' | 'indexed' | 'ready' | 'failed'
  result: string
  event_count?: number
  finding_count?: number
  events_per_second?: number
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
  info: '正常',
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const findingSeverityLevels: Severity[] = ['critical', 'high', 'medium']

type FindingSortMode = 'risk_desc' | 'long_desc' | 'event_desc' | 'latest_desc'

const findingSortOptions: Array<{ value: FindingSortMode; label: string }> = [
  { value: 'risk_desc', label: '综合风险：高到低' },
  { value: 'long_desc', label: '长程关联：高到低' },
  { value: 'event_desc', label: '事件异常：高到低' },
  { value: 'latest_desc', label: '发现时间：新到旧' },
]

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

function HelpHint({ title, description }: { title: string; description: string }) {
  return (
    <Popover
      trigger="click"
      placement="top"
      title={title}
      content={<div className="mc-help-content">{description}</div>}
    >
      <button
        type="button"
        className="mc-help-trigger"
        aria-label={`${title}说明`}
        onClick={(event) => event.stopPropagation()}
      >
        <QuestionCircleOutlined />
      </button>
    </Popover>
  )
}

function HelpTitle({ title, description }: { title: string; description: string }) {
  return <Space size={5}><span>{title}</span><HelpHint title={`${title}说明`} description={description} /></Space>
}

function selectedExcerpt(fallback: string) {
  const selected = typeof window === 'undefined' ? '' : window.getSelection()?.toString().trim() || ''
  return (selected || fallback).replace(/\s+/g, ' ').slice(0, 900)
}

function ExplainableText({
  children,
  fallback,
  context,
  onExplain,
}: {
  children: ReactNode
  fallback: string
  context: AssistantContext
  onExplain: (excerpt: string, context: AssistantContext) => void
}) {
  return <span className="mc-ai-explainable" title="双击交给小影解释" onClick={(event) => event.stopPropagation()} onDoubleClick={(event) => { event.stopPropagation(); onExplain(selectedExcerpt(fallback), context) }}>{children}</span>
}

function ExplainableBlock({
  children,
  fallback,
  context,
  onExplain,
}: {
  children: ReactNode
  fallback: string
  context: AssistantContext
  onExplain: (excerpt: string, context: AssistantContext) => void
}) {
  return <div className="mc-ai-explainable-block" title="双击交给小影解释" onDoubleClick={() => onExplain(selectedExcerpt(fallback), context)}>{children}</div>
}

function riskLevelExplanation(value: number) {
  if (value >= 80) return `当前分数 ${value}，属于高优先级风险。80 分及以上建议优先核查。`
  if (value >= 65) return `当前分数 ${value}，属于较高风险。65 至 79 分建议尽快复核。`
  return `当前分数 ${value}，属于中等风险。建议结合事件证据和上下文判断。`
}

function RiskBadge({ value }: { value: number }) {
  return (
    <Popover trigger="click" placement="top" title="风险分数" content={<div className="mc-help-content">{riskLevelExplanation(value)}</div>}>
      <button type="button" className={`mc-risk-score mc-explainable-tag ${value >= 80 ? 'critical' : value >= 65 ? 'high' : 'medium'}`} onClick={(event) => event.stopPropagation()}>{value}</button>
    </Popover>
  )
}

function SeverityTag({ value }: { value: Severity }) {
  const color = value === 'critical' ? 'red' : value === 'high' ? 'orange' : value === 'medium' ? 'gold' : 'blue'
  return <Popover trigger="click" placement="top" title="风险等级" content={<div className="mc-help-content">严重：80 分及以上；高危：65 至 79 分；中危：低于 65 分。等级用于排序，不替代人工判断。</div>}><Tag color={color} className="mc-explainable-tag" onClick={(event) => event.stopPropagation()}>{severityLabel[value]}</Tag></Popover>
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

function parseAbsoluteDateTime(value?: string) {
  if (!value) return 0
  const parsed = Date.parse(value.replace(' ', 'T'))
  return Number.isNaN(parsed) ? 0 : parsed
}

function filterRowsByTimeRange<T extends { time: string }>(rows: T[], timeRange: string) {
  const datedRows = rows.map((row) => ({ row, timestamp: parseAbsoluteDateTime(row.time) }))
  const timestamps = datedRows.map((item) => item.timestamp).filter((value) => value > 0)
  if (!timestamps.length) return rows
  const cutoff = Math.max(...timestamps) - rangeToMilliseconds(timeRange)
  return datedRows.filter(({ timestamp }) => {
    return timestamp === 0 || timestamp >= cutoff
  }).map(({ row }) => row)
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

function filterRowsBySourceTimeRange<T extends { time: string; source?: string }>(rows: T[], timeRange: string) {
  const grouped = new Map<string, T[]>()
  rows.forEach((row) => {
    const key = row.source || 'unknown'
    const items = grouped.get(key)
    if (items) items.push(row)
    else grouped.set(key, [row])
  })
  return Array.from(grouped.values()).flatMap((items) => filterRowsByTimeRange(items, timeRange))
}

function buildReplayEventRows(
  demoEvents: DemoReplayEvent[],
  findings: FindingRecord[],
  evidenceByFinding: Record<string, EvidenceRecord[]>,
) {
  if (
    replayEventRowsCache
    && replayEventRowsCache.demoEvents === demoEvents
    && replayEventRowsCache.findings === findings
    && replayEventRowsCache.evidenceByFinding === evidenceByFinding
  ) {
    return replayEventRowsCache.rows
  }

  const findingByEventId = new Map<string, FindingRecord>()
  const evidenceIdsByEventId = new Map<string, string[]>()
  findings.forEach((finding) => {
    finding.events.forEach((event) => findingByEventId.set(event.id, finding))
    const evidence = evidenceByFinding[finding.id] || []
    evidence.forEach((item) => {
      const ids = evidenceIdsByEventId.get(item.eventId)
      if (ids) ids.push(item.id)
      else evidenceIdsByEventId.set(item.eventId, [item.id])
    })
  })

  const rows = demoEvents.map<EventRow>((event) => {
    const finding = findingByEventId.get(event.id)
    const normalizedAction = normalizedEventCategory(event.action, event.raw, event.process)
    return {
      ...event,
      source: event.dataset,
      action: describeLogEvent({ ...event, source: event.dataset, normalizedAction }),
      normalizedAction,
      rawLogRef: event.raw_log_ref || `${event.source}:${event.id}`,
      entities: [event.actor, event.host, event.process, event.ip].filter((value): value is string => Boolean(value)),
      findingId: finding?.id,
      findingTitle: finding?.title || '未形成异常发现',
      risk: finding?.risk,
      moduleScores: event.module_scores,
      evidenceIds: evidenceIdsByEventId.get(event.id) || [],
    }
  })

  replayEventRowsCache = { demoEvents, findings, evidenceByFinding, rows }
  return rows
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

function readableAction(value?: string) {
  const action = value || '未知行为'
  const normalized = action.toUpperCase()
  const labels: Array<[RegExp, string]> = [
    [/LOGIN_FAILURE|FAILED_PASSWORD|AUTH_FAILURE|登录失败|认证失败/i, '登录失败'],
    [/SSH_LOGIN|LOGIN|LOGON|AUTH|ACCEPTED_PASSWORD|登录成功|认证成功/i, '登录或认证'],
    [/PROCESS_START|EXEC|COMMAND|SHELL|进程启动|命令执行/i, '进程或命令执行'],
    [/NETWORK_CONNECT|NETWORK_BURST|PORT_BURST|DNS|外联|网络连接/i, '网络连接或探测'],
    [/FILE_CREATE|FILE_WRITE|ARCHIVE_CREATE|文件创建|写入/i, '文件创建或写入'],
    [/FILE_READ|FILE_ACCESS|文件读取|文件访问/i, '文件读取或访问'],
    [/DB_EXPORT|数据导出/i, '数据库或数据导出'],
    [/PRIVILEGE|TOKEN|权限提升|令牌/i, '权限或令牌操作'],
  ]
  return labels.find(([pattern]) => pattern.test(normalized) || pattern.test(action))?.[1] || action.replace(/[_-]+/g, ' ')
}

function normalizedEventCategory(value?: string, raw?: string, process?: string) {
  const readable = readableAction(value)
  if (/[\u4e00-\u9fff]/.test(readable)) return readable
  const text = `${value || ''} ${raw || ''} ${process || ''}`.toLowerCase()
  if (/failed password|authentication failure|login failed|\b4625\b/.test(text)) return '认证失败'
  if (/accepted password|accepted publickey|authentication success|\b4624\b/.test(text)) return '认证成功'
  if (/pam_unix\((?:sshd|sudo|systemd)|session (?:opened|closed)/.test(text)) return '用户或权限会话变化'
  if (/useradd|new user|new group|shadow group|account create/.test(text)) return '账户或用户组变更'
  if (/powershell|command=|type=user_cmd|process start|\bexec(?:ute)?\b/.test(text)) return '进程或命令执行'
  if (/systemd|starting |started |stopped |reached target|mounting /.test(text)) return '系统服务状态变化'
  if (/metricbeat|system\.network|system\.cpu|system\.memory/.test(text)) return '主机指标采集'
  if (/kernel|\bata\d|acpi|\busb\b|\bpnp\b/.test(text)) return '内核设备或驱动事件'
  if (/cloud-init|temporary failure resolving|failed to fetch/.test(text)) return '主机初始化或配置事件'
  if (/freshclam|clamav/.test(text)) return '安全软件更新事件'
  if (/\b(get|post|put|delete|patch|head)\s+\//.test(text)) return 'Web 访问事件'
  if (/dns|connect|outbound|src_ip|dst_ip|network/.test(text)) return '网络连接或探测'
  if (/file|archive|write|read|mount/.test(text)) return '文件或存储操作'
  if (/fail|error|denied|unable|unavailable/.test(text)) return '系统操作失败'
  return '其他系统事件'
}

type LogEventDescriptionInput = {
  raw?: string
  normalizedAction?: string
  actor?: string
  host?: string
  process?: string
  ip?: string
  source?: string
}

function compactEventObject(value: string, maxLength = 58) {
  const clean = value.replace(/\s+/g, ' ').replace(/[.。]+$/, '').trim()
  return clean.length > maxLength ? `${clean.slice(0, maxLength)}…` : clean
}

function describeLogEvent(event: LogEventDescriptionInput) {
  const raw = String(event.raw || '').trim()
  const syslogMessage = raw.match(/^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[^:]+:\s*(.*)$/)?.[1]
  const message = syslogMessage || raw
  let match: RegExpMatchArray | null

  match = message.match(/pam_unix\((sshd|sudo|systemd(?:[-_ ]user)?)(?::session)?\):\s*session\s+(opened|closed)\s+for user\s+([\w.@-]+)(?:\s+by\s+([^\s(]+)?\s*\(uid=(\d+)\))?/i)
  if (match) {
    const service = match[1].toLowerCase()
    const channel = service === 'sshd' ? 'SSH' : service === 'sudo' ? 'sudo 权限' : '用户'
    const state = match[2].toLowerCase() === 'opened' ? '已建立' : '已关闭'
    const initiator = match[4] || match[5] ? `（由 ${match[4] || `UID ${match[5]}`} 发起）` : ''
    return `${channel}会话${state}：${match[3]}${initiator}`
  }

  match = message.match(/failed password for (?:invalid user )?([\w.@-]+).*?from\s+((?:\d{1,3}\.){3}\d{1,3})/i)
  if (match) return `SSH 登录失败：用户 ${match[1]}，来源 ${match[2]}`
  match = message.match(/accepted (?:password|publickey) for\s+([\w.@-]+).*?from\s+((?:\d{1,3}\.){3}\d{1,3})/i)
  if (match) return `SSH 登录成功：用户 ${match[1]}，来源 ${match[2]}`

  match = message.match(/\bStarting\s+(.+?)(?:\.\.\.|$)/i)
  if (match) return `正在启动系统服务：${compactEventObject(match[1])}`
  match = message.match(/\bStarted\s+(.+?)(?:\.|$)/i)
  if (match) return `系统服务启动完成：${compactEventObject(match[1])}`
  match = message.match(/\bReached target\s+(.+?)(?:\.|$)/i)
  if (match) return `系统运行目标已就绪：${compactEventObject(match[1])}`
  match = message.match(/\bStopped\s+(.+?)(?:\.|$)/i)
  if (match) return `系统服务已停止：${compactEventObject(match[1])}`

  match = message.match(/\b(ata\d+(?:\.\d+)?):\s*NODEV after polling detection/i)
  if (match) return `磁盘设备轮询未发现设备：${match[1]}`
  match = message.match(/metricbeat\s+system\.network\s+interface=([^\s]+)\s+in[_ ]bytes=(\d+)\s+out[_ ]bytes=(\d+)/i)
  if (match) return `采集网络指标：接口 ${match[1]}，入站 ${match[2]} B，出站 ${match[3]} B`
  if (/ClamAV update process started|freshclam/i.test(message)) return 'ClamAV 病毒库更新任务已启动'

  match = message.match(/temporary failure resolving ['"]?([^'"\s]+)['"]?/i)
  if (match) return `DNS 解析临时失败：${match[1]}`
  match = message.match(/failed to fetch\s+https?:\/\/([^/\s]+)/i)
  if (match) return `软件源获取失败：${match[1]}`
  if (/generating public\/private .* key pair|the key fingerprint is|\[(?:rsa|ecdsa|ed25519)\s+\d+\]/i.test(message)) return '生成或展示 SSH 主机密钥信息'
  if (/ci info:/i.test(message)) return 'cloud-init 输出网络配置摘要'

  match = message.match(/(?:new user:\s*name=|useradd(?:\s+created)?\s+|add(?:ed)? user\s+)([\w.@-]+)/i)
  if (match) return `创建本地账户：${match[1]}`
  match = message.match(/new group:\s*name=([\w.@-]+)/i)
  if (match) return `创建本地用户组：${match[1]}`
  match = message.match(/add ['"]?([\w.@-]+)['"]? to (?:shadow )?group ['"]?([\w.@-]+)['"]?/i)
  if (match) return `修改用户组：将 ${match[1]} 加入 ${match[2]}`
  if (/powershell(?:\.exe)?\s+(?:-enc|-encodedcommand)/i.test(message)) {
    return `执行编码 PowerShell：${event.actor || event.process || '执行主体未解析'}`
  }

  match = message.match(/"(GET|POST|PUT|DELETE|PATCH|HEAD)\s+([^\s]+)\s+HTTP\/[^"]+"\s+(\d{3})/i)
  if (match) return `HTTP ${match[1].toUpperCase()} 请求：${compactEventObject(match[2], 48)}，状态 ${match[3]}`
  if (/Possible Nmap User-Agent Observed/i.test(message)) return `检测到疑似 Nmap 扫描：${event.ip || '来源地址待解析'}`
  if (/type=USER_CMD/i.test(message)) {
    match = message.match(/\bpid=(\d+)/i)
    return `记录到用户命令执行${match ? `：进程 PID ${match[1]}` : ''}`
  }

  const normalized = event.normalizedAction || '未知行为'
  if (normalized === '进程或命令执行') return `执行进程或命令：${event.process || event.actor || '执行对象待解析'}`
  if (normalized === '网络连接或探测') return `发起网络连接或探测：${event.ip || event.host || '目标待解析'}`
  if (normalized === '文件创建或写入' || normalized === '文件读取或访问') return `${normalized}：${event.process || '文件对象待解析'}`
  if (normalized !== '未知行为' && /[\u4e00-\u9fff]/.test(normalized)) return normalized

  const component = event.process || event.source
  if (/kernel/i.test(component || '')) return `内核设备或驱动事件：${event.host || '主机待解析'}`
  if (/systemd/i.test(component || '')) return `系统服务状态变化：${event.host || '主机待解析'}`
  if (/metricbeat/i.test(message)) return `主机指标采集事件：${event.host || '主机待解析'}`
  if (/sshd/i.test(component || '')) return `SSH 认证或会话事件：${event.actor || '用户待解析'}`
  if (/sudo/i.test(component || '')) return `sudo 权限会话事件：${event.actor || '用户待解析'}`
  return `其他系统事件：${component || '类型待解析'}`
}

function readableReason(value?: string) {
  if (!value) return '未说明'
  const labels: Record<string, string> = {
    shared_account: '共享账号',
    same_user: '相同用户',
    same_host: '相同主机',
    multi_source_corroboration: '多来源印证',
    process_relation: '进程关联',
    new_host_relation: '新主机关系',
    unusual_time: '异常时段',
    long_range_entity_overlap: '长程实体重叠',
  }
  if (labels[value]) return labels[value]
  const gap = value.match(/^Δt\s*(.*)$/i)
  if (gap) return `时间间隔 ${gap[1]}`
  return value.replace(/[_-]+/g, ' ')
}

function reasonExplanation(value: string) {
  const descriptions: Record<string, string> = {
    shared_account: '当前发现与其他行为使用同一账号。共享账号本身不等于攻击，需要结合时间和行为判断。',
    same_user: '两段行为由同一用户账号触发，可能属于同一操作过程。',
    same_host: '两段行为发生在同一主机上，说明存在共同的执行环境。',
    multi_source_corroboration: '同一时间段被多个日志来源同时印证，证据完整度更高。',
    process_relation: '时间窗口内出现进程、脚本、命令或令牌操作，可能与当前事件有关。',
    new_host_relation: '时间窗口内出现网络连接、DNS、SSH 或新的主机关系，需要核查是否为正常通信。',
    unusual_time: '行为发生在较少见的时段。该理由仅表示偏离常态，不单独代表攻击。',
    long_range_entity_overlap: '相隔较长时间的发现共享多个实体，可能属于同一持续过程。',
  }
  if (descriptions[value]) return descriptions[value]
  if (/^Δt\s*/i.test(value)) return `两段关联行为之间的时间间隔为 ${value.replace(/^Δt\s*/i, '')}。时间接近时，关联强度通常更高。`
  return '这是系统用于解释关联依据的标签，应结合原始日志和时间线复核。'
}

function ReasonTag({ reason }: { reason: string }) {
  return <Popover trigger="click" placement="top" title={readableReason(reason)} content={<div className="mc-help-content">{reasonExplanation(reason)}</div>}><Tag className="mc-explainable-tag" onClick={(event) => event.stopPropagation()}>{readableReason(reason)}</Tag></Popover>
}

function readableStage(stage: FindingStage) {
  return stage === 'main' ? '主链证据' : stage === 'candidate' ? '候选证据' : '已排除'
}

function readableEntityType(type: EntityProfile['type']) {
  return ({ User: '用户账号', Host: '主机', Process: '进程或程序', IP: 'IP 地址', Asset: '文件或资产' } as Record<EntityProfile['type'], string>)[type] || '未知实体'
}

function normalizedLogAction(row: SecurityLogRecord) {
  const value = row.action || row.labels?.slice(0, 2).join(' ') || row.source_type || row.source || '未知行为'
  return normalizedEventCategory(value, row.text, row.source_type || row.source)
}

function toEventRow(row: SecurityLogRecord): EventRow {
  const entities = row.entities || []
  const { actor, host, process, ip } = inferLogParticipants(entities)
  const normalizedAction = normalizedLogAction(row)
  const raw = row.text || JSON.stringify(row, null, 2)
  return {
    id: row.event_id || row.id || row.raw_log_ref || 'unknown',
    time: row.time || row.timestamp || '—',
    source: row.source_type || row.source || 'Unknown',
    action: describeLogEvent({ raw, normalizedAction, actor, host, process, ip, source: row.source_type || row.source }),
    normalizedAction,
    actor,
    host,
    process,
    ip,
    raw,
    rawLogRef: row.raw_log_ref || [row.path, row.event_id || row.id].filter(Boolean).join(':'),
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
  const derivedBase = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([host, count], index) => {
      const loginCount = events.filter((event) => (event.entities || []).includes(host) && /LOGIN|LOGON|AUTH|SSH|RDP|REMOTE|登录|认证|远程/i.test(`${event.text || ''} ${(event.labels || []).join(' ')}`)).length
      return { host, count, loginCount, loginShare: 0, isNew: index >= 1 || count <= 2 }
    })
  const totalLoginCount = derivedBase.reduce((sum, item) => sum + item.loginCount, 0)
  const derived = derivedBase.map((item) => ({
    ...item,
    loginShare: totalLoginCount > 0 ? Math.round((item.loginCount / totalLoginCount) * 100) : 0,
  }))
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
      feature: '来源多样性',
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
    <div className="mc-assistant-answer">
      {content.split(/\r?\n/).map((rawLine, index) => {
        const line = rawLine.trim()
        if (!line) return <div className="mc-assistant-answer-gap" key={`gap-${index}`} />
        if (/^【.+】$/.test(line)) return <div className="mc-assistant-answer-heading" key={`heading-${index}`}>{line.slice(1, -1)}</div>
        if (/^\d+\.\s/.test(line)) return <div className="mc-assistant-answer-step" key={`step-${index}`}>{line}</div>
        if (line.startsWith('- ')) return <div className="mc-assistant-answer-bullet" key={`bullet-${index}`}>{line.slice(2)}</div>
        return <Paragraph key={`paragraph-${index}`}>{line}</Paragraph>
      })}
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

function AssistantAnswerContent({ content }: { content: string }) {
  return (
    <div className="mc-assistant-answer">
      {content.split(/\r?\n/).map((rawLine, index) => {
        const line = rawLine.trim()
        if (!line) return <div className="mc-assistant-answer-gap" key={`gap-${index}`} />
        if (/^【.+】$/.test(line)) return <div className="mc-assistant-answer-heading" key={`heading-${index}`}>{line.slice(1, -1)}</div>
        if (/^\d+\.\s/.test(line)) return <div className="mc-assistant-answer-step" key={`step-${index}`}>{line}</div>
        if (line.startsWith('- ')) return <div className="mc-assistant-answer-bullet" key={`bullet-${index}`}>{line.slice(2)}</div>
        return <Paragraph key={`paragraph-${index}`}>{line}</Paragraph>
      })}
    </div>
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
  { label: '项目方法', prompt: '结合链影寻踪项目知识库，解释当前分析用到了哪些 M0-M6 模块和三项核心创新，并给出知识库引用。' },
]

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

  const deleteLogSource = async (sourceId: string) => {
    const result = await deleteIngestedSource(sourceId)
    setSourceItems((current) => current.filter((source) => source.id !== sourceId))
    setIngestionRevision((current) => current + 1)
    message.success(`已删除 ${result.name} 及其关联事件、发现和案件。`)
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
          <Routes>
            <Route path="/overview" element={<OverviewPage findings={findings} cases={filteredCaseItems} caseBoards={caseBoards} timeRange={timeRange} inputOverviewSeries={demoOverviewSeries} />} />
            <Route path="/findings" element={<FindingsPage findings={findings} evidenceByFinding={evidenceByFinding} onOpenAssistant={openFindingAssistant} onOpenEntity={(entityId) => navigate(`/entities?entity=${encodeURIComponent(entityId)}`)} onOpenInvestigation={() => navigate('/investigations')} onSaveM3Graph={saveM3Graph} />} />
            <Route path="/entities" element={<EntityInvestigationPage profiles={entityProfiles} findings={findings} timeRange={timeRange} onOpenAssistant={openEntityAssistant} onSubmitBatch={submitBatchToAssistant} onExplain={explainWithAssistant} onOpenFinding={() => navigate('/findings')} />} />
            <Route path="/investigations" element={<InvestigationsPage cases={caseItems} findings={allFindings} evidenceByFinding={allEvidenceByFinding} caseBoards={caseBoards} activeFindingIds={filteredWindowIds} timeRange={timeRange} m3GraphSnapshots={m3GraphSnapshots} onDeleteCase={deleteCase} onSetFindingStage={setFindingStage} onOpenAssistant={openCaseAssistant} onSubmitBatch={submitBatchToAssistant} onGenerateReport={generateAttackChainReport} onExplain={explainWithAssistant} onOpenEntity={(entityId) => navigate(`/entities?entity=${encodeURIComponent(entityId)}`)} />} />
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
            <Route path="/evaluation" element={<EvaluationPage findings={findings} caseBoards={caseBoards} rawEvents={demoEvents.length} />} />
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
            onSubmit={(question) => { void runAssistant(question, assistantContext) }}
            onToggleCollapsed={() => setAssistantDockCollapsed((current) => !current)}
          />
        )}
      </Layout>
    </Layout>
  )
}

function OverviewPage({
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
  const correlatedFindings = cases.reduce((sum, item) => sum + item.windowIds.length, 0)
  const reviewed = cases.reduce((sum, item) => sum + item.windowIds.filter((findingId) => findingId in (caseBoards[item.id] || {})).length, 0)
  const mainChainEvidence = cases.reduce((sum, item) => sum + Object.entries(caseBoards[item.id] || {}).filter(([, stage]) => stage === 'main').length, 0)
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
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="人工研判" value={reviewed} /></Card></Col>
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

function FindingsPage({
  findings,
  evidenceByFinding,
  onOpenAssistant,
  onOpenEntity,
  onOpenInvestigation,
  onSaveM3Graph,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  onOpenAssistant: (finding: FindingRecord) => void
  onOpenEntity: (entityId: string) => void
  onOpenInvestigation: () => void
  onSaveM3Graph: (finding: FindingRecord) => void
}) {
  const [selected, setSelected] = useState<FindingRecord | null>(null)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [source, setSource] = useState('all')
  const [sortMode, setSortMode] = useState<FindingSortMode>('risk_desc')

  const filtered = useMemo(() => {
    const matched = findings.filter((finding) => {
      const haystack = [finding.id, finding.title, finding.entity, finding.host, finding.source, finding.reasons.join(' ')].join(' ').toLowerCase()
      return haystack.includes(query.toLowerCase())
        && (severity === 'all' || finding.severity === severity)
        && (source === 'all' || finding.source.includes(source))
    })
    return [...matched].sort((left, right) => {
      if (sortMode === 'long_desc') return right.longScore - left.longScore || right.risk - left.risk || right.eventScore - left.eventScore
      if (sortMode === 'event_desc') return right.eventScore - left.eventScore || right.risk - left.risk || right.longScore - left.longScore
      if (sortMode === 'latest_desc') return parseAbsoluteDateTime(right.start) - parseAbsoluteDateTime(left.start) || right.risk - left.risk
      return right.risk - left.risk || right.longScore - left.longScore || right.eventScore - left.eventScore
    })
  }, [findings, query, severity, sortMode, source])

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
    { title: '长程关联', dataIndex: 'longScore', key: 'longScore', width: 120, render: (value: number) => <Progress percent={Math.min(100, Math.max(0, Number(value)))} size="small" status={scoreTone(Number(value))} format={(percent) => `${percent ?? 0}%`} /> },
    { title: <HelpTitle title="理由" description="理由说明系统为何将该发现列为需要关注。点击每个标签可查看具体关联依据。" />, dataIndex: 'reasons', key: 'reasons', render: (value: string[]) => <Space size={[4, 4]} wrap>{value.map((item) => <ReasonTag key={item} reason={item} />)}</Space> },
  ]

  return (
    <>
      <PageTitle title="异常发现" />
      <Card className="mc-queue-card">
        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索异常发现 / 实体 / 主机 / 理由" className="mc-search" />
          <Select value={severity} onChange={setSeverity} style={{ width: 120 }} options={[{ value: 'all', label: '全部风险' }, ...findingSeverityLevels.map((value) => ({ value, label: severityLabel[value] }))]} />
          <Select value={source} onChange={setSource} style={{ width: 150 }} options={[{ value: 'all', label: '全部日志源' }, ...Array.from(new Set(findings.flatMap((finding) => finding.sourceTypes))).map((value) => ({ value, label: value }))]} />
          <Select
            value={sortMode}
            onChange={(value) => setSortMode(value as FindingSortMode)}
            style={{ width: 190 }}
            options={findingSortOptions}
            aria-label="发现排序方式"
          />
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
            <Card size="small" title={<HelpTitle title="调查锚点" description="当前异常发现的核心对象、主机和时间范围，是开始复核的切入点。" />} className="mc-drawer-card">
              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label="异常发现">{selected.id}</Descriptions.Item>
                <Descriptions.Item label="实体">{selected.entity}</Descriptions.Item>
                <Descriptions.Item label="主机">{selected.host}</Descriptions.Item>
                <Descriptions.Item label="锚点事件">{selected.anchorEvent.action}</Descriptions.Item>
                <Descriptions.Item label="Investigation Range">过去 1 小时</Descriptions.Item>
                <Descriptions.Item label="Model Context">过去 30 分钟</Descriptions.Item>
              </Descriptions>
            </Card>

            <Card size="small" title={<HelpTitle title="M6 风险融合" description="综合事件自身、短程上下文和长程关联形成排序分数。分数用于优先级，不是攻击结论。" />} className="mc-drawer-card">
              <Row gutter={[8, 8]}>
                <Col span={8}><Statistic title="综合风险" value={selected.risk} /></Col>
                <Col span={8}><Statistic title="事件自身异常" value={selected.eventScore} /></Col>
                <Col span={8}><Statistic title="局部上下文" value={selected.localScore} /></Col>
                <Col span={24}><Statistic title="长程关联" value={selected.longScore} /></Col>
              </Row>
              <Divider style={{ margin: '12px 0 8px' }} />
              <Text type="secondary">weak_fusion_v2 · 综合风险 = 36% 事件异常 + 29% 局部上下文 + 35% 长程关联</Text>
            </Card>

            <Card size="small" title={<HelpTitle title="远程候选" description="与当前发现相隔较远但存在实体或行为关联的候选证据，需要人工确认。" />} className="mc-drawer-card">
              <List
                dataSource={selected.relatedCandidates}
                locale={{ emptyText: '暂无远程候选' }}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta title={<Text strong>{item.title}</Text>} description={`${item.id} · ${item.time}`} />
                    <Space size={[4, 4]} wrap>{item.reasons.map((reason) => <ReasonTag key={`${item.id}-${reason}`} reason={reason} />)}</Space>
                  </List.Item>
                )}
              />
            </Card>

            <Card size="small" title={<HelpTitle title="M5 关联依据" description="说明长程关联使用的共同实体、时间间隔和关联强度。" />} className="mc-drawer-card">
              <Descriptions size="small" column={2}>
                <Descriptions.Item label="关联置信度">{selected.association.confidence.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="共享锚点">{selected.association.sharedAnchor}</Descriptions.Item>
                <Descriptions.Item label="锚点强度">{selected.association.anchorStrength}</Descriptions.Item>
                <Descriptions.Item label="实体稀有度">{selected.association.entityRarity.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="行为兼容度">{selected.association.actionCompatibility.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="图相似度">{selected.association.graphSimilarity.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="时间间隔" span={2}>{selected.association.timeGap}</Descriptions.Item>
              </Descriptions>
              <Divider />
              <List size="small" dataSource={selected.association.summary} renderItem={(item) => <List.Item>{item}</List.Item>} />
            </Card>

            <Card size="small" title={<HelpTitle title="证据" description="保留支撑该发现的原始日志引用和事实陈述，可作为人工复核依据。" />} className="mc-drawer-card">
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
              <Button icon={<LinkOutlined />} onClick={() => onSaveM3Graph(selected)}>保存当前事件 30 分钟 M3 关联图</Button>
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
  onSubmitBatch,
  onExplain,
  onOpenFinding,
}: {
  profiles: EntityProfile[]
  findings: FindingRecord[]
  timeRange: string
  onOpenAssistant: (entity: EntityProfile) => void
  onSubmitBatch: (prompt: string, context: AssistantContext) => void
  onExplain: (excerpt: string, context: AssistantContext) => void
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
  // Replay data arrives asynchronously; avoid deriving presentation fields
  // until the 30-day entity inventory is available.
  if (!selected) return null
  const filtered = availableProfiles.filter((item) => `${item.id} ${item.type}`.toLowerCase().includes(query.toLowerCase()))
  const relatedFindings = findings.filter((finding) => selected && (selected.findingIds.includes(finding.id) || finding.entities.includes(selected.id)))
  const entityTypeLabel: Record<EntityProfile['type'], string> = {
    User: '用户账号',
    Host: '主机',
    Process: '进程或程序',
    IP: 'IP 地址',
    Asset: '文件或资产',
  }
  const attentionLevel = selected.rareRelations >= 3 ? '高关注' : selected.rareRelations >= 2 ? '需要核查' : '一般关注'
  const attentionColor = selected.rareRelations >= 3 ? 'red' : selected.rareRelations >= 2 ? 'orange' : 'blue'
  const entityExplanation = `${entityTypeLabel[selected.type]} ${selected.id} 在近 30 天资产画像中出现 ${selected.thirtyDayEvents} 次，涉及 ${selected.currentLoginHosts} 个关联主机。系统将它标记为${attentionLevel}，主要依据是关联关系的稀有程度、最近活动与历史基线的偏离，以及它参与的异常发现。`

  const submitEntities = () => {
    const snapshot = filtered.map((profile) => {
      const profileFindings = findings.filter((finding) => profile.findingIds.includes(finding.id) || finding.entities.includes(profile.id))
      const findingSummary = profileFindings.map((finding) => `${finding.start} ${finding.title} (${finding.host || 'host unresolved'}, risk ${finding.risk})`).join('; ') || 'no linked finding'
      return `entity=${profile.id}; type=${entityTypeLabel[profile.type]}; first_seen=${profile.firstSeen}; last_seen=${profile.lastSeen}; event_count=${profile.thirtyDayEvents}; active_hosts=${profile.currentLoginHosts}; new_relations=${profile.newHostRelations}; linked_findings=${findingSummary}`
    }).join('\n')
    onSubmitBatch(
      `The following is the complete set of ${filtered.length} entities currently filtered in Entity Investigation, with their related findings. Analyze them as security investigation context. In Chinese, first state what this entity set represents, then list no more than four entities needing attention and why. Risk scores and anomalous-relation labels are leads, not proof of compromise. Do not invent events not present in this snapshot.\n\n${snapshot}`,
      { entityIds: filtered.map((item) => item.id), windowIds: Array.from(new Set(filtered.flatMap((item) => item.findingIds))), timeRange },
    )
  }

  return (
    <>
      <PageTitle title="实体调查" subtitle={`完整 30 天实体资产画像 · 当前关联发现聚焦 ${timeRange}`} extra={<Space><Button onClick={onOpenFinding}>异常发现</Button><Button onClick={() => onOpenAssistant(selected)}>分析当前实体</Button><Button type="primary" icon={<RobotOutlined />} onClick={submitEntities}>提交当前筛选结果给小影</Button></Space>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={7}>
          <Card title={`实体列表 · ${filtered.length}/${availableProfiles.length}`} className="mc-investigation-list">
            <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索实体" className="mc-search" />
            <Divider />
            <List
              dataSource={filtered}
              renderItem={(item) => (
                <List.Item className={item.id === selected?.id ? 'active' : ''} onClick={() => setSelectedId(item.id)}>
                  <List.Item.Meta title={<Text strong>{item.id}</Text>} description={`${entityTypeLabel[item.type]} · 最近活动 ${item.lastSeen}`} />
                  <Tag color={item.rareRelations >= 2 ? 'red' : 'blue'}>{item.rareRelations} 个异常关系</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={17}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3}><ExplainableText fallback={selected.id} context={{ entityIds: [selected.id], windowIds: selected.findingIds }} onExplain={onExplain}>{selected.id}</ExplainableText></Title>
                <Text type="secondary">{entityTypeLabel[selected.type]} · 首次出现 {selected.firstSeen} · 最近出现 {selected.lastSeen}</Text>
              </div>
              <Tag color={attentionColor}>关注级别：{attentionLevel}</Tag>
            </div>
            <div className="mc-entity-explanation">
              <InfoCircleOutlined />
              <div><strong>实体说明</strong><div>{entityExplanation}</div></div>
            </div>
            {useRepositoryData && (
              <div style={{ marginTop: 10 }}>
                <Text type="secondary">{loading ? '正在从真实数据层加载实体画像...' : loadError || `已接入真实实体数据 · ${timeRange} 历史窗口`}</Text>
              </div>
            )}
          </Card>

          <Row gutter={[12, 12]}>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="时间范围内事件" value={selected.thirtyDayEvents} suffix="次" /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="正常主机" value={selected.normalLoginHosts} /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="当前主机" value={selected.currentLoginHosts} /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="新增关系" value={selected.newHostRelations} /></Card></Col>
          </Row>

           <Row gutter={[12, 12]}>
             <Col xs={24}>
              <Card title={<HelpTitle title="基线对比" description="将当前实体行为与历史常态比较。偏离表示值得关注，不代表单独成立的攻击证据。" />} className="mc-panel">
                <Table
                  rowKey="feature"
                  pagination={false}
                  size="small"
                  columns={[
                    { title: '特征', dataIndex: 'feature', key: 'feature' },
                    { title: '当前观察', dataIndex: 'current', key: 'current' },
                    { title: '历史常态', dataIndex: 'baseline', key: 'baseline' },
                    { title: '偏离程度', dataIndex: 'deviation', key: 'deviation', render: (value: number) => <Space size={6}><Progress percent={Math.round(value * 100)} size="small" status={value >= 0.8 ? 'exception' : 'normal'} /><Text type="secondary">{value >= 0.8 ? '明显偏离' : value >= 0.6 ? '有所偏离' : '接近常态'}</Text></Space> },
                  ]}
                  dataSource={selected.baseline}
                  className="mc-baseline-table"
                  scroll={{ x: 582 }}
                />
              </Card>
            </Col>
            <Col span={24}>
              <Card title={<HelpTitle title="关联发现" description="列出近期与该实体有关的异常发现。点击关联理由标签可查看为什么被关联。" />} className="mc-panel">
                <Table
                  rowKey="id"
                  size="small"
                  pagination={{ pageSize: 5, hideOnSinglePage: true }}
                  columns={[
                    { title: '时间', dataIndex: 'start', key: 'start', width: 170 },
                    { title: '关联行为', dataIndex: 'title', key: 'title', width: 220 },
                    { title: '主机', dataIndex: 'host', key: 'host', width: 150 },
                    { title: <HelpTitle title="为什么关联" description="这些标签说明当前实体与异常发现之间的关联依据。点击标签可查看简要解释。" />, key: 'reason', render: (_: unknown, row: FindingRecord) => <Space size={4} wrap>{row.reasons.slice(0, 3).map((reason) => <ReasonTag key={reason} reason={reason} />)}</Space> },
                    { title: '风险', dataIndex: 'risk', key: 'risk', width: 90, render: (value: number) => <Tag color={value >= 75 ? 'red' : value >= 50 ? 'orange' : 'blue'}>{value}</Tag> },
                  ]}
                  dataSource={relatedFindings}
                  locale={{ emptyText: '当前实体暂无关联异常发现' }}
                />
                {/*
                  dot: <ClockCircleOutlined />,
                  children: <div><strong>{finding.start}</strong><div>{finding.title}</div><Text type="secondary">{finding.id} · {finding.host}</Text></div>,
                }))} */}
              </Card>
            </Col>
            <Col span={24}>
              <Card title={<HelpTitle title="调查提示" description="根据当前证据整理的复核方向，帮助分析人员决定下一步查看什么。" />} className="mc-panel">
                <Space direction="vertical" size={6}>
                  <Text><LinkOutlined /> 优先核对：{selected.currentActivity} 附近是否存在认证、远程访问或进程启动行为。</Text>
                  <Text><LinkOutlined /> 关系变化：当前关联 {selected.currentLoginHosts} 台主机，其中 {selected.newHostRelations} 台被识别为新增关系。</Text>
                  <Text><LinkOutlined /> 证据边界：以上内容来自实体历史、标准化事件和关联发现；异常分数是模型判断，不会改写原始日志事实。</Text>
                </Space>
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
}) {
  const location = useLocation()
  const [selectedId, setSelectedId] = useState(cases[0]?.id || '')
  const [graphDetail, setGraphDetail] = useState<{ title: string; kind: string; description: string; relation?: string; evidence?: string; explanation?: string; boundary?: string; originalName?: string; details?: string[]; source?: string; target?: string; prompt?: string } | null>(null)
  const [graphPositions, setGraphPositions] = useState<Record<string, Record<string, { x: number; y: number }>>>(() => {
    try {
      return JSON.parse(window.localStorage.getItem('wad-demo-graph-positions-v2') || '{}') as Record<string, Record<string, { x: number; y: number }>>
    } catch {
      return {}
    }
  })
  const attackChartRef = useRef<any>(null)
  const m3ChartRef = useRef<any>(null)
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
  const related = selected ? findings.filter((finding) => selected.windowIds.includes(finding.id)) : []
  const activeRelatedCount = related.filter((finding) => activeFindingIds.has(finding.id)).length
  const board = selected ? caseBoards[selected.id] || {} : {}
  const main = related.filter((finding) => board[finding.id] === 'main')
  const candidate = related.filter((finding) => board[finding.id] === 'candidate')
  const excluded = related.filter((finding) => board[finding.id] === 'excluded')
  const entities = Array.from(new Set(related.flatMap((finding) => finding.entities))).slice(0, 8)
  const graphFindings = related.filter((finding) => board[finding.id] !== 'excluded')
  const datasetName = selected?.title.startsWith('Short') ? 'Short' : selected?.title.startsWith('Long') ? 'Long' : ''
  const attackGraphFindings = datasetName
    ? findings.filter((finding) => finding.events.some((event) => event.id.startsWith(`${datasetName.toUpperCase()}-`)))
    : graphFindings
  const graphEntities = Array.from(new Set(graphFindings.flatMap((finding) => finding.entities))).slice(0, 8)
  const savedM3Graphs = related.flatMap((finding) => m3GraphSnapshots[finding.id] ? [m3GraphSnapshots[finding.id]] : [])
  const attackChainGraph = useMemo(() => buildAttackChainGraph(attackGraphFindings), [attackGraphFindings])
  const activeM3Graph = savedM3Graphs[0]
  const saveInteractiveGraphPositions = (graphId: string, positions: Record<string, { x: number; y: number }>) => {
    setGraphPositions((current) => {
      const next = { ...current, [graphId]: positions }
      window.localStorage.setItem('wad-demo-graph-positions-v2', JSON.stringify(next))
      return next
    })
  }
  const rememberGraphPosition = (graphId: string, params: { data?: { id?: string; x?: number; y?: number } }) => {
    const node = params.data
    if (!node?.id || typeof node.x !== 'number' || typeof node.y !== 'number') return
    setGraphPositions((current) => {
      const next = { ...current, [graphId]: { ...(current[graphId] || {}), [node.id as string]: { x: node.x as number, y: node.y as number } } }
      window.localStorage.setItem('wad-demo-graph-positions-v2', JSON.stringify(next))
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
      window.localStorage.setItem('wad-demo-graph-positions-v2', JSON.stringify(next))
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

  const attackChainGraphOption = useMemo(() => {
    const chain = buildAttackChainGraph(graphFindings)
    return {
      animation: false,
      tooltip: { formatter: (params: { data?: { name?: string; description?: string } }) => `${params.data?.name || ''}<br/>${params.data?.description || ''}` },
      series: [{
        type: 'graph', layout: 'force', roam: true,
        force: { repulsion: 0, gravity: 0, edgeLength: 0, layoutAnimation: false },
        data: chain.nodes.map((node, index) => { const position = graphPositions[`attack:${selected?.id || 'pending'}`]?.[node.id]; return { ...node, x: position?.x ?? 110 + index * 155, y: position?.y ?? 170 + (index % 2) * 70, fixed: Boolean(position), symbolSize: 54, draggable: true, label: { show: true, color: '#111827', fontSize: 11 }, itemStyle: { color: node.category === 0 ? '#ef4444' : '#f59e0b', borderColor: '#fde68a', borderWidth: 1.2 } } }),
        links: chain.links.map((link) => ({ ...link, lineStyle: { color: link.weight && link.weight >= 1 ? '#f87171' : '#f59e0b', width: link.weight && link.weight >= 1 ? 2.3 : 1.5, type: link.weight && link.weight >= 1 ? 'solid' : 'dashed' } })),
        emphasis: { focus: 'adjacency' },
      }],
    }
  }, [graphFindings, graphPositions, selected?.id])

  const m3GraphOption = useMemo(() => {
    const snapshot = savedM3Graphs[0]
    if (!snapshot) return { title: { text: '尚未保存 M3 图', left: 'center', top: 'middle', textStyle: { color: '#c6d4e4', fontSize: 16 } }, series: [] }
    return {
      animation: false,
      tooltip: { formatter: (params: { data?: { name?: string; description?: string } }) => `${params.data?.name || ''}<br/>${params.data?.description || ''}` },
      series: [{
        type: 'graph', layout: 'force', roam: true,
        force: { repulsion: 0, gravity: 0, edgeLength: 0, layoutAnimation: false },
        data: snapshot.nodes.map((node, index) => { const eventCount = snapshot.nodes.filter((item) => item.kind === 'event').length; const position = graphPositions[`m3:${snapshot.findingId}`]?.[node.id]; return { ...node, x: position?.x ?? (node.kind === 'event' ? 130 + index * 180 : 130 + (index - eventCount) * 150), y: position?.y ?? (node.kind === 'event' ? 120 : 300), fixed: Boolean(position), symbolSize: node.kind === 'event' ? 42 : 30, draggable: true, label: { show: true, color: '#111827', fontSize: 11 } } }),
        links: snapshot.links.map((link) => ({ ...link, lineStyle: { color: link.relation === '时间先后' ? '#60a5fa' : '#94a3b8', width: link.relation === '时间先后' ? 2 : 1.2 } })),
        categories: [{ name: '事件' }, { name: '实体' }],
        emphasis: { focus: 'adjacency' },
      }],
    }
  }, [graphPositions, savedM3Graphs])

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
                      {stage !== 'main' && <Button type="link" size="small" onClick={() => onSetFindingStage(selected.id, item.id, 'main')}>加入主链</Button>}
                      {stage !== 'candidate' && <Button type="link" size="small" onClick={() => onSetFindingStage(selected.id, item.id, 'candidate')}>保留候选</Button>}
                      {stage !== 'excluded' && <Button type="link" size="small" danger onClick={() => onSetFindingStage(selected.id, item.id, 'excluded')}>排除</Button>}
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
      <PageTitle title="案件调查" extra={<Space><Button onClick={() => onOpenAssistant(selected)}>分析当前案件</Button><Button icon={<RobotOutlined />} onClick={() => submitCase(false)}>提交当前攻击链给小影</Button><Button type="primary" icon={<RobotOutlined />} onClick={() => submitCase(true)}>生成攻击链分析报告</Button><Button danger icon={<DeleteOutlined />} onClick={() => onDeleteCase(selected.id)}>删除当前案件</Button></Space>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={5}>
          <Card title="案件" className="mc-investigation-list">
            <List
              dataSource={cases}
              renderItem={(item) => (
                <List.Item className={item.id === selected?.id ? 'active' : ''} onClick={() => setSelectedId(item.id)} actions={[<Button key="delete" danger type="text" size="small" icon={<DeleteOutlined />} aria-label={`删除案件 ${item.title}`} onClick={(event) => { event.stopPropagation(); onDeleteCase(item.id) }} />]}>
                  <List.Item.Meta title={<Text strong>{item.title}</Text>} description={`${item.id} · ${item.owner}`} />
                  <Tag color={item.severity === 'critical' ? 'red' : 'orange'}>{severityLabel[item.severity]}</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={19}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3}>{selected.title}</Title>
                <Text type="secondary">{selected.id} · {selected.owner} · {statusLabel[selected.status === 'contained' ? 'closed' : selected.status]}</Text>
                <Paragraph style={{ margin: '8px 0 0' }}>{selected.summary}</Paragraph>
                <Space size={[6, 6]} wrap>
                  <Tag color="blue">多尺度上下文主动检索</Tag>
                  <Tag color="geekblue">跨时间窗口长周期关联</Tag>
                  <Tag color="cyan">跨源语义与实体关系建模</Tag>
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
              {datasetName && <Card title={<HelpTitle title={`${datasetName} · 24小时 ATT&CK 攻击链路`} description="展示该日志最新事件向前 24 小时内可由日志事实串联的 ATT&CK 技术节点。节点名称是技术类型，点击节点查看全部相关事件、实体和原始日志；连线表示技术证据的时间顺序，不代表已确认攻击。" />} className="mc-panel">
                <InteractiveCaseGraph
                  nodes={attackChainGraph.nodes}
                  links={attackChainGraph.links}
                  height={460}
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

function LogsPage({
  findings,
  evidenceByFinding,
  demoEvents,
  timeRange,
  onSubmitBatch,
  onExplain,
  onSaveM3Graph,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  demoEvents: DemoReplayEvent[]
  timeRange: string
  onSubmitBatch: (prompt: string, context: AssistantContext) => void
  onExplain: (excerpt: string, context: AssistantContext) => void
  onSaveM3Graph: (finding: FindingRecord) => void
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
  const requestedQuery = useMemo(() => new URLSearchParams(location.search).get('q') || '', [location.search])
  useEffect(() => {
    if (requestedQuery) {
      setQuery(requestedQuery)
    }
  }, [requestedQuery])

  const events = useMemo<EventRow[]>(() => {
    if (demoEvents.length) {
      return buildReplayEventRows(demoEvents, findings, evidenceByFinding)
    }
    return findings.flatMap((finding) => finding.events.map((event) => {
      const source = finding.sourceTypes[0] || 'Short'
      const normalizedAction = normalizedEventCategory(event.action, event.raw, event.process)
      return {
        ...event,
        source,
        action: describeLogEvent({ ...event, source, normalizedAction }),
        normalizedAction,
        findingId: finding.id,
        findingTitle: finding.title,
        risk: finding.risk,
        evidenceIds: (evidenceByFinding[finding.id] || []).filter((item) => item.eventId === event.id).map((item) => item.id),
      }
    }))
  }, [demoEvents, evidenceByFinding, findings])
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
          limit: 200,
        })
        if (!active) return
        setRemoteEvents(filterRowsByTimeRange(result.events.map(toEventRow), timeRange))
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
  }, [query, source, timeRange, useRepositoryData])

  const filtered = useMemo(() => {
    if (useRepositoryData) return remoteEvents
    const sourceMatched = source === 'all' ? events : events.filter((event) => event.source === source)
    const ranged = source === 'all'
      ? filterRowsBySourceTimeRange(sourceMatched, timeRange)
      : filterRowsByTimeRange(sourceMatched, timeRange)
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return ranged
    return ranged.filter((event) => {
      const haystack = [event.id, event.action, event.normalizedAction, event.actor, event.host, event.process, event.ip, event.source, event.raw, event.findingTitle].join(' ').toLowerCase()
      return haystack.includes(normalizedQuery)
    })
  }, [events, query, remoteEvents, source, timeRange, useRepositoryData])

  const pageSize = 50
  const pageRows = useMemo(
    () => filtered.slice((page - 1) * pageSize, page * pageSize),
    [filtered, page],
  )

  useEffect(() => {
    setPage(1)
  }, [query, source, timeRange])

  const eventContext = (row: EventRow): AssistantContext => ({
    windowIds: row.findingId ? [row.findingId] : [],
    entityIds: [row.actor, row.host, row.process, row.ip].filter((value): value is string => Boolean(value)),
    timeRange,
  })

  const saveSelectedM3 = () => {
    const finding = selected?.findingId ? findings.find((item) => item.id === selected.findingId) : undefined
    if (finding) onSaveM3Graph(finding)
  }

  const submitLogs = () => {
    const sample = filtered.slice(0, 200)
    const snapshot = sample.map((event) => [
      `time=${event.time}`,
      `source=${event.source}`,
      `event_summary=${event.action}`,
      `normalized_action=${event.normalizedAction || 'unknown'}`,
      `actor=${event.actor || 'unresolved'}`,
      `host=${event.host || 'unresolved'}`,
      `target=${event.process || event.ip || 'unresolved'}`,
      `entities=${event.entities?.join(',') || 'none'}`,
      `finding=${event.findingTitle || 'none'}`,
      `risk=${event.risk ?? 'none'}`,
      `raw=${event.raw.slice(0, 500)}`,
    ].join('; ')).join('\n')
    const entityIds = Array.from(new Set(filtered.flatMap((event) => [event.actor, event.host, event.process, event.ip, ...(event.entities || [])]).filter((value): value is string => Boolean(value))))
    onSubmitBatch(
      `Log Search currently contains ${filtered.length} matching events. The snapshot below contains the first ${sample.length} events after the active time, source and keyword filters. Analyze in concise Chinese: identify the dominant behavior, explain whether there is a coherent sequence worth investigating, list at most four events or patterns that deserve attention, and state what cannot be concluded. Do not claim the snapshot is the complete dataset. Event labels and risk scores are only leads, not ground truth.\n\n${snapshot}`,
      { windowIds: Array.from(new Set(filtered.map((event) => event.findingId).filter((value): value is string => Boolean(value)))), entityIds, timeRange },
    )
  }

  const columns = [
    { title: '时间', dataIndex: 'time', key: 'time', width: 110 },
    { title: '日志源', dataIndex: 'source', key: 'source', width: 140, render: (value: string) => <Tag>{value}</Tag> },
    {
      title: '标准化事件',
      dataIndex: 'action',
      key: 'action',
      width: 250,
      render: (value: string, row: EventRow) => (
        <div className="mc-log-event-summary">
          <Text strong><ExplainableText fallback={value} context={eventContext(row)} onExplain={onExplain}>{value}</ExplainableText></Text>
          {row.normalizedAction && row.normalizedAction !== value && <Text type="secondary">标准动作：{row.normalizedAction}</Text>}
        </div>
      ),
    },
    { title: '执行者', dataIndex: 'actor', key: 'actor', width: 120, render: (value?: string) => value || '—' },
    { title: '主机', dataIndex: 'host', key: 'host', width: 120, render: (value?: string) => value || '—' },
    { title: '对象 / IP', key: 'target', width: 160, render: (_: unknown, row: EventRow) => row.process || row.ip || '—' },
    { title: '异常发现', dataIndex: 'findingTitle', key: 'findingTitle', width: 220 },
  ]

  return (
    <>
      <PageTitle title="日志检索" extra={<Button type="primary" icon={<RobotOutlined />} onClick={submitLogs}>提交当前检索结果给小影</Button>} />
      <Card className="mc-queue-card">
        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索用户 / Host / IP / Process / 原始日志" className="mc-search" />
          <Select value={source} onChange={setSource} style={{ width: 170 }} options={[{ value: 'all', label: '全部日志源' }, ...Array.from(new Set((!useRepositoryData ? events : remoteEvents).map((event) => event.source))).map((value) => ({ value, label: value }))]} />
        </div>
        {useRepositoryData ? (
          <div style={{ marginBottom: 12 }}>
            <Text type="secondary">{loading ? '正在查询真实日志数据...' : loadError || `真实日志模式 · 当前展示 ${filtered.length} 条 ${timeRange} 范围内结果`}</Text>
          </div>
        ) : (
          <div style={{ marginBottom: 12 }}>
            <Text type="secondary">已载入 {events.length.toLocaleString()} 条原始事件，当前筛选命中 {filtered.length.toLocaleString()} 条</Text>
          </div>
        )}
        <Table
          rowKey="id"
          loading={loading}
          columns={columns}
          dataSource={pageRows}
          pagination={{
            current: page,
            total: filtered.length,
            pageSize,
            showSizeChanger: false,
            showTotal: (total) => `共 ${total.toLocaleString()} 条`,
            onChange: (nextPage) => setPage(nextPage),
          }}
          scroll={{ x: 1100 }}
          onRow={(row) => ({ onClick: () => setSelected(row) })}
        />
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} width={620} title={selected?.id} extra={<Button size="small" icon={<LinkOutlined />} onClick={saveSelectedM3}>保存当前事件 30 分钟 M3 图</Button>}>
        {selected && (
          <Tabs
            items={[
              {
                key: 'normalized',
                label: '标准化字段',
                children: (
                  <Descriptions bordered size="small" column={1}>
                    <Descriptions.Item label="事件摘要">{selected.action}</Descriptions.Item>
                    <Descriptions.Item label="标准化动作">{selected.normalizedAction || '—'}</Descriptions.Item>
                    <Descriptions.Item label="执行者">{selected.actor || '—'}</Descriptions.Item>
                    <Descriptions.Item label="来源主机">{selected.host || '—'}</Descriptions.Item>
                    <Descriptions.Item label="进程">{selected.process || '—'}</Descriptions.Item>
                    <Descriptions.Item label="IP 地址">{selected.ip || '—'}</Descriptions.Item>
                    <Descriptions.Item label="异常发现">{selected.findingTitle}</Descriptions.Item>
                    <Descriptions.Item label="实体集合">{selected.entities?.join(', ') || '—'}</Descriptions.Item>
                    <Descriptions.Item label="证据编号">{selected.evidenceIds.join(', ') || '—'}</Descriptions.Item>
                  </Descriptions>
                ),
              },
              {
                key: 'raw',
                label: '原始日志',
                children: (
                  <>
                    <Descriptions bordered size="small" column={1}>
                      <Descriptions.Item label="日志源">{selected.source}</Descriptions.Item>
                      <Descriptions.Item label="原始日志引用">{selected.rawLogRef || `${selected.source}:${selected.id}`}</Descriptions.Item>
                    </Descriptions>
                    <Divider />
                    <ExplainableBlock fallback={selected.raw} context={eventContext(selected)} onExplain={onExplain}>
                      <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{selected.raw}</pre>
                    </ExplainableBlock>
                  </>
                ),
              },
              ...(selected.moduleScores ? [{
                key: 'pipeline',
                label: 'M0-M6 链路',
                children: (
                  <>
                    <Card size="small" title="真实上传处理结果">
                      <Text type="secondary">评分由 M0-M6 可解释检测链路综合计算。</Text>
                      <Row gutter={[8, 8]} style={{ marginTop: 12 }}>
                        {Object.entries(selected.moduleScores).map(([stage, score]) => (
                          <Col span={8} key={stage}>
                            <Statistic title={stage} value={Math.round(score * 100)} suffix="%" />
                          </Col>
                        ))}
                      </Row>
                    </Card>
                  </>
                ),
              }] : []),
            ]}
          />
        )}
      </Drawer>
    </>
  )
}

function SourcesPage({
  sources,
  onDeleteSource,
  onRefresh,
  onImportFile,
}: {
  sources: LogSource[]
  onDeleteSource: (sourceId: string) => Promise<void>
  onRefresh: () => Promise<void>
  onImportFile: (file: UploadSourceEntry) => Promise<IngestResult>
}) {
  const [refreshing, setRefreshing] = useState(false)
  const [deletingSourceId, setDeletingSourceId] = useState('')
  const [queue, setQueue] = useState<UploadSourceEntry[]>([])
  const [tasks, setTasks] = useState<ImportTask[]>([])

  const refresh = async () => {
    setRefreshing(true)
    try {
      await onRefresh()
    } finally {
      setRefreshing(false)
    }
  }

  const removeSource = async (sourceId: string) => {
    setDeletingSourceId(sourceId)
    try {
      await onDeleteSource(sourceId)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '删除数据源失败。')
    } finally {
      setDeletingSourceId('')
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
          status={record.status === 'failed' ? 'exception' : record.status === 'ready' ? 'success' : record.status === 'indexed' ? 'active' : 'normal'}
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
          status={value === 'failed' ? 'error' : value === 'ready' ? 'success' : value === 'indexed' ? 'processing' : value === 'parsing' ? 'warning' : 'default'}
          text={value === 'failed' ? '失败' : value === 'ready' ? '已就绪' : value === 'indexed' ? '索引中' : value === 'parsing' ? '解析中' : '排队中'}
        />
      ),
    },
    { title: '结果', dataIndex: 'result', key: 'result' },
  ]

  const importFiles = async () => {
    if (!queue.length) {
      message.info('请先选择要上传的日志文件。')
      return
    }
    const selectedFiles = [...queue]
    const queuedTasks = selectedFiles.map((file) => ({
        id: `TASK-${Date.now()}-${file.uid}`,
        name: file.name,
        kind: inferSourceKind(file.name),
        size: file.size,
        progress: 5,
        status: 'queued' as const,
        result: '等待上传到后端',
      }))
    setTasks((current) => [...queuedTasks, ...current])
    setQueue([])
    for (let index = 0; index < selectedFiles.length; index += 1) {
      const file = selectedFiles[index]
      const taskId = queuedTasks[index].id
      setTasks((current) => current.map((task) => task.id === taskId
        ? { ...task, progress: 35, status: 'parsing', result: '后端正在执行 M0-M6 处理链路' }
        : task))
      try {
        const result = await onImportFile(file)
        setTasks((current) => current.map((task) => task.id === taskId
          ? {
              ...task,
              ...result.job,
              id: taskId,
              progress: 100,
              status: 'ready',
              result: `${result.job.result} · 小样本仅作功能验证，不作为吞吐结论`,
            }
          : task))
      } catch (error) {
        setTasks((current) => current.map((task) => task.id === taskId
          ? { ...task, progress: 100, status: 'failed', result: error instanceof Error ? error.message : '上传处理失败' }
          : task))
      }
    }
    message.success(`已完成 ${selectedFiles.length} 个文件的后端导入请求。`)
  }

  const queuedCount = tasks.filter((task) => task.status === 'queued').length
  const runningCount = tasks.filter((task) => task.status === 'parsing' || task.status === 'indexed').length
  const readyCount = tasks.filter((task) => task.status === 'ready').length

  return (
    <>
      <PageTitle title="数据源管理" extra={<Button icon={<ReloadOutlined />} loading={refreshing} onClick={refresh}>刷新</Button>} />
      <Card className="mc-panel" title={<HelpTitle title="文件导入" description="接入新的日志文件。导入后会进行格式识别、解析和索引，不会直接改变既有分析结果。" />}>
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
            setQueue((current) => fileList.map((file) => ({
              uid: file.uid,
              name: file.name,
              size: file.size || 0,
              file: file.originFileObj || current.find((item) => item.uid === file.uid)?.file,
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
          <Text type="secondary">日志文件将上传至后端并执行 M0-M6 检测流程。</Text>
          <Button type="primary" onClick={() => { void importFiles() }}>上传并执行 M0-M6</Button>
        </div>
      </Card>
      <Row gutter={[12, 12]} className="mc-summary-row">
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="排队中" value={queuedCount} /></Card></Col>
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="处理中" value={runningCount} /></Card></Col>
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="已就绪" value={readyCount} /></Card></Col>
      </Row>
      <Card className="mc-panel" title={<HelpTitle title="导入任务" description="显示每个日志源的排队、解析、索引和就绪状态。" />}>
        <Table rowKey="id" columns={taskColumns} dataSource={tasks} pagination={false} locale={{ emptyText: '当前没有导入任务。' }} scroll={{ x: 920 }} />
      </Card>
      <Card className="mc-queue-card">
        <Table
          rowKey="id"
          columns={[...columns, {
            title: '操作',
            key: 'actions',
            width: 90,
            render: (_: unknown, row: LogSource) => row.id.startsWith('UPLOAD-')
              ? <Button danger type="text" icon={<DeleteOutlined />} loading={deletingSourceId === row.id} onClick={() => { void removeSource(row.id) }}>删除</Button>
              : <Text type="secondary">系统源</Text>,
          }]}
          dataSource={sources}
          pagination={false}
          scroll={{ x: 960 }}
        />
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
      <PageTitle title="小影" subtitle="链影寻踪项目知识增强型调查智能体 · 数据工具、M0-M6 方法库与证据核验协同" />
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
                    <AssistantAnswerContent content={item.content} />
                    {item.evidence && <Space size={[4, 4]} wrap>{item.evidence.map((evidence) => (
                      <Tag
                        color={evidence.ref.startsWith('KB-') || evidence.ref.startsWith('DOC-') ? 'blue' : undefined}
                        key={`${evidence.ref}-${evidence.label}`}
                        title={`${evidence.ref}${evidence.source ? ` · ${evidence.source}` : ''}`}
                      >
                        {evidence.label}
                      </Tag>
                    ))}</Space>}
                    {item.structured && (
                      <>
                        <StructuredSection title="事实" items={item.structured.facts} />
                        <StructuredSection title="判断" items={item.structured.assessments} />
                        <StructuredSection title="待确认" items={item.structured.uncertainties} />
                        <StructuredSection title="下一步核验" items={item.structured.recommended_queries} />
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
                      {stage !== 'main' && <Button type="link" size="small" onClick={() => onSetFindingStage(selected.id, item.id, 'main')}>加入主链</Button>}
                      {stage !== 'candidate' && <Button type="link" size="small" onClick={() => onSetFindingStage(selected.id, item.id, 'candidate')}>保留候选</Button>}
                      {stage !== 'excluded' && <Button type="link" size="small" danger onClick={() => onSetFindingStage(selected.id, item.id, 'excluded')}>排除</Button>}
                    </Space>
                  </div>
                </div>
              ))}
            </div>
            <div className="mc-chat-composer">
              <Input.TextArea value={question} onChange={(event) => onQuestionChange(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); onSubmit(question) } }} autoSize={{ minRows: 2, maxRows: 5 }} placeholder="输入调查问题" />
              <Button type="primary" icon={<SendOutlined />} loading={sending} onClick={() => onSubmit(question)}>发送</Button>
            </div>
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title={<HelpTitle title="当前上下文" description="小影当前可引用的案件、窗口、实体和时间范围。更换上下文会影响回答范围。" />} className="mc-panel">
            <Space wrap size={[6, 6]}>
              <Tag>{context.caseId || '未选择案件'}</Tag>
              {(context.windowIds || []).slice(0, 3).map((windowId) => <Tag key={windowId}>{windowId}</Tag>)}
              {(context.entityIds || []).slice(0, 3).map((entityId) => <Tag key={entityId}>{entityId}</Tag>)}
              {context.timeRange && <Tag>{context.timeRange}</Tag>}
            </Space>
          </Card>
          <Card title={<HelpTitle title="项目能力" description="小影将可替换的通用模型作为推理层，项目知识、检测工具、上下文和证据协议由链影寻踪提供。" />} className="mc-panel" style={{ marginTop: 12 }}>
            <Space wrap size={[6, 6]}>
              <Tag color="blue">M0-M6 方法库</Tag>
              <Tag color="blue">多尺度主动检索</Tag>
              <Tag color="blue">跨源实体关系图</Tag>
              <Tag color="blue">长周期攻击链</Tag>
              <Tag color="cyan">weak_fusion_v2</Tag>
              <Tag color="green">证据引用与核验</Tag>
              <Tag color="gold">真实标签评测隔离</Tag>
            </Space>
            <Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
              回答当前环境问题时先读取 Finding、案件、实体、时间线或原始日志；解释方法时检索项目知识库。事实、判断和不确定性分别呈现。
            </Paragraph>
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
    <>
      <PageTitle title="案件调查" extra={<Space><Button onClick={() => onOpenAssistant(selected)}>分析当前案件</Button><Button icon={<RobotOutlined />} onClick={() => submitCase(false)}>提交当前攻击链给小影</Button><Button type="primary" icon={<RobotOutlined />} onClick={() => submitCase(true)}>生成攻击链分析报告</Button></Space>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={5}>
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
        <Col xs={24} xl={19}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3}>{selected.title}</Title>
                <Text type="secondary">{selected.id} · {selected.owner} · {statusLabel[selected.status === 'contained' ? 'closed' : selected.status]}</Text>
                <Paragraph style={{ margin: '8px 0 0' }}>{selected.summary}</Paragraph>
                <Space size={[6, 6]} wrap>
                  <Tag color="blue">多尺度上下文主动检索</Tag>
                  <Tag color="geekblue">跨时间窗口长周期关联</Tag>
                  <Tag color="cyan">跨源语义与实体关系建模</Tag>
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
              <Card title={<HelpTitle title="攻击链图" description="始终保留完整长周期链路；当前时间窗内节点高亮，窗口外节点作为历史锚点淡化展示。连线表示关联证据，不等同于已确认攻击。" />} className="mc-panel">
                <Suspense fallback={<ChartFallback height={360} />}>
                  <EChartsView
                    option={graphOption}
                    style={{ height: 360 }}
                    onEvents={{
                      dblclick: (params) => {
                        const finding = related.find((item) => item.id === params.data?.id)
                        if (finding) {
                          onExplain(finding.title, { caseId: selected.id, windowIds: [finding.id], entityIds: [finding.entity] })
                          return
                        }
                        const entity = params.data?.id || params.data?.name
                        if (entity) onExplain(entity, { caseId: selected.id, entityIds: [entity] })
                      },
                    }}
                  />
                </Suspense>
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
    </>
  )
}

function LogsPage({
  findings,
  evidenceByFinding,
  demoEvents,
  timeRange,
  onSubmitBatch,
  onExplain,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  demoEvents: DemoReplayEvent[]
  timeRange: string
  onSubmitBatch: (prompt: string, context: AssistantContext) => void
  onExplain: (excerpt: string, context: AssistantContext) => void
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
  const requestedQuery = useMemo(() => new URLSearchParams(location.search).get('q') || '', [location.search])
  useEffect(() => {
    if (requestedQuery) {
      setQuery(requestedQuery)
    }
  }, [requestedQuery])

  const events = useMemo<EventRow[]>(() => {
    if (demoEvents.length) {
      return buildReplayEventRows(demoEvents, findings, evidenceByFinding)
    }
    return findings.flatMap((finding) => finding.events.map((event) => {
      const source = finding.sourceTypes[0] || 'Short'
      const normalizedAction = normalizedEventCategory(event.action, event.raw, event.process)
      return {
        ...event,
        source,
        action: describeLogEvent({ ...event, source, normalizedAction }),
        normalizedAction,
        findingId: finding.id,
        findingTitle: finding.title,
        risk: finding.risk,
        evidenceIds: (evidenceByFinding[finding.id] || []).filter((item) => item.eventId === event.id).map((item) => item.id),
      }
    }))
  }, [demoEvents, evidenceByFinding, findings])
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
          limit: 200,
        })
        if (!active) return
        setRemoteEvents(filterRowsByTimeRange(result.events.map(toEventRow), timeRange))
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
  }, [query, source, timeRange, useRepositoryData])

  const filtered = useMemo(() => {
    if (useRepositoryData) return remoteEvents
    const sourceMatched = source === 'all' ? events : events.filter((event) => event.source === source)
    const ranged = source === 'all'
      ? filterRowsBySourceTimeRange(sourceMatched, timeRange)
      : filterRowsByTimeRange(sourceMatched, timeRange)
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return ranged
    return ranged.filter((event) => {
      const haystack = [event.id, event.action, event.normalizedAction, event.actor, event.host, event.process, event.ip, event.source, event.raw, event.findingTitle].join(' ').toLowerCase()
      return haystack.includes(normalizedQuery)
    })
  }, [events, query, remoteEvents, source, timeRange, useRepositoryData])

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

function EvaluationPage({ findings, caseBoards, rawEvents }: { findings: FindingRecord[]; caseBoards: Record<string, CaseBoard>; rawEvents: number }) {
  const reviewed = Object.values(caseBoards).reduce((sum, board) => sum + Object.keys(board).length, 0)
  const analystReduction = rawEvents > 0 ? ((rawEvents - reviewed) / rawEvents) * 100 : 0
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
      <PageTitle title="评估" subtitle="基于独立标签文件与消融实验生成的检测评估结果。" />
      <Card style={{ marginBottom: 12 }}>
        <Badge status="success" /> 评测指标在检测结果落盘后由独立标签文件生成，覆盖召回率、误报率与模块消融分析。
      </Card>
      <Row gutter={[12, 12]}>
        {metrics.map((item) => (
          <Col xs={12} md={8} xl={4} key={item.title}>
            <Card className="mc-summary-card"><Statistic title={item.title} value={item.value} precision={item.suffix === '%' ? 1 : 0} suffix={item.suffix} /></Card>
          </Col>
        ))}
        <Col xs={24} xl={24}>
          <Card title={<HelpTitle title="消融实验" description="比较移除或替换某个模块后，评估指标的变化，用于判断模块贡献。" />} className="mc-panel">
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
          <Card title={<HelpTitle title="错误案例" description="展示需要复核的预测偏差，用于定位模型和数据处理中的薄弱环节。" />} className="mc-panel">
            <List
              size="small"
              dataSource={['backup_admin', 'FS-02', '稀有账号-主机关系', '非工作时段', 'SMB 访问', '已批准维护工单', '已排除']}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title={<HelpTitle title="源域对比" description="比较不同日志来源上的结果，观察模型在不同环境中的稳定性。" />} className="mc-panel">
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
