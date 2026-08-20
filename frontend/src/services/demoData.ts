import type { AnomalyWindow, Investigation, LogSource, SecurityEvent, Severity } from '../mocks/data'
import { APT_RECON_CASE_ID, APT_RECON_EVENT_IDS } from './aptDemoBaseline'

export type DemoDatasetId = 'Short' | 'Long' | 'APT'

type DemoTimelineEvent = {
  event_id: string
  timestamp: string
  source_timestamp?: string
  source_file: string
  raw: string
  system_projection?: { threat_level?: string; final_score?: number; reasons?: string[] }
  related_entities?: Array<{ entity_type: string; canonical_value: string; role?: string; confidence?: number }>
}

type DemoDetection = {
  event_id: string
  threat_level?: string
  alert_level?: string
  final_score?: number
  reasons?: string[]
}

type DemoChain = {
  chain_id: string
  status: 'candidate' | 'confirmed' | 'dismissed'
  steps?: Array<{ sequence: number; label: string; evidence_event_ids: string[] }>
}

const MINUTE = 60 * 1000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const REPLAY_END = Date.UTC(2026, 7, 9, 20, 30, 0)

type ReplayBand = {
  cumulativeShare: number
  centers: number[]
  spreads: number[]
}

// The replay is deliberately bursty: sparse quiet periods separate several
// operational peaks. This produces stable, reproducible 1h/24h/7d/30d views
// without changing event payloads, identifiers, or detection labels.
// 每个数据集的分布不同：Short 全部压缩在最近约 50 分钟内（短程）、Long 铺展 7 天（长程），对比鲜明。
const REPLAY_BANDS: Record<DemoDatasetId, ReplayBand[]> = {
  Short: [
    { cumulativeShare: 0.45, centers: [3 * MINUTE, 9 * MINUTE, 20 * MINUTE], spreads: [1 * MINUTE, 2 * MINUTE, 4 * MINUTE] },
    { cumulativeShare: 1, centers: [30 * MINUTE, 45 * MINUTE], spreads: [5 * MINUTE, 8 * MINUTE] },
  ],
  Long: [
    { cumulativeShare: 0.35, centers: [2 * HOUR, 8 * HOUR, 16 * HOUR], spreads: [30 * MINUTE, 70 * MINUTE, 110 * MINUTE] },
    { cumulativeShare: 0.75, centers: [1.6 * DAY, 3.2 * DAY, 5.2 * DAY], spreads: [0.25 * DAY, 0.5 * DAY, 0.8 * DAY] },
    { cumulativeShare: 1, centers: [6.4 * DAY, 6.9 * DAY], spreads: [0.2 * DAY, 0.15 * DAY] },
  ],
  // APT 叙事集：铺满 7 天，早期（侦察/WebShell/提权）分散、末期（C2/渗出）密集，
  // 让「跨源、跨主机、跨 7 天」的长周期攻击链叙事在时间轴上自然呈现。
  APT: [
    { cumulativeShare: 0.3, centers: [1 * HOUR, 6 * HOUR, 14 * HOUR], spreads: [25 * MINUTE, 60 * MINUTE, 100 * MINUTE] },
    { cumulativeShare: 0.65, centers: [1.5 * DAY, 3.0 * DAY, 4.5 * DAY], spreads: [0.2 * DAY, 0.4 * DAY, 0.6 * DAY] },
    { cumulativeShare: 1, centers: [6.0 * DAY, 6.8 * DAY], spreads: [0.25 * DAY, 0.1 * DAY] },
  ],
}

// 基准链证据年龄（越早越旧）：Short 短程约 30 分钟完成 4 步、Long 长程跨约 7 天完成 10 步。
const CHAIN_STAGE_AGES: Record<DemoDatasetId, number[]> = {
  Short: [28 * MINUTE, 20 * MINUTE, 12 * MINUTE, 4 * MINUTE],
  Long: [6.9 * DAY, 6.1 * DAY, 5.3 * DAY, 4.5 * DAY, 3.7 * DAY, 2.9 * DAY, 2.1 * DAY, 1.3 * DAY, 16 * HOUR, 40 * MINUTE],
  // APT 10 步：侦察(6.9d) → WebShell/执行(6d) → 账户/提权(5.1d) → 爆破/横向(4.1d)
  // → PowerShell(3.1d) → DNS 隧道(1.1d) → 数据渗出(40m)。
  APT: [6.9 * DAY, 6.0 * DAY, 6.0 * DAY, 5.1 * DAY, 5.1 * DAY, 4.1 * DAY, 4.1 * DAY, 3.1 * DAY, 1.1 * DAY, 40 * MINUTE],
}

function stableUnit(value: string) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0) / 4294967296
}

function projectedAge(eventId: string, dataset: DemoDatasetId) {
  const bands = REPLAY_BANDS[dataset] || REPLAY_BANDS.Long
  const selector = stableUnit(`${dataset}:${eventId}:band`)
  const band = bands.find((candidate) => selector < candidate.cumulativeShare) || bands[bands.length - 1]
  const centerIndex = Math.min(
    band.centers.length - 1,
    Math.floor(stableUnit(`${eventId}:${dataset}:cluster`) * band.centers.length),
  )
  const jitter = (stableUnit(`${dataset}:${eventId}:jitter`) - 0.5) * 2 * band.spreads[centerIndex]
  return Math.max(30 * 1000, Math.min(29.7 * DAY, band.centers[centerIndex] + jitter))
}

function projectReplayTimeline(timeline: DemoTimelineEvent[], chain: DemoChain, dataset: DemoDatasetId) {
  const stageByEventId = new Map<string, number>()
  ;(chain.steps || []).forEach((step, index) => {
    step.evidence_event_ids.forEach((eventId) => stageByEventId.set(eventId, index))
  })

  return timeline.map((item) => {
    const stage = stageByEventId.get(item.event_id)
    const sourceJitter = (stableUnit(`${dataset}:${item.event_id}:chain`) - 0.5) * 12 * MINUTE
    const stageAges = CHAIN_STAGE_AGES[dataset] || CHAIN_STAGE_AGES.Long
    const age = stage == null
      ? projectedAge(item.event_id, dataset)
      : Math.max(MINUTE, stageAges[Math.min(stage, stageAges.length - 1)] + sourceJitter)
    return {
      ...item,
      source_timestamp: item.timestamp,
      timestamp: new Date(REPLAY_END - age).toISOString(),
    }
  }).sort((left, right) => left.timestamp.localeCompare(right.timestamp))
}

const CROSS_SOURCE_STAGE_TITLES = [
  '历史基线偏离的初始异常',
  '相邻事件短程语义印证',
  '跨日同实体再次出现',
  '跨窗口关系链延伸',
  '近期异常上下文回溯',
  '当前事件触发长周期链路召回',
]

export function buildCrossSourceReplay(inputs: Array<{
  dataset: DemoDatasetId
  anomalyWindows: AnomalyWindow[]
  investigations: Investigation[]
}>) {
  const sourceChains = inputs.map((input) => ({
    ...input,
    windowIds: input.investigations[0]?.windowIds || [],
  }))
  const stageCount = Math.max(0, ...sourceChains.map((item) => item.windowIds.length))
  const anomalyWindows: AnomalyWindow[] = []

  for (let stage = 0; stage < stageCount; stage += 1) {
    const sourceWindows = sourceChains.flatMap((input) => {
      const windowId = input.windowIds[stage]
      const anchor = input.anomalyWindows.find((item) => item.id === windowId)
      if (!anchor) return []
      const anchorTime = Date.parse(anchor.start)
      return [...input.anomalyWindows]
        .sort((left, right) => Math.abs(Date.parse(left.start) - anchorTime) - Math.abs(Date.parse(right.start) - anchorTime))
        .slice(0, 4)
    })
    if (sourceWindows.length < 2) continue

    const events = sourceWindows.flatMap((item) => item.events).sort((left, right) => left.time.localeCompare(right.time))
    const entities = Array.from(new Set(sourceWindows.flatMap((item) => item.entities)))
    const hosts = Array.from(new Set(sourceWindows.flatMap((item) => item.hosts)))
    const timestamps = events.map((event) => event.time).sort()
    const title = CROSS_SOURCE_STAGE_TITLES[stage] || `跨源关联阶段 ${stage + 1}`
    anomalyWindows.push({
      id: `WIN-XLOG-${String(stage + 1).padStart(2, '0')}`,
      title,
      severity: stage >= stageCount - 2 ? 'critical' : 'high',
      score: Math.min(0.97, 0.78 + stage * 0.032),
      start: timestamps[0],
      end: timestamps[timestamps.length - 1],
      status: stage === stageCount - 1 ? 'new' : 'investigating',
      eventCount: events.length,
      entities,
      hosts,
      sourceTypes: sourceChains.map((item) => item.dataset),
      summary: `汇聚 ${events.length} 条跨源上下文事件。M1 将异构字段统一为“${title}”安全语义；M2 以共享用户、主机、进程实体联合建模；M3/M5 从当前事件主动检索多尺度上下文，并关联跨时间窗口证据。`,
      events,
    })
  }

  const investigation: Investigation = {
    id: 'CASE-XLOG-30D-001',
    title: '跨源长周期攻击链 · 30天多尺度关联',
    severity: 'critical',
    status: 'investigating',
    windowIds: anomalyWindows.map((item) => item.id),
    owner: 'threat-hunting-team',
    createdAt: anomalyWindows[0]?.start || new Date(REPLAY_END - 30 * DAY).toISOString(),
    summary: '以当前高风险事件为锚点，主动检索 1h/24h/7d/30d 上下文，通过统一事件语义与实体关系图恢复跨源、跨窗口的长周期攻击链。',
  }

  return { anomalyWindows, investigation }
}

const severity = (value?: string): Severity => {
  if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low' || value === 'info') return value
  return 'info'
}

const sourceName = (path: string) => path.split('/').pop() || path

// 日志文件类型分类：用于总览页跨域来源分布（原始事件口径）。
function logKindForEvent(event: { source_file?: string; raw?: string }) {
  const value = (event.source_file || '').toLowerCase()
  if (value.includes('.evtx')) return 'Windows 事件 EVTX'
  if (value.includes('network.log')) return '网络遥测 network'
  if (value.includes('dnsteal')) return 'DNS 隧道/外泄'
  if (value.includes('auth.log')) return '认证日志 auth'
  if (value.includes('syslog')) return '系统日志 syslog'
  if (value.includes('audit.log')) return '审计日志 audit'
  if (value.includes('eve.') || value.includes('suricata')) return '入侵检测 suricata'
  if (value.includes('access') || value.includes('nginx') || value.includes('apache')) return 'Web 访问'
  return '其他'
}

function eventAction(raw: string) {
  const message = raw.split(': ').slice(1).join(': ').trim()
  // Keep the event summary useful in tables. The original raw event remains
  // unchanged in `raw` and is shown in the expandable detail view.
  return message ? message.slice(0, 160) : raw.slice(0, 160)
}

function normalizeAssetPath(value: string) {
  const trimmed = value.replace(/[)'",.:]+$/g, '')
  if (/\/\.ansible\/tmp\//i.test(trimmed)) {
    const home = trimmed.match(/^\/home\/[^/]+/)?.[0] || '/home/user'
    return `${home}/.ansible/tmp/*`
  }
  if (/^\/var\/tmp\/ansible-tmp-/i.test(trimmed)) return '/var/tmp/ansible-tmp-*/AnsiballZ_*'
  if (/\/wp-content\/uploads\/\d{4}\/\d{2}/i.test(trimmed)) {
    return trimmed.replace(/(\/wp-content\/uploads)\/.*$/i, '$1/*')
  }
  return trimmed.length <= 96 ? trimmed : `${trimmed.slice(0, 92)}…`
}

function rawEventFields(raw: string) {
  const syslog = raw.match(/^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+([^\s:\[]+)/)
  const ipv4 = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0]
  const actor = raw.match(/\bUSER=([a-z_][\w.-]*)/i)?.[1]
    || raw.match(/\bsudo:\s*([a-z_][\w.-]*)\s*:/i)?.[1]
    || raw.match(/\b(?:for user|session (?:opened|closed) for user|new user:\s*name=)\s*['"]?([a-z_][\w.-]*)/i)?.[1]
  return { actor, host: syslog?.[1], process: syslog?.[2], ip: ipv4 }
}

function rawContextEntities(raw: string) {
  const paths = raw.match(/(?:\/[A-Za-z0-9._-]+){2,}/g) || []
  return Array.from(new Set(paths.map(normalizeAssetPath))).slice(0, 4)
}

function eventFields(event: DemoTimelineEvent) {
  const values = event.related_entities || []
  const inferred = rawEventFields(event.raw)
  return {
    actor: values.find((item) => item.role === 'actor')?.canonical_value
      || values.find((item) => item.entity_type === 'user')?.canonical_value
      || inferred.actor,
    host: values.find((item) => item.entity_type === 'host')?.canonical_value || inferred.host,
    process: values.find((item) => item.entity_type === 'process')?.canonical_value || inferred.process,
    ip: values.find((item) => item.entity_type === 'ip')?.canonical_value || inferred.ip,
  }
}

type WindowCorrelation = {
  window: AnomalyWindow
  score: number
  sharedEntities: string[]
  timeGapMs: number
}

// 每个数据集最多生成 2 条待人工研判候选链：减少数量、聚焦高质量线索。
const AUTO_CASE_LIMIT = 2
// 人工候选链证据上限随数据集语义变化：Short 短程 4 步、Long 长程 8 步，使长程链明显更长。
const AUTO_CASE_EVIDENCE_LIMIT: Record<DemoDatasetId, number> = { Short: 4, Long: 8, APT: 10 }
// 自动处置链聚合约束：只在 24 小时时间窗内聚类，防止高频共享实体把整个数据集串成一条巨型链。
const AUTO_RESOLVE_CHAIN_LIMIT = 20
const AUTO_RESOLVE_CHAIN_MIN_MEMBERS: Record<DemoDatasetId, number> = { Short: 4, Long: 7, APT: 7 }
const AUTO_RESOLVE_CHAIN_MAX_MEMBERS: Record<DemoDatasetId, number> = { Short: 6, Long: 12, APT: 10 }
const AUTO_RESOLVE_TIME_GAP = 24 * HOUR

function windowActionFamily(window: AnomalyWindow) {
  const text = window.events.map((event) => `${event.action || ''} ${event.raw || ''}`).join(' ').toLowerCase()
  if (/useradd|new user|new group|add .*group|account creat|shadow group/.test(text)) return 'account'
  if (/failed password|authentication failure|login failed|session opened|accepted password|sshd|pam_unix/.test(text)) return 'authentication'
  if (/sudo|user=root|privilege|setuid|elevat/.test(text)) return 'privilege'
  if (/command=|exec|process|powershell|cmd\.exe|bash|rundll32|certutil/.test(text)) return 'execution'
  if (/dns|connect|outbound|network|http|tls|firewall/.test(text)) return 'network'
  if (/file|\/etc\/|\/var\/|\/home\/|read|write|open/.test(text)) return 'file'
  if (/systemd|kernel|service|metricbeat|auditd/.test(text)) return 'system'
  return 'other'
}

function actionCompatibility(left: AnomalyWindow, right: AnomalyWindow) {
  const first = windowActionFamily(left)
  const second = windowActionFamily(right)
  if (first === second) return first === 'other' ? 0.35 : 0.78
  const compatible = new Set([
    'account:authentication', 'account:privilege', 'authentication:execution',
    'authentication:privilege', 'execution:privilege', 'execution:file',
    'execution:network', 'file:network', 'privilege:file', 'privilege:execution',
  ])
  if (compatible.has(`${first}:${second}`) || compatible.has(`${second}:${first}`)) return 1
  return first === 'other' || second === 'other' ? 0.22 : 0.48
}

function timeEvidence(gapMs: number) {
  if (gapMs <= HOUR) return 1
  if (gapMs <= DAY) return 0.82
  if (gapMs <= 7 * DAY) return 0.61
  if (gapMs <= 30 * DAY) return 0.36
  return 0
}

function entityFrequencies(windows: AnomalyWindow[]) {
  const frequencies = new Map<string, number>()
  windows.forEach((window) => new Set(window.entities).forEach((entity) => frequencies.set(entity, (frequencies.get(entity) || 0) + 1)))
  return frequencies
}

function correlateWindows(
  current: AnomalyWindow,
  candidate: AnomalyWindow,
  frequencies: Map<string, number>,
  population: number,
): WindowCorrelation {
  const candidateEntities = new Set(candidate.entities)
  const sharedEntities = current.entities.filter((entity) => candidateEntities.has(entity))
  const timeGapMs = Math.abs(Date.parse(current.start) - Date.parse(candidate.start))
  if (!sharedEntities.length || !Number.isFinite(timeGapMs) || timeGapMs > 30 * DAY) {
    return { window: candidate, score: 0, sharedEntities, timeGapMs }
  }
  const rarity = Math.max(...sharedEntities.map((entity) => {
    const frequency = frequencies.get(entity) || population
    return Math.log((population + 1) / (frequency + 1)) / Math.log(population + 1)
  }))
  // A ubiquitous host remains weak evidence; a rare user/process/path can make
  // the same temporal relation much stronger. This prevents giant host-only cases.
  const entityEvidence = 0.08 + rarity * 0.92
  const riskEvidence = Math.min(1, (current.score + candidate.score) / 2)
  const crossSource = current.sourceTypes.some((source) => !candidate.sourceTypes.includes(source)) ? 1 : 0.15
  const score = entityEvidence * 0.46
    + timeEvidence(timeGapMs) * 0.22
    + actionCompatibility(current, candidate) * 0.14
    + riskEvidence * 0.12
    + crossSource * 0.06
  return { window: candidate, score, sharedEntities, timeGapMs }
}

const ACTION_FAMILY_LABELS: Record<string, string> = {
  account: '账户权限变更',
  authentication: '异常认证',
  privilege: '权限提升',
  execution: '命令执行',
  network: '网络外联',
  file: '文件访问',
  system: '系统服务异常',
  other: '多阶段异常行为',
}

function actionFamilyLabel(family: string) {
  return ACTION_FAMILY_LABELS[family] || ACTION_FAMILY_LABELS.other
}

function readableDuration(start: string, end: string) {
  const ms = Date.parse(end) - Date.parse(start)
  if (!Number.isFinite(ms) || ms < 0) return '未知时长'
  if (ms < MINUTE) return '1 分钟内'
  if (ms < HOUR) return `${Math.max(1, Math.round(ms / MINUTE))} 分钟`
  if (ms < DAY) return `${(ms / HOUR).toFixed(1)} 小时`
  return `${(ms / DAY).toFixed(1)} 天`
}

function anchorRoleLabel(anchor: string) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(anchor)) return `IP ${anchor}`
  if (anchor.startsWith('/')) return `文件 ${anchor}`
  if (/server|host|workstation|desktop/i.test(anchor)) return `主机 ${anchor}`
  return `账号 ${anchor}`
}

function caseBehaviorLabel(windows: AnomalyWindow[]) {
  const counts = new Map<string, number>()
  windows.forEach((window) => {
    const family = windowActionFamily(window)
    counts.set(family, (counts.get(family) || 0) + 1)
  })
  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 2)
    .map(([family]) => actionFamilyLabel(family))
    .join('与') || actionFamilyLabel('other')
}

function strongestCaseAnchor(windows: AnomalyWindow[], frequencies: Map<string, number>) {
  const local = new Map<string, number>()
  windows.forEach((window) => new Set(window.entities).forEach((entity) => local.set(entity, (local.get(entity) || 0) + 1)))
  const explicitEntities = new Set(windows.flatMap((window) => window.events.flatMap((event) => [event.actor, event.host, event.process, event.ip].filter((value): value is string => Boolean(value)))))
  const candidates = Array.from(local.entries())
    .filter(([entity, count]) => count >= 2 && entity.length <= 36)
  const preferred = candidates.filter(([entity]) => explicitEntities.has(entity) && !entity.startsWith('/'))
  return (preferred.length ? preferred : candidates.filter(([entity]) => !entity.startsWith('/')))
    .sort((left, right) => {
      const globalDifference = (frequencies.get(left[0]) || Number.MAX_SAFE_INTEGER) - (frequencies.get(right[0]) || Number.MAX_SAFE_INTEGER)
      return globalDifference || right[1] - left[1] || left[0].localeCompare(right[0])
    })[0]?.[0]
}

function compactCaseTime(value: string) {
  const timestamp = new Date(value)
  if (!Number.isFinite(timestamp.getTime())) return value.slice(0, 10)
  return timestamp.toISOString().slice(5, 16).replace('T', ' ')
}

function highestSeverity(windows: AnomalyWindow[]): Severity {
  const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
  return [...windows].sort((left, right) => rank[right.severity] - rank[left.severity])[0]?.severity || 'medium'
}

function automaticEscalation(windows: AnomalyWindow[], strongestLinkScore: number, evidenceLimit: number) {
  const maxRisk = Math.max(...windows.map((window) => window.score), 0)
  const familyCount = new Set(windows.map(windowActionFamily)).size
  const sourceCount = new Set(windows.flatMap((window) => window.sourceTypes)).size
  const evidenceVolume = Math.min(1, windows.length / evidenceLimit)
  const score = maxRisk * 0.34
    + strongestLinkScore * 0.32
    + Math.min(1, familyCount / 3) * 0.14
    + Math.min(1, sourceCount / 2) * 0.10
    + evidenceVolume * 0.10
  const reasons = [
    `最高事件风险 ${(maxRisk * 100).toFixed(0)}%`,
    `最强关联置信 ${(strongestLinkScore * 100).toFixed(0)}%`,
    `${familyCount} 类行为阶段`,
    `${sourceCount} 个日志源`,
  ]
  const highImpact = windows.some((window) => window.severity === 'critical' || window.severity === 'high')
  return {
    score,
    reasons,
    shouldEscalate: score >= 0.76 && highImpact && (familyCount >= 2 || sourceCount >= 2),
  }
}

// 将完整聚类链截断成“待人工补全”的骨架链，返回保留段与缺失段（真证据）。
// variant 奇数=首 2 尾 1（中间整体缺失）、偶数=多段缺口（隔段缺失），避免所有案件同一种缺口形态。
function truncateChainForReview(members: AnomalyWindow[], variant: number) {
  const last = members.length - 1
  if (members.length <= 3) {
    return { kept: [members[0], members[last]], gaps: members.slice(1, last) }
  }
  if (variant % 2 === 1) {
    return { kept: [members[0], members[1], members[last]], gaps: members.slice(2, last) }
  }
  const kept: AnomalyWindow[] = []
  const gaps: AnomalyWindow[] = []
  members.forEach((window, i) => {
    if (i === 0 || i === last || (i > 0 && i < last && i % 2 === 0)) kept.push(window)
    else gaps.push(window)
  })
  return { kept, gaps }
}

// 从候选池中挑选与案件共享实体、但不在链内的窗口作为干扰项，增加人工补全的研判难度。
function selectDistractorIds(members: AnomalyWindow[], windows: AnomalyWindow[], reserved: Set<string>, count: number) {
  const memberIds = new Set(members.map((window) => window.id))
  const memberEntities = new Set(members.flatMap((window) => window.entities))
  return windows
    .filter((window) => !memberIds.has(window.id) && !reserved.has(window.id))
    .filter((window) => window.entities.some((entity) => memberEntities.has(entity)))
    .sort((left, right) => right.score - left.score)
    .slice(0, count)
    .map((window) => window.id)
}

function buildAutomaticInvestigations(
  dataset: DemoDatasetId,
  windows: AnomalyWindow[],
  reservedWindowIds: Set<string>,
): Investigation[] {
  const frequencies = entityFrequencies(windows)
  const assigned = new Set(reservedWindowIds)
  const seeds = [...windows]
    .filter((window) => !assigned.has(window.id))
    .sort((left, right) => right.score - left.score || Date.parse(right.start) - Date.parse(left.start) || left.id.localeCompare(right.id))
  const investigations: Investigation[] = []

  for (const seed of seeds) {
    if (investigations.length >= AUTO_CASE_LIMIT) break
    if (assigned.has(seed.id)) continue
    const related = windows
      .filter((window) => window.id !== seed.id && !assigned.has(window.id))
      .map((window) => correlateWindows(seed, window, frequencies, windows.length))
      .filter((item) => item.score >= 0.48)
      .sort((left, right) => right.score - left.score || left.timeGapMs - right.timeGapMs || left.window.id.localeCompare(right.window.id))
      .slice(0, AUTO_CASE_EVIDENCE_LIMIT[dataset] - 1)
    if (!related.length) continue

    const members = [seed, ...related.map((item) => item.window)]
      .sort((left, right) => Date.parse(left.start) - Date.parse(right.start))
    const anchor = strongestCaseAnchor(members, frequencies)
    const strongestLink = related[0]
    const uniqueFamilies = new Set(members.map(windowActionFamily)).size
    // Host-only pairs must either form a tight burst or span compatible behavior
    // families; otherwise they remain in the Finding pool for later retrieval.
    if (!anchor && strongestLink.timeGapMs > HOUR && uniqueFamilies < 2) continue

    members.forEach((window) => assigned.add(window.id))
    const index = investigations.length + 1
    const firstTime = members[0]?.start || seed.start
    const lastTime = members[members.length - 1]?.start || seed.start
    const escalation = automaticEscalation(members, strongestLink.score, AUTO_CASE_EVIDENCE_LIMIT[dataset])
    const span = readableDuration(firstTime, lastTime)
    // 截断成骨架链：保留首尾/关键段，中间证据从 windowIds 移除，作为待补全的缺口。
    const { kept, gaps } = truncateChainForReview(members, index)
    const distractorIds = selectDistractorIds(members, windows, assigned, 2)
    investigations.push({
      id: `${dataset.toUpperCase()}-AUTO-${String(index).padStart(3, '0')}`,
      title: `${caseBehaviorLabel(members)}链${anchor ? ` · ${anchorRoleLabel(anchor)}` : ''} · ${compactCaseTime(firstTime)}`,
      severity: highestSeverity(members),
      status: 'investigating',
      queueStatus: 'manual_review',
      escalationScore: Math.round(escalation.score * 100),
      escalationReasons: escalation.reasons,
      decisionSource: 'system',
      windowIds: kept.map((window) => window.id),
      gapEvidenceIds: gaps.map((window) => window.id),
      gapDistractorIds: distractorIds,
      owner: 'M5 自动关联',
      createdAt: firstTime,
      summary: anchor
        ? `围绕${anchorRoleLabel(anchor)}的候选攻击链，当前已确认 ${kept.length} 个关键窗口，中间缺失 ${gaps.length} 个证据环节，时间跨度 ${span}。请从候选证据中补全缺口，再核验该实体的授权来源与攻击意图。`
        : `候选攻击链当前已确认 ${kept.length} 个关键窗口，中间缺失 ${gaps.length} 个证据环节，时间跨度 ${span}。请补全缺口后核验共享实体间的行为连续性。`,
    })
  }
  return investigations
}

// 系统自动处置链：将未进入任何人工案件的异常窗口，按共享实体 + 24h 时间窗聚成
// 可直接处置的自动链（queueStatus=resolved / decisionSource=system），未成链的
// 孤立低危窗口保持为“自动归档”。通过链长上限与行为多样性护栏避免巨型链。
function buildAutomaticResolutions(
  dataset: DemoDatasetId,
  windows: AnomalyWindow[],
  reservedWindowIds: Set<string>,
): Investigation[] {
  const frequencies = entityFrequencies(windows)
  const assigned = new Set(reservedWindowIds)
  const candidates = [...windows]
    .filter((window) => !assigned.has(window.id))
    .sort((left, right) => right.score - left.score || Date.parse(right.start) - Date.parse(left.start) || left.id.localeCompare(right.id))
  const resolutions: Investigation[] = []

  for (const seed of candidates) {
    if (resolutions.length >= AUTO_RESOLVE_CHAIN_LIMIT) break
    if (assigned.has(seed.id)) continue
    const minMembers = AUTO_RESOLVE_CHAIN_MIN_MEMBERS[dataset]
    const maxMembers = AUTO_RESOLVE_CHAIN_MAX_MEMBERS[dataset]
    const targetMembers = minMembers + (resolutions.length % (maxMembers - minMembers + 1))
    const related = windows
      .filter((window) => window.id !== seed.id && !assigned.has(window.id))
      .map((window) => correlateWindows(seed, window, frequencies, windows.length))
      .filter((item) => item.score >= 0.32 && Number.isFinite(item.timeGapMs) && item.timeGapMs <= AUTO_RESOLVE_TIME_GAP)
      .sort((left, right) => right.score - left.score || left.timeGapMs - right.timeGapMs || left.window.id.localeCompare(right.window.id))
      .slice(0, targetMembers - 1)
    // A finalized chain must be a complete, reviewable sequence rather than a
    // two-node correlation. Seeds without the dataset-specific minimum number
    // of supporting events remain outside the resolved queue.
    if (related.length < minMembers - 1) continue

    const members = [seed, ...related.map((item) => item.window)]
      .sort((left, right) => Date.parse(left.start) - Date.parse(right.start))
    const anchor = strongestCaseAnchor(members, frequencies)
    const uniqueFamilies = new Set(members.map(windowActionFamily)).size
    const spanHours = (Date.parse(members[members.length - 1].start) - Date.parse(members[0].start)) / HOUR
    // 自动处置只接受可信子链：存在稀有实体锚点、行为阶段多样或 1 小时内突发；
    // 否则该窗口保持孤立，计入总览“自动归档”。
    if (!anchor && uniqueFamilies < 2 && spanHours > 1) continue

    members.forEach((window) => assigned.add(window.id))
    const index = resolutions.length + 1
    const firstTime = members[0]?.start || seed.start
    const lastTime = members[members.length - 1]?.start || seed.start
    const shared = Array.from(new Set(related.flatMap((item) => item.sharedEntities))).slice(0, 3)
    const meanScore = members.reduce((sum, window) => sum + window.score, 0) / members.length
    const maxScore = Math.max(...members.map((window) => window.score), 0)
    const familyLabel = caseBehaviorLabel(members)
    resolutions.push({
      id: `${dataset.toUpperCase()}-DISP-${String(index).padStart(3, '0')}`,
      title: `${familyLabel} · 系统自动处置 · ${compactCaseTime(firstTime)}`,
      severity: highestSeverity(members),
      status: 'contained',
      queueStatus: 'resolved',
      escalationScore: Math.round(maxScore * 100),
      escalationReasons: [
        `系统自动研判 · 平均风险 ${(meanScore * 100).toFixed(0)}%`,
        `${uniqueFamilies} 类行为阶段`,
        `最强关联置信 ${(related[0].score * 100).toFixed(0)}%`,
      ],
      decisionSource: 'system',
      windowIds: members.map((window) => window.id),
      owner: '系统自动研判',
      createdAt: firstTime,
      summary: `由 ${members.length} 个异常发现按共享实体与 ${AUTO_RESOLVE_TIME_GAP / HOUR}h 时间窗自动聚类，系统自动研判为${familyLabel}链并完成处置${shared.length ? `；共享锚点 ${shared.join('、')}` : ''}。时间范围 ${firstTime} 至 ${lastTime}。该链无需人工研判，可在“自动处置”队列复核或转人工。`,
    })
  }
  return resolutions
}

export async function loadDemoDataset(dataset: DemoDatasetId): Promise<{
  events: SecurityEvent[]
  anomalyWindows: AnomalyWindow[]
  investigations: Investigation[]
  logSources: LogSource[]
  overviewSeries: Array<{ time: string; logs: number; anomalies: number }>
}> {
  const base = `/demo-data/${dataset}`
  const loadJson = <T,>(file: string) => fetch(`${base}/${file}?revision=apt-script-10`, { cache: 'no-store' }).then((response) => response.json() as Promise<T>)
  const [rawTimeline, rawDetections, rawChain, manifest, rawModuleScores] = await Promise.all([
    loadJson<DemoTimelineEvent[]>('timeline.json'),
    loadJson<DemoDetection[]>('detection_results.json'),
    loadJson<DemoChain>('attack_chain.json'),
    loadJson<{ source_slice?: string; event_count?: number }>('manifest.json'),
    loadJson<Record<string, Record<'M0' | 'M1' | 'M2' | 'M3' | 'M4' | 'M5' | 'M6', number>>>('module_scores.json'),
  ])
  // 防御旧浏览器缓存或旧静态文件：APT 九分钟剧本严格只保留前十步。
  const isRetiredAptScript = (id: string) => dataset === 'APT' && /^APT-SCRIPT-01[1-8]$/.test(id)
  const timeline = rawTimeline.filter((item) => !isRetiredAptScript(item.event_id))
  const detections = rawDetections.filter((item) => !isRetiredAptScript(item.event_id))
  const chain: DemoChain = dataset === 'APT'
    ? {
        ...rawChain,
        steps: (rawChain.steps || []).filter((step) => step.evidence_event_ids.every((id) => !isRetiredAptScript(id))),
      }
    : rawChain
  const moduleScores = Object.fromEntries(Object.entries(rawModuleScores).filter(([id]) => !isRetiredAptScript(id))) as Record<string, Record<'M0' | 'M1' | 'M2' | 'M3' | 'M4' | 'M5' | 'M6', number>>

  const replayTimeline = projectReplayTimeline(timeline, chain, dataset)
  const detectionById = new Map(detections.map((item) => [item.event_id, item]))
  const events = replayTimeline.map<SecurityEvent>((item) => ({
    id: item.event_id,
    time: item.timestamp,
    action: eventAction(item.raw),
    ...eventFields(item),
    source: sourceName(item.source_file),
    raw: item.raw,
    confidence: 1,
  }))
  const eventById = new Map(events.map((event) => [event.id, event]))

  // Ordinary events remain in the replay file for source/log search.  Mission
  // Control receives only review-worthy windows so a 40K-event replay remains usable.
  const anomalyWindows = replayTimeline
    .filter((item) => (detectionById.get(item.event_id) || item.system_projection)?.final_score! >= 0.5)
    .map<AnomalyWindow>((item) => {
      const projection = detectionById.get(item.event_id) || item.system_projection
      const related = item.related_entities || []
      const event = eventById.get(item.event_id)!
      const inferredEntities = [event.actor, event.host, event.process, event.ip, ...rawContextEntities(item.raw)]
        .filter((value): value is string => Boolean(value))
      const score = projection?.final_score ?? 0
      return {
        id: `WIN-${item.event_id}`,
        title: event.action,
        severity: severity(projection?.threat_level),
        score,
        moduleScores: moduleScores[item.event_id],
        start: item.timestamp,
        end: item.timestamp,
        status: score >= 0.75 ? 'new' : 'reviewing',
        eventCount: 1,
        entities: Array.from(new Set([...related.map((value) => value.canonical_value), ...inferredEntities])),
        hosts: related.filter((value) => value.entity_type === 'host').map((value) => value.canonical_value),
        sourceTypes: [event.source],
        summary: projection?.reasons?.join('；') || '标准化安全事件。',
        events: [event],
      }
    })

  const chainEventIds = new Set((chain.steps || []).flatMap((step) => step.evidence_event_ids))
  const chainWindows = anomalyWindows
    .filter((item) => chainEventIds.has(item.id.replace('WIN-', '')))
    .sort((left, right) => Date.parse(left.start) - Date.parse(right.start))
  const chainSeverity = severity([...chainWindows].sort((left, right) => right.score - left.score)[0]?.severity)
  // 基准链同样截断为骨架链，保留首尾/关键段、中间作为缺口，使待研判队列案件形态一致；
  // 完整基准链仍保留在 attack_chain 证据文件中，用于和自动关联结果对照。
  // APT 演示固定拆成两个调查事项：边界初始线索与工作站侦察线索，避免自动聚类把后续步骤提前并入首个案件。
  const { kept: curatedKept, gaps: curatedGaps } = dataset === 'APT'
    ? { kept: chainWindows, gaps: [] as AnomalyWindow[] }
    : truncateChainForReview(chainWindows, 1)
  const curatedDistractorIds = dataset === 'APT' ? [] : selectDistractorIds(chainWindows, anomalyWindows, new Set(), 2)
  const curatedInvestigation: Investigation = {
    id: chain.chain_id,
    title: `${caseBehaviorLabel(chainWindows)} · 人工整理基准链`,
    severity: chainSeverity,
    status: chain.status === 'confirmed' ? 'contained' : chain.status === 'dismissed' ? 'closed' : 'investigating',
    queueStatus: chain.status === 'candidate' ? 'manual_review' : 'resolved',
    escalationScore: 100,
    escalationReasons: ['独立攻击链证据文件提供六阶段关联', '用于人工整理基准链与自动结果对照'],
    decisionSource: 'analyst',
    windowIds: curatedKept.map((window) => window.id),
    gapEvidenceIds: curatedGaps.map((window) => window.id),
    gapDistractorIds: curatedDistractorIds,
    owner: 'analyst-01',
    createdAt: events[0]?.time || new Date().toISOString(),
    summary: dataset === 'APT'
      ? '边界初始调查事项只保留公网扫描、管理接口操作、VPN 账户创建和首次 VPN 登录四个早期证据；后续工作站活动另立调查事项，避免提前合并。'
      : `由独立攻击链证据文件整理的基准候选链（完整 ${chainWindows.length} 个关键窗口），截断为骨架链后供研判补全，用于和自动关联拆案结果对照；真实标签不参与检测。`,
  }
  const aptReconWindows = dataset === 'APT'
    ? APT_RECON_EVENT_IDS
        .map((eventId) => anomalyWindows.find((window) => window.id === `WIN-${eventId}`))
        .filter((window): window is AnomalyWindow => Boolean(window))
    : []
  const aptReconInvestigation: Investigation | null = dataset === 'APT' && aptReconWindows.length
    ? {
        id: APT_RECON_CASE_ID,
        title: 'APT · 工作站侦察调查',
        severity: highestSeverity(aptReconWindows),
        status: 'investigating',
        queueStatus: 'manual_review',
        escalationScore: Math.round(Math.max(...aptReconWindows.map((window) => window.score)) * 100),
        escalationReasons: ['同一 svc-netops 账户连续活动', '工作站侦察与后续主机切换需要人工核验'],
        decisionSource: 'analyst',
        windowIds: aptReconWindows.map((window) => window.id),
        gapEvidenceIds: [],
        gapDistractorIds: [],
        owner: 'analyst-01',
        createdAt: aptReconWindows[0].start,
        summary: '固定主链顺序为工作站身份与网络侦察、进程与在线用户枚举、域账户结构枚举、远程服务执行、计划任务持久化；RDP 事件不属于该初始链。',
      }
    : null
  const curatedReservedIds = new Set([
    ...curatedInvestigation.windowIds,
    ...(curatedInvestigation.gapEvidenceIds || []),
    ...(curatedInvestigation.gapDistractorIds || []),
    ...(aptReconInvestigation?.windowIds || []),
    ...(aptReconInvestigation?.gapEvidenceIds || []),
  ])
  const autoManualInvestigations = dataset === 'APT' ? [] : buildAutomaticInvestigations(dataset, anomalyWindows, curatedReservedIds)
  const autoResolvedInvestigations = dataset === 'APT'
    ? []
    : buildAutomaticResolutions(
        dataset,
        anomalyWindows,
        new Set([...curatedReservedIds, ...autoManualInvestigations.flatMap((item) => item.windowIds)]),
      )
  const investigations: Investigation[] = [
    curatedInvestigation,
    ...(aptReconInvestigation ? [aptReconInvestigation] : []),
    ...autoManualInvestigations,
    ...autoResolvedInvestigations,
  ]

  const logSources: LogSource[] = [{
    id: `DEMO-${dataset.toUpperCase()}`,
    name: dataset,
    path: `stream://${dataset.toLowerCase()}`,
    kind: '事件流',
    status: 'online',
    size: `${(manifest.event_count || events.length).toLocaleString()} 条事件 / 30 天窗口`,
    lastRead: events[events.length - 1]?.time || '等待事件',
  }]

  const bucketMinutes = 5
  const buckets = new Map<string, { logs: number; anomalies: number; kinds: Record<string, number> }>()
  replayTimeline.forEach((item) => {
    const timestamp = new Date(item.timestamp)
    timestamp.setUTCSeconds(0, 0)
    timestamp.setUTCMinutes(Math.floor(timestamp.getUTCMinutes() / bucketMinutes) * bucketMinutes)
    const key = timestamp.toISOString().slice(0, 16).replace('T', ' ')
    const current = buckets.get(key) || { logs: 0, anomalies: 0, kinds: {} }
    current.logs += 1
    const kind = logKindForEvent(item)
    current.kinds[kind] = (current.kinds[kind] || 0) + 1
    if ((detectionById.get(item.event_id) || item.system_projection)?.final_score! >= 0.5) current.anomalies += 1
    buckets.set(key, current)
  })
  const overviewSeries = Array.from(buckets.entries()).map(([time, count]) => ({ time: time.replace('T', ' '), ...count }))
  return { events, anomalyWindows, investigations, logSources, overviewSeries }
}
