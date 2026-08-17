import type { AnomalyWindow, Investigation, LogSource, SecurityEvent, Severity } from '../mocks/data'

export type DemoDatasetId = 'Short' | 'Long'

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
}

// 基准链六步证据的年龄（越早越旧）：Short 在 30 分钟内完成、Long 跨约 7 天。
const CHAIN_STAGE_AGES: Record<DemoDatasetId, number[]> = {
  Short: [25 * MINUTE, 20 * MINUTE, 15 * MINUTE, 10 * MINUTE, 5 * MINUTE, MINUTE],
  Long: [6.8 * DAY, 5.4 * DAY, 3.8 * DAY, 2.1 * DAY, 16 * HOUR, 40 * MINUTE],
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

function eventAction(raw: string) {
  const message = raw.split(': ').slice(1).join(': ').trim()
  return message ? message.slice(0, 68) : raw.slice(0, 68)
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

const AUTO_CASE_LIMIT = 4
const AUTO_CASE_EVIDENCE_LIMIT = 7

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

function caseBehaviorLabel(windows: AnomalyWindow[]) {
  const counts = new Map<string, number>()
  const labels: Record<string, string> = {
    account: '账户权限变更',
    authentication: '异常认证',
    privilege: '权限提升',
    execution: '命令执行',
    network: '网络外联',
    file: '文件访问',
    system: '系统服务异常',
    other: '多阶段异常行为',
  }
  windows.forEach((window) => {
    const family = windowActionFamily(window)
    counts.set(family, (counts.get(family) || 0) + 1)
  })
  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 2)
    .map(([family]) => labels[family])
    .join('与') || labels.other
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

function automaticEscalation(windows: AnomalyWindow[], strongestLinkScore: number) {
  const maxRisk = Math.max(...windows.map((window) => window.score), 0)
  const familyCount = new Set(windows.map(windowActionFamily)).size
  const sourceCount = new Set(windows.flatMap((window) => window.sourceTypes)).size
  const evidenceVolume = Math.min(1, windows.length / AUTO_CASE_EVIDENCE_LIMIT)
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
      .slice(0, AUTO_CASE_EVIDENCE_LIMIT - 1)
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
    const shared = Array.from(new Set(related.flatMap((item) => item.sharedEntities))).slice(0, 3)
    const escalation = automaticEscalation(members, strongestLink.score)
    investigations.push({
      id: `${dataset.toUpperCase()}-AUTO-${String(index).padStart(3, '0')}`,
      title: `${caseBehaviorLabel(members)}${anchor ? ` · ${anchor}` : ''} · ${compactCaseTime(firstTime)}`,
      severity: highestSeverity(members),
      status: 'investigating',
      queueStatus: 'manual_review',
      escalationScore: Math.round(escalation.score * 100),
      escalationReasons: escalation.reasons,
      decisionSource: 'system',
      windowIds: members.map((window) => window.id),
      owner: 'M5 自动关联',
      createdAt: firstTime,
      summary: `由 ${members.length} 个异常发现自动聚类形成；${shared.length ? `共享锚点 ${shared.join('、')}，` : ''}时间范围 ${firstTime} 至 ${lastTime}，最强关联置信 ${(strongestLink.score * 100).toFixed(0)}%。该链为待人工核验的候选线索，不代表已确认攻击。`,
    })
  }
  return investigations
}

export async function loadDemoDataset(dataset: DemoDatasetId): Promise<{
  events: SecurityEvent[]
  anomalyWindows: AnomalyWindow[]
  investigations: Investigation[]
  logSources: LogSource[]
  overviewSeries: Array<{ time: string; logs: number; anomalies: number }>
}> {
  const base = `/demo-data/${dataset}`
  const [timeline, detections, chain, manifest] = await Promise.all([
    fetch(`${base}/timeline.json`).then((response) => response.json() as Promise<DemoTimelineEvent[]>),
    fetch(`${base}/detection_results.json`).then((response) => response.json() as Promise<DemoDetection[]>),
    fetch(`${base}/attack_chain.json`).then((response) => response.json() as Promise<DemoChain>),
    fetch(`${base}/manifest.json`).then((response) => response.json() as Promise<{ source_slice?: string; event_count?: number }>),
  ])

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
  const chainWindows = anomalyWindows.filter((item) => chainEventIds.has(item.id.replace('WIN-', '')))
  const curatedInvestigation: Investigation = {
    id: chain.chain_id,
    title: `${caseBehaviorLabel(chainWindows)} · 人工整理基准链`,
    severity: severity(chainWindows.sort((a, b) => b.score - a.score)[0]?.severity),
    status: chain.status === 'confirmed' ? 'contained' : chain.status === 'dismissed' ? 'closed' : 'investigating',
    queueStatus: chain.status === 'candidate' ? 'manual_review' : 'resolved',
    escalationScore: 100,
    escalationReasons: ['独立攻击链证据文件提供六阶段关联', '用于人工整理基准链与自动结果对照'],
    decisionSource: 'analyst',
    windowIds: Array.from(chainEventIds).map((id) => `WIN-${id}`),
    owner: 'analyst-01',
    createdAt: events[0]?.time || new Date().toISOString(),
    summary: '由独立攻击链证据文件整理的基准候选链，用于和自动关联拆案结果对照；真实标签不参与检测。',
  }
  const investigations: Investigation[] = [
    curatedInvestigation,
    ...buildAutomaticInvestigations(dataset, anomalyWindows, new Set(curatedInvestigation.windowIds)),
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
  const buckets = new Map<string, { logs: number; anomalies: number }>()
  replayTimeline.forEach((item) => {
    const timestamp = new Date(item.timestamp)
    timestamp.setUTCSeconds(0, 0)
    timestamp.setUTCMinutes(Math.floor(timestamp.getUTCMinutes() / bucketMinutes) * bucketMinutes)
    const key = timestamp.toISOString().slice(0, 16).replace('T', ' ')
    const current = buckets.get(key) || { logs: 0, anomalies: 0 }
    current.logs += 1
    if ((detectionById.get(item.event_id) || item.system_projection)?.final_score! >= 0.5) current.anomalies += 1
    buckets.set(key, current)
  })
  const overviewSeries = Array.from(buckets.entries()).map(([time, count]) => ({ time: time.replace('T', ' '), ...count }))
  return { events, anomalyWindows, investigations, logSources, overviewSeries }
}
