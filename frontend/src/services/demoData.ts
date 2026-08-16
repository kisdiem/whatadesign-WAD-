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
const REPLAY_BANDS: ReplayBand[] = [
  { cumulativeShare: 0.045, centers: [7 * MINUTE, 21 * MINUTE, 49 * MINUTE], spreads: [3 * MINUTE, 6 * MINUTE, 8 * MINUTE] },
  { cumulativeShare: 0.20, centers: [2.4 * HOUR, 8.7 * HOUR, 19.5 * HOUR], spreads: [35 * MINUTE, 80 * MINUTE, 130 * MINUTE] },
  { cumulativeShare: 0.60, centers: [1.35 * DAY, 3.15 * DAY, 5.75 * DAY], spreads: [0.22 * DAY, 0.48 * DAY, 0.72 * DAY] },
  { cumulativeShare: 1, centers: [8.4 * DAY, 13.8 * DAY, 22.6 * DAY, 28.3 * DAY], spreads: [0.7 * DAY, 1.1 * DAY, 1.5 * DAY, 0.65 * DAY] },
]

// Six evidence stages deliberately cross every selectable time scale.
const CHAIN_STAGE_AGES = [23 * DAY, 12 * DAY, 5 * DAY, 28 * HOUR, 9 * HOUR, 22 * MINUTE]

function stableUnit(value: string) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0) / 4294967296
}

function projectedAge(eventId: string, dataset: DemoDatasetId) {
  const selector = stableUnit(`${dataset}:${eventId}:band`)
  const band = REPLAY_BANDS.find((candidate) => selector < candidate.cumulativeShare) || REPLAY_BANDS[REPLAY_BANDS.length - 1]
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
    const age = stage == null
      ? projectedAge(item.event_id, dataset)
      : Math.max(MINUTE, CHAIN_STAGE_AGES[Math.min(stage, CHAIN_STAGE_AGES.length - 1)] + sourceJitter)
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
  const investigations: Investigation[] = [{
    id: chain.chain_id,
    title: `${dataset} 候选攻击链`,
    severity: severity(chainWindows.sort((a, b) => b.score - a.score)[0]?.severity),
    status: chain.status === 'confirmed' ? 'contained' : chain.status === 'dismissed' ? 'closed' : 'investigating',
    windowIds: Array.from(chainEventIds).map((id) => `WIN-${id}`),
    owner: 'analyst-01',
    createdAt: events[0]?.time || new Date().toISOString(),
    summary: '基于事件关联构建的候选攻击链。',
  }]

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
