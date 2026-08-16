import type { AnomalyWindow, Investigation, LogSource, SecurityEvent, Severity } from '../mocks/data'

export type DemoDatasetId = 'Short' | 'Long'

type DemoTimelineEvent = {
  event_id: string
  timestamp: string
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

const severity = (value?: string): Severity => {
  if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low' || value === 'info') return value
  return 'info'
}

const sourceName = (path: string) => path.split('/').pop() || path

function eventAction(raw: string) {
  const message = raw.split(': ').slice(1).join(': ').trim()
  return message ? message.slice(0, 68) : raw.slice(0, 68)
}

function eventFields(event: DemoTimelineEvent) {
  const values = event.related_entities || []
  return {
    actor: values.find((item) => item.role === 'actor')?.canonical_value,
    host: values.find((item) => item.entity_type === 'host')?.canonical_value,
    process: values.find((item) => item.entity_type === 'process')?.canonical_value,
    ip: values.find((item) => item.entity_type === 'ip')?.canonical_value,
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

  const detectionById = new Map(detections.map((item) => [item.event_id, item]))
  const events = timeline.map<SecurityEvent>((item) => ({
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
  const anomalyWindows = timeline
    .filter((item) => (detectionById.get(item.event_id) || item.system_projection)?.final_score! >= 0.5)
    .map<AnomalyWindow>((item) => {
      const projection = detectionById.get(item.event_id) || item.system_projection
      const related = item.related_entities || []
      const event = eventById.get(item.event_id)!
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
        entities: related.map((value) => value.canonical_value),
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
    path: manifest.source_slice || 'local archive',
    kind: '日志归档',
    status: 'online',
    size: `${manifest.event_count || events.length} events`,
    lastRead: manifest.source_slice || 'local archive',
  }]

  const bucketMinutes = dataset === 'Short' ? 5 : 60
  const buckets = new Map<string, { logs: number; anomalies: number }>()
  timeline.forEach((item) => {
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
