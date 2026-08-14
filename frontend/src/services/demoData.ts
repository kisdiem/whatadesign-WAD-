import type { AnomalyWindow, Investigation, LogSource, SecurityEvent, Severity } from '../mocks/data'

export type DemoDatasetId = 'Short' | 'Long'

type DemoTimelineEvent = {
  event_id: string
  timestamp: string
  source_file: string
  raw: string
  system_projection?: {
    threat_level?: string
    final_score?: number
    reasons?: string[]
    provenance?: { model_execution?: boolean; synthetic_scores?: boolean; formal_evaluation?: boolean }
  }
  related_entities?: Array<{ entity_type: string; canonical_value: string; role?: string; confidence?: number }>
}

type DemoDetection = {
  event_id: string
  threat_level?: string
  alert_level?: string
  final_score?: number
  reasons?: string[]
  provenance?: { model_execution?: boolean; synthetic_scores?: boolean; formal_evaluation?: boolean }
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
  const actor = values.find((item) => item.role === 'actor')?.canonical_value
  const host = values.find((item) => item.entity_type === 'host')?.canonical_value
  const process = values.find((item) => item.entity_type === 'process')?.canonical_value
  const ip = values.find((item) => item.entity_type === 'ip')?.canonical_value
  return { actor, host, process, ip }
}

export async function loadDemoDataset(dataset: DemoDatasetId): Promise<{
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
    fetch(`${base}/manifest.json`).then((response) => response.json() as Promise<{ source_member?: string; source_slice?: string; event_count?: number }>),
  ])

  const detectionById = new Map(detections.map((item) => [item.event_id, item]))
  const events: SecurityEvent[] = timeline.map((item) => {
    const projection = detectionById.get(item.event_id) || item.system_projection
    return {
      id: item.event_id,
      time: item.timestamp,
      action: eventAction(item.raw),
      ...eventFields(item),
      source: sourceName(item.source_file),
      raw: item.raw,
      confidence: 1,
    }
  })

  const anomalyWindows = timeline.map<AnomalyWindow>((item) => {
    const projection = detectionById.get(item.event_id) || item.system_projection
    const related = item.related_entities || []
    const event = events.find((value) => value.id === item.event_id)!
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
      summary: projection?.reasons?.join('；') || '演示数据包中的标准化安全事件。',
      events: [event],
    }
  })

  const chainEventIds = new Set((chain.steps || []).flatMap((step) => step.evidence_event_ids))
  const investigations: Investigation[] = [{
    id: chain.chain_id,
    title: `${dataset} 候选攻击链`,
    severity: severity(anomalyWindows.filter((item) => chainEventIds.has(item.id.replace('WIN-', ''))).sort((a, b) => b.score - a.score)[0]?.severity),
    status: chain.status === 'confirmed' ? 'contained' : chain.status === 'dismissed' ? 'closed' : 'investigating',
    windowIds: Array.from(chainEventIds).map((id) => `WIN-${id}`),
    owner: 'demo-analyst',
    createdAt: events[0]?.time || new Date().toISOString(),
    summary: '基于演示包 attack_chain.json 的人工整理候选链；不是模型预测结果。',
  }]

  const sourceMembers = new Set(timeline.map((item) => item.source_file))
  const logSources: LogSource[] = Array.from(sourceMembers).map((path, index) => ({
    id: `DEMO-SRC-${index + 1}`,
    name: sourceName(path),
    path,
    kind: 'Demo replay',
    status: 'online',
    size: `${manifest.event_count || events.length} events`,
    lastRead: manifest.source_slice || 'demo package',
  }))

  const buckets = new Map<string, number>()
  events.forEach((item) => {
    const key = item.time.slice(0, 13)
    buckets.set(key, (buckets.get(key) || 0) + 1)
  })
  const overviewSeries = Array.from(buckets.entries()).map(([time, count]) => ({ time: time.replace('T', ' '), logs: count, anomalies: anomalyWindows.filter((item) => item.start.startsWith(time)).length }))
  return { anomalyWindows, investigations, logSources, overviewSeries }
}
