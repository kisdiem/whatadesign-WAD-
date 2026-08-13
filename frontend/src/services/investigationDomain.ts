import {
  anomalyWindows,
  investigations,
  type AnomalyWindow,
  type Investigation,
  type SecurityEvent,
  type Severity,
} from '../mocks/data'

export type EntityKind = 'User' | 'Host' | 'Process' | 'IP' | 'Asset'
export type FindingStage = 'main' | 'candidate' | 'excluded'
export type FindingStatus = AnomalyWindow['status']

export type EvidenceRecord = {
  id: string
  eventId: string
  findingId: string
  statement: string
  source: string
  rawLogRef: string
  raw: string
  normalized: {
    action: string
    actor: string
    sourceHost: string
    process: string
    ip: string
  }
}

export type RelatedCandidate = {
  id: string
  title: string
  time: string
  reasons: string[]
}

export type FindingRecord = {
  id: string
  caseId?: string
  title: string
  severity: Severity
  status: FindingStatus
  risk: number
  eventScore: number
  localScore: number
  longScore: number
  reasons: string[]
  entity: string
  entityType: EntityKind
  host: string
  start: string
  end: string
  source: string
  sourceTypes: string[]
  summary: string
  events: SecurityEvent[]
  entities: string[]
  anchorEvent: SecurityEvent
  relatedCandidates: RelatedCandidate[]
  association: {
    confidence: number
    sharedAnchor: string
    anchorStrength: 'Strong' | 'Medium' | 'Weak'
    entityRarity: number
    actionCompatibility: number
    graphSimilarity: number
    timeGap: string
    summary: string[]
  }
}

export type EntityProfile = {
  id: string
  type: EntityKind
  firstSeen: string
  lastSeen: string
  thirtyDayEvents: number
  normalLoginHosts: number
  currentLoginHosts: number
  newHostRelations: number
  rareRelations: number
  usualLogin: string
  currentActivity: string
  hostHistory: Array<{ host: string; count: number; isNew: boolean }>
  baseline: Array<{ feature: string; current: string; baseline: string; deviation: number }>
  findingIds: string[]
}

export type CaseBoard = Record<string, FindingStage>

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max)
}

function toPercent(value: number) {
  return Math.round(value * 100)
}

function timeToMinutes(value: string) {
  const normalized = value.trim()
  const direct = Date.parse(normalized.replace(' ', 'T'))
  if (!Number.isNaN(direct)) return Math.floor(direct / 60000)

  const match = normalized.match(/(\d{2}):(\d{2})(?::(\d{2}))?$/)
  if (match) {
    const hour = Number(match[1])
    const minute = Number(match[2])
    return hour * 60 + minute
  }

  return 0
}

function formatGap(minutes: number) {
  const days = Math.floor(minutes / (24 * 60))
  const afterDays = minutes % (24 * 60)
  const hours = Math.floor(minutes / 60)
  const remain = minutes % 60
  if (days > 0) return `${days}d ${Math.floor(afterDays / 60)}h`
  return hours > 0 ? `${hours}h ${remain}m` : `${remain}m`
}

function intersect(a: string[], b: string[]) {
  return a.filter((item) => b.includes(item))
}

export function inferEntityType(entity: string): EntityKind {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(entity)) return 'IP'
  if (/host|srv|ws-|fs-|app-/i.test(entity)) return 'Host'
  if (/\.(exe|dat)$/i.test(entity)) return 'Process'
  if (/[\\/]/.test(entity)) return 'Asset'
  return 'User'
}

function primaryEntity(window: AnomalyWindow) {
  return window.events.find((event) => event.actor)?.actor
    || window.events.find((event) => event.host)?.host
    || window.entities[0]
    || 'Unknown'
}

function anchorEvent(window: AnomalyWindow) {
  return window.events[window.events.length - 1] || window.events[0]
}

function linkReasons(current: AnomalyWindow, candidate: AnomalyWindow) {
  const reasons: string[] = []
  const shared = intersect(current.entities, candidate.entities)
  if (shared.some((item) => inferEntityType(item) === 'User')) reasons.push('same_user')
  if (shared.some((item) => inferEntityType(item) === 'Host')) reasons.push('same_host')
  if (shared.some((item) => inferEntityType(item) === 'Process')) reasons.push('process_relation')
  const gap = Math.abs(timeToMinutes(current.start) - timeToMinutes(candidate.start))
  reasons.push(`Δt ${formatGap(gap)}`)
  return reasons
}

function deriveReasons(window: AnomalyWindow, sharedCount: number) {
  const reasons: string[] = []
  const actor = window.events.some((event) => Boolean(event.actor))
  if (actor) reasons.push('shared_account')
  if (window.sourceTypes.length >= 2) reasons.push('multi_source_corroboration')
  if (window.events.some((event) => /PROCESS|SCRIPT|TASK|TOKEN/.test(event.action))) reasons.push('process_relation')
  if (window.events.some((event) => /NETWORK|DNS|SSH/.test(event.action))) reasons.push('new_host_relation')
  if (timeToMinutes(window.start) < 6 * 60 || timeToMinutes(window.start) > 20 * 60) reasons.push('unusual_time')
  if (sharedCount >= 2) reasons.push('long_range_entity_overlap')
  return Array.from(new Set(reasons))
}

export function buildFindings(
  windows: AnomalyWindow[] = anomalyWindows,
  cases: Investigation[] = investigations,
) {
  return windows.map<FindingRecord>((window) => {
    const peers = windows.filter((item) => item.id !== window.id && intersect(item.entities, window.entities).length > 0)
    const sharedCount = peers.length
    const eventScore = clamp(window.score * 0.68 + (window.events.length >= 2 ? 0.16 : 0.08), 0.38, 0.96)
    const localScore = clamp(window.score * 0.54 + window.sourceTypes.length * 0.08 + (window.eventCount > 30 ? 0.08 : 0.02), 0.34, 0.95)
    const longScore = clamp(window.score * 0.42 + sharedCount * 0.14 + (window.events.some((event) => Boolean(event.actor)) ? 0.12 : 0.04), 0.21, 0.97)
    const risk = Math.round((eventScore * 0.32 + localScore * 0.28 + longScore * 0.4) * 100)
    const anchor = anchorEvent(window)
    const primary = primaryEntity(window)
    const caseId = cases.find((item) => item.windowIds.includes(window.id))?.id
    const rarity = clamp(0.58 + (sharedCount <= 1 ? 0.24 : 0.12) + (window.sourceTypes.length >= 3 ? 0.08 : 0), 0.4, 0.97)
    const compatibility = clamp(0.56 + (window.events.length >= 2 ? 0.16 : 0.08) + (/LOGIN|FILE|DB_EXPORT/.test(anchor.action) ? 0.08 : 0), 0.42, 0.95)
    const graphSimilarity = clamp(0.48 + sharedCount * 0.1 + (window.sourceTypes.length >= 2 ? 0.08 : 0), 0.35, 0.92)
    const closestPeer = peers[0]
    const timeGap = closestPeer ? formatGap(Math.abs(timeToMinutes(window.start) - timeToMinutes(closestPeer.start))) : '24h+'
    const strength = inferEntityType(primary) === 'User' || inferEntityType(primary) === 'Process'
      ? 'Strong'
      : inferEntityType(primary) === 'Host'
        ? 'Medium'
        : 'Weak'

    return {
      id: window.id,
      caseId,
      title: window.title,
      severity: window.severity,
      status: window.status,
      risk,
      eventScore: toPercent(eventScore),
      localScore: toPercent(localScore),
      longScore: toPercent(longScore),
      reasons: deriveReasons(window, sharedCount),
      entity: primary,
      entityType: inferEntityType(primary),
      host: window.hosts[0] || anchor.host || 'Unknown',
      start: window.start,
      end: window.end,
      source: window.sourceTypes.join(' / '),
      sourceTypes: window.sourceTypes,
      summary: window.summary,
      events: window.events,
      entities: window.entities,
      anchorEvent: anchor,
      relatedCandidates: peers.slice(0, 4).map((item) => ({
        id: item.id,
        title: item.title,
        time: item.start,
        reasons: linkReasons(window, item),
      })),
      association: {
        confidence: clamp(risk / 100 - (strength === 'Weak' ? 0.18 : 0), 0.22, 0.95),
        sharedAnchor: primary,
        anchorStrength: strength,
        entityRarity: rarity,
        actionCompatibility: compatibility,
        graphSimilarity,
        timeGap,
        summary: [
          `${primary} 在跨窗口中重复出现，作为 ${strength === 'Strong' ? '强' : strength === 'Medium' ? '中' : '弱'}锚点参与关联。`,
          `当前关系在近 30 天画像中偏离基线，稀有度 ${toPercent(rarity)}。`,
          `行为兼容度 ${toPercent(compatibility)}，图相似度 ${toPercent(graphSimilarity)}。`,
        ],
      },
    }
  })
}

export function buildEvidence(findings: FindingRecord[]) {
  return findings.reduce<Record<string, EvidenceRecord[]>>((result, finding) => {
    result[finding.id] = finding.events.map((event, index) => ({
      id: `EV-${finding.id.split('-').slice(-1)[0]}-${String(index + 1).padStart(2, '0')}`,
      eventId: event.id,
      findingId: finding.id,
      statement: `${event.actor || finding.entity} 在 ${event.host || finding.host} 执行 ${event.action}${event.process ? ` / ${event.process}` : ''}${event.ip ? ` / ${event.ip}` : ''}`,
      source: event.source,
      rawLogRef: `${event.source}:${event.id}`,
      raw: event.raw,
      normalized: {
        action: event.action,
        actor: event.actor || '—',
        sourceHost: event.host || '—',
        process: event.process || '—',
        ip: event.ip || '—',
      },
    }))
    return result
  }, {})
}

export function buildEntityProfiles(findings: FindingRecord[]) {
  const entities = Array.from(new Set(findings.flatMap((finding) => finding.entities)))
  return entities
    .map<EntityProfile>((entity) => {
      const linked = findings.filter((finding) => finding.entities.includes(entity))
      const ordered = [...linked].sort((a, b) => timeToMinutes(a.start) - timeToMinutes(b.start))
      const hosts = linked.flatMap((finding) => finding.events.map((event) => event.host).filter(Boolean) as string[])
      const uniqueHosts = Array.from(new Set(hosts))
      const hostHistory = uniqueHosts.map((host, index) => ({
        host,
        count: linked.filter((finding) => finding.host === host).reduce((sum, finding) => sum + finding.events.length, 0) * 8 + 4,
        isNew: index >= 1,
      })).sort((a, b) => b.count - a.count)
      const latest = ordered[ordered.length - 1]
      const dominantHost = hostHistory[0]?.host || '—'
      const currentHost = latest?.host || '—'
      const latestAction = latest?.anchorEvent.action || '—'

      return {
        id: entity,
        type: inferEntityType(entity),
        firstSeen: ordered[0]?.start || '—',
        lastSeen: latest?.end || '—',
        thirtyDayEvents: linked.reduce((sum, finding) => sum + finding.events.length * 12, 0),
        normalLoginHosts: Math.max(hostHistory.length - 1, 1),
        currentLoginHosts: hostHistory.length || 1,
        newHostRelations: Math.max(hostHistory.filter((item) => item.isNew).length, 0),
        rareRelations: linked.filter((finding) => finding.longScore >= 75).length,
        usualLogin: entity.toLowerCase().includes('svc') ? '08:00-18:00' : '09:00-19:00',
        currentActivity: latest?.start || '—',
        hostHistory,
        baseline: [
          { feature: '登录主机', current: currentHost, baseline: dominantHost, deviation: currentHost === dominantHost ? 0.28 : 0.91 },
          { feature: '活动时间', current: latest?.start || '—', baseline: entity.toLowerCase().includes('svc') ? '08:00-18:00' : '09:00-19:00', deviation: timeToMinutes(latest?.start || '09:00:00') < 6 * 60 ? 0.88 : 0.42 },
          { feature: '关键行为', current: latestAction, baseline: linked[0]?.anchorEvent.action || 'LOGIN', deviation: latestAction === linked[0]?.anchorEvent.action ? 0.34 : 0.79 },
          { feature: 'User→Host', current: `${entity} → ${currentHost}`, baseline: `${entity} → ${dominantHost}`, deviation: currentHost === dominantHost ? 0.31 : 0.93 },
        ],
        findingIds: linked.map((finding) => finding.id),
      }
    })
    .sort((a, b) => b.rareRelations - a.rareRelations)
}

export function initialCaseBoards(cases: Investigation[] = investigations) {
  return cases.reduce<Record<string, CaseBoard>>((result, investigation) => {
    result[investigation.id] = {}
    investigation.windowIds.forEach((findingId, index) => {
      result[investigation.id][findingId] = index < 2 ? 'main' : index < 4 ? 'candidate' : 'excluded'
    })
    return result
  }, {})
}
