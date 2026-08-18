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

type LinkEvidenceScore = {
  candidate: AnomalyWindow
  score: number
  anchor: string
  anchorStrength: 'Strong' | 'Medium' | 'Weak'
  entityRarity: number
  actionCompatibility: number
  graphSimilarity: number
  timeGapMinutes: number
}

const RISK_SCORING_VERSION = 'weak_fusion_v2'
const RISK_FUSION_WEIGHTS = { event: 0.36, local: 0.29, long: 0.35 } as const

function actionFamily(value?: string) {
  const action = (value || '').toUpperCase()
  if (/LOGIN|LOGON|AUTH|PASSWORD|SESSION/.test(action)) return 'authentication'
  if (/PROCESS|EXEC|COMMAND|SHELL|SUDO|SU\b/.test(action)) return 'execution'
  if (/NETWORK|DNS|CONNECT|PORT|HTTP|TLS/.test(action)) return 'network'
  if (/FILE|ARCHIVE|WRITE|READ|UPLOAD/.test(action)) return 'file'
  if (/USERADD|GROUP|ACCOUNT|PRIVILEGE|TOKEN/.test(action)) return 'identity'
  return 'other'
}

function anchorWeight(entity: string) {
  const type = inferEntityType(entity)
  if (type === 'User' || type === 'Process') return 1
  if (type === 'Host') return 0.5
  if (type === 'Asset') return 0.35
  return 0
}

function multiscaleTimeDecay(deltaMinutes: number) {
  const hours = Math.max(deltaMinutes, 0) / 60
  const horizons = [1, 24, 168, 720]
  return horizons.reduce((sum, horizon) => sum + Math.exp(-hours / horizon), 0) / horizons.length
}

function entityFrequency(windows: AnomalyWindow[]) {
  const frequencies = new Map<string, number>()
  windows.forEach((window) => {
    new Set(window.entities).forEach((entity) => frequencies.set(entity, (frequencies.get(entity) || 0) + 1))
  })
  return frequencies
}

function entityRarity(entity: string, frequencies: Map<string, number>, total: number) {
  if (!entity || total <= 1) return 0
  const frequency = frequencies.get(entity) || 0
  return clamp(Math.log((total + 1) / (frequency + 1)) / Math.log(total + 1), 0, 1)
}

function scoreWindowLink(
  current: AnomalyWindow,
  candidate: AnomalyWindow,
  frequencies: Map<string, number>,
  total: number,
): LinkEvidenceScore {
  const shared = intersect(current.entities, candidate.entities)
  const rankedAnchors = shared
    .map((entity) => ({ entity, weight: anchorWeight(entity), rarity: entityRarity(entity, frequencies, total) }))
    .sort((left, right) => (right.weight * right.rarity) - (left.weight * left.rarity))
  const bestAnchor = rankedAnchors[0]
  const weightedAnchorEvidence = rankedAnchors.reduce((sum, item) => sum + item.weight * item.rarity, 0)
  const anchorEvidence = 1 - Math.exp(-weightedAnchorEvidence)
  const timeGapMinutes = Math.abs(timeToMinutes(current.start) - timeToMinutes(candidate.start))
  const timeEvidence = multiscaleTimeDecay(timeGapMinutes)
  const currentFamily = actionFamily(anchorEvent(current).action)
  const candidateFamily = actionFamily(anchorEvent(candidate).action)
  const actionCompatibility = currentFamily === candidateFamily ? 1 : currentFamily === 'other' || candidateFamily === 'other' ? 0.2 : 0
  const unionSources = new Set([...current.sourceTypes, ...candidate.sourceTypes])
  const crossSourceEvidence = unionSources.size >= 2 ? 1 : 0.15
  const unionEntities = new Set([...current.entities, ...candidate.entities])
  const graphSimilarity = unionEntities.size ? shared.length / unionEntities.size : 0
  const evidenceQuality = Math.min(1, Math.log2(2 + current.events.length + candidate.events.length) / 4)
  const score = clamp(
    anchorEvidence * 0.4
      + timeEvidence * 0.2
      + actionCompatibility * 0.15
      + crossSourceEvidence * 0.15
      + evidenceQuality * 0.1,
    0,
    1,
  )
  const type = bestAnchor ? inferEntityType(bestAnchor.entity) : 'IP'
  return {
    candidate,
    score,
    anchor: bestAnchor?.entity || shared[0] || '—',
    anchorStrength: type === 'User' || type === 'Process' ? 'Strong' : type === 'Host' ? 'Medium' : 'Weak',
    entityRarity: bestAnchor?.rarity || 0,
    actionCompatibility,
    graphSimilarity,
    timeGapMinutes,
  }
}

export function inferEntityType(entity: string): EntityKind {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(entity)) return 'IP'
  if (/host|srv|ws-|fs-|app-/i.test(entity)) return 'Host'
  if (/\.(exe|dat)$/i.test(entity) || /^(sudo|su|useradd|sshd|systemd|kernel|metricbeat|auditd|python\d*|bash|sh|powershell|cmd)$/i.test(entity)) return 'Process'
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

// 计算除案件归属（caseId）外的全部证据字段：实体稀有度、三层分数、M5 关联依据、
// 远程候选等。这部分只依赖窗口数据，是 O(n²) 的关联分析；案件编辑（插入/排除节点）
// 不会改变这些字段，因此应由调用方独立缓存，避免每次拖拽节点都全量重算。
export function buildFindingEvidence(
  windows: AnomalyWindow[] = anomalyWindows,
): FindingRecord[] {
  const frequencies = entityFrequency(windows)
  return windows.map<FindingRecord>((window) => {
    const peers = windows.filter((item) => item.id !== window.id && intersect(item.entities, window.entities).length > 0)
    const anchor = anchorEvent(window)
    const primary = primaryEntity(window)
    const linkEvidence = peers
      .map((candidate) => scoreWindowLink(window, candidate, frequencies, windows.length))
      .sort((left, right) => right.score - left.score)
    const bestLink = linkEvidence[0]
    const topLinks = linkEvidence.slice(0, 3)
    const linkWeights = [0.55, 0.3, 0.15]
    const linkWeightTotal = topLinks.reduce((sum, _item, index) => sum + linkWeights[index], 0) || 1
    const linkAggregate = topLinks.reduce((sum, item, index) => sum + item.score * linkWeights[index], 0) / linkWeightTotal
    const baseScore = clamp(window.score, 0, 1)
    const fieldCoverage = [
      window.events.some((event) => Boolean(event.actor)),
      window.events.some((event) => Boolean(event.process || event.ip)),
      window.entities.length >= 2,
      window.events.every((event) => Boolean(event.raw)),
    ].filter(Boolean).length / 4
    const eventScore = clamp(baseScore * 0.82 + fieldCoverage * 0.18, 0.03, 0.98)
    const contextDensity = 1 - Math.exp(-Math.max(window.eventCount, window.events.length) / 6)
    const sourceDiversity = Math.min(1, window.sourceTypes.length / 2)
    const entityDiversity = Math.min(1, new Set(window.entities.map(inferEntityType)).size / 4)
    const localScore = clamp(baseScore * 0.46 + contextDensity * 0.2 + sourceDiversity * 0.18 + entityDiversity * 0.16, 0.03, 0.96)
    const primaryRarity = entityRarity(primary, frequencies, windows.length)
    const longScore = clamp(baseScore * 0.28 + linkAggregate * 0.57 + primaryRarity * 0.15, 0.02, 0.96)
    // 综合风险 = M6 风险融合分数：实时上传数据直接用后端模块分数；
    // 历史回放数据无 M6 分层，使用三层融合投影（连续、有区分度）。
    const risk = window.moduleScores?.M6 !== undefined
      ? Math.round(clamp(window.moduleScores.M6, 0, 1) * 100)
      : Math.round((
          eventScore * RISK_FUSION_WEIGHTS.event
          + localScore * RISK_FUSION_WEIGHTS.local
          + longScore * RISK_FUSION_WEIGHTS.long
        ) * 100)
    const rarity = bestLink?.entityRarity ?? primaryRarity
    const compatibility = bestLink?.actionCompatibility ?? 0
    const graphSimilarity = bestLink?.graphSimilarity ?? 0
    const timeGap = bestLink ? formatGap(bestLink.timeGapMinutes) : '无可用关联'
    const strength = bestLink?.anchorStrength || 'Weak'

    return {
      id: window.id,
      caseId: undefined,
      title: window.title,
      severity: window.severity,
      status: window.status,
      risk,
      eventScore: toPercent(eventScore),
      localScore: toPercent(localScore),
      longScore: toPercent(longScore),
      reasons: deriveReasons(window, linkEvidence.filter((item) => item.score >= 0.5).length),
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
      relatedCandidates: linkEvidence.slice(0, 4).map((item) => ({
        id: item.candidate.id,
        title: item.candidate.title,
        time: item.candidate.start,
        reasons: linkReasons(window, item.candidate),
      })),
      association: {
        confidence: bestLink?.score || 0,
        sharedAnchor: bestLink?.anchor || primary,
        anchorStrength: strength,
        entityRarity: rarity,
        actionCompatibility: compatibility,
        graphSimilarity,
        timeGap,
        summary: [
          `${bestLink?.anchor || primary} 作为${strength === 'Strong' ? '强' : strength === 'Medium' ? '中' : '弱'}锚点参与关联；高频公共实体已通过 IDF 稀有度降权。`,
          `多尺度时间衰减同时考察 1h、24h、7d、30d，当前最佳关联间隔 ${timeGap}。`,
          `评分版本 ${RISK_SCORING_VERSION}：实体稀有度 ${toPercent(rarity)}，行为兼容度 ${toPercent(compatibility)}，图相似度 ${toPercent(graphSimilarity)}。`,
        ],
      },
    }
  })
}

// 轻量地为每条 finding 补上案件归属（caseId）：O(n·m)，只随案件列表变化而重算。
// 与 buildFindingEvidence 拆分，使重计算（关联证据）与轻计算（归属）解耦。
export function attachCaseIds(
  findings: FindingRecord[],
  cases: Investigation[] = investigations,
): FindingRecord[] {
  return findings.map((finding) => ({
    ...finding,
    caseId: cases.find((item) => item.windowIds.includes(finding.id))?.id,
  }))
}

// 兼容旧调用：证据计算 + 归属补齐。新代码请分别使用 buildFindingEvidence 与 attachCaseIds。
export function buildFindings(
  windows: AnomalyWindow[] = anomalyWindows,
  cases: Investigation[] = investigations,
): FindingRecord[] {
  return attachCaseIds(buildFindingEvidence(windows), cases)
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

export function buildEntityProfiles(findings: FindingRecord[], events: SecurityEvent[] = []) {
  const eventEntities = events.flatMap((event) => [event.actor, event.host, event.process, event.ip])
    .filter((value): value is string => Boolean(value))
  const entities = Array.from(new Set([...findings.flatMap((finding) => finding.entities), ...eventEntities]))
  return entities
    .map<EntityProfile>((entity) => {
      const linked = findings.filter((finding) => finding.entities.includes(entity))
      const ordered = [...linked].sort((a, b) => timeToMinutes(a.start) - timeToMinutes(b.start))
      const linkedEvents = events
        .filter((event) => [event.actor, event.host, event.process, event.ip].includes(entity))
        .sort((left, right) => timeToMinutes(left.time) - timeToMinutes(right.time))
      const hosts = [
        ...linked.flatMap((finding) => finding.events.map((event) => event.host).filter(Boolean) as string[]),
        ...linkedEvents.map((event) => event.host).filter((value): value is string => Boolean(value)),
      ]
      const uniqueHosts = Array.from(new Set(hosts))
      const hostHistory = uniqueHosts.map((host, index) => ({
        host,
        count: Math.max(
          linkedEvents.filter((event) => event.host === host).length,
          linked.filter((finding) => finding.host === host).reduce((sum, finding) => sum + finding.events.length, 0) * 8 + 4,
        ),
        isNew: index >= 1,
      })).sort((a, b) => b.count - a.count)
      const latest = ordered[ordered.length - 1]
      const latestEvent = linkedEvents[linkedEvents.length - 1]
      const firstSeen = [ordered[0]?.start, linkedEvents[0]?.time].filter(Boolean).sort()[0] || '—'
      const lastSeen = [latest?.end, latestEvent?.time].filter(Boolean).sort().slice(-1)[0] || '—'
      const dominantHost = hostHistory[0]?.host || '—'
      const currentHost = latest?.host || latestEvent?.host || '—'
      const latestAction = latest?.anchorEvent.action || latestEvent?.action || '—'
      const observedType: EntityKind = events.some((event) => event.ip === entity)
        ? 'IP'
        : events.some((event) => event.host === entity)
          ? 'Host'
          : events.some((event) => event.process === entity)
            ? 'Process'
            : inferEntityType(entity)

      return {
        id: entity,
        type: observedType,
        firstSeen,
        lastSeen,
        thirtyDayEvents: Math.max(linkedEvents.length, linked.reduce((sum, finding) => sum + finding.events.length * 12, 0)),
        normalLoginHosts: Math.max(hostHistory.length - 1, 1),
        currentLoginHosts: hostHistory.length || 1,
        newHostRelations: Math.max(hostHistory.filter((item) => item.isNew).length, 0),
        rareRelations: linked.filter((finding) => finding.longScore >= 75).length,
        usualLogin: entity.toLowerCase().includes('svc') ? '08:00-18:00' : '09:00-19:00',
        currentActivity: latest?.start || latestEvent?.time || '—',
        hostHistory,
        baseline: [
          { feature: '登录主机', current: currentHost, baseline: dominantHost, deviation: currentHost === dominantHost ? 0.28 : 0.91 },
          { feature: '活动时间', current: latest?.start || latestEvent?.time || '—', baseline: entity.toLowerCase().includes('svc') ? '08:00-18:00' : '09:00-19:00', deviation: timeToMinutes(latest?.start || latestEvent?.time || '09:00:00') < 6 * 60 ? 0.88 : 0.42 },
          { feature: '关键行为', current: latestAction, baseline: linked[0]?.anchorEvent.action || 'LOGIN', deviation: latestAction === linked[0]?.anchorEvent.action ? 0.34 : 0.79 },
          { feature: 'User→Host', current: `${entity} → ${currentHost}`, baseline: `${entity} → ${dominantHost}`, deviation: currentHost === dominantHost ? 0.31 : 0.93 },
        ],
        findingIds: linked.map((finding) => finding.id),
      }
    })
    .filter((profile) => profile.findingIds.length > 0
      || profile.type === 'Host'
      || profile.type === 'IP'
      || profile.thirtyDayEvents >= 8)
    .sort((a, b) => b.rareRelations - a.rareRelations)
}

export function initialCaseBoards(cases: Investigation[] = investigations) {
  return cases.reduce<Record<string, CaseBoard>>((result, investigation) => {
    result[investigation.id] = {}
    // 待人工研判案件：windowIds 是已确认的骨架段，全部归入主链；缺失环节由 gapEvidenceIds 单独呈现。
    if (investigation.gapEvidenceIds?.length) {
      investigation.windowIds.forEach((findingId) => {
        result[investigation.id][findingId] = 'main'
      })
      return result
    }
    investigation.windowIds.forEach((findingId, index) => {
      if (investigation.id === 'CASE-XLOG-30D-001') {
        // The current event and the oldest recovered anchor form the two
        // verified endpoints; intermediate stages remain candidates until an
        // analyst promotes or excludes them.
        result[investigation.id][findingId] = index === 0 || index === investigation.windowIds.length - 1
          ? 'main'
          : 'candidate'
        return
      }
      // 自动关联链与人工整理链统一按证据强度分层：前 2 条为当前主链、
      // 中间为候选、末尾为已排除。保证每条案件在主链/候选/排除三区都有内容。
      result[investigation.id][findingId] = index < 2 ? 'main' : index < 4 ? 'candidate' : 'excluded'
    })
    return result
  }, {})
}
