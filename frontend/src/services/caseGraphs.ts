import type { SecurityEvent } from '../mocks/data'
import type { FindingRecord } from './investigationDomain'

export type CaseGraphNode = {
  id: string
  name: string
  category: number
  kind: 'event' | 'entity' | 'window' | 'technique'
  timestamp?: string
  description?: string
  originalName?: string
  details?: string[]
  tactic?: string
  x?: number
  y?: number
}

type AttackTechnique = {
  id: string
  name: string
  tactic: string
  reason: string
}

export type CaseGraphLink = {
  source: string
  target: string
  label?: string
  relation: string
  weight?: number
  evidence?: string
  explanation?: string
  boundary?: string
}

export type M3GraphSnapshot = {
  findingId: string
  findingTitle: string
  start: string
  end: string
  windowLabel: string
  nodes: CaseGraphNode[]
  links: CaseGraphLink[]
  savedAt: string
}

const STORAGE_KEY = 'wad-demo-m3-graph-snapshots-v1'

export const GRAPH_EXPLANATION_PROMPT = '解释安全图中的实体和事件关系：说清原始日志表示什么、关键字段如何拆解、关联实体扮演什么角色、边依据什么事实建立，以及哪些结论仍需核验；只使用给定日志事实，不把关联直接表述为已确认攻击。'

function eventName(event: SecurityEvent) {
  const raw = String(event.raw || event.action || '未归一化事件')
  const value = String(event.action || event.raw || '未归一化事件').replace(/^\S+\s+\S+\s+\S+\s+/, '').trim()
  if (/add .*shadow group/i.test(value)) return '加入 shadow 组'
  if (/useradd|new user|account create/i.test(value)) return '创建用户账户'
  if (/session opened|login success|accepted password/i.test(value)) return '登录成功'
  if (/session closed|logout/i.test(value)) return '登录会话结束'
  if (/failed password|authentication failure|login failed/i.test(value)) return '登录失败'
  if (/sudo|privilege/i.test(value)) return '权限使用或提升'
  if (/starting\s+network\s+service/i.test(raw)) return '启动网络服务'
  if (/reached target/i.test(raw)) return '系统服务目标就绪'
  if (/metricbeat.*system\.network/i.test(raw)) return '采集网络指标'
  if (/nodev after polling|after polling detection/i.test(raw)) return '设备轮询未发现'
  if (/dns (query|request|lookup)|query.*dns/i.test(raw)) return 'DNS 查询'
  if (/network[_ ]?(connect|connection)|outbound connection/i.test(raw)) return '建立网络连接'
  if (/file (access|open|read)|sensitive file/i.test(raw)) return '访问文件'
  if (/waf|request blocked|malicious request/i.test(raw)) return '拦截可疑请求'
  if (/command|exec|process/i.test(value)) return '执行命令或进程'
  return value.length > 34 ? `${value.slice(0, 34)}…` : value
}

function eventNodeName(event: SecurityEvent) {
  const action = eventName(event)
  const raw = String(event.raw || event.action || '')
  const actor = event.actor
    || raw.match(/(?:for user|user=|user\s+)([\w.@-]+)/i)?.[1]
    || raw.match(/sudo:\s+([\w.@-]+)/i)?.[1]
  const command = raw.match(/COMMAND=([^\s]+(?:\s+[^;|]+)?)/i)?.[1]?.trim()
  const commandName = command?.split(/[\\/]/).pop()?.split(/\s+/)[0]
  const participant = actor || commandName || event.process || event.ip
  const label = participant && !action.toLowerCase().includes(participant.toLowerCase())
    ? `${action} · ${participant}`
    : action
  return label.length > 28 ? `${label.slice(0, 28)}…` : label
}

function eventDescription(event: SecurityEvent) {
  const participants = [event.actor, event.host, event.process || event.ip].filter(Boolean).join(' · ')
  return participants ? `事件主体：${participants}` : '事件主体待解析'
}

function eventMeaning(event: SecurityEvent) {
  const name = eventName(event)
  if (name === '执行命令或进程') return '表示某个主体在主机上启动或执行了命令/进程，重点关注执行主体、程序来源和执行结果。'
  if (name === '加入 shadow 组') return '表示用户被加入可读取敏感账户信息的系统组，属于账户权限变化，需要核对操作者和变更前后状态。'
  if (name === '创建用户账户') return '表示系统新增了用户账户或账户属性，需核对创建者、账户用途和后续登录活动。'
  if (name === '登录成功') return '表示身份认证成功并建立登录会话，需结合来源地址、账户和后续操作判断是否异常。'
  if (name === '登录失败') return '表示一次身份认证失败，单条失败不代表攻击，需要结合频率、来源和后续成功登录判断。'
  if (name === '权限使用或提升') return '表示进程或账户使用了较高权限，需核对权限来源、执行程序和目标资源。'
  return `表示系统记录了一次“${name}”行为，需结合参与实体和前后事件理解其作用。`
}

function eventFactExplanation(event: SecurityEvent, entity: string) {
  const raw = String(event.raw || event.action || '').trim()
  const sudoUser = raw.match(/sudo:\s+(\S+)/i)?.[1]
  const targetUser = raw.match(/USER=(\S+)/i)?.[1]
  const command = raw.match(/COMMAND=(.*)$/i)?.[1]?.trim()
  const role = event.actor === entity ? `“${entity}”是发起操作的用户` : event.host === entity ? `“${entity}”是承载操作的主机` : event.process === entity ? `“${entity}”是被执行的进程` : event.ip === entity ? `“${entity}”是网络地址或通信对端` : `“${entity}”是日志中出现的相关实体`
  if (sudoUser || targetUser || command) {
    return limitGraphExplanation(`原始日志表示：用户${sudoUser || event.actor || '未知'}通过sudo在主机${event.host || '未知'}上切换到${targetUser || '目标账户'}，执行${command || event.process || '命令'}。字段拆解：${role}，目标账户是${targetUser || '未知'}。该边说明事件与实体的事实归属，不单独证明攻击。`)
  }
  return limitGraphExplanation(`原始日志表示系统记录了一次“${eventName(event)}”行为。字段拆解：${role}，时间为${event.time}，行为主体为${event.actor || '未知'}，主机为${event.host || '未知'}。该边只说明事件与实体的事实关系，不单独证明攻击。`)
}

function eventSequenceExplanation(previous: SecurityEvent, current: SecurityEvent) {
  return limitGraphExplanation(`前一条日志表示“${eventName(previous)}”，时间为${previous.time}；后一条日志表示“${eventName(current)}”，时间为${current.time}。两条日志按时间先后连接，用于还原行为顺序，不单独证明因果或攻击。`)
}

function possibleMaliciousUse(event: SecurityEvent) {
  const name = eventName(event)
  if (name === '权限使用或提升' || /sudo|USER=root|privilege/i.test(event.raw || '')) return '若来源用户未经授权，可能是权限提升链中的执行环节。'
  if (name === '加入 shadow 组') return '若变更未获授权，可能扩大敏感账户信息读取能力。'
  if (name === '创建用户账户') return '若账户由异常主体创建，可能用于持久化或后续登录。'
  if (name === '执行命令或进程') return '若命令来自异常会话，可能是执行阶段或后续攻击动作的证据。'
  if (name === '登录成功' || name === '登录失败') return '只有结合异常来源、频率和后续操作时，才可能支持入侵或凭据滥用判断。'
  return ''
}

function entityPairExplanation(event: SecurityEvent, first: string, second: string) {
  const firstRole = event.actor === first ? '发起用户' : event.host === first ? '承载主机' : event.process === first ? '执行进程' : event.ip === first ? '网络地址' : '相关实体'
  const secondRole = event.actor === second ? '发起用户' : event.host === second ? '承载主机' : event.process === second ? '执行进程' : event.ip === second ? '网络地址' : '相关实体'
  const possibility = possibleMaliciousUse(event)
  return limitGraphExplanation(`原始日志记录“${eventName(event)}”：${event.raw || event.action}。字段拆解：${first}是${firstRole}，${second}是${secondRole}，两者在同一事件中共同出现，因此建立实体关系。${possibility}`)
}

export function limitGraphExplanation(value: string) {
  return value
}

function compactEventNodeName(value: string) {
  const text = value.replace(/^\d+\.\s*/, '')
  return eventNodeName({ id: '', time: '', action: text, raw: text } as SecurityEvent)
}

function eventRelevanceScore(event: SecurityEvent, anchor: SecurityEvent, anchorTime: number) {
  const text = `${event.action || ''} ${event.raw || ''}`
  const anchorEntities = new Set([anchor.actor, anchor.host, anchor.process, anchor.ip].filter(Boolean))
  const eventEntities = [event.actor, event.host, event.process, event.ip].filter(Boolean)
  const sharedEntityBoost = eventEntities.some((entity) => anchorEntities.has(entity)) ? 0.24 : 0
  const behaviorBoost = /sudo|USER=root|privilege|shadow group|useradd|new user|account create|command|exec|process|failed password|authentication failure/i.test(text) ? 0.38 : /login|session opened|accepted password/i.test(text) ? 0.18 : 0.06
  const explicitScore = Number((event as SecurityEvent & { score?: number }).score)
  const modelBoost = Number.isFinite(explicitScore) ? Math.max(0, Math.min(1, explicitScore > 1 ? explicitScore / 100 : explicitScore)) * 0.3 : 0
  const eventTime = Date.parse(event.time)
  const distance = Number.isFinite(anchorTime) && Number.isFinite(eventTime) ? Math.abs(anchorTime - eventTime) : 30 * 60 * 1000
  const timeBoost = Math.max(0, 1 - distance / (30 * 60 * 1000)) * 0.16
  return Math.min(1, behaviorBoost + sharedEntityBoost + modelBoost + timeBoost)
}

export function buildM3GraphSnapshot(finding: FindingRecord): M3GraphSnapshot {
  const anchorTime = Date.parse(finding.anchorEvent?.time || finding.start)
  const events = (Array.isArray(finding.events) ? finding.events : []).filter((event) => {
    const eventTime = Date.parse(event.time)
    if (!Number.isFinite(anchorTime) || !Number.isFinite(eventTime)) return event.id === finding.anchorEvent?.id
    return eventTime >= anchorTime - 30 * 60 * 1000 && eventTime <= anchorTime
  })
  const anchor = finding.anchorEvent || events[events.length - 1]
  const rankedEvents = [...events].sort((left, right) => eventRelevanceScore(right, anchor || right, anchorTime) - eventRelevanceScore(left, anchor || left, anchorTime))
  const selectedEvents = rankedEvents.slice(0, 15)
  const currentEvent = anchor && !selectedEvents.some((event) => event.id === anchor.id) ? [anchor, ...selectedEvents.slice(0, 14)] : selectedEvents
  currentEvent.sort((left, right) => Date.parse(left.time) - Date.parse(right.time))
  const eventNodes: CaseGraphNode[] = currentEvent.map((event, index) => ({
    id: `${finding.id}:event:${event.id}`,
    name: `${index + 1}. ${eventNodeName(event)}`,
    category: 0,
    kind: 'event',
    timestamp: event.time,
    description: eventDescription(event),
    details: [`事件含义：${eventMeaning(event)}`, `事件时间：${event.time}`, `关联筛选分：${eventRelevanceScore(event, anchor || event, anchorTime).toFixed(2)}`, `原始日志：${event.raw || event.action || '暂无'}`],
  }))
  const entityNames = Array.from(new Set(currentEvent.flatMap((event) => [event.actor, event.host, event.process, event.ip].filter(Boolean) as string[])))
  const entityNodes: CaseGraphNode[] = entityNames.map((entity) => ({
    id: `${finding.id}:entity:${entity}`,
    name: entity,
    category: 1,
    kind: 'entity',
    originalName: entity,
    description: `安全事件中解析出的实体：${entity}。`,
    details: ['实体类型：安全事件参与者', `原始名称：${entity}`],
  }))
  const links: CaseGraphLink[] = []
  currentEvent.forEach((event, index) => {
    const eventId = `${finding.id}:event:${event.id}`
    const relevanceScore = eventRelevanceScore(event, anchor || event, anchorTime)
    const eventEntities = Array.from(new Set([event.actor, event.host, event.process, event.ip].filter((entity): entity is string => Boolean(entity))))
    eventEntities.forEach((entity) => {
      links.push({
        source: eventId,
        target: `${finding.id}:entity:${entity}`,
        relation: '事件涉及实体',
        label: '涉及',
        weight: relevanceScore,
        evidence: `日志事实：${event.time}，行为为“${eventName(event)}”，其中出现实体“${entity}”。因此建立事件与实体的直接关系。`,
        explanation: eventFactExplanation(event, entity),
        boundary: '只能确认该实体出现在该事件中，不能单独证明恶意意图。',
      })
    })
    for (let firstIndex = 0; firstIndex < eventEntities.length; firstIndex += 1) {
      for (let secondIndex = firstIndex + 1; secondIndex < eventEntities.length; secondIndex += 1) {
        const first = eventEntities[firstIndex]
        const second = eventEntities[secondIndex]
        if (!first || !second) continue
        links.push({
          source: `${finding.id}:entity:${first}`,
          target: `${finding.id}:entity:${second}`,
          relation: '同一事件共同参与',
          label: '共同参与',
          weight: relevanceScore,
          evidence: `日志事实：${event.time} 的“${eventName(event)}”同时出现实体“${first}”和“${second}”，因此建立共同参与关系。`,
          explanation: entityPairExplanation(event, first, second),
          boundary: '共同出现只说明同一事件中的角色联系，不能单独证明两个实体属于同一攻击者。',
        })
      }
    }
    if (index > 0) {
      const previous = events[index - 1]
      if (!previous) return
      links.push({
        source: `${finding.id}:event:${previous.id}`,
        target: eventId,
        relation: '时间先后',
        label: '先于',
        weight: Math.max(relevanceScore, eventRelevanceScore(previous, anchor || previous, anchorTime)),
        evidence: `日志事实：前一事件在 ${previous.time}，行为为“${eventName(previous)}”；后一事件在 ${event.time}，行为为“${eventName(event)}”。因此按时间顺序建立先后关系。`,
        explanation: eventSequenceExplanation(previous, event),
        boundary: '时间先后不等于因果关系，仍需结合实体和行为内容判断。',
      })
    }
  })
  return {
    findingId: finding.id,
    findingTitle: finding.title,
    start: finding.start,
    end: finding.end,
    windowLabel: `当前事件前后 30 分钟事实窗口 · ${finding.start}`,
    nodes: eventNodes.concat(entityNodes),
    links: links.map((link) => link.explanation ? { ...link, explanation: limitGraphExplanation(link.explanation) } : link),
    savedAt: new Date().toISOString(),
  }
}

export function normalizeM3GraphSnapshot(snapshot: M3GraphSnapshot): M3GraphSnapshot {
  const nodes = snapshot.nodes.map((node) => {
    if (node.kind === 'event') {
      const rawDetail = node.details?.find((item) => item.startsWith('原始日志：') || item.startsWith('原始事件：'))
      const rawEvent = rawDetail?.replace(/^(原始日志|原始事件)：/, '') || compactEventNodeName(node.name)
      const meaning = node.details?.find((item) => item.startsWith('事件含义：')) || `事件含义：${eventMeaning({ id: node.id, time: node.timestamp || '', action: rawEvent, raw: rawEvent } as SecurityEvent)}`
      const semanticName = eventNodeName({ id: node.id, time: node.timestamp || '', action: rawEvent, raw: rawEvent } as SecurityEvent)
      return {
        ...node,
        name: semanticName,
        description: node.description?.replace(/\s*原始事件：.*$/, '') || `事件摘要：${semanticName}`,
        details: [meaning, `事件时间：${node.timestamp || '未知'}`, rawDetail || `原始日志：${rawEvent}`],
      }
    }
    if (node.kind !== 'entity') return node
    const original = node.description?.match(/^原始实体：([^。]+)/)?.[1] || node.name
    return {
      ...node,
      name: original,
      originalName: original,
      description: `安全事件中解析出的实体：${original}。`,
      details: [`实体类型：安全事件参与者`, `原始名称：${original}`],
    }
  })
  const nodeById = new Map(nodes.map((node) => [node.id, node]))
  const normalizedLinks = snapshot.links.map((link) => {
      const source = nodeById.get(link.source)
      const target = nodeById.get(link.target)
      if (link.relation === '事件涉及实体' && source?.kind === 'event' && target?.kind === 'entity') {
        const meaning = source.details?.find((item) => item.startsWith('事件含义：')) || `事件节点 ${source.name} 的行为需要结合原始日志核对。`
        const raw = source.details?.find((item) => item.startsWith('原始日志：'))?.replace(/^原始日志：/, '') || meaning.replace(/^事件含义：/, '')
        return { ...link, explanation: eventFactExplanation({ id: source.id, time: source.timestamp || '', action: raw, raw, host: target.originalName || target.name } as SecurityEvent, target.originalName || target.name) }
      }
      if (link.relation === '时间先后' && source?.kind === 'event' && target?.kind === 'event') {
        const sourceMeaning = source.details?.find((item) => item.startsWith('事件含义：')) || `前一事件 ${source.name}`
        const targetMeaning = target.details?.find((item) => item.startsWith('事件含义：')) || `后一事件 ${target.name}`
        return { ...link, explanation: eventSequenceExplanation({ id: source.id, time: source.timestamp || '', action: sourceMeaning, raw: sourceMeaning } as SecurityEvent, { id: target.id, time: target.timestamp || '', action: targetMeaning, raw: targetMeaning } as SecurityEvent) }
      }
      return link
    })
  const existingPairs = new Set(normalizedLinks.filter((link) => link.relation === '同一事件共同参与').map((link) => `${link.source}|${link.target}`))
  const addedPairs: CaseGraphLink[] = []
  const eventEntityGroups = new Map<string, string[]>()
  normalizedLinks.filter((link) => link.relation === '事件涉及实体').forEach((link) => {
    const group = eventEntityGroups.get(link.source) || []
    group.push(link.target)
    eventEntityGroups.set(link.source, group)
  })
  eventEntityGroups.forEach((entityIds, eventId) => {
    const event = nodeById.get(eventId)
    const eventRaw = event?.details?.find((item) => item.startsWith('原始日志：'))?.replace(/^原始日志：/, '') || event?.name || '事件'
    for (let firstIndex = 0; firstIndex < entityIds.length; firstIndex += 1) {
      for (let secondIndex = firstIndex + 1; secondIndex < entityIds.length; secondIndex += 1) {
        const first = entityIds[firstIndex]
        const second = entityIds[secondIndex]
        if (!first || !second || existingPairs.has(`${first}|${second}`)) continue
        addedPairs.push({ source: first, target: second, relation: '同一事件共同参与', label: '共同参与', weight: 0.75, evidence: `同一事件${event?.timestamp || ''}同时出现两个实体，原始日志：${eventRaw}`, explanation: limitGraphExplanation(`原始日志记录同一事件同时出现两个实体，说明它们在该事件中存在角色联系。若该事件属于未经授权的提权、账户变更或异常命令执行，可能成为恶意行为链的一环，但当前证据不能单独确认攻击。`), boundary: '共同出现不等于同一攻击者。' })
      }
    }
  })
  return {
    ...snapshot,
    nodes,
    links: normalizedLinks.concat(addedPairs),
  }
}

export function loadM3GraphSnapshots(): Record<string, M3GraphSnapshot> {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    const snapshots = raw ? JSON.parse(raw) as Record<string, M3GraphSnapshot> : {}
    const normalized = Object.fromEntries(Object.entries(snapshots).map(([id, snapshot]) => [id, normalizeM3GraphSnapshot(snapshot)]))
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(normalized))
    return normalized
  } catch {
    return {}
  }
}

export function persistM3GraphSnapshot(snapshot: M3GraphSnapshot) {
  const current = loadM3GraphSnapshots()
  const next = { ...current, [snapshot.findingId]: normalizeM3GraphSnapshot(snapshot) }
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
  return next
}

export function removeM3GraphSnapshot(findingId: string) {
  const current = loadM3GraphSnapshots()
  const next = { ...current }
  delete next[findingId]
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
  return next
}

function attackTechniqueForEvent(event: SecurityEvent): AttackTechnique[] {
  const text = `${event.action || ''} ${event.raw || ''}`
  const techniques: AttackTechnique[] = []
  const add = (id: string, name: string, tactic: string, reason: string) => techniques.push({ id, name, tactic, reason })

  if (/useradd|new user|account create|new account|创建用户/i.test(text)) {
    add('T1136.001', '创建本地账户', '持久化', '日志出现 useradd 或新用户创建字段。')
  }
  if (/shadow group|add .*group|new group|groupadd|group membership/i.test(text)) {
    add('T1098.007', '附加本地或域组', '持久化·权限提升', '日志出现用户加入组或新建用户组字段。')
  }
  if (/sudo|USER=root|privilege|权限提升/i.test(text)) {
    add('T1548.003', 'Sudo 与 Sudo 缓存', '权限提升', '日志出现 sudo、目标高权限账户或权限使用字段。')
  }
  if (/ansible|ansiballz|python\d*|python3/i.test(text)) {
    add('T1059.006', 'Python', '执行', '日志出现 Python 或 Ansible Python 执行路径。')
  } else if (/bash|\/bin\/sh|shell|COMMAND=|command|exec|process|进程|命令/i.test(text)) {
    add('T1059.004', 'Unix Shell', '执行', '日志出现 Shell、命令行、进程或 COMMAND 字段。')
  }
  if (/accepted password|session opened|login success|登录成功|ssh|sshd/i.test(text)) {
    add('T1078', '有效账户', '初始访问·持久化', '日志记录了成功认证或已建立会话。')
  }
  if (/failed password|authentication failure|login failed|登录失败/i.test(text)) {
    add('T1110.001', '密码猜测', '凭证访问', '日志记录认证失败；该映射仅表示候选技术，不等同于确认爆破。')
  }
  if (/shell\.php|webshell|php-fpm|upload.*web|web.*script/i.test(text)) {
    add('T1505.003', 'Web Shell', '持久化·执行', '日志出现 Web 目录脚本、WebShell 或 PHP 执行迹象。')
  }
  if (/network|connect|port|dns|http|https|外联|网络/i.test(text)) {
    add('T1071.001', 'Web 协议', '命令与控制', '日志出现 HTTP、HTTPS 或网络连接行为。')
  }
  if (!techniques.length) add('T1046', '网络服务扫描', '发现', '日志行为未匹配更具体技术，保留为待核验的行为候选。')
  return techniques
}

function attackEventDetails(finding: FindingRecord, event: SecurityEvent, technique: AttackTechnique) {
  const entityValues = [event.actor, event.host, event.process, event.ip].filter(Boolean)
  return [
    `ATT&CK：${technique.id} ${technique.name}`,
    `战术阶段：${technique.tactic}`,
    `事件时间：${event.time}`,
    `事件行为：${event.action || '未归一化行为'}`,
    `用户/主体：${event.actor || '未解析'}`,
    `主机：${event.host || '未解析'}`,
    `进程：${event.process || '未解析'}`,
    `网络地址：${event.ip || '未解析'}`,
    `事件来源：${event.source || finding.source || '未标明'}`,
    `事件实体：${entityValues.length ? entityValues.join('、') : '未解析'}`,
    `关联窗口：${finding.id}；窗口风险：${finding.risk}`,
    `技术映射依据：${technique.reason}`,
    `原始日志：${event.raw || '暂无原始日志'}`,
  ]
}

/**
 * ATT&CK 图只表达指定窗口（默认 24 小时）内可由事实串联的技术证据。
 * 窗口由数据集语义决定：Short 短时突发用 24 小时、Long 长程关联覆盖 7 天，
 * 使长程链包含更多阶段技术、链路自然更长。
 * M3 仍然负责单个当前事件之前 30 分钟的事实图；这里不再把窗口伪装成技术节点。
 */
export function buildAttackChainGraph(findings: FindingRecord[], options?: { windowHours?: number }): { nodes: CaseGraphNode[]; links: CaseGraphLink[] } {
  const allEvents = findings.flatMap((finding) => (Array.isArray(finding.events) ? finding.events.map((event) => ({ finding, event })) : []))
  const uniqueEvents = Array.from(new Map(allEvents.map((item) => [`${item.finding.id}:${item.event.id}`, item])).values())
  const timestamps = uniqueEvents.map(({ event }) => Date.parse(event.time)).filter(Number.isFinite)
  if (!timestamps.length) return { nodes: [], links: [] }
  const windowHours = options?.windowHours ?? 24
  const windowLabel = windowHours >= 168 ? '7天' : windowHours >= 72 ? '3天' : '24小时'
  const endTime = Math.max(...timestamps)
  const startTime = endTime - windowHours * 60 * 60 * 1000
  const scoped = uniqueEvents
    .filter(({ event }) => {
      const time = Date.parse(event.time)
      return Number.isFinite(time) && time >= startTime && time <= endTime
    })
    .sort((left, right) => Date.parse(left.event.time) - Date.parse(right.event.time))

  const techniqueEvents = new Map<string, { technique: AttackTechnique; finding: FindingRecord; event: SecurityEvent }[]>()
  scoped.forEach(({ finding, event }) => {
    attackTechniqueForEvent(event).forEach((technique) => {
      const list = techniqueEvents.get(technique.id) || []
      list.push({ technique, finding, event })
      techniqueEvents.set(technique.id, list)
    })
  })

  const nodes: CaseGraphNode[] = Array.from(techniqueEvents.entries()).map(([id, items], index) => {
    const first = items[0]
    const times = items.map((item) => item.event.time).sort()
    const entitySet = Array.from(new Set(items.flatMap((item) => [item.event.actor, item.event.host, item.event.process, item.event.ip].filter(Boolean))))
    return {
      id: `attack-technique:${id}`,
      name: `${first.technique.id} ${first.technique.name}`,
      category: index === 0 ? 0 : 1,
      kind: 'technique',
      tactic: first.technique.tactic,
      timestamp: first.event.time,
      description: `${first.technique.tactic} · 24小时内 ${items.length} 条证据 · ${times[0]} 至 ${times[times.length - 1]}`,
      details: [
        `技术类型：${first.technique.id} ${first.technique.name}`,
        `ATT&CK 战术：${first.technique.tactic}`,
        `24小时证据数量：${items.length}`,
        `证据时间范围：${times[0]} 至 ${times[times.length - 1]}`,
        `涉及实体：${entitySet.length ? entitySet.join('、') : '未解析'}`,
        ...items.flatMap((item) => attackEventDetails(item.finding, item.event, item.technique)),
      ],
    }
  })

  const links: CaseGraphLink[] = []
  const orderedTechniques = Array.from(techniqueEvents.entries())
    .map(([id, items]) => ({ id, items, firstTime: Math.min(...items.map((item) => Date.parse(item.event.time))) }))
    .sort((left, right) => left.firstTime - right.firstTime)
  // 通用进程名不算有区分度的共享实体，避免解释出现 "sudo、bash" 这类噪音。
  const ENTITY_NOISE = /^(sudo|bash|sh|zsh|nologin|sshd|systemd)$/i
  for (let index = 1; index < orderedTechniques.length; index += 1) {
    const previous = orderedTechniques[index - 1]
    const current = orderedTechniques[index]
    const previousEvent = previous.items[previous.items.length - 1]
    const currentEvent = current.items[0]
    const shared = Array.from(new Set([
      previousEvent.event.actor, previousEvent.event.host, previousEvent.event.process, previousEvent.event.ip,
    ].filter((entity): entity is string => Boolean(entity)))).filter((entity) => [currentEvent.event.actor, currentEvent.event.host, currentEvent.event.process, currentEvent.event.ip].includes(entity) && !ENTITY_NOISE.test(entity))
    const gap = (Date.parse(currentEvent.event.time) - Date.parse(previousEvent.event.time)) / 1000
    const overlap = gap < 0
    const gapMinutes = Math.round(Math.abs(gap) / 60)
    const gapText = overlap ? '时间重叠'
      : gapMinutes >= 1440 ? `${Math.round(gapMinutes / 1440)}d`
      : gapMinutes >= 60 ? `${Math.round(gapMinutes / 60)}h`
      : `${gapMinutes}m`
    const sourceName = `${previousEvent.technique.id} ${previousEvent.technique.name}`
    const targetName = `${currentEvent.technique.id} ${currentEvent.technique.name}`
    const sharedEntity = shared[0] || ''
    const entityType = /^(\d{1,3}\.){3}\d{1,3}$/.test(sharedEntity) ? 'IP'
      : /server|host|workstation|desktop/i.test(sharedEntity) ? '主机'
      : '账号'
    const prevTime = formatEvidenceTime(previousEvent.event.time)
    const currTime = formatEvidenceTime(currentEvent.event.time)
    const gapInfo = overlap ? '技术时间范围重叠' : `时间间隔 ${gapText}`
    links.push({
      source: `attack-technique:${previous.id}`,
      target: `attack-technique:${current.id}`,
      relation: shared.length ? '共享实体的技术先后关系' : `${windowLabel}内技术先后关系`,
      label: shared.length ? `同一${entityType} · ${sharedEntity}` : (overlap ? '时间重叠' : `间隔 · ${gapText}`),
      weight: shared.length ? 1 : 0.72,
      evidence: `${prevTime} ${sourceName}；${currTime} ${targetName}；${gapInfo}${shared.length ? `；共享实体：${shared.join('、')}` : ''}`,
      explanation: `前序技术“${sourceName}”在 ${prevTime} 出现，后续技术“${targetName}”在 ${currTime} 出现，${gapInfo.toLowerCase() === '时间重叠' ? '两者时间范围有重叠' : `两者相隔 ${gapText}`}。${shared.length ? `两者共享实体 ${shared.join('、')}，因此具备更强的事件连续性。` : `两者仅依据 ${windowLabel} 内的时间顺序连接，仍需核对实体和原始日志。`}该边表示 ATT&CK 技术证据的可能发展顺序，不代表已经确认攻击链。`,
      boundary: '技术映射来自日志行为规则和当前演示数据；必须结合原始日志、实体上下文和授权情况进行人工确认。',
    })
  }
  return { nodes, links }
}

function formatEvidenceTime(value: string) {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return value
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/**
 * ATT&CK 攻击链图布局：采用轻量力导向模拟让节点自然散开——
 * 相邻技术按时间顺序被边牵引，无直接关联的节点互相排斥，
 * 保留"时间从左到右推进"的流向感，同时避免整齐的行列排布。
 * 返回的坐标作为默认布局，用户拖拽后的位置会覆盖默认值。
 */
const LAYOUT_WIDTH = 1000
const LAYOUT_HEIGHT = 640
const LAYOUT_ITERATIONS = 260
const REST_LENGTH = 200
const REPULSION_STRENGTH = 5200
const INITIAL_JITTER = 360
const CENTER_Y = LAYOUT_HEIGHT / 2

function layoutHash(value: string) {
  return value.split('').reduce((sum, ch) => (sum * 31 + ch.charCodeAt(0)) % 100000, 0)
}

export function layoutAttackChainByTactic(
  nodes: CaseGraphNode[],
  links: CaseGraphLink[],
): { nodes: Array<CaseGraphNode & { x: number; y: number }>; links: CaseGraphLink[] } {
  if (!nodes.length) return { nodes: [], links }
  const sorted = [...nodes].sort((left, right) => Date.parse(left.timestamp || '') - Date.parse(right.timestamp || ''))
  const positions = new Map<string, { x: number; y: number; vx: number; vy: number }>()
  sorted.forEach((node, index) => {
    const x = 90 + ((LAYOUT_WIDTH - 180) * index) / Math.max(1, sorted.length - 1)
    const jitter = (((layoutHash(node.id) % 1000) / 1000) - 0.5) * INITIAL_JITTER
    positions.set(node.id, { x, y: CENTER_Y + jitter, vx: 0, vy: 0 })
  })

  for (let iteration = 0; iteration < LAYOUT_ITERATIONS; iteration += 1) {
    const items = Array.from(positions.entries())
    // 排斥力：无关联节点互相推开，形成自然散布
    for (let i = 0; i < items.length; i += 1) {
      const [, p] = items[i]
      for (let j = i + 1; j < items.length; j += 1) {
        const [, p2] = items[j]
        const dx = p.x - p2.x
        const dy = p.y - p2.y
        const squared = dx * dx + dy * dy + 1
        const distance = Math.sqrt(squared)
        const force = REPULSION_STRENGTH / squared
        p.vx += (dx / distance) * force
        p.vy += (dy / distance) * force
        p2.vx -= (dx / distance) * force
        p2.vy -= (dy / distance) * force
      }
    }
    // 弹簧力：相邻技术被边牵引，维持时间先后次序
    for (const link of links) {
      const a = positions.get(String(link.source))
      const b = positions.get(String(link.target))
      if (!a || !b) continue
      const dx = b.x - a.x
      const dy = b.y - a.y
      const distance = Math.sqrt(dx * dx + dy * dy) || 1
      const force = (distance - REST_LENGTH) * 0.045
      a.vx += (dx / distance) * force
      a.vy += (dy / distance) * force
      b.vx -= (dx / distance) * force
      b.vy -= (dy / distance) * force
    }
    // 热扰动：前期引入随机摆动，避免节点收敛成一条直线，随迭代逐渐冷却
    const heat = 1 - iteration / LAYOUT_ITERATIONS
    for (const p of positions.values()) {
      p.vx += (Math.random() - 0.5) * 18 * heat
      p.vy += (Math.random() - 0.5) * 18 * heat
    }
    // 位置更新与边界约束
    for (const p of positions.values()) {
      p.x += p.vx * 0.4
      p.y += p.vy * 0.4
      p.x = Math.max(46, Math.min(LAYOUT_WIDTH - 46, p.x))
      p.y = Math.max(46, Math.min(LAYOUT_HEIGHT - 46, p.y))
      p.vx *= 0.86
      p.vy *= 0.86
    }
  }

  const laidOut: Array<CaseGraphNode & { x: number; y: number }> = sorted.map((node) => {
    const position = positions.get(node.id)!
    return { ...node, x: Math.round(position.x), y: Math.round(position.y) }
  })
  return { nodes: laidOut, links }
}
