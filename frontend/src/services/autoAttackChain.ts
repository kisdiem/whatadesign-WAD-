import type { FindingRecord } from './investigationDomain'
import { attackTechniqueForEvent } from './caseGraphs'

/**
 * 自动攻击链提取：从案件关联的异常事件中，按 ATT&CK 战术阶段自动提取攻击链，
 * 并给出链级罕见度与阶段覆盖评估。
 *
 * 与案件页图（buildAttackChainGraph）的区别：
 *  - 图负责"可视化"：把案件事件映射为技术节点 + 连线；
 *  - 本模块负责"提取与度量"：把同一案件的事件按战术阶段聚合为链，
 *    输出阶段序列、覆盖数、链级罕见度（M2 实体稀有 + M4 模板稀有 +
 *    时间压缩度 + 高风险占比），供 UI 直接展示"自动提取"结论。
 *
 * 数据来源：案件内 FindingRecord 的事件 + 可选的事件级 M0-M6 分数
 * （AnomalyWindow.moduleScores），均来自 demo 回放或真实上传链路。
 */

/** 标准 ATT&CK 战术推进顺序（按杀伤链常见推进排序，用于阶段覆盖评估）。 */
export const ATTACK_TACTIC_ORDER = [
  '侦察',
  '资源开发',
  '初始访问',
  '执行',
  '持久化',
  '权限提升',
  '防御绕过',
  '凭证访问',
  '发现',
  '横向移动',
  '收集',
  '命令与控制',
  '渗出',
  '影响',
]

export type AutoChainStage = {
  tactic: string
  orderIndex: number
  techniqueIds: string[]
  events: Array<{
    eventId: string
    time: string
    techniqueId: string
    techniqueName: string
    source: string
    actor: string
    host: string
  }>
}

export type AutoAttackChain = {
  chainId: string
  eventsCount: number
  start: string
  end: string
  spanHours: number
  stages: AutoChainStage[]
  stageCount: number
  coverage: number
  coverageRatio: number
  rarity: number
  rarityLabel: string
  entities: string[]
  sources: string[]
  summary: string
  extractionNote: string
}

export type ModuleScoresMap = Map<string, Record<string, number>>

function clamp(value: number, low = 0, high = 1) {
  return Math.max(low, Math.min(high, value))
}

function primaryTactic(tactic: string) {
  return tactic.split('·')[0].trim()
}

function rarityLabel(value: number) {
  if (value >= 0.7) return '罕见'
  if (value >= 0.5) return '较罕见'
  return '一般'
}

function scoreMean(values: number[]) {
  if (!values.length) return 0
  return values.reduce((sum, value) => sum + value, 0) / values.length
}

/**
 * 从案件 findings 自动提取攻击链。
 * @param findings 案件关联的异常发现（含事件）。
 * @param moduleScoresByEvent 可选：事件级 M0-M6 分数（用于 M2 实体稀有 / M4 模板稀有）。
 */
export function extractAutoAttackChain(
  findings: FindingRecord[],
  moduleScoresByEvent?: ModuleScoresMap,
): AutoAttackChain | null {
  const allEvents = findings.flatMap((finding) =>
    (Array.isArray(finding.events) ? finding.events.map((event) => ({ finding, event })) : []),
  )
  const uniqueEvents = Array.from(
    new Map(allEvents.map((item) => [`${item.finding.id}:${item.event.id}`, item])).values(),
  ).sort((left, right) => Date.parse(left.event.time) - Date.parse(right.event.time))
  if (!uniqueEvents.length) return null

  // 阶段聚合：事件 → ATT&CK 技术（主战术）→ 分阶段。
  const stageEvents = new Map<string, AutoChainStage['events']>()
  uniqueEvents.forEach(({ finding, event }) => {
    attackTechniqueForEvent(event).forEach((technique) => {
      const tactic = primaryTactic(technique.tactic)
      const list = stageEvents.get(tactic) || []
      list.push({
        eventId: event.id,
        time: event.time,
        techniqueId: technique.id,
        techniqueName: technique.name,
        source: event.source || finding.source || '未标明',
        actor: event.actor || '未解析',
        host: event.host || '未解析',
      })
      stageEvents.set(tactic, list)
    })
  })

  const stages: AutoChainStage[] = ATTACK_TACTIC_ORDER
    .map((tactic, orderIndex) => ({ tactic, orderIndex, events: stageEvents.get(tactic) || [] }))
    .filter((stage) => stage.events.length > 0)
    .map((stage) => ({
      ...stage,
      techniqueIds: Array.from(new Set(stage.events.map((item) => item.techniqueId))),
    }))
  const stageCount = stages.length
  const coverage = stageCount
  const coverageRatio = clamp(coverage / ATTACK_TACTIC_ORDER.length)
  const start = uniqueEvents[0].event.time
  const end = uniqueEvents[uniqueEvents.length - 1].event.time
  const spanHours = (Date.parse(end) - Date.parse(start)) / 3600_000

  // 链级罕见度：M2 实体稀有（agent 场景回退 entityRarity）+ M4 模板稀有 + 时间压缩度 + 高风险占比。
  const m2Values: number[] = []
  const m4Values: number[] = []
  const entityRarityValues: number[] = []
  const highRiskValues: number[] = []
  uniqueEvents.forEach(({ finding, event }) => {
    const scores = moduleScoresByEvent?.get(event.id)
    if (scores?.M2 !== undefined) m2Values.push(scores.M2)
    if (scores?.M4 !== undefined) m4Values.push(scores.M4)
    entityRarityValues.push(finding.association?.entityRarity ?? 0.5)
    if ((finding.risk ?? 0) >= 70) highRiskValues.push(1)
  })
  // 时间压缩度：短时间完成多阶段 → 链越"紧凑"，符合"短时间内完成整条链"的罕见特征。
  const timePressure = clamp(1 - Math.log10(Math.max(spanHours, 0.1) + 1) / 3)
  const highSignal = scoreMean(highRiskValues)
  const m2Mean = m2Values.length ? scoreMean(m2Values) : scoreMean(entityRarityValues)
  const m4Mean = m4Values.length ? scoreMean(m4Values) : (findingRiskMean(uniqueEvents.map(({ finding }) => finding.risk)) / 100)
  const rarity = clamp(0.35 * m2Mean + 0.30 * m4Mean + 0.20 * timePressure + 0.15 * highSignal)

  const entities = Array.from(new Set(uniqueEvents.flatMap(({ finding }) => finding.entities || []))).slice(0, 8)
  const sources = Array.from(new Set(uniqueEvents.flatMap(({ event }) => event.source ? [event.source] : [])))
  const stageNames = stages.map((stage) => stage.tactic).join(' → ')
  const summary = `系统按共享实体与时间序自动提取：${uniqueEvents.length} 条证据覆盖 ${coverage} 个战术阶段${stageNames ? `（${stageNames}）` : ''}，链罕见度 ${(rarity * 100).toFixed(0)}%，跨度 ${formatSpan(spanHours)}。`
  const extractionNote = '自动链由 M5 长周期关联 + ATT&CK 阶段映射生成，属于调查投影；需结合原始日志与授权情况人工确认，不等同于入侵事实。'

  return {
    chainId: `${uniqueEvents[0].finding.id}-chain`,
    eventsCount: uniqueEvents.length,
    start,
    end,
    spanHours,
    stages,
    stageCount,
    coverage,
    coverageRatio,
    rarity: Math.round(rarity * 100) / 100,
    rarityLabel: rarityLabel(rarity),
    entities,
    sources,
    summary,
    extractionNote,
  }
}

function findingRiskMean(values: number[]) {
  if (!values.length) return 0
  return values.reduce((sum, value) => sum + value, 0) / values.length
}

function formatSpan(spanHours: number) {
  if (spanHours >= 24) return `${(spanHours / 24).toFixed(1)} 天`
  if (spanHours >= 1) return `${spanHours.toFixed(1)} 小时`
  return `${Math.max(1, Math.round(spanHours * 60))} 分钟`
}

/** 阶段覆盖可视化：按标准顺序返回每个阶段是否命中。 */
export function attackStageCoverage(chain: AutoAttackChain | null) {
  if (!chain) return []
  return ATTACK_TACTIC_ORDER.map((tactic, index) => ({
    tactic,
    index,
    hit: chain.stages.some((stage) => stage.tactic === tactic),
  }))
}
