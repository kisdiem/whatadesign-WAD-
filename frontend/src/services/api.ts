import {
  anomalyWindows,
  investigations,
  knowledgeDocs,
  logSources,
  type AnomalyWindow,
  type Investigation,
  type KnowledgeDoc,
  type LogSource,
} from '../mocks/data'

const USE_LOCAL_DATA = import.meta.env.VITE_USE_MOCKS !== 'false'
const AGENT_USE_MOCKS = import.meta.env.VITE_AGENT_USE_MOCKS === 'true'
const API_BASE = import.meta.env.VITE_API_BASE || '/api'

function detailToMessage(detail: unknown, fallback: string): string {
  if (typeof detail === 'string' && detail.trim()) return detail
  if (detail && typeof detail === 'object') {
    const value = detail as { message?: unknown; code?: unknown }
    if (typeof value.message === 'string' && value.message.trim()) return value.message
  }
  return fallback
}

async function responseError(response: Response, fallback: string): Promise<Error> {
  let detail = fallback
  try {
    const body = await response.json() as { detail?: unknown }
    detail = detailToMessage(body.detail, fallback)
  } catch {
    // Keep the HTTP status message when the response is not JSON.
  }
  return new Error(detail)
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  })
  if (!response.ok) throw await responseError(response, `Request failed: ${response.status}`)
  return response.json() as Promise<T>
}

const delay = (ms = 140) => new Promise((resolve) => setTimeout(resolve, ms))

export function isUsingLocalData() {
  return USE_LOCAL_DATA
}

export async function getWindows(): Promise<AnomalyWindow[]> {
  if (!USE_LOCAL_DATA) return request<AnomalyWindow[]>('/windows')
  await delay()
  return anomalyWindows
}

export async function getInvestigations(): Promise<Investigation[]> {
  if (!USE_LOCAL_DATA) return request<Investigation[]>('/investigations')
  await delay()
  return investigations
}

export async function getLogSources(): Promise<LogSource[]> {
  if (!USE_LOCAL_DATA) return request<LogSource[]>('/settings/log-sources')
  await delay()
  return logSources
}

export async function getKnowledgeDocs(): Promise<KnowledgeDoc[]> {
  if (!USE_LOCAL_DATA) return request<KnowledgeDoc[]>('/knowledge/documents')
  await delay()
  return knowledgeDocs
}

export interface SecurityLogRecord {
  id?: string
  event_id?: string
  timestamp?: string
  time?: string
  source?: string
  source_type?: string
  path?: string
  raw_log_ref?: string
  labels?: string[]
  text?: string
  entities?: string[]
  event_id_value?: string
  tactic?: string
  evtx_file?: string
  action?: string
  outcome?: string
}

export interface SecurityLogSearchResponse {
  count: number
  events: SecurityLogRecord[]
}

export interface SecurityLogSearchParams {
  entities?: string[]
  sourceTypes?: string[]
  keywords?: string[]
  startTime?: string
  endTime?: string
  limit?: number
}

export interface SecurityEntityRecord {
  id: string
  entity_id?: string
  type?: string
  first_seen?: string
  last_seen?: string
  source_count?: number
  event_count?: number
  risk?: number
  sources?: string[]
}

export interface SecurityBaselineRecord {
  id?: string
  entity_id?: string
  type?: string
  baseline_window?: string
  activity_count?: number
  source_diversity?: number
  rarity_score?: number
  last_seen?: string
  range?: string
}

export interface SecurityEntityHistoryResponse {
  entity_id?: string
  range?: string
  count: number
  events: SecurityLogRecord[]
}

export async function searchSecurityLogs(params: SecurityLogSearchParams): Promise<SecurityLogSearchResponse> {
  if (USE_LOCAL_DATA) {
    await delay()
    return { count: 0, events: [] }
  }
  return request<SecurityLogSearchResponse>('/security/logs/search', {
    method: 'POST',
    body: JSON.stringify({
      entities: params.entities || [],
      source_types: params.sourceTypes || [],
      keywords: params.keywords || [],
      start_time: params.startTime || null,
      end_time: params.endTime || null,
      limit: params.limit || 50,
    }),
  })
}

export async function getSecurityEntity(entityId: string): Promise<SecurityEntityRecord> {
  if (USE_LOCAL_DATA) {
    await delay()
    throw new Error('Local mock mode has no repository entity endpoint.')
  }
  return request<SecurityEntityRecord>(`/security/entities/${encodeURIComponent(entityId)}`)
}

export async function getSecurityEntityHistory(entityId: string, timeRange = '24h'): Promise<SecurityEntityHistoryResponse> {
  if (USE_LOCAL_DATA) {
    await delay()
    return { entity_id: entityId, range: timeRange, count: 0, events: [] }
  }
  return request<SecurityEntityHistoryResponse>(`/security/entities/${encodeURIComponent(entityId)}/history?time_range=${encodeURIComponent(timeRange)}`)
}

export async function getSecurityBaseline(entityId: string, timeRange = '30d'): Promise<SecurityBaselineRecord> {
  if (USE_LOCAL_DATA) {
    await delay()
    throw new Error('Local mock mode has no baseline endpoint.')
  }
  return request<SecurityBaselineRecord>(`/security/entities/${encodeURIComponent(entityId)}/baseline?time_range=${encodeURIComponent(timeRange)}`)
}

export interface ApiLogSourceConfig {
  name: string
  endpoint: string
  method: 'GET' | 'POST'
  authType: 'bearer' | 'api-key' | 'none'
  token?: string
  pollInterval: number
}

export interface ApiConnectionTestResult {
  ok: boolean
  message: string
}

export async function testApiLogSource(config: ApiLogSourceConfig): Promise<ApiConnectionTestResult> {
  if (!USE_LOCAL_DATA) {
    return request<ApiConnectionTestResult>('/settings/log-sources/test', {
      method: 'POST',
      body: JSON.stringify({ type: 'api', ...config }),
    })
  }

  await delay(260)
  return {
    ok: false,
    message: 'API 接入服务连接失败，请检查接入配置后重试。',
  }
}

export async function createApiLogSource(config: ApiLogSourceConfig): Promise<LogSource> {
  if (!USE_LOCAL_DATA) {
    return request<LogSource>('/settings/log-sources', {
      method: 'POST',
      body: JSON.stringify({ type: 'api', ...config }),
    })
  }

  await delay(180)
  return {
    id: `SRC-API-${Date.now()}`,
    name: config.name,
    path: config.endpoint,
    kind: 'API',
    status: 'offline',
    size: '0 B',
    lastRead: '等待后端接入',
  }
}

export interface AssistantContext {
  windowIds?: string[]
  caseId?: string
  entityIds?: string[]
  timeRange?: string
}

export type AgentMode = 'auto' | 'security' | 'knowledge' | 'general'
export type ResolvedAgentMode = Exclude<AgentMode, 'auto'>

export interface AgentHealth {
  ok: boolean
  openai_configured: boolean
  provider_source?: 'environment' | 'runtime-memory' | 'none' | string
  modes?: AgentMode[]
  production_mock_fallback?: boolean
  knowledge_base?: {
    version: string
    documents: number
    project_documents: number
    scopes: string[]
    retriever: string
    labels_used_for_detection: boolean
  }
}

export interface AgentProviderResult {
  ok: boolean
  openai_configured: boolean
  provider_source: string
  message: string
}

export interface AgentProviderConfig {
  apiKey: string
  provider: 'openai' | 'deepseek' | 'qwen' | 'siliconflow' | 'custom'
  baseUrl?: string
  model: string
}

export async function getAgentHealth(): Promise<AgentHealth> {
  return request<AgentHealth>('/agent/health')
}

export async function configureAgentProvider(config: AgentProviderConfig): Promise<AgentProviderResult> {
  return request<AgentProviderResult>('/agent/provider', {
    method: 'POST',
    body: JSON.stringify({
      api_key: config.apiKey,
      provider: config.provider,
      base_url: config.baseUrl || undefined,
      model: config.model,
    }),
  })
}

const MODE_STORAGE_KEY = 'wad-agent-mode'
const CONVERSATION_STORAGE_KEY = 'wad-agent-conversation-id'
let activeAgentMode: AgentMode = (() => {
  try {
    const saved = window.sessionStorage.getItem(MODE_STORAGE_KEY) as AgentMode | null
    return saved && ['auto', 'security', 'knowledge', 'general'].includes(saved) ? saved : 'auto'
  } catch {
    return 'auto'
  }
})()

export function setAgentMode(mode: AgentMode) {
  activeAgentMode = mode
  try { window.sessionStorage.setItem(MODE_STORAGE_KEY, mode) } catch { /* session storage may be disabled */ }
}

export function getAgentMode(): AgentMode {
  return activeAgentMode
}

function getConversationId(): string {
  try {
    const existing = window.sessionStorage.getItem(CONVERSATION_STORAGE_KEY)
    if (existing) return existing
    const generated = `CONV-${typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : Date.now()}`
    window.sessionStorage.setItem(CONVERSATION_STORAGE_KEY, generated)
    return generated
  } catch {
    return `CONV-${Date.now()}`
  }
}

export interface AssistantEvidence {
  label: string
  ref: string
  source?: string
}

export interface AssistantStructuredItem {
  text: string
  evidence_ids: string[]
}

export interface AssistantStructuredResult {
  facts: AssistantStructuredItem[]
  assessments: AssistantStructuredItem[]
  uncertainties: AssistantStructuredItem[]
  recommended_queries: AssistantStructuredItem[]
}

export interface AssistantVerificationSummary {
  totalItems: number
  verifiedItems: number
  downgradedItems: number
}

export interface AssistantAnswer {
  answer: string
  evidence: AssistantEvidence[]
  structured?: AssistantStructuredResult
  mode?: ResolvedAgentMode
  runId?: string
  verified?: boolean
  confidence?: number
  verification?: AssistantVerificationSummary
}

interface SubmittedCaseStage {
  id: string
  stage: string
  time: string
  finding: string
  entity: string
  host: string
  risk: number
  summary: string
  evidence: string
  events: string
}

function makeVerificationSummary(
  structured?: AssistantStructuredResult,
  downgradedItems = 0,
): AssistantVerificationSummary | undefined {
  if (!structured) return undefined
  const totalItems = structured.facts.length
    + structured.assessments.length
    + structured.uncertainties.length
    + structured.recommended_queries.length
  return {
    totalItems,
    downgradedItems,
    verifiedItems: Math.max(totalItems - downgradedItems, 0),
  }
}

function parseSubmittedCaseStages(question: string, context: AssistantContext): SubmittedCaseStage[] {
  const stagePattern = /^stage=(.*?); time=(.*?); finding_id=(.*?); finding=(.*?); entity=(.*?); host=(.*?); risk=(.*?); summary=(.*?); evidence=(.*?); events=(.*)$/
  const legacyPattern = /^stage=(.*?); time=(.*?); finding=(.*?); entity=(.*?); host=(.*?); risk=(.*?); summary=(.*?); evidence=(.*?); events=(.*)$/

  return question.split(/\r?\n/).flatMap((line, index) => {
    const current = line.trim().match(stagePattern)
    const legacy = current ? null : line.trim().match(legacyPattern)
    const match = current || legacy
    if (!match) return []

    const hasId = Boolean(current)
    const offset = hasId ? 0 : -1
    const fallbackId = context.windowIds?.[index] || `CASE-STAGE-${index + 1}`
    return [{
      stage: match[1].trim(),
      time: match[2].trim(),
      id: hasId ? match[3].trim() : fallbackId,
      finding: match[4 + offset].trim(),
      entity: match[5 + offset].trim(),
      host: match[6 + offset].trim(),
      risk: Number.parseFloat(match[7 + offset]) || 0,
      summary: match[8 + offset].trim(),
      evidence: match[9 + offset].trim(),
      events: match[10 + offset].trim(),
    }]
  })
}

function formatCaseStageTime(value: string): string {
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp)) return value || '时间未解析'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(timestamp)).replace('/', '-')
}

function countValues(values: string[]) {
  const counts = new Map<string, number>()
  values.filter(Boolean).forEach((value) => counts.set(value, (counts.get(value) || 0) + 1))
  return [...counts.entries()].sort((left, right) => right[1] - left[1])
}

function compactCaseText(value: string, maxLength = 86): string {
  const clean = value.replace(/\s+/g, ' ').trim()
  return clean.length > maxLength ? `${clean.slice(0, maxLength)}…` : clean
}

function buildSubmittedCaseAnalysis(
  question: string,
  context: AssistantContext,
): AssistantAnswer | null {
  if (!context.caseId) return null
  const stages = parseSubmittedCaseStages(question, context)
  if (!stages.length) return null

  const ordered = [...stages].sort((left, right) => {
    const leftTime = Date.parse(left.time)
    const rightTime = Date.parse(right.time)
    if (!Number.isFinite(leftTime) || !Number.isFinite(rightTime)) return 0
    return leftTime - rightTime
  })
  const main = ordered.filter((item) => item.stage.includes('主链'))
  const candidates = ordered.filter((item) => item.stage.includes('候选'))
  const excluded = ordered.filter((item) => item.stage.includes('排除'))
  const active = ordered.filter((item) => !item.stage.includes('排除'))
  const highest = [...active].sort((left, right) => right.risk - left.risk)[0] || ordered[0]
  const [dominantEntity = '当前实体', dominantEntityCount = 0] = countValues(active.map((item) => item.entity))[0] || []
  const [dominantHost = '当前主机', dominantHostCount = 0] = countValues(active.map((item) => item.host))[0] || []
  const first = ordered[0]
  const last = ordered[ordered.length - 1]
  const mainIds = main.map((item) => item.id)
  const candidateIds = candidates.map((item) => item.id)
  const activeIds = active.map((item) => item.id)
  const timeline = ordered.map((item, index) => (
    `${index + 1}. ${formatCaseStageTime(item.time)} · [${item.stage}] ${item.finding} · ${item.entity}@${item.host} · 风险 ${Math.round(item.risk)}\n   ${compactCaseText(item.summary || item.evidence)}`
  )).join('\n')

  const actorTransition = countValues(active.map((item) => item.entity)).length > 1
  const hostContinuity = dominantHostCount >= Math.max(2, Math.ceil(active.length * 0.6))
  const mainChainAssessment = main.length >= 2
    ? `主链目前只固化了 ${main.length} 个阶段，${candidates.length} 个中间阶段仍为候选；这是一条“已有首尾锚点、过渡步骤尚待核验”的链路骨架，不应直接表述为已确认入侵。`
    : `当前只有 ${main.length} 个主链阶段，现有内容更适合作为调查假设，还不足以形成闭环攻击链。`
  const relationReasons = [
    dominantEntityCount > 1 ? `${dominantEntity} 在 ${dominantEntityCount}/${active.length} 个有效阶段重复出现` : null,
    hostContinuity ? `${dominantHost} 覆盖 ${dominantHostCount}/${active.length} 个有效阶段` : null,
    `时间上从 ${formatCaseStageTime(first.time)} 延续到 ${formatCaseStageTime(last.time)}`,
  ].filter(Boolean).join('；')

  const structured: AssistantStructuredResult = {
    facts: [
      {
        text: `${context.caseId} 共包含 ${ordered.length} 个阶段：主链 ${main.length}、候选 ${candidates.length}、已排除 ${excluded.length}。`,
        evidence_ids: ordered.map((item) => item.id),
      },
      {
        text: `当前时间跨度为 ${formatCaseStageTime(first.time)} 至 ${formatCaseStageTime(last.time)}；${relationReasons}。`,
        evidence_ids: activeIds,
      },
      {
        text: `最高风险阶段是“${highest.finding}”（${highest.id}，风险 ${Math.round(highest.risk)}），关键实体为 ${highest.entity}@${highest.host}。`,
        evidence_ids: [highest.id],
      },
    ],
    assessments: [
      { text: mainChainAssessment, evidence_ids: [...mainIds, ...candidateIds] },
      {
        text: `${relationReasons}，这些重复锚点支持继续按同一案件调查；但它们只能证明相关性，不能替代直接的因果证据。`,
        evidence_ids: activeIds,
      },
    ],
    uncertainties: [
      {
        text: candidates.length
          ? `${candidates.length} 个候选阶段尚未进入主链，需要逐一核验其原始日志、时间邻接和父子进程或认证关系。`
          : '当前阶段均已归类，但仍需复核原始日志引用是否足以支持因果关系。',
        evidence_ids: candidateIds.length ? candidateIds : activeIds,
      },
      ...(actorTransition ? [{
        text: `链路中出现多个行为实体，尤其需要解释从 ${first.entity} 到 ${last.entity} 的身份或进程主体转换，当前快照尚未提供直接转换证据。`,
        evidence_ids: [first.id, last.id],
      }] : []),
    ],
    recommended_queries: [
      {
        text: `先核验 ${candidates.slice(0, 2).map((item) => item.id).join('、') || highest.id}：调取其前后 30 分钟的原始事件、父进程、登录会话与目标对象，把相邻阶段连成直接证据。`,
        evidence_ids: candidates.slice(0, 2).map((item) => item.id).length ? candidates.slice(0, 2).map((item) => item.id) : [highest.id],
      },
      {
        text: `以 ${dominantEntity} 和 ${dominantHost} 做交叉检索，对比 7d 认证、进程、文件访问和网络连接，确认重复关系不是共享账号或重复导入造成。`,
        evidence_ids: activeIds.slice(0, 4),
      },
      {
        text: `优先复核风险最高的 ${highest.id}，确认“${highest.finding}”是否有可定位到原始日志的动作、对象和结果。`,
        evidence_ids: [highest.id],
      },
    ],
  }

  const answer = [
    '【案件结论】',
    `${context.caseId} 已形成 ${main.length} 个主链锚点和 ${candidates.length} 个候选阶段。${mainChainAssessment}`,
    '',
    '【链路时间线】',
    timeline,
    '',
    '【为什么这些阶段可能属于同一链】',
    `- ${relationReasons}。`,
    `- 当前最高风险点是 ${highest.id}“${highest.finding}”（风险 ${Math.round(highest.risk)}），它应当成为下一轮证据核验的入口。`,
    '',
    '【当前最关键的缺口】',
    `- ${candidates.length} 个中间阶段仍停留在候选区，主链的连续性还没有被直接证据完全证明。`,
    ...(actorTransition ? [`- 需要解释行为主体从 ${first.entity} 到 ${last.entity} 的转换，否则无法确认是同一攻击者、权限切换还是正常运维。`] : []),
  ].join('\n')

  return {
    answer,
    evidence: [
      { label: context.caseId, ref: context.caseId, source: '案件快照' },
      ...main.slice(0, 2).map((item) => ({ label: item.id, ref: item.id, source: '主链证据' })),
      ...candidates.slice(0, 2).map((item) => ({ label: item.id, ref: item.id, source: '候选证据' })),
    ],
    structured,
    mode: 'security',
    verified: false,
    confidence: Math.min(0.9, 0.68 + main.length * 0.05 + Math.min(active.length, 6) * 0.015),
    verification: makeVerificationSummary(structured, structured.uncertainties.length),
  }
}

export interface ProjectKnowledgeDocument {
  document_id: string
  title: string
  content?: string
  chunk?: string
  knowledge_version?: string
  tags?: string[]
  scope?: string
  retrieval_score?: number
}

export interface ProjectKnowledgeSearchResult {
  documents: ProjectKnowledgeDocument[]
  count: number
  retrieval: string
}

export async function searchProjectKnowledge(query: string): Promise<ProjectKnowledgeSearchResult> {
  return request<ProjectKnowledgeSearchResult>('/knowledge/search', {
    method: 'POST',
    body: JSON.stringify({
      query,
      top_k: 5,
      scope: ['project', 'security', 'organization', 'historical_cases'],
    }),
  })
}

interface AgentApiResponse {
  run_id: string
  conversation_id: string
  requested_mode: AgentMode
  mode: ResolvedAgentMode
  answer: string
  evidence: AssistantEvidence[]
  verified: boolean
  confidence?: number
  structured?: AssistantStructuredResult
  verification_summary?: AssistantVerificationSummary
}

type AgentStreamEvent =
  | { type: 'route'; mode: ResolvedAgentMode; confidence: number; reason_code: string }
  | { type: 'status'; label: string }
  | ({ type: 'citation' } & AssistantEvidence)
  | ({ type: 'final' } & AgentApiResponse)
  | { type: 'error'; code?: string; message: string }

function publishAgentStatus(label: string) {
  try {
    window.dispatchEvent(new CustomEvent('wad-agent-status', { detail: { label } }))
  } catch {
    // UI event is best effort only.
  }
}

function publishAgentResult(result: Pick<AssistantAnswer, 'mode' | 'verified' | 'confidence' | 'runId'>) {
  try {
    window.dispatchEvent(new CustomEvent('wad-agent-result', { detail: result }))
  } catch {
    // UI event is best effort only.
  }
}

function buildAgentPayload(question: string, context: AssistantContext) {
  return {
    conversation_id: getConversationId(),
    mode: activeAgentMode,
    message: question,
    context: {
      finding_ids: context.windowIds || [],
      investigation_id: context.caseId || null,
      entity_ids: context.entityIds || [],
      time_range: context.timeRange || null,
    },
  }
}

async function agentStreamRequest(question: string, context: AssistantContext): Promise<AgentApiResponse> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}/agent/query/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildAgentPayload(question, context)),
    })
  } catch {
    throw new Error('Agent 后端未连接。请确认 agent_service 已在 127.0.0.1:8000 启动，并检查 Vite /api 代理。')
  }

  if (!response.ok) {
    throw await responseError(response, `Agent request failed: ${response.status}`)
  }
  if (!response.body) throw new Error('Agent 后端未返回可读取的 SSE 数据流。')

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let finalResponse: AgentApiResponse | null = null

  const consumeBlock = (block: string) => {
    const dataLine = block.split('\n').find((line) => line.startsWith('data: '))
    if (!dataLine) return
    const event = JSON.parse(dataLine.slice(6)) as AgentStreamEvent
    if (event.type === 'route') {
      publishAgentStatus(`已路由至${event.mode === 'security' ? '安全分析' : event.mode === 'knowledge' ? '知识问答' : '普通'}模式`)
    } else if (event.type === 'status') {
      publishAgentStatus(event.label)
    } else if (event.type === 'error') {
      throw new Error(event.message)
    } else if (event.type === 'final') {
      finalResponse = event
    }
  }

  while (true) {
    const { value, done } = await reader.read()
    buffer += decoder.decode(value, { stream: !done })
    const blocks = buffer.split('\n\n')
    buffer = blocks.pop() || ''
    for (const block of blocks) consumeBlock(block)
    if (done) break
  }
  if (buffer.trim()) consumeBlock(buffer)
  if (!finalResponse) throw new Error('Agent SSE 已结束，但没有收到 final 结果。')
  return finalResponse
}

async function askRealAgent(question: string, context: AssistantContext): Promise<AssistantAnswer> {
  publishAgentStatus('正在接收问题')
  const response = await agentStreamRequest(question, context)
  // 模型在线并正常返回时直接采纳其回答；即使内部数据工具暂无结果，模型回答
  // 已自带 facts/assessments/uncertainties 与 recommended_queries，无需降级。
  const result: AssistantAnswer = {
    answer: response.answer,
    evidence: response.evidence,
    structured: response.structured,
    mode: response.mode,
    runId: response.run_id,
    verified: response.verified,
    confidence: response.confidence,
    verification: response.verification_summary,
  }
  publishAgentResult(result)
  publishAgentStatus('')
  return result
}

function friendlyAgentError(error: unknown): string {
  const message = error instanceof Error ? error.message : '未知错误'
  const lower = message.toLowerCase()

  if (message.includes('模型 API Key 未配置') || message.includes('OPENAI_API_KEY')) {
    return '模型 API Key 尚未配置。请在 AI 分析页的“配置模型服务”中填写 API Key，或在后端设置 OPENAI_API_KEY。'
  }
  if (message.includes('认证失败') || lower.includes('authentication') || lower.includes('invalid api key')) {
    return '模型服务认证失败。请重新检查 API Key。'
  }
  if (message.includes('没有访问') || lower.includes('permission')) {
    return '当前 API Key 没有所配置模型的访问权限。请检查账号权限或模型配置。'
  }
  if (message.includes('限流') || lower.includes('rate limit')) {
    return '模型服务当前触发限流，请稍后重试。'
  }
  if (message.includes('模型不可用') || lower.includes('model_not_found')) {
    return '当前模型不可用或 API Key 没有访问权限，请检查后端模型配置。'
  }
  if (message.includes('Agent 后端未连接')) return message
  if (message.includes('SSE')) return `Agent 数据流异常：${message}`

  return import.meta.env.DEV
    ? `Agent 请求失败：${message}`
    : 'Agent 服务暂时不可用，请稍后重试。'
}

export async function askAssistant(question: string, context: AssistantContext = {}): Promise<AssistantAnswer> {
  if (!AGENT_USE_MOCKS) {
    try {
      return await askRealAgent(question, context)
    } catch (error) {
      const reason = friendlyAgentError(error)
      publishAgentStatus(reason)
      const fallback = await askAssistantDemo(question, context, reason)
      publishAgentStatus('')
      return fallback
    }
  }

  return askAssistantDemo(question, context)
}

async function askAssistantDemo(
  question: string,
  context: AssistantContext = {},
  fallbackReason?: string,
): Promise<AssistantAnswer> {
  await delay(420)
  const normalized = question.toLowerCase()
  const projectKnowledgeQuestion = /(m[0-6]|多尺度|主动检索|长周期|攻击链|跨源|语义统一|实体关系|综合风险|评分|弱监督|无监督|真实标签|召回|误报|消融|吞吐|tb|collector|知识库|小影)/i.test(question)
  const knowledgeResult = (activeAgentMode === 'knowledge' || projectKnowledgeQuestion)
    ? await searchProjectKnowledge(question).catch(() => null)
    : null
  const knowledgeAnswer = knowledgeResult?.documents.length
    ? `根据链影寻踪项目知识库：\n${knowledgeResult.documents.slice(0, 2).map((document, index) => `${index + 1}. ${document.title}：${String(document.content || document.chunk || '').slice(0, 220)}`).join('\n')}`
    : ''
  const knowledgeEvidence: AssistantEvidence[] = knowledgeResult?.documents.map((document) => ({
    label: document.title,
    ref: document.document_id,
    source: document.knowledge_version || '链影寻踪项目知识库',
  })) || []
  let result: AssistantAnswer
  const submittedCaseAnalysis = buildSubmittedCaseAnalysis(question, context)

  if (activeAgentMode === 'general') {
    result = { answer: '当前为普通问答模式，不读取内部日志与实体数据。', evidence: [], mode: 'general' }
  } else if (activeAgentMode === 'knowledge') {
    result = {
      answer: knowledgeAnswer || '项目知识库中暂未找到足以支撑回答的内容。',
      evidence: knowledgeEvidence,
      mode: 'knowledge',
      verified: knowledgeEvidence.length > 0,
      confidence: knowledgeEvidence.length > 0 ? 0.82 : 0.35,
    }
  } else if (!hasSecurityContext(context) && knowledgeAnswer) {
    result = {
      answer: knowledgeAnswer,
      evidence: knowledgeEvidence,
      mode: 'knowledge',
      verified: true,
      confidence: 0.82,
    }
  } else if (submittedCaseAnalysis) {
    result = submittedCaseAnalysis
  } else if (normalized.includes('alice') || context.caseId === 'CASE-001') {
    const structured: AssistantStructuredResult = {
      facts: [
        { text: 'Alice 相关 Finding 在 HOST-07、HOST-12 与 HOST-18 的多个时间窗口中重复出现。', evidence_ids: ['EV-0321-01', 'EV-0935-01', 'EV-1422-01'] },
        { text: '当前链路包含登录、PowerShell 执行、命令执行与敏感文件访问。', evidence_ids: ['EV-0321-02', 'EV-0935-02', 'EV-1422-01'] },
      ],
      assessments: [
        { text: '同一用户实体跨主机延续出现，具备较强的长程关联特征。', evidence_ids: ['EV-0321-01', 'EV-0935-01'] },
        { text: 'HOST-18 的文件访问与外联行为更接近后渗透或数据获取阶段。', evidence_ids: ['EV-1422-01'] },
      ],
      uncertainties: [
        { text: '仍缺少从 HOST-12 到 HOST-18 的直接横向移动证据。', evidence_ids: ['EV-0935-02'] },
      ],
      recommended_queries: [
        { text: '检索 Alice 在 09:40 至 14:20 之间是否出现新的认证与远程访问日志。', evidence_ids: ['EV-0935-01'] },
        { text: '补查 HOST-18 上 archive.exe 的父进程与目标外联上下文。', evidence_ids: ['EV-1422-01'] },
      ],
    }
    result = {
      answer: 'Alice 在多个时间窗口和不同主机中连续出现。当前链路从 HOST-07 登录与 PowerShell 执行开始，随后在 HOST-12 出现命令执行，并进一步延伸到敏感文件访问。多个窗口共享用户实体，同时伴随进程与主机行为连续性，建议作为同一调查链继续核验。',
      evidence: [
        { label: 'WIN-0321', ref: 'WIN-20260809-0321' },
        { label: 'WIN-0935', ref: 'WIN-20260809-0935' },
        { label: 'CASE-001', ref: 'CASE-001' },
      ],
      structured,
      mode: 'security',
      verified: true,
      confidence: 0.88,
      verification: makeVerificationSummary(structured),
    }
  } else if (normalized.includes('host-07') || context.entityIds?.includes('HOST-07')) {
    const structured: AssistantStructuredResult = {
      facts: [
        { text: 'HOST-07 在登录后紧接着出现高权限 PowerShell 执行。', evidence_ids: ['EV-0321-01', 'EV-0321-02'] },
        { text: '同一窗口中还出现了后续外联行为。', evidence_ids: ['EV-0321-03'] },
      ],
      assessments: [
        { text: '这组行为更像一个需要优先核验的短程攻击链起点。', evidence_ids: ['EV-0321-01', 'EV-0321-02', 'EV-0321-03'] },
      ],
      uncertainties: [
        { text: '当前尚未确认外联目标是否为已知恶意地址。', evidence_ids: ['EV-0321-03'] },
      ],
      recommended_queries: [
        { text: '继续检索 HOST-07 同时段的父进程、脚本块与网络目标资产标签。', evidence_ids: ['EV-0321-02', 'EV-0321-03'] },
      ],
    }
    result = {
      answer: 'HOST-07 当前最需要关注的是登录后紧接着出现的高权限 PowerShell 执行与外联行为。建议优先核对执行账号、父进程、目标地址以及相邻时间窗口中的同一用户活动。',
      evidence: [{ label: 'WIN-0321', ref: 'WIN-20260809-0321' }],
      structured,
      mode: 'security',
      verified: true,
      confidence: 0.84,
      verification: makeVerificationSummary(structured),
    }
  } else if (normalized.includes('缺口') || normalized.includes('gap') || normalized.includes('query')) {
    const structured: AssistantStructuredResult = {
      facts: [
        { text: '当前上下文已经包含 Finding、Entity 与时间范围信息，可用于收敛后续检索。', evidence_ids: ['CTX-001'] },
      ],
      assessments: [
        { text: '现有证据足以形成初步攻击链，但不足以完成最终归因。', evidence_ids: ['CTX-001'] },
      ],
      uncertainties: [
        { text: '部分证据引用尚未关联到具体事件日志，建议补充原始日志引用。', evidence_ids: ['CTX-001'] },
      ],
      recommended_queries: [
        { text: '优先查找当前实体在前后 30 分钟内的认证、远程访问与文件操作。', evidence_ids: ['CTX-001'] },
        { text: '补查是否存在弱锚点导致的误关联，例如共享 IP 或 NAT 地址。', evidence_ids: ['CTX-001'] },
      ],
    }
    result = {
      answer: '我已经把当前链路中的确定事实、判断性结论和证据缺口拆开了。下一步最值得补的是能够直接把实体活动串起来的认证与远程访问证据。',
      evidence: [{ label: 'CTX-001', ref: context.caseId || context.windowIds?.[0] || 'CONTEXT' }],
      structured,
      mode: 'security',
      verified: false,
      confidence: 0.67,
      verification: makeVerificationSummary(structured, 1),
    }
  } else if (context.caseId || context.entityIds?.length || context.windowIds?.length) {
    const caseLabel = context.caseId || '当前案件'
    const entityLabel = context.entityIds?.slice(0, 2).join('、') || '当前实体'
    const findingLabel = context.windowIds?.slice(0, 2).join('、') || '当前发现'
    const structured: AssistantStructuredResult = {
      facts: [
        { text: `${caseLabel} 已经关联到 ${findingLabel}。`, evidence_ids: [context.caseId || context.windowIds?.[0] || 'CTX-CASE'] },
        { text: `${entityLabel} 是当前上下文里最值得优先核验的锚点。`, evidence_ids: [context.entityIds?.[0] || 'CTX-ENTITY'] },
      ],
      assessments: [
        { text: '当前上下文已经具备继续调查的基本条件，可以先围绕实体关系和时间相邻行为收敛线索。', evidence_ids: [context.caseId || context.entityIds?.[0] || 'CTX-ASSESS'] },
      ],
      uncertainties: [
        { text: '仍需要更多直接日志把当前发现、实体和时间线完全串起来。', evidence_ids: [context.windowIds?.[0] || 'CTX-GAP'] },
      ],
      recommended_queries: [
        { text: `优先检索 ${entityLabel} 在 ${context.timeRange || '24h'} 内的认证、进程和访问日志。`, evidence_ids: [context.entityIds?.[0] || 'CTX-QUERY'] },
        { text: `回看 ${findingLabel} 前后相邻时间窗口，确认是否存在连续动作。`, evidence_ids: [context.windowIds?.[0] || 'CTX-QUERY-2'] },
      ],
    }
    result = {
      answer: `${caseLabel} 当前已经有可继续分析的上下文。建议先围绕 ${entityLabel} 收敛日志，再回看 ${findingLabel} 前后相邻窗口，把关键动作串成更完整的链路。`,
      evidence: [
        { label: context.caseId || 'CTX-CASE', ref: context.caseId || 'CTX-CASE' },
        ...(context.entityIds?.slice(0, 2).map((entityId) => ({ label: entityId, ref: entityId })) || []),
      ],
      structured,
      mode: 'security',
      verified: false,
      confidence: 0.72,
      verification: makeVerificationSummary(structured, 1),
    }
  } else {
    result = {
      answer: 'Agent 在线模型服务未启用，已使用内置安全分析引擎生成结果。',
      evidence: [],
      mode: activeAgentMode === 'auto' ? 'general' : activeAgentMode,
    }
  }

  // 真实 Agent 失败降级时，把失败原因透出给用户，避免“有问必答”但不知为何没走在线服务。
  if (fallbackReason) {
    result = { ...result, answer: `【在线小影未生效：${fallbackReason}】\n\n${result.answer}` }
  }

  publishAgentResult(result)
  return result
}

function hasSecurityContext(context: AssistantContext) {
  return Boolean(context.caseId || context.entityIds?.length || context.windowIds?.length)
}
