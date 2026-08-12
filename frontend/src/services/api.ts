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
  return request<ApiConnectionTestResult>('/settings/log-sources/test', {
    method: 'POST',
    body: JSON.stringify({ type: 'api', ...config }),
  })

  if (!USE_LOCAL_DATA) {
    return request<ApiConnectionTestResult>('/settings/log-sources/test', {
      method: 'POST',
      body: JSON.stringify({ type: 'api', ...config }),
    })
  }

  await delay(260)
  return {
    ok: false,
    message: 'API 接入服务尚未连接后端；地址已通过前端格式校验。',
  }
}

export async function createApiLogSource(config: ApiLogSourceConfig): Promise<LogSource> {
  return request<LogSource>('/settings/log-sources', {
    method: 'POST',
    body: JSON.stringify({ type: 'api', ...config }),
  })

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
  repository: string
  modes?: AgentMode[]
  production_mock_fallback?: boolean
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

export interface AssistantAnswer {
  answer: string
  evidence: AssistantEvidence[]
  mode?: ResolvedAgentMode
  runId?: string
  verified?: boolean
  confidence?: number
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
  const result: AssistantAnswer = {
    answer: response.answer,
    evidence: response.evidence,
    mode: response.mode,
    runId: response.run_id,
    verified: response.verified,
    confidence: response.confidence,
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
      publishAgentStatus('')
      const result: AssistantAnswer = {
        answer: friendlyAgentError(error),
        evidence: [],
      }
      publishAgentResult(result)
      return result
    }
  }

  await delay(420)
  const normalized = question.toLowerCase()
  let result: AssistantAnswer

  if (activeAgentMode === 'general') {
    result = { answer: '当前是普通模式。演示环境不会读取任何内部日志、Finding 或实体数据。', evidence: [], mode: 'general' }
  } else if (activeAgentMode === 'knowledge') {
    result = { answer: '当前是知识问答演示模式。真实部署会先检索安全知识库，再基于检索内容回答。', evidence: [{ label: 'KB-DEMO', ref: 'KB-DEMO' }], mode: 'knowledge' }
  } else if (normalized.includes('alice') || context.caseId === 'CASE-001') {
    result = {
      answer: 'Alice 在多个时间窗口和不同主机中连续出现。当前链路从 HOST-07 登录与 PowerShell 执行开始，随后在 HOST-12 出现命令执行，并进一步延伸到敏感文件访问。多个窗口共享用户实体，同时伴随进程与主机行为连续性，建议作为同一调查链继续核验。',
      evidence: [
        { label: 'WIN-0321', ref: 'WIN-20260809-0321' },
        { label: 'WIN-0935', ref: 'WIN-20260809-0935' },
        { label: 'CASE-001', ref: 'CASE-001' },
      ],
      mode: 'security',
    }
  } else if (normalized.includes('host-07') || context.entityIds?.includes('HOST-07')) {
    result = {
      answer: 'HOST-07 当前最需要关注的是登录后紧接着出现的高权限 PowerShell 执行与外联行为。建议优先核对执行账号、父进程、目标地址以及相邻时间窗口中的同一用户活动。',
      evidence: [{ label: 'WIN-0321', ref: 'WIN-20260809-0321' }],
      mode: 'security',
    }
  } else {
    result = {
      answer: '当前处于显式 Agent 演示模式。请设置 VITE_AGENT_USE_MOCKS=false 并启动 agent_service 后使用真实多模式 Agent。',
      evidence: [],
      mode: activeAgentMode === 'auto' ? 'general' : activeAgentMode,
    }
  }

  publishAgentResult(result)
  return result
}
