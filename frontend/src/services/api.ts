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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  })
  if (!response.ok) {
    let detail = `Request failed: ${response.status}`
    try {
      const body = await response.json() as { detail?: string }
      if (body.detail) detail = body.detail
    } catch {
      // Keep the HTTP status message when the response is not JSON.
    }
    throw new Error(detail)
  }
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

async function askRealAgent(question: string, context: AssistantContext): Promise<AssistantAnswer> {
  const response = await request<AgentApiResponse>('/agent/query', {
    method: 'POST',
    body: JSON.stringify({
      conversation_id: getConversationId(),
      mode: activeAgentMode,
      message: question,
      context: {
        finding_ids: context.windowIds || [],
        investigation_id: context.caseId || null,
        entity_ids: context.entityIds || [],
        time_range: context.timeRange || null,
      },
    }),
  })

  return {
    answer: response.answer,
    evidence: response.evidence,
    mode: response.mode,
    runId: response.run_id,
    verified: response.verified,
    confidence: response.confidence,
  }
}

export async function askAssistant(question: string, context: AssistantContext = {}): Promise<AssistantAnswer> {
  if (!AGENT_USE_MOCKS) return askRealAgent(question, context)

  await delay(420)
  const normalized = question.toLowerCase()

  if (activeAgentMode === 'general') {
    return { answer: '当前是普通模式。演示环境不会读取任何内部日志、Finding 或实体数据。', evidence: [], mode: 'general' }
  }

  if (activeAgentMode === 'knowledge') {
    return { answer: '当前是知识问答演示模式。真实部署会先检索安全知识库，再基于检索内容回答。', evidence: [{ label: 'KB-DEMO', ref: 'KB-DEMO' }], mode: 'knowledge' }
  }

  if (normalized.includes('alice') || context.caseId === 'CASE-001') {
    return {
      answer: 'Alice 在多个时间窗口和不同主机中连续出现。当前链路从 HOST-07 登录与 PowerShell 执行开始，随后在 HOST-12 出现命令执行，并进一步延伸到敏感文件访问。多个窗口共享用户实体，同时伴随进程与主机行为连续性，建议作为同一调查链继续核验。',
      evidence: [
        { label: 'WIN-0321', ref: 'WIN-20260809-0321' },
        { label: 'WIN-0935', ref: 'WIN-20260809-0935' },
        { label: 'CASE-001', ref: 'CASE-001' },
      ],
      mode: 'security',
    }
  }

  if (normalized.includes('host-07') || context.entityIds?.includes('HOST-07')) {
    return {
      answer: 'HOST-07 当前最需要关注的是登录后紧接着出现的高权限 PowerShell 执行与外联行为。建议优先核对执行账号、父进程、目标地址以及相邻时间窗口中的同一用户活动。',
      evidence: [{ label: 'WIN-0321', ref: 'WIN-20260809-0321' }],
      mode: 'security',
    }
  }

  return {
    answer: '当前处于显式 Agent 演示模式。请设置 VITE_AGENT_USE_MOCKS=false 并启动 agent_service 后使用真实多模式 Agent。',
    evidence: [],
    mode: activeAgentMode === 'auto' ? 'general' : activeAgentMode,
  }
}
