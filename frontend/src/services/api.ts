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
const API_BASE = import.meta.env.VITE_API_BASE || '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  })
  if (!response.ok) throw new Error(`Request failed: ${response.status}`)
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

export interface AssistantContext {
  windowIds?: string[]
  caseId?: string
  entityIds?: string[]
}

export interface AssistantAnswer {
  answer: string
  evidence: { label: string; ref: string }[]
}

export async function askAssistant(question: string, context: AssistantContext = {}): Promise<AssistantAnswer> {
  if (!USE_LOCAL_DATA) {
    return request<AssistantAnswer>('/assistant/query', {
      method: 'POST',
      body: JSON.stringify({ question, context }),
    })
  }

  await delay(420)
  const normalized = question.toLowerCase()

  if (normalized.includes('alice') || context.caseId === 'CASE-001') {
    return {
      answer:
        'Alice 在多个时间窗口和不同主机中连续出现。当前链路从 HOST-07 登录与 PowerShell 执行开始，随后在 HOST-12 出现命令执行，并进一步延伸到敏感文件访问。多个窗口共享用户实体，同时伴随进程与主机行为连续性，建议作为同一调查链继续核验。',
      evidence: [
        { label: 'WIN-0321', ref: 'WIN-20260809-0321' },
        { label: 'WIN-0935', ref: 'WIN-20260809-0935' },
        { label: 'CASE-001', ref: 'CASE-001' },
      ],
    }
  }

  if (normalized.includes('host-07') || context.entityIds?.includes('HOST-07')) {
    return {
      answer:
        'HOST-07 当前最需要关注的是登录后紧接着出现的高权限 PowerShell 执行与外联行为。建议优先核对执行账号、父进程、目标地址以及相邻时间窗口中的同一用户活动。',
      evidence: [{ label: 'WIN-0321', ref: 'WIN-20260809-0321' }],
    }
  }

  return {
    answer:
      '当前上下文中没有足够证据直接形成攻击结论。可以继续限定用户、主机、进程、IP 或具体异常窗口，我会据此整理相关事件和调查记录。',
    evidence: [],
  }
}
