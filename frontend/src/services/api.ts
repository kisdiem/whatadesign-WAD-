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

const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false'
const API_BASE = import.meta.env.VITE_API_BASE || '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  })
  if (!response.ok) throw new Error(`API ${response.status}: ${response.statusText}`)
  return response.json() as Promise<T>
}

const delay = (ms = 160) => new Promise((resolve) => setTimeout(resolve, ms))

export async function getWindows(): Promise<AnomalyWindow[]> {
  if (!USE_MOCKS) return request<AnomalyWindow[]>('/windows')
  await delay()
  return anomalyWindows
}

export async function getInvestigations(): Promise<Investigation[]> {
  if (!USE_MOCKS) return request<Investigation[]>('/investigations')
  await delay()
  return investigations
}

export async function getLogSources(): Promise<LogSource[]> {
  if (!USE_MOCKS) return request<LogSource[]>('/settings/log-sources')
  await delay()
  return logSources
}

export async function getKnowledgeDocs(): Promise<KnowledgeDoc[]> {
  if (!USE_MOCKS) return request<KnowledgeDoc[]>('/knowledge/documents')
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
  if (!USE_MOCKS) {
    return request<AssistantAnswer>('/assistant/query', {
      method: 'POST',
      body: JSON.stringify({ question, context }),
    })
  }

  await delay(520)
  const normalized = question.toLowerCase()
  if (normalized.includes('alice') || context.caseId === 'CASE-001') {
    return {
      answer:
        'Alice 的风险主要来自跨窗口连续性，而不是单条日志。WIN-20260809-0321 中该用户登录 HOST-07 后启动 PowerShell 并外联；约 6 小时后，WIN-20260809-0935 在 HOST-12 再次观察到同一用户及命令执行行为；随后 WIN-20260809-1422 出现敏感文件访问。用户实体是强关联锚点，进程/主机行为为辅助证据，因此更适合放入同一调查中继续验证。',
      evidence: [
        { label: 'PowerShell 异常窗口', ref: 'WIN-20260809-0321' },
        { label: '跨主机连续窗口', ref: 'WIN-20260809-0935' },
        { label: 'CASE-001', ref: 'CASE-001' },
      ],
    }
  }

  return {
    answer:
      '当前回答来自前端演示数据。正式接入后，该页面会通过后端调用 GPT，并让模型按需查询异常窗口、实体历史、调查案件和知识库，而不是把全部原始日志直接发送给模型。',
    evidence: [{ label: '演示模式', ref: 'MOCK' }],
  }
}

export const frontendRuntime = {
  useMocks: USE_MOCKS,
  apiBase: API_BASE,
}
