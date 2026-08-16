import type { AnomalyWindow, Investigation, LogSource, SecurityEvent } from '../mocks/data'

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

export type ModuleScores = Record<'M0' | 'M1' | 'M2' | 'M3' | 'M4' | 'M5' | 'M6', number>

export type IngestedEvent = SecurityEvent & {
  dataset?: string
  source_type?: string
  module_scores?: ModuleScores
  pipeline?: string
  labels_used?: boolean
  findingId?: string
  findingTitle?: string
}

export type IngestJob = {
  id: string
  name: string
  kind: string
  size: number
  progress: number
  status: 'queued' | 'parsing' | 'indexed' | 'ready' | 'failed'
  result: string
  source_id?: string
  event_count?: number
  finding_count?: number
  duration_seconds?: number
  events_per_second?: number
  pipeline?: string
  stage_mean_scores?: Record<string, number>
  labels_used?: boolean
}

export type IngestionSnapshot = {
  events: IngestedEvent[]
  event_count: number
  event_limit: number
  windows: AnomalyWindow[]
  investigations: Investigation[]
  sources: LogSource[]
  jobs: IngestJob[]
  manifest: {
    pipeline: string
    labels_used_for_detection: boolean
    counts: Record<string, number>
  }
}

export type IngestResult = {
  job: IngestJob
  source: LogSource
  events: IngestedEvent[]
  windows: AnomalyWindow[]
  investigation: Investigation | null
}

export type DeleteIngestedSourceResult = {
  source_id: string
  name: string
  deleted: {
    jobs: number
    sources: number
    events: number
    windows: number
    investigations: number
  }
}

async function responseError(response: Response, fallback: string) {
  try {
    const body = await response.json() as { detail?: string }
    return new Error(body.detail || fallback)
  } catch {
    return new Error(fallback)
  }
}

async function fileBase64(file: File) {
  const bytes = new Uint8Array(await file.arrayBuffer())
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }
  return window.btoa(binary)
}

export async function uploadLogFile(file: File): Promise<IngestResult> {
  const response = await fetch(`${API_BASE}/ingest/files`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      filename: file.name,
      content_base64: await fileBase64(file),
      content_type: file.type,
    }),
  })
  if (!response.ok) throw await responseError(response, `上传失败：HTTP ${response.status}`)
  return response.json() as Promise<IngestResult>
}

export async function getIngestionSnapshot(eventLimit = 5000): Promise<IngestionSnapshot> {
  const response = await fetch(`${API_BASE}/ingest/snapshot?event_limit=${eventLimit}`)
  if (!response.ok) throw await responseError(response, `实时导入快照不可用：HTTP ${response.status}`)
  return response.json() as Promise<IngestionSnapshot>
}

export async function deleteIngestedSource(sourceId: string): Promise<DeleteIngestedSourceResult> {
  const response = await fetch(`${API_BASE}/ingest/sources/${encodeURIComponent(sourceId)}`, { method: 'DELETE' })
  if (!response.ok) throw await responseError(response, `删除失败：HTTP ${response.status}`)
  return response.json() as Promise<DeleteIngestedSourceResult>
}
