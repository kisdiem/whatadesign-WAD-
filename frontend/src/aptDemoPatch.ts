type AptTimelineEvent = {
  event_id: string
  timestamp: string
  source_timestamp?: string
  source_file: string
  raw: string
  system_projection?: {
    threat_level?: string
    final_score?: number
    reasons?: string[]
  }
  related_entities?: Array<{
    entity_type: string
    canonical_value: string
    role?: string
    confidence?: number
  }>
}

const REMOVED_APT_EVENT_IDS = new Set(
  Array.from({ length: 10 }, (_, index) => `APT-${String(index + 1).padStart(6, '0')}`),
)

const NORMAL_TEMPLATES = [
  {
    source: 'gather/monitoring/logs/logstash/intranet-server/2022-01-24..31-system.auth.log',
    host: 'intranet-server',
    process: 'sshd',
    user: 'ops',
    ip: '10.20.4.18',
    raw: (stamp: string) => `${stamp} intranet-server sshd[2418]: Accepted publickey for ops from 10.20.4.18 port 52214 ssh2`,
  },
  {
    source: 'gather/monitoring/logs/logstash/intranet-server/2022-01-24..31-system.syslog.log',
    host: 'intranet-server',
    process: 'systemd',
    user: 'root',
    ip: '10.20.4.10',
    raw: (stamp: string) => `${stamp} intranet-server systemd[1]: Started Daily cleanup of temporary directories.`,
  },
  {
    source: 'gather/monitoring/logs/logstash/intranet-server/2022-01-24..31-system.network.log',
    host: 'intranet-server',
    process: 'networkd',
    user: 'service',
    ip: '10.20.4.21',
    raw: (stamp: string) => `${stamp} intranet-server networkd[966]: established internal connection src=10.20.4.21 dst=10.20.4.10 proto=tcp dpt=443 state=ESTABLISHED`,
  },
  {
    source: 'gather/windows/2022-01-24..31-Security.evtx',
    host: 'workstation-07',
    process: 'winlogon.exe',
    user: 'employee07',
    ip: '10.20.7.34',
    raw: (stamp: string) => `${stamp} workstation-07 Security EventID=4624 LogonType=2 AccountName=employee07 WorkstationName=workstation-07 IpAddress=10.20.7.34 Status=Success`,
  },
  {
    source: 'gather/suricata/eve.json',
    host: 'web-gateway',
    process: 'suricata',
    user: 'web-service',
    ip: '10.20.3.12',
    raw: (stamp: string) => `${stamp} web-gateway suricata: flow allowed src_ip=10.20.3.12 dest_ip=10.20.4.10 proto=TCP app_proto=http action=allowed`,
  },
]

function buildNormalEvents(): AptTimelineEvent[] {
  const start = Date.parse('2022-01-24T14:00:00.000Z')
  const span = 7 * 24 * 60 * 60 * 1000 - 60 * 60 * 1000
  return Array.from({ length: 50 }, (_, index) => {
    const template = NORMAL_TEMPLATES[index % NORMAL_TEMPLATES.length]
    const timestamp = new Date(start + Math.floor((span * index) / 49)).toISOString()
    const syslogStamp = new Date(timestamp).toUTCString().replace(/GMT$/, 'UTC')
    const score = 0.06 + (index % 7) * 0.015
    return {
      event_id: `APT-NORMAL-${String(index + 1).padStart(6, '0')}`,
      timestamp,
      source_timestamp: timestamp,
      source_file: template.source,
      raw: template.raw(syslogStamp),
      system_projection: {
        threat_level: 'low',
        final_score: Number(score.toFixed(3)),
        reasons: ['常见业务/运维行为', '实体与访问模式符合历史基线', '未形成可疑跨窗口关联'],
      },
      related_entities: [
        { entity_type: 'host', canonical_value: template.host, role: 'target', confidence: 0.99 },
        { entity_type: 'process', canonical_value: template.process, role: 'process', confidence: 0.98 },
        { entity_type: 'user', canonical_value: template.user, role: 'actor', confidence: 0.98 },
        { entity_type: 'ip', canonical_value: template.ip, role: 'source', confidence: 0.99 },
      ],
    }
  })
}

const NORMAL_APT_EVENTS = buildNormalEvents()
const originalFetch = window.fetch.bind(window)

function jsonResponse(value: unknown, original: Response) {
  const headers = new Headers(original.headers)
  headers.set('content-type', 'application/json; charset=utf-8')
  headers.delete('content-length')
  return new Response(JSON.stringify(value), {
    status: original.status,
    statusText: original.statusText,
    headers,
  })
}

window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const response = await originalFetch(input, init)
  if (!response.ok) return response

  const requestUrl = input instanceof Request ? input.url : String(input)
  if (!requestUrl.includes('/demo-data/APT/')) return response

  if (requestUrl.includes('/timeline.json')) {
    const timeline = await response.clone().json() as AptTimelineEvent[]
    const patched = timeline
      .filter((event) => !REMOVED_APT_EVENT_IDS.has(event.event_id))
      .concat(NORMAL_APT_EVENTS)
      .sort((left, right) => left.timestamp.localeCompare(right.timestamp))
    return jsonResponse(patched, response)
  }

  if (requestUrl.includes('/detection_results.json')) {
    const detections = await response.clone().json() as Array<{ event_id: string }>
    return jsonResponse(detections.filter((item) => !REMOVED_APT_EVENT_IDS.has(item.event_id)), response)
  }

  if (requestUrl.includes('/module_scores.json')) {
    const scores = await response.clone().json() as Record<string, unknown>
    REMOVED_APT_EVENT_IDS.forEach((eventId) => delete scores[eventId])
    return jsonResponse(scores, response)
  }

  return response
}
