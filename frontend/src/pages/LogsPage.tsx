import { useEffect, useMemo, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Button, Card, Col, Descriptions, Divider, Drawer, Input, Row, Select, Space, Statistic, Table, Tabs, Tag, Typography } from 'antd'
import { LinkOutlined, RobotOutlined, SearchOutlined } from '@ant-design/icons'
import { searchSecurityLogs, type AssistantContext, type SecurityLogRecord } from '../services/api'
import { inferEntityType, type EvidenceRecord, type FindingRecord } from '../services/investigationDomain'
import type { ModuleScores } from '../services/ingestion'
import {
  ExplainableBlock,
  ExplainableText,
  HelpTitle,
  PageTitle,
  filterRowsBySourceTimeRange,
  filterRowsByTimeRange,
  readableAction,
  useRepositoryPresentation,
  type DemoReplayEvent,
} from './shared'

const { Text } = Typography

type EventRow = {
  id: string
  time: string
  source: string
  action: string
  normalizedAction?: string
  actor?: string
  host?: string
  process?: string
  ip?: string
  raw: string
  rawLogRef?: string
  entities?: string[]
  findingId?: string
  findingTitle: string
  risk?: number
  moduleScores?: ModuleScores
  evidenceIds: string[]
}

type ReplayEventRowsCache = {
  demoEvents: DemoReplayEvent[]
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  rows: EventRow[]
}

let replayEventRowsCache: ReplayEventRowsCache | null = null

function inferLogParticipants(entities: string[] = []) {
  const actor = entities.find((item) => inferEntityType(item) === 'User')
  const host = entities.find((item) => inferEntityType(item) === 'Host')
  const process = entities.find((item) => inferEntityType(item) === 'Process')
  const ip = entities.find((item) => inferEntityType(item) === 'IP')
  return { actor, host, process, ip }
}

function normalizedEventCategory(value?: string, raw?: string, process?: string) {
  const readable = readableAction(value)
  if (/[\u4e00-\u9fff]/.test(readable)) return readable
  const text = `${value || ''} ${raw || ''} ${process || ''}`.toLowerCase()
  if (/failed password|authentication failure|login failed|\b4625\b/.test(text)) return '认证失败'
  if (/accepted password|accepted publickey|authentication success|\b4624\b/.test(text)) return '认证成功'
  if (/pam_unix\((?:sshd|sudo|systemd)|session (?:opened|closed)/.test(text)) return '用户或权限会话变化'
  if (/useradd|new user|new group|shadow group|account create/.test(text)) return '账户或用户组变更'
  if (/powershell|command=|type=user_cmd|process start|\bexec(?:ute)?\b/.test(text)) return '进程或命令执行'
  if (/systemd|starting |started |stopped |reached target|mounting /.test(text)) return '系统服务状态变化'
  if (/metricbeat|system\.network|system\.cpu|system\.memory/.test(text)) return '主机指标采集'
  if (/kernel|\bata\d|acpi|\busb\b|\bpnp\b/.test(text)) return '内核设备或驱动事件'
  if (/cloud-init|temporary failure resolving|failed to fetch/.test(text)) return '主机初始化或配置事件'
  if (/freshclam|clamav/.test(text)) return '安全软件更新事件'
  if (/\b(get|post|put|delete|patch|head)\s+\//.test(text)) return 'Web 访问事件'
  if (/dns|connect|outbound|src_ip|dst_ip|network/.test(text)) return '网络连接或探测'
  if (/file|archive|write|read|mount/.test(text)) return '文件或存储操作'
  if (/fail|error|denied|unable|unavailable/.test(text)) return '系统操作失败'
  return '其他系统事件'
}

type LogEventDescriptionInput = {
  raw?: string
  normalizedAction?: string
  actor?: string
  host?: string
  process?: string
  ip?: string
  source?: string
}

function compactEventObject(value: string, maxLength = 58) {
  const clean = value.replace(/\s+/g, ' ').replace(/[.。]+$/, '').trim()
  return clean.length > maxLength ? `${clean.slice(0, maxLength)}…` : clean
}

function describeLogEvent(event: LogEventDescriptionInput) {
  const raw = String(event.raw || '').trim()
  const syslogMessage = raw.match(/^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[^:]+:\s*(.*)$/)?.[1]
  const message = syslogMessage || raw
  let match: RegExpMatchArray | null

  match = message.match(/pam_unix\((sshd|sudo|systemd(?:[-_ ]user)?)(?::session)?\):\s*session\s+(opened|closed)\s+for user\s+([\w.@-]+)(?:\s+by\s+([^\s(]+)?\s*\(uid=(\d+)\))?/i)
  if (match) {
    const service = match[1].toLowerCase()
    const channel = service === 'sshd' ? 'SSH' : service === 'sudo' ? 'sudo 权限' : '用户'
    const state = match[2].toLowerCase() === 'opened' ? '已建立' : '已关闭'
    const initiator = match[4] || match[5] ? `（由 ${match[4] || `UID ${match[5]}`} 发起）` : ''
    return `${channel}会话${state}：${match[3]}${initiator}`
  }

  match = message.match(/failed password for (?:invalid user )?([\w.@-]+).*?from\s+((?:\d{1,3}\.){3}\d{1,3})/i)
  if (match) return `SSH 登录失败：用户 ${match[1]}，来源 ${match[2]}`
  match = message.match(/accepted (?:password|publickey) for\s+([\w.@-]+).*?from\s+((?:\d{1,3}\.){3}\d{1,3})/i)
  if (match) return `SSH 登录成功：用户 ${match[1]}，来源 ${match[2]}`

  match = message.match(/\bStarting\s+(.+?)(?:\.\.\.|$)/i)
  if (match) return `正在启动系统服务：${compactEventObject(match[1])}`
  match = message.match(/\bStarted\s+(.+?)(?:\.|$)/i)
  if (match) return `系统服务启动完成：${compactEventObject(match[1])}`
  match = message.match(/\bReached target\s+(.+?)(?:\.|$)/i)
  if (match) return `系统运行目标已就绪：${compactEventObject(match[1])}`
  match = message.match(/\bStopped\s+(.+?)(?:\.|$)/i)
  if (match) return `系统服务已停止：${compactEventObject(match[1])}`

  match = message.match(/\b(ata\d+(?:\.\d+)?):\s*NODEV after polling detection/i)
  if (match) return `磁盘设备轮询未发现设备：${match[1]}`
  match = message.match(/metricbeat\s+system\.network\s+interface=([^\s]+)\s+in[_ ]bytes=(\d+)\s+out[_ ]bytes=(\d+)/i)
  if (match) return `采集网络指标：接口 ${match[1]}，入站 ${match[2]} B，出站 ${match[3]} B`
  if (/ClamAV update process started|freshclam/i.test(message)) return 'ClamAV 病毒库更新任务已启动'

  match = message.match(/temporary failure resolving ['"]?([^'"\s]+)['"]?/i)
  if (match) return `DNS 解析临时失败：${match[1]}`
  match = message.match(/failed to fetch\s+https?:\/\/([^/\s]+)/i)
  if (match) return `软件源获取失败：${match[1]}`
  if (/generating public\/private .* key pair|the key fingerprint is|\[(?:rsa|ecdsa|ed25519)\s+\d+\]/i.test(message)) return '生成或展示 SSH 主机密钥信息'
  if (/ci info:/i.test(message)) return 'cloud-init 输出网络配置摘要'

  match = message.match(/(?:new user:\s*name=|useradd(?:\s+created)?\s+|add(?:ed)? user\s+)([\w.@-]+)/i)
  if (match) return `创建本地账户：${match[1]}`
  match = message.match(/new group:\s*name=([\w.@-]+)/i)
  if (match) return `创建本地用户组：${match[1]}`
  match = message.match(/add ['"]?([\w.@-]+)['"]? to (?:shadow )?group ['"]?([\w.@-]+)['"]?/i)
  if (match) return `修改用户组：将 ${match[1]} 加入 ${match[2]}`
  if (/powershell(?:\.exe)?\s+(?:-enc|-encodedcommand)/i.test(message)) {
    return `执行编码 PowerShell：${event.actor || event.process || '执行主体未解析'}`
  }

  match = message.match(/"(GET|POST|PUT|DELETE|PATCH|HEAD)\s+([^\s]+)\s+HTTP\/[^"]+"\s+(\d{3})/i)
  if (match) return `HTTP ${match[1].toUpperCase()} 请求：${compactEventObject(match[2], 48)}，状态 ${match[3]}`
  if (/Possible Nmap User-Agent Observed/i.test(message)) return `检测到疑似 Nmap 扫描：${event.ip || '来源地址待解析'}`
  if (/type=USER_CMD/i.test(message)) {
    match = message.match(/\bpid=(\d+)/i)
    return `记录到用户命令执行${match ? `：进程 PID ${match[1]}` : ''}`
  }

  const normalized = event.normalizedAction || '未知行为'
  if (normalized === '进程或命令执行') return `执行进程或命令：${event.process || event.actor || '执行对象待解析'}`
  if (normalized === '网络连接或探测') return `发起网络连接或探测：${event.ip || event.host || '目标待解析'}`
  if (normalized === '文件创建或写入' || normalized === '文件读取或访问') return `${normalized}：${event.process || '文件对象待解析'}`
  if (normalized !== '未知行为' && /[\u4e00-\u9fff]/.test(normalized)) return normalized

  const component = event.process || event.source
  if (/kernel/i.test(component || '')) return `内核设备或驱动事件：${event.host || '主机待解析'}`
  if (/systemd/i.test(component || '')) return `系统服务状态变化：${event.host || '主机待解析'}`
  if (/metricbeat/i.test(message)) return `主机指标采集事件：${event.host || '主机待解析'}`
  if (/sshd/i.test(component || '')) return `SSH 认证或会话事件：${event.actor || '用户待解析'}`
  if (/sudo/i.test(component || '')) return `sudo 权限会话事件：${event.actor || '用户待解析'}`
  return `其他系统事件：${component || '类型待解析'}`
}

function buildReplayEventRows(
  demoEvents: DemoReplayEvent[],
  findings: FindingRecord[],
  evidenceByFinding: Record<string, EvidenceRecord[]>,
) {
  if (
    replayEventRowsCache
    && replayEventRowsCache.demoEvents === demoEvents
    && replayEventRowsCache.findings === findings
    && replayEventRowsCache.evidenceByFinding === evidenceByFinding
  ) {
    return replayEventRowsCache.rows
  }

  const findingByEventId = new Map<string, FindingRecord>()
  const evidenceIdsByEventId = new Map<string, string[]>()
  findings.forEach((finding) => {
    finding.events.forEach((event) => findingByEventId.set(event.id, finding))
    const evidence = evidenceByFinding[finding.id] || []
    evidence.forEach((item) => {
      const ids = evidenceIdsByEventId.get(item.eventId)
      if (ids) ids.push(item.id)
      else evidenceIdsByEventId.set(item.eventId, [item.id])
    })
  })

  const rows = demoEvents.map<EventRow>((event) => {
    const finding = findingByEventId.get(event.id)
    const normalizedAction = normalizedEventCategory(event.action, event.raw, event.process)
    return {
      ...event,
      source: event.dataset,
      action: describeLogEvent({ ...event, source: event.dataset, normalizedAction }),
      normalizedAction,
      rawLogRef: event.raw_log_ref || `${event.source}:${event.id}`,
      entities: [event.actor, event.host, event.process, event.ip].filter((value): value is string => Boolean(value)),
      findingId: finding?.id,
      findingTitle: finding?.title || '未形成异常发现',
      risk: finding?.risk,
      moduleScores: event.module_scores,
      evidenceIds: evidenceIdsByEventId.get(event.id) || [],
    }
  })

  replayEventRowsCache = { demoEvents, findings, evidenceByFinding, rows }
  return rows
}

function normalizedLogAction(row: SecurityLogRecord) {
  const value = row.action || row.labels?.slice(0, 2).join(' ') || row.source_type || row.source || '未知行为'
  return normalizedEventCategory(value, row.text, row.source_type || row.source)
}

function toEventRow(row: SecurityLogRecord): EventRow {
  const entities = row.entities || []
  const { actor, host, process, ip } = inferLogParticipants(entities)
  const normalizedAction = normalizedLogAction(row)
  const raw = row.text || JSON.stringify(row, null, 2)
  return {
    id: row.event_id || row.id || row.raw_log_ref || 'unknown',
    time: row.time || row.timestamp || '—',
    source: row.source_type || row.source || 'Unknown',
    action: describeLogEvent({ raw, normalizedAction, actor, host, process, ip, source: row.source_type || row.source }),
    normalizedAction,
    actor,
    host,
    process,
    ip,
    raw,
    rawLogRef: row.raw_log_ref || [row.path, row.event_id || row.id].filter(Boolean).join(':'),
    entities,
    findingTitle: row.labels?.join(' / ') || 'Repository Event',
    evidenceIds: [],
  }
}

export default function LogsPage({
  findings,
  evidenceByFinding,
  demoEvents,
  timeRange,
  onSubmitBatch,
  onExplain,
  onSaveM3Graph,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  demoEvents: DemoReplayEvent[]
  timeRange: string
  onSubmitBatch: (prompt: string, context: AssistantContext) => void
  onExplain: (excerpt: string, context: AssistantContext) => void
  onSaveM3Graph: (finding: FindingRecord) => void
}) {
  const location = useLocation()
  const useRepositoryData = useRepositoryPresentation()
  const [query, setQuery] = useState('')
  const [source, setSource] = useState('all')
  const [selected, setSelected] = useState<EventRow | null>(null)
  const [remoteEvents, setRemoteEvents] = useState<EventRow[]>([])
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [page, setPage] = useState(1)
  const requestedQuery = useMemo(() => new URLSearchParams(location.search).get('q') || '', [location.search])
  useEffect(() => {
    if (requestedQuery) {
      setQuery(requestedQuery)
    }
  }, [requestedQuery])

  const events = useMemo<EventRow[]>(() => {
    if (demoEvents.length) {
      return buildReplayEventRows(demoEvents, findings, evidenceByFinding)
    }
    return findings.flatMap((finding) => finding.events.map((event) => {
      const source = finding.sourceTypes[0] || 'Short'
      const normalizedAction = normalizedEventCategory(event.action, event.raw, event.process)
      return {
        ...event,
        source,
        action: describeLogEvent({ ...event, source, normalizedAction }),
        normalizedAction,
        findingId: finding.id,
        findingTitle: finding.title,
        risk: finding.risk,
        evidenceIds: (evidenceByFinding[finding.id] || []).filter((item) => item.eventId === event.id).map((item) => item.id),
      }
    }))
  }, [demoEvents, evidenceByFinding, findings])
  useEffect(() => {
    if (!useRepositoryData) {
      setRemoteEvents([])
      setLoadError('')
      return
    }
    let active = true
    const handle = window.setTimeout(async () => {
      setLoading(true)
      setLoadError('')
      try {
        const result = await searchSecurityLogs({
          sourceTypes: source === 'all' ? [] : [source],
          keywords: query.trim() ? query.trim().split(/\s+/).slice(0, 6) : [],
          limit: 200,
        })
        if (!active) return
        setRemoteEvents(filterRowsByTimeRange(result.events.map(toEventRow), timeRange))
      } catch (error) {
        if (!active) return
        setRemoteEvents([])
        setLoadError(error instanceof Error ? error.message : '真实日志查询失败。')
      } finally {
        if (active) setLoading(false)
      }
    }, 220)
    return () => {
      active = false
      window.clearTimeout(handle)
    }
  }, [query, source, timeRange, useRepositoryData])

  const filtered = useMemo(() => {
    if (useRepositoryData) return remoteEvents
    const sourceMatched = source === 'all' ? events : events.filter((event) => event.source === source)
    const ranged = source === 'all'
      ? filterRowsBySourceTimeRange(sourceMatched, timeRange)
      : filterRowsByTimeRange(sourceMatched, timeRange)
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return ranged
    return ranged.filter((event) => {
      const haystack = [event.id, event.action, event.normalizedAction, event.actor, event.host, event.process, event.ip, event.source, event.raw, event.findingTitle].join(' ').toLowerCase()
      return haystack.includes(normalizedQuery)
    })
  }, [events, query, remoteEvents, source, timeRange, useRepositoryData])

  const pageSize = 50
  const pageRows = useMemo(
    () => filtered.slice((page - 1) * pageSize, page * pageSize),
    [filtered, page],
  )

  useEffect(() => {
    setPage(1)
  }, [query, source, timeRange])

  const eventContext = (row: EventRow): AssistantContext => ({
    windowIds: row.findingId ? [row.findingId] : [],
    entityIds: [row.actor, row.host, row.process, row.ip].filter((value): value is string => Boolean(value)),
    timeRange,
  })

  const saveSelectedM3 = () => {
    const finding = selected?.findingId ? findings.find((item) => item.id === selected.findingId) : undefined
    if (finding) onSaveM3Graph(finding)
  }

  const submitLogs = () => {
    const sample = filtered.slice(0, 200)
    const snapshot = sample.map((event) => [
      `time=${event.time}`,
      `source=${event.source}`,
      `event_summary=${event.action}`,
      `normalized_action=${event.normalizedAction || 'unknown'}`,
      `actor=${event.actor || 'unresolved'}`,
      `host=${event.host || 'unresolved'}`,
      `target=${event.process || event.ip || 'unresolved'}`,
      `entities=${event.entities?.join(',') || 'none'}`,
      `finding=${event.findingTitle || 'none'}`,
      `risk=${event.risk ?? 'none'}`,
      `raw=${event.raw.slice(0, 500)}`,
    ].join('; ')).join('\n')
    const entityIds = Array.from(new Set(filtered.flatMap((event) => [event.actor, event.host, event.process, event.ip, ...(event.entities || [])]).filter((value): value is string => Boolean(value))))
    onSubmitBatch(
      `Log Search currently contains ${filtered.length} matching events. The snapshot below contains the first ${sample.length} events after the active time, source and keyword filters. Analyze in concise Chinese: identify the dominant behavior, explain whether there is a coherent sequence worth investigating, list at most four events or patterns that deserve attention, and state what cannot be concluded. Do not claim the snapshot is the complete dataset. Event labels and risk scores are only leads, not ground truth.\n\n${snapshot}`,
      { windowIds: Array.from(new Set(filtered.map((event) => event.findingId).filter((value): value is string => Boolean(value)))), entityIds, timeRange },
    )
  }

  const columns = [
    { title: '时间', dataIndex: 'time', key: 'time', width: 110 },
    { title: '日志源', dataIndex: 'source', key: 'source', width: 140, render: (value: string) => <Tag>{value}</Tag> },
    {
      title: '标准化事件',
      dataIndex: 'action',
      key: 'action',
      width: 250,
      render: (value: string, row: EventRow) => (
        <div className="mc-log-event-summary">
          <Text strong><ExplainableText fallback={value} context={eventContext(row)} onExplain={onExplain}>{value}</ExplainableText></Text>
          {row.normalizedAction && row.normalizedAction !== value && <Text type="secondary">标准动作：{row.normalizedAction}</Text>}
        </div>
      ),
    },
    { title: '执行者', dataIndex: 'actor', key: 'actor', width: 120, render: (value?: string) => value || '—' },
    { title: '主机', dataIndex: 'host', key: 'host', width: 120, render: (value?: string) => value || '—' },
    { title: '对象 / IP', key: 'target', width: 160, render: (_: unknown, row: EventRow) => row.process || row.ip || '—' },
    { title: '异常发现', dataIndex: 'findingTitle', key: 'findingTitle', width: 220 },
  ]

  return (
    <>
      <PageTitle title="日志检索" extra={<Button type="primary" icon={<RobotOutlined />} onClick={submitLogs}>提交当前检索结果给小影</Button>} />
      <Card className="mc-queue-card">
        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索用户 / Host / IP / Process / 原始日志" className="mc-search" />
          <Select value={source} onChange={setSource} style={{ width: 170 }} options={[{ value: 'all', label: '全部日志源' }, ...Array.from(new Set((!useRepositoryData ? events : remoteEvents).map((event) => event.source))).map((value) => ({ value, label: value }))]} />
        </div>
        {useRepositoryData ? (
          <div style={{ marginBottom: 12 }}>
            <Text type="secondary">{loading ? '正在查询真实日志数据...' : loadError || `真实日志模式 · 当前展示 ${filtered.length} 条 ${timeRange} 范围内结果`}</Text>
          </div>
        ) : (
          <div style={{ marginBottom: 12 }}>
            <Text type="secondary">已载入 {events.length.toLocaleString()} 条原始事件，当前筛选命中 {filtered.length.toLocaleString()} 条</Text>
          </div>
        )}
        <Table
          rowKey="id"
          loading={loading}
          columns={columns}
          dataSource={pageRows}
          pagination={{
            current: page,
            total: filtered.length,
            pageSize,
            showSizeChanger: false,
            showTotal: (total) => `共 ${total.toLocaleString()} 条`,
            onChange: (nextPage) => setPage(nextPage),
          }}
          scroll={{ x: 1100 }}
          onRow={(row) => ({ onClick: () => setSelected(row) })}
        />
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} width={620} title={selected?.id} extra={<Button size="small" icon={<LinkOutlined />} onClick={saveSelectedM3}>保存当前事件 30 分钟 M3 图</Button>}>
        {selected && (
          <Tabs
            items={[
              {
                key: 'normalized',
                label: '标准化字段',
                children: (
                  <Descriptions bordered size="small" column={1}>
                    <Descriptions.Item label="事件摘要">{selected.action}</Descriptions.Item>
                    <Descriptions.Item label="标准化动作">{selected.normalizedAction || '—'}</Descriptions.Item>
                    <Descriptions.Item label="执行者">{selected.actor || '—'}</Descriptions.Item>
                    <Descriptions.Item label="来源主机">{selected.host || '—'}</Descriptions.Item>
                    <Descriptions.Item label="进程">{selected.process || '—'}</Descriptions.Item>
                    <Descriptions.Item label="IP 地址">{selected.ip || '—'}</Descriptions.Item>
                    <Descriptions.Item label="异常发现">{selected.findingTitle}</Descriptions.Item>
                    <Descriptions.Item label="实体集合">{selected.entities?.join(', ') || '—'}</Descriptions.Item>
                    <Descriptions.Item label="证据编号">{selected.evidenceIds.join(', ') || '—'}</Descriptions.Item>
                  </Descriptions>
                ),
              },
              {
                key: 'raw',
                label: '原始日志',
                children: (
                  <>
                    <Descriptions bordered size="small" column={1}>
                      <Descriptions.Item label="日志源">{selected.source}</Descriptions.Item>
                      <Descriptions.Item label="原始日志引用">{selected.rawLogRef || `${selected.source}:${selected.id}`}</Descriptions.Item>
                    </Descriptions>
                    <Divider />
                    <ExplainableBlock fallback={selected.raw} context={eventContext(selected)} onExplain={onExplain}>
                      <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{selected.raw}</pre>
                    </ExplainableBlock>
                  </>
                ),
              },
              ...(selected.moduleScores ? [{
                key: 'pipeline',
                label: 'M0-M6 链路',
                children: (
                  <>
                    <Card size="small" title="真实上传处理结果">
                      <Text type="secondary">评分由 M0-M6 可解释检测链路综合计算。</Text>
                      <Row gutter={[8, 8]} style={{ marginTop: 12 }}>
                        {Object.entries(selected.moduleScores).map(([stage, score]) => (
                          <Col span={8} key={stage}>
                            <Statistic title={stage} value={Math.round(score * 100)} suffix="%" />
                          </Col>
                        ))}
                      </Row>
                    </Card>
                  </>
                ),
              }] : []),
            ]}
          />
        )}
      </Drawer>
    </>
  )
}
