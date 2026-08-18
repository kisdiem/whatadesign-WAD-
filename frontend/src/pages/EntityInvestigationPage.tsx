import { useEffect, useMemo, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Button, Card, Col, Divider, Input, List, Progress, Row, Space, Statistic, Table, Tag, Typography } from 'antd'
import { InfoCircleOutlined, LinkOutlined, RobotOutlined, SearchOutlined } from '@ant-design/icons'
import {
  getSecurityBaseline,
  getSecurityEntity,
  getSecurityEntityHistory,
  type AssistantContext,
  type SecurityBaselineRecord,
  type SecurityEntityRecord,
  type SecurityLogRecord,
} from '../services/api'
import { inferEntityType, type EntityProfile, type FindingRecord } from '../services/investigationDomain'
import {
  ExplainableText,
  HelpTitle,
  PageTitle,
  ReasonTag,
  parseAbsoluteDateTime,
  useRepositoryPresentation,
} from './shared'

const { Text, Title } = Typography

function normalizeEntityType(value?: string, fallback = 'Unknown'): EntityProfile['type'] {
  if (!value) return inferEntityType(fallback)
  if (value.toLowerCase() === 'user') return 'User'
  if (value.toLowerCase() === 'host') return 'Host'
  if (value.toLowerCase() === 'process') return 'Process'
  if (value.toLowerCase() === 'ip') return 'IP'
  return inferEntityType(fallback)
}

function extractTimePart(value?: string) {
  if (!value) return '—'
  const match = value.match(/(\d{2}:\d{2}(?::\d{2})?)$/)
  return match?.[1] || value
}

function deriveUsualActivity(events: SecurityLogRecord[]) {
  const hours = events
    .map((event) => parseAbsoluteDateTime(event.time || event.timestamp))
    .filter((value) => value > 0)
    .map((value) => new Date(value).getHours())
  if (!hours.length) return '—'
  return `${String(Math.min(...hours)).padStart(2, '0')}:00-${String(Math.max(...hours)).padStart(2, '0')}:59`
}

function deriveHostHistory(entityId: string, events: SecurityLogRecord[], fallbackHosts: EntityProfile['hostHistory'] = []) {
  const counts = new Map<string, number>()
  for (const event of events) {
    for (const item of event.entities || []) {
      if (item === entityId || inferEntityType(item) !== 'Host') continue
      counts.set(item, (counts.get(item) || 0) + 1)
    }
  }
  const derivedBase = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([host, count], index) => {
      const loginCount = events.filter((event) => (event.entities || []).includes(host) && /LOGIN|LOGON|AUTH|SSH|RDP|REMOTE|登录|认证|远程/i.test(`${event.text || ''} ${(event.labels || []).join(' ')}`)).length
      return { host, count, loginCount, loginShare: 0, isNew: index >= 1 || count <= 2 }
    })
  const totalLoginCount = derivedBase.reduce((sum, item) => sum + item.loginCount, 0)
  const derived = derivedBase.map((item) => ({
    ...item,
    loginShare: totalLoginCount > 0 ? Math.round((item.loginCount / totalLoginCount) * 100) : 0,
  }))
  return derived.length ? derived : fallbackHosts
}

function buildBaselineRows(
  entityId: string,
  entity: SecurityEntityRecord | null,
  baseline: SecurityBaselineRecord | null,
  hosts: EntityProfile['hostHistory'],
  fallback: EntityProfile['baseline'] = [],
) {
  const rarityScore = baseline?.rarity_score ?? ((entity?.risk || 0) / 100)
  const rows = [
    {
      feature: 'Event Count',
      current: String(entity?.event_count ?? 0),
      baseline: baseline?.activity_count != null ? String(baseline.activity_count) : '—',
      deviation: Math.max(0.08, Math.min(0.98, rarityScore || 0.12)),
    },
    {
      feature: '来源多样性',
      current: String(entity?.source_count ?? entity?.sources?.length ?? 0),
      baseline: baseline?.source_diversity != null ? String(baseline.source_diversity) : '—',
      deviation: Math.max(0.06, Math.min(0.95, (baseline?.source_diversity || 1) / Math.max(entity?.source_count || 1, 1))),
    },
    {
      feature: '当前主机',
      current: hosts.length ? hosts.map((item) => item.host).join(', ') : '—',
      baseline: baseline?.baseline_window || '30d',
      deviation: Math.max(0.1, Math.min(0.97, 0.35 + (hosts.filter((item) => item.isNew).length * 0.18))),
    },
    {
      feature: '稀有度',
      current: rarityScore ? rarityScore.toFixed(3) : '—',
      baseline: baseline?.baseline_window || '30d',
      deviation: Math.max(0.05, Math.min(0.99, rarityScore || 0.1)),
    },
  ].filter((item) => item.current !== '0' || item.baseline !== '—')
  return rows.length ? rows : fallback
}

export default function EntityInvestigationPage({
  profiles,
  findings,
  timeRange,
  onSubmitBatch,
  onExplain,
  onOpenFinding,
}: {
  profiles: EntityProfile[]
  findings: FindingRecord[]
  timeRange: string
  onSubmitBatch: (prompt: string, context: AssistantContext) => void
  onExplain: (excerpt: string, context: AssistantContext) => void
  onOpenFinding: () => void
}) {
  const location = useLocation()
  const useRepositoryData = useRepositoryPresentation()
  const [selectedId, setSelectedId] = useState(profiles[0]?.id || '')
  const [query, setQuery] = useState('')
  const [remoteEntity, setRemoteEntity] = useState<SecurityEntityRecord | null>(null)
  const [remoteHistory, setRemoteHistory] = useState<SecurityLogRecord[]>([])
  const [remoteBaseline, setRemoteBaseline] = useState<SecurityBaselineRecord | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const requestedEntity = useMemo(() => new URLSearchParams(location.search).get('entity') || '', [location.search])
  useEffect(() => {
    if (requestedEntity) {
      setSelectedId(requestedEntity)
    }
  }, [requestedEntity])
  useEffect(() => {
    if (!selectedId) {
      setSelectedId(profiles[0]?.id || '')
    }
  }, [profiles, selectedId])
  useEffect(() => {
    if (!useRepositoryData || !selectedId) {
      setRemoteEntity(null)
      setRemoteHistory([])
      setRemoteBaseline(null)
      setLoadError('')
      return
    }
    let active = true
    const loadEntityContext = async () => {
      setLoading(true)
      setLoadError('')
      const [entityResult, historyResult, baselineResult] = await Promise.allSettled([
        getSecurityEntity(selectedId),
        getSecurityEntityHistory(selectedId, timeRange),
        getSecurityBaseline(selectedId, '30d'),
      ])
      if (!active) return
      if (entityResult.status === 'fulfilled') {
        setRemoteEntity(entityResult.value)
      } else {
        setRemoteEntity(null)
        setLoadError(entityResult.reason instanceof Error ? entityResult.reason.message : '实体详情加载失败。')
      }
      setRemoteHistory(historyResult.status === 'fulfilled' ? historyResult.value.events : [])
      setRemoteBaseline(baselineResult.status === 'fulfilled' ? baselineResult.value : null)
      setLoading(false)
    }
    void loadEntityContext()
    return () => {
      active = false
    }
  }, [selectedId, timeRange, useRepositoryData])
  const localSelected = profiles.find((item) => item.id === selectedId) || profiles[0]
  const remoteSelected = useMemo<EntityProfile | null>(() => {
    if (!remoteEntity) return null
    const entityId = remoteEntity.entity_id || remoteEntity.id
    const fallback = localSelected
    const hostHistory = deriveHostHistory(entityId, remoteHistory, fallback?.hostHistory)
    const newRelations = hostHistory.filter((item) => item.isNew).length
    return {
      id: entityId,
      type: normalizeEntityType(remoteEntity.type, entityId),
      firstSeen: remoteEntity.first_seen || fallback?.firstSeen || '—',
      lastSeen: remoteEntity.last_seen || fallback?.lastSeen || '—',
      thirtyDayEvents: remoteEntity.event_count || remoteHistory.length || fallback?.thirtyDayEvents || 0,
      normalLoginHosts: Math.max(hostHistory.length - newRelations, 0),
      currentLoginHosts: hostHistory.length || fallback?.currentLoginHosts || 0,
      newHostRelations: newRelations,
      rareRelations: Math.max(1, Math.round((remoteBaseline?.rarity_score ?? (remoteEntity.risk || 0) / 100) * 4)),
      usualLogin: deriveUsualActivity(remoteHistory) || fallback?.usualLogin || '—',
      currentActivity: extractTimePart(remoteEntity.last_seen),
      hostHistory,
      baseline: buildBaselineRows(entityId, remoteEntity, remoteBaseline, hostHistory, fallback?.baseline),
      findingIds: fallback?.findingIds || [],
    }
  }, [localSelected, remoteBaseline, remoteEntity, remoteHistory])
  const availableProfiles = useMemo(
    () => (remoteSelected && !profiles.some((item) => item.id === remoteSelected.id) ? [remoteSelected, ...profiles] : profiles),
    [profiles, remoteSelected],
  )
  const selected = availableProfiles.find((item) => item.id === selectedId) || remoteSelected || availableProfiles[0]
  // Replay data arrives asynchronously; avoid deriving presentation fields
  // until the 30-day entity inventory is available.
  if (!selected) return null
  const filtered = availableProfiles.filter((item) => `${item.id} ${item.type}`.toLowerCase().includes(query.toLowerCase()))
  const relatedFindings = findings.filter((finding) => selected && (selected.findingIds.includes(finding.id) || finding.entities.includes(selected.id)))
  const entityTypeLabel: Record<EntityProfile['type'], string> = {
    User: '用户账号',
    Host: '主机',
    Process: '进程或程序',
    IP: 'IP 地址',
    Asset: '文件或资产',
  }
  const attentionLevel = selected.rareRelations >= 3 ? '高关注' : selected.rareRelations >= 2 ? '需要核查' : '一般关注'
  const attentionColor = selected.rareRelations >= 3 ? 'red' : selected.rareRelations >= 2 ? 'orange' : 'blue'
  const entityExplanation = `${entityTypeLabel[selected.type]} ${selected.id} 在近 30 天资产画像中出现 ${selected.thirtyDayEvents} 次，涉及 ${selected.currentLoginHosts} 个关联主机。系统将它标记为${attentionLevel}，主要依据是关联关系的稀有程度、最近活动与历史基线的偏离，以及它参与的异常发现。`

  const submitEntities = () => {
    const snapshot = filtered.map((profile) => {
      const profileFindings = findings.filter((finding) => profile.findingIds.includes(finding.id) || finding.entities.includes(profile.id))
      const findingSummary = profileFindings.map((finding) => `${finding.start} ${finding.title} (${finding.host || 'host unresolved'}, risk ${finding.risk})`).join('; ') || 'no linked finding'
      return `entity=${profile.id}; type=${entityTypeLabel[profile.type]}; first_seen=${profile.firstSeen}; last_seen=${profile.lastSeen}; event_count=${profile.thirtyDayEvents}; active_hosts=${profile.currentLoginHosts}; new_relations=${profile.newHostRelations}; linked_findings=${findingSummary}`
    }).join('\n')
    onSubmitBatch(
      `The following is the complete set of ${filtered.length} entities currently filtered in Entity Investigation, with their related findings. Analyze them as security investigation context. In Chinese, first state what this entity set represents, then list no more than four entities needing attention and why. Risk scores and anomalous-relation labels are leads, not proof of compromise. Do not invent events not present in this snapshot.\n\n${snapshot}`,
      { entityIds: filtered.map((item) => item.id), windowIds: Array.from(new Set(filtered.flatMap((item) => item.findingIds))), timeRange },
    )
  }

  return (
    <>
      <PageTitle title="实体调查" subtitle={`完整 30 天实体资产画像 · 当前关联发现聚焦 ${timeRange}`} extra={<Space><Button onClick={onOpenFinding}>异常发现</Button><Button type="primary" icon={<RobotOutlined />} onClick={submitEntities}>小影</Button></Space>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={7}>
          <Card title={`实体列表 · ${filtered.length}/${availableProfiles.length}`} className="mc-investigation-list">
            <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索实体" className="mc-search" />
            <Divider />
            <List
              dataSource={filtered}
              renderItem={(item) => (
                <List.Item className={item.id === selected?.id ? 'active' : ''} onClick={() => setSelectedId(item.id)}>
                  <List.Item.Meta title={<Text strong>{item.id}</Text>} description={`${entityTypeLabel[item.type]} · 最近活动 ${item.lastSeen}`} />
                  <Tag color={item.rareRelations >= 2 ? 'red' : 'blue'}>{item.rareRelations} 个异常关系</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={17}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3}><ExplainableText fallback={selected.id} context={{ entityIds: [selected.id], windowIds: selected.findingIds }} onExplain={onExplain}>{selected.id}</ExplainableText></Title>
                <Text type="secondary">{entityTypeLabel[selected.type]} · 首次出现 {selected.firstSeen} · 最近出现 {selected.lastSeen}</Text>
              </div>
              <Tag color={attentionColor}>关注级别：{attentionLevel}</Tag>
            </div>
            <div className="mc-entity-explanation">
              <InfoCircleOutlined />
              <div><strong>实体说明</strong><div>{entityExplanation}</div></div>
            </div>
            {useRepositoryData && (
              <div style={{ marginTop: 10 }}>
                <Text type="secondary">{loading ? '正在从真实数据层加载实体画像...' : loadError || `已接入真实实体数据 · ${timeRange} 历史窗口`}</Text>
              </div>
            )}
          </Card>

          <Row gutter={[12, 12]}>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="时间范围内事件" value={selected.thirtyDayEvents} suffix="次" /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="正常主机" value={selected.normalLoginHosts} /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="当前主机" value={selected.currentLoginHosts} /></Card></Col>
            <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="新增关系" value={selected.newHostRelations} /></Card></Col>
          </Row>

           <Row gutter={[12, 12]}>
             <Col xs={24}>
              <Card title={<HelpTitle title="基线对比" description="将当前实体行为与历史常态比较。偏离表示值得关注，不代表单独成立的攻击证据。" />} className="mc-panel">
                <Table
                  rowKey="feature"
                  pagination={false}
                  size="small"
                  columns={[
                    { title: '特征', dataIndex: 'feature', key: 'feature' },
                    { title: '当前观察', dataIndex: 'current', key: 'current' },
                    { title: '历史常态', dataIndex: 'baseline', key: 'baseline' },
                    { title: '偏离程度', dataIndex: 'deviation', key: 'deviation', render: (value: number) => <Space size={6}><Progress percent={Math.round(value * 100)} size="small" status={value >= 0.8 ? 'exception' : 'normal'} /><Text type="secondary">{value >= 0.8 ? '明显偏离' : value >= 0.6 ? '有所偏离' : '接近常态'}</Text></Space> },
                  ]}
                  dataSource={selected.baseline}
                  className="mc-baseline-table"
                  scroll={{ x: 582 }}
                />
              </Card>
            </Col>
            <Col span={24}>
              <Card title={<HelpTitle title="关联发现" description="列出近期与该实体有关的异常发现。点击关联理由标签可查看为什么被关联。" />} className="mc-panel">
                <Table
                  rowKey="id"
                  size="small"
                  pagination={{ pageSize: 5, hideOnSinglePage: true }}
                  columns={[
                    { title: '时间', dataIndex: 'start', key: 'start', width: 170 },
                    { title: '关联行为', dataIndex: 'title', key: 'title', width: 220 },
                    { title: '主机', dataIndex: 'host', key: 'host', width: 150 },
                    { title: <HelpTitle title="为什么关联" description="这些标签说明当前实体与异常发现之间的关联依据。点击标签可查看简要解释。" />, key: 'reason', render: (_: unknown, row: FindingRecord) => <Space size={4} wrap>{row.reasons.slice(0, 3).map((reason) => <ReasonTag key={reason} reason={reason} />)}</Space> },
                    { title: '风险', dataIndex: 'risk', key: 'risk', width: 90, render: (value: number) => <Tag color={value >= 75 ? 'red' : value >= 50 ? 'orange' : 'blue'}>{value}</Tag> },
                  ]}
                  dataSource={relatedFindings}
                  locale={{ emptyText: '当前实体暂无关联异常发现' }}
                />
                {/*
                  dot: <ClockCircleOutlined />,
                  children: <div><strong>{finding.start}</strong><div>{finding.title}</div><Text type="secondary">{finding.id} · {finding.host}</Text></div>,
                }))} */}
              </Card>
            </Col>
            <Col span={24}>
              <Card title={<HelpTitle title="调查提示" description="根据当前证据整理的复核方向，帮助分析人员决定下一步查看什么。" />} className="mc-panel">
                <Space direction="vertical" size={6}>
                  <Text><LinkOutlined /> 优先核对：{selected.currentActivity} 附近是否存在认证、远程访问或进程启动行为。</Text>
                  <Text><LinkOutlined /> 关系变化：当前关联 {selected.currentLoginHosts} 台主机，其中 {selected.newHostRelations} 台被识别为新增关系。</Text>
                  <Text><LinkOutlined /> 证据边界：以上内容来自实体历史、标准化事件和关联发现；异常分数是模型判断，不会改写原始日志事实。</Text>
                </Space>
              </Card>
            </Col>
          </Row>
        </Col>
      </Row>
    </>
  )
}
