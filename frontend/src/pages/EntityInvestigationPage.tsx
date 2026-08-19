import { useEffect, useMemo, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Button, Card, Col, Descriptions, Divider, Input, List, Progress, Row, Space, Statistic, Table, Tag, Typography } from 'antd'
import { ApartmentOutlined, ClockCircleFilled, DesktopOutlined, InfoCircleOutlined, LinkOutlined, RobotOutlined, SearchOutlined, WarningFilled } from '@ant-design/icons'
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
  readableAction,
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

function riskTagColor(value: number) {
  if (value >= 75) return 'red'
  if (value >= 50) return 'orange'
  return 'green'
}

function relationTagColor(value: number) {
  if (value >= 3) return 'red'
  if (value >= 2) return 'orange'
  return 'green'
}

function deviationTagColor(value: number) {
  if (value >= 0.8) return 'red'
  if (value >= 0.6) return 'orange'
  return 'green'
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
  const attentionColor = selected.rareRelations >= 3 ? 'red' : selected.rareRelations >= 2 ? 'orange' : 'green'
  const associatedHosts = selected.hostHistory.map((item) => `${item.host}（${item.count} 次）`).join('、') || '暂无已确认关联主机'
  const riskReason = relatedFindings.length
    ? `关联 ${relatedFindings.length} 个异常发现，最高风险 ${Math.max(...relatedFindings.map((finding) => finding.risk))}；需结合对应事件和原始日志复核。`
    : `${attentionLevel}：依据事件频次、关联关系稀有程度和最近活动变化标记，当前没有直接关联的异常发现。`

  const submitEntities = () => {
    const snapshot = filtered.map((profile) => {
      const profileFindings = findings.filter((finding) => profile.findingIds.includes(finding.id) || finding.entities.includes(profile.id))
      const findingSummary = profileFindings.map((finding) => `${finding.start} ${finding.title} (${finding.host || 'host unresolved'}, risk ${finding.risk})`).join('; ') || 'no linked finding'
      return `entity=${profile.id}; type=${entityTypeLabel[profile.type]}; first_seen=${profile.firstSeen}; last_seen=${profile.lastSeen}; event_count=${profile.thirtyDayEvents}; active_hosts=${profile.currentLoginHosts}; new_relations=${profile.newHostRelations}; linked_findings=${findingSummary}`
    })
    // 后端 /agent/query/stream 的 message 上限为 12000 字符，批量实体快照极易超限
    // 触发 422 校验失败，前端会静默降级为演示回答。这里按预算截断快照文本，
    // 实体清单本身仍通过 context.entityIds 完整传递。
    const SNAPSHOT_BUDGET = 9500
    let snapshotText = ''
    for (const line of snapshot) {
      if (snapshotText.length + line.length + 1 > SNAPSHOT_BUDGET) break
      snapshotText += `${snapshotText ? '\n' : ''}${line}`
    }
    const includedCount = snapshotText ? snapshotText.split('\n').length : 0
    const scopeLabel = includedCount < filtered.length
      ? `the top ${includedCount} of ${filtered.length} entities currently filtered`
      : `the complete set of ${filtered.length} entities currently filtered`
    onSubmitBatch(
      `The following is ${scopeLabel} in Entity Investigation, with their related findings. Analyze them as security investigation context. In Chinese, first state what this entity set represents, then list no more than four entities needing attention and why. Risk scores and anomalous-relation labels are leads, not proof of compromise. Do not invent events not present in this snapshot.\n\n${snapshotText}`,
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
                  <span className={`mc-entity-relation-chip ${item.rareRelations >= 3 ? 'high' : item.rareRelations >= 2 ? 'review' : 'low'}`}>{item.rareRelations} 个异常关系</span>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={17}>
          <Card className="mc-case-card">
            <div className="mc-case-head">
              <div>
                <Title level={3} className="mc-entity-title"><ExplainableText fallback={selected.id} context={{ entityIds: [selected.id], windowIds: selected.findingIds }} onExplain={onExplain}>{selected.id}</ExplainableText></Title>
                <Text type="secondary">{entityTypeLabel[selected.type]} · 首次出现 <Text strong>{selected.firstSeen}</Text> · 最近出现 <Text strong>{selected.lastSeen}</Text></Text>
              </div>
              <Tag color={attentionColor}>关注级别：{attentionLevel}</Tag>
            </div>
            <div className="mc-entity-explanation">
              <InfoCircleOutlined />
              <div className="mc-entity-explanation-content">
                <Space size={8} wrap>
                  <Tag color={attentionColor}>{attentionLevel}</Tag>
                  <Text>已出现 {selected.thirtyDayEvents} 次，关联 {selected.currentLoginHosts} 台主机，关联发现 {relatedFindings.length} 个。</Text>
                </Space>
              </div>
            </div>
            {useRepositoryData && (
              <div style={{ marginTop: 10 }}>
                <Text type="secondary">{loading ? '正在从真实数据层加载实体画像...' : loadError || `已接入真实实体数据 · ${timeRange} 历史窗口`}</Text>
              </div>
            )}
          </Card>

          <Row gutter={[8, 8]} className="mc-entity-summary-row">
            <Col xs={12} md={6}><Card size="small" className={`mc-summary-card mc-entity-kpi mc-entity-kpi-${attentionColor}`}><Statistic title={<span><WarningFilled /> 风险等级</span>} value={attentionLevel} /></Card></Col>
            <Col xs={12} md={6}><Card size="small" className="mc-summary-card mc-entity-kpi mc-entity-kpi-blue"><Statistic title={<span><ClockCircleFilled /> 关联事件</span>} value={selected.thirtyDayEvents} suffix="次" /></Card></Col>
            <Col xs={12} md={6}><Card size="small" className="mc-summary-card mc-entity-kpi mc-entity-kpi-green"><Statistic title={<span><DesktopOutlined /> 关联主机</span>} value={selected.currentLoginHosts} /></Card></Col>
            <Col xs={12} md={6}><Card size="small" className="mc-summary-card mc-entity-kpi mc-entity-kpi-purple"><Statistic title={<span><ApartmentOutlined /> 攻击步骤</span>} value={relatedFindings.length} /></Card></Col>
          </Row>

          <Card title="实体关键信息" className="mc-panel">
            <Descriptions size="small" column={{ xs: 1, sm: 2, md: 3 }}>
              <Descriptions.Item label="原名">{selected.id}</Descriptions.Item>
              <Descriptions.Item label="实体类型">{entityTypeLabel[selected.type]}</Descriptions.Item>
              <Descriptions.Item label="关联事件数">{selected.thirtyDayEvents} 次</Descriptions.Item>
              <Descriptions.Item label="首次出现">{selected.firstSeen}</Descriptions.Item>
              <Descriptions.Item label="最近出现">{selected.lastSeen}</Descriptions.Item>
              <Descriptions.Item label="关联主机">{associatedHosts}</Descriptions.Item>
              <Descriptions.Item label="参与的攻击步骤" span={3}>
                <Space size={[4, 4]} wrap>
                  {relatedFindings.length
                    ? relatedFindings.slice(0, 6).map((finding) => <Tag className="mc-attack-step-tag" key={finding.id} color={riskTagColor(finding.risk)}>{readableAction(`${finding.anchorEvent.action} ${finding.anchorEvent.raw || ''}`)}</Tag>)
                    : <Text type="secondary">暂无已关联攻击步骤</Text>}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="风险原因" span={3}>{riskReason}</Descriptions.Item>
            </Descriptions>
          </Card>

           <Row gutter={[12, 12]}>
             {false && <Col xs={24}>
              <Card title={<HelpTitle title="基线对比" description="将当前实体行为与历史常态比较。偏离表示值得关注，不代表单独成立的攻击证据。" />} className="mc-panel">
                <Table
                  rowKey="feature"
                  pagination={false}
                  size="small"
                  columns={[
                    { title: '特征', dataIndex: 'feature', key: 'feature' },
                    { title: '当前观察', dataIndex: 'current', key: 'current' },
                    { title: '历史常态', dataIndex: 'baseline', key: 'baseline' },
                    { title: '偏离程度', dataIndex: 'deviation', key: 'deviation', render: (value: number) => <Space size={6}><Progress percent={Math.round(value * 100)} size="small" strokeColor={deviationTagColor(value) === 'red' ? '#dc2626' : deviationTagColor(value) === 'orange' ? '#d97706' : '#16a34a'} trailColor="#e5e7eb" /><Tag color={deviationTagColor(value)}>{value >= 0.8 ? '明显偏离' : value >= 0.6 ? '有所偏离' : '接近常态'}</Tag></Space> },
                  ]}
                  dataSource={selected.baseline}
                  className="mc-baseline-table"
                  scroll={{ x: 582 }}
                />
              </Card>
             </Col>}
             <Col span={24}>
              <Card title={<HelpTitle title="关联发现" description="列出近期与该实体有关的异常发现。点击关联理由标签可查看为什么被关联。" />} className="mc-panel">
                <Table
                  rowKey="id"
                  size="small"
                  pagination={{ pageSize: 5, hideOnSinglePage: true }}
                  columns={[
                    { title: '时间', dataIndex: 'start', key: 'start', width: 155, render: (value: string) => <Text strong className="mc-finding-time">{value}</Text> },
                    { title: '发生了什么', key: 'action', width: 230, render: (_: unknown, row: FindingRecord) => <div><Text strong>{readableAction(`${row.anchorEvent.action} ${row.anchorEvent.raw || ''}`)}</Text><div className="mc-finding-summary">{row.summary}</div></div> },
                    { title: '关联主机', dataIndex: 'host', key: 'host', width: 140, render: (value: string) => <Tag color="blue" className="mc-finding-host-tag">{value || '待解析'}</Tag> },
                    { title: '为什么关联', key: 'reason', render: (_: unknown, row: FindingRecord) => <Space size={[4, 4]} wrap>{row.reasons.slice(0, 2).map((reason) => <ReasonTag key={reason} reason={reason} />)}</Space> },
                    { title: '风险', dataIndex: 'risk', key: 'risk', width: 100, render: (value: number) => <Tag color={riskTagColor(value)} className={`mc-finding-risk-tag ${value >= 75 ? 'high' : value >= 50 ? 'review' : 'low'}`}>{value >= 75 ? '高风险' : value >= 50 ? '需核查' : '低风险'} · {value}</Tag> },
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
             {false && <Col span={24}>
              <Card title={<HelpTitle title="调查提示" description="根据当前证据整理的复核方向，帮助分析人员决定下一步查看什么。" />} className="mc-panel">
                <Space direction="vertical" size={6}>
                  <Text><LinkOutlined /> 优先核对：{selected.currentActivity} 附近是否存在认证、远程访问或进程启动行为。</Text>
                  <Text><LinkOutlined /> 关系变化：当前关联 {selected.currentLoginHosts} 台主机，其中 {selected.newHostRelations} 台被识别为新增关系。</Text>
                  <Text><LinkOutlined /> 证据边界：以上内容来自实体历史、标准化事件和关联发现；异常分数是模型判断，不会改写原始日志事实。</Text>
                </Space>
              </Card>
             </Col>}
          </Row>
        </Col>
      </Row>
    </>
  )
}
