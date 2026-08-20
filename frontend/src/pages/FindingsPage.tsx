import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Col, Descriptions, Divider, Drawer, Input, List, Modal, Progress, Radio, Row, Select, Space, Statistic, Table, Typography } from 'antd'
import { RobotOutlined, SearchOutlined } from '@ant-design/icons'
import type { EvidenceRecord, FindingRecord } from '../services/investigationDomain'
import type { Investigation } from '../mocks/data'
import { buildM3GraphSnapshot, layoutForceDirected } from '../services/caseGraphs'
import InteractiveCaseGraph from '../InteractiveCaseGraph'
import {
  HelpTitle,
  PageTitle,
  ReasonTag,
  RiskBadge,
  findingSeverityLevels,
  findingSortOptions,
  parseAbsoluteDateTime,
  readableAction,
  investigationQueueStatus,
  scoreTone,
  severityLabel,
  type FindingSortMode,
} from './shared'

const { Paragraph, Text } = Typography

function riskMetricClass(value: number) {
  return value >= 80 ? 'critical' : value >= 65 ? 'high' : 'medium'
}

export default function FindingsPage({
  findings,
  evidenceByFinding,
  onOpenAssistant,
  onOpenEntity,
  investigations,
  onSaveToInvestigation,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  onOpenAssistant: (finding: FindingRecord) => void
  onOpenEntity: (entityId: string) => void
  investigations: Investigation[]
  onSaveToInvestigation: (finding: FindingRecord, investigationId: string | null) => void
}) {
  const [selected, setSelected] = useState<FindingRecord | null>(null)
  const [investigationPickerOpen, setInvestigationPickerOpen] = useState(false)
  const [investigationTarget, setInvestigationTarget] = useState<string>('new')
  const pendingInvestigations = useMemo(
    () => investigations.filter((item) => investigationQueueStatus(item) === 'manual_review' || item.status === 'investigating'),
    [investigations],
  )
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [source, setSource] = useState('all')
  const [sortMode, setSortMode] = useState<FindingSortMode>('risk_desc')

  const filtered = useMemo(() => {
    const matched = findings.filter((finding) => {
      const haystack = [finding.id, finding.title, finding.entity, finding.host, finding.source, finding.reasons.join(' ')].join(' ').toLowerCase()
      return haystack.includes(query.toLowerCase())
        && (severity === 'all' || finding.severity === severity)
        && (source === 'all' || finding.source.includes(source))
    })
    return [...matched].sort((left, right) => {
      if (sortMode === 'long_desc') return right.longScore - left.longScore || right.risk - left.risk || right.eventScore - left.eventScore
      if (sortMode === 'event_desc') return right.eventScore - left.eventScore || right.risk - left.risk || right.longScore - left.longScore
      if (sortMode === 'latest_desc') return parseAbsoluteDateTime(right.start) - parseAbsoluteDateTime(left.start) || right.risk - left.risk
      return right.risk - left.risk || right.longScore - left.longScore || right.eventScore - left.eventScore
    })
  }, [findings, query, severity, sortMode, source])

  const m3Snapshot = useMemo(() => (selected ? buildM3GraphSnapshot(selected) : null), [selected])
  const m3Layout = useMemo(() => {
    if (!m3Snapshot) return null
    const hasLayout = m3Snapshot.nodes.some((node) => node.x !== undefined && node.y !== undefined)
    return hasLayout ? { nodes: m3Snapshot.nodes, links: m3Snapshot.links } : layoutForceDirected(m3Snapshot.nodes, m3Snapshot.links)
  }, [m3Snapshot])

  useEffect(() => {
    if (!filtered.length) {
      setSelected(null)
      return
    }
    if (selected && !filtered.some((item) => item.id === selected.id)) {
      setSelected(null)
    }
  }, [filtered, selected])

  const columns = [
    { title: '关键行为', key: 'action', width: 220, render: (_: unknown, row: FindingRecord) => <div><Text strong>{readableAction(row.anchorEvent.action)}</Text><div className="mc-row-id">{row.start}</div></div> },
    { title: '调查对象', key: 'entity', width: 170, render: (_: unknown, row: FindingRecord) => <div><div>{row.entity}</div><Text type="secondary">{row.entityType} · {row.host || '主机待解析'}</Text></div> },
    { title: '风险', dataIndex: 'risk', key: 'risk', width: 90, render: (value: number) => <RiskBadge value={value} /> },
    { title: '为什么关注', key: 'reason', render: (_: unknown, row: FindingRecord) => <div><Text>{row.summary}</Text><div style={{ marginTop: 5 }}><Space size={[4, 4]} wrap>{row.reasons.slice(0, 3).map((item) => <ReasonTag key={item} reason={item} />)}</Space></div></div> },
  ]

  return (
    <>
      <PageTitle title="异常发现" />
      <Card className="mc-queue-card">
        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索异常发现 / 实体 / 主机 / 理由" className="mc-search" />
          <Select value={severity} onChange={setSeverity} style={{ width: 120 }} options={[{ value: 'all', label: '全部风险' }, ...findingSeverityLevels.map((value) => ({ value, label: severityLabel[value] }))]} />
          <Select value={source} onChange={setSource} style={{ width: 150 }} options={[{ value: 'all', label: '全部日志源' }, ...Array.from(new Set(findings.flatMap((finding) => finding.sourceTypes))).map((value) => ({ value, label: value }))]} />
          <Select
            value={sortMode}
            onChange={(value) => setSortMode(value as FindingSortMode)}
            style={{ width: 190 }}
            options={findingSortOptions}
            aria-label="发现排序方式"
          />
        </div>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={filtered}
          pagination={{ pageSize: 8, showSizeChanger: false }}
          scroll={{ x: 1100 }}
          onRow={(row) => ({ onClick: () => setSelected(row) })}
          rowClassName="mc-queue-row"
        />
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} width={680} title={selected?.title} extra={selected && <RiskBadge value={selected.risk} />}>
        {selected && (
          <div className="mc-detail-drawer">
            <Card size="small" className="mc-investigation-brief" title="调查摘要">
              <Descriptions size="small" column={1}>
                <Descriptions.Item label="发生了什么"><Text strong>{readableAction(selected.anchorEvent.action)}</Text> · {selected.summary}</Descriptions.Item>
                <Descriptions.Item label="原始事件">
                  <Paragraph
                    className="mc-raw-event-detail"
                    copyable
                    ellipsis={{ rows: 4, expandable: true, symbol: '展开原文' }}
                  >
                    {selected.anchorEvent.raw || selected.anchorEvent.action || '暂无原始事件'}
                  </Paragraph>
                </Descriptions.Item>
                <Descriptions.Item label="重点对象">{selected.entity} · {selected.host || '主机待解析'}</Descriptions.Item>
                <Descriptions.Item label="调查范围">{selected.start} 至 {selected.end} · {selected.events.length} 条事件</Descriptions.Item>
                <Descriptions.Item label="当前结论"><Text type="secondary">这是需要优先核验的异常线索，不等同于已确认攻击。</Text></Descriptions.Item>
              </Descriptions>
            </Card>
            <Card size="small" title={<HelpTitle title="M3 事件关联图" description="当前异常发现的 30 分钟事实窗口：事件、实体、时间先后与涉及关系，随所选发现即时构建，无需保存。" />} className="mc-drawer-card" styles={{ body: { padding: 0 } }}>
              {m3Layout ? (
                <InteractiveCaseGraph
                  key={`m3:${selected.id}`}
                  nodes={m3Layout.nodes}
                  links={m3Layout.links}
                  height={440}
                  positions={{}}
                  onPositionsChange={() => {}}
                  onNodeClick={() => {}}
                  onEdgeClick={() => {}}
                  staticView
                />
              ) : <Text type="secondary">暂无可用事件构建 M3 关联图。</Text>}
            </Card>

            <Card size="small" title={<HelpTitle title="调查锚点" description="当前异常发现的核心对象、主机和时间范围，是开始复核的切入点。" />} className="mc-drawer-card">
              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label="关键行为">{readableAction(selected.anchorEvent.action)}</Descriptions.Item>
                <Descriptions.Item label="实体">{selected.entity}</Descriptions.Item>
                <Descriptions.Item label="主机">{selected.host}</Descriptions.Item>
                <Descriptions.Item label="锚点事件">{selected.anchorEvent.action}</Descriptions.Item>
                <Descriptions.Item label="Investigation Range">过去 1 小时</Descriptions.Item>
                <Descriptions.Item label="Model Context">过去 30 分钟</Descriptions.Item>
              </Descriptions>
            </Card>

            <Card size="small" title={<HelpTitle title="M6 风险融合" description="综合事件自身、短程上下文和长程关联形成排序分数。分数用于优先级，不是攻击结论。" />} className="mc-drawer-card">
              <Row gutter={8} wrap={false} className="mc-compact-risk-row">
                <Col flex="1"><Statistic className={`mc-risk-stat ${riskMetricClass(selected.risk)}`} title="综合风险" value={selected.risk} /></Col>
                <Col flex="1"><Statistic className={`mc-risk-stat ${riskMetricClass(selected.eventScore)}`} title="事件自身异常" value={selected.eventScore} /></Col>
                <Col flex="1"><Statistic className={`mc-risk-stat ${riskMetricClass(selected.localScore)}`} title="局部上下文" value={selected.localScore} /></Col>
                <Col flex="1"><Statistic className={`mc-risk-stat ${riskMetricClass(selected.longScore)}`} title="长程关联" value={selected.longScore} /></Col>
              </Row>
              <Divider style={{ margin: '12px 0 8px' }} />
              <Text type="secondary">综合风险 = M6 风险融合输出（weak_fusion_v2），融合事件异常、局部上下文与长程关联信号。</Text>
            </Card>

            <Card size="small" title={<HelpTitle title="远程候选" description="与当前发现相隔较远但存在实体或行为关联的候选证据，需要人工确认。" />} className="mc-drawer-card">
              <List
                dataSource={selected.relatedCandidates}
                locale={{ emptyText: '暂无远程候选' }}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta title={<Text strong>{item.title}</Text>} description={item.time} />
                    <Space size={[4, 4]} wrap>{item.reasons.map((reason) => <ReasonTag key={`${item.id}-${reason}`} reason={reason} />)}</Space>
                  </List.Item>
                )}
              />
            </Card>

            <Card size="small" title={<HelpTitle title="M5 关联依据" description="说明长程关联使用的共同实体、时间间隔和关联强度。" />} className="mc-drawer-card">
              <Text>
                当前发现与其他窗口通过 <Text strong>{selected.association.sharedAnchor}</Text> 相关，时间间隔为 <Text strong>{selected.association.timeGap}</Text>。
                关联行为具有 <Text strong>{selected.association.actionCompatibility.toFixed(2)}</Text> 的兼容度，作为长程调查线索，仍需结合原始日志复核。
              </Text>
              <Descriptions size="small" column={1} style={{ marginTop: 10 }}>
                <Descriptions.Item label="共享对象">{selected.association.sharedAnchor}</Descriptions.Item>
                <Descriptions.Item label="时间间隔">{selected.association.timeGap}</Descriptions.Item>
                <Descriptions.Item label="关联行为">{selected.association.summary[0] || '存在跨窗口行为关联'}</Descriptions.Item>
              </Descriptions>
            </Card>

            <Card size="small" title={<HelpTitle title="证据" description="保留支撑该发现的原始日志引用和事实陈述，可作为人工复核依据。" />} className="mc-drawer-card">
              <List
                dataSource={evidenceByFinding[selected.id]}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta title={<Text strong>{item.statement}</Text>} description={item.rawLogRef} />
                  </List.Item>
                )}
              />
            </Card>

            <Space wrap>
              <Button onClick={() => onOpenEntity(selected.entity)}>实体画像</Button>
              <Button onClick={() => { setInvestigationTarget('new'); setInvestigationPickerOpen(true) }}>案件调查</Button>
                <Button type="primary" icon={<RobotOutlined />} onClick={() => onOpenAssistant(selected)}>小影</Button>
            </Space>
          </div>
        )}
      </Drawer>
      <Modal
        open={investigationPickerOpen}
        title="加入案件调查"
        okText="保存并查看案件"
        cancelText="取消"
        onCancel={() => setInvestigationPickerOpen(false)}
        onOk={() => {
          if (!selected) return
          onSaveToInvestigation(selected, investigationTarget === 'new' ? null : investigationTarget)
          setInvestigationPickerOpen(false)
          setSelected(null)
        }}
      >
        <Radio.Group
          value={investigationTarget}
          onChange={(event) => setInvestigationTarget(event.target.value)}
          style={{ width: '100%' }}
        >
          <Space direction="vertical" style={{ width: '100%' }}>
            <Radio value="new">创建新的调查事项</Radio>
            {pendingInvestigations.length > 0 && <Typography.Text type="secondary">合并到待研判或调查中的事项：</Typography.Text>}
            {pendingInvestigations.map((item) => <Radio key={item.id} value={item.id}>{item.title} · {item.windowIds.length} 个事件 · {item.owner}</Radio>)}
          </Space>
        </Radio.Group>
        {pendingInvestigations.length === 0 && <Typography.Text type="secondary" style={{ display: 'block', marginTop: 12 }}>当前没有可合并的待研判或调查中事项。</Typography.Text>}
      </Modal>
    </>
  )
}
