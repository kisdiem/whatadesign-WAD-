import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Col, Descriptions, Divider, Drawer, Input, List, Progress, Row, Select, Space, Statistic, Table, Typography } from 'antd'
import { RobotOutlined, SearchOutlined } from '@ant-design/icons'
import type { EvidenceRecord, FindingRecord } from '../services/investigationDomain'
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
  scoreTone,
  severityLabel,
  type FindingSortMode,
} from './shared'

const { Text } = Typography

export default function FindingsPage({
  findings,
  evidenceByFinding,
  onOpenAssistant,
  onOpenEntity,
  onOpenInvestigation,
}: {
  findings: FindingRecord[]
  evidenceByFinding: Record<string, EvidenceRecord[]>
  onOpenAssistant: (finding: FindingRecord) => void
  onOpenEntity: (entityId: string) => void
  onOpenInvestigation: () => void
}) {
  const [selected, setSelected] = useState<FindingRecord | null>(null)
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
    { title: 'Finding', dataIndex: 'title', key: 'title', render: (value: string, row: FindingRecord) => <div><Text strong>{value}</Text><div className="mc-row-id">{row.id}</div></div> },
    { title: '实体', dataIndex: 'entity', key: 'entity', width: 140, render: (value: string, row: FindingRecord) => <div><div>{value}</div><Text type="secondary">{row.entityType}</Text></div> },
    { title: '综合风险', dataIndex: 'risk', key: 'risk', width: 100, render: (value: number) => <RiskBadge value={value} /> },
    { title: '事件异常', dataIndex: 'eventScore', key: 'eventScore', width: 120, render: (value: number) => <Progress percent={value} size="small" status={scoreTone(value)} /> },
    { title: '局部上下文', dataIndex: 'localScore', key: 'localScore', width: 120, render: (value: number) => <Progress percent={value} size="small" status={scoreTone(value)} /> },
    { title: '长程关联', dataIndex: 'longScore', key: 'longScore', width: 120, render: (value: number) => <Progress percent={Math.min(100, Math.max(0, Number(value)))} size="small" status={scoreTone(Number(value))} format={(percent) => `${percent ?? 0}%`} /> },
    { title: <HelpTitle title="理由" description="理由说明系统为何将该发现列为需要关注。点击每个标签可查看具体关联依据。" />, dataIndex: 'reasons', key: 'reasons', render: (value: string[]) => <Space size={[4, 4]} wrap>{value.map((item) => <ReasonTag key={item} reason={item} />)}</Space> },
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
                <Descriptions.Item label="异常发现">{selected.id}</Descriptions.Item>
                <Descriptions.Item label="实体">{selected.entity}</Descriptions.Item>
                <Descriptions.Item label="主机">{selected.host}</Descriptions.Item>
                <Descriptions.Item label="锚点事件">{selected.anchorEvent.action}</Descriptions.Item>
                <Descriptions.Item label="Investigation Range">过去 1 小时</Descriptions.Item>
                <Descriptions.Item label="Model Context">过去 30 分钟</Descriptions.Item>
              </Descriptions>
            </Card>

            <Card size="small" title={<HelpTitle title="M6 风险融合" description="综合事件自身、短程上下文和长程关联形成排序分数。分数用于优先级，不是攻击结论。" />} className="mc-drawer-card">
              <Row gutter={[8, 8]}>
                <Col span={8}><Statistic title="综合风险" value={selected.risk} /></Col>
                <Col span={8}><Statistic title="事件自身异常" value={selected.eventScore} /></Col>
                <Col span={8}><Statistic title="局部上下文" value={selected.localScore} /></Col>
                <Col span={24}><Statistic title="长程关联" value={selected.longScore} /></Col>
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
                    <List.Item.Meta title={<Text strong>{item.title}</Text>} description={`${item.id} · ${item.time}`} />
                    <Space size={[4, 4]} wrap>{item.reasons.map((reason) => <ReasonTag key={`${item.id}-${reason}`} reason={reason} />)}</Space>
                  </List.Item>
                )}
              />
            </Card>

            <Card size="small" title={<HelpTitle title="M5 关联依据" description="说明长程关联使用的共同实体、时间间隔和关联强度。" />} className="mc-drawer-card">
              <Descriptions size="small" column={2}>
                <Descriptions.Item label="关联置信度">{selected.association.confidence.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="共享锚点">{selected.association.sharedAnchor}</Descriptions.Item>
                <Descriptions.Item label="锚点强度">{selected.association.anchorStrength}</Descriptions.Item>
                <Descriptions.Item label="实体稀有度">{selected.association.entityRarity.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="行为兼容度">{selected.association.actionCompatibility.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="图相似度">{selected.association.graphSimilarity.toFixed(2)}</Descriptions.Item>
                <Descriptions.Item label="时间间隔" span={2}>{selected.association.timeGap}</Descriptions.Item>
              </Descriptions>
              <Divider />
              <List size="small" dataSource={selected.association.summary} renderItem={(item) => <List.Item>{item}</List.Item>} />
            </Card>

            <Card size="small" title={<HelpTitle title="证据" description="保留支撑该发现的原始日志引用和事实陈述，可作为人工复核依据。" />} className="mc-drawer-card">
              <List
                dataSource={evidenceByFinding[selected.id]}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta title={<Text strong>{item.statement}</Text>} description={`${item.id} · ${item.rawLogRef}`} />
                  </List.Item>
                )}
              />
            </Card>

            <Space wrap>
              <Button onClick={() => onOpenEntity(selected.entity)}>实体画像</Button>
              <Button onClick={onOpenInvestigation}>案件调查</Button>
                <Button type="primary" icon={<RobotOutlined />} onClick={() => onOpenAssistant(selected)}>小影</Button>
            </Space>
          </div>
        )}
      </Drawer>
    </>
  )
}
