import { useMemo, useState, type Dispatch, type ReactNode, type SetStateAction } from 'react'
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Drawer,
  Form,
  Input,
  Layout,
  List,
  Menu,
  Modal,
  Row,
  Segmented,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Timeline,
  Typography,
  message,
} from 'antd'
import {
  ApartmentOutlined,
  CheckCircleFilled,
  ClockCircleOutlined,
  DatabaseOutlined,
  FileSearchOutlined,
  FolderOpenOutlined,
  PlusOutlined,
  ReloadOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SendOutlined,
  SettingOutlined,
  ThunderboltOutlined,
  UserOutlined,
} from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import {
  anomalyWindows,
  investigations,
  logSources,
  overviewSeries,
  type AnomalyWindow,
  type Investigation,
  type LogSource,
  type SecurityEvent,
  type Severity,
} from './mocks/data'
import { askAssistant, type AssistantAnswer, type AssistantContext } from './services/api'

const { Header, Sider, Content } = Layout
const { Title, Text, Paragraph } = Typography

type QueueType = 'Finding' | 'Investigation'
type QueueStatus = '新建' | '处理中' | '待处理' | '已解决' | '已关闭'
type QueueUrgency = '严重' | '高危' | '中危' | '低危'

type QueueRow = {
  key: string
  type: QueueType
  name: string
  entity: string
  risk: number
  findings: number
  time: string
  disposition: string
  urgency: QueueUrgency
  status: QueueStatus
  owner: string
  domain: string
  source: string
  summary: string
  window?: AnomalyWindow
  investigation?: Investigation
}

type ChatItem = {
  role: 'user' | 'assistant'
  content: string
  evidence?: AssistantAnswer['evidence']
}

const severityLabel: Record<Severity, QueueUrgency> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const statusLabel: Record<AnomalyWindow['status'], QueueStatus> = {
  new: '新建',
  reviewing: '待处理',
  investigating: '处理中',
  ignored: '已解决',
  closed: '已关闭',
}

const urgencyColor: Record<QueueUrgency, string> = {
  严重: '#b42318',
  高危: '#e5484d',
  中危: '#f59e0b',
  低危: '#2563eb',
}

function inferDomain(item: AnomalyWindow) {
  if (item.sourceTypes.some((source) => /EDR/i.test(source))) return 'Endpoint'
  if (item.sourceTypes.some((source) => /Firewall|Flow/i.test(source))) return 'Network'
  if (item.sourceTypes.some((source) => /Windows/i.test(source))) return 'Identity'
  return 'Threat'
}

function queueFromData(): QueueRow[] {
  const findingRows = anomalyWindows.map<QueueRow>((item, index) => ({
    key: item.id,
    type: 'Finding',
    name: item.title,
    entity: item.entities[0] || item.hosts[0] || 'Unknown',
    risk: Math.round(item.score * 100),
    findings: 1,
    time: item.end,
    disposition: item.status === 'ignored' ? '良性活动' : '待研判',
    urgency: severityLabel[item.severity],
    status: statusLabel[item.status],
    owner: item.status === 'investigating' ? 'analyst-01' : index % 5 === 0 ? 'analyst-02' : '未分配',
    domain: inferDomain(item),
    source: item.sourceTypes.join(' / '),
    summary: item.summary,
    window: item,
  }))

  const investigationRows = investigations.map<QueueRow>((item) => {
    const linked = item.windowIds.map((id) => anomalyWindows.find((window) => window.id === id)).filter(Boolean) as AnomalyWindow[]
    const maxRisk = linked.length ? Math.max(...linked.map((window) => Math.round(window.score * 100))) : 50
    return {
      key: item.id,
      type: 'Investigation',
      name: item.title,
      entity: linked[0]?.entities[0] || 'Multiple entities',
      risk: maxRisk,
      findings: item.windowIds.length,
      time: item.createdAt,
      disposition: item.status === 'closed' ? '已确认' : '待研判',
      urgency: severityLabel[item.severity],
      status: item.status === 'investigating' ? '处理中' : item.status === 'contained' ? '已解决' : '已关闭',
      owner: item.owner,
      domain: linked[0] ? inferDomain(linked[0]) : 'Threat',
      source: Array.from(new Set(linked.flatMap((window) => window.sourceTypes))).join(' / ') || 'Mixed',
      summary: item.summary,
      investigation: item,
    }
  })

  return [...findingRows, ...investigationRows]
}

function RiskScore({ value }: { value: number }) {
  const level = value > 75 ? 'critical' : value > 50 ? 'high' : value > 25 ? 'medium' : 'low'
  return <span className={`mc-risk-score ${level}`}>{value}</span>
}

function UrgencyTag({ value }: { value: QueueUrgency }) {
  return <Tag color={urgencyColor[value]}>{value}</Tag>
}

function PageTitle({ title, subtitle, extra }: { title: string; subtitle?: string; extra?: ReactNode }) {
  return (
    <div className="mc-page-title">
      <div>
        <Title level={2}>{title}</Title>
        {subtitle && <Text type="secondary">{subtitle}</Text>}
      </div>
      {extra}
    </div>
  )
}

export default function MissionControlApp() {
  const navigate = useNavigate()
  const location = useLocation()
  const [queueRows, setQueueRows] = useState<QueueRow[]>(queueFromData)
  const [sources, setSources] = useState<LogSource[]>(logSources)
  const [assistantContext, setAssistantContext] = useState<AssistantContext>({})
  const [timeRange, setTimeRange] = useState('24h')
  const [autoRefresh, setAutoRefresh] = useState(true)

  const selectedMenu = ['/mission-control', '/investigations', '/logs', '/assistant', '/sources', '/settings']
    .find((key) => location.pathname.startsWith(key)) || '/mission-control'

  const openAssistantForRow = (row: QueueRow) => {
    if (row.window) setAssistantContext({ windowIds: [row.window.id], entityIds: row.window.entities })
    else if (row.investigation) setAssistantContext({ caseId: row.investigation.id, windowIds: row.investigation.windowIds })
    navigate('/assistant')
  }

  const updateQueueRow = (key: string, patch: Partial<QueueRow>) => {
    setQueueRows((current) => current.map((row) => row.key === key ? { ...row, ...patch } : row))
  }

  const onlineSources = sources.filter((source) => source.status === 'online').length

  return (
    <Layout className="mc-shell">
      <Sider width={236} className="mc-sidebar" breakpoint="lg" collapsedWidth={72}>
        <div className="mc-brand">
          <div className="mc-brand-mark"><SafetyCertificateOutlined /></div>
          <div className="mc-brand-copy">
            <strong>链影寻踪</strong>
            <span>Security Operations</span>
          </div>
        </div>

        <Menu
          mode="inline"
          selectedKeys={[selectedMenu]}
          onClick={({ key }) => navigate(key)}
          className="mc-menu"
          items={[
            { key: '/mission-control', icon: <ThunderboltOutlined />, label: 'Mission Control' },
            { key: '/investigations', icon: <ApartmentOutlined />, label: '攻击调查' },
            { key: '/logs', icon: <FileSearchOutlined />, label: '日志检索' },
            { key: '/assistant', icon: <RobotOutlined />, label: 'AI 分析' },
            { key: '/sources', icon: <DatabaseOutlined />, label: '数据源管理' },
            { key: '/settings', icon: <SettingOutlined />, label: '设置' },
          ]}
        />

        <div className="mc-sidebar-health">
          <div><Badge status="processing" /> 检测服务运行中</div>
          <div><Badge status={onlineSources === sources.length ? 'success' : 'warning'} /> {onlineSources}/{sources.length} 日志源在线</div>
          <div><Badge status="success" /> 事件状态库正常</div>
        </div>
      </Sider>

      <Layout className="mc-workspace">
        <Header className="mc-topbar">
          <div className="mc-topbar-title">安全运营中心 / 链影寻踪</div>
          <Space size={10} wrap>
            <Select
              value={timeRange}
              onChange={setTimeRange}
              style={{ width: 126 }}
              options={[
                { value: '1h', label: '过去 1 小时' },
                { value: '24h', label: '过去 24 小时' },
                { value: '7d', label: '过去 7 天' },
                { value: '30d', label: '过去 30 天' },
              ]}
            />
            <Button icon={<ReloadOutlined />}>刷新</Button>
            <Space size={5}><Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} /><Text type="secondary">自动刷新</Text></Space>
          </Space>
        </Header>

        <Content className="mc-content">
          <Routes>
            <Route path="/mission-control" element={<MissionControlPage rows={queueRows} sources={sources} onUpdate={updateQueueRow} onOpenAssistant={openAssistantForRow} onOpenInvestigation={() => navigate('/investigations')} timeRange={timeRange} />} />
            <Route path="/investigations" element={<InvestigationsPage onOpenAssistant={(item) => { setAssistantContext({ caseId: item.id, windowIds: item.windowIds }); navigate('/assistant') }} />} />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/assistant" element={<AssistantPage context={assistantContext} />} />
            <Route path="/sources" element={<SourcesPage sources={sources} setSources={setSources} />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/overview" element={<Navigate to="/mission-control" replace />} />
            <Route path="/anomalies" element={<Navigate to="/mission-control" replace />} />
            <Route path="*" element={<Navigate to="/mission-control" replace />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  )
}

function MissionControlPage({ rows, sources, onUpdate, onOpenAssistant, onOpenInvestigation, timeRange }: {
  rows: QueueRow[]
  sources: LogSource[]
  onUpdate: (key: string, patch: Partial<QueueRow>) => void
  onOpenAssistant: (row: QueueRow) => void
  onOpenInvestigation: () => void
  timeRange: string
}) {
  const [selected, setSelected] = useState<QueueRow | null>(null)
  const [query, setQuery] = useState('')
  const [type, setType] = useState('all')
  const [urgency, setUrgency] = useState('all')
  const [status, setStatus] = useState('all')
  const [source, setSource] = useState('all')
  const [showCharts, setShowCharts] = useState(true)

  const filtered = rows.filter((row) => {
    const haystack = [row.key, row.name, row.entity, row.owner, row.domain, row.source].join(' ').toLowerCase()
    return haystack.includes(query.toLowerCase())
      && (type === 'all' || row.type === type)
      && (urgency === 'all' || row.urgency === urgency)
      && (status === 'all' || row.status === status)
      && (source === 'all' || row.source.includes(source))
  })

  const countBy = (field: keyof QueueRow) => {
    const result: Record<string, number> = {}
    rows.forEach((row) => {
      const key = String(row[field])
      result[key] = (result[key] || 0) + 1
    })
    return result
  }

  const donutOption = (title: string, data: Record<string, number>) => ({
    tooltip: { trigger: 'item' },
    title: { text: title, left: 14, top: 10, textStyle: { fontSize: 13, fontWeight: 600, color: '#334155' } },
    legend: { type: 'scroll', orient: 'vertical', right: 8, top: 38, bottom: 8, textStyle: { fontSize: 10, color: '#64748b' } },
    series: [{
      type: 'pie',
      radius: ['48%', '70%'],
      center: ['34%', '57%'],
      avoidLabelOverlap: true,
      label: { show: false },
      itemStyle: { borderColor: '#fff', borderWidth: 2 },
      data: Object.entries(data).map(([name, value]) => ({ name, value })),
    }],
  })

  const timelineOption = useMemo(() => ({
    tooltip: { trigger: 'axis' },
    grid: { left: 42, right: 18, top: 20, bottom: 30 },
    xAxis: { type: 'category', data: overviewSeries.map((item) => item.time), axisLine: { lineStyle: { color: '#cbd5e1' } }, axisLabel: { color: '#64748b' } },
    yAxis: { type: 'value', axisLabel: { color: '#64748b' }, splitLine: { lineStyle: { color: '#eef2f7' } } },
    dataZoom: [{ type: 'inside' }],
    series: [{ name: 'Findings', type: 'bar', barMaxWidth: 18, data: overviewSeries.map((item) => item.anomalies), itemStyle: { opacity: 0.78 } }],
  }), [])

  const columns = [
    { title: '类型', dataIndex: 'type', key: 'type', width: 118, render: (value: QueueType) => <Tag>{value}</Tag> },
    { title: '实体', dataIndex: 'entity', key: 'entity', width: 150, sorter: (a: QueueRow, b: QueueRow) => a.entity.localeCompare(b.entity) },
    { title: '名称', dataIndex: 'name', key: 'name', render: (value: string, row: QueueRow) => <div><Text strong>{value}</Text><div className="mc-row-id">{row.key}</div></div> },
    { title: '风险分', dataIndex: 'risk', key: 'risk', width: 96, sorter: (a: QueueRow, b: QueueRow) => a.risk - b.risk, render: (value: number) => <RiskScore value={value} /> },
    { title: 'Findings', dataIndex: 'findings', key: 'findings', width: 92, align: 'center' as const },
    { title: '时间', dataIndex: 'time', key: 'time', width: 128 },
    { title: '处置结论', dataIndex: 'disposition', key: 'disposition', width: 110 },
    { title: '紧急度', dataIndex: 'urgency', key: 'urgency', width: 90, render: (value: QueueUrgency) => <UrgencyTag value={value} /> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 92, render: (value: QueueStatus) => <span className="mc-status-text"><span className={`mc-status-dot ${value === '新建' ? 'new' : value === '处理中' ? 'active' : 'muted'}`} />{value}</span> },
    { title: '负责人', dataIndex: 'owner', key: 'owner', width: 110 },
  ]

  const selectedLive = selected ? rows.find((row) => row.key === selected.key) || selected : null

  return (
    <>
      <PageTitle
        title="Mission Control"
        subtitle="集中查看、分诊和调查 Findings 与 Investigations"
        extra={<Space><Button onClick={() => setShowCharts((value) => !value)}>{showCharts ? '隐藏图表' : '显示图表'}</Button><Button icon={<ApartmentOutlined />} onClick={onOpenInvestigation}>攻击调查</Button></Space>}
      />

      <Row gutter={[12, 12]} className="mc-summary-row">
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="队列总量" value={rows.length} /><Text type="secondary">{timeRange === '24h' ? '过去 24 小时' : '当前时间范围'}</Text></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="高风险" value={rows.filter((row) => row.risk >= 75).length} /><Text type="secondary">Risk ≥ 75</Text></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="处理中" value={rows.filter((row) => row.status === '处理中').length} /><Text type="secondary">已分配分析员</Text></Card></Col>
        <Col xs={12} md={6}><Card className="mc-summary-card"><Statistic title="在线数据源" value={sources.filter((item) => item.status === 'online').length} suffix={`/ ${sources.length}`} /><Text type="secondary">持续接入</Text></Card></Col>
      </Row>

      {showCharts && (
        <>
          <Row gutter={[12, 12]} className="mc-chart-row">
            <Col xs={24} md={12} xl={6}><Card className="mc-chart-card"><ReactECharts option={donutOption('Urgency', countBy('urgency'))} style={{ height: 190 }} /></Card></Col>
            <Col xs={24} md={12} xl={6}><Card className="mc-chart-card"><ReactECharts option={donutOption('Status', countBy('status'))} style={{ height: 190 }} /></Card></Col>
            <Col xs={24} md={12} xl={6}><Card className="mc-chart-card"><ReactECharts option={donutOption('Owner', countBy('owner'))} style={{ height: 190 }} /></Card></Col>
            <Col xs={24} md={12} xl={6}><Card className="mc-chart-card"><ReactECharts option={donutOption('Domain', countBy('domain'))} style={{ height: 190 }} /></Card></Col>
          </Row>
          <Card className="mc-timeline-card" title="Finding Timeline" extra={<Text type="secondary">拖动或滚轮缩放时间段</Text>}>
            <ReactECharts option={timelineOption} style={{ height: 180 }} />
          </Card>
        </>
      )}

      <Card className="mc-queue-card">
        <div className="mc-queue-head">
          <div>
            <Title level={4}>Analyst Queue</Title>
            <Text type="secondary">{filtered.length} 条结果 · 默认按最新事件优先</Text>
          </div>
          <Segmented value={type} onChange={(value) => setType(String(value))} options={[{ label: '全部', value: 'all' }, { label: 'Findings', value: 'Finding' }, { label: 'Investigations', value: 'Investigation' }]} />
        </div>

        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 ID / 实体 / 规则 / 负责人 / 域" className="mc-search" />
          <Select value={urgency} onChange={setUrgency} style={{ width: 126 }} options={[{ value: 'all', label: '全部紧急度' }, ...(['严重', '高危', '中危', '低危'] as QueueUrgency[]).map((value) => ({ value, label: value }))]} />
          <Select value={status} onChange={setStatus} style={{ width: 126 }} options={[{ value: 'all', label: '全部状态' }, ...(['新建', '处理中', '待处理', '已解决', '已关闭'] as QueueStatus[]).map((value) => ({ value, label: value }))]} />
          <Select value={source} onChange={setSource} style={{ width: 150 }} options={[{ value: 'all', label: '全部日志源' }, { value: 'Windows', label: 'Windows' }, { value: 'EDR', label: 'EDR' }, { value: 'Firewall', label: 'Firewall' }, { value: 'Network', label: 'Network Flow' }]} />
        </div>

        <Table
          rowKey="key"
          columns={columns}
          dataSource={filtered}
          size="middle"
          pagination={{ pageSize: 10, showSizeChanger: false }}
          scroll={{ x: 1180 }}
          onRow={(row) => ({ onClick: () => setSelected(row) })}
          rowClassName="mc-queue-row"
        />
      </Card>

      <Drawer open={Boolean(selectedLive)} onClose={() => setSelected(null)} width={620} title={selectedLive?.name} extra={selectedLive && <UrgencyTag value={selectedLive.urgency} />}>
        {selectedLive && (
          <div className="mc-detail-drawer">
            <div className="mc-detail-scoreline">
              <div><Text type="secondary">Risk score</Text><div><RiskScore value={selectedLive.risk} /></div></div>
              <div><Text type="secondary">类型</Text><div><Tag>{selectedLive.type}</Tag></div></div>
              <div><Text type="secondary">Domain</Text><div><strong>{selectedLive.domain}</strong></div></div>
            </div>

            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="ID">{selectedLive.key}</Descriptions.Item>
              <Descriptions.Item label="Entity">{selectedLive.entity}</Descriptions.Item>
              <Descriptions.Item label="Status"><Select size="small" value={selectedLive.status} onChange={(value) => onUpdate(selectedLive.key, { status: value })} style={{ width: 118 }} options={(['新建', '处理中', '待处理', '已解决', '已关闭'] as QueueStatus[]).map((value) => ({ value, label: value }))} /></Descriptions.Item>
              <Descriptions.Item label="Owner"><Select size="small" value={selectedLive.owner} onChange={(value) => onUpdate(selectedLive.key, { owner: value })} style={{ width: 126 }} options={['未分配', 'analyst-01', 'analyst-02', 'admin'].map((value) => ({ value, label: value }))} /></Descriptions.Item>
              <Descriptions.Item label="Disposition">{selectedLive.disposition}</Descriptions.Item>
              <Descriptions.Item label="Time">{selectedLive.time}</Descriptions.Item>
              <Descriptions.Item label="Source" span={2}>{selectedLive.source}</Descriptions.Item>
            </Descriptions>

            <Card size="small" title="研判摘要" className="mc-drawer-card"><Paragraph>{selectedLive.summary}</Paragraph></Card>

            {selectedLive.window && (
              <Card size="small" title={`关联事件 · ${selectedLive.window.eventCount}`} className="mc-drawer-card">
                <Timeline items={selectedLive.window.events.map((event) => ({ children: <div><strong>{event.time} · {event.action}</strong><div><Text type="secondary">{[event.actor, event.host, event.process, event.ip].filter(Boolean).join(' · ') || event.source}</Text></div></div> }))} />
              </Card>
            )}

            <Card size="small" title="处理缓存" className="mc-drawer-card">
              <Row gutter={[8, 8]}>
                <Col span={8}><div className="mc-cache-tile"><CheckCircleFilled /><strong>特征已缓存</strong><span>Embedding</span></div></Col>
                <Col span={8}><div className="mc-cache-tile"><CheckCircleFilled /><strong>事件已持久化</strong><span>Fingerprint</span></div></Col>
                <Col span={8}><div className="mc-cache-tile"><CheckCircleFilled /><strong>AI 结果缓存</strong><span>增量更新</span></div></Col>
              </Row>
            </Card>

            <Space wrap>
              <Button onClick={() => onUpdate(selectedLive.key, { owner: 'analyst-01', status: '处理中' })}>分配给我</Button>
              <Button icon={<RobotOutlined />} onClick={() => onOpenAssistant(selectedLive)}>AI 分析</Button>
              <Button type="primary" icon={<ApartmentOutlined />} onClick={onOpenInvestigation}>开始调查</Button>
            </Space>
          </div>
        )}
      </Drawer>
    </>
  )
}

function InvestigationsPage({ onOpenAssistant }: { onOpenAssistant: (item: Investigation) => void }) {
  const [selectedId, setSelectedId] = useState(investigations[0]?.id || '')
  const selected = investigations.find((item) => item.id === selectedId) || investigations[0]
  const linked = selected ? selected.windowIds.map((id) => anomalyWindows.find((window) => window.id === id)).filter(Boolean) as AnomalyWindow[] : []

  const graphOption = useMemo(() => {
    if (!selected) return {}
    const entitySet = Array.from(new Set(linked.flatMap((window) => window.entities))).slice(0, 8)
    const nodes = [
      ...linked.map((window, index) => ({ id: window.id, name: window.title, category: 0, symbolSize: 54, x: 120 + index * 190, y: 150 + (index % 2) * 60, label: { show: true, formatter: window.title, fontSize: 10 } })),
      ...entitySet.map((entity, index) => ({ id: `entity-${entity}`, name: entity, category: 1, symbolSize: 34, x: 110 + index * 100, y: 350 + (index % 2) * 55, label: { show: true, formatter: entity, fontSize: 10 } })),
    ]
    const links: { source: string; target: string }[] = []
    linked.forEach((window, index) => {
      if (index < linked.length - 1) links.push({ source: window.id, target: linked[index + 1].id })
      window.entities.filter((entity) => entitySet.includes(entity)).slice(0, 2).forEach((entity) => links.push({ source: window.id, target: `entity-${entity}` }))
    })
    return { tooltip: {}, legend: [{ data: ['Finding', 'Entity'] }], series: [{ type: 'graph', layout: 'none', roam: true, draggable: true, categories: [{ name: 'Finding' }, { name: 'Entity' }], data: nodes, links, edgeSymbol: ['none', 'arrow'], lineStyle: { width: 1.4, opacity: 0.7 }, emphasis: { focus: 'adjacency' } }] }
  }, [selectedId])

  if (!selected) return null

  return (
    <>
      <PageTitle title="攻击调查" subtitle="将多个 Findings 聚合为案件，按实体与时间关系完成调查" extra={<Button type="primary" icon={<RobotOutlined />} onClick={() => onOpenAssistant(selected)}>AI 调查摘要</Button>} />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={7}>
          <Card title="Investigations" className="mc-investigation-list">
            <List dataSource={investigations} renderItem={(item) => (
              <List.Item className={item.id === selected.id ? 'active' : ''} onClick={() => setSelectedId(item.id)}>
                <List.Item.Meta title={<Text strong>{item.title}</Text>} description={`${item.id} · ${item.windowIds.length} findings`} />
                <UrgencyTag value={severityLabel[item.severity]} />
              </List.Item>
            )} />
          </Card>
        </Col>
        <Col xs={24} xl={17}>
          <Card className="mc-case-card">
            <div className="mc-case-head"><div><Title level={3}>{selected.title}</Title><Text type="secondary">{selected.id} · Owner: {selected.owner}</Text></div><Tag color="processing">{selected.status === 'investigating' ? '处理中' : selected.status === 'contained' ? '已处置' : '已关闭'}</Tag></div>
            <Paragraph>{selected.summary}</Paragraph>
          </Card>
          <Card title="实体与 Finding 关系" className="mc-panel"><ReactECharts option={graphOption} style={{ height: 430 }} /></Card>
          <Row gutter={[12, 12]}>
            <Col xs={24} lg={14}><Card title="调查时间线" className="mc-panel"><Timeline items={linked.map((window) => ({ dot: <ClockCircleOutlined />, children: <div><strong>{window.start}</strong><div>{window.title}</div><Text type="secondary">{window.id}</Text></div> }))} /></Card></Col>
            <Col xs={24} lg={10}><Card title="响应工作流" className="mc-panel"><List size="small" dataSource={['确认受影响实体', '复核关键事件证据', '补充 7 天深度溯源', '生成处置建议与调查记录']} renderItem={(item, index) => <List.Item><Space><Badge status={index < 2 ? 'success' : 'default'} /><span>{item}</span></Space></List.Item>} /></Card></Col>
          </Row>
        </Col>
      </Row>
    </>
  )
}

function LogsPage() {
  const [query, setQuery] = useState('')
  const [source, setSource] = useState('all')
  const events = useMemo(() => anomalyWindows.flatMap((window) => window.events.map((event) => ({ ...event, windowId: window.id, risk: Math.round(window.score * 100) }))), [])
  const filtered = events.filter((event) => {
    const haystack = [event.id, event.action, event.actor, event.host, event.process, event.ip, event.source, event.raw].join(' ').toLowerCase()
    return haystack.includes(query.toLowerCase()) && (source === 'all' || event.source === source)
  })

  const columns = [
    { title: '时间', dataIndex: 'time', key: 'time', width: 105 },
    { title: '日志源', dataIndex: 'source', key: 'source', width: 145, render: (value: string) => <Tag>{value}</Tag> },
    { title: '行为', dataIndex: 'action', key: 'action', width: 165, render: (value: string) => <Text strong>{value}</Text> },
    { title: 'Actor', dataIndex: 'actor', key: 'actor', width: 120, render: (value?: string) => value || '—' },
    { title: 'Host', dataIndex: 'host', key: 'host', width: 120, render: (value?: string) => value || '—' },
    { title: 'Process / IP', key: 'target', width: 170, render: (_: unknown, row: SecurityEvent) => row.process || row.ip || '—' },
    { title: '原始内容', dataIndex: 'raw', key: 'raw', ellipsis: true },
  ]

  return (
    <>
      <PageTitle title="日志检索" subtitle="从已索引日志中检索原始证据，调查时回溯而不是重复执行模型" />
      <Card className="mc-queue-card">
        <div className="mc-filterbar">
          <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索用户 / Host / IP / Process / 原始日志" className="mc-search" />
          <Select value={source} onChange={setSource} style={{ width: 170 }} options={[{ value: 'all', label: '全部日志源' }, ...Array.from(new Set(events.map((event) => event.source))).map((value) => ({ value, label: value }))]} />
          <Button type="primary" icon={<SearchOutlined />}>检索</Button>
        </div>
        <Table rowKey="id" columns={columns} dataSource={filtered} pagination={{ pageSize: 12, showSizeChanger: false }} scroll={{ x: 1000 }} />
      </Card>
    </>
  )
}

function AssistantPage({ context }: { context: AssistantContext }) {
  const [question, setQuestion] = useState('')
  const [sending, setSending] = useState(false)
  const [chat, setChat] = useState<ChatItem[]>([{ role: 'assistant', content: '已接入当前 Analyst Queue / Investigation 上下文。你可以询问攻击链、实体历史、证据和处置建议。' }])

  const submit = async () => {
    const text = question.trim()
    if (!text || sending) return
    setChat((current) => [...current, { role: 'user', content: text }])
    setQuestion('')
    setSending(true)
    try {
      const answer = await askAssistant(text, context)
      setChat((current) => [...current, { role: 'assistant', content: answer.answer, evidence: answer.evidence }])
    } catch {
      setChat((current) => [...current, { role: 'assistant', content: 'AI 服务暂时不可用；已保留当前调查上下文。' }])
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <PageTitle title="AI 分析" subtitle="只对新增或发生变化的事件执行分析，已处理结果从本地状态库直接复用" />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={17}>
          <Card className="mc-chat-card">
            <div className="mc-chat-stream">
              {chat.map((item, index) => (
                <div className={`mc-chat-row ${item.role}`} key={`${item.role}-${index}`}>
                  <div className="mc-chat-avatar">{item.role === 'assistant' ? <RobotOutlined /> : <UserOutlined />}</div>
                  <div className="mc-chat-bubble"><Paragraph>{item.content}</Paragraph>{item.evidence && <Space size={[4, 4]} wrap>{item.evidence.map((evidence) => <Tag key={`${evidence.ref}-${evidence.label}`}>{evidence.label}</Tag>)}</Space>}</div>
                </div>
              ))}
              {sending && <div><Badge status="processing" /> 正在执行增量研判…</div>}
            </div>
            <div className="mc-chat-composer"><Input.TextArea value={question} onChange={(event) => setQuestion(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); submit() } }} autoSize={{ minRows: 2, maxRows: 5 }} placeholder="询问当前事件或案件…" /><Button type="primary" icon={<SendOutlined />} loading={sending} onClick={submit}>发送</Button></div>
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title="当前上下文" className="mc-panel">
            <Descriptions column={1} size="small">
              <Descriptions.Item label="Investigation">{context.caseId || '未选择'}</Descriptions.Item>
              <Descriptions.Item label="Findings">{context.windowIds?.join(', ') || '未选择'}</Descriptions.Item>
              <Descriptions.Item label="Entities">{context.entityIds?.join(', ') || '随事件自动带入'}</Descriptions.Item>
            </Descriptions>
            <Divider />
            <Alert type="success" showIcon message="结果缓存已启用" description="相同事件指纹与分析版本命中时，不重复调用大模型。" />
          </Card>
        </Col>
      </Row>
    </>
  )
}

function SourcesPage({ sources, setSources }: { sources: LogSource[]; setSources: Dispatch<SetStateAction<LogSource[]>> }) {
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm()

  const addSource = async () => {
    const values = await form.validateFields()
    setSources((current) => [...current, {
      id: `SRC-${String(current.length + 1).padStart(2, '0')}`,
      name: values.name,
      path: values.path,
      kind: values.kind,
      status: 'online',
      size: '0 B',
      lastRead: '刚刚',
    }])
    form.resetFields()
    setOpen(false)
    message.success('日志接入点已保存，并开始持续采集')
  }

  const columns = [
    { title: '日志源', dataIndex: 'name', key: 'name', render: (value: string) => <Space><FolderOpenOutlined /><Text strong>{value}</Text></Space> },
    { title: '接入点', dataIndex: 'path', key: 'path', render: (value: string) => <Text code>{value}</Text> },
    { title: '类型', dataIndex: 'kind', key: 'kind', render: (value: string) => <Tag>{value}</Tag> },
    { title: '采集状态', dataIndex: 'status', key: 'status', render: (value: LogSource['status']) => <Badge status={value === 'online' ? 'success' : value === 'warning' ? 'warning' : 'error'} text={value === 'online' ? '在线' : value === 'warning' ? '延迟' : '离线'} /> },
    { title: '历史回填', key: 'backfill', render: (_: unknown, _row: LogSource, index: number) => <Tag color={index % 2 === 0 ? 'success' : 'default'}>{index % 2 === 0 ? '已回填 7 天' : '仅实时'}</Tag> },
    { title: '最后读取', dataIndex: 'lastRead', key: 'lastRead' },
    { title: '数据量', dataIndex: 'size', key: 'size' },
  ]

  return (
    <>
      <PageTitle title="数据源管理" subtitle="日志接入点在这里低频配置；Mission Control 日常只筛选已接入的数据" extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>添加日志源</Button>} />
      <Alert className="mc-source-alert" type="info" showIcon message="首次接入可选择历史回填" description="接入时间只表示建立连接的时间。旧日志被回填并索引后，仍可参与历史关联、7 天深度溯源和 30 天行为基线。" />
      <Card className="mc-queue-card"><Table rowKey="id" columns={columns} dataSource={sources} pagination={false} scroll={{ x: 1000 }} /></Card>

      <Modal title="添加日志接入点" open={open} onCancel={() => setOpen(false)} onOk={addSource} okText="保存并接入" cancelText="取消" width={620}>
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input placeholder="核心域控 DC01" /></Form.Item>
          <Row gutter={12}>
            <Col span={12}><Form.Item name="kind" label="日志类型" initialValue="Windows EVTX"><Select options={[{ value: 'Windows EVTX', label: 'Windows EVTX' }, { value: 'Linux Audit', label: 'Linux Audit' }, { value: 'Syslog', label: 'Firewall / Syslog' }, { value: 'EDR API', label: 'EDR API' }, { value: 'JSONL', label: 'JSONL / File' }]} /></Form.Item></Col>
            <Col span={12}><Form.Item name="mode" label="接入方式" initialValue="Agent"><Select options={[{ value: 'Agent', label: 'Agent' }, { value: 'Syslog', label: 'Syslog' }, { value: 'API', label: 'API' }, { value: 'File', label: '文件目录' }]} /></Form.Item></Col>
          </Row>
          <Form.Item name="path" label="地址 / 路径" rules={[{ required: true }]}><Input placeholder="192.168.10.23:514 或 D:\\Logs\\DC01\\" /></Form.Item>
          <Row gutter={12}>
            <Col span={12}><Form.Item name="backfill" label="历史数据" initialValue="7d"><Select options={[{ value: 'none', label: '仅从现在开始' }, { value: '24h', label: '回填过去 24 小时' }, { value: '7d', label: '回填过去 7 天' }, { value: '30d', label: '回填过去 30 天' }]} /></Form.Item></Col>
            <Col span={12}><Form.Item label="连接测试"><Button block>测试连接</Button></Form.Item></Col>
          </Row>
        </Form>
      </Modal>
    </>
  )
}

function SettingsPage() {
  return (
    <>
      <PageTitle title="设置" subtitle="把回溯窗口、缓存和持久化策略明确成可配置的工程规则" />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={12}>
          <Card title="多尺度时间回溯" className="mc-settings-card">
            <div className="mc-setting-row"><div><strong>即时行为关联</strong><div><Text type="secondary">连续登录、进程、网络与文件行为</Text></div></div><Select defaultValue="1h" style={{ width: 140 }} options={[{ value: '30m', label: '30 分钟' }, { value: '1h', label: '1 小时' }, { value: '6h', label: '6 小时' }]} /></div>
            <div className="mc-setting-row"><div><strong>默认事件关联</strong><div><Text type="secondary">新日志到达后的主要上下文窗口</Text></div></div><Select defaultValue="24h" style={{ width: 140 }} options={[{ value: '12h', label: '12 小时' }, { value: '24h', label: '24 小时' }, { value: '48h', label: '48 小时' }]} /></div>
            <div className="mc-setting-row"><div><strong>深度攻击溯源</strong><div><Text type="secondary">高风险事件跨日追踪</Text></div></div><Select defaultValue="7d" style={{ width: 140 }} options={[{ value: '3d', label: '3 天' }, { value: '7d', label: '7 天' }, { value: '14d', label: '14 天' }]} /></div>
            <div className="mc-setting-row"><div><strong>历史行为基线</strong><div><Text type="secondary">读取画像与统计特征，不逐条重跑原始日志</Text></div></div><Select defaultValue="30d" style={{ width: 140 }} options={[{ value: '14d', label: '14 天' }, { value: '30d', label: '30 天' }, { value: '90d', label: '90 天' }]} /></div>
          </Card>
        </Col>

        <Col xs={24} xl={12}>
          <Card title="事件状态库与推理缓存" className="mc-settings-card">
            <div className="mc-setting-row"><div><strong>标准化日志持久化</strong><div><Text type="secondary">避免重复解析字段</Text></div></div><Switch defaultChecked /></div>
            <div className="mc-setting-row"><div><strong>Embedding / 异常分缓存</strong><div><Text type="secondary">相同日志不重复执行 DeBERTa</Text></div></div><Switch defaultChecked /></div>
            <div className="mc-setting-row"><div><strong>安全事件持久化</strong><div><Text type="secondary">event_id + fingerprint + analysis_version</Text></div></div><Switch defaultChecked /></div>
            <div className="mc-setting-row"><div><strong>LLM 分析结果缓存</strong><div><Text type="secondary">事件未变化时直接读取旧结论</Text></div></div><Switch defaultChecked /></div>
            <div className="mc-setting-row"><div><strong>新增日志触发增量分析</strong><div><Text type="secondary">ANALYZED → UPDATED → ANALYZED</Text></div></div><Switch defaultChecked /></div>
          </Card>
        </Col>

        <Col span={24}>
          <Card title="处理策略" className="mc-settings-card">
            <Alert type="success" showIcon message="默认策略：24 小时关联 / 7 天溯源 / 30 天基线" description="低风险事件优先使用短窗口；风险升高时扩展时间范围。30 天数据主要用于历史画像与罕见性判断，避免对全量历史日志重复推理。" />
            <Divider />
            <Row gutter={[12, 12]}>
              <Col xs={24} md={8}><Card size="small" title="NEW"><Text type="secondary">首次出现，执行完整模型与必要的 AI 研判。</Text></Card></Col>
              <Col xs={24} md={8}><Card size="small" title="ANALYZED"><Text type="secondary">指纹和分析版本未变化，直接读取本地结果。</Text></Card></Col>
              <Col xs={24} md={8}><Card size="small" title="UPDATED"><Text type="secondary">出现新的关联日志，仅对增量上下文重新计算。</Text></Card></Col>
            </Row>
          </Card>
        </Col>
      </Row>
    </>
  )
}
