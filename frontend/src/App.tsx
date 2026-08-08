import { useEffect, useMemo, useState } from 'react'
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
  Progress,
  Row,
  Segmented,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Timeline,
  Typography,
  message,
} from 'antd'
import {
  AlertOutlined,
  ApiOutlined,
  ApartmentOutlined,
  BookOutlined,
  DatabaseOutlined,
  FileSearchOutlined,
  PlusOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SettingOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import {
  anomalyTypeStats,
  anomalyWindows,
  assistantSuggestions,
  investigations,
  knowledgeDocs,
  logSources,
  overviewSeries,
  sourceHeatmap,
  type AnomalyWindow,
  type Investigation,
  type Severity,
} from './mocks/data'
import { askAssistant, frontendRuntime, type AssistantAnswer } from './services/api'

const { Header, Sider, Content } = Layout
const { Title, Text, Paragraph } = Typography

type ChatItem = { role: 'user' | 'assistant'; content: string; evidence?: AssistantAnswer['evidence'] }

const severityMeta: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'CRITICAL', color: 'red' },
  high: { label: 'HIGH', color: 'orange' },
  medium: { label: 'MEDIUM', color: 'gold' },
  low: { label: 'LOW', color: 'blue' },
}

function SeverityTag({ value }: { value: Severity }) {
  const meta = severityMeta[value]
  return <Tag color={meta.color}>{meta.label}</Tag>
}

const menuItems = [
  { key: '/overview', icon: <SafetyCertificateOutlined />, label: '态势总览' },
  { key: '/anomalies', icon: <AlertOutlined />, label: '异常事件' },
  { key: '/assistant', icon: <RobotOutlined />, label: '智能分析' },
  { key: '/investigations', icon: <ApartmentOutlined />, label: '攻击调查' },
  { key: '/settings', icon: <SettingOutlined />, label: '设置' },
]

function Shell() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <Layout className="app-shell">
      <Sider width={236} className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ThunderboltOutlined /></div>
          <div>
            <div className="brand-title">WAD</div>
            <div className="brand-subtitle">Semantic APT Hunter</div>
          </div>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          className="nav-menu"
        />
        <div className="sidebar-status">
          <Text className="muted-label">系统状态</Text>
          <div className="status-line"><Badge status="processing" /> Pipeline Running</div>
          <div className="status-line"><Badge status="success" /> 7 / 8 Sources Online</div>
          <div className="status-line"><Badge status={frontendRuntime.useMocks ? 'warning' : 'success'} /> {frontendRuntime.useMocks ? 'Demo / Mock Mode' : 'Live API Mode'}</div>
        </div>
      </Sider>
      <Layout>
        <Header className="topbar">
          <div>
            <Text className="topbar-kicker">跨域语义图 APT 攻击调查平台</Text>
          </div>
          <Space>
            <Tag color={frontendRuntime.useMocks ? 'gold' : 'green'}>{frontendRuntime.useMocks ? 'DEMO' : 'LIVE'}</Tag>
            <Text className="topbar-time">2026-08-09 · Security Console</Text>
          </Space>
        </Header>
        <Content className="content-wrap">
          <Routes>
            <Route path="/overview" element={<OverviewPage />} />
            <Route path="/anomalies" element={<AnomaliesPage />} />
            <Route path="/assistant" element={<AssistantPage />} />
            <Route path="/investigations" element={<InvestigationsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  )
}

function PageHeading({ title, description, extra }: { title: string; description: string; extra?: React.ReactNode }) {
  return (
    <div className="page-heading">
      <div>
        <Title level={2}>{title}</Title>
        <Text type="secondary">{description}</Text>
      </div>
      {extra}
    </div>
  )
}

function OverviewPage() {
  const navigate = useNavigate()
  const lineOption = useMemo(() => ({
    tooltip: { trigger: 'axis' },
    grid: { left: 48, right: 48, top: 42, bottom: 34 },
    legend: { data: ['日志量', '异常窗口'], textStyle: { color: '#91a0ad' } },
    xAxis: { type: 'category', data: overviewSeries.map((x) => x.time), axisLine: { lineStyle: { color: '#31404d' } }, axisLabel: { color: '#7f8c98' } },
    yAxis: [
      { type: 'value', axisLabel: { color: '#7f8c98', formatter: (v: number) => `${Math.round(v / 1000)}k` }, splitLine: { lineStyle: { color: '#18232d' } } },
      { type: 'value', axisLabel: { color: '#7f8c98' }, splitLine: { show: false } },
    ],
    series: [
      { name: '日志量', type: 'line', smooth: true, showSymbol: false, areaStyle: { opacity: 0.12 }, data: overviewSeries.map((x) => x.logs) },
      { name: '异常窗口', type: 'bar', yAxisIndex: 1, barMaxWidth: 14, data: overviewSeries.map((x) => x.anomalies) },
    ],
  }), [])

  const barOption = useMemo(() => ({
    tooltip: { trigger: 'axis' },
    grid: { left: 80, right: 24, top: 16, bottom: 20 },
    xAxis: { type: 'value', splitLine: { lineStyle: { color: '#18232d' } }, axisLabel: { color: '#7f8c98' } },
    yAxis: { type: 'category', inverse: true, data: anomalyTypeStats.map((x) => x.name), axisLabel: { color: '#9aa8b4' }, axisLine: { show: false }, axisTick: { show: false } },
    series: [{ type: 'bar', barWidth: 12, data: anomalyTypeStats.map((x) => x.value), label: { show: true, position: 'right', color: '#9aa8b4' } }],
  }), [])

  const heatmapOption = useMemo(() => ({
    tooltip: { position: 'top' },
    grid: { left: 96, right: 20, top: 20, bottom: 34 },
    xAxis: { type: 'category', data: sourceHeatmap.hours, splitArea: { show: true }, axisLabel: { color: '#7f8c98' } },
    yAxis: { type: 'category', data: sourceHeatmap.sources, splitArea: { show: true }, axisLabel: { color: '#9aa8b4' } },
    visualMap: { min: 0, max: 100, calculable: false, orient: 'horizontal', left: 'center', bottom: 0, show: false },
    series: [{ type: 'heatmap', data: sourceHeatmap.values, label: { show: false }, emphasis: { itemStyle: { shadowBlur: 8 } } }],
  }), [])

  return (
    <>
      <PageHeading title="态势总览" description="近期系统日志、异常窗口和日志源健康状态的统一视图。" />
      <Row gutter={[14, 14]} className="metric-row">
        <Col xs={24} sm={12} xl={5}><MetricCard title="今日日志" value={2417281} suffix="条" hint="↑ 12.4% vs 昨日" /></Col>
        <Col xs={24} sm={12} xl={5}><MetricCard title="异常窗口" value={327} hint="↑ 5.2%" /></Col>
        <Col xs={24} sm={12} xl={5}><MetricCard title="高风险窗口" value={21} hint="3 个新增" danger /></Col>
        <Col xs={24} sm={12} xl={5}><MetricCard title="调查中" value={4} hint="2 个待复核" /></Col>
        <Col xs={24} sm={12} xl={4}><MetricCard title="活跃日志源" value={7} suffix="/ 8" hint="1 个延迟" /></Col>
      </Row>

      <Row gutter={[14, 14]}>
        <Col xs={24} xl={15}>
          <Card title="24 小时日志活动与异常窗口" className="panel-card"><ReactECharts option={lineOption} style={{ height: 330 }} /></Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="异常类型排行" className="panel-card"><ReactECharts option={barOption} style={{ height: 330 }} /></Card>
        </Col>
        <Col xs={24} xl={15}>
          <Card title="日志源 × 时间异常密度" className="panel-card"><ReactECharts option={heatmapOption} style={{ height: 300 }} /></Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="最新异常事件" extra={<Button type="link" onClick={() => navigate('/anomalies')}>查看全部</Button>} className="panel-card">
            <List
              dataSource={anomalyWindows.slice(0, 4)}
              renderItem={(item) => (
                <List.Item className="compact-list-item" onClick={() => navigate('/anomalies')}>
                  <List.Item.Meta
                    avatar={<div className={`risk-dot ${item.severity}`} />}
                    title={<Space><Text strong>{item.title}</Text><SeverityTag value={item.severity} /></Space>}
                    description={`${item.id} · ${item.start} · ${item.eventCount} events`}
                  />
                  <Text strong>{Math.round(item.score * 100)}%</Text>
                </List.Item>
              )}
            />
          </Card>
        </Col>
      </Row>
    </>
  )
}

function MetricCard({ title, value, suffix, hint, danger }: { title: string; value: number; suffix?: string; hint: string; danger?: boolean }) {
  return (
    <Card className={`metric-card ${danger ? 'metric-danger' : ''}`}>
      <Statistic title={title} value={value} suffix={suffix} valueStyle={{ fontSize: 27 }} />
      <Text className="metric-hint">{hint}</Text>
    </Card>
  )
}

function AnomaliesPage() {
  const navigate = useNavigate()
  const [selected, setSelected] = useState<AnomalyWindow | null>(null)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<string>('all')
  const [view, setView] = useState<string | number>('卡片')

  const filtered = anomalyWindows.filter((item) => {
    const blob = [item.id, item.title, ...item.entities, ...item.hosts].join(' ').toLowerCase()
    return blob.includes(search.toLowerCase()) && (severity === 'all' || item.severity === severity)
  })

  const addToInvestigation = (item: AnomalyWindow) => {
    message.success(`${item.id} 已加入调查工作区（演示状态）`)
  }

  const columns = [
    { title: '窗口', dataIndex: 'id', key: 'id', render: (_: string, row: AnomalyWindow) => <div><Text strong>{row.title}</Text><div><Text type="secondary">{row.id}</Text></div></div> },
    { title: '风险', key: 'severity', render: (_: unknown, row: AnomalyWindow) => <SeverityTag value={row.severity} /> },
    { title: '评分', dataIndex: 'score', key: 'score', render: (v: number) => `${(v * 100).toFixed(1)}%` },
    { title: '时间', key: 'time', render: (_: unknown, row: AnomalyWindow) => `${row.start} — ${row.end}` },
    { title: '实体', key: 'entities', render: (_: unknown, row: AnomalyWindow) => row.entities.slice(0, 3).map((x) => <Tag key={x}>{x}</Tag>) },
    { title: '操作', key: 'actions', render: (_: unknown, row: AnomalyWindow) => <Space><Button size="small" onClick={() => setSelected(row)}>详情</Button><Button size="small" onClick={() => addToInvestigation(row)}>加入调查</Button></Space> },
  ]

  return (
    <>
      <PageHeading
        title="异常事件"
        description="模型自动产生的异常 Window 在这里统一整理；调查 Case 由用户主动创建。"
        extra={<Button type="primary" icon={<ApartmentOutlined />} onClick={() => navigate('/investigations')}>打开调查工作区</Button>}
      />
      <Card className="toolbar-card">
        <Space wrap>
          <Input prefix={<SearchOutlined />} placeholder="搜索用户 / IP / Host / Process / Window ID" value={search} onChange={(e) => setSearch(e.target.value)} style={{ width: 360 }} />
          <Select value={severity} onChange={setSeverity} style={{ width: 140 }} options={[{ value: 'all', label: '全部风险' }, { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }]} />
          <Segmented value={view} onChange={setView} options={['卡片', '表格']} />
        </Space>
      </Card>

      {view === '卡片' ? (
        <Row gutter={[14, 14]}>
          {filtered.map((item) => (
            <Col xs={24} lg={12} xxl={8} key={item.id}>
              <Card className={`window-card severity-${item.severity}`} hoverable onClick={() => setSelected(item)}>
                <div className="window-card-head"><SeverityTag value={item.severity} /><Text type="secondary">{item.id}</Text></div>
                <Title level={4}>{item.title}</Title>
                <Paragraph type="secondary" ellipsis={{ rows: 2 }}>{item.summary}</Paragraph>
                <div className="window-stat-grid">
                  <div><Text type="secondary">时间窗口</Text><strong>{item.start} — {item.end}</strong></div>
                  <div><Text type="secondary">事件</Text><strong>{item.eventCount}</strong></div>
                  <div><Text type="secondary">主机</Text><strong>{item.hosts.length}</strong></div>
                  <div><Text type="secondary">异常评分</Text><strong>{(item.score * 100).toFixed(1)}%</strong></div>
                </div>
                <Space size={[4, 6]} wrap>{item.entities.map((x) => <Tag key={x}>{x}</Tag>)}</Space>
                <Divider />
                <div className="window-actions" onClick={(e) => e.stopPropagation()}>
                  <Button onClick={() => setSelected(item)}>查看详情</Button>
                  <Button onClick={() => navigate('/assistant', { state: { question: `分析 ${item.id} 的异常原因`, windowIds: [item.id] } })}>询问 AI</Button>
                  <Button type="primary" onClick={() => addToInvestigation(item)}>加入调查</Button>
                </div>
              </Card>
            </Col>
          ))}
        </Row>
      ) : (
        <Card className="panel-card"><Table rowKey="id" dataSource={filtered} columns={columns} pagination={{ pageSize: 8 }} /></Card>
      )}

      <Drawer title={selected ? `${selected.id} · ${selected.title}` : '异常事件'} width={660} open={!!selected} onClose={() => setSelected(null)}>
        {selected && <WindowDetail item={selected} onAsk={() => navigate('/assistant', { state: { question: `解释 ${selected.id} 的关键异常证据`, windowIds: [selected.id] } })} onInvestigate={() => addToInvestigation(selected)} />}
      </Drawer>
    </>
  )
}

function WindowDetail({ item, onAsk, onInvestigate }: { item: AnomalyWindow; onAsk: () => void; onInvestigate: () => void }) {
  return (
    <>
      <div className="drawer-risk"><SeverityTag value={item.severity} /><Progress percent={Math.round(item.score * 100)} size="small" status={item.severity === 'critical' ? 'exception' : 'active'} /></div>
      <Descriptions column={2} size="small" bordered items={[
        { key: '1', label: '状态', children: item.status },
        { key: '2', label: '事件数', children: item.eventCount },
        { key: '3', label: '开始', children: item.start },
        { key: '4', label: '结束', children: item.end },
        { key: '5', label: '数据源', span: 2, children: item.sourceTypes.join(' / ') },
      ]} />
      <Title level={5} className="section-title">事件时间线</Title>
      <Timeline items={item.events.map((event) => ({
        children: <div><Text strong>{event.time} · {event.action}</Text><div className="timeline-meta">{[event.actor, event.host, event.process, event.ip].filter(Boolean).join(' · ')}</div><code className="raw-log">{event.raw}</code></div>,
      }))} />
      <Title level={5} className="section-title">关键实体</Title>
      <Space wrap>{item.entities.map((x) => <Tag key={x}>{x}</Tag>)}</Space>
      <Divider />
      <Space><Button icon={<RobotOutlined />} onClick={onAsk}>询问 AI</Button><Button type="primary" icon={<ApartmentOutlined />} onClick={onInvestigate}>加入攻击调查</Button></Space>
    </>
  )
}

function AssistantPage() {
  const location = useLocation()
  const initialState = location.state as { question?: string; windowIds?: string[]; caseId?: string } | null
  const [messages, setMessages] = useState<ChatItem[]>([
    { role: 'assistant', content: '我是 WAD 智能分析助手。正式接入时，我会通过后端调用 GPT，并按需查询异常窗口、实体历史、攻击调查与本地知识库。' },
  ])
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [contextWindows, setContextWindows] = useState<string[]>(initialState?.windowIds || ['WIN-20260809-0321'])
  const [contextCase, setContextCase] = useState<string | undefined>(initialState?.caseId)

  const submit = async (text?: string) => {
    const q = (text || question).trim()
    if (!q || loading) return
    setQuestion('')
    setMessages((prev) => [...prev, { role: 'user', content: q }])
    setLoading(true)
    try {
      const answer = await askAssistant(q, { windowIds: contextWindows, caseId: contextCase })
      setMessages((prev) => [...prev, { role: 'assistant', content: answer.answer, evidence: answer.evidence }])
    } catch (error) {
      setMessages((prev) => [...prev, { role: 'assistant', content: `请求失败：${error instanceof Error ? error.message : 'unknown error'}` }])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (initialState?.question) void submit(initialState.question)
    // Only consume route state on first mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <>
      <PageHeading title="智能分析" description="让 GPT 查询系统事实与知识库后再回答，而不是把全部原始日志直接交给模型。" />
      <Row gutter={14} className="assistant-layout">
        <Col xs={24} xl={17}>
          <Card className="chat-card">
            <div className="chat-stream">
              {messages.map((item, index) => (
                <div key={index} className={`chat-row ${item.role}`}>
                  <div className="chat-avatar">{item.role === 'assistant' ? <RobotOutlined /> : 'U'}</div>
                  <div className="chat-bubble">
                    <Paragraph>{item.content}</Paragraph>
                    {item.evidence && <Space wrap>{item.evidence.map((e) => <Tag key={`${e.ref}-${e.label}`} icon={<FileSearchOutlined />}>{e.label} · {e.ref}</Tag>)}</Space>}
                  </div>
                </div>
              ))}
              {loading && <div className="chat-row assistant"><div className="chat-avatar"><RobotOutlined /></div><div className="chat-bubble"><Text type="secondary">正在查询上下文并组织回答…</Text></div></div>}
            </div>
            <div className="suggestion-row">{assistantSuggestions.map((x) => <Button size="small" key={x} onClick={() => void submit(x)}>{x}</Button>)}</div>
            <Space.Compact block>
              <Input.TextArea autoSize={{ minRows: 2, maxRows: 5 }} value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="例如：为什么 Alice 被认为是高风险实体？" onPressEnter={(e) => { if (!e.shiftKey) { e.preventDefault(); void submit() } }} />
              <Button type="primary" loading={loading} onClick={() => void submit()}>发送</Button>
            </Space.Compact>
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title="当前分析上下文" className="panel-card context-card">
            <Text className="muted-label">异常窗口</Text>
            <Select mode="multiple" value={contextWindows} onChange={setContextWindows} style={{ width: '100%', marginTop: 8 }} options={anomalyWindows.map((x) => ({ value: x.id, label: x.id }))} />
            <Divider />
            <Text className="muted-label">调查 Case</Text>
            <Select allowClear value={contextCase} onChange={setContextCase} placeholder="未绑定调查" style={{ width: '100%', marginTop: 8 }} options={investigations.map((x) => ({ value: x.id, label: `${x.id} · ${x.title}` }))} />
            <Divider />
            <Text className="muted-label">可检索知识</Text>
            <List size="small" dataSource={knowledgeDocs.slice(0, 4)} renderItem={(doc) => <List.Item><Space><BookOutlined /><Text>{doc.name}</Text></Space><Tag>{doc.category}</Tag></List.Item>} />
            <Alert type="info" showIcon message="API Key 不应保存在浏览器" description="真实 GPT 调用应由后端完成；前端只调用 /api/assistant/query。" />
          </Card>
        </Col>
      </Row>
    </>
  )
}

function InvestigationsPage() {
  const navigate = useNavigate()
  const [selectedId, setSelectedId] = useState(investigations[0].id)
  const current = investigations.find((x) => x.id === selectedId) || investigations[0]
  const windows = current.windowIds.map((id) => anomalyWindows.find((x) => x.id === id)).filter(Boolean) as AnomalyWindow[]

  const graphOption = useMemo(() => buildInvestigationGraph(current), [current])

  return (
    <>
      <PageHeading title="攻击调查" description="将多个异常 Window 组合成 Case，围绕实体、时间与证据关系进行人工调查。" extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => message.info('V1 演示：创建 Case 表单将在后端接入后持久化')}>新建调查</Button>} />
      <Row gutter={14}>
        <Col xs={24} xl={6}>
          <Card title="调查案件" className="panel-card investigation-list">
            {investigations.map((item) => (
              <div key={item.id} className={`case-card ${item.id === current.id ? 'active' : ''}`} onClick={() => setSelectedId(item.id)}>
                <div className="case-card-head"><Text strong>{item.id}</Text><SeverityTag value={item.severity} /></div>
                <Text strong>{item.title}</Text>
                <div className="case-meta">{item.windowIds.length} windows · {item.owner}</div>
              </div>
            ))}
          </Card>
        </Col>
        <Col xs={24} xl={18}>
          <Card className="panel-card case-header-card">
            <div className="case-title-line"><div><Space><Title level={3}>{current.id} · {current.title}</Title><SeverityTag value={current.severity} /></Space><Paragraph type="secondary">{current.summary}</Paragraph></div><Space><Button onClick={() => navigate('/assistant', { state: { question: `总结 ${current.id} 的关键攻击证据`, caseId: current.id, windowIds: current.windowIds } })} icon={<RobotOutlined />}>询问 AI</Button><Button>编辑案件</Button></Space></div>
            <Space wrap>{windows.map((w) => <Tag key={w.id} color="geekblue">{w.id}</Tag>)}</Space>
          </Card>
          <Card title="攻击关系图" extra={<Tag>实体 + 长时窗口关联</Tag>} className="panel-card graph-card">
            <ReactECharts option={graphOption} style={{ height: 410 }} />
          </Card>
          <Row gutter={14}>
            <Col xs={24} lg={14}>
              <Card title="调查时间线" className="panel-card">
                <Timeline items={windows.map((w) => ({ color: w.severity === 'critical' ? 'red' : w.severity === 'high' ? 'orange' : 'blue', children: <div><Space><Text strong>{w.start}</Text><SeverityTag value={w.severity} /></Space><div><Text>{w.title}</Text></div><Text type="secondary">{w.id} · {w.entities.join(' · ')}</Text></div> }))} />
              </Card>
            </Col>
            <Col xs={24} lg={10}>
              <Card title="关键关联证据" className="panel-card">
                <EvidenceRow label="Alice" kind="USER MATCH" strength="强证据" score={0.96} />
                <EvidenceRow label="powershell.exe" kind="PROCESS MATCH" strength="强证据" score={0.91} />
                <EvidenceRow label="HOST-07 → HOST-12" kind="HOST CONTINUITY" strength="中证据" score={0.78} />
                <EvidenceRow label="6h 14m" kind="TIME LINK" strength="时间衰减后保留" score={0.72} />
                <Alert className="evidence-alert" type="info" showIcon message="IP 相同不会单独建立攻击链" description="符合现有 M5 设计：user/process 为强锚点，host 为中等锚点，IP-only 关系不作为充分证据。" />
              </Card>
            </Col>
          </Row>
        </Col>
      </Row>
    </>
  )
}

function EvidenceRow({ label, kind, strength, score }: { label: string; kind: string; strength: string; score: number }) {
  return (
    <div className="evidence-row">
      <div><Text strong>{label}</Text><div><Text type="secondary">{kind} · {strength}</Text></div></div>
      <Progress type="circle" percent={Math.round(score * 100)} size={42} />
    </div>
  )
}

function buildInvestigationGraph(current: Investigation) {
  if (current.id !== 'CASE-001') {
    return {
      tooltip: {},
      series: [{ type: 'graph', layout: 'force', roam: true, label: { show: true, color: '#cbd5df' }, force: { repulsion: 280 }, data: [
        { name: 'svc_backup', category: 0, symbolSize: 58 }, { name: 'HOST-03', category: 1, symbolSize: 52 }, { name: '172.16.2.44', category: 2, symbolSize: 48 },
      ], links: [{ source: 'svc_backup', target: 'HOST-03', value: 'auth failures' }, { source: '172.16.2.44', target: 'HOST-03', value: 'source ip' }], lineStyle: { opacity: 0.75, width: 2 }, edgeLabel: { show: true, formatter: '{c}', color: '#7f8c98' } }],
    }
  }
  return {
    tooltip: { formatter: (params: { data?: { detail?: string; name?: string } }) => params.data?.detail || params.data?.name || '' },
    legend: [{ data: ['User', 'Host', 'Process', 'IP/File'], textStyle: { color: '#91a0ad' } }],
    series: [{
      type: 'graph', layout: 'force', roam: true, draggable: true,
      categories: [{ name: 'User' }, { name: 'Host' }, { name: 'Process' }, { name: 'IP/File' }],
      label: { show: true, color: '#dce4eb' },
      force: { repulsion: 520, edgeLength: [90, 170], gravity: 0.08 },
      data: [
        { name: 'Alice', category: 0, symbolSize: 68, detail: 'USER · strong anchor' },
        { name: 'HOST-07', category: 1, symbolSize: 60, detail: '03:21 · first host' },
        { name: 'powershell.exe', category: 2, symbolSize: 66, detail: '03:22 · process start' },
        { name: '10.2.3.7', category: 3, symbolSize: 48, detail: '03:23 · network destination' },
        { name: 'HOST-12', category: 1, symbolSize: 60, detail: '09:35 · second host' },
        { name: 'cmd.exe', category: 2, symbolSize: 54, detail: '09:37 · process start' },
        { name: 'HOST-18', category: 1, symbolSize: 60, detail: '14:22 · third host' },
        { name: 'sensitive.dat', category: 3, symbolSize: 54, detail: '14:22 · sensitive file' },
      ],
      links: [
        { source: 'Alice', target: 'HOST-07', value: 'login' },
        { source: 'HOST-07', target: 'powershell.exe', value: 'process' },
        { source: 'powershell.exe', target: '10.2.3.7', value: 'connect' },
        { source: 'Alice', target: 'HOST-12', value: '6h · user match' },
        { source: 'HOST-12', target: 'cmd.exe', value: 'process' },
        { source: 'Alice', target: 'HOST-18', value: 'long-horizon' },
        { source: 'HOST-18', target: 'sensitive.dat', value: 'file read' },
      ],
      lineStyle: { opacity: 0.78, width: 2, curveness: 0.08 },
      edgeLabel: { show: true, formatter: '{c}', color: '#83919d', fontSize: 10 },
      emphasis: { focus: 'adjacency', lineStyle: { width: 4 } },
    }],
  }
}

function SettingsPage() {
  const [sourceModal, setSourceModal] = useState(false)
  const [form] = Form.useForm()

  const sourceColumns = [
    { title: '日志源', key: 'name', render: (_: unknown, row: (typeof logSources)[number]) => <div><Text strong>{row.name}</Text><div><Text type="secondary">{row.path}</Text></div></div> },
    { title: '类型', dataIndex: 'kind', key: 'kind', render: (v: string) => <Tag>{v}</Tag> },
    { title: '状态', key: 'status', render: (_: unknown, row: (typeof logSources)[number]) => <Badge status={row.status === 'online' ? 'success' : row.status === 'warning' ? 'warning' : 'error'} text={row.status} /> },
    { title: '大小', dataIndex: 'size', key: 'size' },
    { title: '最后读取', dataIndex: 'lastRead', key: 'lastRead' },
    { title: '操作', key: 'action', render: () => <Button size="small">配置</Button> },
  ]

  const kbColumns = [
    { title: '文档', key: 'name', render: (_: unknown, row: (typeof knowledgeDocs)[number]) => <Space><BookOutlined /><div><Text strong>{row.name}</Text><div><Text type="secondary">{row.kind}</Text></div></div></Space> },
    { title: '分类', dataIndex: 'category', key: 'category', render: (v: string) => <Tag>{v}</Tag> },
    { title: '索引状态', key: 'status', render: (_: unknown, row: (typeof knowledgeDocs)[number]) => <Badge status={row.status === 'indexed' ? 'success' : row.status === 'indexing' ? 'processing' : 'error'} text={row.status} /> },
    { title: '知识块', dataIndex: 'chunks', key: 'chunks' },
    { title: '更新时间', dataIndex: 'updatedAt', key: 'updatedAt' },
    { title: '操作', key: 'action', render: () => <Space><Button size="small">重新索引</Button><Button size="small" danger>删除</Button></Space> },
  ]

  const items = [
    {
      key: 'sources', label: '日志源', children: <Card className="panel-card" title="日志位置" extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => setSourceModal(true)}>添加日志源</Button>}><Paragraph type="secondary">日志源是可独立管理的多路径配置。前端只保存配置意图，实际扫描/监听由后端执行。</Paragraph><Table rowKey="id" dataSource={logSources} columns={sourceColumns} pagination={false} /></Card>,
    },
    {
      key: 'knowledge', label: '知识库', children: <Card className="panel-card" title="GPT 检索知识库" extra={<Space><Button icon={<PlusOutlined />}>添加文件</Button><Button>添加文本</Button></Space>}><Paragraph type="secondary">用于组织环境、攻击知识、历史调查和运维文档检索。原始海量日志不直接塞入向量知识库。</Paragraph><Table rowKey="id" dataSource={knowledgeDocs} columns={kbColumns} pagination={false} /></Card>,
    },
    {
      key: 'ai', label: 'AI 配置', children: <Row gutter={14}><Col xs={24} xl={14}><Card title="GPT 后端连接" className="panel-card"><Form layout="vertical" initialValues={{ endpoint: '/api/assistant/query', model: '由后端配置', retrieval: true }}><Form.Item label="后端接口" name="endpoint"><Input prefix={<ApiOutlined />} /></Form.Item><Form.Item label="模型" name="model"><Input disabled /></Form.Item><Form.Item label="启用知识库检索" name="retrieval" valuePropName="checked"><Switch /></Form.Item><Button type="primary">保存配置</Button></Form></Card></Col><Col xs={24} xl={10}><Alert type="warning" showIcon message="不要在前端保存 OpenAI API Key" description="API Key 应保存在服务端环境变量或密钥管理服务中。浏览器只访问你自己的后端接口。" /></Col></Row>,
    },
    {
      key: 'storage', label: '存储', children: <Row gutter={14}><Col xs={24} lg={12}><Card title="业务数据库" className="panel-card"><Space direction="vertical"><Text><DatabaseOutlined /> Windows / Events / Entities / Cases</Text><Text type="secondary">推荐 PostgreSQL；演示阶段也可使用 SQLite。</Text><Badge status="success" text="Schema adapter ready" /></Space></Card></Col><Col xs={24} lg={12}><Card title="知识索引" className="panel-card"><Space direction="vertical"><Text><BookOutlined /> Documents / Chunks / Embeddings / Metadata</Text><Text type="secondary">与业务事实库分离，避免把全部日志作为向量文档。</Text><Badge status="processing" text="5 documents" /></Space></Card></Col></Row>,
    },
    {
      key: 'system', label: '系统', children: <Card className="panel-card"><Descriptions bordered column={1} items={[{ key: '1', label: '前端模式', children: frontendRuntime.useMocks ? 'Demo / Mock' : 'Live API' }, { key: '2', label: 'API Base', children: frontendRuntime.apiBase }, { key: '3', label: '设计原则', children: 'frontend/ 独立目录，不读取或修改 src/、scripts/、训练产物' }]} /></Card>,
    },
  ]

  return (
    <>
      <PageHeading title="设置" description="统一管理多日志源、知识库、GPT 后端和数据存储策略。" />
      <Tabs items={items} defaultActiveKey="sources" />
      <Modal title="添加日志源" open={sourceModal} onCancel={() => setSourceModal(false)} onOk={() => { form.validateFields().then(() => { message.success('日志源配置已通过前端校验（演示）'); setSourceModal(false) }).catch(() => undefined) }}>
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input placeholder="Windows Domain Controller" /></Form.Item>
          <Form.Item name="path" label="路径" rules={[{ required: true }]}><Input placeholder="D:\\Logs\\DC01\\" /></Form.Item>
          <Form.Item name="kind" label="类型" rules={[{ required: true }]}><Select options={['EVTX', 'LOG', 'CSV', 'JSONL'].map((x) => ({ value: x, label: x }))} /></Form.Item>
          <Form.Item name="recursive" label="递归扫描" valuePropName="checked" initialValue><Switch /></Form.Item>
          <Form.Item name="watch" label="监控新增文件" valuePropName="checked" initialValue><Switch /></Form.Item>
        </Form>
      </Modal>
    </>
  )
}

export default function App() {
  return <Shell />
}
