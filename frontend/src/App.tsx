import { useMemo, useState, type ReactNode } from 'react'
import {
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
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
  ApartmentOutlined,
  BookOutlined,
  CheckCircleFilled,
  ClockCircleOutlined,
  DatabaseOutlined,
  FileTextOutlined,
  FolderOpenOutlined,
  PlusOutlined,
  RobotOutlined,
  SearchOutlined,
  SendOutlined,
  SettingOutlined,
  ThunderboltOutlined,
  UserOutlined,
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
  type KnowledgeDoc,
  type LogSource,
  type Severity,
} from './mocks/data'
import { askAssistant, type AssistantAnswer, type AssistantContext } from './services/api'

const { Header, Sider, Content } = Layout
const { Title, Text, Paragraph } = Typography

type ChatItem = {
  role: 'user' | 'assistant'
  content: string
  evidence?: AssistantAnswer['evidence']
}

type InvestigationStatus = Investigation['status']

const severityMeta: Record<Severity, { label: string; color: string }> = {
  critical: { label: '严重', color: 'red' },
  high: { label: '高危', color: 'orange' },
  medium: { label: '中危', color: 'gold' },
  low: { label: '低危', color: 'blue' },
  info: { label: '正常', color: 'default' },
}

const caseStatusLabel: Record<InvestigationStatus, string> = {
  investigating: '调查中',
  contained: '已处置',
  closed: '已关闭',
}

function SeverityTag({ value }: { value: Severity }) {
  const meta = severityMeta[value]
  return <Tag color={meta.color}>{meta.label}</Tag>
}

function PageHeading({ title, extra }: { title: string; extra?: ReactNode }) {
  return (
    <div className="page-heading">
      <Title level={2}>{title}</Title>
      {extra}
    </div>
  )
}

function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const [windowItems, setWindowItems] = useState(anomalyWindows)
  const [caseItems, setCaseItems] = useState(investigations)
  const [sources, setSources] = useState(logSources)
  const [docs, setDocs] = useState(knowledgeDocs)
  const [assistantContext, setAssistantContext] = useState<AssistantContext>({})

  const onlineCount = sources.filter((item) => item.status === 'online').length
  const selectedMenu = ['/overview', '/anomalies', '/assistant', '/investigations', '/settings'].find((key) => location.pathname.startsWith(key)) || '/overview'

  const sendWindowToAssistant = (item: AnomalyWindow) => {
    setAssistantContext({ windowIds: [item.id], entityIds: item.entities })
    navigate('/assistant')
  }

  const sendCaseToAssistant = (item: Investigation) => {
    setAssistantContext({ caseId: item.id, windowIds: item.windowIds })
    navigate('/assistant')
  }

  const addWindowToCase = (windowId: string, caseId: string) => {
    setCaseItems((current) => current.map((item) => (
      item.id === caseId && !item.windowIds.includes(windowId)
        ? { ...item, windowIds: [...item.windowIds, windowId] }
        : item
    )))
    setWindowItems((current) => current.map((item) => (
      item.id === windowId ? { ...item, status: 'investigating' } : item
    )))
    message.success('已加入攻击调查')
  }

  return (
    <Layout className="app-shell">
      <Sider width={228} className="sidebar" breakpoint="lg" collapsedWidth={72}>
        <div className="brand">
          <div className="brand-mark"><ThunderboltOutlined /></div>
          <div className="brand-copy">
            <div className="brand-title">WAD</div>
            <div className="brand-subtitle">APT Security Console</div>
          </div>
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedMenu]}
          onClick={({ key }) => navigate(key)}
          className="nav-menu"
          items={[
            { key: '/overview', icon: <ThunderboltOutlined />, label: '态势总览' },
            { key: '/anomalies', icon: <AlertOutlined />, label: '异常事件' },
            { key: '/assistant', icon: <RobotOutlined />, label: '智能分析' },
            { key: '/investigations', icon: <ApartmentOutlined />, label: '攻击调查' },
            { key: '/settings', icon: <SettingOutlined />, label: '设置' },
          ]}
        />

        <div className="sidebar-status">
          <div className="status-line"><Badge status="processing" /> 检测服务运行中</div>
          <div className="status-line"><Badge status={onlineCount === sources.length ? 'success' : 'warning'} /> {onlineCount}/{sources.length} 日志源在线</div>
        </div>
      </Sider>

      <Layout className="workspace">
        <Header className="topbar">
          <div className="topbar-title">跨域语义图 APT 攻击调查平台</div>
          <div className="topbar-state"><span className="status-dot" /> 系统正常</div>
        </Header>

        <Content className="content-wrap">
          <Routes>
            <Route path="/overview" element={<OverviewPage windows={windowItems} sources={sources} onOpenAnomalies={() => navigate('/anomalies')} />} />
            <Route path="/anomalies" element={<AnomaliesPage windows={windowItems} cases={caseItems} onAddToCase={addWindowToCase} onAsk={sendWindowToAssistant} onOpenInvestigations={() => navigate('/investigations')} />} />
            <Route path="/assistant" element={<AssistantPage context={assistantContext} windows={windowItems} cases={caseItems} />} />
            <Route path="/investigations" element={<InvestigationsPage cases={caseItems} windows={windowItems} onAsk={sendCaseToAssistant} />} />
            <Route path="/settings" element={<SettingsPage sources={sources} setSources={setSources} docs={docs} setDocs={setDocs} />} />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  )
}

function OverviewPage({ windows, sources, onOpenAnomalies }: { windows: AnomalyWindow[]; sources: LogSource[]; onOpenAnomalies: () => void }) {
  const highRisk = windows.filter((item) => item.severity === 'critical' || item.severity === 'high').length
  const onlineSources = sources.filter((item) => item.status === 'online').length

  const activityOption = useMemo(() => ({
    tooltip: { trigger: 'axis' },
    grid: { left: 50, right: 48, top: 42, bottom: 34 },
    legend: { data: ['日志量', '异常窗口'], textStyle: { color: '#91a0ad' } },
    xAxis: { type: 'category', data: overviewSeries.map((item) => item.time), axisLine: { lineStyle: { color: '#304153' } }, axisLabel: { color: '#7f8c98' } },
    yAxis: [
      { type: 'value', axisLabel: { color: '#7f8c98', formatter: (value: number) => `${Math.round(value / 1000)}k` }, splitLine: { lineStyle: { color: '#182738' } } },
      { type: 'value', axisLabel: { color: '#7f8c98' }, splitLine: { show: false } },
    ],
    series: [
      { name: '日志量', type: 'line', smooth: true, showSymbol: false, areaStyle: { opacity: 0.1 }, lineStyle: { width: 2 }, data: overviewSeries.map((item) => item.logs) },
      { name: '异常窗口', type: 'bar', yAxisIndex: 1, barMaxWidth: 13, data: overviewSeries.map((item) => item.anomalies) },
    ],
  }), [])

  const anomalyOption = useMemo(() => ({
    tooltip: { trigger: 'axis' },
    grid: { left: 82, right: 30, top: 16, bottom: 20 },
    xAxis: { type: 'value', splitLine: { lineStyle: { color: '#182738' } }, axisLabel: { color: '#7f8c98' } },
    yAxis: { type: 'category', inverse: true, data: anomalyTypeStats.map((item) => item.name), axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: '#a7b3bf' } },
    series: [{ type: 'bar', barWidth: 12, data: anomalyTypeStats.map((item) => item.value), label: { show: true, position: 'right', color: '#a7b3bf' } }],
  }), [])

  const heatmapOption = useMemo(() => ({
    tooltip: { position: 'top' },
    grid: { left: 105, right: 24, top: 24, bottom: 30 },
    xAxis: { type: 'category', data: sourceHeatmap.hours, axisLabel: { color: '#7f8c98' }, splitArea: { show: true } },
    yAxis: { type: 'category', data: sourceHeatmap.sources, axisLabel: { color: '#a7b3bf' }, splitArea: { show: true } },
    visualMap: { min: 0, max: 100, show: false },
    series: [{ type: 'heatmap', data: sourceHeatmap.values }],
  }), [])

  return (
    <>
      <PageHeading title="态势总览" />
      <Row gutter={[14, 14]} className="metric-row">
        <Col xs={24} sm={12} xl={5}><MetricCard title="今日日志" value={2417281} suffix="条" hint="较昨日 +12.4%" /></Col>
        <Col xs={24} sm={12} xl={5}><MetricCard title="异常窗口" value={327} hint="近 24 小时" /></Col>
        <Col xs={24} sm={12} xl={5}><MetricCard title="高风险窗口" value={highRisk} hint="需要优先处理" danger /></Col>
        <Col xs={24} sm={12} xl={5}><MetricCard title="调查中" value={4} hint="2 个待复核" /></Col>
        <Col xs={24} sm={12} xl={4}><MetricCard title="活跃日志源" value={onlineSources} suffix={`/ ${sources.length}`} hint={onlineSources === sources.length ? '全部正常' : '存在延迟'} /></Col>
      </Row>

      <Row gutter={[14, 14]}>
        <Col xs={24} xl={15}>
          <Card title="24 小时日志活动" className="panel-card"><ReactECharts option={activityOption} style={{ height: 322 }} /></Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="异常类型" className="panel-card"><ReactECharts option={anomalyOption} style={{ height: 322 }} /></Card>
        </Col>
        <Col xs={24} xl={15}>
          <Card title="日志源异常密度" className="panel-card"><ReactECharts option={heatmapOption} style={{ height: 286 }} /></Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title="最新异常" extra={<Button type="link" onClick={onOpenAnomalies}>查看全部</Button>} className="panel-card">
            <List
              dataSource={windows.slice(0, 4)}
              renderItem={(item) => (
                <List.Item className="compact-list-item" onClick={onOpenAnomalies}>
                  <List.Item.Meta
                    avatar={<div className={`risk-dot ${item.severity}`} />}
                    title={<Space size={6}><Text strong>{item.title}</Text><SeverityTag value={item.severity} /></Space>}
                    description={`${item.id} · ${item.start}`}
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

function AnomaliesPage({ windows, cases, onAddToCase, onAsk, onOpenInvestigations }: {
  windows: AnomalyWindow[]
  cases: Investigation[]
  onAddToCase: (windowId: string, caseId: string) => void
  onAsk: (item: AnomalyWindow) => void
  onOpenInvestigations: () => void
}) {
  const [selected, setSelected] = useState<AnomalyWindow | null>(null)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [view, setView] = useState<string | number>('卡片')
  const [targetWindow, setTargetWindow] = useState<AnomalyWindow | null>(null)
  const [targetCase, setTargetCase] = useState(cases[0]?.id || '')

  const filtered = windows.filter((item) => {
    const text = [item.id, item.title, ...item.entities, ...item.hosts].join(' ').toLowerCase()
    return text.includes(search.toLowerCase()) && (severity === 'all' || item.severity === severity)
  })

  const openAdd = (item: AnomalyWindow) => {
    setTargetWindow(item)
    setTargetCase(cases[0]?.id || '')
  }

  const confirmAdd = () => {
    if (!targetWindow || !targetCase) return
    onAddToCase(targetWindow.id, targetCase)
    setTargetWindow(null)
  }

  const columns = [
    { title: '异常窗口', key: 'window', render: (_: unknown, item: AnomalyWindow) => <div><Text strong>{item.title}</Text><div><Text type="secondary">{item.id}</Text></div></div> },
    { title: '风险', key: 'risk', render: (_: unknown, item: AnomalyWindow) => <SeverityTag value={item.severity} /> },
    { title: '评分', dataIndex: 'score', key: 'score', render: (value: number) => `${(value * 100).toFixed(1)}%` },
    { title: '时间', key: 'time', render: (_: unknown, item: AnomalyWindow) => `${item.start} — ${item.end}` },
    { title: '关键实体', key: 'entities', render: (_: unknown, item: AnomalyWindow) => <Space size={[2, 4]} wrap>{item.entities.slice(0, 3).map((value) => <Tag key={value}>{value}</Tag>)}</Space> },
    { title: '操作', key: 'actions', render: (_: unknown, item: AnomalyWindow) => <Space><Button size="small" onClick={() => setSelected(item)}>查看</Button><Button size="small" type="primary" ghost onClick={() => openAdd(item)}>加入调查</Button></Space> },
  ]

  return (
    <>
      <PageHeading title="异常事件" extra={<Button icon={<ApartmentOutlined />} onClick={onOpenInvestigations}>攻击调查</Button>} />

      <Card className="toolbar-card">
        <Space wrap>
          <Input prefix={<SearchOutlined />} placeholder="搜索用户 / IP / Host / Process / Window ID" value={search} onChange={(event) => setSearch(event.target.value)} style={{ width: 360 }} />
          <Select
            value={severity}
            onChange={setSeverity}
            style={{ width: 130 }}
            options={[
              { value: 'all', label: '全部风险' },
              { value: 'critical', label: '严重' },
              { value: 'high', label: '高危' },
              { value: 'medium', label: '中危' },
              { value: 'low', label: '低危' },
            ]}
          />
          <Segmented value={view} onChange={setView} options={['卡片', '表格']} />
        </Space>
      </Card>

      {view === '卡片' ? (
        <Row gutter={[14, 14]}>
          {filtered.map((item) => (
            <Col xs={24} lg={12} xxl={8} key={item.id}>
              <Card className={`window-card severity-${item.severity}`} hoverable>
                <div className="window-card-head"><SeverityTag value={item.severity} /><Text type="secondary">{item.id}</Text></div>
                <Title level={4}>{item.title}</Title>
                <Paragraph type="secondary" ellipsis={{ rows: 2 }}>{item.summary}</Paragraph>
                <div className="window-stat-grid">
                  <div><Text type="secondary">时间窗口</Text><strong>{item.start} — {item.end}</strong></div>
                  <div><Text type="secondary">事件</Text><strong>{item.eventCount}</strong></div>
                  <div><Text type="secondary">主机</Text><strong>{item.hosts.length}</strong></div>
                  <div><Text type="secondary">风险评分</Text><strong>{(item.score * 100).toFixed(1)}%</strong></div>
                </div>
                <Space size={[4, 5]} wrap className="entity-tags">{item.entities.map((value) => <Tag key={value}>{value}</Tag>)}</Space>
                <div className="window-actions">
                  <Button onClick={() => setSelected(item)}>查看详情</Button>
                  <Button type="primary" ghost onClick={() => openAdd(item)}>加入调查</Button>
                </div>
              </Card>
            </Col>
          ))}
        </Row>
      ) : (
        <Card className="panel-card"><Table rowKey="id" columns={columns} dataSource={filtered} pagination={false} /></Card>
      )}

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} width={590} title={selected?.title} extra={selected && <SeverityTag value={selected.severity} />}>
        {selected && (
          <>
            <Descriptions column={2} size="small" className="detail-descriptions">
              <Descriptions.Item label="窗口编号">{selected.id}</Descriptions.Item>
              <Descriptions.Item label="风险评分">{(selected.score * 100).toFixed(1)}%</Descriptions.Item>
              <Descriptions.Item label="开始">{selected.start}</Descriptions.Item>
              <Descriptions.Item label="结束">{selected.end}</Descriptions.Item>
              <Descriptions.Item label="事件数">{selected.eventCount}</Descriptions.Item>
              <Descriptions.Item label="日志源">{selected.sourceTypes.join(' / ')}</Descriptions.Item>
            </Descriptions>

            <Card size="small" title="关键实体" className="drawer-card">
              <Space size={[5, 6]} wrap>{selected.entities.map((value) => <Tag key={value}>{value}</Tag>)}</Space>
            </Card>

            <Card size="small" title="事件时间线" className="drawer-card">
              <Timeline
                items={selected.events.map((event) => ({
                  children: (
                    <div className="event-line">
                      <div className="event-time">{event.time}</div>
                      <div className="event-body">
                        <strong>{event.action}</strong>
                        <div>{[event.actor, event.host, event.process, event.ip].filter(Boolean).join(' · ')}</div>
                        <Text type="secondary">{event.source}</Text>
                      </div>
                    </div>
                  ),
                }))}
              />
            </Card>

            <Space>
              <Button icon={<RobotOutlined />} onClick={() => onAsk(selected)}>询问 AI</Button>
              <Button type="primary" icon={<ApartmentOutlined />} onClick={() => openAdd(selected)}>加入调查</Button>
            </Space>
          </>
        )}
      </Drawer>

      <Modal title="加入攻击调查" open={Boolean(targetWindow)} onCancel={() => setTargetWindow(null)} onOk={confirmAdd} okText="加入" cancelText="取消">
        <div className="modal-window-name">{targetWindow?.title}</div>
        <Select value={targetCase} onChange={setTargetCase} style={{ width: '100%' }} options={cases.map((item) => ({ value: item.id, label: `${item.id} · ${item.title}` }))} />
      </Modal>
    </>
  )
}

function AssistantPage({ context, windows, cases }: { context: AssistantContext; windows: AnomalyWindow[]; cases: Investigation[] }) {
  const [question, setQuestion] = useState('')
  const [sending, setSending] = useState(false)
  const [chat, setChat] = useState<ChatItem[]>([
    { role: 'assistant', content: '你可以直接询问异常窗口、实体历史、调查案件或知识库内容。' },
  ])

  const activeCase = context.caseId ? cases.find((item) => item.id === context.caseId) : undefined
  const activeWindows = (context.windowIds || []).map((id) => windows.find((item) => item.id === id)).filter(Boolean) as AnomalyWindow[]

  const submit = async (preset?: string) => {
    const text = (preset || question).trim()
    if (!text || sending) return
    setChat((current) => [...current, { role: 'user', content: text }])
    setQuestion('')
    setSending(true)
    try {
      const answer = await askAssistant(text, context)
      setChat((current) => [...current, { role: 'assistant', content: answer.answer, evidence: answer.evidence }])
    } catch {
      setChat((current) => [...current, { role: 'assistant', content: '暂时无法完成查询，请稍后重试。' }])
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <PageHeading title="智能分析" />
      <Row gutter={[14, 14]} className="assistant-layout">
        <Col xs={24} xl={17}>
          <Card className="chat-card">
            <div className="chat-stream">
              {chat.map((item, index) => (
                <div key={`${item.role}-${index}`} className={`chat-row ${item.role}`}>
                  <div className="chat-avatar">{item.role === 'assistant' ? <RobotOutlined /> : <UserOutlined />}</div>
                  <div className="chat-bubble">
                    <Paragraph>{item.content}</Paragraph>
                    {item.evidence && item.evidence.length > 0 && (
                      <Space size={[4, 5]} wrap>{item.evidence.map((evidence) => <Tag key={`${evidence.ref}-${evidence.label}`}>{evidence.label}</Tag>)}</Space>
                    )}
                  </div>
                </div>
              ))}
              {sending && <div className="thinking-row"><Badge status="processing" /> 正在分析</div>}
            </div>

            <div className="suggestion-row">
              {assistantSuggestions.slice(0, 3).map((item) => <Button size="small" key={item} onClick={() => submit(item)}>{item}</Button>)}
            </div>
            <div className="chat-composer">
              <Input.TextArea value={question} onChange={(event) => setQuestion(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); submit() } }} autoSize={{ minRows: 2, maxRows: 5 }} placeholder="输入问题…" />
              <Button type="primary" icon={<SendOutlined />} loading={sending} onClick={() => submit()}>发送</Button>
            </div>
          </Card>
        </Col>

        <Col xs={24} xl={7}>
          <Card title="当前上下文" className="panel-card context-card">
            {activeCase && (
              <div className="context-section">
                <Text type="secondary">调查案件</Text>
                <strong>{activeCase.id}</strong>
                <div>{activeCase.title}</div>
              </div>
            )}
            {activeWindows.length > 0 && (
              <div className="context-section">
                <Text type="secondary">异常窗口</Text>
                <Space size={[4, 5]} wrap>{activeWindows.map((item) => <Tag key={item.id}>{item.id}</Tag>)}</Space>
              </div>
            )}
            <div className="context-section">
              <Text type="secondary">知识库</Text>
              <div className="context-ready"><CheckCircleFilled /> 已启用检索</div>
            </div>
          </Card>
        </Col>
      </Row>
    </>
  )
}

function InvestigationsPage({ cases, windows, onAsk }: { cases: Investigation[]; windows: AnomalyWindow[]; onAsk: (item: Investigation) => void }) {
  const [selectedId, setSelectedId] = useState(cases[0]?.id || '')
  const selectedCase = cases.find((item) => item.id === selectedId) || cases[0]
  const caseWindows = selectedCase ? selectedCase.windowIds.map((id) => windows.find((item) => item.id === id)).filter(Boolean) as AnomalyWindow[] : []

  const graphOption = useMemo(() => {
    const windowNodes = caseWindows.map((item, index) => ({
      id: item.id,
      name: item.title,
      symbolSize: 56 + item.score * 18,
      category: 0,
      value: Math.round(item.score * 100),
      x: 130 + index * 210,
      y: index % 2 === 0 ? 140 : 215,
      label: { show: true, formatter: `${item.id.replace('WIN-20260809-', '')}\n${item.title}`, color: '#d8e1ea', fontSize: 12 },
    }))
    const entitySet = Array.from(new Set(caseWindows.flatMap((item) => item.entities))).slice(0, 7)
    const entityNodes = entitySet.map((entity, index) => ({
      id: `entity-${entity}`,
      name: entity,
      symbolSize: 34,
      category: 1,
      x: 140 + index * 105,
      y: index % 2 === 0 ? 350 : 405,
      label: { show: true, formatter: entity, color: '#9eb0c0', fontSize: 11 },
    }))
    const links = [] as { source: string; target: string; value?: string }[]
    for (let index = 0; index < caseWindows.length - 1; index += 1) {
      links.push({ source: caseWindows[index].id, target: caseWindows[index + 1].id, value: '关联窗口' })
    }
    caseWindows.forEach((item) => {
      item.entities.filter((entity) => entitySet.includes(entity)).slice(0, 2).forEach((entity) => links.push({ source: item.id, target: `entity-${entity}` }))
    })

    return {
      tooltip: { formatter: (params: { data?: { name?: string; value?: number } }) => params.data?.value ? `${params.data.name}<br/>风险 ${params.data.value}%` : params.data?.name },
      legend: [{ data: ['异常窗口', '关键实体'], textStyle: { color: '#91a0ad' } }],
      series: [{
        type: 'graph',
        layout: 'none',
        roam: true,
        draggable: true,
        categories: [{ name: '异常窗口' }, { name: '关键实体' }],
        data: [...windowNodes, ...entityNodes],
        links,
        lineStyle: { width: 1.6, opacity: 0.7, curveness: 0.05 },
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: 7,
        emphasis: { focus: 'adjacency', lineStyle: { width: 3 } },
      }],
    }
  }, [selectedCase?.id, windows])

  if (!selectedCase) return null

  return (
    <>
      <PageHeading title="攻击调查" extra={<Button type="primary" icon={<RobotOutlined />} onClick={() => onAsk(selectedCase)}>询问 AI</Button>} />
      <Row gutter={[14, 14]}>
        <Col xs={24} xl={7}>
          <Card title="调查案件" className="case-list-card">
            <List
              dataSource={cases}
              renderItem={(item) => (
                <List.Item className={`case-item ${item.id === selectedCase.id ? 'active' : ''}`} onClick={() => setSelectedId(item.id)}>
                  <List.Item.Meta
                    title={<Space size={6}><Text strong>{item.title}</Text><SeverityTag value={item.severity} /></Space>}
                    description={`${item.id} · ${item.windowIds.length} 个异常窗口`}
                  />
                  <Tag>{caseStatusLabel[item.status]}</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>

        <Col xs={24} xl={17}>
          <Card className="case-header-card">
            <div className="case-header">
              <div>
                <Space><Title level={3}>{selectedCase.title}</Title><SeverityTag value={selectedCase.severity} /></Space>
                <Text type="secondary">{selectedCase.id} · {selectedCase.owner}</Text>
              </div>
              <Tag color="processing">{caseStatusLabel[selectedCase.status]}</Tag>
            </div>
            <Paragraph>{selectedCase.summary}</Paragraph>
          </Card>

          <Card title="攻击关系" className="panel-card graph-card">
            <ReactECharts option={graphOption} style={{ height: 430 }} />
          </Card>

          <Row gutter={[14, 14]}>
            <Col xs={24} lg={13}>
              <Card title="调查时间线" className="panel-card">
                <Timeline
                  items={caseWindows.map((item) => ({
                    dot: <ClockCircleOutlined />,
                    children: <div className="case-timeline-item"><strong>{item.start}</strong><div>{item.title}</div><Text type="secondary">{item.id}</Text></div>,
                  }))}
                />
              </Card>
            </Col>
            <Col xs={24} lg={11}>
              <Card title="案件信息" className="panel-card">
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="创建时间">{selectedCase.createdAt}</Descriptions.Item>
                  <Descriptions.Item label="负责人">{selectedCase.owner}</Descriptions.Item>
                  <Descriptions.Item label="异常窗口">{selectedCase.windowIds.length}</Descriptions.Item>
                  <Descriptions.Item label="关键实体"><Space size={[3, 4]} wrap>{Array.from(new Set(caseWindows.flatMap((item) => item.entities))).slice(0, 5).map((value) => <Tag key={value}>{value}</Tag>)}</Space></Descriptions.Item>
                </Descriptions>
              </Card>
            </Col>
          </Row>
        </Col>
      </Row>
    </>
  )
}

function SettingsPage({ sources, setSources, docs, setDocs }: {
  sources: LogSource[]
  setSources: (value: LogSource[] | ((current: LogSource[]) => LogSource[])) => void
  docs: KnowledgeDoc[]
  setDocs: (value: KnowledgeDoc[] | ((current: KnowledgeDoc[]) => KnowledgeDoc[])) => void
}) {
  const [sourceModal, setSourceModal] = useState(false)
  const [docModal, setDocModal] = useState(false)
  const [sourceForm] = Form.useForm()
  const [docForm] = Form.useForm()

  const addSource = async () => {
    const values = await sourceForm.validateFields()
    setSources((current) => [...current, {
      id: `SRC-${String(current.length + 1).padStart(2, '0')}`,
      name: values.name,
      path: values.path,
      kind: values.kind,
      status: 'online',
      size: '0 B',
      lastRead: '刚刚',
    }])
    sourceForm.resetFields()
    setSourceModal(false)
    message.success('日志源已添加')
  }

  const addDocument = async () => {
    const values = await docForm.validateFields()
    setDocs((current) => [...current, {
      id: `KB-${String(current.length + 1).padStart(2, '0')}`,
      name: values.name,
      category: values.category,
      kind: values.kind,
      status: 'indexed',
      chunks: Number(values.chunks || 1),
      updatedAt: new Date().toISOString().slice(0, 10),
    }])
    docForm.resetFields()
    setDocModal(false)
    message.success('知识已加入')
  }

  const sourceColumns = [
    { title: '名称', dataIndex: 'name', key: 'name', render: (value: string) => <Space><FolderOpenOutlined /><Text strong>{value}</Text></Space> },
    { title: '路径', dataIndex: 'path', key: 'path', render: (value: string) => <Text code>{value}</Text> },
    { title: '类型', dataIndex: 'kind', key: 'kind', render: (value: string) => <Tag>{value}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', render: (value: LogSource['status']) => <Badge status={value === 'online' ? 'success' : value === 'warning' ? 'warning' : 'error'} text={value === 'online' ? '正常' : value === 'warning' ? '延迟' : '离线'} /> },
    { title: '最后读取', dataIndex: 'lastRead', key: 'lastRead' },
  ]

  const docColumns = [
    { title: '文档', dataIndex: 'name', key: 'name', render: (value: string) => <Space><FileTextOutlined /><Text strong>{value}</Text></Space> },
    { title: '分类', dataIndex: 'category', key: 'category' },
    { title: '格式', dataIndex: 'kind', key: 'kind', render: (value: string) => <Tag>{value}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', render: (value: KnowledgeDoc['status']) => <Badge status={value === 'indexed' ? 'success' : value === 'indexing' ? 'processing' : 'error'} text={value === 'indexed' ? '已索引' : value === 'indexing' ? '索引中' : '失败'} /> },
    { title: '知识块', dataIndex: 'chunks', key: 'chunks' },
    { title: '更新', dataIndex: 'updatedAt', key: 'updatedAt' },
  ]

  return (
    <>
      <PageHeading title="设置" />
      <Card className="settings-card">
        <Tabs
          tabPosition="left"
          items={[
            {
              key: 'sources',
              label: <Space><FolderOpenOutlined />日志源</Space>,
              children: (
                <div className="settings-pane">
                  <div className="settings-pane-head"><Title level={4}>日志源</Title><Button type="primary" icon={<PlusOutlined />} onClick={() => setSourceModal(true)}>添加日志源</Button></div>
                  <Table rowKey="id" columns={sourceColumns} dataSource={sources} pagination={false} />
                </div>
              ),
            },
            {
              key: 'knowledge',
              label: <Space><BookOutlined />知识库</Space>,
              children: (
                <div className="settings-pane">
                  <div className="settings-pane-head"><Title level={4}>知识库</Title><Button type="primary" icon={<PlusOutlined />} onClick={() => setDocModal(true)}>添加内容</Button></div>
                  <Table rowKey="id" columns={docColumns} dataSource={docs} pagination={false} />
                </div>
              ),
            },
            {
              key: 'ai',
              label: <Space><RobotOutlined />AI</Space>,
              children: (
                <div className="settings-pane compact-pane">
                  <Title level={4}>AI 服务</Title>
                  <Card size="small" className="setting-section">
                    <div className="setting-line"><div><strong>GPT 服务</strong><div><Text type="secondary">用于安全问答与调查摘要</Text></div></div><Badge status="success" text="已连接" /></div>
                    <div className="setting-line"><div><strong>知识库检索</strong><div><Text type="secondary">回答时检索已索引内容</Text></div></div><Switch defaultChecked /></div>
                    <div className="setting-line"><div><strong>调查上下文</strong><div><Text type="secondary">自动带入当前 Window / Case</Text></div></div><Switch defaultChecked /></div>
                  </Card>
                </div>
              ),
            },
            {
              key: 'storage',
              label: <Space><DatabaseOutlined />存储</Space>,
              children: (
                <div className="settings-pane compact-pane">
                  <Title level={4}>数据存储</Title>
                  <Row gutter={[14, 14]}>
                    <Col xs={24} md={12}><Card size="small" title="事件与调查"><Progress percent={38} /><Text type="secondary">异常窗口、实体索引、调查记录</Text></Card></Col>
                    <Col xs={24} md={12}><Card size="small" title="知识库"><Progress percent={26} /><Text type="secondary">文档、知识块与检索索引</Text></Card></Col>
                  </Row>
                  <Card size="small" className="setting-section">
                    <div className="setting-line"><div><strong>事件保留周期</strong></div><Select defaultValue="180" style={{ width: 140 }} options={[{ value: '30', label: '30 天' }, { value: '90', label: '90 天' }, { value: '180', label: '180 天' }, { value: '365', label: '1 年' }]} /></div>
                    <div className="setting-line"><div><strong>历史调查进入知识库</strong></div><Switch defaultChecked /></div>
                  </Card>
                </div>
              ),
            },
          ]}
        />
      </Card>

      <Modal title="添加日志源" open={sourceModal} onCancel={() => setSourceModal(false)} onOk={addSource} okText="保存" cancelText="取消">
        <Form layout="vertical" form={sourceForm}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input placeholder="Windows Domain Controller" /></Form.Item>
          <Form.Item label="日志路径" name="path" rules={[{ required: true }]}><Input placeholder="D:\\Logs\\DC01\\ 或 /var/log/audit/" /></Form.Item>
          <Form.Item label="类型" name="kind" initialValue="EVTX"><Select options={[{ value: 'EVTX', label: 'Windows EVTX' }, { value: 'LOG', label: 'Text / Audit Log' }, { value: 'CSV', label: 'CSV' }, { value: 'JSONL', label: 'JSONL' }]} /></Form.Item>
        </Form>
      </Modal>

      <Modal title="添加知识内容" open={docModal} onCancel={() => setDocModal(false)} onOk={addDocument} okText="添加" cancelText="取消">
        <Form layout="vertical" form={docForm}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input placeholder="Security_Policy.pdf" /></Form.Item>
          <Form.Item label="分类" name="category" initialValue="组织环境"><Select options={[{ value: '组织环境', label: '组织环境' }, { value: '攻击知识', label: '攻击知识' }, { value: '运维知识', label: '运维知识' }, { value: '历史调查', label: '历史调查' }]} /></Form.Item>
          <Form.Item label="格式" name="kind" initialValue="PDF"><Select options={[{ value: 'PDF', label: 'PDF' }, { value: 'Markdown', label: 'Markdown' }, { value: 'CSV', label: 'CSV' }, { value: 'Text', label: 'Text' }]} /></Form.Item>
        </Form>
      </Modal>
    </>
  )
}

export default App
