import { useState } from 'react'
import { Badge, Button, Card, Col, Input, Row, Space, Tag, Typography } from 'antd'
import { RobotOutlined, SearchOutlined, SendOutlined, UserOutlined } from '@ant-design/icons'
import { searchProjectKnowledge, type AssistantContext, type ProjectKnowledgeDocument } from '../services/api'
import {
  AssistantAnswerContent,
  HelpTitle,
  PageTitle,
  StructuredSection,
  type AssistantQuickAction,
  type ChatItem,
} from './shared'

const { Text, Paragraph } = Typography

const assistantPresets = [
  { label: '证据整理', prompt: '根据当前上下文整理攻击时间线，区分 facts、assessments 和 uncertainties。' },
  { label: '关联检查', prompt: '检查当前 Finding 是否有足够证据属于同一活动，并给出支持或反对的证据。' },
  { label: '缺口分析', prompt: '找出当前 Investigation 仍缺少的关键证据，并给出 recommended_queries。' },
  { label: '项目方法', prompt: '结合链影寻踪项目知识库，解释当前分析用到了哪些 M0-M6 模块和三项核心创新，并给出知识库引用。' },
]

const knowledgePresets = [
  '长周期攻击链怎么关联',
  '多尺度上下文主动检索',
  '综合风险评分怎么算',
  'TB 级日志怎么接入',
  '真实标签评测隔离',
]

function KnowledgeSearchPanel() {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [documents, setDocuments] = useState<ProjectKnowledgeDocument[]>([])
  const [retrieval, setRetrieval] = useState('')
  const [searched, setSearched] = useState(false)
  const [error, setError] = useState('')

  const runSearch = async (value?: string) => {
    const text = (value ?? query).trim()
    if (!text || loading) return
    setQuery(text)
    setLoading(true)
    setError('')
    try {
      const result = await searchProjectKnowledge(text)
      setDocuments(result.documents)
      setRetrieval(result.retrieval)
      setSearched(true)
    } catch {
      setError('知识库检索失败，请确认后端服务已启动。')
      setDocuments([])
      setSearched(true)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card
      title={<HelpTitle title="知识库检索" description="对链影寻踪项目知识库执行混合词法检索：中文字符片段 + 英文词元 + 标题标签加权，返回可引用的知识卡片。" />}
      className="mc-panel"
      style={{ marginTop: 12 }}
    >
      <Space.Compact style={{ width: '100%' }}>
        <Input value={query} onChange={(event) => setQuery(event.target.value)} onPressEnter={() => runSearch()} placeholder="例如：长周期攻击链怎么关联" prefix={<SearchOutlined />} allowClear />
        <Button type="primary" icon={<SearchOutlined />} loading={loading} onClick={() => runSearch()}>检索</Button>
      </Space.Compact>
      <Space size={[4, 6]} wrap style={{ marginTop: 8 }}>
        {knowledgePresets.map((item) => <Button size="small" key={item} onClick={() => runSearch(item)}>{item}</Button>)}
      </Space>
      {searched && !error && (
        <div style={{ marginTop: 12 }}>
          <Text type="secondary" style={{ fontSize: 12 }}>命中 {documents.length} 篇 · 检索器 {retrieval || 'hybrid_lexical_cjk_v1'}</Text>
          {documents.length === 0 && <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>未命中相关知识卡片，换一个项目术语试试。</Text>}
          {documents.map((doc) => (
            <div key={doc.document_id} className="mc-kb-card">
              <Space size={6} wrap><Text strong>{doc.title}</Text><Tag color="blue">{doc.document_id}</Tag></Space>
              <div style={{ marginTop: 4 }}>
                <Space size={[3, 4]} wrap>
                  {(doc.tags || []).slice(0, 5).map((tag) => <Tag key={tag} style={{ fontSize: 11 }}>{tag}</Tag>)}
                  {typeof doc.retrieval_score === 'number' && <Tag color="cyan" style={{ fontSize: 11 }}>相关度 {doc.retrieval_score.toFixed(1)}</Tag>}
                </Space>
              </div>
              <Paragraph type="secondary" ellipsis={{ rows: 2 }} style={{ marginTop: 4, marginBottom: 0, fontSize: 12 }}>
                {doc.content || doc.chunk || ''}
              </Paragraph>
            </div>
          ))}
        </div>
      )}
      {error && <Text type="danger" style={{ display: 'block', marginTop: 8 }}>{error}</Text>}
    </Card>
  )
}

export default function AssistantPage({
  context,
  chat,
  actions,
  sending,
  question,
  onQuestionChange,
  onSubmit,
}: {
  context: AssistantContext
  chat: ChatItem[]
  actions: AssistantQuickAction[]
  sending: boolean
  question: string
  onQuestionChange: (value: string) => void
  onSubmit: (value: string) => void
}) {
  return (
    <>
      <PageTitle title="小影" subtitle="链影寻踪项目知识增强型调查智能体 · 数据工具、M0-M6 方法库与证据核验协同" />
      <Row gutter={[12, 12]}>
        <Col xs={24} xl={17}>
          <Card className="mc-chat-card">
            <Space wrap style={{ marginBottom: 12 }}>
              {assistantPresets.map((item) => <Button key={item.label} onClick={() => onSubmit(item.prompt)}>{item.label}</Button>)}
            </Space>
            <div className="mc-chat-stream">
              {chat.map((item, index) => (
                <div className={`mc-chat-row ${item.role}`} key={`${item.role}-${index}`}>
                  <div className="mc-chat-avatar">{item.role === 'assistant' ? <RobotOutlined /> : <UserOutlined />}</div>
                  <div className="mc-chat-bubble">
                    <AssistantAnswerContent content={item.content} />
                    {item.evidence && <Space size={[4, 4]} wrap>{item.evidence.map((evidence) => (
                      <Tag
                        color={evidence.ref.startsWith('KB-') || evidence.ref.startsWith('DOC-') ? 'blue' : undefined}
                        key={`${evidence.ref}-${evidence.label}`}
                        title={`${evidence.ref}${evidence.source ? ` · ${evidence.source}` : ''}`}
                      >
                        {evidence.label}
                      </Tag>
                    ))}</Space>}
                    {item.structured && (
                      <>
                        <StructuredSection title="事实" items={item.structured.facts} />
                        <StructuredSection title="判断" items={item.structured.assessments} />
                        <StructuredSection title="待确认" items={item.structured.uncertainties} />
                        <StructuredSection title="下一步核验" items={item.structured.recommended_queries} />
                      </>
                    )}
                    {(item.verified !== undefined || item.confidence !== undefined) && (
                      <div style={{ marginTop: 8 }}>
                        {item.verified !== undefined && <Tag color={item.verified ? 'success' : 'warning'}>{item.verified ? '已核验' : '待确认'}</Tag>}
                        {item.confidence !== undefined && <Tag>置信 {Math.round(item.confidence * 100)}%</Tag>}
                        {item.verification && (
                          <>
                            <Tag>证据 {item.verification.totalItems}</Tag>
                            <Tag color={item.verification.downgradedItems > 0 ? 'warning' : 'success'}>
                              降级 {item.verification.downgradedItems}
                            </Tag>
                          </>
                        )}
                      </div>
                    )}
                    {item.role === 'assistant' && index === chat.length - 1 && actions.length > 0 && (
                      <Space wrap className="mc-chat-actions">
                        {actions.map((action) => (
                          <Button key={action.key} size="small" onClick={action.onClick}>
                            {action.label}
                          </Button>
                        ))}
                      </Space>
                    )}
                  </div>
                </div>
              ))}
              {sending && <div><Badge status="processing" /> 小影处理中…</div>}
            </div>
            <div className="mc-chat-composer">
              <Input.TextArea value={question} onChange={(event) => onQuestionChange(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); onSubmit(question) } }} autoSize={{ minRows: 2, maxRows: 5 }} placeholder="输入调查问题" />
              <Button type="primary" icon={<SendOutlined />} loading={sending} onClick={() => onSubmit(question)}>发送</Button>
            </div>
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title={<HelpTitle title="当前上下文" description="小影当前可引用的案件、窗口、实体和时间范围。更换上下文会影响回答范围。" />} className="mc-panel">
            <Space wrap size={[6, 6]}>
              <Tag>{context.caseId || '未选择案件'}</Tag>
              {(context.windowIds || []).slice(0, 3).map((windowId) => <Tag key={windowId}>{windowId}</Tag>)}
              {(context.entityIds || []).slice(0, 3).map((entityId) => <Tag key={entityId}>{entityId}</Tag>)}
              {context.timeRange && <Tag>{context.timeRange}</Tag>}
            </Space>
          </Card>
          <Card title={<HelpTitle title="项目能力" description="小影将可替换的通用模型作为推理层，项目知识、检测工具、上下文和证据协议由链影寻踪提供。" />} className="mc-panel" style={{ marginTop: 12 }}>
            <Space wrap size={[6, 6]}>
              <Tag color="blue">M0-M6 方法库</Tag>
              <Tag color="blue">多尺度主动检索</Tag>
              <Tag color="blue">跨源实体关系图</Tag>
              <Tag color="blue">长周期攻击链</Tag>
              <Tag color="cyan">weak_fusion_v2</Tag>
              <Tag color="green">证据引用与核验</Tag>
              <Tag color="gold">真实标签评测隔离</Tag>
            </Space>
            <Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
              回答当前环境问题时先读取 Finding、案件、实体、时间线或原始日志；解释方法时检索项目知识库。事实、判断和不确定性分别呈现。
            </Paragraph>
          </Card>
          <KnowledgeSearchPanel />
        </Col>
      </Row>
    </>
  )
}
