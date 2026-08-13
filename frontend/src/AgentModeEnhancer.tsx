import { useEffect, useState } from 'react'
import { Badge, Button, Card, Input, Modal, Segmented, Select, Space, Tag, Typography, message } from 'antd'
import { KeyOutlined, RobotOutlined } from '@ant-design/icons'
import { createPortal } from 'react-dom'
import { useLocation } from 'react-router-dom'
import {
  configureAgentProvider,
  getAgentHealth,
  getAgentMode,
  setAgentMode,
  type AgentHealth,
  type AgentMode,
  type AgentProviderConfig,
  type ResolvedAgentMode,
} from './services/api'

const { Text } = Typography

const providerPresets: Record<AgentProviderConfig['provider'], { label: string; baseUrl: string; model: string }> = {
  openai: { label: 'OpenAI', baseUrl: '', model: 'gpt-4o-mini' },
  deepseek: { label: 'DeepSeek', baseUrl: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
  qwen: { label: '通义千问', baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-plus' },
  siliconflow: { label: 'SiliconFlow', baseUrl: 'https://api.siliconflow.cn/v1', model: 'Qwen/Qwen2.5-72B-Instruct' },
  custom: { label: '自定义兼容接口', baseUrl: '', model: '' },
}

const modeOptions = [
  { label: '自动', value: 'auto' },
  { label: '安全分析', value: 'security' },
  { label: '知识问答', value: 'knowledge' },
  { label: '普通', value: 'general' },
]

const modeLabels: Record<ResolvedAgentMode, string> = {
  security: '安全分析',
  knowledge: '知识问答',
  general: '普通',
}

type AgentResultEvent = {
  mode?: ResolvedAgentMode
  verified?: boolean
  confidence?: number
  runId?: string
}

export default function AgentModeEnhancer() {
  const location = useLocation()
  const [host, setHost] = useState<HTMLDivElement | null>(null)
  const [mode, setMode] = useState<AgentMode>(getAgentMode())
  const [health, setHealth] = useState<AgentHealth | null>(null)
  const [lastResult, setLastResult] = useState<AgentResultEvent | null>(null)
  const [liveStatus, setLiveStatus] = useState('')
  const [providerOpen, setProviderOpen] = useState(false)
  const [apiKey, setApiKey] = useState('')
  const [provider, setProvider] = useState<AgentProviderConfig['provider']>('openai')
  const [baseUrl, setBaseUrl] = useState(providerPresets.openai.baseUrl)
  const [model, setModel] = useState(providerPresets.openai.model)
  const [savingKey, setSavingKey] = useState(false)

  useEffect(() => {
    if (!location.pathname.startsWith('/assistant')) {
      setHost(null)
      return
    }

    const content = document.querySelector('.mc-content')
    const pageTitle = content?.querySelector('.mc-page-title')
    if (!content || !pageTitle) return

    let slot = document.getElementById('agent-mode-slot') as HTMLDivElement | null
    if (!slot) {
      slot = document.createElement('div')
      slot.id = 'agent-mode-slot'
      pageTitle.insertAdjacentElement('afterend', slot)
    }
    setHost(slot)
    return () => slot?.remove()
  }, [location.pathname])

  const refreshHealth = async () => {
    try {
      setHealth(await getAgentHealth())
    } catch {
      setHealth(null)
    }
  }

  useEffect(() => {
    if (!host) return
    refreshHealth()
    const timer = window.setInterval(refreshHealth, 10000)
    return () => window.clearInterval(timer)
  }, [host])

  useEffect(() => {
    const resultHandler = (event: Event) => {
      const custom = event as CustomEvent<AgentResultEvent>
      setLastResult(custom.detail || null)
      setLiveStatus('')
    }
    const statusHandler = (event: Event) => {
      const custom = event as CustomEvent<{ label?: string }>
      setLiveStatus(custom.detail?.label || '')
    }
    window.addEventListener('wad-agent-result', resultHandler)
    window.addEventListener('wad-agent-status', statusHandler)
    return () => {
      window.removeEventListener('wad-agent-result', resultHandler)
      window.removeEventListener('wad-agent-status', statusHandler)
    }
  }, [])

  const changeMode = (value: string | number) => {
    const next = String(value) as AgentMode
    setMode(next)
    setAgentMode(next)
    setLastResult(null)
    setLiveStatus('')
  }

  const saveProviderKey = async () => {
    const key = apiKey.trim()
    if (key.length < 8) {
      message.error('请输入有效的模型 API Key')
      return
    }

    setSavingKey(true)
    try {
      const result = await configureAgentProvider({ apiKey: key, provider, baseUrl, model })
      setApiKey('')
      setProviderOpen(false)
      await refreshHealth()
      message.success(result.message)
    } catch (error) {
      const text = error instanceof Error ? error.message : '模型服务配置失败'
      message.error(text)
    } finally {
      setSavingKey(false)
    }
  }

  if (!host) return null

  return createPortal(
    <>
      <Card className="agent-mode-card" size="small">
        <div className="agent-mode-row">
          <div>
            <Space size={8} wrap>
              <RobotOutlined />
              <Text strong>小影</Text>
              <Segmented value={mode} options={modeOptions} onChange={changeMode} />
              {lastResult?.mode && (
                <Tag color={lastResult.mode === 'security' ? 'processing' : undefined}>
                  本轮：{modeLabels[lastResult.mode]}
                </Tag>
              )}
              {lastResult?.verified && <Tag color="success">证据已核验</Tag>}
            </Space>
            {liveStatus && <div className="agent-live-status"><Badge status="processing" /> {liveStatus}</div>}
          </div>
          <Space size={8} wrap>
            {health ? (
              <>
                <Badge
                  status={health.openai_configured ? 'success' : 'warning'}
                  text={health.openai_configured ? '在线' : '未配置'}
                />
                <Button size="small" icon={<KeyOutlined />} onClick={() => setProviderOpen(true)}>
                  模型配置
                </Button>
              </>
            ) : (
              <>
                <Badge status="error" text="未连接" />
                <Button size="small" icon={<KeyOutlined />} onClick={() => setProviderOpen(true)}>
                  模型配置
                </Button>
              </>
            )}
          </Space>
        </div>
      </Card>

      <Modal
        title="配置模型服务"
        open={providerOpen}
        onCancel={() => { setProviderOpen(false); setApiKey('') }}
        onOk={saveProviderKey}
        okText="加载到后端"
        cancelText="取消"
        confirmLoading={savingKey}
        destroyOnClose
      >
        <Text type="secondary">仅当前后端进程有效</Text>
        <Select
          value={provider}
          style={{ width: '100%', marginTop: 8 }}
          options={Object.entries(providerPresets).map(([value, item]) => ({ value, label: item.label }))}
          onChange={(value: AgentProviderConfig['provider']) => {
            setProvider(value)
            setBaseUrl(providerPresets[value].baseUrl)
            setModel(providerPresets[value].model)
          }}
        />
        <Input
          value={baseUrl}
          onChange={(event) => setBaseUrl(event.target.value)}
          placeholder="Base URL，例如 https://api.deepseek.com/v1"
          style={{ marginTop: 8 }}
        />
        <Input
          value={model}
          onChange={(event) => setModel(event.target.value)}
          placeholder="模型名，例如 deepseek-chat"
          style={{ marginTop: 8 }}
        />
        <Input.Password
          value={apiKey}
          onChange={(event) => setApiKey(event.target.value)}
          placeholder="sk-..."
          autoComplete="new-password"
          style={{ marginTop: 8 }}
          onPressEnter={saveProviderKey}
        />
      </Modal>
    </>,
    host,
  )
}
