import { useEffect, useState } from 'react'
import { Badge, Card, Segmented, Space, Tag, Typography } from 'antd'
import { RobotOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { createPortal } from 'react-dom'
import { useLocation } from 'react-router-dom'
import {
  getAgentMode,
  setAgentMode,
  type AgentMode,
  type ResolvedAgentMode,
} from './services/api'

const { Text } = Typography

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

const descriptions: Record<AgentMode, string> = {
  auto: '根据问题与当前 Finding / Investigation / Entity 上下文自动选择最小权限模式。',
  security: '允许调用只读安全工具，查询 Finding、日志、实体、历史基线与调查证据。',
  knowledge: '优先检索安全知识库，不主动读取当前环境日志。',
  general: '普通对话模式，不具备内部日志、Finding、实体或 Investigation 读取权限。',
}

type Health = {
  ok: boolean
  openai_configured: boolean
  repository: string
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
  const [health, setHealth] = useState<Health | null>(null)
  const [lastResult, setLastResult] = useState<AgentResultEvent | null>(null)
  const [liveStatus, setLiveStatus] = useState('')

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

  useEffect(() => {
    if (!host) return
    let active = true
    fetch('/api/agent/health')
      .then(async (response) => response.ok ? response.json() as Promise<Health> : Promise.reject())
      .then((value) => { if (active) setHealth(value) })
      .catch(() => { if (active) setHealth(null) })
    return () => { active = false }
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

  if (!host) return null

  return createPortal(
    <Card className="agent-mode-card" size="small">
      <div className="agent-mode-row">
        <div>
          <Space size={8} wrap>
            <RobotOutlined />
            <Text strong>Agent 模式</Text>
            <Segmented value={mode} options={modeOptions} onChange={changeMode} />
            {lastResult?.mode && (
              <Tag color={lastResult.mode === 'security' ? 'processing' : undefined}>
                本轮：{modeLabels[lastResult.mode]}
              </Tag>
            )}
            {lastResult?.verified && <Tag color="success">证据已核验</Tag>}
          </Space>
          <div className="agent-mode-description">{descriptions[mode]}</div>
          {liveStatus && <div className="agent-live-status"><Badge status="processing" /> {liveStatus}</div>}
        </div>
        <Space size={8} wrap>
          <Tag icon={<SafetyCertificateOutlined />}>只读工具</Tag>
          {health ? (
            <Badge
              status={health.openai_configured ? 'success' : 'warning'}
              text={health.openai_configured ? `Agent 在线 · ${health.repository}` : 'Agent 在线 · 未配置模型密钥'}
            />
          ) : (
            <Badge status="default" text="Agent 服务未连接" />
          )}
        </Space>
      </div>
    </Card>,
    host,
  )
}
