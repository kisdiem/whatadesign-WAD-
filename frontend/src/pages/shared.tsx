import { type ReactNode } from 'react'
import { Card, List, Popover, Space, Tag, Typography } from 'antd'
import { QuestionCircleOutlined } from '@ant-design/icons'
import type { Severity, Investigation, SecurityEvent } from '../mocks/data'
import type { FindingStatus, FindingStage, EntityProfile } from '../services/investigationDomain'
import {
  isUsingLocalData,
  type AssistantAnswer,
  type AssistantContext,
  type AssistantStructuredItem,
  type AssistantStructuredResult,
  type AssistantVerificationSummary,
} from '../services/api'
import type { ModuleScores } from '../services/ingestion'

const { Title, Text, Paragraph } = Typography
const PREFER_DEMO_DATA = import.meta.env.VITE_PREFER_DEMO_DATA !== 'false'

export function ChartFallback({ height }: { height: number }) {
  return <div style={{ height, borderRadius: 14, background: 'rgba(128, 165, 210, 0.12)' }} />
}

export const severityLabel: Record<Severity, string> = {
  info: '正常',
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

export const findingSeverityLevels: Severity[] = ['critical', 'high', 'medium']

export type FindingSortMode = 'risk_desc' | 'long_desc' | 'event_desc' | 'latest_desc'

export const findingSortOptions: Array<{ value: FindingSortMode; label: string }> = [
  { value: 'risk_desc', label: '综合风险：高到低' },
  { value: 'long_desc', label: '长程关联：高到低' },
  { value: 'event_desc', label: '事件异常：高到低' },
  { value: 'latest_desc', label: '发现时间：新到旧' },
]

export const statusLabel: Record<FindingStatus, string> = {
  new: '新建',
  reviewing: '待处理',
  investigating: '调查中',
  ignored: '已排除',
  closed: '已关闭',
}

export type InvestigationQueueStatus = NonNullable<Investigation['queueStatus']>

export function investigationQueueStatus(item: Investigation): InvestigationQueueStatus {
  if (item.queueStatus) return item.queueStatus
  if (item.id.includes('-AUTO-') || item.owner === 'm0-m6-ingestion' || item.owner === 'M5 自动关联') return 'auto_observe'
  if (item.status === 'closed' || item.status === 'contained') return 'resolved'
  return 'manual_review'
}

export function isManualInvestigation(item: Investigation) {
  const status = investigationQueueStatus(item)
  return status === 'manual_review' || status === 'resolved'
}

// 系统自动处置链：系统判定并已完成研判（resolved 且决策来源为 system），与人工完成的
// 基准链（resolved + analyst）区分开，分别落入案件队列的“自动处置 / 完成”分类。
export function isSystemResolved(item: Investigation) {
  return investigationQueueStatus(item) === 'resolved' && item.decisionSource === 'system'
}

export const investigationQueueMeta: Record<InvestigationQueueStatus, { label: string; color: string }> = {
  auto_observe: { label: '自动观察', color: 'cyan' },
  manual_review: { label: '待人工研判', color: 'orange' },
  resolved: { label: '已定案', color: 'green' },
  suppressed: { label: '自动抑制', color: 'default' },
  merged: { label: '已归并', color: 'blue' },
}

export function scoreTone(value: number) {
  if (value >= 80) return 'exception'
  if (value >= 60) return 'active'
  return 'normal'
}

export function HelpHint({ title, description }: { title: string; description: string }) {
  return (
    <Popover
      trigger="click"
      placement="top"
      title={title}
      content={<div className="mc-help-content">{description}</div>}
    >
      <button
        type="button"
        className="mc-help-trigger"
        aria-label={`${title}说明`}
        onClick={(event) => event.stopPropagation()}
      >
        <QuestionCircleOutlined />
      </button>
    </Popover>
  )
}

export function HelpTitle({ title, description }: { title: string; description: string }) {
  return <Space size={5}><span>{title}</span><HelpHint title={`${title}说明`} description={description} /></Space>
}

export function selectedExcerpt(fallback: string) {
  const selected = typeof window === 'undefined' ? '' : window.getSelection()?.toString().trim() || ''
  return (selected || fallback).replace(/\s+/g, ' ').slice(0, 900)
}

export function ExplainableText({
  children,
  fallback,
  context,
  onExplain,
}: {
  children: ReactNode
  fallback: string
  context: AssistantContext
  onExplain: (excerpt: string, context: AssistantContext) => void
}) {
  return <span className="mc-ai-explainable" title="双击交给小影解释" onClick={(event) => event.stopPropagation()} onDoubleClick={(event) => { event.stopPropagation(); onExplain(selectedExcerpt(fallback), context) }}>{children}</span>
}

export function ExplainableBlock({
  children,
  fallback,
  context,
  onExplain,
}: {
  children: ReactNode
  fallback: string
  context: AssistantContext
  onExplain: (excerpt: string, context: AssistantContext) => void
}) {
  return <div className="mc-ai-explainable-block" title="双击交给小影解释" onDoubleClick={() => onExplain(selectedExcerpt(fallback), context)}>{children}</div>
}

export function riskLevelExplanation(value: number) {
  if (value >= 80) return `当前分数 ${value}，属于高优先级风险。80 分及以上建议优先核查。`
  if (value >= 65) return `当前分数 ${value}，属于较高风险。65 至 79 分建议尽快复核。`
  return `当前分数 ${value}，属于中等风险。建议结合事件证据和上下文判断。`
}

export function RiskBadge({ value }: { value: number }) {
  return (
    <Popover trigger="click" placement="top" title="风险分数" content={<div className="mc-help-content">{riskLevelExplanation(value)}</div>}>
      <button type="button" className={`mc-risk-score mc-explainable-tag ${value >= 80 ? 'critical' : value >= 65 ? 'high' : 'medium'}`} onClick={(event) => event.stopPropagation()}>{value}</button>
    </Popover>
  )
}

export function SeverityTag({ value }: { value: Severity }) {
  const color = value === 'critical' ? 'red' : value === 'high' ? 'orange' : value === 'medium' ? 'gold' : 'blue'
  return <Popover trigger="click" placement="top" title="风险等级" content={<div className="mc-help-content">严重：80 分及以上；高危：65 至 79 分；中危：低于 65 分。等级用于排序，不替代人工判断。</div>}><Tag color={color} className="mc-explainable-tag" onClick={(event) => event.stopPropagation()}>{severityLabel[value]}</Tag></Popover>
}

export function readableReason(value?: string) {
  if (!value) return '未说明'
  const labels: Record<string, string> = {
    shared_account: '共享账号',
    same_user: '相同用户',
    same_host: '相同主机',
    multi_source_corroboration: '多来源印证',
    process_relation: '进程关联',
    new_host_relation: '新主机关系',
    unusual_time: '异常时段',
    long_range_entity_overlap: '长程实体重叠',
  }
  if (labels[value]) return labels[value]
  const gap = value.match(/^Δt\s*(.*)$/i)
  if (gap) return `时间间隔 ${gap[1]}`
  return value.replace(/[_-]+/g, ' ')
}

export function reasonExplanation(value: string) {
  const descriptions: Record<string, string> = {
    shared_account: '当前发现与其他行为使用同一账号。共享账号本身不等于攻击，需要结合时间和行为判断。',
    same_user: '两段行为由同一用户账号触发，可能属于同一操作过程。',
    same_host: '两段行为发生在同一主机上，说明存在共同的执行环境。',
    multi_source_corroboration: '同一时间段被多个日志来源同时印证，证据完整度更高。',
    process_relation: '时间窗口内出现进程、脚本、命令或令牌操作，可能与当前事件有关。',
    new_host_relation: '时间窗口内出现网络连接、DNS、SSH 或新的主机关系，需要核查是否为正常通信。',
    unusual_time: '行为发生在较少见的时段。该理由仅表示偏离常态，不单独代表攻击。',
    long_range_entity_overlap: '相隔较长时间的发现共享多个实体，可能属于同一持续过程。',
  }
  if (descriptions[value]) return descriptions[value]
  if (/^Δt\s*/i.test(value)) return `两段关联行为之间的时间间隔为 ${value.replace(/^Δt\s*/i, '')}。时间接近时，关联强度通常更高。`
  return '这是系统用于解释关联依据的标签，应结合原始日志和时间线复核。'
}

export function ReasonTag({ reason }: { reason: string }) {
  return <Popover trigger="click" placement="top" title={readableReason(reason)} content={<div className="mc-help-content">{reasonExplanation(reason)}</div>}><Tag className="mc-explainable-tag" onClick={(event) => event.stopPropagation()}>{readableReason(reason)}</Tag></Popover>
}

export function readableStage(stage: FindingStage) {
  return stage === 'main' ? '主链证据' : stage === 'candidate' ? '候选证据' : '已排除'
}

export function readableEntityType(type: EntityProfile['type']) {
  return ({ User: '用户账号', Host: '主机', Process: '进程或程序', IP: 'IP 地址', Asset: '文件或资产' } as Record<EntityProfile['type'], string>)[type] || '未知实体'
}

export function readableAction(value?: string) {
  const action = value || '未知行为'
  const normalized = action.toUpperCase()
  const labels: Array<[RegExp, string]> = [
    [/LOGIN_FAILURE|FAILED_PASSWORD|AUTH_FAILURE|登录失败|认证失败/i, '登录失败'],
    [/SSH_LOGIN|LOGIN|LOGON|AUTH|ACCEPTED_PASSWORD|登录成功|认证成功/i, '登录或认证'],
    [/PROCESS_START|EXEC|COMMAND|SHELL|进程启动|命令执行/i, '进程或命令执行'],
    [/NETWORK_CONNECT|NETWORK_BURST|PORT_BURST|DNS|外联|网络连接/i, '网络连接或探测'],
    [/FILE_CREATE|FILE_WRITE|ARCHIVE_CREATE|文件创建|写入/i, '文件创建或写入'],
    [/FILE_READ|FILE_ACCESS|文件读取|文件访问/i, '文件读取或访问'],
    [/DB_EXPORT|数据导出/i, '数据库或数据导出'],
    [/PRIVILEGE|TOKEN|权限提升|令牌/i, '权限或令牌操作'],
  ]
  return labels.find(([pattern]) => pattern.test(normalized) || pattern.test(action))?.[1] || action.replace(/[_-]+/g, ' ')
}

export function useRepositoryPresentation() {
  return !isUsingLocalData() && !PREFER_DEMO_DATA
}

export function PageTitle({ title, subtitle, extra }: { title: string; subtitle?: string; extra?: ReactNode }) {
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

export function StructuredSection({
  title,
  items,
}: {
  title: string
  items: AssistantStructuredItem[]
}) {
  if (!items.length) return null

  const visibleEvidenceIds = (evidenceIds: string[]) =>
    evidenceIds.filter((evidenceId) => /^[A-Z]+[-_]/.test(evidenceId))

  return (
    <Card size="small" title={title} style={{ marginTop: 12 }}>
      <List
        size="small"
        dataSource={items}
        renderItem={(item) => (
          <List.Item>
            <div style={{ width: '100%' }}>
              <Paragraph style={{ marginBottom: 8 }}>{item.text}</Paragraph>
              {visibleEvidenceIds(item.evidence_ids).length > 0 && (
                <Space size={[4, 4]} wrap>
                  {visibleEvidenceIds(item.evidence_ids).map((evidenceId) => <Tag key={`${title}-${evidenceId}`}>{evidenceId}</Tag>)}
                </Space>
              )}
            </div>
          </List.Item>
        )}
      />
    </Card>
  )
}

export function AssistantAnswerContent({ content }: { content: string }) {
  return (
    <div className="mc-assistant-answer">
      {content.split(/\r?\n/).map((rawLine, index) => {
        const line = rawLine.trim()
        if (!line) return <div className="mc-assistant-answer-gap" key={`gap-${index}`} />
        if (/^【.+】$/.test(line)) return <div className="mc-assistant-answer-heading" key={`heading-${index}`}>{line.slice(1, -1)}</div>
        if (/^\d+\.\s/.test(line)) return <div className="mc-assistant-answer-step" key={`step-${index}`}>{line}</div>
        if (line.startsWith('- ')) return <div className="mc-assistant-answer-bullet" key={`bullet-${index}`}>{line.slice(2)}</div>
        return <Paragraph key={`paragraph-${index}`}>{line}</Paragraph>
      })}
    </div>
  )
}

export function rangeToMilliseconds(range: string) {
  if (range === '1h') return 60 * 60 * 1000
  if (range === '24h') return 24 * 60 * 60 * 1000
  if (range === '7d') return 7 * 24 * 60 * 60 * 1000
  return 30 * 24 * 60 * 60 * 1000
}

export function parseAbsoluteDateTime(value?: string) {
  if (!value) return 0
  const parsed = Date.parse(value.replace(' ', 'T'))
  return Number.isNaN(parsed) ? 0 : parsed
}

export function filterRowsByTimeRange<T extends { time: string }>(rows: T[], timeRange: string) {
  const datedRows = rows.map((row) => ({ row, timestamp: parseAbsoluteDateTime(row.time) }))
  const timestamps = datedRows.map((item) => item.timestamp).filter((value) => value > 0)
  if (!timestamps.length) return rows
  const cutoff = Math.max(...timestamps) - rangeToMilliseconds(timeRange)
  return datedRows.filter(({ timestamp }) => {
    return timestamp === 0 || timestamp >= cutoff
  }).map(({ row }) => row)
}

export function filterRowsBySourceTimeRange<T extends { time: string; source?: string }>(rows: T[], timeRange: string) {
  const grouped = new Map<string, T[]>()
  rows.forEach((row) => {
    const key = row.source || 'unknown'
    const items = grouped.get(key)
    if (items) items.push(row)
    else grouped.set(key, [row])
  })
  return Array.from(grouped.values()).flatMap((items) => filterRowsByTimeRange(items, timeRange))
}

export type DemoReplayEvent = SecurityEvent & {
  dataset: string
  module_scores?: ModuleScores
  raw_log_ref?: string
  score?: number
}

export type UploadSourceEntry = {
  uid: string
  name: string
  size: number
  file?: File
}

export type ChatItem = {
  role: 'user' | 'assistant'
  content: string
  evidence?: AssistantAnswer['evidence']
  verified?: boolean
  confidence?: number
  structured?: AssistantStructuredResult
  verification?: AssistantVerificationSummary
}

export type AssistantQuickAction = {
  key: string
  label: string
  onClick: () => void
}
