import { useState } from 'react'
import { Badge, Button, Card, Col, Progress, Row, Statistic, Table, Tag, Typography, Upload, message } from 'antd'
import { DeleteOutlined, InboxOutlined, ReloadOutlined } from '@ant-design/icons'
import type { LogSource } from '../mocks/data'
import type { IngestResult } from '../services/ingestion'
import { HelpTitle, PageTitle, type UploadSourceEntry } from './shared'

const { Text } = Typography
const { Dragger } = Upload

type ImportTask = {
  id: string
  name: string
  kind: string
  size: number
  progress: number
  status: 'queued' | 'parsing' | 'indexed' | 'ready' | 'failed'
  result: string
  event_count?: number
  finding_count?: number
  events_per_second?: number
}

function formatBytes(bytes: number) {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

function inferSourceKind(filename: string) {
  const extension = filename.split('.').pop()?.toLowerCase()
  if (!extension) return 'FILE'
  if (extension === 'evtx') return 'EVTX'
  if (extension === 'jsonl') return 'JSONL'
  if (extension === 'json') return 'JSON'
  if (extension === 'csv') return 'CSV'
  if (extension === 'log' || extension === 'txt') return 'LOG'
  return extension.toUpperCase()
}

export default function SourcesPage({
  sources,
  onDeleteSource,
  onRefresh,
  onImportFile,
}: {
  sources: LogSource[]
  onDeleteSource: (sourceId: string) => Promise<void>
  onRefresh: () => Promise<void>
  onImportFile: (file: UploadSourceEntry) => Promise<IngestResult>
}) {
  const [refreshing, setRefreshing] = useState(false)
  const [deletingSourceId, setDeletingSourceId] = useState('')
  const [queue, setQueue] = useState<UploadSourceEntry[]>([])
  const [tasks, setTasks] = useState<ImportTask[]>([])

  const refresh = async () => {
    setRefreshing(true)
    try {
      await onRefresh()
    } finally {
      setRefreshing(false)
    }
  }

  const removeSource = async (sourceId: string) => {
    setDeletingSourceId(sourceId)
    try {
      await onDeleteSource(sourceId)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '删除数据源失败。')
    } finally {
      setDeletingSourceId('')
    }
  }

  const columns = [
    { title: '日志源', dataIndex: 'name', key: 'name', render: (value: string) => <Text strong>{value}</Text> },
    { title: '接入点', dataIndex: 'path', key: 'path', render: (value: string) => <Text code>{value}</Text> },
    { title: '类型', dataIndex: 'kind', key: 'kind', render: (value: string) => <Tag>{value}</Tag> },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (value: LogSource['status']) => (
        <Badge status={value === 'online' ? 'success' : value === 'warning' ? 'warning' : 'error'} text={value === 'online' ? '在线' : value === 'warning' ? '延迟' : '离线'} />
      ),
    },
    { title: '最后读取', dataIndex: 'lastRead', key: 'lastRead' },
    { title: '数据量', dataIndex: 'size', key: 'size' },
  ]

  const taskColumns = [
    { title: '任务', dataIndex: 'name', key: 'name', render: (value: string) => <Text strong>{value}</Text> },
    { title: '类型', dataIndex: 'kind', key: 'kind', width: 96, render: (value: string) => <Tag>{value}</Tag> },
    { title: '大小', dataIndex: 'size', key: 'size', width: 110, render: (value: number) => formatBytes(value) },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      width: 180,
      render: (value: number, record: ImportTask) => (
        <Progress
          percent={value}
          size="small"
          status={record.status === 'failed' ? 'exception' : record.status === 'ready' ? 'success' : record.status === 'indexed' ? 'active' : 'normal'}
        />
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (value: ImportTask['status']) => (
        <Badge
          status={value === 'failed' ? 'error' : value === 'ready' ? 'success' : value === 'indexed' ? 'processing' : value === 'parsing' ? 'warning' : 'default'}
          text={value === 'failed' ? '失败' : value === 'ready' ? '已就绪' : value === 'indexed' ? '索引中' : value === 'parsing' ? '解析中' : '排队中'}
        />
      ),
    },
    { title: '结果', dataIndex: 'result', key: 'result' },
  ]

  const importFiles = async () => {
    if (!queue.length) {
      message.info('请先选择要上传的日志文件。')
      return
    }
    const selectedFiles = [...queue]
    const queuedTasks = selectedFiles.map((file) => ({
        id: `TASK-${Date.now()}-${file.uid}`,
        name: file.name,
        kind: inferSourceKind(file.name),
        size: file.size,
        progress: 5,
        status: 'queued' as const,
        result: '等待上传到后端',
      }))
    setTasks((current) => [...queuedTasks, ...current])
    setQueue([])
    for (let index = 0; index < selectedFiles.length; index += 1) {
      const file = selectedFiles[index]
      const taskId = queuedTasks[index].id
      setTasks((current) => current.map((task) => task.id === taskId
        ? { ...task, progress: 35, status: 'parsing', result: '后端正在执行 M0-M6 处理链路' }
        : task))
      try {
        const result = await onImportFile(file)
        setTasks((current) => current.map((task) => task.id === taskId
          ? {
              ...task,
              ...result.job,
              id: taskId,
              progress: 100,
              status: 'ready',
              result: `${result.job.result} · 小样本仅作功能验证，不作为吞吐结论`,
            }
          : task))
      } catch (error) {
        setTasks((current) => current.map((task) => task.id === taskId
          ? { ...task, progress: 100, status: 'failed', result: error instanceof Error ? error.message : '上传处理失败' }
          : task))
      }
    }
    message.success(`已完成 ${selectedFiles.length} 个文件的后端导入请求。`)
  }

  const queuedCount = tasks.filter((task) => task.status === 'queued').length
  const runningCount = tasks.filter((task) => task.status === 'parsing' || task.status === 'indexed').length
  const readyCount = tasks.filter((task) => task.status === 'ready').length

  return (
    <>
      <PageTitle title="数据源管理" extra={<Button icon={<ReloadOutlined />} loading={refreshing} onClick={refresh}>刷新</Button>} />
      <Card className="mc-panel" title={<HelpTitle title="文件导入" description="接入新的日志文件。导入后会进行格式识别、解析和索引，不会直接改变既有分析结果。" />}>
        <Dragger
          multiple
          accept=".evtx,.log,.txt,.json,.jsonl,.csv"
          beforeUpload={() => false}
          fileList={queue.map((file) => ({
            uid: file.uid,
            name: file.name,
            size: file.size,
            status: 'done' as const,
          }))}
          onChange={({ fileList }) => {
            setQueue((current) => fileList.map((file) => ({
              uid: file.uid,
              name: file.name,
              size: file.size || 0,
              file: file.originFileObj || current.find((item) => item.uid === file.uid)?.file,
            })))
          }}
          onRemove={(file) => {
            setQueue((current) => current.filter((item) => item.uid !== file.uid))
          }}
        >
          <p className="ant-upload-drag-icon"><InboxOutlined /></p>
          <p className="ant-upload-text">拖拽或选择日志文件</p>
          <p className="ant-upload-hint">支持 EVTX / LOG / JSON / JSONL / CSV</p>
        </Dragger>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginTop: 12, flexWrap: 'wrap' }}>
          <Text type="secondary">日志文件将上传至后端并执行 M0-M6 检测流程。</Text>
          <Button type="primary" onClick={() => { void importFiles() }}>上传并执行 M0-M6</Button>
        </div>
      </Card>
      <Row gutter={[12, 12]} className="mc-summary-row">
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="排队中" value={queuedCount} /></Card></Col>
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="处理中" value={runningCount} /></Card></Col>
        <Col xs={12} md={8}><Card className="mc-summary-card"><Statistic title="已就绪" value={readyCount} /></Card></Col>
      </Row>
      <Card className="mc-panel" title={<HelpTitle title="导入任务" description="显示每个日志源的排队、解析、索引和就绪状态。" />}>
        <Table rowKey="id" columns={taskColumns} dataSource={tasks} pagination={false} locale={{ emptyText: '当前没有导入任务。' }} scroll={{ x: 920 }} />
      </Card>
      <Card className="mc-queue-card">
        <Table
          rowKey="id"
          columns={[...columns, {
            title: '操作',
            key: 'actions',
            width: 90,
            render: (_: unknown, row: LogSource) => row.id.startsWith('UPLOAD-')
              ? <Button danger type="text" icon={<DeleteOutlined />} loading={deletingSourceId === row.id} onClick={() => { void removeSource(row.id) }}>删除</Button>
              : <Text type="secondary">系统源</Text>,
          }]}
          dataSource={sources}
          pagination={false}
          scroll={{ x: 960 }}
        />
      </Card>
    </>
  )
}
