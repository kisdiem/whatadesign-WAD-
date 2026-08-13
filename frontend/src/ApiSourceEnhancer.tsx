import { useEffect, useState } from 'react'
import { Alert, Button, Card, Col, Form, Input, Row, Select, Space, Typography, message } from 'antd'
import { ApiOutlined, CheckCircleOutlined, SaveOutlined } from '@ant-design/icons'
import { createPortal } from 'react-dom'
import { useLocation } from 'react-router-dom'
import {
  createApiLogSource,
  testApiLogSource,
  type ApiLogSourceConfig,
} from './services/api'

const { Text } = Typography
const STORAGE_KEY = 'wad-api-source-config'

function loadSavedConfig(): Partial<ApiLogSourceConfig> {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY)
    return value ? JSON.parse(value) as Partial<ApiLogSourceConfig> : {}
  } catch {
    return {}
  }
}

export default function ApiSourceEnhancer() {
  const location = useLocation()
  const [host, setHost] = useState<HTMLDivElement | null>(null)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null)
  const [form] = Form.useForm<ApiLogSourceConfig>()

  useEffect(() => {
    if (!location.pathname.startsWith('/sources')) {
      setHost(null)
      return
    }

    const content = document.querySelector('.mc-content')
    const sourceAlert = content?.querySelector('.mc-source-alert')
    if (!content || !sourceAlert) return

    let slot = document.getElementById('api-source-config-slot') as HTMLDivElement | null
    if (!slot) {
      slot = document.createElement('div')
      slot.id = 'api-source-config-slot'
      sourceAlert.insertAdjacentElement('afterend', slot)
    }
    setHost(slot)

    return () => slot?.remove()
  }, [location.pathname])

  useEffect(() => {
    if (!host) return
    const saved = loadSavedConfig()
    form.setFieldsValue({
      name: saved.name || '外部安全日志 API',
      endpoint: saved.endpoint || '',
      method: saved.method || 'GET',
      authType: saved.authType || 'bearer',
      token: '',
      pollInterval: saved.pollInterval || 60,
    })
  }, [form, host])

  const getValues = async () => form.validateFields()

  const testConnection = async () => {
    try {
      const values = await getValues()
      setTesting(true)
      const result = await testApiLogSource(values)
      setTestResult(result)
      if (result.ok) message.success(result.message)
      else message.warning(result.message)
    } catch {
      // Ant Design displays validation errors on the corresponding fields.
    } finally {
      setTesting(false)
    }
  }

  const saveConfig = async () => {
    try {
      const values = await getValues()
      setSaving(true)
      await createApiLogSource(values)
      window.dispatchEvent(new CustomEvent('wad-log-sources-updated'))
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify({
        name: values.name,
        endpoint: values.endpoint,
        method: values.method,
        authType: values.authType,
        pollInterval: values.pollInterval,
      }))
      message.success('API 接入配置已保存')
    } catch {
      // Validation and request errors are surfaced by the form or message layer.
    } finally {
      setSaving(false)
    }
  }

  if (!host) return null

  return createPortal(
    <Card
      title={<Space><ApiOutlined />API 接入</Space>}
      className="mc-panel"
      extra={<Text type="secondary">用于接入 EDR、云平台、安全设备或第三方日志服务</Text>}
    >
      <Form form={form} layout="vertical">
        <Row gutter={12}>
          <Col xs={24} lg={8}>
            <Form.Item name="name" label="接入名称" rules={[{ required: true, message: '请输入接入名称' }]}>
              <Input placeholder="例如：CrowdStrike EDR API" />
            </Form.Item>
          </Col>
          <Col xs={24} lg={16}>
            <Form.Item
              name="endpoint"
              label="API 地址"
              rules={[
                { required: true, message: '请输入 API 地址' },
                { type: 'url', message: '请输入完整的 http:// 或 https:// 地址' },
              ]}
            >
              <Input placeholder="https://security.example.com/api/v1/events" />
            </Form.Item>
          </Col>
        </Row>

        <Row gutter={12}>
          <Col xs={24} md={6}>
            <Form.Item name="method" label="请求方式">
              <Select options={[{ value: 'GET', label: 'GET' }, { value: 'POST', label: 'POST' }]} />
            </Form.Item>
          </Col>
          <Col xs={24} md={6}>
            <Form.Item name="authType" label="认证方式">
              <Select options={[{ value: 'bearer', label: 'Bearer Token' }, { value: 'api-key', label: 'API Key' }, { value: 'none', label: '无需认证' }]} />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item shouldUpdate noStyle>
              {({ getFieldValue }) => getFieldValue('authType') === 'none' ? null : (
                <Form.Item name="token" label="Token / API Key">
                  <Input.Password autoComplete="new-password" placeholder="仅用于提交接入配置，不写入浏览器持久存储" />
                </Form.Item>
              )}
            </Form.Item>
          </Col>
          <Col xs={24} md={4}>
            <Form.Item name="pollInterval" label="轮询间隔（秒）" rules={[{ required: true }]}>
              <Input type="number" min={10} />
            </Form.Item>
          </Col>
        </Row>

        {testResult && (
          <Alert
            style={{ marginBottom: 14 }}
            type={testResult.ok ? 'success' : 'warning'}
            showIcon
            message={testResult.message}
          />
        )}

        <Space>
          <Button icon={<CheckCircleOutlined />} loading={testing} onClick={testConnection}>测试连接</Button>
          <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={saveConfig}>保存 API 接入</Button>
        </Space>
      </Form>
    </Card>,
    host,
  )
}
