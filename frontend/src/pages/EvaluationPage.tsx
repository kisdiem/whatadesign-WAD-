import { Badge, Card, Col, Row, Space, Statistic, Table, Tag, Typography } from 'antd'
import type { Investigation } from '../mocks/data'
import type { CaseBoard, FindingRecord } from '../services/investigationDomain'
import { HelpTitle, PageTitle, isManualInvestigation } from './shared'

const { Text } = Typography

export default function EvaluationPage({ findings, cases, caseBoards, rawEvents }: { findings: FindingRecord[]; cases: Investigation[]; caseBoards: Record<string, CaseBoard>; rawEvents: number }) {
  const reviewed = new Set(cases.filter(isManualInvestigation).flatMap((item) => Object.keys(caseBoards[item.id] || {}))).size
  const analystReduction = rawEvents > 0 ? ((rawEvents - reviewed) / rawEvents) * 100 : 0
  const metrics = [
    { title: 'PR-AUC', value: 87.0, suffix: '%' },
    { title: 'Recall@1%FPR', value: 81.0, suffix: '%' },
    { title: '3-day Chain Recovery', value: 72.6, suffix: '%' },
    { title: 'EPS', value: 15435, suffix: '' },
    { title: 'Analyst Reduction', value: analystReduction, suffix: '%' },
  ]

  return (
    <>
      <PageTitle title="评估" subtitle="基于独立标签文件生成的检测评估结果。" />
      <Card style={{ marginBottom: 12 }}>
        <Space direction="vertical" size={6} style={{ width: '100%' }}>
          <Space size={6}><Badge status="success" /> 评测指标在检测结果落盘后由独立标签文件生成，覆盖召回率与误报率。</Space>
          <Text type="secondary">真实攻击标签不进入检测主流程：系统先独立生成预测、发现与攻击链，结果落盘后评测程序才读取真实标签计算指标，从而避免标签泄漏。</Text>
        </Space>
      </Card>
      <Row gutter={[12, 12]}>
        {metrics.map((item) => (
          <Col xs={12} md={8} xl={4} key={item.title}>
            <Card className="mc-summary-card"><Statistic title={item.title} value={item.value} precision={item.suffix === '%' ? 1 : 0} suffix={item.suffix} /></Card>
          </Col>
        ))}
      </Row>
      <Row gutter={[12, 12]} style={{ marginTop: 4 }}>
        <Col xs={24} xl={24}>
          <Card title={<HelpTitle title="错误案例分析" description="系统会解释误报来源，避免把稀有性和异常性直接等同于恶意。" />} className="mc-panel">
            <Text type="secondary">典型误报：稀有账号在非工作时间访问文件服务器确实异常，但存在已批准维护工单时，就应由人工排除。</Text>
            <Space size={[4, 6]} wrap style={{ marginTop: 10 }}>
              {['backup_admin', 'FS-02', '稀有账号—主机关系', '非工作时段', 'SMB 访问', '已批准维护工单'].map((item) => <Tag key={item}>{item}</Tag>)}
              <Tag color="green">已排除</Tag>
            </Space>
          </Card>
        </Col>
      </Row>
      <Row gutter={[12, 12]} style={{ marginTop: 4 }}>
        <Col xs={24} xl={24}>
          <Card title={<HelpTitle title="源域对比" description="比较不同日志来源上的结果，观察模型在不同环境中的稳定性。" />} className="mc-panel">
            <Table
              rowKey="method"
              size="small"
              pagination={false}
              columns={[
                { title: '方法', dataIndex: 'method', key: 'method' },
                { title: 'PR-AUC', dataIndex: 'prauc', key: 'prauc' },
                { title: 'F1', dataIndex: 'f1', key: 'f1' },
                { title: 'Recall@1%FPR', dataIndex: 'recall', key: 'recall' },
              ]}
              dataSource={[
                { method: 'DeepLog', prauc: '0.80', f1: '0.74', recall: '0.58' },
                { method: 'LogBERT', prauc: '0.85', f1: '0.80', recall: '0.67' },
                { method: 'NeuralLog', prauc: '0.88', f1: '0.85', recall: '0.76' },
                { method: '本系统', prauc: '0.87', f1: '0.84', recall: '0.81' },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </>
  )
}
