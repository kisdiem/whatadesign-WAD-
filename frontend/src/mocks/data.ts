export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type WindowStatus = 'new' | 'reviewing' | 'investigating' | 'ignored' | 'closed'

export interface SecurityEvent {
  id: string
  time: string
  action: string
  actor?: string
  host?: string
  process?: string
  ip?: string
  source: string
  raw: string
  confidence: number
}

export interface AnomalyWindow {
  id: string
  title: string
  severity: Severity
  score: number
  start: string
  end: string
  status: WindowStatus
  eventCount: number
  entities: string[]
  hosts: string[]
  sourceTypes: string[]
  summary: string
  events: SecurityEvent[]
}

export interface Investigation {
  id: string
  title: string
  severity: Severity
  status: 'investigating' | 'contained' | 'closed'
  windowIds: string[]
  owner: string
  createdAt: string
  summary: string
}

export interface LogSource {
  id: string
  name: string
  path: string
  kind: string
  status: 'online' | 'warning' | 'offline'
  size: string
  lastRead: string
}

export interface KnowledgeDoc {
  id: string
  name: string
  category: string
  kind: string
  status: 'indexed' | 'indexing' | 'failed'
  chunks: number
  updatedAt: string
}

export const overviewSeries = [
  { time: '00:00', logs: 84000, anomalies: 8 },
  { time: '02:00', logs: 72000, anomalies: 5 },
  { time: '04:00', logs: 69000, anomalies: 4 },
  { time: '06:00', logs: 92000, anomalies: 9 },
  { time: '08:00', logs: 138000, anomalies: 18 },
  { time: '10:00', logs: 176000, anomalies: 24 },
  { time: '12:00', logs: 164000, anomalies: 17 },
  { time: '14:00', logs: 181000, anomalies: 31 },
  { time: '16:00', logs: 215000, anomalies: 42 },
  { time: '18:00', logs: 193000, anomalies: 37 },
  { time: '20:00', logs: 221000, anomalies: 51 },
  { time: '22:00', logs: 168000, anomalies: 28 },
]

export const anomalyTypeStats = [
  { name: '认证异常', value: 82 },
  { name: '进程执行', value: 61 },
  { name: '网络连接', value: 43 },
  { name: '文件访问', value: 31 },
  { name: '未知语义', value: 18 },
]

export const sourceHeatmap = {
  hours: ['00', '04', '08', '12', '16', '20'],
  sources: ['Windows EVTX', 'Linux Audit', 'Firewall', 'Network Flow', 'EDR'],
  values: [
    [0, 0, 18], [1, 0, 22], [2, 0, 38], [3, 0, 57], [4, 0, 91], [5, 0, 43],
    [0, 1, 12], [1, 1, 17], [2, 1, 21], [3, 1, 35], [4, 1, 54], [5, 1, 26],
    [0, 2, 21], [1, 2, 31], [2, 2, 56], [3, 2, 88], [4, 2, 93], [5, 2, 46],
    [0, 3, 29], [1, 3, 34], [2, 3, 63], [3, 3, 97], [4, 3, 76], [5, 3, 51],
    [0, 4, 13], [1, 4, 18], [2, 4, 42], [3, 4, 89], [4, 4, 69], [5, 4, 33],
  ],
}

const commonEvents: SecurityEvent[] = [
  {
    id: 'EVT-10031', time: '03:21:14', action: 'LOGIN', actor: 'Alice', host: 'HOST-07', source: 'Windows EVTX', confidence: 0.96,
    raw: 'EventID=4624 AccountName=Alice Workstation=HOST-07 LogonType=3 Status=Success',
  },
  {
    id: 'EVT-10032', time: '03:22:03', action: 'PROCESS_START', actor: 'Alice', host: 'HOST-07', process: 'powershell.exe', source: 'EDR', confidence: 0.94,
    raw: 'User=Alice Host=HOST-07 Process=powershell.exe Parent=explorer.exe Integrity=High',
  },
  {
    id: 'EVT-10033', time: '03:23:18', action: 'NETWORK_CONNECT', host: 'HOST-07', process: 'powershell.exe', ip: '10.2.3.7', source: 'Firewall', confidence: 0.91,
    raw: 'src=HOST-07 process=powershell.exe dst=10.2.3.7 dpt=443 action=allow',
  },
]

export const anomalyWindows: AnomalyWindow[] = [
  {
    id: 'WIN-20260809-0321', title: '可疑 PowerShell 执行', severity: 'high', score: 0.913, start: '03:21:14', end: '03:26:14', status: 'new',
    eventCount: 23, entities: ['Alice', 'powershell.exe', '10.2.3.7', 'HOST-07'], hosts: ['HOST-07'], sourceTypes: ['Windows EVTX', 'EDR', 'Firewall'],
    summary: '同一用户完成网络登录后，以高权限启动 PowerShell 并建立外联。', events: commonEvents,
  },
  {
    id: 'WIN-20260809-0935', title: '跨主机身份连续行为', severity: 'high', score: 0.887, start: '09:35:02', end: '09:41:38', status: 'investigating',
    eventCount: 18, entities: ['Alice', 'cmd.exe', 'HOST-12', '10.2.8.19'], hosts: ['HOST-12'], sourceTypes: ['Windows EVTX', 'EDR'],
    summary: 'Alice 在约 6 小时后出现在第二台主机，实体与行为链存在长时关联。',
    events: [
      { id: 'EVT-10172', time: '09:35:02', action: 'LOGIN', actor: 'Alice', host: 'HOST-12', source: 'Windows EVTX', confidence: 0.95, raw: 'EventID=4624 AccountName=Alice Workstation=HOST-12 Status=Success' },
      { id: 'EVT-10175', time: '09:37:49', action: 'PROCESS_START', actor: 'Alice', host: 'HOST-12', process: 'cmd.exe', source: 'EDR', confidence: 0.92, raw: 'User=Alice Host=HOST-12 Process=cmd.exe Parent=services.exe' },
    ],
  },
  {
    id: 'WIN-20260809-1148', title: '异常认证失败聚集', severity: 'medium', score: 0.721, start: '11:48:00', end: '11:53:00', status: 'reviewing',
    eventCount: 41, entities: ['svc_backup', 'HOST-03', '172.16.2.44'], hosts: ['HOST-03'], sourceTypes: ['Windows EVTX'],
    summary: '短窗口内出现高频认证失败，尚未观察到后续高风险进程或文件行为。',
    events: [{ id: 'EVT-10241', time: '11:48:03', action: 'LOGIN_FAILURE', actor: 'svc_backup', host: 'HOST-03', ip: '172.16.2.44', source: 'Windows EVTX', confidence: 0.89, raw: 'EventID=4625 AccountName=svc_backup Workstation=HOST-03 Status=Failure' }],
  },
  {
    id: 'WIN-20260809-1422', title: '敏感文件访问与外联', severity: 'critical', score: 0.948, start: '14:22:11', end: '14:29:45', status: 'new',
    eventCount: 29, entities: ['Alice', 'HOST-18', 'archive.exe', 'sensitive.dat'], hosts: ['HOST-18'], sourceTypes: ['Linux Audit', 'Network Flow', 'EDR'],
    summary: '用户实体再次出现，并在敏感文件访问后产生新的外部网络连接。',
    events: [{ id: 'EVT-10418', time: '14:22:11', action: 'FILE_READ', actor: 'Alice', host: 'HOST-18', process: 'archive.exe', source: 'Linux Audit', confidence: 0.93, raw: 'user=Alice host=HOST-18 process=archive.exe op=read path=/data/sensitive.dat result=success' }],
  },
]

export const investigations: Investigation[] = [
  {
    id: 'CASE-001', title: '疑似横向移动与数据访问', severity: 'critical', status: 'investigating', owner: 'Analyst-01', createdAt: '2026-08-09 09:44',
    windowIds: ['WIN-20260809-0321', 'WIN-20260809-0935', 'WIN-20260809-1422'],
    summary: '同一用户在多个主机与长时间窗口中持续出现，行为从登录、命令执行延伸至敏感文件访问。',
  },
  {
    id: 'CASE-002', title: '服务账号异常认证', severity: 'medium', status: 'investigating', owner: 'Analyst-02', createdAt: '2026-08-09 12:02',
    windowIds: ['WIN-20260809-1148'], summary: '持续观察服务账号失败认证是否出现后续执行行为。',
  },
]

export const logSources: LogSource[] = [
  { id: 'SRC-01', name: 'Windows Server Logs', path: 'C:\\SecurityLogs\\Windows\\', kind: 'EVTX', status: 'online', size: '12.7 GB', lastRead: '05:27:13' },
  { id: 'SRC-02', name: 'Linux Audit', path: '/var/log/audit/', kind: 'LOG', status: 'online', size: '4.2 GB', lastRead: '05:27:11' },
  { id: 'SRC-03', name: 'Firewall', path: '/data/firewall/', kind: 'CSV', status: 'online', size: '21.4 GB', lastRead: '05:27:09' },
  { id: 'SRC-04', name: 'EDR Backup', path: '/mnt/edr/', kind: 'JSONL', status: 'warning', size: '8.9 GB', lastRead: '05:19:41' },
]

export const knowledgeDocs: KnowledgeDoc[] = [
  { id: 'KB-01', name: 'Windows_Event_ID.md', category: '运维知识', kind: 'Markdown', status: 'indexed', chunks: 317, updatedAt: '2026-08-09' },
  { id: 'KB-02', name: 'Network_Architecture.pdf', category: '组织环境', kind: 'PDF', status: 'indexed', chunks: 84, updatedAt: '2026-08-08' },
  { id: 'KB-03', name: 'Asset_List.csv', category: '组织环境', kind: 'CSV', status: 'indexed', chunks: 126, updatedAt: '2026-08-09' },
  { id: 'KB-04', name: 'MITRE_ATTACK.md', category: '攻击知识', kind: 'Markdown', status: 'indexed', chunks: 503, updatedAt: '2026-08-07' },
  { id: 'KB-05', name: 'CASE-2026-07.md', category: '历史调查', kind: 'Markdown', status: 'indexing', chunks: 0, updatedAt: '2026-08-09' },
]

export const assistantSuggestions = [
  '为什么 Alice 被判定为高风险？',
  '总结 CASE-001 的关键证据',
  '哪些异常窗口可能属于同一攻击链？',
  'HOST-07 最近 24 小时有哪些可疑行为？',
]
