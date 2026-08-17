import generatedDataset from './generatedDataset.json'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
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
  moduleScores?: Partial<Record<'M0' | 'M1' | 'M2' | 'M3' | 'M4' | 'M5' | 'M6', number>>
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
  queueStatus?: 'auto_observe' | 'manual_review' | 'resolved' | 'suppressed' | 'merged'
  escalationScore?: number
  escalationReasons?: string[]
  decisionSource?: 'system' | 'analyst'
  decisionAt?: string
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

const e = (
  id: string,
  time: string,
  action: string,
  source: string,
  extra: Partial<SecurityEvent> = {},
): SecurityEvent => ({
  id,
  time,
  action,
  source,
  raw: `${time} ${action}`,
  confidence: 0.9,
  ...extra,
})

const baseAnomalyWindows: AnomalyWindow[] = [
  {
    id: 'WIN-20260803-1042', title: '外部侦察与目录探测', severity: 'medium', score: 0.701, start: '2026-08-03 10:42:13', end: '2026-08-03 10:58:44', status: 'reviewing',
    eventCount: 53, entities: ['WEB-01', '185.199.110.42', '/wp-admin', 'dirb'], hosts: ['WEB-01'], sourceTypes: ['WAF', 'Suricata', 'Wazuh'],
    summary: 'Web 服务在 7 天窗口内出现高频目录探测与异常请求路径访问。',
    events: [
      e('EVT-09001', '2026-08-03 10:42:13', 'DIR_SCAN', 'WAF', { host: 'WEB-01', ip: '185.199.110.42' }),
      e('EVT-09002', '2026-08-03 10:49:27', 'RECON_BURST', 'Suricata', { host: 'WEB-01', ip: '185.199.110.42' }),
    ],
  },
  {
    id: 'WIN-20260805-1854', title: '可疑 WebShell 落地', severity: 'high', score: 0.889, start: '2026-08-05 18:54:08', end: '2026-08-05 19:07:42', status: 'new',
    eventCount: 27, entities: ['WEB-01', 'www-data', 'shell.php', '185.199.110.42'], hosts: ['WEB-01'], sourceTypes: ['Wazuh', 'WAF', 'Linux Audit'],
    summary: '目录探测两天后，Web 目录出现新脚本文件并伴随异常执行行为。',
    events: [
      e('EVT-09121', '2026-08-05 18:54:08', 'FILE_CREATE', 'Wazuh', { actor: 'www-data', host: 'WEB-01', process: 'php-fpm' }),
      e('EVT-09122', '2026-08-05 19:02:31', 'REMOTE_EXECUTION', 'Linux Audit', { actor: 'www-data', host: 'WEB-01', process: 'shell.php', ip: '185.199.110.42' }),
    ],
  },
  {
    id: 'WIN-20260809-0112', title: '异常远程登录尝试', severity: 'medium', score: 0.734, start: '01:12:08', end: '01:18:42', status: 'reviewing',
    eventCount: 37, entities: ['svc_ops', 'HOST-02', '172.16.4.22'], hosts: ['HOST-02'], sourceTypes: ['Windows EVTX', 'Firewall'],
    summary: '短时间内连续出现远程登录失败与来源地址切换。',
    events: [
      e('EVT-10001', '01:12:08', 'LOGIN_FAILURE', 'Windows EVTX', { actor: 'svc_ops', host: 'HOST-02', ip: '172.16.4.22' }),
      e('EVT-10002', '01:15:14', 'LOGIN_FAILURE', 'Windows EVTX', { actor: 'svc_ops', host: 'HOST-02', ip: '172.16.4.31' }),
    ],
  },
  {
    id: 'WIN-20260809-0248', title: '可疑端口扫描', severity: 'low', score: 0.612, start: '02:48:11', end: '02:56:30', status: 'new',
    eventCount: 64, entities: ['HOST-05', '10.1.7.19'], hosts: ['HOST-05'], sourceTypes: ['Firewall', 'Network Flow'],
    summary: '单一源地址在短时段内访问多个非常用端口。',
    events: [
      e('EVT-10015', '02:48:11', 'NETWORK_CONNECT', 'Firewall', { host: 'HOST-05', ip: '10.1.7.19' }),
      e('EVT-10016', '02:52:49', 'PORT_BURST', 'Network Flow', { host: 'HOST-05', ip: '10.1.7.19' }),
    ],
  },
  {
    id: 'WIN-20260809-0321', title: '可疑 PowerShell 执行', severity: 'high', score: 0.913, start: '03:21:14', end: '03:26:14', status: 'new',
    eventCount: 23, entities: ['Alice', 'powershell.exe', '10.2.3.7', 'HOST-07'], hosts: ['HOST-07'], sourceTypes: ['Windows EVTX', 'EDR', 'Firewall'],
    summary: '同一用户完成网络登录后，以高权限启动 PowerShell 并建立外联。',
    events: [
      e('EVT-10031', '03:21:14', 'LOGIN', 'Windows EVTX', { actor: 'Alice', host: 'HOST-07', confidence: 0.96 }),
      e('EVT-10032', '03:22:03', 'PROCESS_START', 'EDR', { actor: 'Alice', host: 'HOST-07', process: 'powershell.exe', confidence: 0.94 }),
      e('EVT-10033', '03:23:18', 'NETWORK_CONNECT', 'Firewall', { host: 'HOST-07', process: 'powershell.exe', ip: '10.2.3.7', confidence: 0.91 }),
    ],
  },
  {
    id: 'WIN-20260809-0516', title: '计划任务异常创建', severity: 'medium', score: 0.768, start: '05:16:25', end: '05:24:12', status: 'new',
    eventCount: 19, entities: ['SYSTEM', 'schtasks.exe', 'HOST-09'], hosts: ['HOST-09'], sourceTypes: ['Windows EVTX', 'EDR'],
    summary: '系统账户创建新的计划任务并调用非常用命令。',
    events: [
      e('EVT-10051', '05:16:25', 'TASK_CREATE', 'Windows EVTX', { actor: 'SYSTEM', host: 'HOST-09' }),
      e('EVT-10052', '05:19:03', 'PROCESS_START', 'EDR', { host: 'HOST-09', process: 'schtasks.exe' }),
    ],
  },
  {
    id: 'WIN-20260809-0744', title: '未知进程异常外联', severity: 'high', score: 0.861, start: '07:44:38', end: '07:53:06', status: 'new',
    eventCount: 28, entities: ['syncsvc.exe', 'HOST-11', '45.77.21.19'], hosts: ['HOST-11'], sourceTypes: ['EDR', 'Network Flow', 'Firewall'],
    summary: '新出现进程持续访问外部地址并绕过常用代理路径。',
    events: [
      e('EVT-10074', '07:44:38', 'PROCESS_START', 'EDR', { host: 'HOST-11', process: 'syncsvc.exe' }),
      e('EVT-10075', '07:47:10', 'NETWORK_CONNECT', 'Network Flow', { host: 'HOST-11', process: 'syncsvc.exe', ip: '45.77.21.19' }),
    ],
  },
  {
    id: 'WIN-20260809-0935', title: '跨主机身份连续行为', severity: 'high', score: 0.887, start: '09:35:02', end: '09:41:38', status: 'investigating',
    eventCount: 18, entities: ['Alice', 'cmd.exe', 'HOST-12', '10.2.8.19'], hosts: ['HOST-12'], sourceTypes: ['Windows EVTX', 'EDR'],
    summary: 'Alice 在约 6 小时后出现在第二台主机，实体与行为链存在长时关联。',
    events: [
      e('EVT-10172', '09:35:02', 'LOGIN', 'Windows EVTX', { actor: 'Alice', host: 'HOST-12', confidence: 0.95 }),
      e('EVT-10175', '09:37:49', 'PROCESS_START', 'EDR', { actor: 'Alice', host: 'HOST-12', process: 'cmd.exe', confidence: 0.92 }),
    ],
  },
  {
    id: 'WIN-20260809-0938', title: '命令执行密集升高', severity: 'medium', score: 0.779, start: '09:38:20', end: '09:45:16', status: 'new',
    eventCount: 46, entities: ['HOST-12', 'cmd.exe', 'whoami.exe'], hosts: ['HOST-12'], sourceTypes: ['EDR', 'Windows EVTX'],
    summary: '与相邻异常窗口重叠，命令执行频率明显升高。',
    events: [
      e('EVT-10181', '09:38:20', 'PROCESS_START', 'EDR', { host: 'HOST-12', process: 'whoami.exe' }),
      e('EVT-10182', '09:41:12', 'PROCESS_START', 'EDR', { host: 'HOST-12', process: 'cmd.exe' }),
    ],
  },
  {
    id: 'WIN-20260809-1022', title: '异常 DNS 请求聚集', severity: 'low', score: 0.648, start: '10:22:04', end: '10:31:52', status: 'reviewing',
    eventCount: 73, entities: ['HOST-14', 'dns-cache', '10.10.3.8'], hosts: ['HOST-14'], sourceTypes: ['Network Flow'],
    summary: '同一主机出现高频、短周期 DNS 请求。',
    events: [e('EVT-10203', '10:22:04', 'DNS_BURST', 'Network Flow', { host: 'HOST-14', ip: '10.10.3.8' })],
  },
  {
    id: 'WIN-20260809-1148', title: '异常认证失败聚集', severity: 'medium', score: 0.721, start: '11:48:00', end: '11:53:00', status: 'reviewing',
    eventCount: 41, entities: ['svc_backup', 'HOST-03', '172.16.2.44'], hosts: ['HOST-03'], sourceTypes: ['Windows EVTX'],
    summary: '短窗口内出现高频认证失败，尚未观察到后续高风险进程或文件行为。',
    events: [e('EVT-10241', '11:48:03', 'LOGIN_FAILURE', 'Windows EVTX', { actor: 'svc_backup', host: 'HOST-03', ip: '172.16.2.44', confidence: 0.89 })],
  },
  {
    id: 'WIN-20260809-1236', title: '脚本解释器链式启动', severity: 'high', score: 0.902, start: '12:36:17', end: '12:44:09', status: 'new',
    eventCount: 32, entities: ['wscript.exe', 'powershell.exe', 'HOST-16'], hosts: ['HOST-16'], sourceTypes: ['EDR', 'Windows EVTX'],
    summary: '脚本解释器连续拉起 PowerShell，执行链偏离基线。',
    events: [
      e('EVT-10301', '12:36:17', 'PROCESS_START', 'EDR', { host: 'HOST-16', process: 'wscript.exe' }),
      e('EVT-10302', '12:37:41', 'PROCESS_START', 'EDR', { host: 'HOST-16', process: 'powershell.exe' }),
    ],
  },
  {
    id: 'WIN-20260808-0826', title: '提权与凭据访问尝试', severity: 'high', score: 0.918, start: '2026-08-08 08:26:33', end: '2026-08-08 08:40:15', status: 'new',
    eventCount: 34, entities: ['Alice', 'HOST-16', 'lsass.exe', 'procdump.exe'], hosts: ['HOST-16'], sourceTypes: ['EDR', 'Windows EVTX', 'Wazuh'],
    summary: '与脚本解释器行为相邻，出现提权后访问高价值进程的迹象。',
    events: [
      e('EVT-10381', '2026-08-08 08:26:33', 'PRIVILEGE_ESCALATION', 'EDR', { actor: 'Alice', host: 'HOST-16', process: 'powershell.exe' }),
      e('EVT-10382', '2026-08-08 08:34:19', 'CREDENTIAL_ACCESS', 'Wazuh', { actor: 'Alice', host: 'HOST-16', process: 'procdump.exe' }),
    ],
  },
  {
    id: 'WIN-20260809-1422', title: '敏感文件访问与外联', severity: 'critical', score: 0.948, start: '14:22:11', end: '14:29:45', status: 'new',
    eventCount: 29, entities: ['Alice', 'HOST-18', 'archive.exe', 'sensitive.dat'], hosts: ['HOST-18'], sourceTypes: ['Linux Audit', 'Network Flow', 'EDR'],
    summary: '用户实体再次出现，并在敏感文件访问后产生新的外部网络连接。',
    events: [
      e('EVT-10418', '14:22:11', 'FILE_READ', 'Linux Audit', { actor: 'Alice', host: 'HOST-18', process: 'archive.exe', confidence: 0.93 }),
      e('EVT-10419', '14:26:44', 'NETWORK_CONNECT', 'Network Flow', { host: 'HOST-18', process: 'archive.exe', ip: '91.92.18.4' }),
    ],
  },
  {
    id: 'WIN-20260809-1424', title: '压缩进程异常聚集', severity: 'high', score: 0.906, start: '14:24:02', end: '14:31:18', status: 'new',
    eventCount: 36, entities: ['archive.exe', 'HOST-18', '/data/export'], hosts: ['HOST-18'], sourceTypes: ['EDR', 'Linux Audit'],
    summary: '与敏感文件窗口交织，压缩进程短时访问多个目录。',
    events: [e('EVT-10424', '14:24:02', 'PROCESS_BURST', 'EDR', { host: 'HOST-18', process: 'archive.exe' })],
  },
  {
    id: 'WIN-20260809-1427', title: '外联流量突增', severity: 'critical', score: 0.961, start: '14:27:36', end: '14:35:50', status: 'new',
    eventCount: 58, entities: ['HOST-18', '91.92.18.4', '443'], hosts: ['HOST-18'], sourceTypes: ['Network Flow', 'Firewall'],
    summary: '与文件访问和压缩窗口重叠，外联流量持续快速增长。',
    events: [
      e('EVT-10431', '14:27:36', 'NETWORK_BURST', 'Network Flow', { host: 'HOST-18', ip: '91.92.18.4' }),
      e('EVT-10432', '14:30:22', 'NETWORK_CONNECT', 'Firewall', { host: 'HOST-18', ip: '91.92.18.4' }),
    ],
  },
  {
    id: 'WIN-20260809-1606', title: '高权限令牌使用异常', severity: 'medium', score: 0.792, start: '16:06:18', end: '16:13:39', status: 'reviewing',
    eventCount: 21, entities: ['Administrator', 'HOST-21', 'services.exe'], hosts: ['HOST-21'], sourceTypes: ['Windows EVTX', 'EDR'],
    summary: '管理员令牌在非常用服务进程中被使用。',
    events: [e('EVT-10520', '16:06:18', 'TOKEN_USE', 'Windows EVTX', { actor: 'Administrator', host: 'HOST-21', process: 'services.exe' })],
  },
  {
    id: 'WIN-20260809-1818', title: '可疑 SSH 会话', severity: 'high', score: 0.874, start: '18:18:09', end: '18:27:46', status: 'new',
    eventCount: 26, entities: ['ops', 'srv-db-02', '185.42.18.9'], hosts: ['srv-db-02'], sourceTypes: ['Linux Audit', 'Firewall'],
    summary: '运维账户从非常用外部地址建立 SSH 会话。',
    events: [e('EVT-10601', '18:18:09', 'SSH_LOGIN', 'Linux Audit', { actor: 'ops', host: 'srv-db-02', ip: '185.42.18.9' })],
  },
  {
    id: 'WIN-20260809-2002', title: '数据库导出行为异常', severity: 'critical', score: 0.953, start: '20:02:21', end: '20:12:58', status: 'new',
    eventCount: 44, entities: ['dbadmin', 'srv-db-02', 'dump.sql'], hosts: ['srv-db-02'], sourceTypes: ['Linux Audit', 'EDR'],
    summary: '数据库主机出现大规模导出并伴随新文件生成。',
    events: [
      e('EVT-10644', '20:02:21', 'DB_EXPORT', 'Linux Audit', { actor: 'dbadmin', host: 'srv-db-02' }),
      e('EVT-10645', '20:08:34', 'FILE_CREATE', 'EDR', { host: 'srv-db-02', process: 'mysqldump' }),
    ],
  },
  {
    id: 'WIN-20260809-2137', title: '异常服务启动', severity: 'medium', score: 0.754, start: '21:37:05', end: '21:43:40', status: 'new',
    eventCount: 17, entities: ['updater-svc', 'HOST-25', 'sc.exe'], hosts: ['HOST-25'], sourceTypes: ['Windows EVTX', 'EDR'],
    summary: '新服务在非维护窗口启动并创建常驻进程。',
    events: [e('EVT-10710', '21:37:05', 'SERVICE_START', 'Windows EVTX', { host: 'HOST-25', process: 'sc.exe' })],
  },
  {
    id: 'WIN-20260809-2250', title: '异常域名访问', severity: 'low', score: 0.633, start: '22:50:11', end: '22:58:52', status: 'reviewing',
    eventCount: 39, entities: ['HOST-28', 'cdn-update.example'], hosts: ['HOST-28'], sourceTypes: ['Network Flow', 'Firewall'],
    summary: '终端访问低频域名，暂未发现后续执行行为。',
    events: [e('EVT-10752', '22:50:11', 'DNS_QUERY', 'Network Flow', { host: 'HOST-28' })],
  },
  {
    id: 'WIN-20260809-2318', title: '疑似数据外传收尾', severity: 'critical', score: 0.941, start: '2026-08-09 23:18:09', end: '2026-08-09 23:29:41', status: 'new',
    eventCount: 31, entities: ['WEB-01', '185.199.110.42', 'archive.tar.gz'], hosts: ['WEB-01'], sourceTypes: ['Suricata', 'Network Flow', 'Wazuh'],
    summary: '多日 Web 攻击链末端出现归档文件生成与持续外联，具备数据外传特征。',
    events: [
      e('EVT-10811', '2026-08-09 23:18:09', 'ARCHIVE_CREATE', 'Wazuh', { host: 'WEB-01', process: 'tar', ip: '185.199.110.42' }),
      e('EVT-10812', '2026-08-09 23:24:57', 'DATA_EXFIL', 'Suricata', { host: 'WEB-01', ip: '185.199.110.42' }),
    ],
  },
]

const baseInvestigations: Investigation[] = [
  {
    id: 'CASE-001', title: '疑似横向移动与数据访问', severity: 'critical', status: 'investigating', owner: 'Analyst-01', createdAt: '2026-08-09 09:44',
    windowIds: ['WIN-20260809-0321', 'WIN-20260809-0935', 'WIN-20260809-1422', 'WIN-20260809-1424', 'WIN-20260809-1427'],
    summary: '同一用户在多个主机与长时间窗口中持续出现，行为从登录、命令执行延伸至敏感文件访问。',
  },
  {
    id: 'CASE-002', title: '服务账号异常认证', severity: 'medium', status: 'investigating', owner: 'Analyst-02', createdAt: '2026-08-09 12:02',
    windowIds: ['WIN-20260809-0112', 'WIN-20260809-1148'], summary: '持续观察服务账号失败认证是否出现后续执行行为。',
  },
  {
    id: 'CASE-003', title: '多日 Web 入侵与外传链', severity: 'critical', status: 'investigating', owner: 'Analyst-03', createdAt: '2026-08-09 23:32',
    windowIds: ['WIN-20260803-1042', 'WIN-20260805-1854', 'WIN-20260809-2318'], summary: '基于多日告警与主机事件重建 Web 侦察、落地和数据外传的长程链路。',
  },
]

const baseLogSources: LogSource[] = [
  { id: 'SRC-01', name: 'Windows Server Logs', path: 'C:\\SecurityLogs\\Windows\\', kind: 'EVTX', status: 'online', size: '12.7 GB', lastRead: '05:27:13' },
  { id: 'SRC-02', name: 'Linux Audit', path: '/var/log/audit/', kind: 'LOG', status: 'online', size: '4.2 GB', lastRead: '05:27:11' },
  { id: 'SRC-03', name: 'Firewall', path: '/data/firewall/', kind: 'CSV', status: 'online', size: '21.4 GB', lastRead: '05:27:09' },
  { id: 'SRC-04', name: 'EDR Backup', path: '/mnt/edr/', kind: 'JSONL', status: 'warning', size: '8.9 GB', lastRead: '05:19:41' },
  { id: 'SRC-05', name: 'AIT-ADS Event Stream', path: '/datasets/ait-ads/', kind: '事件流', status: 'online', size: '2.9 GB', lastRead: '05:28:04' },
]

const baseKnowledgeDocs: KnowledgeDoc[] = [
  { id: 'KB-01', name: 'Windows_Event_ID.md', category: '运维知识', kind: 'Markdown', status: 'indexed', chunks: 317, updatedAt: '2026-08-09' },
  { id: 'KB-02', name: 'Network_Architecture.pdf', category: '组织环境', kind: 'PDF', status: 'indexed', chunks: 84, updatedAt: '2026-08-08' },
  { id: 'KB-03', name: 'Asset_List.csv', category: '组织环境', kind: 'CSV', status: 'indexed', chunks: 126, updatedAt: '2026-08-09' },
  { id: 'KB-04', name: 'MITRE_ATTACK.md', category: '攻击知识', kind: 'Markdown', status: 'indexed', chunks: 503, updatedAt: '2026-08-07' },
  { id: 'KB-05', name: 'CASE-2026-07.md', category: '历史调查', kind: 'Markdown', status: 'indexing', chunks: 0, updatedAt: '2026-08-09' },
  { id: 'KB-06', name: 'AIT-ADS_Mapping.md', category: '数据集映射', kind: 'Markdown', status: 'indexed', chunks: 96, updatedAt: '2026-08-09' },
]

export const assistantSuggestions = [
  '为什么 Alice 被判定为高风险？',
  '总结 CASE-001 的关键证据',
  '哪些异常窗口可能属于同一攻击链？',
  'HOST-07 最近 24 小时有哪些可疑行为？',
]

function mergeById<T extends { id: string }>(base: T[], extra: T[]): T[] {
  const seen = new Set(base.map((item) => item.id))
  return [...base, ...extra.filter((item) => !seen.has(item.id))]
}

const extension = generatedDataset as unknown as {
  anomalyWindows?: AnomalyWindow[]
  investigations?: Investigation[]
  logSources?: LogSource[]
  knowledgeDocs?: KnowledgeDoc[]
}

function toEpoch(value: string): number {
  return Number.isNaN(Date.parse(value)) ? 0 : Date.parse(value)
}

export const anomalyWindows: AnomalyWindow[] = mergeById(
  baseAnomalyWindows,
  extension.anomalyWindows ?? [],
).sort((a, b) => toEpoch(a.start) - toEpoch(b.start))

export const investigations: Investigation[] = mergeById(
  baseInvestigations,
  extension.investigations ?? [],
).sort((a, b) => toEpoch(a.createdAt) - toEpoch(b.createdAt))

export const logSources: LogSource[] = mergeById(
  baseLogSources,
  extension.logSources ?? [],
)

export const knowledgeDocs: KnowledgeDoc[] = mergeById(
  baseKnowledgeDocs,
  extension.knowledgeDocs ?? [],
)
