const fs = require('fs')
const crypto = require('crypto')
const path = require('path')

const root = path.resolve(__dirname, '..', 'frontend', 'public', 'demo-data', 'APT')
const read = (name) => JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'))
const write = (name, value) => fs.writeFileSync(path.join(root, name), `${JSON.stringify(value, null, 2)}\n`, 'utf8')

const retiredIds = new Set([
  ...Array.from({ length: 10 }, (_, index) => `APT-${String(index + 1).padStart(6, '0')}`),
  ...Array.from({ length: 18 }, (_, index) => `APT-SCRIPT-${String(index + 1).padStart(3, '0')}`),
])
const base = Date.parse('2022-01-24T13:30:00Z')
const source = 'demo/apt_narrative/2022-01-24-management-path.log'

const entities = {
  src: ['ip', '198.51.100.23', 'external_source'],
  firewall: ['host', 'EDGE-FW-01', 'target_device'],
  vpn: ['service', 'ssl-vpn', 'access_service'],
  vpnUser: ['user', 'svc-netops', 'account'],
  ws: ['host', 'ENG-WS-07', 'workstation'],
  app: ['host', 'APP-SRV-03', 'application_server'],
  domain: ['domain', 'CORP.LOCAL', 'domain'],
  router: ['host', 'BR-01', 'network_device'],
  jump: ['host', 'OT-JUMP-01', 'ot_jump_host'],
  scada: ['host', 'SCADA-HIST-01', 'ot_asset'],
  task: ['process', 'WindowsUpdateHealthCheck', 'scheduled_task'],
  proxy: ['process', 'earthworm', 'proxy_process'],
  tool: ['process', 'wmic/powershell', 'discovery_tool'],
}

const steps = [
  { id: 'APT-SCRIPT-001', sec: 0, title: '公网管理接口扫描', technique: 'T1046', host: 'EDGE-FW-01', raw: 'ids: external source 198.51.100.23 scanned exposed management endpoints on EDGE-FW-01; service=ssl-vpn, result=blocked', level: 'high', score: 0.88, reasons: ['公网源地址', '集中扫描管理接口'], use: ['src', 'firewall', 'vpn'] },
  { id: 'APT-SCRIPT-002', sec: 28, title: '管理接口异常命令执行', technique: 'T1190', host: 'EDGE-FW-01', raw: 'fortigate[412]: admin_api request from 198.51.100.23; endpoint=/api/v2/monitor/system/status; result=command_execution', level: 'critical', score: 0.97, reasons: ['管理接口出现异常命令执行', '与前一公网扫描源一致'], use: ['src', 'firewall'] },
  { id: 'APT-SCRIPT-003', sec: 61, title: '创建 VPN 本地账户', technique: 'T1136.003', host: 'EDGE-FW-01', raw: 'fortigate[412]: local user svc-netops created; profile=ssl-vpn-user; actor=admin_api; result=success', level: 'critical', score: 0.96, reasons: ['管理设备新增 VPN 账户', '创建来源为异常管理接口会话'], use: ['firewall', 'vpnUser', 'vpn'] },
  { id: 'APT-SCRIPT-004', sec: 18 * 3600 + 8 * 60, title: 'SSL-VPN 正常远程登录', technique: 'T1078', host: 'EDGE-FW-01', raw: 'vpn-gateway: user=svc-netops login=success; source=198.51.100.23; tunnel=SSL; client=approved; bytes=normal', level: 'high', score: 0.9, reasons: ['使用刚创建的本地账户', '通道和流量外观正常'], use: ['vpnUser', 'src', 'vpn', 'firewall'] },
  { id: 'APT-SCRIPT-005', sec: 18 * 3600 + 10 * 60, title: '主机身份与网络侦察', technique: 'T1033/T1016', host: 'ENG-WS-07', raw: 'ENG-WS-07: user=svc-netops command="whoami && netstat -ano && systeminfo && ping 10.20.0.1" result=success', level: 'high', score: 0.91, reasons: ['远程会话首次进入工作站', '连续执行身份和网络枚举'], use: ['vpnUser', 'ws'] },
  { id: 'APT-SCRIPT-006', sec: 18 * 3600 + 14 * 60, title: '进程与在线用户枚举', technique: 'T1057/T1033', host: 'ENG-WS-07', raw: 'ENG-WS-07: wmic process list brief; powershell Get-ADComputer; quser; result=success; account=svc-netops', level: 'high', score: 0.93, reasons: ['同一远程账户连续侦察', '同时获取进程、域主机和在线用户信息'], use: ['ws', 'domain', 'tool', 'vpnUser'] },
  { id: 'APT-SCRIPT-007', sec: 18 * 3600 + 21 * 60, title: '域账户结构枚举', technique: 'T1087.002', host: 'ENG-WS-07', raw: 'ENG-WS-07: command="net user /domain && net group /domain"; result=success; queried_groups=Domain Admins, Remote Desktop Users', level: 'high', score: 0.94, reasons: ['读取域用户和高权限组', '与上一条域枚举连续发生'], use: ['ws', 'domain', 'vpnUser'] },
  { id: 'APT-SCRIPT-008', sec: 2 * 86400 + 9 * 3600 + 20 * 60, title: '合法凭据 RDP 到新主机', technique: 'T1021.001', host: 'APP-SRV-03', raw: 'windows-security: host=APP-SRV-03; logon_type=10; account=svc-netops; source=ENG-WS-07; destination=APP-SRV-03; protocol=RDP; result=success', level: 'high', score: 0.92, reasons: ['从已侦察工作站转向业务主机', '使用合法账户和标准 RDP 通道'], use: ['vpnUser', 'ws', 'app', 'domain'] },
  { id: 'APT-SCRIPT-009', sec: 2 * 86400 + 9 * 3600 + 23 * 60, title: '远程服务执行', technique: 'T1569.002', host: 'APP-SRV-03', raw: 'windows-system: host=APP-SRV-03; service creation name=WindowsUpdateHealthCheck; initiator=ENG-WS-07; account=svc-netops; start=automatic; result=success', level: 'critical', score: 0.95, reasons: ['RDP 后在目标业务主机创建自动启动服务', '服务名称伪装成运维组件'], use: ['ws', 'app', 'task', 'vpnUser'] },
  { id: 'APT-SCRIPT-010', sec: 2 * 86400 + 9 * 3600 + 28 * 60, title: '计划任务持久化', technique: 'T1053.005', host: 'APP-SRV-03', raw: 'schtasks: create /tn WindowsUpdateHealthCheck /sc daily /st 09:15 /ru SYSTEM; result=success', level: 'critical', score: 0.96, reasons: ['创建 SYSTEM 权限计划任务', '执行时间落在工作日运维时段'], use: ['task', 'vpnUser'] },
]

function eventFor(step) {
  const timestamp = new Date(base + step.sec * 1000).toISOString()
  const related = step.use.map((key) => {
    const [entity_type, canonical_value, role] = entities[key]
    return { event_id: step.id, entity_type, canonical_value, role, confidence: 0.95 }
  })
  const projection = {
    event_id: step.id, timestamp, threat_level: step.level, alert_level: step.level,
    final_score: step.score, raw_event_score: Math.min(0.99, step.score + 0.03),
    micro_window_score: Math.max(0.5, step.score - 0.1), macro_window_score: Math.max(0.5, step.score - 0.06),
    long_horizon_score: Math.max(0.5, step.score - 0.02), reasons: step.reasons,
    module_projection: { M1: '演示：事件语义归一化', M2: '演示：实体关系解析', M3: '演示：窗口因果关联', M4: '演示：当前事件异常', M5: '演示：长程证据关联', M6: `演示：融合风险 ${step.score}` },
    provenance: { kind: 'analyst_curated_demo_script_v2', model_execution: false, synthetic_scores: true, formal_evaluation: false },
  }
  return { event_id: step.id, timestamp, source_file: source, source_line: step.sec + 1, raw: step.raw, facts_only: true, system_projection: projection, related_entities: related, outgoing_relations: [], incoming_relations: [] }
}

const scriptedIds = new Set(steps.map((step) => step.id))
const timeline = read('timeline.json').filter((event) => !retiredIds.has(event.event_id))
const scripted = steps.map(eventFor)
const mergedTimeline = [...timeline, ...scripted].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
const detections = read('detection_results.json').filter((item) => !retiredIds.has(item.event_id))
  .concat(scripted.map((event) => event.system_projection))
const moduleScores = read('module_scores.json')
for (const id of retiredIds) delete moduleScores[id]
for (const event of scripted) {
  const p = event.system_projection
  moduleScores[event.event_id] = { M0: 0.9, M1: 0.82, M2: 0.88, M3: p.micro_window_score, M4: p.raw_event_score, M5: p.long_horizon_score, M6: p.final_score }
}

const chain = {
  chain_id: 'APT-SCRIPT-CANDIDATE-001', status: 'candidate', claim_type: 'analyst_curated_demo_script_v2',
  title: '九分钟演示：从公网边界到 OT 拓扑的跨十二天调查剧本',
  narrative: '演示汇报控制在约九分钟，但底层日志时间跨度为十二天。初始告警只暴露了公网管理接口异常、VPN 账户创建和一次远程登录。调查员先确认边界设备与账户实体，再沿实体检索工作站侦察、横向移动、代理和 OT 访问证据，逐步补齐攻击链。',
  initial_view: { visible_event_ids: ['APT-SCRIPT-001', 'APT-SCRIPT-002', 'APT-SCRIPT-003', 'APT-SCRIPT-004'], note: '首次发现阶段只展示前四步，后续步骤保留为候选证据，不预先合并。' },
  steps: steps.slice(0, 4).map((step, index) => ({ sequence: index + 1, label: `${step.technique} ${step.title}`, evidence_event_ids: [step.id], status: 'confirmed_in_demo' })),
  discovered_candidates: steps.slice(4).map((step) => ({ event_id: step.id, label: `${step.technique} ${step.title}`, reason: step.reasons.join('；'), status: 'candidate_pending_human_review' })),
  investigation_flow: ['发现高危边界事件', '确认设备、账户和来源 IP 实体', '按实体回查工作站与域活动', '补充横向移动和持久化证据', '沿代理实体进入 OT 网络', '提交当前已纳入链路给小影总结'],
  limitations: ['这是人工编排的九分钟演示剧本，不是模型预测结果。', '初始链路故意不完整，候选步骤需要调查员逐步加入。', '当前证据支持“预留长期访问能力”的判断，不足以证明已执行破坏。'],
}

const threatCounts = detections.reduce((counts, item) => { counts[item.threat_level] = (counts[item.threat_level] || 0) + 1; return counts }, {})
const times = mergedTimeline.map((item) => Date.parse(item.timestamp)).filter(Number.isFinite)
const manifest = read('manifest.json')
manifest.event_count = mergedTimeline.length
manifest.source_slice = `${new Date(Math.min(...times)).toISOString()}/${new Date(Math.max(...times)).toISOString()}`
manifest.sha256_events_log = crypto.createHash('sha256').update(JSON.stringify(mergedTimeline)).digest('hex')
manifest.apt_narrative = true
manifest.note = '九分钟人工编排演示剧本：首次仅展示部分攻击链，后续通过实体调查和候选证据逐步补链；不代表模型预测或真实入侵。'

write('timeline.json', mergedTimeline)
write('detection_results.json', detections)
write('module_scores.json', moduleScores)
write('attack_chain.json', chain)
write('manifest.json', manifest)
write('summary.json', { dataset_id: 'APT', kind: 'demo_system_projection', model_execution: false, synthetic_scores: true, formal_evaluation: false, event_count: mergedTimeline.length, anomaly_count: detections.filter((item) => item.final_score >= 0.5).length, threat_level_counts: { info: threatCounts.info || 0, low: threatCounts.low || 0, medium: threatCounts.medium || 0, high: threatCounts.high || 0, critical: threatCounts.critical || 0 }, time_range: manifest.source_slice, candidate_chain_id: chain.chain_id, candidate_chain_status: chain.status, initial_visible_steps: chain.steps.length, deferred_candidate_steps: chain.discovered_candidates.length })

console.log(JSON.stringify({ removed_retired_events: retiredIds.size, added_script_events: scripted.length, timeline_events: mergedTimeline.length, initial_chain_steps: chain.steps.length, deferred_candidates: chain.discovered_candidates.length }, null, 2))
