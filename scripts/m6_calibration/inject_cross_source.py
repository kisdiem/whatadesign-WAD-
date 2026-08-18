"""跨源真实样本注入：给 Short/Long 回放包补充 EVTX / IDS / DNS 跨源事件。

背景：
  演示回放 timeline 目前只有 Linux syslog 系（auth/network/syslog/audit/eve），
  与 README 声称的 "Syslog / ETW / WAF / DNS" 跨源口径不一致。本脚本从
  四个真实数据源中抽取真实样本事件注入 demo，让总览饼图出现 EVTX / DNS 扇区，
  让发现页出现跨源异常（EVTX 认证失败、IDS 恶意告警、DNS 隧道）。

数据来源（只读，绝不修改）：
  D:\\CODE\\EVTX-ATTACK-SAMPLES-master\\evtx_data.csv   —— 真实 Windows 事件日志攻击样本
  D:\\CODE\\santos\\gather\\cloud_share\\logs\\suricata\\eve.json —— 真实 Suricata IDS 告警
  D:\\CODE\\santos\\gather\\attacker_0\\logs\\dnsteal.log  —— 真实 DNS 隧道（dnsteal）工具日志

隔离纪律：
  - evtx_data.csv 的 EVTX_Tactic 列是 ATT&CK 标签，本脚本显式不读取该列值
    （仅使用事件字段：EventID/时间/主体/进程/IP 等），输出 labels_accessed=false；
  - 注入事件保留源数据原始文本，不合成"新攻击故事"；
  - 攻击链证据事件（attack_chain 的 evidence_event_ids）不受影响（不修改链文件）。

用法：
  python scripts/m6_calibration/inject_cross_source.py
  # 之后必须重跑：python scripts/m6_calibration/project_m6.py 重算 module_scores
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _scoring import IP_RE, weak_supervision  # noqa: E402

EVTX_CSV = Path(r"D:\CODE\EVTX-ATTACK-SAMPLES-master\evtx_data.csv")
IDS_JSON = Path(r"D:\CODE\santos\gather\cloud_share\logs\suricata\eve.json")
DNS_LOG = Path(r"D:\CODE\santos\gather\attacker_0\logs\dnsteal.log")

BACKUP_DIR = ROOT / "outputs/m6_calibration/backup_demo_pre_crosssource"

# 注入量（每个数据集）：(evtx, ids, dns)
INJECT_COUNTS = {
    "Long": (500, 150, 80),
    "Short": (120, 40, 20),
}

DATASET_DIRS = {
    "Long": ROOT / "frontend/public/demo-data/Long",
    "Short": ROOT / "frontend/public/demo-data/Short",
}


def _iso(dt_text: str) -> str:
    """'2019-02-13 15:14:52.409735' → '2019-02-13T15:14:52Z'"""
    try:
        parsed = datetime.strptime(dt_text.strip(), "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            parsed = datetime.strptime(dt_text.strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "2019-02-13T00:00:00Z"
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _non_empty(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value or value == "-":
        return None
    return value


def _build_evtx_event(row: dict[str, str], seq: int) -> dict:
    """把 EVTX CSV 行组装为演示 timeline 事件（显式不读取 EVTX_Tactic 列值）。"""
    event_id = str(row.get("EventID") or "")
    system_time = str(row.get("SystemTime") or "")
    computer = _non_empty(row.get("Computer")) or "PC01.example.corp"
    provider = _non_empty(row.get("ProviderName")) or "Microsoft-Windows-Security-Auditing"
    subject = _non_empty(row.get("SubjectUserName"))
    target = _non_empty(row.get("TargetUserName"))
    logon_type = _non_empty(row.get("LogonType"))
    ip_address = _non_empty(row.get("IpAddress"))
    ip_port = _non_empty(row.get("IpPort"))
    process = _non_empty(row.get("ProcessName"))
    channel = _non_empty(row.get("Channel")) or "Security"
    command_line = _non_empty(row.get("CommandLine"))
    script_block = _non_empty(row.get("ScriptBlockText"))

    fields = [f"EventID={event_id}"]
    if subject:
        fields.append(f"SubjectUserName={subject}")
    if target:
        fields.append(f"TargetUserName={target}")
    if logon_type:
        fields.append(f"LogonType={logon_type}")
    if ip_address and ip_address != "-":
        fields.append(f"IpAddress={ip_address}")
    if ip_port and ip_port != "-":
        fields.append(f"IpPort={ip_port}")
    if process:
        fields.append(f"Image={process}")
    # 攻击命令在 CommandLine / ScriptBlockText 字段，纳入 raw 以便弱监督规则命中。
    if command_line:
        fields.append(f"CommandLine={command_line}")
    elif script_block:
        fields.append(f"ScriptBlockText={script_block[:300]}")
    if provider:
        fields.append(f"ProviderName={provider}")
    if channel:
        fields.append(f"Channel={channel}")

    raw = f"{system_time} {computer} {provider}: {' '.join(fields)}"
    related = [{
        "canonical_value": computer.lower(),
        "confidence": 0.98,
        "entity_type": "host",
        "event_id": f"EVTX-{seq}",
        "role": "host",
    }]
    for value, role in ((subject, "actor"), (target, "target")):
        if value and IP_RE.fullmatch(value) is None:
            related.append({
                "canonical_value": value,
                "confidence": 0.9,
                "entity_type": "user",
                "event_id": f"EVTX-{seq}",
                "role": role,
            })
    if ip_address and IP_RE.fullmatch(ip_address):
        related.append({
            "canonical_value": ip_address,
            "confidence": 0.95,
            "entity_type": "ip",
            "event_id": f"EVTX-{seq}",
            "role": "source_ip",
        })
    weak_score, reasons = weak_supervision(raw)
    return _timeline_event(raw, f"gather/windows_client/logs/{provider}.evtx", weak_score, reasons, related, system_time)


def _build_ids_event(line: str, seq: int) -> dict:
    """把 Suricata eve.json 的 alert 行组装为演示事件（保留原始 JSON 文本）。"""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if obj.get("event_type") != "alert":
        return None
    alert = obj.get("alert") or {}
    timestamp = obj.get("timestamp") or "2022-01-14T03:41:34.065506+0000"
    src_ip = obj.get("src_ip") or ""
    dest_ip = obj.get("dest_ip") or ""
    signature = str(alert.get("signature") or "Suricata alert")
    classification = str(alert.get("classification") or "")
    action = str(alert.get("action") or "allowed")
    raw = (f"{timestamp} gateway suricata[1]: alert event_type=alert signature=\"{signature}\""
           f" classification=\"{classification}\" action={action}"
           f" src_ip={src_ip} src_port={obj.get('src_port')} dst_ip={dest_ip} dst_port={obj.get('dest_port')}"
           f" proto={obj.get('proto')}")
    related = [{
        "canonical_value": dest_ip or src_ip or "10.10.3.1",
        "confidence": 0.96,
        "entity_type": "ip",
        "event_id": f"IDS-{seq}",
        "role": "dest_ip",
    }]
    if src_ip:
        related.append({
            "canonical_value": src_ip,
            "confidence": 0.96,
            "entity_type": "ip",
            "event_id": f"IDS-{seq}",
            "role": "src_ip",
        })
    weak_score, reasons = weak_supervision(raw)
    return _timeline_event(raw, "gather/gateway/logs/suricata/eve.log", weak_score, reasons, related, timestamp)


def _build_dns_event(line: str, seq: int) -> dict:
    """把 dnsteal 工具 JSONL 行组装为演示事件（DNS 隧道/外泄特征）。"""
    raw = line.strip()
    try:
        obj = json.loads(raw)
        timestamp = obj.get("timestamp")
        ip_value = obj.get("ip")
    except json.JSONDecodeError:
        timestamp = None
        ip_value = None
    iso_time = datetime.fromtimestamp(float(timestamp), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if timestamp else "2022-01-13T18:00:00Z"
    related = []
    if ip_value:
        related.append({
            "canonical_value": str(ip_value),
            "confidence": 0.95,
            "entity_type": "ip",
            "event_id": f"DNS-{seq}",
            "role": "source_ip",
        })
    weak_score, reasons = weak_supervision(raw)
    return _timeline_event(raw, "gather/attacker/logs/dnsteal.log", weak_score, reasons, related, iso_time)


def _timeline_event(raw: str, source_file: str, weak_score: float, reasons: list[str], related: list[dict], source_time: str) -> dict:
    threat = "critical" if weak_score >= 0.75 else "high" if weak_score >= 0.55 else "medium" if weak_score >= 0.35 else "info"
    return {
        "facts_only": True,
        "incoming_relations": [],
        "outgoing_relations": [],
        "raw": raw,
        "related_entities": related,
        "source_file": source_file,
        "source_line": -1,
        "system_projection": {
            "alert_level": threat,
            "event_id": "PLACEHOLDER",
            "final_score": round(weak_score, 4),
            "long_horizon_score": round(weak_score, 4),
            "macro_window_score": round(weak_score, 4),
            "micro_window_score": round(weak_score, 4),
            "module_projection": {
                "M1": "跨源注入：弱监督信号命中",
                "M2": "跨源注入：实体已从事实字段提取",
                "M3": "跨源注入：实体图上下文可查询",
                "M4": "跨源注入：模板稀有度参与评分",
                "M5": "跨源注入：共享实体长程关联",
                "M6": "跨源注入：M0-M6 融合分数",
            },
            "provenance": {
                "formal_evaluation": False,
                "kind": "analyst_curated_demo_projection",
                "model_execution": False,
                "synthetic_scores": True,
            },
            "raw_event_score": round(weak_score, 4),
            "reasons": reasons or ["跨源真实样本注入"],
            "threat_level": threat,
            "timestamp": source_time,
        },
        "timestamp": source_time,
    }


# 攻击命令关键词：命中即认为高信号 EVTX 样本（真实攻击命令会落在 CommandLine/ScriptBlockText）
ATTACK_CMD_TOKENS = (
    "powershell", "certutil", "mimikatz", "sekurlsa", "regsvr32", "rundll32",
    "wscript", "cscript", "cmd /c", "curl", "wget", "ncat", "nc.exe", "nmap",
    "-enc", "invoke-", "bypass", "base64", "downloadstring", "downloadfile",
    "mshta", "bitsadmin", "schtasks", "whoami", "net user", "net localgroup",
    "psexec", "wmic",
)


def _evtx_is_attack(row: dict[str, str]) -> bool:
    """判断 EVTX 行是否含攻击特征：认证失败或 CommandLine/ScriptBlock 命中攻击命令。"""
    event_id = str(row.get("EventID") or "")
    text = f"{row.get('CommandLine') or ''} {row.get('ScriptBlockText') or ''} {row.get('ProcessName') or ''}".lower()
    if event_id == "4625":
        return True
    if event_id in ("4688", "1") and any(token in text for token in ATTACK_CMD_TOKENS):
        return True
    return any(token in text for token in ATTACK_CMD_TOKENS)


def _sample_evtx(rng: random.Random, count: int) -> list[dict]:
    """从 evtx_data.csv 流式抽样组装 EVTX 事件（跳过 EVTX_Tactic 列值）。

    分层采样：攻击特征样本约占 60%（保证跨源异常可见），常规样本约占 40%
    （保留真实数据分布，避免演示全是攻击）。
    """
    if not EVTX_CSV.exists():
        print(f"[warn] 缺少 EVTX 数据源：{EVTX_CSV}", file=sys.stderr)
        return []
    attack_pool: list[dict] = []
    normal_pool: list[dict] = []
    with EVTX_CSV.open("r", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        # 隔离：EVTX_Tactic 列存在但绝不读取其值。
        for row in reader:
            if _evtx_is_attack(row):
                attack_pool.append(row)
            elif rng.random() < 0.25:
                normal_pool.append(row)
            if len(attack_pool) >= max(count, 200) and len(normal_pool) >= max(count, 200):
                break
    rng.shuffle(attack_pool)
    rng.shuffle(normal_pool)
    attack_take = min(len(attack_pool), max(1, round(count * 0.6)))
    normal_take = min(len(normal_pool), count - attack_take)
    return attack_pool[:attack_take] + normal_pool[:normal_take]


def _sample_ids(rng: random.Random, count: int) -> list[str]:
    """从 eve.json 流式抽样 alert 行，优先恶意/扫描/攻击类告警。"""
    if not IDS_JSON.exists():
        print(f"[warn] 缺少 IDS 数据源：{IDS_JSON}", file=sys.stderr)
        return []
    alerts: list[dict] = []
    with IDS_JSON.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("event_type") != "alert":
                continue
            signature = str((obj.get("alert") or {}).get("signature") or "").lower()
            weight = 2 if any(k in signature for k in ("malicious", "scan", "exploit", "exec", "dropper", "backdoor", "c2", "et trojan")) else 1
            if rng.random() * 2 > weight:
                continue
            alerts.append(obj)
            if len(alerts) >= count * 6:
                break
    rng.shuffle(alerts)
    return [json.dumps(obj, ensure_ascii=False) for obj in alerts[:count]]


def _sample_dns(rng: random.Random, count: int) -> list[str]:
    """从 dnsteal.log 抽样含 DNS 隧道特征的行（server listening / query / dig / subdomain）。"""
    if not DNS_LOG.exists():
        print(f"[warn] 缺少 DNS 数据源：{DNS_LOG}", file=sys.stderr)
        return []
    lines: list[str] = []
    with DNS_LOG.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            lowered = line.lower()
            if not any(k in lowered for k in ("dns", "query", "dig ", "subdomain", "server listening", "resolv", "hostname")):
                continue
            if rng.random() < 0.5:
                continue
            lines.append(line)
            if len(lines) >= count * 4:
                break
    rng.shuffle(lines)
    return lines[:count]


def inject_dataset(dataset: str, rng: random.Random) -> dict:
    target = DATASET_DIRS[dataset] / "timeline.json"
    if not target.exists():
        print(f"[skip] 未找到 {target}", file=sys.stderr)
        return {"events": 0}
    timeline = json.loads(target.read_text(encoding="utf-8"))
    existing_ids = {str(item.get("event_id")) for item in timeline}
    evtx_count, ids_count, dns_count = INJECT_COUNTS[dataset]
    prefix = dataset.upper()

    additions: list[dict] = []
    for seq, row in enumerate(_sample_evtx(rng, evtx_count), start=1):
        event = _build_evtx_event(row, seq)
        event_id = f"{prefix}-EVTX-{seq:04d}"
        if event_id in existing_ids:
            continue
        existing_ids.add(event_id)
        event["event_id"] = event_id
        event["system_projection"]["event_id"] = event_id
        additions.append(event)

    ids_rows = _sample_ids(rng, ids_count)
    for seq, line in enumerate(ids_rows, start=1):
        event = _build_ids_event(line, seq)
        if not event:
            continue
        event_id = f"{prefix}-IDS-{seq:04d}"
        if event_id in existing_ids:
            continue
        existing_ids.add(event_id)
        event["event_id"] = event_id
        event["system_projection"]["event_id"] = event_id
        additions.append(event)

    dns_rows = _sample_dns(rng, dns_count)
    for seq, line in enumerate(dns_rows, start=1):
        event = _build_dns_event(line, seq)
        event_id = f"{prefix}-DNS-{seq:04d}"
        if event_id in existing_ids:
            continue
        existing_ids.add(event_id)
        event["event_id"] = event_id
        event["system_projection"]["event_id"] = event_id
        additions.append(event)

    timeline.extend(additions)
    target.write_text(json.dumps(timeline, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return {
        "before": len(timeline) - len(additions),
        "after": len(timeline),
        "added": len(additions),
        "evtx": sum(1 for item in additions if "-EVTX-" in item["event_id"]),
        "ids": sum(1 for item in additions if "-IDS-" in item["event_id"]),
        "dns": sum(1 for item in additions if "-DNS-" in item["event_id"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="跨源真实样本注入")
    parser.add_argument("--seed", type=int, default=20260818)
    args = parser.parse_args()

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    summary: dict = {}
    for dataset in ("Long", "Short"):
        src = DATASET_DIRS[dataset] / "timeline.json"
        backup = BACKUP_DIR / dataset
        backup.mkdir(parents=True, exist_ok=True)
        if src.exists():
            shutil.copy2(src, backup / "timeline.json")
        summary[dataset] = inject_dataset(dataset, random.Random(args.seed))
        print(json.dumps({dataset: summary[dataset]}, ensure_ascii=False))

    meta = {
        "schema_version": "cross_source_inject_v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "labels_used": False,
        "note": "向 Short/Long 回放注入 EVTX（Windows 安全审计样本）/ IDS（Suricata eve alert）/ DNS（dnsteal 隧道日志）真实样本事件；EVTX_Tactic 列未读取；注入后需重跑 project_m6.py。",
        "backup": str(BACKUP_DIR),
        "datasets": summary,
    }
    meta_path = ROOT / "outputs/m6_calibration/cross_source_inject_meta.json"
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"meta": str(meta_path), "labels_used": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
