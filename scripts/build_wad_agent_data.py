from __future__ import annotations

import argparse
import csv
import json
import re
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ATTACK_TITLES = {
    "network_scans": "外部网络扫描",
    "service_scans": "服务枚举探测",
    "dirb": "目录扫描与路径发现",
    "wpscan": "WordPress 资产探测",
    "webshell": "可疑 WebShell 落地",
    "cracking": "凭据破解尝试",
    "reverse_shell": "反向 Shell 建立",
    "privilege_escalation": "权限提升行为",
    "service_stop": "关键服务中断",
    "dnsteal": "疑似 DNS 数据外传",
}

ATTACK_SEVERITY = {
    "network_scans": ("medium", 0.68),
    "service_scans": ("medium", 0.72),
    "dirb": ("medium", 0.74),
    "wpscan": ("medium", 0.76),
    "webshell": ("high", 0.89),
    "cracking": ("high", 0.9),
    "reverse_shell": ("critical", 0.95),
    "privilege_escalation": ("critical", 0.96),
    "service_stop": ("medium", 0.7),
    "dnsteal": ("critical", 0.94),
}

SOURCE_TYPE_MAP = {
    "auth.log": "Linux Auth",
    "audit.log": "Linux Audit",
    "dnsmasq.log": "DNS",
    "openvpn.log": "VPN",
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PROCESS_RE = re.compile(r"\b([\w.-]+\.(?:exe|php|sh|py|pl|dll))\b", re.I)
USER_RE = re.compile(r"\buser\s+([A-Za-z0-9_.-]+)\b", re.I)
APACHE_TS_RE = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}:\d{2}:\d{2})")
SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass
class AttackWindow:
    scenario: str
    attack: str
    start_epoch: float
    end_epoch: float

    @property
    def title(self) -> str:
        return ATTACK_TITLES.get(self.attack, self.attack.replace("_", " "))

    @property
    def severity(self) -> str:
        return ATTACK_SEVERITY.get(self.attack, ("medium", 0.7))[0]

    @property
    def score(self) -> float:
        return ATTACK_SEVERITY.get(self.attack, ("medium", 0.7))[1]

    @property
    def window_id(self) -> str:
        start = datetime.fromtimestamp(self.start_epoch, tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"WIN-{self.scenario}-{self.attack}-{start}"


def iso_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def ensure_json(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def format_bytes(value: int) -> str:
    if value >= 1024 ** 3:
        return f"{value / (1024 ** 3):.1f} GB"
    if value >= 1024 ** 2:
        return f"{value / (1024 ** 2):.1f} MB"
    if value >= 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value} B"


def safe_read_json_lines(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for line in stream:
        text = line.strip()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            yield data


def read_attack_windows(labels_csv: Path, scenarios: set[str]) -> list[AttackWindow]:
    windows: list[AttackWindow] = []
    with labels_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            scenario = str(row.get("scenario", "")).strip()
            if scenario not in scenarios:
                continue
            attack = str(row.get("attack", "")).strip()
            start = float(row.get("start", "0") or 0)
            end = float(row.get("end", "0") or 0)
            windows.append(AttackWindow(scenario=scenario, attack=attack, start_epoch=start, end_epoch=end))
    return sorted(windows, key=lambda item: (item.scenario, item.start_epoch, item.attack))


def event_time_from_alert(alert: dict[str, Any]) -> float | None:
    if "@timestamp" in alert:
        text = str(alert["@timestamp"]).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text).timestamp()
        except ValueError:
            pass
    log_data = alert.get("LogData")
    if isinstance(log_data, dict):
        detection = log_data.get("DetectionTimestamp")
        if isinstance(detection, list) and detection:
            try:
                return float(detection[0])
            except (TypeError, ValueError):
                return None
    return None


def alert_detector(alert: dict[str, Any]) -> str:
    if "AMiner" in alert:
        return "AMiner"
    return "Wazuh"


def alert_title(alert: dict[str, Any]) -> str:
    rule = alert.get("rule")
    if isinstance(rule, dict) and rule.get("description"):
        return str(rule["description"])
    component = alert.get("AnalysisComponent")
    if isinstance(component, dict) and component.get("AnalysisComponentName"):
        return str(component["AnalysisComponentName"])
    return "Alert"


def alert_raw(alert: dict[str, Any]) -> str:
    if isinstance(alert.get("full_log"), str):
        return str(alert["full_log"])
    log_data = alert.get("LogData")
    if isinstance(log_data, dict):
        raw = log_data.get("RawLogData")
        if isinstance(raw, list) and raw:
            return str(raw[0])
    return ensure_json(alert)


def alert_location(alert: dict[str, Any]) -> str:
    if isinstance(alert.get("location"), str):
        return str(alert["location"])
    log_data = alert.get("LogData")
    if isinstance(log_data, dict):
        resources = log_data.get("LogResources")
        if isinstance(resources, list) and resources:
            return str(resources[0])
    return ""


def extract_entities(text: str) -> list[str]:
    entities: list[str] = []
    entities.extend(IP_RE.findall(text))
    entities.extend(PROCESS_RE.findall(text))
    user = USER_RE.search(text)
    if user:
        entities.append(user.group(1))
    deduped: list[str] = []
    seen: set[str] = set()
    for value in entities:
        cleaned = value.strip().strip('"').strip("'")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
    return deduped[:8]


def detector_source_type(detector: str, location: str) -> str:
    lowered = location.lower()
    if detector == "AMiner":
        return "AMiner"
    if "suricata" in lowered:
        return "Suricata"
    if "auth.log" in lowered:
        return "Linux Auth"
    if "audit.log" in lowered:
        return "Linux Audit"
    if "dns" in lowered:
        return "DNS"
    return "Wazuh"


def alert_priority(alert: dict[str, Any]) -> int:
    score = 0
    detector = alert_detector(alert)
    title = alert_title(alert).lower()
    raw = alert_raw(alert).lower()
    if detector == "AMiner":
        score += 6
    rule = alert.get("rule")
    if isinstance(rule, dict):
        try:
            score += int(rule.get("level", 0))
        except (TypeError, ValueError):
            pass
        groups = " ".join(str(item) for item in rule.get("groups", []) if item).lower()
        if "suricata" in groups:
            score += 4
        if "fts" in groups:
            score += 2
        if "virus" in groups or "freshclam" in groups:
            score -= 8
    negative_markers = [
        "clamav update",
        "not suspicious traffic",
        "apt user-agent outbound",
        "update process started",
    ]
    positive_markers = [
        "shell",
        "reverse",
        "exploit",
        "crack",
        "scan",
        "privilege",
        "suricata",
        "ids event",
        "dns",
        "audit",
        "alert",
    ]
    for marker in positive_markers:
        if marker in title or marker in raw:
            score += 3
    for marker in negative_markers:
        if marker in title or marker in raw:
            score -= 10
    return score


def build_event_from_alert(alert: dict[str, Any], event_id: str) -> dict[str, Any]:
    timestamp = event_time_from_alert(alert)
    raw = alert_raw(alert)
    detector = alert_detector(alert)
    location = alert_location(alert)
    title = alert_title(alert)
    entities = extract_entities(raw)
    host = None
    agent = alert.get("agent")
    if isinstance(agent, dict):
        host = str(agent.get("name") or "") or None
    if not host:
        predecoder = alert.get("predecoder")
        if isinstance(predecoder, dict):
            host = str(predecoder.get("hostname") or "") or None
    ip = next((value for value in entities if IP_RE.fullmatch(value)), None)
    process = next((value for value in entities if value.lower().endswith((".exe", ".php", ".sh", ".py", ".pl", ".dll"))), None)
    actor = next((value for value in entities if value not in {ip, process}), None)
    return {
        "id": event_id,
        "time": iso_from_epoch(timestamp) if timestamp else "",
        "action": title[:64],
        "actor": actor,
        "host": host,
        "process": process,
        "ip": ip,
        "source": detector_source_type(detector, location),
        "raw": raw[:500],
        "confidence": 0.87 if detector == "AMiner" else 0.91,
    }


def collect_alert_windows(ait_ads_zip: Path, target_windows: list[AttackWindow]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    windows_by_scenario: dict[str, list[AttackWindow]] = defaultdict(list)
    for item in target_windows:
        windows_by_scenario[item.scenario].append(item)

    collected: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)

    with zipfile.ZipFile(ait_ads_zip, "r") as archive:
        for scenario, scenario_windows in windows_by_scenario.items():
            for suffix in ("wazuh", "aminer"):
                member = f"{scenario}_{suffix}.json"
                try:
                    with archive.open(member, "r") as raw_handle:
                        lines = (line.decode("utf-8", errors="replace") for line in raw_handle)
                        for alert in safe_read_json_lines(lines):
                            event_time = event_time_from_alert(alert)
                            if event_time is None:
                                continue
                            for window in scenario_windows:
                                if window.start_epoch <= event_time <= window.end_epoch:
                                    counts[window.window_id] += 1
                                    event_id = str(alert.get("id") or f"{window.window_id}-E{counts[window.window_id]:04d}")
                                    collected[window.window_id].append((alert_priority(alert), build_event_from_alert(alert, event_id)))

                except KeyError:
                    continue

    anomaly_windows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for window in target_windows:
        ranked_events = sorted(collected.get(window.window_id, []), key=lambda item: item[0], reverse=True)
        events = [event for _, event in ranked_events[:12]]
        source_types = sorted({event["source"] for event in events if event.get("source")})
        entities = sorted({value for event in events for value in [event.get("actor"), event.get("process"), event.get("ip"), event.get("host")] if value})
        hosts = sorted({str(event["host"]) for event in events if event.get("host")})
        anomaly_windows.append({
            "id": window.window_id,
            "title": window.title,
            "severity": window.severity,
            "score": window.score,
            "start": iso_from_epoch(window.start_epoch),
            "end": iso_from_epoch(window.end_epoch),
            "status": "investigating" if window.severity in {"high", "critical"} else "reviewing",
            "eventCount": counts.get(window.window_id, 0),
            "entities": entities[:8],
            "hosts": hosts[:4],
            "sourceTypes": source_types or ["AIT-ADS"],
            "summary": f"{window.scenario} 场景中的 {window.title} 阶段，来自 AIT-ADS 的关联告警已聚合为调查窗口。",
            "events": events,
        })
        findings.append({
            "finding_id": window.window_id,
            "id": window.window_id,
            "title": window.title,
            "scenario": window.scenario,
            "attack": window.attack,
            "risk_score": int(round(window.score * 100)),
            "severity": window.severity,
            "start": iso_from_epoch(window.start_epoch),
            "end": iso_from_epoch(window.end_epoch),
            "source_types": source_types or ["AIT-ADS"],
            "entities": entities[:8],
            "evidence_refs": [event["id"] for event in events],
            "summary": f"{window.title}，共命中 {counts.get(window.window_id, 0)} 条告警。",
        })
    return anomaly_windows, findings


def read_labeled_lines(label_file: Path) -> list[tuple[int, list[str]]]:
    rows: list[tuple[int, list[str]]] = []
    with label_file.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            index = int(payload.get("line", 0) or 0)
            labels = [str(item) for item in payload.get("labels", []) if item]
            if index > 0 and labels:
                rows.append((index, labels))
    return rows


def infer_log_source_type(path: Path) -> str:
    for suffix, source_type in SOURCE_TYPE_MAP.items():
        if path.name.endswith(suffix):
            return source_type
    lowered = str(path).lower()
    if "apache2" in lowered:
        return "WAF"
    return path.suffix.lstrip(".").upper() or "LOG"


def parse_raw_timestamp(text: str, year_hint: int) -> str | None:
    apache = APACHE_TS_RE.search(text)
    if apache:
        day, month, year, hhmmss = apache.groups()
        month_number = MONTHS.get(month, 1)
        return f"{year}-{month_number:02d}-{int(day):02d} {hhmmss}"

    syslog = SYSLOG_TS_RE.search(text)
    if syslog:
        month, day, hhmmss = syslog.groups()
        month_number = MONTHS.get(month, 1)
        return f"{year_hint}-{month_number:02d}-{int(day):02d} {hhmmss}"
    return None


def collect_raw_logs(dataset_root: Path, scenario: str, max_rows: int) -> list[dict[str, Any]]:
    year_hint = int(str(dataset_root.joinpath("dataset.yaml").read_text(encoding="utf-8")).split("start: '")[1][:4])
    rows: list[dict[str, Any]] = []
    label_files = sorted(dataset_root.joinpath("labels").rglob("*"))
    for label_file in label_files:
        if not label_file.is_file():
            continue
        if "logs" not in label_file.parts:
            continue
        selected = read_labeled_lines(label_file)
        if not selected:
            continue
        line_map = {line_number: labels for line_number, labels in selected}
        gather_file = Path(str(label_file).replace(str(dataset_root / "labels"), str(dataset_root / "gather")))
        if not gather_file.exists():
            continue
        with gather_file.open("r", encoding="utf-8", errors="replace") as handle:
            for idx, content in enumerate(handle, 1):
                labels = line_map.get(idx)
                if not labels:
                    continue
                raw = content.rstrip("\r\n")
                timestamp = parse_raw_timestamp(raw, year_hint)
                source_type = infer_log_source_type(gather_file)
                event_id = f"RAW-{scenario}-{len(rows) + 1:05d}"
                entities = extract_entities(raw)
                rows.append({
                    "id": event_id,
                    "event_id": event_id,
                    "scenario": scenario,
                    "timestamp": timestamp or "",
                    "time": timestamp or "",
                    "source": source_type,
                    "source_type": source_type,
                    "path": str(gather_file),
                    "raw_log_ref": f"{gather_file}:{idx}",
                    "labels": labels,
                    "text": raw,
                    "entities": entities,
                })
                if len(rows) >= max_rows:
                    return rows
    return rows


def collect_evtx_logs(evtx_dir: Path, max_rows: int) -> list[dict[str, Any]]:
    csv_path = evtx_dir / "evtx_data.csv"
    if not csv_path.exists():
        return []

    preferred_tactics = {
        "Command and Control",
        "Credential Access",
        "Execution",
        "Lateral Movement",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Discovery",
    }
    rows: list[dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        candidates: list[dict[str, Any]] = []
        for row in reader:
            tactic = str(row.get("EVTX_Tactic", "")).strip()
            system_time = str(row.get("SystemTime", "")).strip()
            if not tactic or not system_time:
                continue
            candidates.append(row)

    def priority(item: dict[str, Any]) -> tuple[int, str]:
        tactic = str(item.get("EVTX_Tactic", "")).strip()
        event_id = str(item.get("EventID", "")).strip()
        score = 1
        if tactic in preferred_tactics:
            score += 8
        if event_id in {"4624", "4625", "4688", "4689", "4698", "4720", "4728", "7045", "4104"}:
            score += 4
        return (-score, str(item.get("SystemTime", "")))

    candidates.sort(key=priority)
    for index, row in enumerate(candidates[:max_rows], 1):
        timestamp = str(row.get("SystemTime", "")).replace("T", " ")[:19]
        host = str(row.get("Computer", "")).strip() or None
        process = str(row.get("ProcessName", "") or row.get("NewProcessName", "") or row.get("Image", "")).strip() or None
        ip = str(row.get("IpAddress", "") or row.get("SourceIp", "") or row.get("DestinationIp", "")).strip() or None
        actor = str(row.get("TargetUserName", "") or row.get("User", "") or row.get("SubjectUserName", "")).strip() or None
        tactic = str(row.get("EVTX_Tactic", "")).strip()
        event_id = str(row.get("EventID", "")).strip()
        raw = f"{tactic} EventID={event_id} File={row.get('EVTX_FileName', '')} User={actor or '-'} Host={host or '-'} Process={process or '-'}"
        rows.append({
            "id": f"EVTX-{index:05d}",
            "event_id": f"EVTX-{index:05d}",
            "scenario": "evtx_attack_samples",
            "timestamp": timestamp,
            "time": timestamp,
            "source": "Windows EVTX",
            "source_type": "Windows EVTX",
            "path": str(csv_path),
            "raw_log_ref": f"{csv_path}:{index + 1}",
            "labels": [tactic] if tactic else [],
            "text": raw,
            "entities": [value for value in [actor, host, process, ip] if value],
            "event_id_value": event_id,
            "tactic": tactic,
            "evtx_file": str(row.get("EVTX_FileName", "")),
        })
    return rows


def build_investigations(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in windows:
        parts = item["id"].split("-")
        if len(parts) >= 3:
            grouped[parts[1]].append(item)

    investigations: list[dict[str, Any]] = []
    for index, (scenario, items) in enumerate(sorted(grouped.items()), 1):
        items.sort(key=lambda value: value["start"])
        max_window = max(items, key=lambda value: float(value["score"]))
        severity = max_window["severity"]
        investigations.append({
            "id": f"CASE-{index:03d}",
            "investigation_id": f"CASE-{index:03d}",
            "title": f"{scenario} 多阶段攻击调查",
            "severity": severity,
            "status": "investigating",
            "owner": "Analyst-01",
            "createdAt": items[0]["start"],
            "windowIds": [item["id"] for item in items],
            "finding_ids": [item["id"] for item in items],
            "summary": f"{scenario} 场景共整理 {len(items)} 个攻击阶段窗口，用于长程调查和证据串联。",
        })
    return investigations


def build_entities(windows: list[dict[str, Any]], logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entities: dict[str, dict[str, Any]] = {}

    def touch(value: str, entity_type: str, seen_at: str, source: str, risk: float) -> None:
        record = entities.setdefault(value, {
            "id": value,
            "entity_id": value,
            "type": entity_type,
            "first_seen": seen_at,
            "last_seen": seen_at,
            "sources": set(),
            "count": 0,
            "risk": 0.0,
        })
        if seen_at and (not record["first_seen"] or seen_at < record["first_seen"]):
            record["first_seen"] = seen_at
        if seen_at and seen_at > record["last_seen"]:
            record["last_seen"] = seen_at
        record["sources"].add(source)
        record["count"] += 1
        record["risk"] = max(record["risk"], risk)

    for window in windows:
        for event in window.get("events", []):
            seen_at = str(event.get("time") or window["start"])
            risk = float(window["score"]) * 100
            for key in ("actor", "host", "process", "ip"):
                value = event.get(key)
                if not value:
                    continue
                entity_type = {
                    "actor": "user",
                    "host": "host",
                    "process": "process",
                    "ip": "ip",
                }[key]
                touch(str(value), entity_type, seen_at, str(event.get("source") or "alert"), risk)

    for row in logs:
        seen_at = str(row.get("timestamp") or "")
        source = str(row.get("source_type") or "raw")
        for value in row.get("entities", []):
            entity_type = "ip" if IP_RE.fullmatch(value or "") else ("process" if str(value).lower().endswith((".exe", ".php", ".sh", ".py", ".pl", ".dll")) else "entity")
            touch(str(value), entity_type, seen_at, source, 55.0)

    output: list[dict[str, Any]] = []
    for item in entities.values():
        output.append({
            "id": item["id"],
            "entity_id": item["entity_id"],
            "type": item["type"],
            "first_seen": item["first_seen"],
            "last_seen": item["last_seen"],
            "source_count": len(item["sources"]),
            "event_count": item["count"],
            "risk": round(item["risk"], 2),
            "sources": sorted(item["sources"]),
        })
    output.sort(key=lambda value: (-value["risk"], value["entity_id"]))
    return output


def build_baselines(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    baselines: list[dict[str, Any]] = []
    for item in entities:
        baselines.append({
            "id": item["entity_id"],
            "entity_id": item["entity_id"],
            "type": item["type"],
            "baseline_window": "30d",
            "activity_count": item["event_count"],
            "source_diversity": item["source_count"],
            "rarity_score": round(min(0.98, 1.0 / max(item["event_count"], 1) + (item["risk"] / 200.0)), 3),
            "last_seen": item["last_seen"],
        })
    return baselines


def build_log_sources(
    ait_ads_dir: Path,
    raw_dirs: list[Path],
    evtx_dir: Path,
) -> list[dict[str, Any]]:
    sources = [
        {
            "id": "SRC-001",
            "name": "AIT-ADS Alert Bundle",
            "path": str(ait_ads_dir / "ait_ads.zip"),
            "kind": "ZIP",
            "status": "online",
            "size": format_bytes((ait_ads_dir / "ait_ads.zip").stat().st_size),
            "lastRead": "已生成平台数据包",
        },
        {
            "id": "SRC-002",
            "name": "EVTX Attack Samples",
            "path": str(evtx_dir),
            "kind": "EVTX",
            "status": "online",
            "size": format_bytes((evtx_dir / "evtx_data.csv").stat().st_size),
            "lastRead": "已索引 EVTX 元数据",
        },
    ]
    for index, raw_dir in enumerate(raw_dirs, 3):
        sources.append({
            "id": f"SRC-{index:03d}",
            "name": raw_dir.name,
            "path": str(raw_dir),
            "kind": "RAW",
            "status": "online",
            "size": "已挂载场景目录",
            "lastRead": "已提取标签与原始日志",
        })
    return sources


def build_knowledge_documents(evtx_dir: Path) -> list[dict[str, Any]]:
    return [
        {
            "id": "KB-001",
            "name": "AIT-ADS_Scenarios.md",
            "category": "数据集映射",
            "kind": "Markdown",
            "status": "indexed",
            "chunks": 48,
            "updatedAt": datetime.now().strftime("%Y-%m-%d"),
        },
        {
            "id": "KB-002",
            "name": "AIT-LDSv2_Label_Rules.md",
            "category": "标签参考",
            "kind": "Markdown",
            "status": "indexed",
            "chunks": 36,
            "updatedAt": datetime.now().strftime("%Y-%m-%d"),
        },
        {
            "id": "KB-003",
            "name": "EVTX_ATT&CK_Metadata.csv",
            "category": "Windows 样本",
            "kind": "CSV",
            "status": "indexed",
            "chunks": 64,
            "updatedAt": datetime.now().strftime("%Y-%m-%d"),
        },
        {
            "id": "KB-004",
            "name": "EVTX_README.md",
            "category": "Windows 样本",
            "kind": "Markdown",
            "status": "indexed",
            "chunks": 12,
            "updatedAt": datetime.now().strftime("%Y-%m-%d"),
        },
    ]


def build_knowledge(rows: list[dict[str, Any]], evtx_dir: Path) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = [
        {
            "id": "DOC-AIT-ADS",
            "document_id": "DOC-AIT-ADS",
            "scope": "security",
            "title": "AIT-ADS 使用说明",
            "content": "AIT-ADS 用于多步攻击告警聚合，适合 Findings、Investigation、Evidence 和攻击链展示。",
        },
        {
            "id": "DOC-AIT-LDS",
            "document_id": "DOC-AIT-LDS",
            "scope": "security",
            "title": "AIT-LDSv2 使用说明",
            "content": "AIT-LDSv2 提供原始日志、标签和多源背景，适合 Log Search、Entity Baseline 和原始证据回查。",
        },
    ]

    evtx_csv = evtx_dir / "evtx_data.csv"
    if evtx_csv.exists():
        with evtx_csv.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            samples: list[str] = []
            for index, row in enumerate(reader):
                samples.append(
                    f"{row.get('EVTX_FileName', '')}: tactic={row.get('EVTX_Tactic', '')}, "
                    f"event_id={row.get('EventID', '')}, user={row.get('TargetUserName', '')}, host={row.get('Computer', '')}"
                )
                if index >= 7:
                    break
        docs.append({
            "id": "DOC-EVTX",
            "document_id": "DOC-EVTX",
            "scope": "security",
            "title": "EVTX Attack Samples 概览",
            "content": "\n".join(samples),
        })

    if rows:
        examples = [f"{row['scenario']} {row['source_type']} {','.join(row.get('labels', []))} {row['raw_log_ref']}" for row in rows[:12]]
        docs.append({
            "id": "DOC-RAW-LOGS",
            "document_id": "DOC-RAW-LOGS",
            "scope": "security",
            "title": "原始日志样本索引",
            "content": "\n".join(examples),
        })
    return docs


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False))
            handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build WAD agent data bundle from downloaded datasets.")
    parser.add_argument("--ait-ads-dir", required=True)
    parser.add_argument("--scenario-dir", action="append", required=True, help="AIT-LDSv2 scenario directory, repeatable.")
    parser.add_argument("--evtx-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-raw-logs-per-scenario", type=int, default=180)
    parser.add_argument("--max-evtx-logs", type=int, default=1200)
    args = parser.parse_args()

    ait_ads_dir = Path(args.ait_ads_dir)
    evtx_dir = Path(args.evtx_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ait_ads_zip = ait_ads_dir / "ait_ads.zip"
    labels_csv = ait_ads_dir / "labels.csv"
    if not ait_ads_zip.exists():
        raise FileNotFoundError(f"AIT-ADS zip not found: {ait_ads_zip}")
    if not labels_csv.exists():
        raise FileNotFoundError(f"AIT-ADS labels.csv not found: {labels_csv}")

    scenario_dirs = [Path(item) for item in args.scenario_dir]
    target_scenarios = {path.name for path in scenario_dirs}

    attack_windows = read_attack_windows(labels_csv, target_scenarios)
    windows, findings = collect_alert_windows(ait_ads_zip, attack_windows)
    investigations = build_investigations(windows)

    raw_logs: list[dict[str, Any]] = []
    for scenario_dir in scenario_dirs:
        raw_logs.extend(collect_raw_logs(scenario_dir, scenario_dir.name, args.max_raw_logs_per_scenario))
    raw_logs.extend(collect_evtx_logs(evtx_dir, args.max_evtx_logs))

    entities = build_entities(windows, raw_logs)
    baselines = build_baselines(entities)
    log_sources = build_log_sources(ait_ads_dir, scenario_dirs, evtx_dir)
    knowledge_documents = build_knowledge_documents(evtx_dir)
    knowledge = build_knowledge(raw_logs, evtx_dir)

    write_json(output_dir / "windows.json", windows)
    write_json(output_dir / "investigations.json", investigations)
    write_json(output_dir / "log_sources.json", log_sources)
    write_json(output_dir / "knowledge_documents.json", knowledge_documents)
    write_json(output_dir / "findings.json", findings)
    write_json(output_dir / "entities.json", entities)
    write_json(output_dir / "baselines.json", baselines)
    write_json(output_dir / "knowledge.json", knowledge)
    write_jsonl(output_dir / "logs.jsonl", raw_logs)

    summary = {
        "status": "ok",
        "output_dir": str(output_dir),
        "windows": len(windows),
        "investigations": len(investigations),
        "findings": len(findings),
        "entities": len(entities),
        "raw_logs": len(raw_logs),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
