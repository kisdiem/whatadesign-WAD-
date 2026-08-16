from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.common.schema import RawRecord
from src.entities.m2_rule_resolver import M2RuleResolver
from src.parsers.m0_drain import M0DrainParser
from src.semantic.m1_normalizer import M1SemanticNormalizer


MAX_UPLOAD_BYTES = int(os.getenv("WAD_MAX_UPLOAD_BYTES", str(8 * 1024 * 1024)))
STATE_DB = os.getenv("WAD_INGEST_DB", "run_state/wad_ingestion.db")
SUPPORTED_SUFFIXES = {".log", ".txt", ".json", ".jsonl", ".csv"}
TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(?:(?:user(?:name)?|login|uid)[=: ]+|account[=:]+)['\"]?([A-Za-z0-9_.@\\-]+)", re.I)
HOST_RE = re.compile(r"(?:host(?:name)?|computer)[=: ]+['\"]?([A-Za-z0-9_.-]+)", re.I)
PROCESS_RE = re.compile(r"(?:process|image|command)[=: ]+['\"]?([^,;\s]+)", re.I)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _clamp(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 4)


def _normalise_timestamp(value: Any, fallback: datetime) -> tuple[str, str]:
    if value is not None:
        text = str(value).strip()
        if text:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), "source"
            except ValueError:
                pass
    return fallback.isoformat().replace("+00:00", "Z"), "ingest_fallback"


def _timestamp_from_payload(payload: Any, raw: str, fallback: datetime) -> tuple[str, str]:
    if isinstance(payload, dict):
        for key in ("@timestamp", "timestamp", "time", "TimeCreated", "SystemTime", "datetime", "date"):
            if payload.get(key) not in (None, ""):
                return _normalise_timestamp(payload[key], fallback)
    match = TIMESTAMP_RE.search(raw)
    return _normalise_timestamp(match.group(0) if match else None, fallback)


def _event_rows(filename: str, content: bytes) -> list[dict[str, Any]]:
    suffix = Path(filename).suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        if suffix == ".evtx":
            raise ValueError("EVTX 二进制解析需要可选 python-evtx 组件；当前原型请先导出为 XML/JSON/CSV。")
        raise ValueError(f"暂不支持 {suffix or '无扩展名'} 文件。")
    text = content.decode("utf-8", "replace")
    rows: list[dict[str, Any]] = []
    if suffix == ".json":
        payload = json.loads(text)
        if isinstance(payload, dict) and isinstance(payload.get("events"), list):
            payload = payload["events"]
        values = payload if isinstance(payload, list) else [payload]
        for line, value in enumerate(values, 1):
            rows.append({"line": line, "payload": value, "raw": _json(value) if not isinstance(value, str) else value})
    elif suffix == ".jsonl":
        for line, value in enumerate(text.splitlines(), 1):
            if not value.strip():
                continue
            try:
                payload = json.loads(value)
            except json.JSONDecodeError:
                payload = {"message": value}
            rows.append({"line": line, "payload": payload, "raw": value})
    elif suffix == ".csv":
        for line, value in enumerate(csv.DictReader(io.StringIO(text)), 2):
            rows.append({"line": line, "payload": dict(value), "raw": _json(value)})
    else:
        for line, value in enumerate(text.splitlines(), 1):
            if value.strip():
                rows.append({"line": line, "payload": value, "raw": value})
    if not rows:
        raise ValueError("文件中没有可处理的日志记录。")
    return rows


def _entities(raw: str, payload: Any, semantic_entities: list[str]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {
        "ip": list(dict.fromkeys(IP_RE.findall(raw))),
        "user": list(dict.fromkeys(USER_RE.findall(raw))),
        "host": list(dict.fromkeys(HOST_RE.findall(raw))),
        "process": list(dict.fromkeys(PROCESS_RE.findall(raw))),
    }
    if isinstance(payload, dict):
        aliases = {
            "ip": ("src_ip", "dst_ip", "source_ip", "destination_ip", "ip"),
            "user": ("user", "username", "account", "actor"),
            "host": ("host", "hostname", "computer", "device"),
            "process": ("process", "process_name", "image", "command"),
        }
        lowered = {str(key).lower(): value for key, value in payload.items()}
        for entity_type, keys in aliases.items():
            for key in keys:
                value = lowered.get(key)
                if isinstance(value, (str, int)) and str(value).strip():
                    output[entity_type].append(str(value).strip())
    for value in semantic_entities:
        output["ip" if IP_RE.fullmatch(value) else "user"].append(value)
    return {key: list(dict.fromkeys(values)) for key, values in output.items() if values}


def _weak_supervision(raw: str) -> tuple[float, list[str]]:
    text = raw.lower()
    hits: list[tuple[float, str]] = []
    rules = (
        (0.88, ("mimikatz", "credential dump", "lsass"), "凭据访问高风险关键词"),
        (0.82, ("powershell -enc", "encodedcommand", "rundll32", "certutil"), "可疑脚本或系统工具执行"),
        (0.78, ("useradd", "new user", "add user", "net user"), "账户创建或组成员变更"),
        (0.72, ("failed password", "authentication failure", "login failed", "4625"), "认证失败事件"),
        (0.68, ("sudo", "session opened for user root", "privilege"), "权限上下文变化"),
        (0.64, ("denied", "blocked", "waf", "malicious"), "安全设备拒绝或恶意标记"),
        (0.60, ("dns", "connect", "outbound", "external"), "网络连接需要结合上下文核查"),
    )
    for score, tokens, reason in rules:
        if any(token in text for token in tokens):
            hits.append((score, reason))
    if not hits:
        return 0.08, ["未命中弱监督高风险规则"]
    return max(score for score, _ in hits), list(dict.fromkeys(reason for _, reason in hits))


class IngestionStore:
    """Persistent small-file ingestion store and explainable M0-M6 prototype runner."""

    def __init__(self, db_path: str | Path = STATE_DB) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialise(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, timestamp TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_id);
                CREATE TABLE IF NOT EXISTS windows (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, timestamp TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL);
                """
            )

    def ingest_base64(self, filename: str, encoded: str, content_type: str = "") -> dict[str, Any]:
        safe_name = Path(filename).name.strip()
        if not safe_name:
            raise ValueError("文件名不能为空。")
        try:
            content = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise ValueError("上传内容不是有效的 Base64。") from error
        if len(content) > MAX_UPLOAD_BYTES:
            raise ValueError(f"单文件最大允许 {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB。")
        return self.ingest_bytes(safe_name, content, content_type)

    def ingest_bytes(self, filename: str, content: bytes, content_type: str = "") -> dict[str, Any]:
        with self._lock:
            return self._run_pipeline(filename, content, content_type)

    def _run_pipeline(self, filename: str, content: bytes, content_type: str) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        started_clock = time.perf_counter()
        job_id = f"JOB-{uuid.uuid4().hex[:12].upper()}"
        source_id = f"UPLOAD-{uuid.uuid4().hex[:10].upper()}"
        dataset_id = source_id.lower()
        rows = _event_rows(filename, content)
        parser = M0DrainParser()
        normalizer = M1SemanticNormalizer()
        resolver = M2RuleResolver()
        parsed_rows: list[dict[str, Any]] = []
        template_counts: Counter[str] = Counter()
        entity_counts: Counter[str] = Counter()
        base_time = started

        # M0-M2: syntax parsing, semantic normalisation and entity resolution.
        for offset, row in enumerate(rows):
            fallback = base_time + timedelta(microseconds=offset)
            timestamp, timestamp_origin = _timestamp_from_payload(row["payload"], row["raw"], fallback)
            record = RawRecord(dataset_id, filename, int(row["line"]), timestamp, row["payload"], M0DrainParser.VERSION)
            parsed = parser.parse(record)
            frame = normalizer.normalize(parsed)
            found = _entities(row["raw"], row["payload"], frame.entities)
            resolved: list[dict[str, Any]] = []
            for entity_type, values in found.items():
                for value in values:
                    item = resolver.resolve(
                        dataset_id=dataset_id,
                        entity_type=entity_type,
                        raw_value=value,
                        source_record_ref=parsed.raw_record_ref,
                        confidence=0.9,
                    )
                    resolved.append(item.to_dict())
                    entity_counts[f"{entity_type}:{item.canonical_value}"] += 1
            template_counts[parsed.template_id] += 1
            parsed_rows.append({
                "row": row,
                "timestamp": timestamp,
                "timestamp_origin": timestamp_origin,
                "parsed": parsed,
                "frame": frame,
                "entities": resolved,
            })

        events: list[dict[str, Any]] = []
        windows: list[dict[str, Any]] = []
        previous_risky: list[dict[str, Any]] = []
        stage_totals: defaultdict[str, float] = defaultdict(float)
        for index, item in enumerate(parsed_rows, 1):
            row = item["row"]
            parsed = item["parsed"]
            frame = item["frame"]
            resolved = item["entities"]
            entity_keys = [f"{value['entity_type']}:{value['canonical_value']}" for value in resolved]
            weak_score, reasons = _weak_supervision(row["raw"])

            # M3: graph/context novelty. M4: unsupervised template rarity.
            entity_rarity = max((1 / math.sqrt(entity_counts[key]) for key in entity_keys), default=0.25)
            m2_score = _clamp(0.2 + 0.55 * entity_rarity)
            m3_score = _clamp(0.12 + min(len(entity_keys), 5) * 0.09 + (0.20 if len(entity_keys) >= 2 else 0))
            template_rarity = 1 / math.sqrt(template_counts[parsed.template_id])
            failure_boost = 0.22 if frame.outcome == "failure" else 0
            m4_score = _clamp(0.16 + 0.62 * template_rarity + failure_boost)

            # M5: link a risky event to earlier risky events sharing an entity.
            linked = [event for event in previous_risky[-100:] if entity_keys and set(entity_keys) & set(event["entity_keys"])]
            m5_score = _clamp(0.12 + min(len(linked), 3) * 0.22 + (0.18 if weak_score >= 0.6 and linked else 0))
            final_score = _clamp(0.30 * weak_score + 0.12 * m2_score + 0.14 * m3_score + 0.28 * m4_score + 0.16 * m5_score)
            if final_score >= 0.75:
                severity = "high"
            elif final_score >= 0.55:
                severity = "medium"
            elif final_score >= 0.35:
                severity = "low"
            else:
                severity = "info"
            if template_rarity >= 0.7:
                reasons.append("M4：当前文件中的稀有日志模板")
            if linked:
                reasons.append(f"M5：与 {len(linked)} 条较早风险事件共享实体")

            event_id = f"UP-{job_id[4:]}-{index:06d}"
            values_by_type: dict[str, list[str]] = defaultdict(list)
            for value in resolved:
                values_by_type[value["entity_type"]].append(value["canonical_value"])
            module_scores = {
                "M0": _clamp(parsed.parse_confidence),
                "M1": _clamp(weak_score),
                "M2": m2_score,
                "M3": m3_score,
                "M4": m4_score,
                "M5": m5_score,
                "M6": final_score,
            }
            for stage, score in module_scores.items():
                stage_totals[stage] += score
            event = {
                "id": event_id,
                "event_id": event_id,
                "timestamp": item["timestamp"],
                "time": item["timestamp"],
                "timestamp_origin": item["timestamp_origin"],
                "source": filename,
                "source_type": f"实时上传/{filename}",
                "source_id": source_id,
                "source_line": int(row["line"]),
                "raw_log_ref": f"upload://{source_id}/{filename}:{row['line']}",
                "raw": row["raw"],
                "text": row["raw"],
                "action": frame.action,
                "outcome": frame.outcome,
                "actor": (values_by_type.get("user") or [None])[0],
                "host": (values_by_type.get("host") or [None])[0],
                "process": (values_by_type.get("process") or [None])[0],
                "ip": (values_by_type.get("ip") or [None])[0],
                "entities": [value["canonical_value"] for value in resolved],
                "resolved_entities": resolved,
                "template_id": parsed.template_id,
                "template": parsed.fields.get("template", ""),
                "risk": round(final_score * 100),
                "score": final_score,
                "severity": severity,
                "reasons": list(dict.fromkeys(reasons)),
                "module_scores": module_scores,
                "pipeline": "m0-m6-prototype-v1",
                "labels_used": False,
            }
            events.append(event)
            if final_score >= 0.55:
                window_id = f"WIN-{event_id}"
                event["findingId"] = window_id
                event["findingTitle"] = f"上传日志风险：{frame.action}"
                windows.append({
                    "id": window_id,
                    "title": event["findingTitle"],
                    "severity": severity,
                    "score": final_score,
                    "start": item["timestamp"],
                    "end": item["timestamp"],
                    "status": "new",
                    "eventCount": 1,
                    "entities": event["entities"],
                    "hosts": values_by_type.get("host", []),
                    "sourceTypes": [f"实时上传/{filename}"],
                    "summary": "；".join(event["reasons"]),
                    "events": [event],
                    "moduleScores": module_scores,
                    "provenance": {"job_id": job_id, "source_id": source_id, "labels_used": False},
                })
            if final_score >= 0.45:
                previous_risky.append({"id": event_id, "entity_keys": entity_keys, "time": item["timestamp"]})

        investigation: dict[str, Any] | None = None
        if windows:
            investigation = {
                "id": f"CASE-{job_id[4:]}",
                "title": f"{filename} 实时导入候选链",
                "severity": max((window["severity"] for window in windows), key=lambda value: {"info": 0, "low": 1, "medium": 2, "high": 3}.get(value, 0)),
                "status": "investigating",
                "windowIds": [window["id"] for window in windows[:50]],
                "owner": "m0-m6-ingestion",
                "createdAt": started.isoformat().replace("+00:00", "Z"),
                "summary": "由实时上传文件经过 M0-M6 原型链路生成；真实标签未参与检测。",
                "source_id": source_id,
            }

        finished = datetime.now(timezone.utc)
        duration = max(time.perf_counter() - started_clock, 0.0001)
        source = {
            "id": source_id,
            "name": filename,
            "path": f"upload://{source_id}/{filename}",
            "kind": "实时上传 · M0-M6",
            "status": "online",
            "size": f"{len(events):,} 条 / {len(content):,} B",
            "lastRead": finished.isoformat().replace("+00:00", "Z"),
            "event_count": len(events),
            "finding_count": len(windows),
        }
        job = {
            "id": job_id,
            "name": filename,
            "kind": Path(filename).suffix.lower().lstrip(".").upper() or "TEXT",
            "size": len(content),
            "progress": 100,
            "status": "ready",
            "result": f"M0-M6 完成：{len(events)} 条事件，{len(windows)} 个风险发现",
            "source_id": source_id,
            "event_count": len(events),
            "finding_count": len(windows),
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": finished.isoformat().replace("+00:00", "Z"),
            "duration_seconds": round(duration, 4),
            "events_per_second": round(len(events) / duration, 2),
            "throughput_scope": "small_sample_functional_check",
            "pipeline": "m0-m6-prototype-v1",
            "stage_mean_scores": {key: round(value / len(events), 4) for key, value in stage_totals.items()},
            "labels_used": False,
            "content_type": content_type,
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        with self._connect() as connection:
            connection.execute("INSERT INTO jobs VALUES (?, ?, ?)", (job_id, job["started_at"], _json(job)))
            connection.execute("INSERT INTO sources VALUES (?, ?, ?)", (source_id, job["started_at"], _json(source)))
            connection.executemany(
                "INSERT INTO events VALUES (?, ?, ?, ?)",
                [(event["id"], source_id, event["timestamp"], _json(event)) for event in events],
            )
            connection.executemany(
                "INSERT INTO windows VALUES (?, ?, ?, ?)",
                [(window["id"], source_id, window["start"], _json(window)) for window in windows],
            )
            if investigation:
                connection.execute(
                    "INSERT INTO investigations VALUES (?, ?, ?, ?)",
                    (investigation["id"], source_id, job["started_at"], _json(investigation)),
                )
        return {"job": job, "source": source, "events": events, "windows": windows, "investigation": investigation}

    def _payloads(self, table: str, order_by: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(f"SELECT payload FROM {table} ORDER BY {order_by}").fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def snapshot(self, event_limit: int = 5000) -> dict[str, Any]:
        limit = max(1, min(event_limit, 20_000))
        with self._connect() as connection:
            event_rows = connection.execute("SELECT payload FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return {
            "events": [json.loads(row["payload"]) for row in event_rows],
            "event_count": total,
            "event_limit": limit,
            "windows": self._payloads("windows", "timestamp DESC"),
            "investigations": self._payloads("investigations", "created_at DESC"),
            "sources": self._payloads("sources", "created_at DESC"),
            "jobs": self._payloads("jobs", "created_at DESC"),
            "manifest": self.manifest(),
        }

    def manifest(self) -> dict[str, Any]:
        with self._connect() as connection:
            counts = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("jobs", "sources", "events", "windows", "investigations")
            }
        return {
            "pipeline": "m0-m6-prototype-v1",
            "stages": {
                "M0": "Drain 日志模板解析",
                "M1": "语义标准化与无标签弱监督信号",
                "M2": "实体抽取、规范化与文件内稀有度",
                "M3": "实体图上下文与关系新颖度",
                "M4": "无监督模板稀有度和失败上下文",
                "M5": "共享实体的长时风险关联",
                "M6": "可解释加权风险融合",
            },
            "model_execution": "explainable_prototype",
            "labels_used_for_detection": False,
            "persistent_store": "sqlite",
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "supported_suffixes": sorted(SUPPORTED_SUFFIXES),
            "counts": counts,
        }

    def search(self, *, entities: list[str], source_types: list[str], keywords: list[str], start_time: str | None, end_time: str | None, limit: int) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM events ORDER BY timestamp DESC LIMIT 20000").fetchall()
        needles = [value.lower() for value in [*entities, *keywords] if value]
        sources = {value.lower() for value in source_types if value}
        matched: list[dict[str, Any]] = []
        for row in rows:
            event = json.loads(row["payload"])
            text = _json(event).lower()
            if needles and not all(value in text for value in needles):
                continue
            if sources and str(event.get("source_type", event.get("source", ""))).lower() not in sources:
                continue
            timestamp = str(event.get("timestamp", ""))
            if start_time and timestamp < start_time:
                continue
            if end_time and timestamp > end_time:
                continue
            matched.append(event)
            if len(matched) >= max(1, min(limit, 200)):
                break
        return {"count": len(matched), "events": matched}


ingestion_store = IngestionStore()
