from __future__ import annotations

import csv
import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

from .schema import FORBIDDEN_TARGET_FIELDS, LogEvent, _entities, parse_timestamp


EXCLUDED_PARTS = frozenset({"labels", "rules", "environment", "processing", ".git", "node_modules", "__pycache__"})
EXCLUDED_SUFFIXES = frozenset({".pcap", ".evtx", ".etl", ".journal", ".gz", ".rules", ".py", ".pyc", ".pdf", ".png", ".jpg"})
TEXT_SUFFIXES = frozenset({".log", ".txt", ".json", ".jsonl"})
TARGET_COLUMNS = frozenset({"EVTX_Tactic", "label", "labels", "ground_truth", "target", "is_attack"})
SYSLOG_TS = re.compile(r"^(?:<\d+>)?(?P<ts>\d{4}-\d{2}-\d{2}[T ][^ ]+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")


@dataclass(frozen=True)
class SourceDescriptor:
    path: str
    kind: str
    size_bytes: int
    member: str | None = None

    @property
    def identity(self) -> str:
        return f"{self.path}::{self.member}" if self.member else self.path


@dataclass
class ReadStats:
    records: int = 0
    rejected: int = 0
    bytes_declared: int = 0
    bytes_read: int = 0


def discover_sources(roots: Iterable[str | Path]) -> tuple[list[SourceDescriptor], list[str]]:
    sources: list[SourceDescriptor] = []
    exclusions: list[str] = []
    for raw_root in roots:
        root = Path(raw_root)
        if not root.exists():
            exclusions.append(f"missing:{root}")
            continue
        if root.is_file():
            candidates = [root]
        elif (root / "gather").is_dir():
            candidates = list((root / "gather").rglob("*"))
            if (root / "labels").exists():
                exclusions.append(f"labels-directory:{root / 'labels'}")
        elif (root / "evtx_data.csv").is_file():
            # The CSV is the unlabelled event projection. Repository metadata and
            # ATT&CK mapping files are deliberately outside the detection surface.
            candidates = [root / "evtx_data.csv"]
            exclusions.append(f"evtx-metadata-and-binaries:{root}")
        else:
            candidates = list(root.rglob("*"))
        for path in candidates:
            if not path.is_file():
                continue
            relative_parts = {part.lower() for part in path.relative_to(root).parts}
            if relative_parts.intersection(EXCLUDED_PARTS) or path.name.lower() == "labels.csv":
                exclusions.append(str(path))
                continue
            lower_name = path.name.lower()
            if lower_name == "evtx_data.csv":
                sources.append(SourceDescriptor(str(path), "evtx_csv", path.stat().st_size))
            elif path.suffix.lower() == ".zip" and lower_name == "ait_ads.zip":
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if not info.is_dir() and info.filename.lower().endswith((".json", ".jsonl")):
                            sources.append(SourceDescriptor(str(path), "zip_jsonl", info.file_size, info.filename))
            elif lower_name == "eve.json":
                sources.append(SourceDescriptor(str(path), "suricata_jsonl", path.stat().st_size))
            elif lower_name == "traffic.json":
                sources.append(SourceDescriptor(str(path), "traffic_jsonl", path.stat().st_size))
            elif path.suffix.lower() in TEXT_SUFFIXES and lower_name != "stats.log":
                sources.append(SourceDescriptor(str(path), "auto_text", path.stat().st_size))
            elif path.suffix.lower() in EXCLUDED_SUFFIXES or ".pcap." in lower_name:
                exclusions.append(str(path))
    unique = {source.identity: source for source in sources}
    return sorted(unique.values(), key=lambda item: item.identity), exclusions


def _first(row: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value: Any = row
        for part in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value not in (None, "", "-"):
            return value
    return None


def _normal_timestamp(value: Any) -> str | None:
    if value in (None, "", "-"):
        return None
    try:
        return parse_timestamp(str(value)).astimezone(timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def _event_from_json(row: dict[str, Any], descriptor: SourceDescriptor, line_number: int) -> LogEvent | None:
    if FORBIDDEN_TARGET_FIELDS.intersection(row):
        raise ValueError(f"target leakage in {descriptor.identity}:{line_number}")
    if row.get("event_type") == "stats":
        return None
    timestamp = _normal_timestamp(_first(row, "timestamp", "@timestamp", "time", "LogData.Timestamps.0", "predecoder.timestamp"))
    if not timestamp:
        return None
    source_type = str(_first(row, "event_type", "event.dataset", "decoder.name", "protocol", "AnalysisComponent.AnalysisComponentType") or descriptor.kind)
    dns = _first(row, "dns.rrname", "dns.query.0.rrname", "data.dns.rrname", "data.dns.query.0.rrname")
    signature = _first(row, "alert.signature", "rule.description")
    message = str(_first(row, "message", "raw", "full_log", "info", "AnalysisComponent.Message") or "")
    if not message:
        summary = {key: value for key, value in {
            "event_type": row.get("event_type"), "signature": signature, "dns_query": dns,
            "src_ip": _first(row, "src_ip", "source"), "dst_ip": _first(row, "dest_ip", "destination"),
            "protocol": row.get("protocol"), "flow_id": row.get("flow_id"),
        }.items() if value not in (None, "")}
        message = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
    fields = {
        "host": _first(row, "host.name", "agent.name", "hostname"),
        "user": _first(row, "user.name", "data.user", "username"),
        "src_ip": _first(row, "src_ip", "source", "data.src_ip", "agent.ip"),
        "dst_ip": _first(row, "dest_ip", "destination", "data.dest_ip"),
        "process": _first(row, "process.name", "process.executable", "data.process.name"),
        "domain": dns,
    }
    fields = {key: value for key, value in fields.items() if value not in (None, "")}
    event_id = str(_first(row, "event_id", "id", "flow_id") or hashlib.sha256(f"{descriptor.identity}|{line_number}".encode()).hexdigest()[:20])
    return LogEvent(event_id, timestamp, source_type, message[:8192], descriptor.identity, line_number, fields, _entities(message, fields, structured=True))


def _iter_text_lines(lines: Iterable[str], descriptor: SourceDescriptor, stats: ReadStats) -> Iterator[LogEvent]:
    file_mtime = Path(descriptor.path).stat().st_mtime
    fallback_timestamp = parse_timestamp(str(file_mtime)).isoformat()
    for line_number, raw in enumerate(lines, 1):
        stats.bytes_read += len(raw.encode("utf-8", errors="replace"))
        raw = raw.strip()
        if not raw:
            continue
        try:
            if raw.startswith("{"):
                event = _event_from_json(json.loads(raw), descriptor, line_number)
            else:
                match = SYSLOG_TS.search(raw)
                timestamp = _normal_timestamp(match.group("ts")) if match and "-" in match.group("ts") else fallback_timestamp
                fields: dict[str, Any] = {}
                event = LogEvent(hashlib.sha256(f"{descriptor.identity}|{line_number}".encode()).hexdigest()[:20], timestamp or fallback_timestamp, "text_log", raw[:8192], descriptor.identity, line_number, fields, _entities(raw, fields))
            if event is not None:
                stats.records += 1
                yield event
        except (ValueError, json.JSONDecodeError, TypeError):
            stats.rejected += 1


def _iter_evtx_csv(descriptor: SourceDescriptor, stats: ReadStats) -> Iterator[LogEvent]:
    with Path(descriptor.path).open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for line_number, row in enumerate(csv.DictReader(handle), 2):
            stats.bytes_read += sum(len(str(value).encode("utf-8", errors="replace")) for value in row.values() if value)
            timestamp = _normal_timestamp(row.get("SystemTime") or row.get("UtcTime"))
            if not timestamp:
                stats.rejected += 1
                continue
            safe = {key: value for key, value in row.items() if key not in TARGET_COLUMNS and value not in (None, "", "-")}
            fields = {"host": safe.get("Computer"), "user": safe.get("TargetUserName") or safe.get("SubjectUserName"), "src_ip": safe.get("SourceIp") or safe.get("IpAddress"), "dst_ip": safe.get("DestinationIp"), "process": safe.get("Image") or safe.get("ProcessName")}
            fields = {key: value for key, value in fields.items() if value}
            message_fields = ("EventID", "ProviderName", "Channel", "Computer", "Image", "CommandLine", "ScriptBlockText", "SourceIp", "DestinationIp", "TargetUserName", "ObjectName")
            message = " ".join(f"{key}={safe[key]}" for key in message_fields if safe.get(key))
            event_id = hashlib.sha256(f"{descriptor.identity}|{line_number}".encode()).hexdigest()[:20]
            stats.records += 1
            yield LogEvent(event_id, timestamp, "EVTX", message[:8192], descriptor.identity, line_number, fields, _entities(message, fields, structured=True))


def iter_source(descriptor: SourceDescriptor, stats: ReadStats | None = None) -> Iterator[LogEvent]:
    stats = stats or ReadStats()
    stats.bytes_declared += descriptor.size_bytes
    if descriptor.kind == "evtx_csv":
        yield from _iter_evtx_csv(descriptor, stats)
    elif descriptor.kind == "zip_jsonl":
        with zipfile.ZipFile(descriptor.path) as archive, archive.open(descriptor.member or "") as binary:
            lines = (line.decode("utf-8", errors="replace") for line in binary)
            yield from _iter_text_lines(lines, descriptor, stats)
    else:
        with Path(descriptor.path).open("r", encoding="utf-8", errors="replace") as handle:
            yield from _iter_text_lines(handle, descriptor, stats)


def iter_all(sources: Iterable[SourceDescriptor], max_records: int = 0, stats: ReadStats | None = None) -> Iterator[LogEvent]:
    stats = stats or ReadStats()
    emitted = 0
    for source in sources:
        for event in iter_source(source, stats):
            yield event
            emitted += 1
            if max_records and emitted >= max_records:
                return


def batched(events: Iterable[LogEvent], batch_size: int) -> Iterator[list[LogEvent]]:
    batch: list[LogEvent] = []
    for event in events:
        batch.append(event)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch
