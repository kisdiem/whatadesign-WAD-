from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


FORBIDDEN_TARGET_FIELDS = frozenset({"label", "labels", "ground_truth", "target", "is_attack"})
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b(?:host|computer|dst_host|server)[=: ]+([A-Za-z0-9_.-]+)", re.I)
USER_RE = re.compile(r"\b(?:user|account|principal)[=: ]+([A-Za-z0-9_.\\@-]+)", re.I)
PROCESS_RE = re.compile(r"\b([A-Za-z0-9_.-]+\.(?:exe|dll|ps1|sh|php))\b", re.I)
DOMAIN_RE = re.compile(r"\b(?:query|domain|qname)[=: ]+([A-Za-z0-9_.-]+)", re.I)


def parse_timestamp(value: str) -> datetime:
    normalized = str(value).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", normalized):
        numeric = float(normalized)
        if numeric > 10_000_000_000:
            numeric /= 1000.0
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00").replace(" ", "T"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class LogEvent:
    event_id: str
    timestamp: str
    source_type: str
    message: str
    source_file: str
    source_line: int
    fields: dict[str, Any] = field(default_factory=dict)
    entities: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _entities(message: str, fields: dict[str, Any], structured: bool = False) -> tuple[str, ...]:
    values: list[str] = []
    for key in ("host", "user", "src_ip", "dst_ip", "process", "domain"):
        if fields.get(key):
            values.append(str(fields[key]))
    patterns = (IP_RE, PROCESS_RE) if structured else (IP_RE, HOST_RE, USER_RE, PROCESS_RE, DOMAIN_RE)
    for pattern in patterns:
        for match in pattern.findall(message):
            values.append(match if isinstance(match, str) else match[0])
    return tuple(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def load_jsonl(path: str | Path) -> Iterator[LogEvent]:
    """Stream unlabelled logs and fail closed if evaluation targets leak in."""
    source = Path(path)
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            row = json.loads(raw_line)
            leaked = FORBIDDEN_TARGET_FIELDS.intersection(row)
            if leaked:
                raise ValueError(f"target leakage in detector input at line {line_number}: {sorted(leaked)}")
            message = str(row.get("message", row.get("raw", ""))).strip()
            timestamp = str(row.get("timestamp", "")).strip()
            if not timestamp or not message:
                raise ValueError(f"timestamp and message are required at line {line_number}")
            parse_timestamp(timestamp)
            fields = dict(row.get("fields", {}))
            event_id = str(row.get("event_id") or hashlib.sha256(
                f"{source}|{line_number}|{timestamp}|{message}".encode()
            ).hexdigest()[:20])
            yield LogEvent(
                event_id=event_id,
                timestamp=timestamp,
                source_type=str(row.get("source_type", "unknown")),
                message=message,
                source_file=str(source),
                source_line=line_number,
                fields=fields,
                entities=_entities(message, fields),
            )


def write_json(path: str | Path, payload: Any) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return target
