from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RawRecord:
    dataset_id: str
    source_file: str
    source_line: int
    raw_timestamp: str | None
    raw_payload: str | dict[str, Any]
    parser_version: str


@dataclass(frozen=True)
class SyntaxParse:
    dataset_id: str
    record_id: str
    source_file: str
    source_line: int
    format: str
    timestamp: str | None
    fields: dict[str, Any]
    template_id: str
    parse_confidence: float
    raw_record_ref: str
    quarantined: bool = False
    quarantine_reason: str | None = None


@dataclass(frozen=True)
class EventFrame:
    record_id: str
    actor: dict[str, Any] = field(default_factory=dict)
    action: str = "unknown"
    object: dict[str, Any] = field(default_factory=dict)
    location: dict[str, Any] = field(default_factory=dict)
    outcome: str = "unknown"
    entities: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    semantic_confidence: float = 0.0
    source_record_ref: str = ""


@dataclass(frozen=True)
class FeatureRecord:
    record_id: str
    dataset_id: str
    timestamp: str | None
    raw_m4_score: float = 0.0
    graph_score: float = 0.0
    long_horizon_score: float = 0.0
    source_record_ref: str = ""
    release_id: str = ""


def stable_record_id(dataset_id: str, source_file: str, source_line: int) -> str:
    import hashlib

    value = f"{dataset_id}|{source_file}|{source_line}".encode()
    return hashlib.sha256(value).hexdigest()
