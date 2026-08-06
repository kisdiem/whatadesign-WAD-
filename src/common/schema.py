from __future__ import annotations

"""Versioned contracts shared by strict V3 stages.

The compatibility fields are retained for the legacy smoke path; strict callers
should use the explicitly named semantic, provenance, and graph fields.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar


SCHEMA_VERSION = "v3-contract-1"


class ContractError(ValueError):
    pass


class _Serializable:
    schema_version: ClassVar[str] = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, **asdict(self)}

    @classmethod
    def from_dict(cls, value: dict[str, Any]):
        if value.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
            raise ContractError(f"incompatible schema: {value.get('schema_version')}")
        payload = {k: v for k, v in value.items() if k != "schema_version"}
        return cls(**payload)


@dataclass(frozen=True)
class RawRecord(_Serializable):
    dataset_id: str
    source_file: str
    source_line: int
    raw_timestamp: str | None
    raw_payload: str | dict[str, Any]
    # parser_version remains the sixth positional field for legacy adapters.
    parser_version: str = "unknown"
    adapter_version: str = "unknown"
    raw_record_id: str = ""
    source_hash: str = ""
    ingestion_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SyntaxParse(_Serializable):
    dataset_id: str
    record_id: str
    source_file: str = ""
    source_line: int = 0
    format: str = "unknown"
    timestamp: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    template_id: str = ""
    parse_confidence: float = 0.0
    raw_record_ref: str = ""
    template_text: str = ""
    dynamic_fields: dict[str, Any] = field(default_factory=dict)
    source_record_ref: str = ""
    parser_version: str = "unknown"
    quarantined: bool = False
    quarantine_reason: str | None = None


@dataclass(frozen=True)
class EventFrame(_Serializable):
    dataset_id: str = ""
    record_id: str = ""
    timestamp: str | None = None
    record_kind: str = "unknown"
    relation_type: str = "unknown"
    action_family: str = "unknown"
    action_leaf: str = "unknown"
    roles: dict[str, Any] = field(default_factory=dict)
    outcome: str = "unknown"
    key_attributes: dict[str, Any] = field(default_factory=dict)
    entity_mentions: list[dict[str, Any] | str] = field(default_factory=list)
    semantic_embedding: list[float] | None = None
    semantic_confidence: float = 0.0
    unknown_score: float = 1.0
    source_record_ref: str = ""
    semantic_version: str = "unknown"
    # compatibility aliases
    actor: dict[str, Any] = field(default_factory=dict)
    action: str = "unknown"
    object: dict[str, Any] = field(default_factory=dict)
    location: dict[str, Any] = field(default_factory=dict)
    entities: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EntityRecord(_Serializable):
    dataset_id: str
    entity_id: str
    entity_type: str
    raw_value: str
    canonical_value: str
    instance_key: str
    host_scope: str = ""
    parent_entity_id: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: float = 0.0
    resolution_method: str = "unknown"
    source_record_refs: tuple[str, ...] = ()


ResolvedEntity = EntityRecord


@dataclass(frozen=True)
class GraphRecord(_Serializable):
    graph_id: str
    dataset_id: str
    window_start: str | None
    window_end: str | None
    current_record_id: str | None
    node_records: tuple[dict[str, Any], ...] = ()
    edge_records: tuple[dict[str, Any], ...] = ()
    graph_schema_version: str = SCHEMA_VERSION
    node_type_vocab_version: str = "v3-node-types-1"
    relation_vocab_version: str = "v3-relations-1"


@dataclass(frozen=True)
class FrozenFeatureRecord(_Serializable):
    record_id: str
    dataset_id: str
    timestamp: str | None
    semantic_embedding: list[float] = field(default_factory=list)
    semantic_confidence: float = 0.0
    unknown_score: float = 1.0
    entity_summary: dict[str, Any] = field(default_factory=dict)
    graph_embedding: list[float] = field(default_factory=list)
    graph_score: float = 0.0
    event_embedding: list[float] = field(default_factory=list)
    slot_nll: float = 0.0
    raw_event_score: float = 0.0
    micro_window_score: float = 0.0
    macro_window_score: float = 0.0
    long_horizon_score: float = 0.0
    queue_features: dict[str, Any] = field(default_factory=dict)
    source_record_ref: str = ""
    feature_schema_version: str = SCHEMA_VERSION
    producer_checkpoint_hashes: dict[str, str] = field(default_factory=dict)

    def model_features(self) -> dict[str, Any]:
        """Return only model inputs; provenance and split metadata stay out."""
        return {k: v for k, v in asdict(self).items() if k not in {
            "record_id", "dataset_id", "timestamp", "source_record_ref",
            "feature_schema_version", "producer_checkpoint_hashes",
        }}


@dataclass(frozen=True)
class FeatureRecord(_Serializable):
    record_id: str
    dataset_id: str
    timestamp: str | None
    raw_m4_score: float = 0.0
    graph_score: float = 0.0
    long_horizon_score: float = 0.0
    source_record_ref: str = ""
    release_id: str = ""


def stable_record_id(dataset_id: str, source_file: str, source_line: int) -> str:
    return hashlib.sha256(f"{dataset_id}|{source_file}|{source_line}".encode()).hexdigest()


def stable_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
