"""Sparse, fact-anchored ATT&CK transition candidates for M5.

This is not an ATT&CK labeler.  It keeps the complete event timeline outside
the module and emits only transitions supported by two high-confidence event
candidates sharing a stable entity.  IP-only and review-only hypotheses cannot
create transitions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from src.common.schema import EventFrame


TACTIC_ORDER = {
    "reconnaissance": 10,
    "resource-development": 20,
    "initial-access": 30,
    "execution": 40,
    "persistence": 50,
    "privilege-escalation": 60,
    "defense-evasion": 70,
    "credential-access": 80,
    "discovery": 90,
    "lateral-movement": 100,
    "collection": 110,
    "command-and-control": 120,
    "exfiltration": 130,
    "impact": 140,
}
STABLE_ENTITY_TYPES = frozenset({"user", "host", "process", "session", "file", "domain", "service"})


@dataclass(frozen=True)
class TransitionConfig:
    min_confidence: float = 0.55
    max_gap_seconds: int = 24 * 3600
    max_predecessors_per_event: int = 8
    version: str = "m5-attack-transition-v1"


@dataclass(frozen=True)
class TransitionCandidate:
    source_event_id: str
    target_event_id: str
    dataset_id: str
    entity_key: str
    source_technique_id: str
    target_technique_id: str
    source_tactic: str
    target_tactic: str
    delta_seconds: float
    confidence: float
    evidence: dict[str, Any]
    version: str = "m5-attack-transition-v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def stable_entity_keys(frame: EventFrame) -> tuple[str, ...]:
    keys = []
    for mention in frame.entity_mentions:
        if not isinstance(mention, dict):
            continue
        entity_type = str(mention.get("entity_type", "")).lower()
        value = str(mention.get("canonical_value", mention.get("raw_value", ""))).strip().lower()
        if entity_type in STABLE_ENTITY_TYPES and value and value not in {"unknown", "-"}:
            keys.append(f"{entity_type}:{value}")
    return tuple(sorted(set(keys)))


def _eligible(row: dict, config: TransitionConfig) -> list[dict]:
    return [
        candidate for candidate in row.get("candidates", [])
        if candidate.get("disposition", "candidate") == "candidate"
        and float(candidate.get("confidence", 0.0)) >= config.min_confidence
        and str(candidate.get("tactic_id", "")) in TACTIC_ORDER
    ]


def build_transition_candidates(
    frames: Iterable[EventFrame], mapping_rows: Iterable[dict], config: TransitionConfig | None = None,
) -> list[TransitionCandidate]:
    config = config or TransitionConfig()
    frame_by_id = {frame.record_id: frame for frame in frames}
    rows = []
    for row in mapping_rows:
        frame = frame_by_id.get(str(row.get("record_id", "")))
        stamp = _timestamp(frame.timestamp) if frame else None
        candidates = _eligible(row, config)
        if frame and stamp and candidates:
            rows.append((stamp, frame, candidates))
    rows.sort(key=lambda item: (item[0], item[1].record_id))

    timelines: dict[str, list[tuple[datetime, EventFrame, dict]]] = {}
    result: list[TransitionCandidate] = []
    emitted: set[tuple[str, str, str, str, str]] = set()
    for stamp, frame, candidates in rows:
        entity_keys = stable_entity_keys(frame)
        for target in candidates:
            target_rank = TACTIC_ORDER[target["tactic_id"]]
            for entity_key in entity_keys:
                history = timelines.get(entity_key, [])
                considered = 0
                for prior_stamp, prior_frame, source in reversed(history):
                    delta = (stamp - prior_stamp).total_seconds()
                    if delta > config.max_gap_seconds:
                        break
                    if source["technique_id"] == target["technique_id"] or TACTIC_ORDER[source["tactic_id"]] > target_rank:
                        continue
                    key = (entity_key, prior_frame.record_id, frame.record_id, source["technique_id"], target["technique_id"])
                    if key in emitted:
                        continue
                    emitted.add(key); considered += 1
                    result.append(TransitionCandidate(
                        source_event_id=prior_frame.record_id, target_event_id=frame.record_id,
                        dataset_id=frame.dataset_id, entity_key=entity_key,
                        source_technique_id=source["technique_id"], target_technique_id=target["technique_id"],
                        source_tactic=source["tactic_id"], target_tactic=target["tactic_id"],
                        delta_seconds=delta,
                        confidence=min(float(source["confidence"]), float(target["confidence"])),
                        evidence={"shared_entity": entity_key, "source_mapping": source["mapping_source"], "target_mapping": target["mapping_source"]},
                        version=config.version,
                    ))
                    if considered >= config.max_predecessors_per_event:
                        break
        for entity_key in entity_keys:
            timelines.setdefault(entity_key, []).extend((stamp, frame, candidate) for candidate in candidates)
    return result
