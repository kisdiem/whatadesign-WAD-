"""ATT&CK technique cards and label-isolated supervision contracts.

Technique identifiers are database/output keys only.  The semantic model sees
the natural-language card, never the opaque identifier as an input feature.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


FORBIDDEN_EVENT_KEYS = frozenset({
    "target_label", "attack_label", "anomaly_label", "is_attack", "label",
    "ground_truth", "split", "scenario_truth", "post_hoc_score",
})


@dataclass(frozen=True)
class TechniqueCard:
    """Human-readable ATT&CK knowledge used for semantic candidate matching."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    procedure_examples: tuple[str, ...] = ()
    data_sources: tuple[str, ...] = ()
    detection_signals: tuple[str, ...] = ()
    exclusion_notes: tuple[str, ...] = ()
    version: str = "attack-card-v1"

    def semantic_text(self) -> str:
        """Return the language-model input; intentionally excludes technique_id."""
        parts = [
            f"Technique: {self.name}",
            f"Tactics: {', '.join(self.tactics)}",
            f"Description: {self.description}",
        ]
        if self.procedure_examples:
            parts.append(f"Procedure examples: {'; '.join(self.procedure_examples)}")
        if self.data_sources:
            parts.append(f"Data sources: {', '.join(self.data_sources)}")
        if self.detection_signals:
            parts.append(f"Detection signals: {'; '.join(self.detection_signals)}")
        if self.exclusion_notes:
            parts.append(f"Do not infer from: {'; '.join(self.exclusion_notes)}")
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TechniqueSupervision:
    """A label record stored separately from EventFrame and model features."""

    record_id: str
    technique_id: str
    provenance: str
    confidence: float
    disposition: str = "candidate"
    reviewer: str | None = None
    notes: str | None = None
    version: str = "attack-supervision-v1"

    def __post_init__(self) -> None:
        if not self.record_id or not self.technique_id:
            raise ValueError("record_id and technique_id are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_event_payload(value: Any) -> None:
    """Reject labels before an event enters an ATT&CK semantic feature path."""
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in FORBIDDEN_EVENT_KEYS:
                raise ValueError(f"ATT&CK semantic input refuses forbidden field: {key}")
            validate_event_payload(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            validate_event_payload(nested)


def cards_from_stix(objects: list[dict[str, Any]]) -> list[TechniqueCard]:
    """Build stable cards from official ATT&CK STIX attack-pattern objects."""
    cards: list[TechniqueCard] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_ids = [
            ref.get("external_id", "") for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ]
        if not external_ids:
            continue
        tactics = tuple(sorted({phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", []) if phase.get("phase_name")}))
        data_sources = tuple(sorted({str(item) for item in obj.get("x_mitre_data_sources", [])}))
        cards.append(TechniqueCard(
            technique_id=external_ids[0],
            name=obj.get("name", "Unknown technique"),
            tactics=tactics,
            description=obj.get("description", ""),
            data_sources=data_sources,
        ))
    return sorted(cards, key=lambda card: card.technique_id)
