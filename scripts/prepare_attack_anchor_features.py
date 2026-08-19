"""Create real frozen M1 features for auditable ATT&CK anchor events.

Technique supervision is intentionally not read by this script.  It turns raw
EVTX XML into a structured, label-free EventFrame serialization and encodes it
with a locally available frozen DeBERTa model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

import torch

from src.common.schema import EventFrame
from src.knowledge.attack_techniques import TechniqueCard, validate_event_payload


FORBIDDEN_SERIALIZATION_KEYS = frozenset({
    "target_label", "attack_label", "anomaly_label", "is_attack", "label",
    "ground_truth", "split", "scenario_truth", "post_hoc_score", "technique_id",
})


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _clean(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def eventframe_from_evtx_anchor(row: dict[str, Any]) -> EventFrame:
    """Parse only event facts; source paths and anchor metadata are excluded."""
    validate_event_payload(row)
    if row.get("raw_format") == "jsonl_windows_event":
        payload = dict(row["raw_payload"])
        validate_event_payload(payload)
        facts = {key: _clean(str(value)) for key, value in payload.items() if key not in FORBIDDEN_SERIALIZATION_KEYS and value not in (None, "")}
        message = " ".join(f"{key}={value}" for key, value in sorted(facts.items()))
        return EventFrame(
            dataset_id=str(row.get("dataset_id", "otrf_security_datasets")), record_id=str(row["record_id"]),
            timestamp=str(payload.get("@timestamp", payload.get("TimeCreated", ""))) or None,
            record_kind="windows_event", relation_type="observed_event", action_family="windows_event",
            action_leaf=str(payload.get("EventID", "unknown")), roles={}, outcome="unknown",
            key_attributes={"provider": str(payload.get("SourceName", "unknown")), "event_id": str(payload.get("EventID", "unknown"))},
            entity_mentions=[], semantic_confidence=1.0, unknown_score=0.0,
            source_record_ref=f"{row.get('dataset_id', 'otrf_security_datasets')}:{row['record_id']}",
            semantic_version="m1-deberta-frozen-anchor-v1", attributes={"m1_text": message},
        )
    root = ET.fromstring(str(row["event_xml"]))
    system: dict[str, str] = {}
    data: dict[str, str] = {}
    for element in root.iter():
        name = _local_name(element.tag)
        if name == "Provider":
            system["provider"] = _clean(element.attrib.get("Name"))
        elif name in {"EventID", "Channel", "Computer"}:
            system[name.lower()] = _clean(element.text)
        elif name == "Data":
            field_name = _clean(element.attrib.get("Name")) or f"data_{len(data)}"
            data[field_name] = _clean(element.text)
    message = " ".join(f"{key}={value}" for key, value in sorted({**system, **data}.items()) if value)
    return EventFrame(
        dataset_id=str(row.get("dataset_id", "evtx_attack_samples")),
        record_id=str(row["record_id"]),
        timestamp=None,
        record_kind="windows_event",
        relation_type="observed_event",
        action_family="windows_event",
        action_leaf=system.get("eventid", "unknown"),
        roles={},
        outcome="unknown",
        key_attributes={"provider": system.get("provider", "unknown"), "event_id": system.get("eventid", "unknown")},
        entity_mentions=[],
        semantic_confidence=1.0,
        unknown_score=0.0,
        source_record_ref=f"{row.get('dataset_id', 'evtx_attack_samples')}:{row['record_id']}",
        semantic_version="m1-deberta-frozen-anchor-v1",
        attributes={"m1_text": message},
    )


def serialize_eventframe(frame: EventFrame) -> str:
    """Stable M1 text using only normalized event facts and no supervision."""
    payload = {
        "record_kind": frame.record_kind,
        "relation_type": frame.relation_type,
        "action_family": frame.action_family,
        "action_leaf": frame.action_leaf,
        "outcome": frame.outcome,
        "key_attributes": frame.key_attributes,
        "event_fields": frame.attributes.get("m1_text", ""),
    }
    validate_event_payload(payload)
    for key in payload:
        if key.lower() in FORBIDDEN_SERIALIZATION_KEYS:
            raise ValueError(f"forbidden serialization field: {key}")
    return "\n".join(f"{key}={value}" for key, value in payload.items() if value not in ({}, ""))


def masked_mean(hidden: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
    weights = mask.unsqueeze(-1).to(dtype=hidden.dtype)
    return (hidden * weights).sum(dim=1) / weights.sum(dim=1).clamp_min(1.0)


def encode_texts(texts: list[str], model_path: str, batch_size: int, device: str) -> tuple[list[list[float]], dict[str, Any]]:
    from transformers import AutoModel, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
    model = AutoModel.from_pretrained(model_path, local_files_only=True).to(device).eval()
    vectors: list[list[float]] = []
    with torch.inference_mode():
        for start in range(0, len(texts), batch_size):
            encoded = tokenizer(texts[start:start + batch_size], padding=True, truncation=True, max_length=256, return_tensors="pt")
            encoded = {key: value.to(device) for key, value in encoded.items()}
            pooled = masked_mean(model(**encoded).last_hidden_state, encoded["attention_mask"])
            vectors.extend(pooled.detach().cpu().float().tolist())
    manifest = {
        "backbone": model_path,
        "hidden_size": int(model.config.hidden_size),
        "pooling": "attention_mask_mean",
        "mode": "frozen",
        "device": device,
    }
    return vectors, manifest


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--cards", type=Path, required=True)
    parser.add_argument("--event-output", type=Path, required=True)
    parser.add_argument("--event-index-output", type=Path, required=True)
    parser.add_argument("--card-output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = parser.parse_args()

    raw_rows = list(read_jsonl(args.events))
    rows_by_id: dict[str, dict[str, Any]] = {}
    for row in raw_rows:
        prior = rows_by_id.setdefault(str(row["record_id"]), row)
        if prior["event_xml"] != row["event_xml"]:
            raise ValueError(f"record_id maps to conflicting EVTX payloads: {row['record_id']}")
    rows = [rows_by_id[record_id] for record_id in sorted(rows_by_id)]
    frames = [eventframe_from_evtx_anchor(row) for row in rows]
    event_texts = [serialize_eventframe(frame) for frame in frames]
    cards = [TechniqueCard(**row) for row in read_jsonl(args.cards)]
    card_texts = [card.semantic_text() for card in cards]
    event_vectors, model_manifest = encode_texts(event_texts, args.model_path, args.batch_size, args.device)
    card_vectors, _ = encode_texts(card_texts, args.model_path, args.batch_size, args.device)

    args.event_output.parent.mkdir(parents=True, exist_ok=True)
    with args.event_output.open("w", encoding="utf-8") as handle:
        for frame, vector in zip(frames, event_vectors, strict=True):
            payload = frame.to_dict()
            payload["semantic_embedding"] = vector
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    with args.event_index_output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps({
                "record_id": row["record_id"],
                "source_group": str(row.get("source_file", "unknown")),
                "source_record_index": row.get("source_record_index"),
            }, sort_keys=True) + "\n")
    with args.card_output.open("w", encoding="utf-8") as handle:
        for card, vector in zip(cards, card_vectors, strict=True):
            handle.write(json.dumps({"technique_id": card.technique_id, "semantic_embedding": vector, "card_version": card.version}, sort_keys=True) + "\n")
    manifest = {
        "event_count": len(frames),
        "input_anchor_rows": len(raw_rows),
        "card_count": len(cards),
        "events_sha256": sha256(args.events),
        "model": model_manifest,
        "event_feature_output": str(args.event_output),
        "event_index_output": str(args.event_index_output),
        "card_feature_output": str(args.card_output),
        "contains_supervision": False,
    }
    args.manifest_output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
