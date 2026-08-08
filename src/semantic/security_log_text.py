from __future__ import annotations

from collections.abc import Mapping


RESERVED = {"label", "class", "attack", "malicious", "ground_truth"}


def security_log_text(dataset_id: str, payload: Mapping[str, object] | str) -> str:
    """Stable, label-free field serialization for DeBERTa security training."""
    if isinstance(payload, str):
        return f"[DATASET] {dataset_id} [MESSAGE] {payload[:4096]}"
    fields = []
    for key, value in sorted(payload.items(), key=lambda item: str(item[0])):
        if str(key).lower() in RESERVED: continue
        normalized = " ".join(str(value).replace("\n", " ").split())[:256]
        if normalized: fields.append(f"[FIELD] {key} [VALUE] {normalized}")
    return f"[DATASET] {dataset_id} " + " ".join(fields)
