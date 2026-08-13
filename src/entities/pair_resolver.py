from __future__ import annotations
from src.common.schema import EntityRecord


class PairResolver:
    def score(self, left: EntityRecord, right: EntityRecord) -> tuple[float, str]:
        if left.dataset_id != right.dataset_id or left.entity_type != right.entity_type:
            return 0.0, "scope_mismatch"
        if left.entity_type == "ip":
            return 0.0, "weak_ip_only"
        return (1.0, "canonical_and_scope_match") if left.entity_id == right.entity_id else (0.0, "no_match")
