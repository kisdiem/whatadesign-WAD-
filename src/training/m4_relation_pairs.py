from __future__ import annotations

"""Source-fact temporal/M3 relation triplets for M4 contrastive training.

The builder uses only timestamps and M2 entity resolution.  It deliberately
does not inspect loss labels, target labels, AIT metadata, or model scores.
"""

from dataclasses import dataclass
from datetime import datetime

from src.common.schema import EventFrame
from src.entities.m2_resolver import M2EntityResolver
from src.training.m4_source_dataset import SourceTarget
from src.training.m4_window_cache import parse_utc


@dataclass(frozen=True)
class SourceRelationTriplet:
    dataset_id: str
    anchor_record_id: str
    positive_record_id: str
    negative_record_id: str


def build_source_relation_triplets(
    targets: list[SourceTarget],
    frames_by_dataset: dict[str, list[EventFrame]],
    *,
    window_seconds: int = 1800,
) -> dict[tuple[str, str], SourceRelationTriplet]:
    """Build one causal M3-style positive/negative triplet per usable target.

    The positive shares an M2-resolved entity with the anchor.  The negative
    is from the same causal history but has no shared resolved entity.  Both
    are earlier than the anchor and must themselves be selected targets so a
    strict M4 cache exists for every branch of the contrastive objective.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    resolver = M2EntityResolver()
    selected = {(target.dataset_id, target.record_id) for target in targets}
    result: dict[tuple[str, str], SourceRelationTriplet] = {}
    for anchor in targets:
        rows = frames_by_dataset.get(anchor.dataset_id, [])
        by_id = {frame.record_id: frame for frame in rows}
        anchor_frame = by_id.get(anchor.record_id)
        if anchor_frame is None or not anchor_frame.timestamp:
            continue
        current = parse_utc(anchor_frame.timestamp)
        anchor_entities = {item.entity_id for item in resolver.resolve(anchor_frame)}
        if not anchor_entities:
            continue
        history: list[tuple[datetime, EventFrame, set[str]]] = []
        for candidate in rows:
            if candidate.record_id == anchor.record_id or not candidate.timestamp:
                continue
            key = (anchor.dataset_id, candidate.record_id)
            if key not in selected:
                continue
            stamp = parse_utc(candidate.timestamp)
            delta = (current - stamp).total_seconds()
            if not 0 < delta <= window_seconds:
                continue
            history.append((stamp, candidate, {item.entity_id for item in resolver.resolve(candidate)}))
        positives = [row for row in history if anchor_entities & row[2]]
        negatives = [row for row in history if not (anchor_entities & row[2])]
        if not positives or not negatives:
            continue
        # Most recent factual relation is the least temporally confounded.
        positive = max(positives, key=lambda row: row[0])[1]
        negative = max(negatives, key=lambda row: row[0])[1]
        result[(anchor.dataset_id, anchor.record_id)] = SourceRelationTriplet(
            dataset_id=anchor.dataset_id,
            anchor_record_id=anchor.record_id,
            positive_record_id=positive.record_id,
            negative_record_id=negative.record_id,
        )
    return result
