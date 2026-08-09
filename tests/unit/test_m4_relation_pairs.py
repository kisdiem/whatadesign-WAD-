from src.common.schema import EventFrame
from src.training.m4_relation_pairs import build_source_relation_triplets
from src.training.m4_source_dataset import SourceTarget


def _frame(record_id: str, timestamp: str, entities: list[str]) -> EventFrame:
    return EventFrame(dataset_id="source", record_id=record_id, timestamp=timestamp, entities=entities)


def test_relation_triplet_is_causal_and_entity_fact_based() -> None:
    frames = [
        _frame("positive", "2026-08-10T10:05:00Z", ["host-1"]),
        _frame("negative", "2026-08-10T10:10:00Z", ["host-2"]),
        _frame("anchor", "2026-08-10T10:20:00Z", ["host-1"]),
    ]
    targets = [SourceTarget(frame.record_id, "source", frame.timestamp or "", "train") for frame in frames]

    triplets = build_source_relation_triplets(targets, {"source": frames})

    triplet = triplets[("source", "anchor")]
    assert triplet.positive_record_id == "positive"
    assert triplet.negative_record_id == "negative"


def test_relation_triplet_excludes_future_and_outside_history() -> None:
    frames = [
        _frame("outside", "2026-08-10T09:40:00Z", ["host-1"]),
        _frame("future", "2026-08-10T10:25:00Z", ["host-1"]),
        _frame("negative", "2026-08-10T10:10:00Z", ["host-2"]),
        _frame("anchor", "2026-08-10T10:20:00Z", ["host-1"]),
    ]
    targets = [SourceTarget(frame.record_id, "source", frame.timestamp or "", "train") for frame in frames]

    assert ("source", "anchor") not in build_source_relation_triplets(targets, {"source": frames})
