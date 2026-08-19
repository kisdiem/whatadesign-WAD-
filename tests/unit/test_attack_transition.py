from src.common.schema import EventFrame
from src.temporal.attack_transition import build_transition_candidates


def frame(record_id, timestamp, host="host-a"):
    return EventFrame(record_id=record_id, dataset_id="source", timestamp=timestamp, entity_mentions=[{"entity_type": "host", "raw_value": host}])


def mapping(record_id, technique, tactic, confidence=0.8, disposition="candidate"):
    return {"record_id": record_id, "candidates": [{"technique_id": technique, "tactic_id": tactic, "confidence": confidence, "mapping_source": "test", "disposition": disposition}]}


def test_transition_requires_shared_entity_and_forward_tactic_order():
    items = build_transition_candidates(
        [frame("a", "2022-01-01T00:00:00+00:00"), frame("b", "2022-01-01T00:10:00+00:00")],
        [mapping("a", "T1595", "reconnaissance"), mapping("b", "T1505.003", "persistence")],
    )
    assert len(items) == 1
    assert items[0].source_event_id == "a"


def test_transition_does_not_link_review_only_or_different_entities():
    items = build_transition_candidates(
        [frame("a", "2022-01-01T00:00:00+00:00"), frame("b", "2022-01-01T00:10:00+00:00", "host-b")],
        [mapping("a", "T1595", "reconnaissance", disposition="review_only"), mapping("b", "T1505.003", "persistence")],
    )
    assert items == []
