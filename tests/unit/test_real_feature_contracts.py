from datetime import datetime, timedelta, timezone
import hashlib

from src.common.schema import EventFrame
from src.graph.m3_graph import M3EventGraphBuilder
from src.semantic.m1_encoder import BackboneAdapter, M1Encoder


def _frame(record_id, stamp, embedding=None):
    return EventFrame(dataset_id="ait", record_id=record_id, timestamp=stamp, action="read",
                      semantic_embedding=embedding or [0.1, 0.2])


def test_m1_embedding_is_persisted_in_event_frame():
    encoder = M1Encoder(BackboneAdapter(mode="mock", hidden_size=4), projection_dim=2)
    frame = encoder.build_event_frame({"embedding": [1.0, 2.0]}, dataset_id="ait", record_id="r1", timestamp=None, source_record_ref="s")
    assert frame.semantic_embedding == [1.0, 2.0]


def test_m3_history_is_causal_and_30_minutes():
    current = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [(_frame("old", (current - timedelta(minutes=31)).isoformat()), []),
            (_frame("inside", (current - timedelta(minutes=5)).isoformat()), []),
            (_frame("future", (current + timedelta(minutes=1)).isoformat()), []),
            (_frame("cur", current.isoformat()), [])]
    graph, rejected = M3EventGraphBuilder().build_history_before_current_event(rows, "cur", current.isoformat())
    event_nodes = {node.node_id for node in graph.nodes if node.node_type == "event"}
    assert event_nodes == {"event:inside"}
    assert {row["record_id"] for row in rejected} == {"old", "future", "cur"}


def test_m3_uses_frame_timestamp_for_graph_bounds():
    frame = _frame("r", "2026-01-01T00:00:00+00:00", [3.0, 4.0])
    graph = M3EventGraphBuilder().build([(frame, [])])
    assert graph.window_start == frame.timestamp
