from dataclasses import replace
from datetime import datetime, timedelta, timezone

import torch

from src.common.schema import EventFrame
from src.entities.m2_resolver import M2EntityResolver
from src.graph.m3_encoder import GraphTensor
from src.graph.m3_graph import M3EventGraphBuilder
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.models.m4_qformer import M4Config, M4QFormerDecoder, freeze_m4_feature
from src.semantic.m1_multitask import M1DebertaMultiTask, M1ModelConfig
from src.temporal.window_builder import WindowBuilder
from src.temporal.m5_long_horizon import M5Config, M5LongHorizonLinker


def _frame(record_id: str, timestamp: datetime, **values) -> EventFrame:
    return EventFrame(record_id=record_id, timestamp=timestamp.isoformat(), action="process", **values)


def test_m1_embedding_is_preserved_in_eventframe():
    output = M1DebertaMultiTask(M1ModelConfig(hidden_dim=4))(torch.ones(1, 2, 4))
    frame = replace(_frame("r1", datetime.now(timezone.utc)), semantic_embedding=output["embedding"][0].tolist())
    assert frame.semantic_embedding == output["embedding"][0].tolist()


def test_macro_history_is_exactly_30min_before_current_and_no_future_leakage():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [_frame("old", now - timedelta(seconds=1801)), _frame("ok", now - timedelta(seconds=1)),
            _frame("current", now), _frame("future", now + timedelta(seconds=1))]
    resolver = M2EntityResolver()
    graph, rejected = M3EventGraphBuilder().build_history_before_current_event(
        [(frame, resolver.resolve(frame)) for frame in rows], "current", now.isoformat()
    )
    assert {node.node_id for node in graph.nodes if node.node_type == "event"} == {"event:ok"}
    assert {item["record_id"] for item in rejected} == {"old", "current", "future"}


def test_micro_window_count_overlap_partial_and_current_exclusion():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    frames = [_frame(str(index), now - timedelta(seconds=1800 - index * 60)) for index in range(30)]
    frames += [_frame("current", now), _frame("future", now + timedelta(seconds=10))]
    windows = WindowBuilder().build_micro_windows(frames, now, "current")
    assert len(windows) == 11
    assert (windows[0].end - windows[1].start).total_seconds() == 150
    assert all("current" not in window.record_ids and "future" not in window.record_ids for window in windows)
    partial = WindowBuilder().build_micro_windows([_frame("p", now - timedelta(minutes=7))], now, "current")
    assert 0 < len(partial) < 11


def test_m3_event_node_uses_m1_embedding():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    frame = _frame("semantic", now, semantic_embedding=[.1, .2, .3, .4])
    graph = M3EventGraphBuilder().build([(frame, M2EntityResolver().resolve(frame))])
    tensor = GraphTensor.from_event_graph(graph, feature_dim=4)
    event_index = next(index for index, node in enumerate(graph.nodes) if node.node_id == "event:semantic")
    assert torch.allclose(tensor.node_features[event_index], torch.tensor([.1, .2, .3, .4]))


def test_qwen_window_encoder_uses_only_eventframe_fields_and_mock_is_deterministic():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    frame = _frame("r1", now, key_attributes={"port": 22, "attack_label": "secret", "split": "target"})
    encoder = QwenBackboneAdapter(mode="mock")
    first, second = encoder.encode_window([frame]), encoder.encode_window([frame])
    assert "attack_label" not in first["serialized"] and "target" not in first["serialized"]
    assert first["is_mock"] and torch.equal(first["embedding"], second["embedding"])


def test_qwen_batch_window_encoder_preserves_window_count():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    encoder = QwenBackboneAdapter(mode="mock")
    output = encoder.encode_windows([[_frame("one", now)], [_frame("two", now + timedelta(seconds=1))]])
    assert output["is_mock"]
    assert output["embeddings"].shape == (2, encoder.hidden_size)


def test_qwen_chunked_window_keeps_every_event_without_truncation():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    encoder = QwenBackboneAdapter(mode="mock")
    frames = [_frame(str(index), now + timedelta(seconds=index)) for index in range(5)]
    output = encoder.encode_window_chunked(frames, mock_events_per_chunk=2)
    assert output["chunk_event_counts"] == [2, 2, 1]
    assert sum(output["chunk_event_counts"]) == len(frames)
    assert output["embedding"].shape == (encoder.hidden_size,)


def test_qformer_current_and_history_conditioning_and_variable_windows():
    torch.manual_seed(7)
    model = M4QFormerDecoder(M4Config(input_dim=4, hidden_dim=4, qwen_hidden_dim=6, heads=2, layers=1, query_count=2, dropout=0.0)).eval()
    events, qwen = torch.randn(1, 3, 2, 4), torch.randn(1, 3, 6)
    current = torch.zeros(1, 4)
    baseline = model.forward_micro_windows(events, qwen, current, micro_window_mask=torch.ones(1, 3, dtype=torch.bool))
    changed_current = model.forward_micro_windows(events, qwen, torch.ones(1, 4), micro_window_mask=torch.ones(1, 3, dtype=torch.bool))
    changed_history = model.forward_micro_windows(events + 2, qwen, current, micro_window_mask=torch.ones(1, 3, dtype=torch.bool))
    assert not torch.allclose(baseline["micro_context_embeddings"], changed_current["micro_context_embeddings"])
    assert not torch.allclose(baseline["event_embedding"], changed_history["event_embedding"])
    variable = model.forward_micro_windows(events[:, :1], qwen[:, :1], current, micro_window_mask=torch.ones(1, 1, dtype=torch.bool))
    assert variable["macro_context_embedding"].shape == (1, 4)
    # Macro aggregation consumes embeddings with temporal attention; it does not
    # directly sum overlapping micro-window scalar scores.
    assert baseline["macro_context_embedding"].shape == (1, 4)


def test_m5_still_accepts_m4_macro_outputs():
    model = M4QFormerDecoder(M4Config(input_dim=4, hidden_dim=4, qwen_hidden_dim=6, heads=2, layers=1, dropout=0.0)).eval()
    output = model.forward_micro_windows(torch.ones(1, 1, 1, 4), torch.ones(1, 1, 6), torch.ones(1, 4))
    record = freeze_m4_feature(_frame("r", datetime(2026, 1, 1, tzinfo=timezone.utc), semantic_embedding=[1.] * 4), output)
    assert record.long_horizon_score == 0.0 and len(record.event_embedding) == 4
    linker = M5LongHorizonLinker(M5Config(embedding_dim=4, hidden_dim=4))
    record_embedding = torch.tensor([record.event_embedding])
    assert linker(record_embedding, record_embedding, torch.tensor([3600.])).shape == (1,)
