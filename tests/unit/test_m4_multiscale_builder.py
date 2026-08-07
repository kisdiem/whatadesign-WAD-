from datetime import datetime, timedelta, timezone

from src.common.schema import EventFrame
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.training.m4_multiscale_builder import StrictM4BatchBuilder


def _frame(record_id, timestamp, value):
    return EventFrame(record_id=record_id, timestamp=timestamp.isoformat(), action="process", semantic_embedding=[value] * 4)


def test_strict_builder_creates_causal_multiscale_tensors_without_labels():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [_frame(f"h{index}", now - timedelta(minutes=30 - index), float(index)) for index in range(30)]
    rows += [_frame("current", now, 9.0), _frame("future", now + timedelta(minutes=1), 8.0)]
    sample = StrictM4BatchBuilder(QwenBackboneAdapter(mode="mock")).build_one(rows, "current")
    assert sample.event_embeddings.shape[0] == 11
    assert sample.qwen_window_embeddings.shape == (11, 1024)
    assert all("future" not in window.record_ids and "current" not in window.record_ids for window in sample.windows)
    assert {item["record_id"] for item in sample.rejected_history} >= {"current", "future"}
    batch = StrictM4BatchBuilder.collate([sample])
    assert batch["micro_event_embeddings"].shape[:2] == (1, 11)
