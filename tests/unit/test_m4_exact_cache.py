import json

from src.common.schema import EventFrame
from src.training.m4_exact_cache import ExactM4Cache


def test_exact_cache_uses_indexed_half_open_membership(tmp_path) -> None:
    cache = tmp_path / "cache.jsonl"
    mapping = tmp_path / "mapping.jsonl"
    window_id = "window"
    cache.write_text(json.dumps({
        "window_id": window_id, "start": "2026-08-10T10:00:00+00:00", "end": "2026-08-10T10:05:00+00:00",
        "alignment": "current", "is_mock": False, "qwen_embedding": [0.0, 0.0],
    }) + "\n", encoding="utf-8")
    mapping.write_text(json.dumps({"dataset_id": "source", "record_id": "current", "window_ids": [window_id]}) + "\n", encoding="utf-8")
    frames = [
        EventFrame(dataset_id="source", record_id="before", timestamp="2026-08-10T10:00:00+00:00", semantic_embedding=[1.0, 2.0]),
        EventFrame(dataset_id="source", record_id="current", timestamp="2026-08-10T10:03:00+00:00", semantic_embedding=[3.0, 4.0]),
        EventFrame(dataset_id="source", record_id="end", timestamp="2026-08-10T10:05:00+00:00", semantic_embedding=[5.0, 6.0]),
    ]

    result = ExactM4Cache(cache, mapping).build(frames, dataset_id="source", record_id="current")

    assert result["micro_event_valid_mask"].tolist() == [[[True]]]
    assert result["micro_event_embeddings"].tolist() == [[[[1.0, 2.0]]]]


def test_exact_cache_aggregates_every_event_in_ordered_chunks(tmp_path) -> None:
    cache = tmp_path / "cache.jsonl"
    mapping = tmp_path / "mapping.jsonl"
    cache.write_text(json.dumps({"window_id": "window", "start": "2026-08-10T10:00:00+00:00", "end": "2026-08-10T10:05:00+00:00", "alignment": "current", "is_mock": False, "qwen_embedding": [0.0, 0.0]}) + "\n", encoding="utf-8")
    mapping.write_text(json.dumps({"dataset_id": "source", "record_id": "current", "window_ids": ["window"]}) + "\n", encoding="utf-8")
    frames = [
        EventFrame(dataset_id="source", record_id=str(index), timestamp=f"2026-08-10T10:0{index}:00+00:00", semantic_embedding=[float(index), float(index)])
        for index in range(4)
    ] + [EventFrame(dataset_id="source", record_id="current", timestamp="2026-08-10T10:04:30+00:00", semantic_embedding=[9.0, 9.0])]

    result = ExactM4Cache(cache, mapping, event_chunk_size=2).build(frames, dataset_id="source", record_id="current")

    assert result["micro_event_valid_mask"].tolist() == [[[True, True]]]
    assert result["micro_event_embeddings"].tolist() == [[[[0.5, 0.5], [2.5, 2.5]]]]
