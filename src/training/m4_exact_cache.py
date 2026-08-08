from __future__ import annotations

"""Build strict M4 tensors from a reproducible exact-Qwen cache."""

import json
from pathlib import Path

import torch

from src.common.schema import EventFrame
from src.training.m4_window_cache import parse_utc


class ExactM4Cache:
    def __init__(self, cache_path: str | Path, mapping_path: str | Path) -> None:
        self.windows = {row["window_id"]: row for row in self._jsonl(cache_path)}
        self.mapping = {(row["dataset_id"], row["record_id"]): row["window_ids"] for row in self._jsonl(mapping_path)}
        if any(row.get("alignment") != "current" for row in self.windows.values()):
            raise ValueError("strict M4 training refuses non-current-aligned cache")
        if any(bool(row.get("is_mock")) for row in self.windows.values()):
            raise ValueError("strict M4 training refuses mock Qwen cache")

    @staticmethod
    def _jsonl(path):
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip(): yield json.loads(line)

    def build(self, frames: list[EventFrame], *, dataset_id: str, record_id: str) -> dict[str, torch.Tensor]:
        current = next(frame for frame in frames if frame.record_id == record_id)
        ids = self.mapping[(dataset_id, record_id)]
        rows = [self.windows[item] for item in ids]
        members = []
        for row in rows:
            start, end = parse_utc(row["start"]), parse_utc(row["end"])
            members.append([frame for frame in frames if frame.record_id != record_id and frame.timestamp
                            and start <= parse_utc(frame.timestamp) < end])
        dim = len(current.semantic_embedding or [])
        if not dim: raise ValueError("current EventFrame lacks M1 semantic_embedding")
        width = max((len(item) for item in members), default=0)
        events = torch.zeros((1, len(rows), width, dim), dtype=torch.float32)
        event_mask = torch.zeros((1, len(rows), width), dtype=torch.bool)
        for window_index, frames_in_window in enumerate(members):
            for event_index, frame in enumerate(frames_in_window):
                events[0, window_index, event_index] = torch.tensor(frame.semantic_embedding, dtype=torch.float32)
                event_mask[0, window_index, event_index] = True
        return {"micro_event_embeddings": events,
                "qwen_window_embeddings": torch.tensor([[row["qwen_embedding"] for row in rows]], dtype=torch.float32),
                "current_event_embedding": torch.tensor([current.semantic_embedding], dtype=torch.float32),
                "micro_event_valid_mask": event_mask,
                "micro_window_mask": torch.ones((1, len(rows)), dtype=torch.bool)}
