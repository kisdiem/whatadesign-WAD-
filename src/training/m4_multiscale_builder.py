from __future__ import annotations

"""Strict source-side EventFrame to M4 multiscale batch construction.

This module deliberately starts after M1 and M2. It neither executes DeBERTa
again nor accepts labels: supervision belongs only in the runner loss.
"""

from dataclasses import dataclass
from typing import Iterable, Mapping

import torch
from torch import Tensor

from src.common.schema import EventFrame
from src.entities.m2_resolver import ResolvedEntity
from src.graph.m3_graph import EventGraph, M3EventGraphBuilder
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.temporal.window_builder import MicroWindow, WindowBuilder


@dataclass(frozen=True)
class M4MultiscaleSample:
    current_record_id: str
    current_event_embedding: Tensor
    event_embeddings: Tensor
    qwen_window_embeddings: Tensor
    event_valid_mask: Tensor
    micro_window_mask: Tensor
    windows: tuple[MicroWindow, ...]
    history_graph: EventGraph
    rejected_history: tuple[dict[str, str], ...]
    qwen_manifest: dict[str, object]


class StrictM4BatchBuilder:
    """Construct causal M4 features from normalized source EventFrames only."""

    def __init__(self, qwen: QwenBackboneAdapter, *, window_builder: WindowBuilder | None = None,
                 graph_builder: M3EventGraphBuilder | None = None) -> None:
        self.qwen = qwen
        self.window_builder = window_builder or WindowBuilder()
        self.graph_builder = graph_builder or M3EventGraphBuilder(self.window_builder.config.macro_seconds)

    @staticmethod
    def _embedding(frame: EventFrame) -> Tensor:
        if not frame.semantic_embedding:
            raise ValueError(f"EventFrame {frame.record_id} has no M1 semantic_embedding")
        return torch.tensor(frame.semantic_embedding, dtype=torch.float32)

    def build_one(self, events: Iterable[EventFrame], current_record_id: str,
                  resolved_entities: Mapping[str, list[ResolvedEntity]] | None = None) -> M4MultiscaleSample:
        rows = list(events)
        current = next((frame for frame in rows if frame.record_id == current_record_id), None)
        if current is None or current.timestamp is None:
            raise ValueError("current event with parseable timestamp is required")
        current_embedding = self._embedding(current)
        for frame in rows:
            vector = self._embedding(frame)
            if vector.shape != current_embedding.shape:
                raise ValueError("all EventFrame semantic embeddings must share one M1 dimension")
        entities = resolved_entities or {}
        history_graph, rejected = self.graph_builder.build_history_before_current_event(
            [(frame, entities.get(frame.record_id, [])) for frame in rows], current.record_id, current.timestamp
        )
        windows = tuple(self.window_builder.build_micro_windows(rows, current.timestamp, current.record_id))
        index = {frame.record_id: frame for frame in rows}
        max_events = max((len(window.record_ids) for window in windows), default=0)
        event_tensor = current_embedding.new_zeros((len(windows), max_events, current_embedding.numel()))
        event_mask = torch.zeros((len(windows), max_events), dtype=torch.bool)
        qwen_rows: list[Tensor] = []
        for window_index, window in enumerate(windows):
            members = [index[record_id] for record_id in window.record_ids]
            for event_index, frame in enumerate(members):
                event_tensor[window_index, event_index] = self._embedding(frame)
                event_mask[window_index, event_index] = True
            # Dense flow windows regularly exceed a backbone context.  The
            # chunked encoder preserves every ordered EventFrame and records a
            # count-weighted semantic aggregation, rather than silently
            # truncating the history at tokenizer length.
            result = self.qwen.encode_window_chunked(members)
            qwen_rows.append(result["embedding"].detach().to(dtype=torch.float32).cpu())
        qwen_tensor = torch.stack(qwen_rows) if qwen_rows else torch.zeros((0, self.qwen.hidden_size), dtype=torch.float32)
        return M4MultiscaleSample(
            current.record_id, current_embedding, event_tensor, qwen_tensor, event_mask,
            torch.ones(len(windows), dtype=torch.bool), windows, history_graph, tuple(rejected),
            self.qwen.export_backbone_manifest(),
        )

    @staticmethod
    def collate(samples: list[M4MultiscaleSample]) -> dict[str, Tensor]:
        """Pad variable source histories without changing their causal masks."""
        if not samples:
            raise ValueError("cannot collate an empty M4 sample list")
        embedding_dim = samples[0].current_event_embedding.numel()
        qwen_dim = samples[0].qwen_window_embeddings.shape[-1]
        if any(sample.current_event_embedding.numel() != embedding_dim or sample.qwen_window_embeddings.shape[-1] != qwen_dim for sample in samples):
            raise ValueError("M1/Qwen dimensions must be consistent across a batch")
        max_windows = max(sample.event_embeddings.shape[0] for sample in samples)
        max_events = max(sample.event_embeddings.shape[1] for sample in samples)
        events = torch.zeros((len(samples), max_windows, max_events, embedding_dim), dtype=torch.float32)
        qwen = torch.zeros((len(samples), max_windows, qwen_dim), dtype=torch.float32)
        event_mask = torch.zeros((len(samples), max_windows, max_events), dtype=torch.bool)
        window_mask = torch.zeros((len(samples), max_windows), dtype=torch.bool)
        current = torch.stack([sample.current_event_embedding for sample in samples])
        for index, sample in enumerate(samples):
            windows, members = sample.event_embeddings.shape[:2]
            events[index, :windows, :members] = sample.event_embeddings
            qwen[index, :windows] = sample.qwen_window_embeddings
            event_mask[index, :windows, :members] = sample.event_valid_mask
            window_mask[index, :windows] = sample.micro_window_mask
        return {
            "micro_event_embeddings": events,
            "qwen_window_embeddings": qwen,
            "current_event_embedding": current,
            "micro_event_valid_mask": event_mask,
            "micro_window_mask": window_mask,
        }
