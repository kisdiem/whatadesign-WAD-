from __future__ import annotations

from datetime import datetime

from torch import Tensor

from src.temporal.m5_entity_progress_linker import ProgressEvent


def progress_event_from_model_output(
    *,
    event_id: str,
    timestamp: datetime,
    entities: dict[str, frozenset[str]],
    output: dict[str, Tensor],
    batch_index: int = 0,
    graph_embedding: Tensor | None = None,
) -> ProgressEvent:
    """Convert one M5KnowledgeProgressTransformer output row into long-horizon state.

    The adapter detaches tensors to CPU so persistent entity memory does not retain
    an inference graph or accumulate long-lived GPU state across a multi-day stream.
    """

    required = (
        "semantic_embedding",
        "relevance_probability",
        "progress_score",
        "position_probabilities",
    )
    missing = [name for name in required if name not in output]
    if missing:
        raise KeyError(f"knowledge-progress output missing fields: {missing}")

    semantic = output["semantic_embedding"]
    relevance = output["relevance_probability"]
    progress = output["progress_score"]
    positions = output["position_probabilities"]
    if semantic.ndim != 2 or positions.ndim != 2 or relevance.ndim != 1 or progress.ndim != 1:
        raise ValueError("unexpected batched output shapes from M5KnowledgeProgressTransformer")
    batch_size = semantic.shape[0]
    if not 0 <= batch_index < batch_size:
        raise IndexError("batch_index out of range")
    if relevance.shape[0] != batch_size or progress.shape[0] != batch_size or positions.shape[0] != batch_size:
        raise ValueError("M5 output tensors must share the same batch dimension")

    graph = graph_embedding.detach().cpu() if graph_embedding is not None else None
    return ProgressEvent(
        event_id=event_id,
        timestamp=timestamp,
        embedding=semantic[batch_index].detach().cpu(),
        entities=entities,
        relevance_probability=float(relevance[batch_index].detach().cpu().item()),
        progress_score=float(progress[batch_index].detach().cpu().item()),
        position_probabilities=positions[batch_index].detach().cpu(),
        graph_embedding=graph,
    )
