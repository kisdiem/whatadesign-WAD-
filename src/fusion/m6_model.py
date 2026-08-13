from __future__ import annotations
import torch
from src.common.schema import FrozenFeatureRecord
from src.fusion.m6_hierarchical import M6HierarchicalFusion


class StrictM6Model:
    """Adapter that accepts only frozen records and passes model-safe features."""
    def __init__(self, model: M6HierarchicalFusion): self.model = model

    def forward_records(self, records: list[FrozenFeatureRecord]):
        if not records: raise ValueError("at least one frozen feature record is required")
        embeddings = torch.tensor([r.event_embedding for r in records], dtype=torch.float32)
        graph = torch.tensor([r.graph_score for r in records], dtype=torch.float32)
        horizon = torch.tensor([r.long_horizon_score for r in records], dtype=torch.float32)
        if embeddings.shape[-1] != self.model.config.embedding_dim: raise ValueError("frozen event embedding dimension mismatch")
        return self.model(embeddings, graph, horizon)
