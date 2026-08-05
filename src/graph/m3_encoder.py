from __future__ import annotations

import hashlib
from dataclasses import dataclass

import torch
from torch import Tensor, nn

from src.graph.m3_graph import EventGraph


@dataclass(frozen=True)
class GraphTensor:
    node_features: Tensor
    edge_index: Tensor
    edge_type: Tensor
    node_type: Tensor

    @classmethod
    def from_event_graph(cls, graph: EventGraph, feature_dim: int = 128) -> "GraphTensor":
        nodes = list(graph.nodes)
        index = {node.node_id: i for i, node in enumerate(nodes)}
        features = torch.zeros(len(nodes), feature_dim)
        node_type = torch.zeros(len(nodes), dtype=torch.long)
        for i, node in enumerate(nodes):
            digest = torch.tensor(list((node.node_type + "|" + node.value).encode()), dtype=torch.float32)
            if digest.numel():
                features[i, :min(feature_dim, digest.numel())] = digest[:feature_dim] / 255.0
            node_type[i] = int(hashlib.sha256(node.node_type.encode()).hexdigest()[:8], 16) % 32
        edges = []
        edge_type = []
        relations = {relation: i for i, relation in enumerate(sorted({edge.relation for edge in graph.edges}))}
        for edge in graph.edges:
            if edge.source in index and edge.target in index:
                edges.append((index[edge.source], index[edge.target]))
                edge_type.append(relations[edge.relation])
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous() if edges else torch.zeros((2, 0), dtype=torch.long)
        return cls(features, edge_index, torch.tensor(edge_type, dtype=torch.long), node_type)


class GraphSAGELayer(nn.Module):
    def __init__(self, input_dim: int, output_dim: int) -> None:
        super().__init__()
        self.projection = nn.Linear(input_dim * 2, output_dim)

    def forward(self, features: Tensor, edge_index: Tensor) -> Tensor:
        neighbors = torch.zeros_like(features)
        counts = torch.zeros(features.shape[0], 1, device=features.device)
        if edge_index.numel():
            source, target = edge_index
            neighbors.index_add_(0, target, features[source])
            counts.index_add_(0, target, torch.ones((target.numel(), 1), device=features.device))
        neighbors = neighbors / counts.clamp_min(1.0)
        return torch.relu(self.projection(torch.cat([features, neighbors], dim=-1)))


class M3GraphSAGEEncoder(nn.Module):
    """Reduced M3 GraphSAGE baseline and self-supervised task heads."""

    def __init__(self, input_dim: int = 128, hidden_dim: int = 128, relation_count: int = 16, node_type_count: int = 32) -> None:
        super().__init__()
        self.layers = nn.ModuleList([GraphSAGELayer(input_dim, hidden_dim), GraphSAGELayer(hidden_dim, hidden_dim)])
        self.relation_head = nn.Linear(hidden_dim * 2, relation_count)
        self.node_type_head = nn.Linear(hidden_dim, node_type_count)

    def forward(self, graph: GraphTensor) -> dict[str, Tensor]:
        hidden = graph.node_features
        for layer in self.layers:
            hidden = layer(hidden, graph.edge_index)
        if graph.edge_index.shape[1]:
            source, target = graph.edge_index
            relation_logits = self.relation_head(torch.cat([hidden[source], hidden[target]], dim=-1))
        else:
            relation_logits = hidden.new_zeros((0, self.relation_head.out_features))
        return {"node_embedding": hidden, "relation_logits": relation_logits, "node_type_logits": self.node_type_head(hidden)}

    def self_supervised_loss(self, output: dict[str, Tensor], graph: GraphTensor, masked_node: Tensor | None = None) -> dict[str, Tensor]:
        masked_node = masked_node if masked_node is not None else torch.zeros(graph.node_features.shape[0], dtype=torch.bool)
        node_loss = output["node_type_logits"].new_zeros(())
        if masked_node.any():
            node_loss = nn.functional.cross_entropy(output["node_type_logits"][masked_node], graph.node_type[masked_node])
        edge_loss = output["relation_logits"].new_zeros(())
        if output["relation_logits"].shape[0] and graph.edge_type.max().item() < output["relation_logits"].shape[1]:
            edge_loss = nn.functional.cross_entropy(output["relation_logits"], graph.edge_type)
        contrastive = output["node_embedding"].new_zeros(())
        if output["node_embedding"].shape[0] > 1:
            normalized = nn.functional.normalize(output["node_embedding"], dim=-1)
            contrastive = (1.0 - normalized @ normalized.T).mean()
        return {"masked_node_type": node_loss, "masked_relation": edge_loss, "neighborhood_contrastive": contrastive, "total": node_loss + edge_loss + contrastive}
