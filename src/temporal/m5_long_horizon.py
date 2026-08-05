from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class M5Config:
    embedding_dim: int = 128
    hidden_dim: int = 128
    decay_hours: tuple[float, ...] = (1.0, 6.0, 24.0)
    strong_anchor_weight: float = 1.0
    medium_anchor_weight: float = 0.5
    weak_anchor_weight: float = 0.0
    version: str = "m5_long_horizon_link_v2"


@dataclass(frozen=True)
class WindowRecord:
    window_id: str
    start: datetime
    end: datetime
    embedding: Tensor
    entities: dict[str, frozenset[str]] = field(default_factory=dict)
    actions: frozenset[str] = frozenset()
    path_nodes: frozenset[str] = frozenset()
    graph_embedding: Tensor | None = None
    suspicious_score: float = 0.0


@dataclass(frozen=True)
class WindowLink:
    source_window: str
    target_window: str
    score: float
    anchors: tuple[str, ...]
    anchor_strength: str
    delta_seconds: float


class PersistentEntityMemory:
    def __init__(self) -> None:
        self._history: dict[str, list[str]] = {}

    def update(self, window: WindowRecord) -> None:
        for entity_type, values in window.entities.items():
            for value in values:
                self._history.setdefault(f"{entity_type}:{value}", []).append(window.window_id)

    def windows_for(self, entity_type: str, value: str) -> tuple[str, ...]:
        return tuple(self._history.get(f"{entity_type}:{value}", ()))


class AttackQueue:
    def __init__(self) -> None:
        self._queues: list[list[str]] = []

    def add_link(self, link: WindowLink) -> None:
        matching = [i for i, queue in enumerate(self._queues) if link.source_window in queue or link.target_window in queue]
        if not matching:
            self._queues.append(sorted({link.source_window, link.target_window}))
            return
        first = matching[0]
        self._queues[first] = sorted(set(self._queues[first] + [link.source_window, link.target_window]))
        for index in reversed(matching[1:]):
            self._queues[first] = sorted(set(self._queues[first] + self._queues[index]))
            del self._queues[index]

    def as_dicts(self) -> list[dict[str, object]]:
        return [{"queue_id": f"attack_queue_{i:04d}", "window_ids": queue} for i, queue in enumerate(sorted(self._queues))]


class M5LongHorizonLinker(nn.Module):
    """Learned pair scorer with explicit long-horizon evidence features."""

    def __init__(self, config: M5Config | None = None) -> None:
        super().__init__()
        self.config = config or M5Config()
        c = self.config
        self.link_head = nn.Sequential(
            nn.Linear(c.embedding_dim * 4 + len(c.decay_hours) + 5, c.hidden_dim),
            nn.LayerNorm(c.hidden_dim), nn.GELU(), nn.Linear(c.hidden_dim, 1),
        )

    def forward(self, source: Tensor, target: Tensor, delta_seconds: Tensor, evidence: Tensor | None = None) -> Tensor:
        if source.shape != target.shape or source.ndim != 2 or source.shape[-1] != self.config.embedding_dim:
            raise ValueError("source and target must have shape [batch, embedding_dim]")
        if delta_seconds.ndim != 1 or delta_seconds.shape[0] != source.shape[0]:
            raise ValueError("delta_seconds must have shape [batch]")
        if evidence is None:
            evidence = source.new_zeros((source.shape[0], 5))
        if evidence.shape != (source.shape[0], 5):
            raise ValueError("evidence must have shape [batch, 5]")
        delta_hours = delta_seconds.to(source.dtype).clamp_min(0) / 3600.0
        decay = torch.stack([torch.exp(-delta_hours / h) for h in self.config.decay_hours], dim=-1)
        features = torch.cat([source, target, source * target, (source - target).abs(), decay, evidence], dim=-1)
        return self.link_head(features).squeeze(-1)

    def probability(self, source: Tensor, target: Tensor, delta_seconds: Tensor, evidence: Tensor | None = None) -> Tensor:
        return torch.sigmoid(self.forward(source, target, delta_seconds, evidence))

    @staticmethod
    def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
        union = left | right
        return len(left & right) / len(union) if union else 0.0

    @staticmethod
    def _cosine(left: Tensor | None, right: Tensor | None) -> float:
        if left is None or right is None:
            return 0.0
        return float(nn.functional.cosine_similarity(left.reshape(1, -1), right.reshape(1, -1)).item())

    def evidence_features(self, source: WindowRecord, target: WindowRecord, entity_rarity: dict[str, float] | None = None) -> tuple[float, ...]:
        entity_rarity = entity_rarity or {}
        strong = source.entities.get("user", frozenset()) & target.entities.get("user", frozenset())
        strong |= source.entities.get("process", frozenset()) & target.entities.get("process", frozenset())
        medium = source.entities.get("host", frozenset()) & target.entities.get("host", frozenset())
        weak = source.entities.get("ip", frozenset()) & target.entities.get("ip", frozenset())
        stable_rarity = sum(entity_rarity.get(value, 0.0) for value in strong | medium) / max(len(strong | medium), 1)
        action_compatibility = 1.0 if source.actions & target.actions else 0.0
        path_coherence = self._jaccard(source.path_nodes, target.path_nodes)
        graph_cosine = self._cosine(source.graph_embedding, target.graph_embedding)
        anchor_score = self.config.strong_anchor_weight * len(strong) + self.config.medium_anchor_weight * len(medium) + self.config.weak_anchor_weight * len(weak)
        return (float(anchor_score), float(stable_rarity), action_compatibility, path_coherence, graph_cosine)

    def link_windows(self, source: WindowRecord, target: WindowRecord, entity_rarity: dict[str, float] | None = None) -> WindowLink | None:
        if target.start < source.start:
            source, target = target, source
        strong = source.entities.get("user", frozenset()) & target.entities.get("user", frozenset())
        strong |= source.entities.get("process", frozenset()) & target.entities.get("process", frozenset())
        medium = source.entities.get("host", frozenset()) & target.entities.get("host", frozenset())
        if not strong and not medium:
            return None
        evidence = self.evidence_features(source, target, entity_rarity)
        delta = max((target.start - source.start).total_seconds(), 0.0)
        with torch.no_grad():
            score = float(self.probability(source.embedding.unsqueeze(0), target.embedding.unsqueeze(0), torch.tensor([delta]), torch.tensor([evidence])).item())
        anchors = tuple(sorted(strong | medium))
        return WindowLink(source.window_id, target.window_id, score, anchors, "strong" if strong else "medium", delta)


def build_attack_queues(windows: list[WindowRecord], linker: M5LongHorizonLinker, threshold: float = 0.5) -> tuple[list[WindowLink], AttackQueue]:
    links: list[WindowLink] = []
    queues = AttackQueue()
    ordered = sorted(windows, key=lambda row: (row.start, row.window_id))
    for index, source in enumerate(ordered):
        for target in ordered[index + 1:]:
            link = linker.link_windows(source, target)
            if link is not None and link.score >= threshold:
                links.append(link)
                queues.add_link(link)
    return links, queues


def write_m5_outputs(root: Path, links: list[WindowLink], queues: AttackQueue, windows: list[WindowRecord]) -> None:
    output = root / "outputs/m5"
    output.mkdir(parents=True, exist_ok=True)
    (output / "window_links.jsonl").write_text("".join(json.dumps(link.__dict__, ensure_ascii=True) + "\n" for link in links), encoding="utf-8")
    (output / "attack_queues.jsonl").write_text("".join(json.dumps(row) + "\n" for row in queues.as_dicts()), encoding="utf-8")
    (output / "suspicious_nodes.json").write_text(json.dumps(sorted({entity for window in windows for values in window.entities.values() for entity in values}), indent=2), encoding="utf-8")
