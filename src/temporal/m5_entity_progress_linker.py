from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from math import exp

import torch
from torch import Tensor, nn
import torch.nn.functional as F


@dataclass(frozen=True)
class M5LongHorizonProgressConfig:
    """Configuration for sparse long-horizon event linking.

    Time order is a hard constraint. Attack progress and ATT&CK position order are
    soft constraints because both are model predictions and real APT campaigns may
    revisit earlier tactics.
    """

    embedding_dim: int = 128
    relevance_threshold: float = 0.35
    link_threshold: float = 0.60
    max_candidates: int = 64
    max_candidates_per_entity: int = 32
    progress_tolerance: float = 0.10
    progress_temperature: float = 0.12
    position_tolerance: float = 0.12
    position_temperature: float = 0.15
    time_scale_hours: float = 168.0
    min_shared_entity_weight: float = 0.50
    entity_weight: float = 0.30
    semantic_weight: float = 0.24
    progress_weight: float = 0.18
    position_weight: float = 0.10
    time_weight: float = 0.10
    graph_weight: float = 0.08
    version: str = "m5_entity_progress_long_horizon_v1"

    def __post_init__(self) -> None:
        if self.embedding_dim <= 0:
            raise ValueError("embedding_dim must be positive")
        if not 0.0 < self.relevance_threshold < 1.0:
            raise ValueError("relevance_threshold must be in (0, 1)")
        if not 0.0 < self.link_threshold < 1.0:
            raise ValueError("link_threshold must be in (0, 1)")
        if self.max_candidates <= 0 or self.max_candidates_per_entity <= 0:
            raise ValueError("candidate limits must be positive")
        if self.progress_tolerance < 0 or self.position_tolerance < 0:
            raise ValueError("tolerances cannot be negative")
        if self.progress_temperature <= 0 or self.position_temperature <= 0:
            raise ValueError("temperatures must be positive")
        if self.time_scale_hours <= 0:
            raise ValueError("time_scale_hours must be positive")


@dataclass(frozen=True)
class ProgressEvent:
    """Compact event/window representation consumed by long-horizon M5.

    `progress_score`, `position_probabilities` and `relevance_probability` are
    intended to come from M5KnowledgeProgressTransformer. The long-horizon linker
    does not re-run token-level Transformer attention across days of raw logs.
    """

    event_id: str
    timestamp: datetime
    embedding: Tensor
    entities: dict[str, frozenset[str]] = field(default_factory=dict)
    relevance_probability: float = 1.0
    progress_score: float = 0.0
    position_probabilities: Tensor | None = None
    graph_embedding: Tensor | None = None

    def validate(self, embedding_dim: int) -> None:
        if self.embedding.shape != (embedding_dim,):
            raise ValueError(f"embedding must have shape [{embedding_dim}]")
        if not 0.0 <= self.relevance_probability <= 1.0:
            raise ValueError("relevance_probability must be in [0, 1]")
        if not 0.0 <= self.progress_score <= 1.0:
            raise ValueError("progress_score must be in [0, 1]")
        if self.position_probabilities is not None:
            if self.position_probabilities.ndim != 1 or self.position_probabilities.numel() == 0:
                raise ValueError("position_probabilities must be a non-empty vector")
            if not torch.isfinite(self.position_probabilities).all():
                raise ValueError("position_probabilities must be finite")
        if self.graph_embedding is not None and self.graph_embedding.ndim != 1:
            raise ValueError("graph_embedding must be a vector")


@dataclass(frozen=True)
class LongHorizonLink:
    source_event: str
    target_event: str
    score: float
    shared_entities: tuple[str, ...]
    delta_seconds: float
    progress_delta: float
    evidence: dict[str, float]


class PersistentEntityMemory:
    """In-memory sparse index from entity attributes to previously seen events."""

    DEFAULT_ENTITY_WEIGHTS = {
        "process": 1.00,
        "host": 0.85,
        "device": 0.85,
        "user": 0.65,
        "account": 0.35,
        "ip": 0.20,
    }

    def __init__(self, entity_weights: dict[str, float] | None = None) -> None:
        self.entity_weights = dict(self.DEFAULT_ENTITY_WEIGHTS)
        if entity_weights:
            self.entity_weights.update(entity_weights)
        self._events: dict[str, ProgressEvent] = {}
        self._history: dict[str, list[str]] = {}

    @staticmethod
    def _key(entity_type: str, value: str) -> str:
        return f"{entity_type}:{value}"

    def entity_weight(self, entity_type: str) -> float:
        return float(self.entity_weights.get(entity_type, 0.50))

    def add(self, event: ProgressEvent) -> None:
        if event.event_id in self._events:
            raise ValueError(f"duplicate event_id: {event.event_id}")
        self._events[event.event_id] = event
        for entity_type, values in event.entities.items():
            for value in values:
                self._history.setdefault(self._key(entity_type, value), []).append(event.event_id)

    def get(self, event_id: str) -> ProgressEvent:
        return self._events[event_id]

    def shared_entity_evidence(self, left: ProgressEvent, right: ProgressEvent) -> tuple[float, tuple[str, ...]]:
        score = 0.0
        anchors: list[str] = []
        for entity_type in set(left.entities) & set(right.entities):
            shared = left.entities[entity_type] & right.entities[entity_type]
            weight = self.entity_weight(entity_type)
            for value in shared:
                score += weight
                anchors.append(self._key(entity_type, value))
        return score, tuple(sorted(anchors))

    def candidates(
        self,
        target: ProgressEvent,
        *,
        max_candidates: int,
        max_candidates_per_entity: int,
    ) -> list[ProgressEvent]:
        """Retrieve only earlier events sharing indexed entities with target."""

        candidate_strength: dict[str, float] = {}
        candidate_recency: dict[str, datetime] = {}
        for entity_type, values in target.entities.items():
            weight = self.entity_weight(entity_type)
            for value in values:
                ids = self._history.get(self._key(entity_type, value), ())
                for event_id in ids[-max_candidates_per_entity:]:
                    event = self._events[event_id]
                    if event.timestamp >= target.timestamp:
                        continue
                    candidate_strength[event_id] = candidate_strength.get(event_id, 0.0) + weight
                    candidate_recency[event_id] = event.timestamp

        ranked = sorted(
            candidate_strength,
            key=lambda event_id: (candidate_strength[event_id], candidate_recency[event_id]),
            reverse=True,
        )
        return [self._events[event_id] for event_id in ranked[:max_candidates]]


class M5EntityProgressLinker(nn.Module):
    """Sparse long-horizon linker over entity memory and progress priors.

    The knowledge Transformer remains a local semantic/progress estimator. This
    module provides the actual long-horizon behavior by retrieving historical
    events through persistent entity memory and scoring only forward-in-time edges.
    """

    def __init__(self, config: M5LongHorizonProgressConfig | None = None) -> None:
        super().__init__()
        self.config = config or M5LongHorizonProgressConfig()

    @staticmethod
    def _cosine01(left: Tensor, right: Tensor) -> float:
        value = float(F.cosine_similarity(left.reshape(1, -1), right.reshape(1, -1)).item())
        return max(0.0, min(1.0, (value + 1.0) * 0.5))

    @staticmethod
    def _soft_forward_score(delta: float, tolerance: float, temperature: float) -> float:
        """Return 1 for forward/small-backtrack deltas; smoothly penalize large reversal."""

        violation = max(0.0, -delta - tolerance)
        return exp(-violation / temperature)

    @staticmethod
    def _expected_position(probabilities: Tensor | None) -> float | None:
        if probabilities is None:
            return None
        probabilities = probabilities.float().clamp_min(0)
        total = float(probabilities.sum().item())
        if total <= 1e-8:
            return None
        axis = torch.linspace(0.0, 1.0, probabilities.numel(), device=probabilities.device)
        return float((probabilities * axis).sum().item() / total)

    def evidence(
        self,
        source: ProgressEvent,
        target: ProgressEvent,
        memory: PersistentEntityMemory,
    ) -> tuple[dict[str, float], tuple[str, ...]] | None:
        c = self.config
        source.validate(c.embedding_dim)
        target.validate(c.embedding_dim)

        # Hard constraint: edges must follow observation time.
        if target.timestamp <= source.timestamp:
            return None

        entity_strength, shared_entities = memory.shared_entity_evidence(source, target)
        if entity_strength < c.min_shared_entity_weight:
            return None

        semantic = self._cosine01(source.embedding, target.embedding)
        progress_delta = target.progress_score - source.progress_score
        progress = self._soft_forward_score(progress_delta, c.progress_tolerance, c.progress_temperature)

        source_position = self._expected_position(source.position_probabilities)
        target_position = self._expected_position(target.position_probabilities)
        if source_position is None or target_position is None:
            position = 0.5
        else:
            position = self._soft_forward_score(
                target_position - source_position,
                c.position_tolerance,
                c.position_temperature,
            )

        delta_hours = (target.timestamp - source.timestamp).total_seconds() / 3600.0
        # Slow rational decay keeps multi-day candidates alive instead of erasing them.
        time_consistency = 1.0 / (1.0 + delta_hours / c.time_scale_hours)

        graph = 0.5
        if source.graph_embedding is not None and target.graph_embedding is not None:
            if source.graph_embedding.shape != target.graph_embedding.shape:
                raise ValueError("graph embeddings must have matching shapes")
            graph = self._cosine01(source.graph_embedding, target.graph_embedding)

        entity_normalized = 1.0 - exp(-entity_strength)
        return ({
            "entity": entity_normalized,
            "semantic": semantic,
            "progress": progress,
            "position": position,
            "time": time_consistency,
            "graph": graph,
            "source_relevance": source.relevance_probability,
            "target_relevance": target.relevance_probability,
        }, shared_entities)

    def score_pair(
        self,
        source: ProgressEvent,
        target: ProgressEvent,
        memory: PersistentEntityMemory,
    ) -> LongHorizonLink | None:
        c = self.config
        if source.relevance_probability < c.relevance_threshold or target.relevance_probability < c.relevance_threshold:
            return None
        result = self.evidence(source, target, memory)
        if result is None:
            return None
        evidence, shared_entities = result
        base = (
            c.entity_weight * evidence["entity"]
            + c.semantic_weight * evidence["semantic"]
            + c.progress_weight * evidence["progress"]
            + c.position_weight * evidence["position"]
            + c.time_weight * evidence["time"]
            + c.graph_weight * evidence["graph"]
        )
        relevance_gate = (evidence["source_relevance"] * evidence["target_relevance"]) ** 0.5
        score = max(0.0, min(1.0, base * relevance_gate))
        delta_seconds = (target.timestamp - source.timestamp).total_seconds()
        return LongHorizonLink(
            source_event=source.event_id,
            target_event=target.event_id,
            score=score,
            shared_entities=shared_entities,
            delta_seconds=delta_seconds,
            progress_delta=target.progress_score - source.progress_score,
            evidence=evidence,
        )

    def link_target(
        self,
        target: ProgressEvent,
        memory: PersistentEntityMemory,
        *,
        top_k: int = 4,
    ) -> list[LongHorizonLink]:
        """Link historical candidates -> target, never target -> history."""

        if top_k <= 0:
            raise ValueError("top_k must be positive")
        c = self.config
        candidates = memory.candidates(
            target,
            max_candidates=c.max_candidates,
            max_candidates_per_entity=c.max_candidates_per_entity,
        )
        links: list[LongHorizonLink] = []
        for source in candidates:
            link = self.score_pair(source, target, memory)
            if link is not None and link.score >= c.link_threshold:
                links.append(link)
        links.sort(key=lambda item: item.score, reverse=True)
        return links[:top_k]


class M5AttackChainAssembler:
    """Streaming DAG assembler: retrieve past candidates, score edges, then remember target."""

    def __init__(
        self,
        linker: M5EntityProgressLinker | None = None,
        memory: PersistentEntityMemory | None = None,
    ) -> None:
        self.linker = linker or M5EntityProgressLinker()
        self.memory = memory or PersistentEntityMemory()
        self.links: list[LongHorizonLink] = []

    def process(self, event: ProgressEvent, *, top_k: int = 4) -> list[LongHorizonLink]:
        event.validate(self.linker.config.embedding_dim)
        new_links = self.linker.link_target(event, self.memory, top_k=top_k)
        self.links.extend(new_links)
        self.memory.add(event)
        return new_links

    def process_many(self, events: list[ProgressEvent], *, top_k: int = 4) -> list[LongHorizonLink]:
        for event in sorted(events, key=lambda row: (row.timestamp, row.event_id)):
            self.process(event, top_k=top_k)
        return list(self.links)

    def adjacency(self) -> dict[str, tuple[str, ...]]:
        graph: dict[str, list[str]] = {}
        for link in self.links:
            graph.setdefault(link.source_event, []).append(link.target_event)
        return {source: tuple(targets) for source, targets in graph.items()}
