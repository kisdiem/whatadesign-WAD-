from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import exp

import torch
from torch import Tensor
import torch.nn.functional as F

from src.temporal.m5_entity_progress_linker import (
    LongHorizonLink,
    M5EntityProgressLinker,
    PersistentEntityMemory,
    ProgressEvent,
)


@dataclass(frozen=True)
class M5AttackChainManagerConfig:
    assignment_threshold: float = 0.60
    ambiguity_margin: float = 0.04
    link_support_weight: float = 0.60
    chain_state_weight: float = 0.40
    max_incoming_links: int = 8

    def __post_init__(self) -> None:
        if not 0.0 < self.assignment_threshold < 1.0:
            raise ValueError("assignment_threshold must be in (0, 1)")
        if self.ambiguity_margin < 0.0:
            raise ValueError("ambiguity_margin cannot be negative")
        if self.link_support_weight < 0 or self.chain_state_weight < 0:
            raise ValueError("chain assignment weights cannot be negative")
        if self.link_support_weight + self.chain_state_weight <= 0:
            raise ValueError("at least one chain assignment weight must be positive")
        if self.max_incoming_links <= 0:
            raise ValueError("max_incoming_links must be positive")


@dataclass
class AttackChainState:
    chain_id: str
    event_ids: list[str]
    entities: dict[str, set[str]]
    semantic_sum: Tensor
    position_sum: Tensor | None
    latest_timestamp: datetime
    latest_progress: float
    relevance_sum: float
    event_count: int

    @classmethod
    def from_event(cls, chain_id: str, event: ProgressEvent) -> "AttackChainState":
        return cls(
            chain_id=chain_id,
            event_ids=[event.event_id],
            entities={kind: set(values) for kind, values in event.entities.items()},
            semantic_sum=event.embedding.detach().cpu().clone(),
            position_sum=(
                event.position_probabilities.detach().cpu().clone()
                if event.position_probabilities is not None
                else None
            ),
            latest_timestamp=event.timestamp,
            latest_progress=event.progress_score,
            relevance_sum=event.relevance_probability,
            event_count=1,
        )

    @property
    def semantic_prototype(self) -> Tensor:
        return self.semantic_sum / float(self.event_count)

    @property
    def position_prototype(self) -> Tensor | None:
        if self.position_sum is None:
            return None
        return self.position_sum / float(self.event_count)

    @property
    def mean_relevance(self) -> float:
        return self.relevance_sum / float(self.event_count)

    def add(self, event: ProgressEvent) -> None:
        self.event_ids.append(event.event_id)
        for kind, values in event.entities.items():
            self.entities.setdefault(kind, set()).update(values)
        self.semantic_sum = self.semantic_sum + event.embedding.detach().cpu()
        if event.position_probabilities is not None:
            if self.position_sum is None:
                self.position_sum = event.position_probabilities.detach().cpu().clone()
            else:
                self.position_sum = self.position_sum + event.position_probabilities.detach().cpu()
        previous_latest = self.latest_timestamp
        if event.timestamp >= previous_latest:
            self.latest_timestamp = event.timestamp
            self.latest_progress = event.progress_score
        self.relevance_sum += event.relevance_probability
        self.event_count += 1


@dataclass(frozen=True)
class ChainAssignment:
    event_id: str
    chain_id: str
    created_new: bool
    score: float
    incoming_links: tuple[LongHorizonLink, ...]


class M5AttackChainManager:
    """Assign every event to at most one attack chain and never merge chains implicitly."""

    def __init__(
        self,
        linker: M5EntityProgressLinker | None = None,
        memory: PersistentEntityMemory | None = None,
        config: M5AttackChainManagerConfig | None = None,
    ) -> None:
        self.linker = linker or M5EntityProgressLinker()
        self.memory = memory or PersistentEntityMemory()
        self.config = config or M5AttackChainManagerConfig()
        self.chains: dict[str, AttackChainState] = {}
        self.event_to_chain: dict[str, str] = {}
        self.links: list[LongHorizonLink] = []
        self._next_chain_id = 1

    def _new_chain_id(self) -> str:
        chain_id = f"attack_chain_{self._next_chain_id:04d}"
        self._next_chain_id += 1
        return chain_id

    @staticmethod
    def _cosine01(left: Tensor, right: Tensor) -> float:
        value = float(F.cosine_similarity(left.reshape(1, -1), right.reshape(1, -1)).item())
        return max(0.0, min(1.0, (value + 1.0) * 0.5))

    def _chain_entity_score(self, chain: AttackChainState, event: ProgressEvent) -> float:
        strength = 0.0
        for kind, values in event.entities.items():
            shared = chain.entities.get(kind, set()) & set(values)
            strength += self.memory.entity_weight(kind) * len(shared)
        return 1.0 - exp(-strength)

    def _chain_state_score(self, chain: AttackChainState, event: ProgressEvent) -> float:
        entity = self._chain_entity_score(chain, event)
        semantic = self._cosine01(chain.semantic_prototype, event.embedding)

        progress_delta = event.progress_score - chain.latest_progress
        progress = self.linker._soft_forward_score(
            progress_delta,
            self.linker.config.progress_tolerance,
            self.linker.config.progress_temperature,
        )

        transition = 0.5
        prototype = chain.position_prototype
        if prototype is not None and event.position_probabilities is not None:
            transition = float(
                self.linker.transition_model(
                    prototype,
                    event.position_probabilities,
                ).detach().cpu().item()
            )

        delta_hours = max(
            (event.timestamp - chain.latest_timestamp).total_seconds() / 3600.0,
            0.0,
        )
        time = 1.0 / (1.0 + delta_hours / self.linker.config.time_scale_hours)
        relevance = (chain.mean_relevance * event.relevance_probability) ** 0.5

        # Chain state guards assignment; the learned event linker remains the edge model.
        return relevance * (
            0.30 * entity
            + 0.25 * semantic
            + 0.20 * progress
            + 0.15 * transition
            + 0.10 * time
        )

    def _candidate_chain_scores(
        self,
        event: ProgressEvent,
        incoming: list[LongHorizonLink],
    ) -> dict[str, float]:
        grouped: dict[str, list[LongHorizonLink]] = {}
        for link in incoming:
            chain_id = self.event_to_chain.get(link.source_event)
            if chain_id is not None:
                grouped.setdefault(chain_id, []).append(link)

        scores: dict[str, float] = {}
        normalizer = self.config.link_support_weight + self.config.chain_state_weight
        for chain_id, links in grouped.items():
            link_support = max(link.score for link in links)
            state_support = self._chain_state_score(self.chains[chain_id], event)
            scores[chain_id] = (
                self.config.link_support_weight * link_support
                + self.config.chain_state_weight * state_support
            ) / normalizer
        return scores

    def process(self, event: ProgressEvent) -> ChainAssignment:
        event.validate(self.linker.config.embedding_dim, self.linker.config.num_positions)
        if event.event_id in self.event_to_chain:
            raise ValueError(f"event already assigned: {event.event_id}")

        incoming = self.linker.link_target(
            event,
            self.memory,
            top_k=self.config.max_incoming_links,
        )
        chain_scores = self._candidate_chain_scores(event, incoming)
        ranked = sorted(chain_scores.items(), key=lambda item: item[1], reverse=True)

        selected_chain: str | None = None
        selected_score = 0.0
        if ranked:
            best_chain, best_score = ranked[0]
            second_score = ranked[1][1] if len(ranked) > 1 else 0.0
            is_ambiguous = len(ranked) > 1 and best_score - second_score < self.config.ambiguity_margin
            if best_score >= self.config.assignment_threshold and not is_ambiguous:
                selected_chain = best_chain
                selected_score = best_score

        if selected_chain is None:
            selected_chain = self._new_chain_id()
            self.chains[selected_chain] = AttackChainState.from_event(selected_chain, event)
            created_new = True
            kept_links: tuple[LongHorizonLink, ...] = ()
        else:
            created_new = False
            kept = [
                link
                for link in incoming
                if self.event_to_chain.get(link.source_event) == selected_chain
            ]
            kept_links = tuple(kept)
            self.links.extend(kept)
            self.chains[selected_chain].add(event)

        self.event_to_chain[event.event_id] = selected_chain
        self.memory.add(event)
        return ChainAssignment(
            event_id=event.event_id,
            chain_id=selected_chain,
            created_new=created_new,
            score=selected_score,
            incoming_links=kept_links,
        )

    def process_many(self, events: list[ProgressEvent]) -> list[ChainAssignment]:
        assignments: list[ChainAssignment] = []
        for event in sorted(events, key=lambda row: (row.timestamp, row.event_id)):
            assignments.append(self.process(event))
        return assignments

    def chain_for(self, event_id: str) -> str:
        return self.event_to_chain[event_id]

    def summaries(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for chain_id in sorted(self.chains):
            chain = self.chains[chain_id]
            rows.append(
                {
                    "chain_id": chain_id,
                    "event_ids": tuple(chain.event_ids),
                    "event_count": chain.event_count,
                    "latest_timestamp": chain.latest_timestamp.isoformat(),
                    "latest_progress": chain.latest_progress,
                    "mean_relevance": chain.mean_relevance,
                }
            )
        return rows
