from datetime import datetime, timedelta

import torch

from src.temporal.m5_entity_progress_linker import (
    M5AttackChainAssembler,
    M5EntityProgressLinker,
    M5LongHorizonProgressConfig,
    PersistentEntityMemory,
    ProgressEvent,
)


def _event(
    event_id: str,
    hour: int,
    *,
    progress: float,
    host: str = "host-a",
    ip: str | None = None,
    relevance: float = 1.0,
    position: int = 2,
) -> ProgressEvent:
    entities = {"host": frozenset({host})} if host else {}
    if ip is not None:
        entities["ip"] = frozenset({ip})
    position_probs = torch.zeros(6)
    position_probs[position] = 1.0
    return ProgressEvent(
        event_id=event_id,
        timestamp=datetime(2026, 8, 1) + timedelta(hours=hour),
        embedding=torch.ones(8),
        entities=entities,
        relevance_probability=relevance,
        progress_score=progress,
        position_probabilities=position_probs,
    )


def _linker(**kwargs) -> M5EntityProgressLinker:
    return M5EntityProgressLinker(M5LongHorizonProgressConfig(
        embedding_dim=8,
        link_threshold=0.55,
        **kwargs,
    ))


def test_entity_memory_retrieves_only_shared_historical_candidates():
    memory = PersistentEntityMemory()
    memory.add(_event("same-host", 1, progress=0.2, host="host-a"))
    memory.add(_event("other-host", 2, progress=0.3, host="host-b"))
    target = _event("target", 10, progress=0.6, host="host-a")

    candidates = memory.candidates(target, max_candidates=8, max_candidates_per_entity=8)
    assert [row.event_id for row in candidates] == ["same-host"]


def test_time_order_is_a_hard_constraint():
    memory = PersistentEntityMemory()
    linker = _linker()
    later = _event("later", 10, progress=0.7)
    earlier = _event("earlier", 2, progress=0.3)

    assert linker.score_pair(later, earlier, memory) is None
    assert linker.score_pair(later, later, memory) is None


def test_progress_order_is_soft_not_hard():
    memory = PersistentEntityMemory()
    linker = _linker(progress_tolerance=0.10, progress_temperature=0.10)
    source = _event("source", 1, progress=0.60)
    small_backtrack = _event("small", 2, progress=0.54)
    large_backtrack = _event("large", 3, progress=0.15)

    small, _ = linker.evidence(source, small_backtrack, memory)
    large, _ = linker.evidence(source, large_backtrack, memory)

    assert small["progress"] == 1.0
    assert 0.0 < large["progress"] < 0.1


def test_ip_only_match_is_not_enough_to_create_long_horizon_edge():
    memory = PersistentEntityMemory()
    linker = _linker()
    source = _event("source", 1, progress=0.2, host="", ip="10.0.0.8")
    target = _event("target", 2, progress=0.6, host="", ip="10.0.0.8")

    assert linker.score_pair(source, target, memory) is None


def test_streaming_assembler_only_creates_forward_edges():
    assembler = M5AttackChainAssembler(linker=_linker())
    first = _event("e1", 1, progress=0.20, position=1)
    second = _event("e2", 6, progress=0.48, position=2)
    third = _event("e3", 30, progress=0.72, position=4)

    assert assembler.process(first) == []
    links_second = assembler.process(second)
    links_third = assembler.process(third)

    assert any(link.source_event == "e1" and link.target_event == "e2" for link in links_second)
    assert any(link.target_event == "e3" for link in links_third)
    assert all(
        assembler.memory.get(link.source_event).timestamp < assembler.memory.get(link.target_event).timestamp
        for link in assembler.links
    )


def test_low_relevance_event_is_not_linked_even_with_shared_entities():
    memory = PersistentEntityMemory()
    linker = _linker()
    source = _event("source", 1, progress=0.2)
    target = _event("target", 2, progress=0.5, relevance=0.1)

    assert linker.score_pair(source, target, memory) is None
