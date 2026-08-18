from datetime import datetime, timedelta

import torch

from src.temporal.m5_attack_chain_manager import (
    M5AttackChainManager,
    M5AttackChainManagerConfig,
)
from src.temporal.m5_entity_progress_linker import (
    M5EntityProgressLinker,
    M5LongHorizonProgressConfig,
    ProgressEvent,
)


def _event(
    event_id: str,
    minute: int,
    *,
    hosts: tuple[str, ...],
    progress: float,
    position: int,
) -> ProgressEvent:
    positions = torch.zeros(6)
    positions[position] = 1.0
    return ProgressEvent(
        event_id=event_id,
        timestamp=datetime(2026, 8, 1) + timedelta(minutes=minute),
        embedding=torch.ones(8),
        entities={"host": frozenset(hosts)},
        relevance_probability=0.95,
        progress_score=progress,
        position_probabilities=positions,
    )


def _manager(ambiguity_margin: float = 0.04) -> M5AttackChainManager:
    linker = M5EntityProgressLinker(
        M5LongHorizonProgressConfig(
            embedding_dim=8,
            num_positions=6,
            local_window_minutes=15,
            link_threshold=0.55,
        )
    )
    return M5AttackChainManager(
        linker=linker,
        config=M5AttackChainManagerConfig(
            assignment_threshold=0.60,
            ambiguity_margin=ambiguity_margin,
        ),
    )


def test_chain_manager_assigns_later_related_event_to_existing_chain():
    manager = _manager()
    first = manager.process(_event("e1", 0, hosts=("host-a",), progress=0.20, position=1))
    second = manager.process(_event("e2", 45, hosts=("host-a",), progress=0.45, position=2))

    assert first.created_new
    assert not second.created_new
    assert first.chain_id == second.chain_id
    assert manager.chain_for("e1") == manager.chain_for("e2")
    assert any(link.source_event == "e1" and link.target_event == "e2" for link in manager.links)


def test_chain_manager_does_not_merge_existing_chains_on_ambiguous_bridge():
    manager = _manager(ambiguity_margin=0.10)
    chain_a = manager.process(_event("a1", 0, hosts=("host-a",), progress=0.20, position=1))
    chain_b = manager.process(_event("b1", 1, hosts=("host-b",), progress=0.20, position=1))
    bridge = manager.process(
        _event("bridge", 60, hosts=("host-a", "host-b"), progress=0.45, position=2)
    )

    assert chain_a.chain_id != chain_b.chain_id
    assert bridge.created_new
    assert bridge.chain_id not in {chain_a.chain_id, chain_b.chain_id}
    assert manager.chain_for("a1") == chain_a.chain_id
    assert manager.chain_for("b1") == chain_b.chain_id
    assert len(manager.chains) == 3


def test_each_event_has_exactly_one_chain_assignment():
    manager = _manager()
    manager.process_many(
        [
            _event("e1", 0, hosts=("host-a",), progress=0.20, position=1),
            _event("e2", 20, hosts=("host-a",), progress=0.35, position=2),
            _event("e3", 40, hosts=("host-b",), progress=0.25, position=1),
        ]
    )

    assert set(manager.event_to_chain) == {"e1", "e2", "e3"}
    assert all(isinstance(chain_id, str) for chain_id in manager.event_to_chain.values())
