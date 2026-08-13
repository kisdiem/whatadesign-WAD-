from datetime import datetime, timedelta

import torch

from src.temporal.m5_long_horizon import M5Config, M5LongHorizonLinker, WindowRecord, build_attack_queues


def test_m5_cross_window_score_contract():
    model = M5LongHorizonLinker(M5Config(embedding_dim=8, hidden_dim=16))
    score = model(torch.zeros(2, 8), torch.ones(2, 8), torch.tensor([1800.0, 86400.0]))
    assert score.shape == (2,)
    assert torch.all((model.probability(torch.zeros(2, 8), torch.ones(2, 8), torch.tensor([1.0, 2.0])) >= 0))


def test_m5_rejects_mismatched_windows():
    model = M5LongHorizonLinker(M5Config(embedding_dim=8, hidden_dim=16))
    try:
        model(torch.zeros(2, 8), torch.zeros(3, 8), torch.zeros(2))
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched windows must be rejected")


def test_m5_weak_ip_does_not_create_attack_link():
    model = M5LongHorizonLinker(M5Config(embedding_dim=8, hidden_dim=8))
    base = datetime(2026, 1, 1)
    left = WindowRecord("w1", base, base + timedelta(minutes=5), torch.randn(8), {"ip": frozenset({"1.1.1.1"})})
    right = WindowRecord("w2", base + timedelta(days=1), base + timedelta(days=1, minutes=5), torch.randn(8), {"ip": frozenset({"1.1.1.1"})})
    assert model.link_windows(left, right) is None


def test_m5_strong_anchor_builds_deterministic_queue():
    model = M5LongHorizonLinker(M5Config(embedding_dim=8, hidden_dim=8))
    base = datetime(2026, 1, 1)
    windows = [
        WindowRecord("w1", base, base + timedelta(minutes=5), torch.ones(8), {"user": frozenset({"u1"})}),
        WindowRecord("w2", base + timedelta(hours=1), base + timedelta(hours=1, minutes=5), torch.ones(8), {"user": frozenset({"u1"})}),
    ]
    links, queues = build_attack_queues(windows, model, threshold=0.0)
    assert len(links) == 1
    assert queues.as_dicts()[0]["window_ids"] == ["w1", "w2"]
