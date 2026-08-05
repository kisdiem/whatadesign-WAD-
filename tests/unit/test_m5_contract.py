import torch

from src.temporal.m5_long_horizon import M5Config, M5LongHorizonLinker


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
