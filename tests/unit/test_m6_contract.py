import torch

from src.fusion.m6_hierarchical import M6Config, M6HierarchicalFusion


def test_m6_hierarchical_output_contract():
    model = M6HierarchicalFusion(M6Config(embedding_dim=8, hidden_dim=16))
    output = model(torch.zeros(4, 8), torch.zeros(4), torch.ones(4))
    assert set(output) == {"event_logit", "micro_logit", "macro_logit", "fused_logit"}
    assert all(value.shape == (4,) for value in output.values())


def test_m6_rejects_misaligned_modalities():
    model = M6HierarchicalFusion(M6Config(embedding_dim=8, hidden_dim=16))
    try:
        model(torch.zeros(4, 8), torch.zeros(3), torch.zeros(4))
    except ValueError:
        pass
    else:
        raise AssertionError("modalities must share batch size")
