import torch

from src.models.m4_qformer import M4Config, M4QFormerDecoder


def test_m4_forward_contract():
    model = M4QFormerDecoder(M4Config(input_dim=16, hidden_dim=16, heads=4, layers=1, query_count=2, slot_count=3, slot_vocab_size=11))
    output = model(torch.zeros(3, 5, 16), torch.zeros(3, 16), torch.zeros(3, 4, 16))
    assert output["embedding"].shape == (3, 16)
    assert output["slot_logits"].shape == (3, 3, 11)
    assert output["raw_event_logit"].shape == (3,)
    assert model.slot_nll(output, torch.zeros(3, 3, dtype=torch.long)).ndim == 0


def test_m4_rejects_wrong_feature_shape():
    model = M4QFormerDecoder(M4Config(input_dim=16, hidden_dim=16, heads=4, layers=1))
    try:
        model(torch.zeros(1, 5, 8), torch.zeros(1, 16), torch.zeros(1, 2, 16))
    except ValueError:
        pass
    else:
        raise AssertionError("wrong input dimension must be rejected")


def test_m4_has_explicit_current_event_boundary():
    model = M4QFormerDecoder(M4Config(input_dim=8, hidden_dim=8, heads=2, layers=1))
    output = model(torch.randn(2, 4, 8), torch.randn(2, 8), torch.randn(2, 3, 8))
    assert output["slot_logits"].shape[0] == 2
