import torch

from src.models.m4_qformer import M4Config, M4QFormerDecoder


def test_m4_forward_contract():
    model = M4QFormerDecoder(M4Config(input_dim=16, hidden_dim=16, heads=4, layers=1, query_count=2))
    output = model(torch.zeros(3, 5, 16))
    assert output["embedding"].shape == (3, 16)
    assert output["score_logit"].shape == (3,)


def test_m4_rejects_wrong_feature_shape():
    model = M4QFormerDecoder(M4Config(input_dim=16, hidden_dim=16, heads=4, layers=1))
    try:
        model(torch.zeros(1, 5, 8))
    except ValueError:
        pass
    else:
        raise AssertionError("wrong input dimension must be rejected")
