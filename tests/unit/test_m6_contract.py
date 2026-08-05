import torch

from src.fusion.m6_hierarchical import FrozenFeatureRecord, M6Config, M6HierarchicalFusion, fit_source_calibration


def test_m6_hierarchical_output_contract():
    model = M6HierarchicalFusion(M6Config(embedding_dim=8, hidden_dim=16))
    output = model(torch.zeros(4, 8), torch.zeros(4), torch.ones(4))
    assert set(output) == {"event_logit", "micro_logit", "macro_logit", "fused_logit"}
    assert all(value.shape == (4,) for value in output.values())
    assert model.loss(output, torch.tensor([0, 1, 0, 1]))["total"].ndim == 0


def test_m6_rejects_misaligned_modalities():
    model = M6HierarchicalFusion(M6Config(embedding_dim=8, hidden_dim=16))
    try:
        model(torch.zeros(4, 8), torch.zeros(3), torch.zeros(4))
    except ValueError:
        pass
    else:
        raise AssertionError("modalities must share batch size")


def test_m6_metadata_is_not_a_model_feature_and_calibration_is_source_only():
    record = FrozenFeatureRecord("r", "source_a", torch.ones(8), 0.2, 0.3, "attack", "scenario")
    assert record.model_features()[0].shape == (8,)
    calibration = fit_source_calibration(torch.tensor([-2.0, 2.0]), torch.tensor([0, 1]), "source_a")
    assert calibration.source_name == "source_a"
    try:
        fit_source_calibration(torch.tensor([0.0]), torch.tensor([0]), "ait_lds_v2")
    except ValueError:
        pass
    else:
        raise AssertionError("AIT must not fit source calibration")
