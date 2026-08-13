import torch

from src.common.schema import RawRecord, SyntaxParse
from src.semantic.m1_normalizer import M1SemanticNormalizer
from src.semantic.m1_multitask import M1DebertaMultiTask, M1ModelConfig


def test_m1_normalizes_without_labels():
    parsed = SyntaxParse("d", "r", "x.log", 1, "text", None,
                         {"template": "failed login from 10.0.0.1 user=alice"},
                         "drain:1", 1.0, "x.log:1")
    frame = M1SemanticNormalizer().normalize(parsed)
    assert frame.action == "authenticate"
    assert frame.outcome == "failure"
    assert "10.0.0.1" in frame.entities
    assert "label" not in str(frame.attributes).lower()


def test_m1_taxonomy_hook_is_descriptive_only():
    class Provider:
        def classify(self, template, fields):
            return {"ocsf_class": "Authentication", "target_label": "must_not_enter"}

    parsed = SyntaxParse("d", "r", "x.log", 1, "text", None, {"template": "successful login"}, "drain:1", 1.0, "x.log:1")
    frame = M1SemanticNormalizer(Provider()).normalize(parsed)
    assert frame.attributes["ocsf_class"] == "Authentication"
    assert "target_label" not in frame.attributes


def test_m1_multitask_outputs_bio_roles_ood_and_slot_losses():
    model = M1DebertaMultiTask(M1ModelConfig(hidden_dim=8, record_kind_count=3, relation_count=4, action_count=5, role_count=3, outcome_count=2, entity_family_count=3, prototype_count=6))
    output = model(torch.randn(2, 4, 8))
    assert output["bio_logits"].shape == (2, 4, 3)
    targets = {name: torch.zeros(2, dtype=torch.long) for name in ("record_kind", "relation", "action", "role", "outcome", "prototype")}
    targets.update({"bio": torch.zeros(2, 4, dtype=torch.long), "entity_family": torch.zeros(2, 4, dtype=torch.long), "ood": torch.zeros(2)})
    assert model.loss(output, targets)["total"].ndim == 0
