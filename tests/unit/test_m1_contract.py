from src.common.schema import RawRecord, SyntaxParse
from src.semantic.m1_normalizer import M1SemanticNormalizer


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
