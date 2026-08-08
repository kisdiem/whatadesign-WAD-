from src.common.schema import EventFrame
from src.semantic.deberta_security import FrozenDebertaSecurityEmbedder
from src.semantic.security_log_text import security_log_text


def test_frozen_embedder_payload_is_allow_listed_and_label_free():
    frame = EventFrame(
        dataset_id="source", record_id="r1", record_kind="network", action_family="connect",
        key_attributes={"port": 443, "attack_label": "must_not_leak"},
        attributes={"target_label": 1, "split": "target"},
    )
    text = security_log_text(frame.dataset_id, FrozenDebertaSecurityEmbedder._payload(frame))
    assert "attack_label" not in text
    assert "target_label" not in text
    assert "split" not in text
