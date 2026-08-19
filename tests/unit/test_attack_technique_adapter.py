import pytest
import torch

from src.knowledge.attack_techniques import TechniqueCard, TechniqueSupervision, cards_from_stix, validate_event_payload
from src.models.attack_technique_adapter import AttackTechniqueAdapter, AttackTechniqueAdapterConfig
from scripts.build_attack_technique_cards import export_high_precision_supervision


def test_card_semantic_text_excludes_opaque_technique_identifier():
    card = TechniqueCard("T1110", "Brute Force", ("credential-access",), "Adversary guesses credentials.")
    assert "T1110" not in card.semantic_text()
    assert "Brute Force" in card.semantic_text()


def test_event_payload_rejects_attack_label():
    with pytest.raises(ValueError, match="forbidden"):
        validate_event_payload({"attributes": {"attack_label": 1}})


def test_stix_cards_keep_external_id_out_of_semantic_text():
    cards = cards_from_stix([{
        "type": "attack-pattern", "name": "Brute Force", "description": "Credential guessing.",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
        "kill_chain_phases": [{"phase_name": "credential-access"}],
    }])
    assert cards[0].technique_id == "T1110"
    assert "T1110" not in cards[0].semantic_text()


def test_adapter_accepts_only_embeddings_and_labels_only_enter_loss():
    model = AttackTechniqueAdapter(AttackTechniqueAdapterConfig(event_dim=4, card_dim=4, hidden_dim=3))
    output = model(torch.ones(2, 4), torch.ones(3, 4))
    assert output["logits"].shape == (2, 3)
    loss = model.loss(output, torch.zeros(2, 3))
    assert torch.isfinite(loss)
    supervision = TechniqueSupervision("event-1", "T1110", "manual_template_audit", 0.95)
    assert supervision.technique_id == "T1110"


def test_only_auditable_high_precision_rules_become_weak_supervision(tmp_path):
    mapping = tmp_path / "mapping.jsonl"
    mapping.write_text(
        '{"record_id":"brute","candidates":[{"technique_id":"T1110","confidence":0.76,"disposition":"candidate","mapping_source":"structured_rule"}]}\n'
        '{"record_id":"scan","candidates":[{"technique_id":"T1595","confidence":0.99,"disposition":"candidate","mapping_source":"structured_rule"}]}\n',
        encoding="utf-8",
    )
    output = tmp_path / "anchors.jsonl"
    assert export_high_precision_supervision([mapping], output) == 1
    assert '"T1110"' in output.read_text(encoding="utf-8")
