from src.common.schema import SyntaxParse
from src.semantic.m1_normalizer import M1SemanticNormalizer


def test_ctu_flow_becomes_structured_label_free_eventframe():
    parsed = SyntaxParse(dataset_id="ctu13", record_id="r1", timestamp="2011/08/15 16:43:20.931208", fields={
        "SrcAddr": "147.32.84.59", "DstAddr": "164.8.32.159", "Sport": "64131", "Dport": "443",
        "Proto": "tcp", "State": "PA_PA", "Label": "flow=Botnet",
    })
    frame = M1SemanticNormalizer().normalize(parsed)
    assert frame.dataset_id == "ctu13"
    assert (frame.record_kind, frame.relation_type, frame.action_family, frame.action_leaf) == ("network", "flow", "connect", "tcp")
    assert {item["raw_value"] for item in frame.entity_mentions} >= {"147.32.84.59", "164.8.32.159"}
    assert "Label" not in frame.key_attributes


def test_sandworm_flow_column_aliases_are_normalized():
    parsed = SyntaxParse(dataset_id="sandworm_flow", record_id="r2", timestamp="2025-02-18 11:02:18.543737", fields={
        "Src IP": "192.168.21.229", "Dst IP": "192.168.21.206", "Src Port": "50431", "Dst Port": "4712",
        "Protocol": "6", "Label": "Malicious",
    })
    frame = M1SemanticNormalizer().normalize(parsed)
    assert frame.action_leaf == "tcp"
    assert frame.roles["source_ip"] == "192.168.21.229"
    assert frame.roles["destination_ip"] == "192.168.21.206"
    assert "Label" not in frame.key_attributes
