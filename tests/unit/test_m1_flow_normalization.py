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
