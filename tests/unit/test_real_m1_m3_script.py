from pathlib import Path


def test_real_upstream_script_refuses_to_claim_frozen_export():
    text = (Path(__file__).parents[2] / "scripts" / "build_real_m1_m3_features.py").read_text(encoding="utf-8")
    assert "PARTIAL_UPSTREAM_READY" in text
    assert "labels_read" in text
    assert "frozen_export" in text
