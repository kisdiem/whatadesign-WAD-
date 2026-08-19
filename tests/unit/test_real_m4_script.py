from pathlib import Path


def test_real_m4_script_requires_m5_before_frozen_export():
    text = (Path(__file__).parents[2] / "scripts" / "build_real_m4_features.py").read_text(encoding="utf-8")
    assert "M4_FEATURES_READY_M5_PENDING" in text
    assert '"m5_score": "not_generated"' in text
    assert "qwen_is_mock" in text
