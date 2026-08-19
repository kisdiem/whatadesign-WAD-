from pathlib import Path


def test_formal_m6_script_exists_and_is_not_development_checkpoint():
    script = Path(__file__).parents[2] / "scripts" / "train_m6_long_horizon.py"
    text = script.read_text(encoding="utf-8")
    assert '"release_eligible": True' in text
    assert "development_checkpoint" not in text
    assert "test_metrics" in text
