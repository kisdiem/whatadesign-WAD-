from pathlib import Path

from src.pipeline.source_preprocess import run_source_preprocess


def test_source_preprocess_connects_m0_to_m3(tmp_path: Path):
    path = tmp_path / "source.log"
    path.write_text("failed login from 10.0.0.1 user=alice\n", encoding="utf-8")
    result = run_source_preprocess("loghub_2_0", path)
    assert result.status == "ok"
    assert result.raw_records == 1
    assert result.parsed_records == 1
    assert result.graph is not None
    assert result.frames[0].outcome == "failure"
