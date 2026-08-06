import json
import subprocess
import sys
from pathlib import Path


def test_synthetic_v3_pipeline_produces_auditable_run(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    work = tmp_path / "synthetic_run"
    result = subprocess.run(
        [sys.executable, "scripts/run_synthetic_v3_pipeline.py", "--work-dir", str(work), "--seed", "42"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout)["status"] == "COMPLETED"
    run = json.loads((work / "run_manifest.json").read_text(encoding="utf-8"))
    assert run["execution_mode"] == "synthetic"
    assert run["real_data_used"] is False
    assert run["release_eligible"] is False
    assert run["m6_parameter_hash_before"] != run["m6_parameter_hash_after"]
    assert run["m0_m5_unchanged_after_m6"] is True
    assert run["ip_only_rejection_count"] >= 1
    assert "development checkpoint" in run["release_rejection_reason"]

    required = [
        "raw_records.jsonl", "syntax_parses.jsonl", "quarantine.jsonl",
        "event_frames.jsonl", "entities.jsonl", "event_entity_links.jsonl",
        "event_graphs.jsonl", "causal_m4_batches.jsonl", "m4_outputs.jsonl",
        "micro_windows.jsonl", "macro_windows.jsonl", "window_pairs.jsonl",
        "ip_only_rejections.jsonl", "window_links.jsonl", "attack_queues.jsonl",
        "summary_graphs.jsonl", "evidence_steps.jsonl", "frozen_features.jsonl",
        "m6_manifest.json",
    ]
    for name in required:
        path = work / name
        assert path.exists(), name
        if path.suffix == ".jsonl":
            assert path.read_text(encoding="utf-8").strip(), name

    graphs = [json.loads(line) for line in (work / "event_graphs.jsonl").read_text(encoding="utf-8").splitlines()]
    roles = {edge["role"] for edge in graphs[0]["edge_records"]}
    assert {"actor_of", "object_of", "destination_of"}.issubset(roles)
    assert not any(node["node_type"] == "action" for node in graphs[0]["node_records"])

    windows = [json.loads(line) for line in (work / "micro_windows.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(row["event_count"] > 1 for row in windows)
    rejected = [json.loads(line) for line in (work / "ip_only_rejections.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(row["rejected_reason"] == "ip_only_anchor" for row in rejected)
