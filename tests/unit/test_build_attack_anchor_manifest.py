import json

from scripts.build_attack_anchor_manifest import build_manifest


def test_manifest_deduplicates_only_same_record_and_technique(tmp_path):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    row = {"record_id": "a", "technique_id": "T1003", "provenance": "rule", "confidence": 0.9}
    first.write_text(json.dumps(row) + "\n", encoding="utf-8")
    second.write_text(json.dumps(row) + "\n" + json.dumps({**row, "technique_id": "T1057"}) + "\n", encoding="utf-8")
    output = tmp_path / "manifest.jsonl"
    summary = build_manifest([first, second], output, tmp_path / "summary.json")
    assert summary["anchor_count"] == 2
    assert len(output.read_text(encoding="utf-8").splitlines()) == 2
