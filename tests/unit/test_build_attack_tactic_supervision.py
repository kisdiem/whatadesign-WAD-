import json

from scripts.build_attack_tactic_supervision import main


def test_tactic_builder_keeps_labels_separate(tmp_path, monkeypatch):
    cards = tmp_path / "cards.jsonl"
    cards.write_text(json.dumps({"technique_id": "T1047", "name": "WMI", "tactics": ["execution"], "description": "x"}) + "\n", encoding="utf-8")
    supervision = tmp_path / "supervision.jsonl"
    supervision.write_text(json.dumps({"record_id": "r", "technique_id": "T1047", "provenance": "rule", "confidence": 0.9}) + "\n", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["script", "--cards", str(cards), "--supervision", str(supervision), "--card-output", str(tmp_path / "out-cards"), "--supervision-output", str(tmp_path / "out-labels")])
    main()
    assert 'tactic:execution' in (tmp_path / "out-labels").read_text(encoding="utf-8")
