import json

from scripts.build_m5_window_features import main


def test_m5_window_aggregation_keeps_labels_separate(tmp_path, monkeypatch):
    m4 = tmp_path / "m4.jsonl"
    windows = tmp_path / "windows.jsonl"
    labels = tmp_path / "labels.jsonl"
    output = tmp_path / "m5.jsonl"
    m4.write_text(json.dumps({"record_id": "e1", "event_embedding": [1.0, 3.0], "raw_event_score": 0.1, "micro_window_score": 0.2, "macro_window_score": 0.3}) + "\n")
    windows.write_text(json.dumps({"window_id": "w1", "dataset_id": "ait2", "end": "2022-01-01T00:30:00+00:00", "record_ids": ["e1"]}) + "\n")
    labels.write_text(json.dumps({"window_id": "w1", "label": 1}) + "\n")
    monkeypatch.setattr("sys.argv", ["build_m5_window_features", "--m4-features", str(m4), "--windows", str(windows), "--labels", str(labels), "--output", str(output)])
    main()
    row = json.loads(output.read_text().splitlines()[0])
    assert row["event_embedding"] == [1.0, 3.0]
    assert row["m5_score"] is None
    assert "label" not in row
    assert json.loads(output.with_name("m5.labels.jsonl").read_text()) == {"record_id": "w1", "label": 1}
