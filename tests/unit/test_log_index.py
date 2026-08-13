from pathlib import Path

from src.detection.log_index import build_log_index, index_metadata, index_overview, search_log_index


def test_log_index_exposes_all_rows_through_pagination(tmp_path: Path) -> None:
    gather = tmp_path / "dataset" / "gather"
    gather.mkdir(parents=True)
    (gather / "eve.json").write_text("\n".join(
        f'{{"timestamp":"2026-01-01T00:00:{index:02d}Z","event_type":"dns","src_ip":"10.0.0.{index}","dns":{{"rrname":"host{index}.example"}}}}'
        for index in range(6)
    ) + "\n", encoding="utf-8")
    database = tmp_path / "logs.sqlite"
    result = build_log_index([gather.parent], database, max_records_per_root=100)
    assert result["indexed_records"] == 6
    assert result["labels_accessed"] is False
    assert result["replay_profile"] == "business-cycle-bursts-v2"
    assert index_metadata(database)["source_count"] == 1

    page = search_log_index(database, entities=[], source_types=[], keywords=[], start_time=None,
                            end_time=None, limit=2, offset=4)
    assert page["count"] == 6
    assert len(page["events"]) == 2
    assert page["offset"] == 4
    assert page["has_more"] is False

    counts = [index_overview(database, value)["event_count"] for value in ("1h", "24h", "7d", "30d")]
    assert counts == sorted(counts)
    assert len(set(counts)) > 1
    replay_page = search_log_index(database, entities=[], source_types=[], keywords=[], start_time=None,
                                   end_time=None, limit=10, offset=0, time_range="1h")
    assert replay_page["count"] == counts[0]
    if replay_page["events"]:
        assert replay_page["events"][0]["original_timestamp"]
        assert replay_page["events"][0]["time_mode"] == "scenario_replay"


def test_replay_profile_has_visible_peak_and_trough_buckets(tmp_path: Path) -> None:
    gather = tmp_path / "dataset" / "gather"
    gather.mkdir(parents=True)
    (gather / "eve.json").write_text("\n".join(
        f'{{"timestamp":"2026-01-01T00:00:00Z","event_type":"dns","src_ip":"10.0.{index // 255}.{index % 255}","dns":{{"rrname":"host{index}.example"}}}}'
        for index in range(4000)
    ) + "\n", encoding="utf-8")
    database = tmp_path / "logs.sqlite"
    build_log_index([gather.parent], database, max_records_per_root=5000)
    daily = [row["events"] for row in index_overview(database, "30d")["timeline"]]
    assert max(daily) > min(daily) * 2


def test_log_index_redacts_suspicious_payloads(tmp_path: Path) -> None:
    gather = tmp_path / "dataset" / "gather"
    gather.mkdir(parents=True)
    (gather / "events.jsonl").write_text(
        '{"timestamp":"2026-01-01T00:00:00Z","message":"powershell -encodedcommand SECRET"}\n',
        encoding="utf-8",
    )
    database = tmp_path / "logs.sqlite"
    build_log_index([gather.parent], database)
    page = search_log_index(database, entities=[], source_types=[], keywords=[], start_time=None,
                            end_time=None, limit=10, offset=0)
    assert "SECRET" not in page["events"][0]["text"]
    assert "quarantined" in page["events"][0]["text"].lower()
