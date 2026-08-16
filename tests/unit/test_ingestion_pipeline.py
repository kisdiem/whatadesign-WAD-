from __future__ import annotations

from agent_service.ingestion import IngestionStore


def test_small_file_runs_persistent_m0_m6_pipeline(tmp_path) -> None:
    store = IngestionStore(tmp_path / "ingestion.db")
    result = store.ingest_bytes(
        "security.log",
        (
            b"2026-08-16T10:00:00Z failed password for user alice from 10.0.0.8\n"
            b"2026-08-16T10:01:00Z useradd user=bob host=server-1\n"
        ),
        "text/plain",
    )

    assert result["job"]["status"] == "ready"
    assert result["job"]["pipeline"] == "m0-m6-prototype-v1"
    assert result["job"]["labels_used"] is False
    assert result["job"]["event_count"] == 2
    assert result["windows"]
    assert result["investigation"] is not None
    assert set(result["events"][0]["module_scores"]) == {f"M{index}" for index in range(7)}
    assert result["events"][0]["timestamp_origin"] == "source"

    reopened = IngestionStore(tmp_path / "ingestion.db")
    snapshot = reopened.snapshot()
    assert snapshot["event_count"] == 2
    assert snapshot["manifest"]["counts"]["jobs"] == 1
    assert reopened.search(entities=["alice"], source_types=[], keywords=[], start_time=None, end_time=None, limit=10)["count"] == 1


def test_missing_timestamp_is_explicitly_marked_as_ingest_fallback(tmp_path) -> None:
    store = IngestionStore(tmp_path / "fallback.db")
    result = store.ingest_bytes("plain.log", b"ordinary message without a timestamp\n")

    assert result["events"][0]["timestamp_origin"] == "ingest_fallback"
    assert result["events"][0]["labels_used"] is False
