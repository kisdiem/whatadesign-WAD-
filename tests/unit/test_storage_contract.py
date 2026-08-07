from pathlib import Path

import pytest

from src.storage.repository import RepositoryError, assert_no_forbidden_business_keys, stable_id


def test_business_payload_rejects_labels_and_splits():
    with pytest.raises(RepositoryError):
        assert_no_forbidden_business_keys({"nested": {"attack_label": 1}})
    with pytest.raises(RepositoryError):
        assert_no_forbidden_business_keys({"split": "test"})


def test_stable_id_is_deterministic():
    assert stable_id("event", {"b": 2, "a": 1}) == stable_id("event", {"a": 1, "b": 2})
    assert stable_id("event", 1) != stable_id("event", 2)


def test_postgres_migrations_define_business_tables_without_stage_records():
    root = Path(__file__).resolve().parents[2]
    sql = "\n".join(path.read_text(encoding="utf-8") for path in sorted((root / "migrations/postgres").glob("*.sql")))
    for table in (
        "pipeline_runs",
        "artifacts",
        "lineage",
        "operation_logs",
        "entities",
        "entity_aliases",
        "entity_observations",
        "events",
        "event_entities",
        "event_relations",
        "context_windows",
        "window_events",
        "detection_results",
        "window_detection_results",
        "window_links",
        "attack_chains",
        "attack_chain_windows",
        "attack_chain_events",
    ):
        assert f"CREATE TABLE {table}" in sql
    assert "CREATE TABLE stage_records" not in sql
