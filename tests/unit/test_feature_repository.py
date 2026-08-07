from src.common.schema import EventFrame, FrozenFeatureRecord
from src.pipeline.feature_repository import FeatureRepository


def test_repository_records_artifacts_lineage_and_operations(tmp_path):
    store = FeatureRepository(tmp_path / "core.sqlite")
    store.register_run("run-1", "m1", "source", "config-hash")
    artifact = store.register_artifact("artifacts/m1.jsonl", "a" * 64, stage="m1", schema_version="v3")
    frame = EventFrame(dataset_id="source", record_id="r1", timestamp="2026-01-01T00:00:00+00:00", semantic_embedding=[.1, .2])
    store.put_eventframe(frame, artifact_id=artifact)
    frozen = FrozenFeatureRecord("r1", "source", frame.timestamp, semantic_embedding=[.1, .2], event_embedding=[.3])
    store.put_frozen_feature(frozen)
    store.link("m6_frozen_feature", "r1", "m1_eventframe", "r1")
    assert store.records("m1_eventframe", "source")[0]["record_id"] == "r1"
    assert store.connection.execute("SELECT COUNT(*) FROM lineage").fetchone()[0] == 1
    assert store.connection.execute("SELECT COUNT(*) FROM operation_log").fetchone()[0] >= 2
    store.close()
