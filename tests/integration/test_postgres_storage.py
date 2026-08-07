from __future__ import annotations

import os
import uuid

import pytest

from src.common.schema import EntityRecord, EventFrame, FrozenFeatureRecord
from src.storage.repository import RepositoryError, SecurityRepository


DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="TEST_DATABASE_URL is not configured")


def test_postgres_entity_history_detection_and_attack_chain():
    suffix = uuid.uuid4().hex
    dataset = f"storage-it-{suffix}"
    event1 = f"event-{suffix}-1"
    event2 = f"event-{suffix}-2"
    entity_id = f"entity-{suffix}"
    chain_id = f"chain-{suffix}"

    with SecurityRepository(DATABASE_URL, auto_migrate=True) as repo:
        frame1 = EventFrame(
            dataset_id=dataset,
            record_id=event1,
            timestamp="2026-08-08T10:00:00+00:00",
            record_kind="authentication",
            relation_type="login",
            action_family="login",
            action_leaf="success",
            outcome="success",
        )
        frame2 = EventFrame(
            dataset_id=dataset,
            record_id=event2,
            timestamp="2026-08-08T12:00:00+00:00",
            record_kind="network",
            relation_type="connect",
            action_family="connect",
            action_leaf="outbound",
            outcome="success",
        )
        repo.put_event(frame1)
        repo.put_event(frame2)
        with pytest.raises(RepositoryError):
            repo.put_event(EventFrame(
                dataset_id=dataset,
                record_id=event1,
                timestamp=frame1.timestamp,
                record_kind="authentication",
                relation_type="login",
                action_family="login",
                action_leaf="success",
                outcome="failure",
            ))

        entity = EntityRecord(
            dataset_id=dataset,
            entity_id=entity_id,
            entity_type="host",
            raw_value="host-a",
            canonical_value="host-a",
            instance_key="host-a",
            confidence=0.9,
            resolution_method="integration_test",
        )
        repo.upsert_entity(entity, observed_at=frame1.timestamp, attributes={"ip": "10.0.0.8"})
        repo.append_entity_observation(
            entity_id,
            event_id=event1,
            timestamp=frame1.timestamp,
            attribute_name="ip",
            observed_value="10.0.0.8",
            confidence=0.9,
        )
        repo.upsert_entity(entity, observed_at=frame2.timestamp, attributes={"ip": "10.0.0.21"})
        repo.append_entity_observation(
            entity_id,
            event_id=event2,
            timestamp=frame2.timestamp,
            attribute_name="ip",
            observed_value="10.0.0.21",
            confidence=0.9,
        )
        repo.link_event_entity(event1, entity_id, "destination_host", 0.9)
        repo.link_event_entity(event2, entity_id, "destination_host", 0.9)
        repo.put_event_relation(event1, event2, "shared_host", confidence=0.9, time_delta_seconds=7200)

        stored = repo.get_entity(entity_id)
        assert stored is not None
        assert stored["first_seen"].isoformat().startswith("2026-08-08T10:00:00")
        assert stored["last_seen"].isoformat().startswith("2026-08-08T12:00:00")
        repo.append_entity_observation(
            entity_id,
            event_id=event2,
            timestamp=frame2.timestamp,
            attribute_name="ip",
            observed_value="10.0.0.21",
            confidence=0.9,
        )
        history = repo.get_entity_history(entity_id)
        assert [row["observed_value"] for row in history] == ["10.0.0.8", "10.0.0.21"]

        ip1 = EntityRecord(dataset, f"ip-{suffix}-1", "ip", "10.0.0.9", "10.0.0.9", "host-a", host_scope="host-a", confidence=0.4)
        ip2 = EntityRecord(dataset, f"ip-{suffix}-2", "ip", "10.0.0.9", "10.0.0.9", "host-b", host_scope="host-b", confidence=0.4)
        repo.upsert_entity(ip1, observed_at=frame1.timestamp)
        repo.upsert_entity(ip2, observed_at=frame1.timestamp)
        repo.upsert_entity_alias(
            ip1.entity_id, dataset, alias_type="ip", alias_value="10.0.0.9",
            scope="host-a", observed_at=frame1.timestamp, confidence=0.4,
        )
        repo.upsert_entity_alias(
            ip2.entity_id, dataset, alias_type="ip", alias_value="10.0.0.9",
            scope="host-b", observed_at=frame1.timestamp, confidence=0.4,
        )
        assert repo.get_entity(ip1.entity_id)["entity_id"] != repo.get_entity(ip2.entity_id)["entity_id"]
        assert len(repo.find_entities_by_alias(dataset, "ip", "10.0.0.9")) == 2
        assert [row["entity_id"] for row in repo.find_entities_by_alias(dataset, "ip", "10.0.0.9", scope="host-a")] == [ip1.entity_id]

        with pytest.raises(Exception):
            repo.link_event_entity(event1, f"missing-{suffix}", "actor", 0.5)

        rollback_event = f"rollback-{suffix}"
        with pytest.raises(RuntimeError):
            with repo.transaction() as db:
                db.execute(
                    """
                    INSERT INTO events(
                        event_id,dataset_id,timestamp,record_kind,relation_type,action_family,action_leaf,outcome,
                        roles,key_attributes,entity_mentions,semantic_confidence,unknown_score,source_record_ref,
                        semantic_version,attributes,fact_hash
                    ) VALUES(%s,%s,now(),'test','test','test','test','unknown','{}'::jsonb,'{}'::jsonb,'[]'::jsonb,0,1,'','test','{}'::jsonb,%s)
                    """,
                    (rollback_event, dataset, "f" * 64),
                )
                raise RuntimeError("force rollback")
        assert repo.get_event(rollback_event) is None

        micro1 = f"micro-{suffix}-1"
        micro2 = f"micro-{suffix}-2"
        repo.put_context_window(
            micro1, dataset, window_kind="micro",
            start_time="2026-08-08T11:50:00+00:00", end_time="2026-08-08T11:55:00+00:00",
            anchor_event_id=event2, stride_seconds=150, window_index=0, config_hash="cfg",
        )
        repo.put_context_window(
            micro2, dataset, window_kind="micro",
            start_time="2026-08-08T11:52:30+00:00", end_time="2026-08-08T11:57:30+00:00",
            anchor_event_id=event2, stride_seconds=150, window_index=1, config_hash="cfg",
        )
        repo.link_window_event(micro1, event1, 0)
        repo.link_window_event(micro2, event1, 0)
        assert repo.get_window_events(micro1)[0]["event_id"] == event1
        assert repo.get_window_events(micro2)[0]["event_id"] == event1
        repo.put_window_detection_result(
            micro1, model_version="integration-test-v1", producer_run_id=None,
            raw_score=0.7, calibrated_score=0.72, alert_level="medium",
        )
        repo.put_window_detection_result(
            micro2, model_version="integration-test-v1", producer_run_id=None,
            raw_score=0.8, calibrated_score=0.81, alert_level="high",
        )
        repo.put_window_link(
            micro1, micro2, link_type="m5_long_horizon", score=0.9, delta_seconds=150,
            anchor_strength="strong", anchors=(entity_id,),
        )

        frozen = FrozenFeatureRecord(
            event2,
            dataset,
            frame2.timestamp,
            raw_event_score=1.2,
            micro_window_score=0.71,
            macro_window_score=0.83,
            long_horizon_score=0.64,
        )
        repo.put_detection_result(
            frozen,
            model_version="integration-test-v1",
            checkpoint_hash="abc123",
            final_score=0.88,
            alert_level="high",
        )
        assert repo.get_detection_results(event2)[0]["final_score"] == pytest.approx(0.88)

        repo.put_attack_chain(
            chain_id,
            dataset,
            start_time=frame1.timestamp,
            end_time=frame2.timestamp,
            risk_score=0.88,
            status="candidate",
            model_version="integration-test-v1",
        )
        repo.link_attack_chain_window(chain_id, micro1, 0, evidence_score=0.72, relation_reason="m5_window_link")
        repo.link_attack_chain_window(chain_id, micro2, 1, evidence_score=0.81, relation_reason="m5_window_link")
        repo.link_attack_chain_event(chain_id, event1, 0, relation_reason="shared_host")
        repo.link_attack_chain_event(chain_id, event2, 1, evidence_score=0.88, relation_reason="shared_host")
        assert [row["window_id"] for row in repo.get_attack_chain_windows(chain_id)] == [micro1, micro2]
        assert [row["event_id"] for row in repo.get_attack_chain_events(chain_id)] == [event1, event2]


def test_postgres_business_table_rejects_label_payload_before_sql():
    with pytest.raises(RepositoryError):
        from src.storage.repository import assert_no_forbidden_business_keys
        assert_no_forbidden_business_keys({"ground_truth": 1})
