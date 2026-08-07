from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from typing import Any, Iterable, Iterator

from src.common.schema import EntityRecord, EventFrame, FrozenFeatureRecord
from src.storage.connection import connect_postgres, jsonb
from src.storage.migrations import apply_migrations


FORBIDDEN_BUSINESS_KEYS = {
    "target_label", "attack_label", "anomaly_label", "ground_truth",
    "is_attack", "malicious", "split", "ait_label",
}


class RepositoryError(RuntimeError):
    pass


def stable_id(*parts: Any) -> str:
    payload = "|".join(
        json.dumps(part, sort_keys=True, ensure_ascii=True, default=str, separators=(",", ":"))
        for part in parts
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def assert_no_forbidden_business_keys(value: Any, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).strip().lower() in FORBIDDEN_BUSINESS_KEYS:
                raise RepositoryError(f"forbidden label/split key in business data: {path}.{key}")
            assert_no_forbidden_business_keys(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, child in enumerate(value):
            assert_no_forbidden_business_keys(child, f"{path}[{i}]")


class SecurityRepository:
    """PostgreSQL system-of-record for V3 facts, detections and attack chains."""

    def __init__(self, database_url: str | None = None, *, auto_migrate: bool = False) -> None:
        self.connection = connect_postgres(database_url)
        if auto_migrate:
            apply_migrations(self.connection)

    def __enter__(self) -> "SecurityRepository":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        try:
            with self.connection.transaction():
                yield self.connection
        except BaseException:
            self.connection.rollback()
            raise

    def _fetchone(self, query: str, values: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self.connection.cursor() as cur:
            cur.execute(query, values)
            row = cur.fetchone()
            return dict(row) if row else None

    def _fetchall(self, query: str, values: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connection.cursor() as cur:
            cur.execute(query, values)
            return [dict(row) for row in cur.fetchall()]

    def register_run(self, run_id: str, stage: str, mode: str, config_hash: str,
                     *, status: str = "RUNNING", metadata: dict[str, Any] | None = None) -> None:
        assert_no_forbidden_business_keys(metadata or {})
        with self.transaction() as db:
            db.execute(
                """INSERT INTO pipeline_runs(run_id,stage,mode,config_hash,status,metadata)
                   VALUES(%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(run_id) DO UPDATE SET
                   stage=EXCLUDED.stage, mode=EXCLUDED.mode, config_hash=EXCLUDED.config_hash,
                   status=EXCLUDED.status, metadata=pipeline_runs.metadata || EXCLUDED.metadata""",
                (run_id, stage, mode, config_hash, status, jsonb(metadata or {})),
            )

    def finish_run(self, run_id: str, status: str, metadata: dict[str, Any] | None = None) -> None:
        with self.transaction() as db:
            db.execute(
                "UPDATE pipeline_runs SET status=%s,finished_at=now(),metadata=metadata||%s WHERE run_id=%s",
                (status, jsonb(metadata or {}), run_id),
            )

    def register_artifact(self, uri: str, sha256: str, *, stage: str, schema_version: str,
                          run_id: str | None = None, bytes: int | None = None,
                          metadata: dict[str, Any] | None = None) -> str:
        artifact_id = stable_id(uri, sha256)
        with self.transaction() as db:
            db.execute(
                """INSERT INTO artifacts(artifact_id,run_id,stage,uri,sha256,bytes,schema_version,metadata)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(artifact_id) DO UPDATE SET
                   run_id=COALESCE(EXCLUDED.run_id,artifacts.run_id), stage=EXCLUDED.stage,
                   bytes=COALESCE(EXCLUDED.bytes,artifacts.bytes),
                   schema_version=EXCLUDED.schema_version,
                   metadata=artifacts.metadata || EXCLUDED.metadata""",
                (artifact_id, run_id, stage, uri, sha256, bytes, schema_version, jsonb(metadata or {})),
            )
        return artifact_id

    def link_lineage(self, output_kind: str, output_id: str, input_kind: str, input_id: str,
                     relation: str = "derived_from") -> None:
        with self.transaction() as db:
            db.execute(
                """INSERT INTO lineage(output_kind,output_id,input_kind,input_id,relation)
                   VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (output_kind, output_id, input_kind, input_id, relation),
            )

    def log_operation(self, operation: str, status: str, *, run_id: str | None = None,
                      details: dict[str, Any] | None = None) -> None:
        with self.transaction() as db:
            db.execute(
                "INSERT INTO operation_logs(operation,status,run_id,details) VALUES(%s,%s,%s,%s)",
                (operation, status, run_id, jsonb(details or {})),
            )

    def put_event(self, frame: EventFrame) -> None:
        payload = {
            "dataset_id": frame.dataset_id, "timestamp": frame.timestamp,
            "record_kind": frame.record_kind, "relation_type": frame.relation_type,
            "action_family": frame.action_family, "action_leaf": frame.action_leaf,
            "outcome": frame.outcome, "roles": frame.roles,
            "key_attributes": frame.key_attributes, "entity_mentions": frame.entity_mentions,
            "semantic_confidence": frame.semantic_confidence, "unknown_score": frame.unknown_score,
            "source_record_ref": frame.source_record_ref, "semantic_version": frame.semantic_version,
            "attributes": frame.attributes,
        }
        assert_no_forbidden_business_keys(payload)
        fact_hash = stable_id(payload)
        with self.transaction() as db:
            cur = db.execute(
                """INSERT INTO events(event_id,dataset_id,timestamp,record_kind,relation_type,
                   action_family,action_leaf,outcome,roles,key_attributes,entity_mentions,
                   semantic_confidence,unknown_score,source_record_ref,semantic_version,attributes,fact_hash)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(event_id) DO NOTHING""",
                (frame.record_id, frame.dataset_id, frame.timestamp, frame.record_kind,
                 frame.relation_type, frame.action_family, frame.action_leaf, frame.outcome,
                 jsonb(frame.roles), jsonb(frame.key_attributes), jsonb(frame.entity_mentions),
                 frame.semantic_confidence, frame.unknown_score, frame.source_record_ref,
                 frame.semantic_version, jsonb(frame.attributes), fact_hash),
            )
            if cur.rowcount == 0:
                row = db.execute("SELECT fact_hash FROM events WHERE event_id=%s", (frame.record_id,)).fetchone()
                if row is None or str(row["fact_hash"]) != fact_hash:
                    raise RepositoryError(f"immutable event conflict for event_id={frame.record_id}")

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM events WHERE event_id=%s", (event_id,))

    def get_event_context(self, event_id: str, minutes: int = 30) -> list[dict[str, Any]]:
        if minutes <= 0:
            raise ValueError("minutes must be positive")
        return self._fetchall(
            """SELECT h.* FROM events c JOIN events h ON h.dataset_id=c.dataset_id
               WHERE c.event_id=%s AND c.timestamp IS NOT NULL
               AND h.timestamp>=c.timestamp-(%s * interval '1 minute')
               AND h.timestamp<c.timestamp ORDER BY h.timestamp,h.event_id""",
            (event_id, minutes),
        )

    def upsert_entity(self, record: EntityRecord, *, observed_at: str | None = None,
                      current_status: str = "observed",
                      attributes: dict[str, Any] | None = None) -> None:
        assert_no_forbidden_business_keys(attributes or {})
        first = record.first_seen or observed_at
        last = record.last_seen or observed_at
        with self.transaction() as db:
            db.execute(
                """INSERT INTO entities(entity_id,dataset_id,entity_type,canonical_value,instance_key,
                   host_scope,parent_entity_id,first_seen,last_seen,current_status,confidence,
                   resolution_method,attributes)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(entity_id) DO UPDATE SET
                   first_seen=CASE WHEN entities.first_seen IS NULL THEN EXCLUDED.first_seen
                     WHEN EXCLUDED.first_seen IS NULL THEN entities.first_seen
                     ELSE LEAST(entities.first_seen,EXCLUDED.first_seen) END,
                   last_seen=CASE WHEN entities.last_seen IS NULL THEN EXCLUDED.last_seen
                     WHEN EXCLUDED.last_seen IS NULL THEN entities.last_seen
                     ELSE GREATEST(entities.last_seen,EXCLUDED.last_seen) END,
                   current_status=EXCLUDED.current_status,
                   confidence=GREATEST(entities.confidence,EXCLUDED.confidence),
                   resolution_method=EXCLUDED.resolution_method,
                   attributes=entities.attributes||EXCLUDED.attributes, updated_at=now()""",
                (record.entity_id, record.dataset_id, record.entity_type, record.canonical_value,
                 record.instance_key, record.host_scope, record.parent_entity_id, first, last,
                 current_status, record.confidence, record.resolution_method, jsonb(attributes or {})),
            )

    def upsert_entity_alias(self, entity_id: str, dataset_id: str, *, alias_type: str,
                            alias_value: str, scope: str = "", observed_at: str | None = None,
                            confidence: float = 0.0, source_record_ref: str = "") -> str:
        alias_id = stable_id(entity_id, alias_type, alias_value, scope)
        with self.transaction() as db:
            db.execute(
                """INSERT INTO entity_aliases(alias_id,entity_id,dataset_id,alias_type,alias_value,
                   scope,first_seen,last_seen,confidence,source_record_ref)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(entity_id,alias_type,alias_value,scope) DO UPDATE SET
                   first_seen=CASE WHEN entity_aliases.first_seen IS NULL THEN EXCLUDED.first_seen
                     WHEN EXCLUDED.first_seen IS NULL THEN entity_aliases.first_seen
                     ELSE LEAST(entity_aliases.first_seen,EXCLUDED.first_seen) END,
                   last_seen=CASE WHEN entity_aliases.last_seen IS NULL THEN EXCLUDED.last_seen
                     WHEN EXCLUDED.last_seen IS NULL THEN entity_aliases.last_seen
                     ELSE GREATEST(entity_aliases.last_seen,EXCLUDED.last_seen) END,
                   confidence=GREATEST(entity_aliases.confidence,EXCLUDED.confidence),
                   source_record_ref=COALESCE(NULLIF(EXCLUDED.source_record_ref,''),entity_aliases.source_record_ref),
                   updated_at=now()""",
                (alias_id, entity_id, dataset_id, alias_type, alias_value, scope,
                 observed_at, observed_at, confidence, source_record_ref),
            )
        return alias_id

    def append_entity_observation(self, entity_id: str, *, event_id: str | None,
                                  timestamp: str | None, attribute_name: str,
                                  observed_value: Any, confidence: float = 0.0,
                                  source_record_ref: str = "") -> str:
        assert_no_forbidden_business_keys(observed_value)
        observation_id = stable_id(entity_id, event_id, timestamp, attribute_name, observed_value)
        with self.transaction() as db:
            db.execute(
                """INSERT INTO entity_observations(observation_id,entity_id,event_id,timestamp,
                   attribute_name,observed_value,confidence,source_record_ref)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(observation_id) DO NOTHING""",
                (observation_id, entity_id, event_id, timestamp, attribute_name,
                 jsonb(observed_value), confidence, source_record_ref),
            )
        return observation_id

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM entities WHERE entity_id=%s", (entity_id,))

    def get_entity_history(self, entity_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM entity_observations WHERE entity_id=%s ORDER BY timestamp,created_at,observation_id",
            (entity_id,),
        )

    def find_entities_by_alias(self, dataset_id: str, alias_type: str, alias_value: str,
                               *, scope: str | None = None) -> list[dict[str, Any]]:
        query = """SELECT e.*,a.alias_type,a.alias_value,a.scope,a.first_seen AS alias_first_seen,
                   a.last_seen AS alias_last_seen FROM entity_aliases a
                   JOIN entities e ON e.entity_id=a.entity_id
                   WHERE a.dataset_id=%s AND a.alias_type=%s AND a.alias_value=%s"""
        values: list[Any] = [dataset_id, alias_type, alias_value]
        if scope is not None:
            query += " AND a.scope=%s"
            values.append(scope)
        return self._fetchall(query + " ORDER BY e.entity_id", tuple(values))

    def link_event_entity(self, event_id: str, entity_id: str, role: str, confidence: float = 0.0) -> None:
        with self.transaction() as db:
            db.execute(
                """INSERT INTO event_entities(event_id,entity_id,role,confidence)
                   VALUES(%s,%s,%s,%s)
                   ON CONFLICT(event_id,entity_id,role) DO UPDATE SET
                   confidence=GREATEST(event_entities.confidence,EXCLUDED.confidence)""",
                (event_id, entity_id, role, confidence),
            )

    def put_event_relation(self, source_event_id: str, target_event_id: str, relation_type: str,
                           *, confidence: float = 0.0, time_delta_seconds: float | None = None,
                           graph_id: str | None = None, evidence: dict[str, Any] | None = None) -> None:
        assert_no_forbidden_business_keys(evidence or {})
        with self.transaction() as db:
            db.execute(
                """INSERT INTO event_relations(source_event_id,target_event_id,relation_type,
                   confidence,time_delta_seconds,graph_id,evidence)
                   VALUES(%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(source_event_id,target_event_id,relation_type) DO UPDATE SET
                   confidence=GREATEST(event_relations.confidence,EXCLUDED.confidence),
                   time_delta_seconds=EXCLUDED.time_delta_seconds,
                   graph_id=COALESCE(EXCLUDED.graph_id,event_relations.graph_id),
                   evidence=event_relations.evidence||EXCLUDED.evidence""",
                (source_event_id, target_event_id, relation_type, confidence,
                 time_delta_seconds, graph_id, jsonb(evidence or {})),
            )

    def put_context_window(self, window_id: str, dataset_id: str, *, window_kind: str,
                           start_time: str, end_time: str, anchor_event_id: str | None = None,
                           stride_seconds: int | None = None, window_index: int | None = None,
                           config_hash: str = "", attributes: dict[str, Any] | None = None) -> None:
        assert_no_forbidden_business_keys(attributes or {})
        window_hash = stable_id(dataset_id, anchor_event_id, window_kind, start_time, end_time,
                                stride_seconds, window_index, config_hash, attributes or {})
        with self.transaction() as db:
            db.execute(
                """INSERT INTO context_windows(window_id,dataset_id,anchor_event_id,window_kind,
                   start_time,end_time,stride_seconds,window_index,config_hash,attributes,window_hash)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(window_id) DO NOTHING""",
                (window_id, dataset_id, anchor_event_id, window_kind, start_time, end_time,
                 stride_seconds, window_index, config_hash, jsonb(attributes or {}), window_hash),
            )

    def link_window_event(self, window_id: str, event_id: str, position: int) -> None:
        with self.transaction() as db:
            db.execute(
                """INSERT INTO window_events(window_id,event_id,position) VALUES(%s,%s,%s)
                   ON CONFLICT(window_id,event_id) DO UPDATE SET position=EXCLUDED.position""",
                (window_id, event_id, position),
            )

    def get_window_events(self, window_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            """SELECT we.position,e.* FROM window_events we
               JOIN events e ON e.event_id=we.event_id
               WHERE we.window_id=%s ORDER BY we.position,e.event_id""",
            (window_id,),
        )

    def put_window_detection_result(self, window_id: str, *, model_version: str,
                                    checkpoint_hash: str = "", producer_run_id: str | None = None,
                                    raw_score: float | None = None,
                                    calibrated_score: float | None = None,
                                    alert_level: str = "unscored",
                                    score_metadata: dict[str, Any] | None = None) -> str:
        assert_no_forbidden_business_keys(score_metadata or {})
        result_id = stable_id(window_id, model_version, checkpoint_hash)
        with self.transaction() as db:
            db.execute(
                """INSERT INTO window_detection_results(window_detection_id,window_id,model_version,
                   checkpoint_hash,producer_run_id,raw_score,calibrated_score,alert_level,score_metadata)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(window_id,model_version,checkpoint_hash) DO UPDATE SET
                   producer_run_id=COALESCE(EXCLUDED.producer_run_id,window_detection_results.producer_run_id),
                   raw_score=EXCLUDED.raw_score, calibrated_score=EXCLUDED.calibrated_score,
                   alert_level=EXCLUDED.alert_level,
                   score_metadata=window_detection_results.score_metadata||EXCLUDED.score_metadata,
                   created_at=now()""",
                (result_id, window_id, model_version, checkpoint_hash, producer_run_id,
                 raw_score, calibrated_score, alert_level, jsonb(score_metadata or {})),
            )
        return result_id

    def put_window_link(self, source_window_id: str, target_window_id: str, *,
                        link_type: str = "long_horizon", score: float | None = None,
                        delta_seconds: float | None = None, anchor_strength: str = "",
                        anchors: Iterable[str] = (), evidence: dict[str, Any] | None = None,
                        producer_run_id: str | None = None) -> None:
        assert_no_forbidden_business_keys(evidence or {})
        with self.transaction() as db:
            db.execute(
                """INSERT INTO window_links(source_window_id,target_window_id,link_type,score,
                   delta_seconds,anchor_strength,anchors,evidence,producer_run_id)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(source_window_id,target_window_id,link_type) DO UPDATE SET
                   score=EXCLUDED.score,delta_seconds=EXCLUDED.delta_seconds,
                   anchor_strength=EXCLUDED.anchor_strength,anchors=EXCLUDED.anchors,
                   evidence=window_links.evidence||EXCLUDED.evidence,
                   producer_run_id=COALESCE(EXCLUDED.producer_run_id,window_links.producer_run_id)""",
                (source_window_id, target_window_id, link_type, score, delta_seconds,
                 anchor_strength, jsonb(list(anchors)), jsonb(evidence or {}), producer_run_id),
            )

    def put_detection_result(self, record: FrozenFeatureRecord, *, model_version: str,
                             checkpoint_hash: str = "", producer_run_id: str | None = None,
                             event_score: float | None = None, final_score: float | None = None,
                             alert_level: str = "unscored",
                             score_metadata: dict[str, Any] | None = None) -> str:
        metadata = {
            "slot_nll": record.slot_nll, "graph_score": record.graph_score,
            "legacy_micro_window_score": record.micro_window_score,
            "legacy_macro_window_score": record.macro_window_score,
            "legacy_long_horizon_score": record.long_horizon_score,
            **(score_metadata or {}),
        }
        assert_no_forbidden_business_keys(metadata)
        detection_id = stable_id(record.record_id, model_version, checkpoint_hash)
        with self.transaction() as db:
            db.execute(
                """INSERT INTO detection_results(detection_id,event_id,model_version,checkpoint_hash,
                   producer_run_id,event_score,final_score,alert_level,score_metadata)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(event_id,model_version,checkpoint_hash) DO UPDATE SET
                   producer_run_id=COALESCE(EXCLUDED.producer_run_id,detection_results.producer_run_id),
                   event_score=EXCLUDED.event_score,final_score=COALESCE(EXCLUDED.final_score,detection_results.final_score),
                   alert_level=EXCLUDED.alert_level,
                   score_metadata=detection_results.score_metadata||EXCLUDED.score_metadata,
                   created_at=now()""",
                (detection_id, record.record_id, model_version, checkpoint_hash, producer_run_id,
                 record.raw_event_score if event_score is None else event_score,
                 final_score, alert_level, jsonb(metadata)),
            )
        return detection_id

    def get_detection_results(self, event_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM detection_results WHERE event_id=%s ORDER BY created_at DESC,detection_id",
            (event_id,),
        )

    def put_attack_chain(self, chain_id: str, dataset_id: str, *, start_time: str | None,
                         end_time: str | None, risk_score: float | None, status: str,
                         model_version: str, checkpoint_hash: str = "",
                         producer_run_id: str | None = None,
                         summary: dict[str, Any] | None = None) -> None:
        assert_no_forbidden_business_keys(summary or {})
        with self.transaction() as db:
            db.execute(
                """INSERT INTO attack_chains(chain_id,dataset_id,start_time,end_time,risk_score,status,
                   model_version,checkpoint_hash,producer_run_id,summary)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(chain_id) DO UPDATE SET start_time=EXCLUDED.start_time,
                   end_time=EXCLUDED.end_time,risk_score=EXCLUDED.risk_score,status=EXCLUDED.status,
                   model_version=EXCLUDED.model_version,checkpoint_hash=EXCLUDED.checkpoint_hash,
                   producer_run_id=COALESCE(EXCLUDED.producer_run_id,attack_chains.producer_run_id),
                   summary=attack_chains.summary||EXCLUDED.summary,updated_at=now()""",
                (chain_id, dataset_id, start_time, end_time, risk_score, status, model_version,
                 checkpoint_hash, producer_run_id, jsonb(summary or {})),
            )

    def link_attack_chain_window(self, chain_id: str, window_id: str, sequence_no: int, *,
                                 evidence_score: float | None = None,
                                 relation_reason: str = "",
                                 evidence: dict[str, Any] | None = None) -> None:
        assert_no_forbidden_business_keys(evidence or {})
        with self.transaction() as db:
            db.execute(
                """INSERT INTO attack_chain_windows(chain_id,window_id,sequence_no,evidence_score,
                   relation_reason,evidence) VALUES(%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(chain_id,window_id) DO UPDATE SET sequence_no=EXCLUDED.sequence_no,
                   evidence_score=EXCLUDED.evidence_score,relation_reason=EXCLUDED.relation_reason,
                   evidence=attack_chain_windows.evidence||EXCLUDED.evidence""",
                (chain_id, window_id, sequence_no, evidence_score, relation_reason, jsonb(evidence or {})),
            )

    def link_attack_chain_event(self, chain_id: str, event_id: str, sequence_no: int, *,
                                evidence_score: float | None = None,
                                relation_reason: str = "",
                                evidence: dict[str, Any] | None = None) -> None:
        assert_no_forbidden_business_keys(evidence or {})
        with self.transaction() as db:
            db.execute(
                """INSERT INTO attack_chain_events(chain_id,event_id,sequence_no,evidence_score,
                   relation_reason,evidence) VALUES(%s,%s,%s,%s,%s,%s)
                   ON CONFLICT(chain_id,event_id) DO UPDATE SET sequence_no=EXCLUDED.sequence_no,
                   evidence_score=EXCLUDED.evidence_score,relation_reason=EXCLUDED.relation_reason,
                   evidence=attack_chain_events.evidence||EXCLUDED.evidence""",
                (chain_id, event_id, sequence_no, evidence_score, relation_reason, jsonb(evidence or {})),
            )

    def get_attack_chain(self, chain_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM attack_chains WHERE chain_id=%s", (chain_id,))

    def get_attack_chain_windows(self, chain_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            """SELECT m.sequence_no,m.evidence_score,m.relation_reason,m.evidence,cw.*
               FROM attack_chain_windows m JOIN context_windows cw ON cw.window_id=m.window_id
               WHERE m.chain_id=%s ORDER BY m.sequence_no,cw.start_time,cw.window_id""",
            (chain_id,),
        )

    def get_attack_chain_events(self, chain_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            """SELECT m.sequence_no,m.evidence_score,m.relation_reason,m.evidence,e.*
               FROM attack_chain_events m JOIN events e ON e.event_id=m.event_id
               WHERE m.chain_id=%s ORDER BY m.sequence_no,e.timestamp,e.event_id""",
            (chain_id,),
        )

    def persist_m2_resolution(self, frame: EventFrame, entities: Iterable[EntityRecord],
                              links: Iterable[Any]) -> None:
        self.put_event(frame)
        entity_rows = list(entities)
        by_id = {row.entity_id: row for row in entity_rows}
        for record in entity_rows:
            self.upsert_entity(record, observed_at=frame.timestamp)
            self.upsert_entity_alias(
                record.entity_id, record.dataset_id, alias_type=record.entity_type,
                alias_value=record.raw_value, scope=record.host_scope,
                observed_at=frame.timestamp, confidence=record.confidence,
                source_record_ref=frame.source_record_ref,
            )
        for link in links:
            record = by_id.get(link.entity_id)
            if record is not None:
                self.append_entity_observation(
                    record.entity_id, event_id=frame.record_id, timestamp=frame.timestamp,
                    attribute_name="identity",
                    observed_value={
                        "raw_value": record.raw_value,
                        "canonical_value": record.canonical_value,
                        "entity_type": record.entity_type,
                        "host_scope": record.host_scope,
                        "instance_key": record.instance_key,
                    },
                    confidence=float(link.confidence),
                    source_record_ref=frame.source_record_ref,
                )
            self.link_event_entity(frame.record_id, link.entity_id, str(link.role), float(link.confidence))
