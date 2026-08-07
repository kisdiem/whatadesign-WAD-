from __future__ import annotations

"""Transactional provenance index for V3 stage outputs.

Large raw logs and embedding batches stay immutable in artifact files; this
SQLite database stores their identity, lineage, hashes, and queryable feature
records. It intentionally has no API for target labels.
"""

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from src.common.schema import EventFrame, FrozenFeatureRecord, GraphRecord


class FeatureRepository:
    SCHEMA_VERSION = "v3-feature-repository-1"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.connection
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def _migrate(self) -> None:
        with self.transaction() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, stage TEXT NOT NULL, mode TEXT NOT NULL,
                config_hash TEXT NOT NULL, started_at TEXT NOT NULL, status TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(run_id), stage TEXT NOT NULL,
                uri TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER, schema_version TEXT NOT NULL,
                metadata_json TEXT NOT NULL, UNIQUE(uri, sha256)
            );
            CREATE TABLE IF NOT EXISTS stage_records (
                stage TEXT NOT NULL, record_id TEXT NOT NULL, dataset_id TEXT NOT NULL,
                timestamp TEXT, artifact_id TEXT REFERENCES artifacts(artifact_id),
                payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
                PRIMARY KEY(stage, record_id)
            );
            CREATE TABLE IF NOT EXISTS lineage (
                output_stage TEXT NOT NULL, output_record_id TEXT NOT NULL,
                input_stage TEXT NOT NULL, input_record_id TEXT NOT NULL,
                relation TEXT NOT NULL, PRIMARY KEY(output_stage, output_record_id, input_stage, input_record_id, relation)
            );
            CREATE TABLE IF NOT EXISTS operation_log (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_utc TEXT NOT NULL,
                operation TEXT NOT NULL, status TEXT NOT NULL, run_id TEXT, details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS stage_records_dataset_time ON stage_records(stage, dataset_id, timestamp);
            CREATE INDEX IF NOT EXISTS lineage_input ON lineage(input_stage, input_record_id);
            """)

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _hash(payload: str) -> str:
        return hashlib.sha256(payload.encode()).hexdigest()

    def log(self, operation: str, status: str, *, run_id: str | None = None, **details: Any) -> None:
        with self.transaction() as db:
            db.execute("INSERT INTO operation_log(timestamp_utc,operation,status,run_id,details_json) VALUES(?,?,?,?,?)",
                       (datetime.now(timezone.utc).isoformat(), operation, status, run_id, self._json(details)))

    def register_run(self, run_id: str, stage: str, mode: str, config_hash: str, **metadata: Any) -> None:
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?)", (run_id, stage, mode, config_hash,
                       datetime.now(timezone.utc).isoformat(), "RUNNING", self._json(metadata)))
        self.log("register_run", "OK", run_id=run_id, stage=stage, mode=mode)

    def register_artifact(self, uri: str, sha256: str, *, stage: str, schema_version: str,
                          run_id: str | None = None, bytes: int | None = None, **metadata: Any) -> str:
        artifact_id = hashlib.sha256(f"{uri}|{sha256}".encode()).hexdigest()
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO artifacts VALUES(?,?,?,?,?,?,?,?)", (artifact_id, run_id, stage, uri, sha256, bytes, schema_version, self._json(metadata)))
        self.log("register_artifact", "OK", run_id=run_id, artifact_id=artifact_id, stage=stage)
        return artifact_id

    def put_record(self, stage: str, record_id: str, dataset_id: str, timestamp: str | None, payload: dict[str, Any], *, artifact_id: str | None = None) -> None:
        encoded = self._json(payload)
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO stage_records VALUES(?,?,?,?,?,?,?)", (stage, record_id, dataset_id, timestamp, artifact_id, encoded, self._hash(encoded)))

    def put_eventframe(self, frame: EventFrame, *, artifact_id: str | None = None) -> None:
        self.put_record("m1_eventframe", frame.record_id, frame.dataset_id, frame.timestamp, frame.to_dict(), artifact_id=artifact_id)

    def put_graph(self, graph: GraphRecord, *, artifact_id: str | None = None) -> None:
        self.put_record("m3_graph", graph.graph_id, graph.dataset_id, graph.window_end, graph.to_dict(), artifact_id=artifact_id)

    def put_frozen_feature(self, record: FrozenFeatureRecord, *, artifact_id: str | None = None) -> None:
        self.put_record("m6_frozen_feature", record.record_id, record.dataset_id, record.timestamp, record.to_dict(), artifact_id=artifact_id)

    def link(self, output_stage: str, output_record_id: str, input_stage: str, input_record_id: str, relation: str = "derived_from") -> None:
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO lineage VALUES(?,?,?,?,?)", (output_stage, output_record_id, input_stage, input_record_id, relation))

    def records(self, stage: str, dataset_id: str, start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
        query, values = "SELECT payload_json FROM stage_records WHERE stage=? AND dataset_id=?", [stage, dataset_id]
        if start: query += " AND timestamp>=?"; values.append(start)
        if end: query += " AND timestamp<?"; values.append(end)
        return [json.loads(row["payload_json"]) for row in self.connection.execute(query + " ORDER BY timestamp,record_id", values)]
