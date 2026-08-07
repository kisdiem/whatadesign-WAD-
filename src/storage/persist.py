from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from src.common.schema import EntityRecord, EventFrame, FrozenFeatureRecord
from src.storage.repository import SecurityRepository, stable_id


BUSINESS_ARTIFACTS = {
    "raw_records.jsonl": "ingest",
    "syntax_parses.jsonl": "m0",
    "event_frames.jsonl": "m1",
    "entities.jsonl": "m2",
    "event_entity_links.jsonl": "m2",
    "graphs.jsonl": "m3",
    "causal_batches.jsonl": "m3",
    "m4_outputs.jsonl": "m4",
    "micro_windows.jsonl": "m5",
    "macro_windows.jsonl": "m5",
    "window_links.jsonl": "m5",
    "attack_queues.jsonl": "m5",
    "frozen_features.jsonl": "m6",
    "run_manifest.json": "run",
}

NEVER_INGEST_BUSINESS = {"labels.jsonl", "splits.json"}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checkpoint_hash(record: FrozenFeatureRecord) -> str:
    if not record.producer_checkpoint_hashes:
        return ""
    return stable_id(record.producer_checkpoint_hashes)


def _event_sort_key(frame: EventFrame) -> tuple[str, str]:
    return (frame.timestamp or "", frame.record_id)


def persist_work_dir(
    work_dir: str | Path,
    database_url: str | None = None,
    *,
    auto_migrate: bool = True,
) -> dict[str, Any]:
    work = Path(work_dir)
    if not work.is_dir():
        raise FileNotFoundError(work)
    manifest_path = work / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    config_hash = str(manifest.get("config_hash", "unknown"))
    run_id = str(manifest.get("run_id") or stable_id("source-work-dir", str(work.resolve()), config_hash)[:32])

    counts = {
        "events": 0,
        "entities": 0,
        "entity_aliases": 0,
        "entity_observations": 0,
        "event_entity_links": 0,
        "event_relations": 0,
        "detections": 0,
        "context_windows": 0,
        "window_event_links": 0,
        "window_detections": 0,
        "window_links": 0,
        "attack_chains": 0,
        "attack_chain_windows": 0,
        "attack_chain_events": 0,
        "artifacts": 0,
    }

    with SecurityRepository(database_url, auto_migrate=auto_migrate) as repo:
        repo.register_run(
            run_id,
            "storage_import",
            str(manifest.get("mode", "source")),
            config_hash,
            metadata={
                "work_dir": str(work.resolve()),
                "source_pipeline_status": manifest.get("status"),
                "ait_accessed": bool(manifest.get("ait_accessed", False)),
            },
        )

        artifact_ids: dict[str, str] = {}
        for filename, stage in BUSINESS_ARTIFACTS.items():
            path = work / filename
            if not path.is_file():
                continue
            artifact_ids[filename] = repo.register_artifact(
                str(path),
                sha256_file(path),
                stage=stage,
                schema_version="v3-file-artifact-1",
                run_id=run_id,
                bytes=path.stat().st_size,
                metadata={"filename": filename},
            )
            counts["artifacts"] += 1

        frames = [EventFrame.from_dict(row) for row in read_jsonl(work / "event_frames.jsonl")]
        frame_by_id = {frame.record_id: frame for frame in frames}
        for frame in frames:
            repo.put_event(frame)
            if "event_frames.jsonl" in artifact_ids:
                repo.link_lineage("event", frame.record_id, "artifact", artifact_ids["event_frames.jsonl"], "materialized_from")
            counts["events"] += 1

        entity_rows = [EntityRecord.from_dict(row) for row in read_jsonl(work / "entities.jsonl")]
        link_rows = read_jsonl(work / "event_entity_links.jsonl")

        if len(entity_rows) == len(link_rows):
            pairs: Iterable[tuple[EntityRecord, dict[str, Any]]] = zip(entity_rows, link_rows)
        else:
            by_entity = {row.entity_id: row for row in entity_rows}
            pairs = (
                (by_entity[str(link["entity_id"])], link)
                for link in link_rows
                if str(link.get("entity_id", "")) in by_entity
            )

        observed_entity_ids: set[str] = set()
        for entity, link in pairs:
            event_id = str(link["event_id"])
            frame = frame_by_id.get(event_id)
            observed_at = frame.timestamp if frame else None
            source_ref = frame.source_record_ref if frame else ""
            confidence = float(link.get("confidence", entity.confidence))
            repo.upsert_entity(entity, observed_at=observed_at)
            alias_id = repo.upsert_entity_alias(
                entity.entity_id,
                entity.dataset_id,
                alias_type=entity.entity_type,
                alias_value=entity.raw_value,
                scope=entity.host_scope,
                observed_at=observed_at,
                confidence=confidence,
                source_record_ref=source_ref,
            )
            if "entities.jsonl" in artifact_ids:
                repo.link_lineage("entity_alias", alias_id, "artifact", artifact_ids["entities.jsonl"], "materialized_from")
            observed_entity_ids.add(entity.entity_id)
            counts["entities"] += 1
            counts["entity_aliases"] += 1
            observation_id = repo.append_entity_observation(
                entity.entity_id,
                event_id=event_id if frame else None,
                timestamp=observed_at,
                attribute_name="identity",
                observed_value={
                    "raw_value": entity.raw_value,
                    "canonical_value": entity.canonical_value,
                    "entity_type": entity.entity_type,
                    "host_scope": entity.host_scope,
                    "instance_key": entity.instance_key,
                },
                confidence=confidence,
                source_record_ref=source_ref,
            )
            if "entities.jsonl" in artifact_ids:
                repo.link_lineage("entity_observation", observation_id, "artifact", artifact_ids["entities.jsonl"], "materialized_from")
            counts["entity_observations"] += 1
            if frame:
                repo.link_event_entity(event_id, entity.entity_id, str(link.get("role", "unknown")), confidence)
                counts["event_entity_links"] += 1

        for entity in entity_rows:
            if entity.entity_id not in observed_entity_ids:
                repo.upsert_entity(entity)
                counts["entities"] += 1

        repo.log_operation(
            "persist_m3_relations",
            "SKIPPED_NO_EVENT_EVENT_EDGES",
            run_id=run_id,
            details={"event_relations_written": 0},
        )

        micro_windows = {str(row["window_id"]): row for row in read_jsonl(work / "micro_windows.jsonl")}
        macro_windows = {str(row["window_id"]): row for row in read_jsonl(work / "macro_windows.jsonl")}
        all_windows: dict[str, dict[str, Any]] = {}
        all_windows.update(micro_windows)
        all_windows.update(macro_windows)

        for kind, window_map, source_name in (
            ("micro", micro_windows, "micro_windows.jsonl"),
            ("macro", macro_windows, "macro_windows.jsonl"),
        ):
            for index, (window_id, row) in enumerate(sorted(window_map.items(), key=lambda item: (str(item[1].get("start", "")), item[0]))):
                repo.put_context_window(
                    window_id,
                    str(row.get("dataset_id", "")),
                    window_kind=kind,
                    start_time=str(row["start"]),
                    end_time=str(row["end"]),
                    anchor_event_id=None,
                    stride_seconds=None,
                    window_index=index,
                    config_hash=config_hash,
                    attributes={
                        "source": source_name,
                        "legacy_bucket_window": True,
                        "event_count": int(row.get("event_count", len(row.get("event_ids", [])))),
                        "graph_summary": row.get("graph_summary", {}),
                    },
                )
                if source_name in artifact_ids:
                    repo.link_lineage("context_window", window_id, "artifact", artifact_ids[source_name], "materialized_from")
                counts["context_windows"] += 1
                for position, event_id in enumerate(row.get("event_ids", [])):
                    event_id = str(event_id)
                    if event_id not in frame_by_id:
                        continue
                    repo.link_window_event(window_id, event_id, position)
                    counts["window_event_links"] += 1
                window_detection_id = repo.put_window_detection_result(
                    window_id,
                    model_version="window_aggregation_v1",
                    producer_run_id=run_id,
                    raw_score=float(row.get("suspicious_score", 0.0)),
                    calibrated_score=None,
                    alert_level="unscored",
                    score_metadata={
                        "source": source_name,
                        "score_space": "mean_sigmoid_event_logit",
                        "authoritative_for_strict_m4_overlap": False,
                    },
                )
                repo.link_lineage("window_detection_result", window_detection_id, "context_window", window_id, "evaluates")
                counts["window_detections"] += 1

        for row in read_jsonl(work / "frozen_features.jsonl"):
            record = FrozenFeatureRecord.from_dict(row)
            detection_id = repo.put_detection_result(
                record,
                model_version="v3_frozen_feature_pre_fusion",
                checkpoint_hash=_checkpoint_hash(record),
                producer_run_id=run_id,
                final_score=None,
                alert_level="unscored",
                score_metadata={"source": "frozen_features.jsonl", "final_m6_score_available": False},
            )
            repo.link_lineage("detection_result", detection_id, "event", record.record_id, "evaluates")
            if "frozen_features.jsonl" in artifact_ids:
                repo.link_lineage("detection_result", detection_id, "artifact", artifact_ids["frozen_features.jsonl"], "materialized_from")
            counts["detections"] += 1

        window_links = read_jsonl(work / "window_links.jsonl")
        for row in window_links:
            source_window = str(row.get("source_window", ""))
            target_window = str(row.get("target_window", ""))
            if source_window not in all_windows or target_window not in all_windows:
                continue
            source_kind = "micro" if source_window in micro_windows else "macro" if source_window in macro_windows else "long_horizon"
            target_kind = "micro" if target_window in micro_windows else "macro" if target_window in macro_windows else "long_horizon"
            repo.put_window_link(
                source_window,
                target_window,
                link_type="m5_long_horizon",
                score=float(row.get("score", 0.0)),
                delta_seconds=float(row.get("delta_seconds", 0.0)),
                anchor_strength=str(row.get("anchor_strength", "")),
                anchors=tuple(str(value) for value in row.get("anchors", [])),
                evidence={
                    "source": "window_links.jsonl",
                    "source_window_kind": source_kind,
                    "target_window_kind": target_kind,
                },
                producer_run_id=run_id,
            )
            counts["window_links"] += 1

        attack_queues = read_jsonl(work / "attack_queues.jsonl")
        for queue in attack_queues:
            chain_id = str(queue["queue_id"])
            window_ids = [str(value) for value in queue.get("window_ids", [])]
            windows = [all_windows[value] for value in window_ids if value in all_windows]
            if not windows:
                continue
            datasets = {str(row.get("dataset_id", "")) for row in windows}
            if len(datasets) != 1:
                raise RuntimeError(f"attack queue {chain_id} spans multiple datasets: {sorted(datasets)}")
            dataset_id = next(iter(datasets))
            member_links = [
                row for row in window_links
                if str(row.get("source_window")) in window_ids and str(row.get("target_window")) in window_ids
            ]
            risk_candidates = [float(row.get("score", 0.0)) for row in member_links]
            if not risk_candidates:
                risk_candidates = [float(row.get("suspicious_score", 0.0)) for row in windows]
            risk_score = max(risk_candidates) if risk_candidates else None
            start_time = min(str(row["start"]) for row in windows)
            end_time = max(str(row["end"]) for row in windows)
            repo.put_attack_chain(
                chain_id,
                dataset_id,
                start_time=start_time,
                end_time=end_time,
                risk_score=risk_score,
                status="candidate",
                model_version="m5_long_horizon_link_v2",
                producer_run_id=run_id,
                summary={
                    "window_ids": window_ids,
                    "window_count": len(windows),
                    "link_count": len(member_links),
                    "anchors": sorted({
                        str(anchor)
                        for link in member_links
                        for anchor in link.get("anchors", [])
                    }),
                    "window_kinds": sorted({
                        "micro" if window_id in micro_windows else "macro" if window_id in macro_windows else "long_horizon"
                        for window_id in window_ids
                    }),
                },
            )
            if "attack_queues.jsonl" in artifact_ids:
                repo.link_lineage("attack_chain", chain_id, "artifact", artifact_ids["attack_queues.jsonl"], "materialized_from")
            counts["attack_chains"] += 1

            ordered_windows = sorted(windows, key=lambda row: (str(row.get("start", "")), str(row.get("window_id", ""))))
            for sequence_no, window in enumerate(ordered_windows):
                window_id = str(window["window_id"])
                relevant = [
                    row for row in member_links
                    if str(row.get("source_window")) == window_id or str(row.get("target_window")) == window_id
                ]
                evidence_score = max((float(row.get("score", 0.0)) for row in relevant), default=risk_score or 0.0)
                repo.link_attack_chain_window(
                    chain_id,
                    window_id,
                    sequence_no,
                    evidence_score=evidence_score,
                    relation_reason="m5_window_link",
                    evidence={"link_count": len(relevant)},
                )
                repo.link_lineage("attack_chain", chain_id, "context_window", window_id, "contains")
                counts["attack_chain_windows"] += 1

            event_ids = {
                str(event_id)
                for window in windows
                for event_id in window.get("event_ids", [])
                if str(event_id) in frame_by_id
            }
            ordered = sorted((frame_by_id[event_id] for event_id in event_ids), key=_event_sort_key)
            for sequence_no, frame in enumerate(ordered):
                repo.link_attack_chain_event(
                    chain_id,
                    frame.record_id,
                    sequence_no,
                    evidence_score=risk_score,
                    relation_reason="m5_window_link",
                    evidence={"window_ids": [wid for wid in window_ids if frame.record_id in all_windows.get(wid, {}).get("event_ids", [])]},
                )
                repo.link_lineage("attack_chain", chain_id, "event", frame.record_id, "contains")
                counts["attack_chain_events"] += 1

        repo.finish_run(
            run_id,
            "COMPLETED",
            metadata={
                "storage_counts": counts,
                "labels_ingested": False,
                "splits_ingested": False,
            },
        )

    return {"run_id": run_id, "counts": counts, "labels_ingested": False, "splits_ingested": False}
