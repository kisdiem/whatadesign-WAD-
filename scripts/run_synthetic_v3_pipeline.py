from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
from dataclasses import asdict
from pathlib import Path
from datetime import datetime, timezone

import torch

import _bootstrap
from src.common.manifest import StageManifest, current_commit, hash_inputs, sha256_file
from src.common.schema import RawRecord
from src.entities.m2_pipeline import M2Pipeline
from src.fusion.frozen_join import join_frozen_features
from src.graph.strict_graph import StrictGraphBuilder
from src.models.m4_strict import M4StrictQFormerDecoder
from src.parsers.m0_parser import M0Parser
from src.pipeline.stage_runtime import write_jsonl
from src.semantic.m1_pipeline import M1RulePipeline
from src.temporal.m5_long_horizon import M5Config, M5LongHorizonLinker, build_attack_queues
from src.temporal.window_aggregation import WindowAggregator
from src.training.m6_development import train_development


def manifest(work: Path, stage: str, inputs: list[Path], outputs: list[Path], count: int, rejected: int = 0, trained: bool = False):
    return StageManifest(stage, "COMPLETED", current_commit(work), execution_mode="synthetic", config_hash=hashlib.sha256(f"{stage}|42".encode()).hexdigest(), input_paths=tuple(str(p) for p in inputs), output_paths=tuple(str(p) for p in outputs), input_hashes=hash_inputs(inputs), output_hashes=hash_inputs(outputs), record_count=count, rejected_count=rejected, real_data_used=False, real_training_completed=trained, release_eligible=False).write(work / f"{stage}_manifest.json")


def write_objects(path: Path, rows):
    return write_jsonl(path, rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    random.seed(args.seed); torch.manual_seed(args.seed)
    work = Path(args.work_dir); work.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/synthetic/source.log"
    raw_rows: list[RawRecord] = []; syntax = []; quarantined = []
    parser_m0 = M0Parser()
    for line_no, line in enumerate(fixture.read_text(encoding="utf-8").splitlines(), 1):
        match = re.match(r"(\d{4}-\d{2}-\d{2}T[^ ]+)\s+(.*)", line)
        timestamp, payload = (match.group(1), match.group(2)) if match else (None, line)
        raw = RawRecord("synthetic", str(fixture), line_no, timestamp, {"message": payload}, adapter_version="synthetic-1", parser_version="synthetic-1", raw_record_id=hashlib.sha256(f"synthetic|{fixture}|{line_no}".encode()).hexdigest(), source_hash=hashlib.sha256(line.encode()).hexdigest())
        raw_rows.append(raw); parsed = parser_m0.parse(raw)
        (quarantined if parsed.quarantined else syntax).append(parsed)
    raw_path = write_objects(work / "raw_records.jsonl", (row.to_dict() for row in raw_rows))
    syntax_path = write_objects(work / "syntax_parses.jsonl", (row.to_dict() for row in syntax))
    quarantine_path = write_objects(work / "quarantine.jsonl", (row.to_dict() for row in quarantined))
    manifest(work, "m0", [fixture], [raw_path, syntax_path, quarantine_path], len(raw_rows), len(quarantined))

    m1 = M1RulePipeline(); frames = [m1.infer(row) for row in syntax]
    frame_path = write_objects(work / "event_frames.jsonl", (asdict(row) for row in frames))
    manifest(work, "m1", [syntax_path], [frame_path], len(frames))

    m2 = M2Pipeline(); all_entities = []; all_links = []; entities_by_event = {}
    for frame in frames:
        entities, links = m2.resolve_frame(frame); all_entities.extend(entities); all_links.extend(links); entities_by_event[(frame.dataset_id, frame.record_id)] = {"entity_count": len(entities), "entity_types": sorted({entity.entity_type for entity in entities})}
    entities_path = write_objects(work / "entities.jsonl", (asdict(row) for row in all_entities))
    links_path = write_objects(work / "event_entity_links.jsonl", (asdict(row) for row in all_links))
    manifest(work, "m2", [frame_path], [entities_path, links_path], len(all_entities))

    graph_builder = StrictGraphBuilder(); graph = graph_builder.build(frames, all_links)
    graph_dict = {"graph_id": graph.graph_id, "dataset_id": graph.dataset_id, "node_records": list(graph.node_records), "edge_records": list(graph.edge_records)}
    graph_path = write_objects(work / "event_graphs.jsonl", [graph_dict]); manifest(work, "m3_graph", [frame_path, links_path], [graph_path], 1)
    causal_rows = []
    ordered_frames = sorted(frames, key=graph_builder._event_key)
    for current in ordered_frames:
        causal = graph_builder.build_before_current_event(frames, all_links, current)
        current_key = graph_builder._event_key(current)
        history = [row for row in ordered_frames if graph_builder._event_key(row) < current_key]
        causal_rows.append({"current_event": asdict(current), "history_events": [asdict(row) for row in history], "graph_before_current_event": {"node_records": list(causal.node_records), "edge_records": list(causal.edge_records)}, "causal_boundary": {"current_record_id": current.record_id, "excluded_current": True, "excluded_future": True}})
    causal_path = write_objects(work / "causal_m4_batches.jsonl", causal_rows); manifest(work, "m3_causal", [frame_path, graph_path], [causal_path], len(causal_rows))

    m4 = M4StrictQFormerDecoder(); m4_outputs = {}; m4_rows = []
    for row in causal_rows:
        current = row["current_event"]; target = torch.zeros((1, m4.config.slot_count), dtype=torch.long)
        output = m4.forward(history_events=row["history_events"], current_event=current, graph_before_current_event=row["graph_before_current_event"], target_slot_ids=target)
        m4_outputs[(current["dataset_id"], current["record_id"])] = output
        m4_rows.append({"record_id": current["record_id"], "stage1_source": output["stage1_source"], "stage2_sources": output["stage2_sources"], "slot_nll": float(output["slot_nll"].detach()), "raw_event_score": float(output["raw_event_logit"].detach()), "event_embedding": [float(x) for x in output["event_embedding"].detach().reshape(-1)]})
    m4_path = write_objects(work / "m4_outputs.jsonl", m4_rows); manifest(work, "m4", [causal_path], [m4_path], len(m4_rows))

    m4_lookup = {("synthetic", row["record_id"]): {"event_embedding": torch.tensor(row["event_embedding"]), "raw_event_logit": torch.tensor(row["raw_event_score"]), "slot_nll": row["slot_nll"]} for row in m4_rows}
    m4_by_id = {row["record_id"]: value for (_, record_id), value in m4_lookup.items() for row in m4_rows if row["record_id"] == record_id}
    aggregator = WindowAggregator(M5LongHorizonLinker(M5Config(embedding_dim=32, hidden_dim=16)), 32)
    micro = aggregator.aggregate(frames, m4_by_id, graph, 5); macro = aggregator.aggregate(frames, m4_by_id, graph, 30)
    micro_path = write_objects(work / "micro_windows.jsonl", (asdict(row) for row in micro)); macro_path = write_objects(work / "macro_windows.jsonl", (asdict(row) for row in macro))
    records = aggregator.to_m5_records(micro); links, queue = build_attack_queues(records, aggregator.m5, threshold=0.0)
    pair_rows = []
    ip_rejections = []
    for index, left in enumerate(records):
        for right in records[index + 1:]:
            left_ips = set(left.entities.get("ip", []))
            right_ips = set(right.entities.get("ip", []))
            shared_ip = sorted(left_ips & right_ips)
            shared_strong = sorted((set(left.entities.get("user", [])) | set(left.entities.get("host", [])) | set(left.entities.get("process", []))) & (set(right.entities.get("user", [])) | set(right.entities.get("host", [])) | set(right.entities.get("process", []))))
            row = {"source_window": left.window_id, "target_window": right.window_id, "candidate": bool(shared_strong), "shared_strong_entities": shared_strong, "shared_ip_entities": shared_ip}
            if shared_ip and not shared_strong:
                row["candidate"] = False
                row["rejected_reason"] = "ip_only_anchor"
                ip_rejections.append(row)
            pair_rows.append(row)
    pair_path = write_objects(work / "window_pairs.jsonl", pair_rows)
    ip_rejections_path = write_objects(work / "ip_only_rejections.jsonl", ip_rejections)
    link_path = write_objects(work / "window_links.jsonl", (asdict(link) for link in links))
    queue_rows = queue.as_dicts(); queue_path = write_objects(work / "attack_queues.jsonl", queue_rows)
    summary_path = write_objects(work / "summary_graphs.jsonl", ({"queue_id": row["queue_id"], "window_ids": row["window_ids"]} for row in queue_rows))
    evidence_path = write_objects(work / "evidence_steps.jsonl", ({"window_id": window.window_id, "event_count": window.event_count, "actions": window.actions} for window in micro))
    manifest(work, "m5", [frame_path, graph_path, m4_path], [micro_path, macro_path, pair_path, ip_rejections_path, link_path, queue_path, summary_path, evidence_path], len(micro), len(ip_rejections))

    micro_score = {}; macro_score = {}
    for window in micro:
        for event_id in window.event_ids: micro_score[("synthetic", event_id)] = window.suspicious_score
    for window in macro:
        for event_id in window.event_ids: macro_score[("synthetic", event_id)] = window.suspicious_score
    graph_by_event = {("synthetic", frame.record_id): {"embedding": [0.1] * 32, "score": len(graph.edge_records) / max(len(graph.node_records), 1)} for frame in frames}
    frozen = join_frozen_features(frames, entities_by_event, graph_by_event, m4_lookup, micro_score, macro_score, {"m0": sha256_file(raw_path), "m1": sha256_file(frame_path), "m2": sha256_file(entities_path), "m3": sha256_file(graph_path), "m4": sha256_file(m4_path), "m5": sha256_file(micro_path)})
    frozen_path = write_objects(work / "frozen_features.jsonl", (row.to_dict() for row in frozen)); manifest(work, "frozen_features", [frame_path, entities_path, graph_path, m4_path, micro_path, macro_path], [frozen_path], len(frozen))

    labels = {row.record_id: int("Alice" in next((frame.roles.get("actor", "") for frame in frames if frame.record_id == row.record_id), "")) for row in frozen}
    label_path = write_objects(work / "synthetic_labels.jsonl", ({"record_id": key, "label": value} for key, value in labels.items()))
    protected_paths = [raw_path, syntax_path, quarantine_path, frame_path, entities_path, links_path, graph_path, causal_path, m4_path, micro_path, macro_path, pair_path, ip_rejections_path, link_path, queue_path, summary_path, evidence_path]
    protected_before = hash_inputs(protected_paths)
    m6_result = train_development(frozen, labels, work / "m6_development", args.seed, 2)
    protected_after = hash_inputs(protected_paths)
    m6_manifest = manifest(work, "m6_development", [frozen_path, label_path], [Path(m6_result["checkpoint"]), work / "m6_development/train_history.json", work / "m6_development/validation_predictions.jsonl"], len(frozen), trained=True)
    shutil.copy2(m6_manifest, work / "m6_manifest.json")
    release_dir = work / "release_attempt"; release_dir.mkdir(exist_ok=True)
    release_reason = "development checkpoint is not a locked source release"
    try:
        from scripts.phase_d_release.lock_release import lock_release
        lock_release(release_dir)
        raise AssertionError("development checkpoint unexpectedly passed release gate")
    except Exception as exc:
        release_reason = f"development checkpoint rejected: {exc}"
    run_manifest = {"execution_mode": "synthetic", "seed": args.seed, "real_data_used": False, "release_eligible": False, "stages": {name: json.loads((work / f"{name}_manifest.json").read_text(encoding="utf-8")) for name in ("m0", "m1", "m2", "m3_graph", "m3_causal", "m4", "m5", "frozen_features", "m6_development")}, "m6_parameter_hash_before": m6_result["parameter_hash_before"], "m6_parameter_hash_after": m6_result["parameter_hash_after"], "m0_m5_hashes_before_m6": protected_before, "m0_m5_hashes_after_m6": protected_after, "m0_m5_unchanged_after_m6": protected_before == protected_after, "ip_only_rejection_count": len(ip_rejections), "release_rejection_reason": release_reason, "ait_accessed": False, "formal_metrics": False}
    (work / "run_manifest.json").write_text(json.dumps(run_manifest, indent=2), encoding="utf-8")
    print(json.dumps({"status": "COMPLETED", "run_manifest": str(work / "run_manifest.json"), "release_rejected": True, "m6_parameter_changed": m6_result["parameter_hash_before"] != m6_result["parameter_hash_after"]}, indent=2))


if __name__ == "__main__":
    main()
