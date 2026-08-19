"""Build real AIT M1 embeddings, M2 entities and causal M3 history graphs.

This script intentionally stops before FrozenFeatureRecord export.  It does
not read AIT labels and does not call an untrained M3/M5 model as if it were a
formal producer.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import torch

import _bootstrap
from src.common.schema import EventFrame
from src.entities.m2_pipeline import M2Pipeline
from src.graph.m3_graph import M3EventGraphBuilder


def _timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).isoformat()
    except ValueError:
        return None


def _frame(row: dict, dataset_id: str, source: str, line_no: int) -> tuple[EventFrame, str]:
    # AIT2 records wrap the original Wazuh object in raw_payload.  Unwrap only
    # the raw event fields; labels/split metadata remain outside the model input.
    payload = row.get("raw_payload") if isinstance(row.get("raw_payload"), dict) else row
    full_log = str(row.get("full_log", ""))
    full_log = str(payload.get("full_log", ""))
    program = str(payload.get("decoder", {}).get("name", payload.get("predecoder", {}).get("program_name", "unknown")))
    lower = full_log.lower()
    action = "authenticate" if any(x in lower for x in ("login", "logon", "authentication")) else "execute" if "process" in lower else "observe"
    outcome = "failure" if any(x in lower for x in ("failed", "failure", "denied", "error")) else "success" if "success" in lower else "unknown"
    agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
    mentions = []
    for value, role, entity_type in ((agent.get("name"), "host", "host"), (agent.get("ip"), "source", "ip"), (program, "process", "process")):
        if value:
            mentions.append({"raw_value": str(value), "role": role, "entity_type": entity_type})
    record_id = str(row.get("record_id") or hashlib.sha256(f"{dataset_id}|{source}|{line_no}".encode()).hexdigest())
    frame = EventFrame(dataset_id=dataset_id, record_id=record_id, timestamp=_timestamp(row.get("timestamp") or payload.get("@timestamp")),
                       record_kind="security_log", relation_type="observed", action_family=action,
                       action_leaf=program, roles={"actor": agent.get("name", "unknown")}, outcome=outcome,
                       key_attributes={"program": program, "location": payload.get("location", "")},
                       entity_mentions=mentions, source_record_ref=str(row.get("source_record_ref") or f"{source}:{line_no}"), semantic_version="m1-ait-v1")
    return frame, full_log


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--dataset-id", default="ait")
    p.add_argument("--m1-model", type=Path, required=True)
    p.add_argument("--limit", type=int, default=128)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--progress-every", type=int, default=256)
    p.add_argument("--skip-m3", action="store_true", help="stop after publishing M1/M2; macro M3 is built by its dedicated runner")
    p.add_argument("--device", default="cuda")
    p.add_argument("--resume-m1", action="store_true", help="reuse the immutable M1 EventFrame JSONL and continue with M2")
    args = p.parse_args()
    if args.resume_m1:
        m1_path = args.output / "m1_eventframes.jsonl"
        if not m1_path.exists():
            raise FileNotFoundError(f"M1 artifact not found: {m1_path}")
        frames = [EventFrame.from_dict(json.loads(line)) for line in m1_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not frames:
            raise RuntimeError("M1 artifact is empty")
        m2 = M2Pipeline(); resolved = []; links = []
        for frame in frames:
            entities, event_links = m2.resolve_frame(frame); resolved.append(entities); links.extend(event_links)
        (args.output / "m2_entities.jsonl").write_text("".join(json.dumps(entity.to_dict(), ensure_ascii=True) + "\n" for group in resolved for entity in group), encoding="utf-8")
        (args.output / "m2_links.jsonl").write_text("".join(json.dumps(link.__dict__, ensure_ascii=True) + "\n" for link in links), encoding="utf-8")
        if args.skip_m3:
            manifest = {"status": "M1_M2_READY_MACRO_M3_PENDING", "real_data_used": True, "labels_read": False,
                        "device": "reused_m1", "count": len(frames), "m2_resolver": "m2_entity_rule_v1"}
            (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            (args.output / "m1_progress.json").write_text(json.dumps({
                "status": "M2_READY_M3_SKIPPED", "count": len(frames), "labels_read": False,
            }, indent=2), encoding="utf-8")
            print(json.dumps(manifest, ensure_ascii=False), flush=True)
            return
        raise ValueError("--resume-m1 without --skip-m3 is not supported; use the dedicated M3 runner")
    from transformers import AutoModel, AutoTokenizer

    device = torch.device(args.device if args.device == "cpu" or torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(str(args.m1_model), local_files_only=True, use_fast=False)
    model = AutoModel.from_pretrained(str(args.m1_model), local_files_only=True).to(device).eval()
    frames: list[EventFrame] = []
    raw_texts: list[str] = []
    with args.input.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if len(frames) >= args.limit:
                break
            if not line.strip():
                continue
            row = json.loads(line)
            frame, text = _frame(row, args.dataset_id, str(args.input), line_no)
            if frame.timestamp is None:
                continue
            frames.append(frame); raw_texts.append(text)
    if not frames:
        raise RuntimeError("no timestamped AIT records available")
    embedding_batches = []
    with torch.no_grad():
        for start in range(0, len(raw_texts), max(1, args.batch_size)):
            batch_texts = raw_texts[start:start + max(1, args.batch_size)]
            encoded = tokenizer(batch_texts, return_tensors="pt", padding=True, truncation=True, max_length=256)
            encoded = {key: value.to(device) for key, value in encoded.items()}
            hidden = model(**encoded).last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1).to(hidden.dtype)
            embedding_batches.append(((hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp_min(1.0)).cpu())
            del encoded, hidden, mask
        embeddings = torch.cat(embedding_batches, dim=0)
    frames = [replace(frame, semantic_embedding=[float(x) for x in emb]) for frame, emb in zip(frames, embeddings)]
    # Publish the M1 contract before the CPU-heavy M2/M3 phase.  Consumers can
    # safely start M4 from this immutable checkpoint while M3 continues.
    args.output.mkdir(parents=True, exist_ok=True)
    m1_path = args.output / "m1_eventframes.jsonl"
    m1_tmp = m1_path.with_suffix(".jsonl.tmp")
    m1_tmp.write_text("".join(json.dumps(frame.to_dict(), ensure_ascii=True) + "\n" for frame in frames), encoding="utf-8")
    m1_tmp.replace(m1_path)
    (args.output / "m1_progress.json").write_text(json.dumps({
        "status": "M1_READY_M2_M3_RUNNING", "count": len(frames),
        "batch_size": max(1, args.batch_size), "device": str(device),
        "labels_read": False,
    }, indent=2), encoding="utf-8")
    print(json.dumps({"stage": "M1", "status": "READY", "count": len(frames)}, ensure_ascii=False), flush=True)
    m2 = M2Pipeline(); resolved = []; links = []
    for frame in frames:
        entities, event_links = m2.resolve_frame(frame); resolved.append(entities); links.extend(event_links)
    # --skip-m3 is a real stage boundary: persist M2 before any graph work.
    # This keeps large source runs resumable and avoids constructing unused
    # 30-minute graphs when the next stage is intentionally deferred.
    (args.output / "m2_entities.jsonl").write_text("".join(json.dumps(entity.to_dict(), ensure_ascii=True) + "\n" for group in resolved for entity in group), encoding="utf-8")
    (args.output / "m2_links.jsonl").write_text("".join(json.dumps(link.__dict__, ensure_ascii=True) + "\n" for link in links), encoding="utf-8")
    if args.skip_m3:
        manifest = {"status": "M1_M2_READY_MACRO_M3_PENDING", "real_data_used": True, "labels_read": False,
                    "device": str(device), "count": len(frames), "m1_batch_size": max(1, args.batch_size),
                    "m1_model": str(args.m1_model), "m2_resolver": "m2_entity_rule_v1"}
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        (args.output / "m1_progress.json").write_text(json.dumps({
            "status": "M2_READY_M3_SKIPPED", "count": len(frames), "labels_read": False,
        }, indent=2), encoding="utf-8")
        print(json.dumps(manifest, ensure_ascii=False), flush=True)
        return
    graph_builder = M3EventGraphBuilder()
    # The strict builder is intentionally defensive and can accept any
    # iterable, but passing the complete dataset for every current event makes
    # this source runner quadratic.  Build a timestamp index once and pass
    # only the candidate 30-minute slice to M3.
    indexed = []
    for row in zip(frames, resolved):
        stamp = graph_builder._parse_timestamp(row[0].timestamp)
        if stamp is not None:
            indexed.append((stamp.timestamp(), row))
    indexed.sort(key=lambda item: item[0])
    index_times = [item[0] for item in indexed]
    graphs = []
    for index, frame in enumerate(frames):
        current_stamp = graph_builder._parse_timestamp(frame.timestamp)
        if current_stamp is None:
            raise ValueError(f"timestamp missing for current event {frame.record_id}")
        left = bisect.bisect_left(index_times, current_stamp.timestamp() - graph_builder.window_seconds)
        right = bisect.bisect_left(index_times, current_stamp.timestamp())
        candidate_rows = [row for _, row in indexed[left:right]]
        graph, rejected = graph_builder.build_history_before_current_event(candidate_rows, frame.record_id, frame.timestamp)
        graphs.append({"record_id": frame.record_id, "graph": {"window_id": graph.window_id, "window_start": graph.window_start, "window_end": graph.window_end, "nodes": [node.__dict__ for node in graph.nodes], "edges": [edge.__dict__ for edge in graph.edges]}, "rejected": rejected})
    (args.output / "m1_progress.json").write_text(json.dumps({
        "status": "M3_READY", "count": len(frames), "labels_read": False,
    }, indent=2), encoding="utf-8")
    (args.output / "m3_history_graphs.jsonl").write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in graphs), encoding="utf-8")
    manifest = {"status": "PARTIAL_UPSTREAM_READY", "real_data_used": True, "labels_read": False, "device": str(device), "count": len(frames), "m1_batch_size": max(1, args.batch_size), "m1_model": str(args.m1_model), "m1_model_sha256": hashlib.sha256((args.m1_model / "pytorch_model.bin").read_bytes()).hexdigest(), "m2_resolver": "m2_entity_rule_v1", "m3_graph": "m3_event_graph_v1_strict_history", "blocked_stages": {"m4": "existing checkpoint is legacy non-Qwen-connected architecture", "m5": "no formal M5 producer checkpoint available", "frozen_export": "not emitted until M4 and M5 are formal"}}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
