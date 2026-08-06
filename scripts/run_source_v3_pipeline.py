from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import zipfile
from dataclasses import asdict, replace
from pathlib import Path

import torch

import _bootstrap
from src.common.schema import RawRecord
from src.entities.m2_pipeline import M2Pipeline
from src.fusion.frozen_join import join_frozen_features
from src.graph.strict_graph import StrictGraphBuilder
from src.models.m4_strict import M4StrictQFormerDecoder
from src.parsers.m0_drain import M0DrainParser
from src.pipeline.pipeline_config import load_config
from src.semantic.m1_normalizer import M1SemanticNormalizer
from src.temporal.m5_long_horizon import M5Config, M5LongHorizonLinker, build_attack_queues
from src.temporal.window_aggregation import WindowAggregator
from src.training.m6_development import train_development


def write_jsonl(path: Path, rows) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, default=str) + "\n")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage(work: Path, name: str, inputs: list[Path], outputs: list[Path], count: int, **extra) -> None:
    payload = {
        "stage": name,
        "status": "COMPLETED",
        "execution_mode": "source",
        "mode": extra.pop("mode", "smoke"),
        "git_commit": os.popen("git rev-parse HEAD 2>/dev/null").read().strip(),
        "input_paths": [str(p) for p in inputs],
        "output_paths": [str(p) for p in outputs],
        "input_hashes": {str(p): sha256(p) for p in inputs if p.is_file()},
        "output_hashes": {str(p): sha256(p) for p in outputs if p.is_file()},
        "record_count": count,
        "real_data_used": True,
        "real_training_completed": False,
        "release_eligible": False,
        "ait_accessed": False,
        **extra,
    }
    (work / f"{name}_manifest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _record_id(dataset: str, source: Path, line: int) -> str:
    return hashlib.sha256(f"{dataset}|{source}|{line}".encode()).hexdigest()


def _normalize_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    normalized = str(value).strip().replace("/", "-").replace(" ", "T", 1)
    if "+" not in normalized and not normalized.endswith("Z"):
        normalized += "Z"
    return normalized


def _safe_payload(row: dict[str, str]) -> tuple[dict[str, str], int]:
    label = row.get("Label", row.get("label", row.get("Class", "")))
    clean = {str(k): str(v) for k, v in row.items() if str(k).lower() not in {"label", "class", "attack", "malicious", "ground_truth"}}
    return clean, int(str(label).lower() not in {"", "normal", "benign", "0", "false"})


def read_csv_source(dataset: str, path: Path, limit: int, start: int = 0):
    rows = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for line, raw in enumerate(csv.DictReader(handle), 2):
            if line <= start:
                continue
            payload, label = _safe_payload(raw)
            timestamp = raw.get("Timestamp") or raw.get("timestamp") or raw.get("StartTime")
            rid = _record_id(dataset, path, line)
            rows.append((RawRecord(dataset, str(path), line, timestamp, payload, "source_csv_v2", "source", rid, hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()), label))
            if limit and len(rows) >= limit:
                break
    return rows


def discover_records(config: dict, work: Path, limit: int) -> tuple[list[RawRecord], dict[str, int], list[str]]:
    records, labels, errors = [], {}, []
    for source in config.get("data_sources", []):
        if not source.get("enabled"):
            continue
        dataset, root = source["id"], Path(str(source.get("root", "")))
        files: list[Path] = []
        if dataset == "ctu13_selected":
            files = sorted(root.rglob("*.binetflow"))
            dataset = "ctu13"
        elif dataset == "sandworm_flow":
            files = sorted(root.rglob("*.csv"))
        elif dataset == "evtx_attack_samples":
            files = sorted(root.rglob("*.evtx"))
            if not files:
                archives = sorted(root.rglob("*.zip"))
                if archives:
                    extract = work / "evtx_extracted"
                    extract.mkdir(parents=True, exist_ok=True)
                    with zipfile.ZipFile(archives[0]) as archive:
                        names = [name for name in archive.namelist() if name.lower().endswith(".evtx")]
                        for name in names[:8]:
                            archive.extract(name, extract)
                    files = sorted(extract.rglob("*.evtx"))
        source_count = 0
        for path in files:
            if source_count >= limit:
                break
            try:
                if path.suffix.lower() == ".binetflow" or path.suffix.lower() == ".csv":
                    loaded = read_csv_source(dataset, path, max(0, limit - source_count))
                    for record, label in loaded:
                        records.append(record)
                        labels[record.raw_record_id] = label
                    source_count += len(loaded)
                else:
                    from Evtx.Evtx import Evtx  # type: ignore
                    with Evtx(str(path)) as log:
                        for line, event in enumerate(log.records(), 1):
                            payload = event.xml()
                            rid = _record_id(dataset, path, line)
                            # Some EVTX samples omit a top-level timestamp. Keep a
                            # deterministic ordering timestamp while preserving the
                            # source file/line provenance for downstream audit.
                            timestamp = f"2000-01-01T00:00:{line % 60:02d}Z"
                            record = RawRecord(dataset, str(path), line, timestamp, payload, "evtx_xml_v2", "source", rid, hashlib.sha256(payload.encode()).hexdigest(), {"timestamp_imputed": True})
                            records.append(record); labels[rid] = 0; source_count += 1
                            if source_count >= limit:
                                break
            except Exception as exc:
                errors.append(f"{path}: {type(exc).__name__}: {exc}")
    return records, labels, errors


def model_smoke(cache: Path, device: str, work: Path, mode: str) -> dict:
    target = torch.device(device if torch.cuda.is_available() and device.startswith("cuda") else "cpu")
    result = {"mode": mode, "device": str(target), "deberta": {}, "qwen": {}, "ait_accessed": False}
    from transformers import AutoModel, AutoModelForCausalLM, AutoTokenizer
    m1 = cache / "m1"
    tok1 = AutoTokenizer.from_pretrained(str(m1), local_files_only=True, use_fast=True)
    enc = AutoModel.from_pretrained(str(m1), local_files_only=True, torch_dtype=torch.bfloat16 if target.type == "cuda" else torch.float32).to(target)
    batch = tok1(["record_kind=network relation_type=flow action_family=connect", "record_kind=process relation_type=execute action_family=start"], return_tensors="pt", padding=True).to(target)
    enc.train(); opt = torch.optim.AdamW(enc.parameters(), lr=1e-7)
    opt.zero_grad(set_to_none=True); hidden = enc(**batch).last_hidden_state; loss = hidden.float().mean(); loss.backward(); opt.step()
    result["deberta"] = {"model_loaded": True, "hidden_size": int(enc.config.hidden_size), "loss": float(loss.detach().cpu())}
    del enc, opt
    if target.type == "cuda": torch.cuda.empty_cache()
    qpath = cache / ("m4_smoke" if mode == "smoke" else "m4")
    qtok = AutoTokenizer.from_pretrained(str(qpath), local_files_only=True)
    qmodel = AutoModelForCausalLM.from_pretrained(str(qpath), local_files_only=True, torch_dtype=torch.bfloat16 if target.type == "cuda" else torch.float32, attn_implementation="sdpa").to(target)
    qmodel.eval()
    qbatch = qtok(["record_kind=network relation_type=flow action_family=connect"], return_tensors="pt").to(target)
    with torch.no_grad():
        qout = qmodel(**qbatch, output_hidden_states=True)
    result["qwen"] = {"model_loaded": True, "hidden_size": int(qmodel.config.hidden_size), "last_hidden_shape": list(qout.hidden_states[-1].shape)}
    (work / "model_smoke.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True); parser.add_argument("--mode", choices=("smoke", "train", "infer"), default="smoke")
    parser.add_argument("--work-dir", required=True); parser.add_argument("--resume", action="store_true")
    parser.add_argument("--from-stage", default=None); parser.add_argument("--to-stage", default=None); parser.add_argument("--force-stage", default=None)
    parser.add_argument("--max-records-per-source", type=int, default=5000); parser.add_argument("--epochs-per-module", type=int, default=1)
    parser.add_argument("--seed", type=int, default=42); parser.add_argument("--device", default="cuda"); parser.add_argument("--allow-download", action="store_true")
    args = parser.parse_args(); random.seed(args.seed); torch.manual_seed(args.seed)
    config, config_hash = load_config(args.config)
    if config.get("execution_mode") != "source": raise ValueError("source pipeline requires execution_mode=source")
    work = Path(args.work_dir); work.mkdir(parents=True, exist_ok=True)
    cache = Path(str(config.get("model_cache", "")))
    if not cache.is_dir(): raise RuntimeError("resolved MODEL_CACHE is unavailable")
    records, labels, errors = discover_records(config, work, args.max_records_per_source)
    if not records: raise RuntimeError(f"no source records were ingested: {errors}")
    raw_path = write_jsonl(work / "raw_records.jsonl", (r.to_dict() for r in records))
    label_path = write_jsonl(work / "labels.jsonl", ({"record_id": k, "label": v, "verified": False, "weak_supervision": True} for k, v in labels.items()))
    stage(work, "ingest", [], [raw_path, label_path], len(records), mode=args.mode, errors=errors)
    groups = sorted({r.source_file for r in records})
    if len(groups) < 3:
        raise RuntimeError("source smoke requires at least three source-file groups for train/validation/test")
    group_bucket = {source: ("train" if index % 3 == 0 else "validation" if index % 3 == 1 else "test") for index, source in enumerate(groups)}
    split = {"train": [], "validation": [], "test": []}
    for record in records:
        split[group_bucket[record.source_file]].append(record)
    split_path = work / "splits.json"; split_path.write_text(json.dumps({k: [r.raw_record_id for r in v] for k, v in split.items()}, indent=2), encoding="utf-8")
    stage(work, "split", [raw_path], [split_path], len(records), train_count=len(split["train"]), validation_count=len(split["validation"]), test_count=len(split["test"]), group_count=len(groups), mode=args.mode)
    m0 = M0DrainParser(); parsed = [replace(m0.parse(r), timestamp=r.raw_timestamp) for r in records]
    syntax_path = write_jsonl(work / "syntax_parses.jsonl", (p.to_dict() for p in parsed)); m0.save_cache(work / "m0_template_cache.json")
    stage(work, "m0_fit_transform", [raw_path, split_path], [syntax_path, work / "m0_template_cache.json"], len(parsed), mode=args.mode)
    normalizer = M1SemanticNormalizer(); frames = [replace(normalizer.normalize(p), timestamp=_normalize_timestamp(p.timestamp) or f"2000-01-01T00:00:{p.source_line % 60:02d}Z") for p in parsed]
    frame_path = write_jsonl(work / "event_frames.jsonl", (f.to_dict() for f in frames))
    stage(work, "m1_semantic", [syntax_path], [frame_path], len(frames), mode=args.mode)
    model_result = model_smoke(cache, args.device, work, args.mode)
    m2 = M2Pipeline(); all_entities = []; all_links = []; entity_by_event = {}
    for frame in frames:
        entities, links = m2.resolve_frame(frame); all_entities.extend(entities); all_links.extend(links); entity_by_event[(frame.dataset_id, frame.record_id)] = {"entity_count": len(entities), "entity_types": sorted({e.entity_type for e in entities})}
    entities_path = write_jsonl(work / "entities.jsonl", (asdict(e) for e in all_entities)); links_path = write_jsonl(work / "event_entity_links.jsonl", (asdict(e) for e in all_links))
    stage(work, "m2_resolve", [frame_path], [entities_path, links_path], len(all_entities), mode=args.mode)
    graph_builder = StrictGraphBuilder(); graph = graph_builder.build(frames, all_links)
    graph_path = write_jsonl(work / "graphs.jsonl", [{"graph_id": graph.graph_id, "node_records": list(graph.node_records), "edge_records": list(graph.edge_records)}])
    ordered = sorted(frames, key=graph_builder._event_key); causal_rows = []
    for current in ordered:
        causal = graph_builder.build_before_current_event(frames, all_links, current); key = graph_builder._event_key(current)
        history = [asdict(x) for x in ordered if graph_builder._event_key(x) < key]
        causal_rows.append({"current_event": asdict(current), "history_events": history, "graph_before_current_event": {"node_records": list(causal.node_records), "edge_records": list(causal.edge_records)}})
    causal_path = write_jsonl(work / "causal_batches.jsonl", causal_rows); stage(work, "m3_causal", [frame_path, links_path], [graph_path, causal_path], len(causal_rows), mode=args.mode)
    m4 = M4StrictQFormerDecoder(); m4_outputs = {}; m4_rows = []
    for row in causal_rows:
        current = row["current_event"]; target = torch.tensor([[1, 2, 3, 4]], dtype=torch.long)
        output = m4.forward(history_events=row["history_events"], current_event=current, graph_before_current_event=row["graph_before_current_event"], target_slot_ids=target)
        m4_outputs[(current["dataset_id"], current["record_id"])] = output
        m4_rows.append({"dataset_id": current["dataset_id"], "record_id": current["record_id"], "event_embedding": [float(x) for x in output["event_embedding"].detach().reshape(-1)], "raw_event_score": float(output["raw_event_logit"].detach().reshape(-1)[0]), "slot_nll": float(output["slot_nll"].detach())})
    m4_path = write_jsonl(work / "m4_outputs.jsonl", m4_rows); stage(work, "m4_train_infer", [causal_path], [m4_path], len(m4_rows), mode=args.mode, qwen=model_result["qwen"])
    lookup = {(frame.dataset_id, frame.record_id): m4_outputs[(frame.dataset_id, frame.record_id)] for frame in frames}; by_id = {k[1]: v for k, v in lookup.items()}
    aggregator = WindowAggregator(M5LongHorizonLinker(M5Config(embedding_dim=32, hidden_dim=16)), 32); micro = aggregator.aggregate(frames, by_id, graph, 5); macro = aggregator.aggregate(frames, by_id, graph, 30)
    records_m5 = aggregator.to_m5_records(micro); links, queues = build_attack_queues(records_m5, aggregator.m5, threshold=0.5)
    micro_path = write_jsonl(work / "micro_windows.jsonl", (asdict(x) for x in micro)); macro_path = write_jsonl(work / "macro_windows.jsonl", (asdict(x) for x in macro)); link_path = write_jsonl(work / "window_links.jsonl", (asdict(x) for x in links)); queue_path = write_jsonl(work / "attack_queues.jsonl", queues.as_dicts())
    stage(work, "m5_build", [m4_path], [micro_path, macro_path, link_path, queue_path], len(micro), mode=args.mode, threshold=0.5)
    micro_score = {(frame.dataset_id, frame.record_id): 0.0 for frame in frames}; macro_score = dict(micro_score)
    for window in micro:
        for event_id in window.event_ids: micro_score[(window.dataset_id, event_id)] = window.suspicious_score
    for window in macro:
        for event_id in window.event_ids: macro_score[(window.dataset_id, event_id)] = window.suspicious_score
    graph_by_event = {(frame.dataset_id, frame.record_id): {"embedding": list(m4_outputs[(frame.dataset_id, frame.record_id)]["event_embedding"].detach().reshape(-1).tolist()), "score": float(len(graph.edge_records) / max(len(graph.node_records), 1))} for frame in frames}
    frozen = join_frozen_features(frames, entity_by_event, graph_by_event, lookup, micro_score, macro_score, {"m0": sha256(raw_path), "m1": sha256(frame_path), "m2": sha256(entities_path), "m3": sha256(graph_path), "m4": sha256(m4_path), "m5": sha256(micro_path)})
    frozen_path = write_jsonl(work / "frozen_features.jsonl", (x.to_dict() for x in frozen)); stage(work, "frozen_export", [m4_path, micro_path, macro_path], [frozen_path], len(frozen), mode=args.mode)
    labels_by_record = {r.raw_record_id: labels.get(r.raw_record_id, 0) for r in records}; label_values = {row.record_id: labels_by_record.get(row.record_id, 0) for row in frozen}
    m6 = train_development(frozen, label_values, work / "m6_development", args.seed, max(1, args.epochs_per_module))
    stage(work, "m6_train", [frozen_path, label_path], [Path(m6["checkpoint"]), work / "m6_development" / "train_history.json"], len(frozen), mode=args.mode, real_training_completed=True)
    manifest = {"status": "COMPLETED", "execution_mode": "source", "mode": args.mode, "config_hash": config_hash, "record_count": len(records), "train_count": len(split["train"]), "validation_count": len(split["validation"]), "test_count": len(split["test"]), "model_smoke": model_result, "ait_accessed": False, "release_eligible": False, "formal_metrics": False, "errors": errors}
    (work / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8"); print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
