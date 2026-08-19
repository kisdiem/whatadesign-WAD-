"""Build one strict causal M3 graph per unique 30-minute macro window.

The window's last timestamped event is the canonical current event.  All
earlier events in [current-30m, current) remain in the graph; labels never
enter this artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import _bootstrap  # noqa: F401
from src.entities.m2_pipeline import M2Pipeline
from src.graph.m3_encoder import GraphTensor
from src.graph.m3_graph import M3EventGraphBuilder
from src.common.schema import EventFrame


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--eventframes", type=Path, required=True)
    p.add_argument("--windows", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--dataset-id", default="ait")
    args = p.parse_args()

    frames = {}
    for line in args.eventframes.read_text(encoding="utf-8").splitlines():
        if line.strip():
            frame = EventFrame.from_dict(json.loads(line))
            frames[frame.record_id] = frame
    if not frames:
        raise ValueError("no EventFrame input")
    resolver = M2Pipeline()
    resolved = {record_id: resolver.resolve_frame(frame)[0] for record_id, frame in frames.items()}
    builder = M3EventGraphBuilder(window_seconds=1800)
    output = []
    missing = 0
    for line in args.windows.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        window = json.loads(line)
        members = [frames[rid] for rid in window.get("record_ids", ()) if rid in frames]
        if not members:
            missing += 1
            continue
        current = max((frame for frame in members if frame.timestamp), key=lambda frame: (frame.timestamp, frame.record_id), default=None)
        if current is None:
            missing += 1
            continue
        rows = [(frame, resolved[frame.record_id]) for frame in members]
        graph, rejected = builder.build_history_before_current_event(rows, current.record_id, current.timestamp)
        tensor = GraphTensor.from_event_graph(graph, feature_dim=128)
        output.append({
            "window_id": window["window_id"], "dataset_id": window.get("dataset_id", args.dataset_id),
            "start": window.get("start"), "end": window.get("end"),
            "current_record_id": current.record_id, "current_timestamp": current.timestamp,
            "history_record_ids": [frame.record_id for frame, _ in rows if frame.record_id != current.record_id],
            "graph": {"window_id": graph.window_id, "window_start": graph.window_start, "window_end": graph.window_end,
                      "nodes": [node.__dict__ for node in graph.nodes], "edges": [edge.__dict__ for edge in graph.edges]},
            "graph_tensor": {"node_features": tensor.node_features.tolist(), "edge_index": tensor.edge_index.tolist(), "edge_type": tensor.edge_type.tolist(), "node_type": tensor.node_type.tolist()},
            "rejected": rejected,
            "provenance": {"kind": "real_m3_macro_window_graph", "labels_read": False, "current_event_excluded": True, "window_seconds": 1800},
        })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in output), encoding="utf-8")
    manifest = {"status": "M3_MACRO_WINDOWS_READY_M4_RETRAIN_PENDING", "count": len(output), "missing_windows": missing,
                "graph_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(), "labels_read": False,
                "policy": "one_graph_per_unique_30min_window; full_strict_history_retained"}
    args.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
