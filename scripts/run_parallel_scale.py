from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import _bootstrap
from src.detection.engine import DetectionEngine
from src.detection.schema import write_json, write_jsonl


def run_worker(index: int, root: str, output: Path, args: argparse.Namespace) -> dict:
    worker_dir = (output / "workers" / f"worker-{index:02d}").resolve()
    command = [
        sys.executable, "scripts/run_scale_detection.py", "--mode", "online",
        "--root", root, "--output-dir", str(worker_dir),
        "--max-records", str(args.max_records_per_worker),
        "--top-k", str(args.top_k_per_worker), "--sketch-width", str(args.sketch_width),
    ]
    completed = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True, text=True)
    manifest = json.loads((worker_dir / "detection_manifest.json").read_text(encoding="utf-8"))
    return {"worker": index, "root": root, "output_dir": str(worker_dir), "command": command, "manifest": manifest, "stdout": completed.stdout[-2000:]}


def load_existing_worker(index: int, root: str, output: Path) -> dict:
    worker_dir = (output / "workers" / f"worker-{index:02d}").resolve()
    manifest = json.loads((worker_dir / "detection_manifest.json").read_text(encoding="utf-8"))
    return {"worker": index, "root": root, "output_dir": str(worker_dir), "command": [], "manifest": manifest, "stdout": ""}


def load_worker_candidates(worker_dir: Path, manifest: dict) -> list[dict]:
    def deduplicate(rows: list[dict]) -> list[dict]:
        unique: dict[str, dict] = {}
        for position, row in enumerate(rows):
            key = str(row.get("event_id") or row.get("id") or f"row-{position}")
            unique[key] = row
        return list(unique.values())

    logs_path = worker_dir / "logs.jsonl"
    if logs_path.is_file():
        try:
            with logs_path.open("r", encoding="utf-8") as handle:
                return deduplicate([json.loads(line) for line in handle if line.strip()])
        except OSError:
            pass
    compressed: list[dict] = []
    for relative in manifest.get("candidate_partitions", []):
        partition = worker_dir / relative
        if not partition.is_file():
            continue
        with gzip.open(partition, "rt", encoding="utf-8") as handle:
            compressed.extend(json.loads(line) for line in handle if line.strip())
    if compressed:
        return deduplicate(compressed)
    # Some Windows filesystem/AV configurations can quarantine an actively created
    # JSONL file. The same retained rows are embedded in findings.json, so merging
    # can recover without re-reading the original multi-GB source.
    findings_path = worker_dir / "findings.json"
    if not findings_path.is_file():
        return []
    unique: dict[str, dict] = {}
    try:
        for finding in json.loads(findings_path.read_text(encoding="utf-8")):
            for row in finding.get("events", []):
                unique[str(row.get("event_id") or row.get("id"))] = row
    except OSError:
        return []
    return list(unique.values())


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded-memory log detection in parallel source shards.")
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--workers", type=int, default=0, help="0 uses one worker per root.")
    parser.add_argument("--max-records-per-worker", type=int, default=0)
    parser.add_argument("--top-k-per-worker", type=int, default=10_000)
    parser.add_argument("--aggregate-top-k", type=int, default=20_000)
    parser.add_argument("--sketch-width", type=int, default=1 << 16)
    parser.add_argument("--merge-existing", action="store_true", help="Merge completed worker directories without rerunning them.")
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    previous_report: dict = {}
    if args.merge_existing and (output / "scale_report.json").is_file():
        previous_report = json.loads((output / "scale_report.json").read_text(encoding="utf-8"))
    started = time.perf_counter()
    worker_count = min(args.workers or len(args.root), len(args.root))
    results: list[dict] = []
    if args.merge_existing:
        results = [load_existing_worker(index, root, output) for index, root in enumerate(args.root)]
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(run_worker, index, root, output, args) for index, root in enumerate(args.root)]
            for future in as_completed(futures):
                results.append(future.result())
    results.sort(key=lambda item: item["worker"])

    candidates: list[dict] = []
    source_catalog: list[dict] = []
    for result in results:
        worker_dir = Path(result["output_dir"]).resolve()
        candidates.extend(load_worker_candidates(worker_dir, result["manifest"]))
        catalog_path = worker_dir / "source_catalog.json"
        if catalog_path.is_file():
            source_catalog.extend(json.loads(catalog_path.read_text(encoding="utf-8")))
    candidates.sort(key=lambda row: (float(row.get("risk_score", 0)), row.get("timestamp", "")), reverse=True)
    candidates = DetectionEngine.dashboard_safe_rows(candidates[:args.aggregate_top_k])
    engine = DetectionEngine()
    windows = engine._windows(candidates)
    investigations = engine._investigations(windows)
    write_jsonl(output / "logs.jsonl", candidates)
    write_json(output / "windows.json", windows)
    write_json(output / "findings.json", windows)
    write_json(output / "investigations.json", investigations)
    write_json(output / "source_catalog.json", source_catalog)
    source_types = sorted({row.get("source_type", "unknown") for row in candidates})
    latest = max((row.get("timestamp", "") for row in candidates), default="")
    write_json(output / "log_sources.json", [{
        "id": f"SRC-{index:03d}", "name": source, "path": "parallel source catalog", "kind": source,
        "status": "online", "size": f"{sum(result['manifest']['unique_source_bytes'] for result in results)} B", "lastRead": latest,
    } for index, source in enumerate(source_types, 1)])
    elapsed = max(time.perf_counter() - started, 1e-9)
    if args.merge_existing and previous_report.get("elapsed_seconds"):
        elapsed = float(previous_report["elapsed_seconds"])
    total_bytes = sum(result["manifest"].get("bytes_read", 0) for result in results)
    total_records = sum(result["manifest"].get("input_count", 0) for result in results)
    report = {
        "status": "COMPLETED", "execution_mode": "parallel_bounded_memory_online",
        "worker_count": worker_count, "worker_root_names": [Path(root).name for root in args.root],
        "worker_results": [result["manifest"] for result in results],
        "source_catalog_sha256": hashlib.sha256(
            "|".join(result["manifest"].get("source_catalog_sha256", "") for result in results).encode()
        ).hexdigest(),
        "labels_accessed": any(result["manifest"].get("labels_accessed", True) for result in results),
        "input_count": total_records, "bytes_read": total_bytes, "candidate_count": len(candidates),
        "finding_count": len(windows), "elapsed_seconds": elapsed,
        "records_per_second": total_records / elapsed, "source_bytes_per_second": total_bytes / elapsed,
        "projected_decimal_tb_per_day": (total_bytes / elapsed) * 86400 / 1_000_000_000_000,
        "aggregate_peak_sampled_working_set_bytes": sum(result["manifest"].get("peak_sampled_working_set_bytes") or 0 for result in results),
        "benchmark_environment": {"platform": platform.platform(), "python": platform.python_version(),
                                  "logical_cpu_count": os.cpu_count()},
        "memory_contract": {"state_grows_with_input": False, "max_retained_candidates": args.aggregate_top_k,
                            "worker_count": worker_count, "isolation": "one fixed-memory state per source shard"},
    }
    write_json(output / "detection_manifest.json", report)
    write_json(output / "scale_report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
