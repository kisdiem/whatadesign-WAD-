from __future__ import annotations

import hashlib
import json
import time
import gzip
import heapq
import os
import platform
import re
import subprocess
from collections import OrderedDict
from dataclasses import asdict, dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from .schema import LogEvent, load_jsonl, parse_timestamp, write_json, write_jsonl
from .sources import ReadStats, SourceDescriptor, discover_sources, iter_all
from .unsupervised import FrequencyIsolationBaseline, StreamingFrequencyBaseline
from .weak_supervision import WeakSupervisor


@dataclass(frozen=True)
class DetectionConfig:
    event_threshold: float = 0.61
    window_minutes: int = 30
    weak_weight: float = 0.62
    anomaly_weight: float = 0.38
    version: str = "wad-weak-unsupervised-v1"


@dataclass(frozen=True)
class DetectionResult:
    input_count: int
    finding_count: int
    elapsed_seconds: float
    events_per_second: float
    output_dir: str
    manifest: dict[str, Any]


class DetectionEngine:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self.supervisor = WeakSupervisor()

    @staticmethod
    def _event_view(event: LogEvent, score: float, anomaly: Any, weak: Any) -> dict[str, Any]:
        action = weak.tactics[0] if weak.tactics else (anomaly.reasons[0] if anomaly.reasons else "Unusual activity")
        return {
            "id": event.event_id,
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "time": event.timestamp,
            "action": action,
            "source": event.source_type,
            "source_type": event.source_type,
            "raw": event.message,
            "text": event.message,
            "raw_log_ref": f"{event.source_file}:{event.source_line}",
            "entities": list(event.entities),
            "confidence": round(score, 6),
            "risk_score": round(score, 6),
            "anomaly_score": round(anomaly.score, 6),
            "weak_score": round(weak.score, 6),
            "weak_rules": list(weak.rules),
            "tactics": list(weak.tactics),
            "anomaly_components": anomaly.components,
        }

    def score_events(self, events: list[LogEvent], variant: str = "full") -> list[dict[str, Any]]:
        baseline = FrequencyIsolationBaseline().fit(events)
        rows: list[dict[str, Any]] = []
        for event in events:
            anomaly = baseline.score(event)
            weak = self.supervisor.vote(event)
            if variant == "unsupervised_only":
                score = anomaly.score
            elif variant == "weak_only":
                score = weak.score
            elif variant == "without_entity_rarity":
                reduced = anomaly.score - self.config.anomaly_weight * 0.27 * anomaly.components["entity_rarity"]
                score = self.config.weak_weight * weak.score + self.config.anomaly_weight * max(0.0, reduced)
            else:
                score = self.config.weak_weight * weak.score + self.config.anomaly_weight * anomaly.score
            rows.append(self._event_view(event, min(score, 1.0), anomaly, weak))
        return rows

    def score_event(self, event: LogEvent, baseline: Any, variant: str = "full") -> dict[str, Any]:
        anomaly = baseline.score(event)
        weak = self.supervisor.vote(event)
        if variant == "unsupervised_only":
            score = anomaly.score
        elif variant == "weak_only":
            score = weak.score
        elif variant == "without_entity_rarity":
            reduced = anomaly.score - self.config.anomaly_weight * 0.27 * anomaly.components["entity_rarity"]
            score = self.config.weak_weight * weak.score + self.config.anomaly_weight * max(0.0, reduced)
        else:
            score = self.config.weak_weight * weak.score + self.config.anomaly_weight * anomaly.score
        return self._event_view(event, min(score, 1.0), anomaly, weak)

    @staticmethod
    def dashboard_safe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove executable attack payloads from UI artifacts while retaining provenance."""
        safe: list[dict[str, Any]] = []
        for row in rows:
            copied = dict(row)
            raw = str(row.get("raw") or row.get("text") or "")
            digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
            summary = (
                f"Quarantined raw security event; sha256={digest[:16]}; "
                f"rules={','.join(str(value) for value in row.get('weak_rules', [])) or 'none'}"
            )
            copied["raw"] = summary
            copied["text"] = summary
            copied["evidence_sha256"] = digest
            copied["raw_payload_available"] = False
            safe.append(copied)
        return safe

    def _windows(self, rows: list[dict[str, Any]], include_chain: bool = True) -> list[dict[str, Any]]:
        candidates = [row for row in rows if float(row["risk_score"]) >= self.config.event_threshold]
        if not candidates:
            return []
        candidates.sort(key=lambda row: (row["timestamp"], row["event_id"]))
        groups: list[list[dict[str, Any]]] = []
        for row in candidates:
            timestamp = parse_timestamp(row["timestamp"])
            entity_set = set(row["entities"])
            match: list[dict[str, Any]] | None = None
            if include_chain:
                for group in reversed(groups):
                    delta = timestamp - parse_timestamp(group[-1]["timestamp"])
                    shared = entity_set.intersection(*(set(item["entities"]) for item in group)) if group else set()
                    if delta <= timedelta(minutes=self.config.window_minutes) and shared:
                        match = group
                        break
            if match is None:
                groups.append([row])
            else:
                match.append(row)
        windows: list[dict[str, Any]] = []
        for group in groups:
            digest = hashlib.sha256("|".join(row["event_id"] for row in group).encode()).hexdigest()[:12]
            score = min(0.995, max(float(row["risk_score"]) for row in group) + 0.035 * (len(group) - 1))
            tactics = list(dict.fromkeys(tactic for row in group for tactic in row["tactics"]))
            entities = list(dict.fromkeys(entity for row in group for entity in row["entities"]))
            severity = "critical" if score >= 0.90 else "high" if score >= 0.78 else "medium" if score >= 0.67 else "low"
            windows.append({
                "id": f"WIN-{digest.upper()}",
                "title": " / ".join(tactics[:2]) if tactics else "无监督稀有行为",
                "severity": severity,
                "score": round(score, 6),
                "start": group[0]["timestamp"],
                "end": group[-1]["timestamp"],
                "status": "new",
                "eventCount": len(group),
                "entities": entities,
                "hosts": [value for value in entities if value.upper().startswith(("HOST", "WEB", "DB"))],
                "sourceTypes": list(dict.fromkeys(row["source_type"] for row in group)),
                "summary": f"由 {len(group)} 条真实日志聚合；弱监督命中 {sum(bool(row['weak_rules']) for row in group)} 条，保留原始行号用于溯源。",
                "events": group,
                "weak_supervision": {"rule_hits": sum(len(row["weak_rules"]) for row in group), "tactics": tactics},
                "provenance": [row["raw_log_ref"] for row in group],
            })
        return windows

    @staticmethod
    def _legacy_single_investigation(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{
            "id": "CASE-AUTO-0001",
            "title": "弱监督与无监督联合发现",
            "severity": max((item["severity"] for item in windows), default="low", key=("low", "medium", "high", "critical").index),
            "status": "investigating",
            "windowIds": [item["id"] for item in windows],
            "owner": "Unassigned",
            "createdAt": windows[0]["start"] if windows else "",
            "summary": "检测引擎自动聚合的候选攻击链；尚未使用任何真实标签。",
        }] if windows else []

    @staticmethod
    def _investigations(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Split findings into cases using stable shared entities and a seven-day gap."""
        if not windows:
            return []

        def anchors(window: dict[str, Any]) -> set[str]:
            result: set[str] = set()
            for raw in window.get("entities", []):
                value = str(raw).strip()
                lower = value.lower()
                if not value or "\\" in value or "/" in value:
                    continue
                if lower.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs")):
                    continue
                result.add(lower)
            return result

        ordered = sorted(windows, key=lambda item: (parse_timestamp(item["start"]), item["id"]))
        groups: list[dict[str, Any]] = []
        for window in ordered:
            start = parse_timestamp(window["start"])
            window_anchors = anchors(window)
            selected: dict[str, Any] | None = None
            for group in reversed(groups):
                if start - group["last"] > timedelta(days=7):
                    continue
                if window_anchors and window_anchors.intersection(group["anchors"]):
                    selected = group
                    break
            if selected is None:
                groups.append({"windows": [window], "anchors": set(window_anchors), "last": parse_timestamp(window["end"])})
            else:
                selected["windows"].append(window)
                selected["anchors"].update(window_anchors)
                selected["last"] = max(selected["last"], parse_timestamp(window["end"]))

        severity_order = ("low", "medium", "high", "critical")
        investigations: list[dict[str, Any]] = []
        for index, group in enumerate(groups, 1):
            case_windows = group["windows"]
            case_id = f"CASE-AUTO-{index:04d}"
            anchor_label = sorted(group["anchors"])[0].upper() if group["anchors"] else "独立线索"
            tactics = list(dict.fromkeys(
                tactic
                for item in case_windows
                for tactic in item.get("weak_supervision", {}).get("tactics", [])
            ))
            tactic_label = " / ".join(tactics[:2]) if tactics else "异常行为"
            investigations.append({
                "id": case_id,
                "investigation_id": case_id,
                "title": f"{anchor_label} · {tactic_label} 调查",
                "severity": max((item["severity"] for item in case_windows), key=severity_order.index),
                "status": "investigating",
                "windowIds": [item["id"] for item in case_windows],
                "finding_ids": [item["id"] for item in case_windows],
                "owner": "Unassigned",
                "createdAt": case_windows[0]["start"],
                "summary": f"由 {len(case_windows)} 个真实日志风险窗口自动聚合；依据共享实体与七天时间邻近性建案，真实标签未参与聚合。",
                "case_anchor_entities": sorted(group["anchors"]),
                "aggregation_method": "shared-stable-entity+7d-proximity-v1",
                "labels_accessed": False,
            })
        return investigations

    def run(self, input_path: str | Path, output_dir: str | Path, variant: str = "full", include_chain: bool = True) -> DetectionResult:
        started = time.perf_counter()
        events = list(load_jsonl(input_path))
        scored = self.score_events(events, variant=variant)
        windows = self._windows(scored, include_chain=include_chain)
        investigations = self._investigations(windows)
        output = Path(output_dir)
        write_jsonl(output / "logs.jsonl", scored)
        write_json(output / "windows.json", windows)
        write_json(output / "findings.json", windows)
        write_json(output / "investigations.json", investigations)
        write_json(output / "weak_rules.json", self.supervisor.manifest())
        source_types = sorted({event.source_type for event in events})
        write_json(output / "log_sources.json", [{
            "id": f"SRC-{index:02d}", "name": source_type, "path": str(input_path),
            "kind": source_type, "status": "online", "size": f"{Path(input_path).stat().st_size} B",
            "lastRead": max(event.timestamp for event in events),
        } for index, source_type in enumerate(source_types, 1)])
        elapsed = max(time.perf_counter() - started, 1e-9)
        manifest = {
            "status": "COMPLETED",
            "execution_mode": "real_log_file",
            "input_path": str(input_path),
            "input_sha256": hashlib.sha256(Path(input_path).read_bytes()).hexdigest(),
            "input_count": len(events),
            "finding_count": len(windows),
            "labels_accessed": False,
            "weak_supervision": True,
            "unsupervised_baseline": "frequency-isolation-robust-v1",
            "variant": variant,
            "chain_aggregation": include_chain,
            "config": asdict(self.config),
            "elapsed_seconds": elapsed,
            "events_per_second": len(events) / elapsed,
        }
        write_json(output / "detection_manifest.json", manifest)
        return DetectionResult(len(events), len(windows), elapsed, len(events) / elapsed, str(output), manifest)


def _process_rss_bytes() -> int | None:
    try:
        if platform.system() == "Windows":
            value = subprocess.check_output(
                ["powershell.exe", "-NoProfile", "-Command", f"(Get-Process -Id {os.getpid()}).WorkingSet64"],
                text=True, stderr=subprocess.DEVNULL, timeout=5,
            ).strip()
            return int(value)
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value * (1024 if platform.system() != "Darwin" else 1))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


class PartitionedCandidateWriter:
    """Compressed, rotated candidate writer with a bounded number of open handles."""

    def __init__(self, root: Path, rotate_bytes: int = 64 * 1024 * 1024, max_open: int = 12) -> None:
        self.root = root
        self.rotate_bytes = rotate_bytes
        self.max_open = max_open
        self.handles: OrderedDict[str, tuple[Any, int, int]] = OrderedDict()
        self.files: list[str] = []
        self.initialized_paths: set[Path] = set()

    @staticmethod
    def _safe(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:80] or "unknown"

    def _open(self, key: str, part: int) -> Any:
        date, source = key.split("|", 1)
        path = self.root / f"date={self._safe(date)}" / f"source_type={self._safe(source)}" / f"part-{part:05d}.jsonl.gz"
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "at" if path in self.initialized_paths else "wt"
        handle = gzip.open(path, mode, encoding="utf-8", compresslevel=4)
        self.initialized_paths.add(path)
        relative = str(path.relative_to(self.root.parent))
        if relative not in self.files:
            self.files.append(relative)
        return handle

    def write(self, row: dict[str, Any]) -> None:
        date = str(row["timestamp"])[:10]
        key = f"{date}|{row['source_type']}"
        if key in self.handles:
            handle, size, part = self.handles.pop(key)
        else:
            if len(self.handles) >= self.max_open:
                _, (old_handle, _, _) = self.handles.popitem(last=False)
                old_handle.close()
            part = 0
            handle = self._open(key, part)
            size = 0
        encoded = json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        if size >= self.rotate_bytes:
            handle.close()
            part += 1
            handle = self._open(key, part)
            size = 0
        handle.write(encoded)
        self.handles[key] = (handle, size + len(encoded.encode("utf-8")), part)

    def close(self) -> None:
        for handle, _, _ in self.handles.values():
            handle.close()
        self.handles.clear()


class ScalableDetectionEngine(DetectionEngine):
    """Two-pass detector whose state is bounded independently of total input size."""

    def run_roots(self, roots: list[str | Path], output_dir: str | Path, *, max_records: int = 0,
                  top_k: int = 20_000, sketch_width: int = 1 << 16,
                  variant: str = "full") -> DetectionResult:
        started = time.perf_counter()
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        sources, exclusions = discover_sources(roots)
        if not sources:
            raise ValueError("no supported unlabelled log sources discovered")
        catalog = [{"path": source.path, "member": source.member, "kind": source.kind, "size_bytes": source.size_bytes} for source in sources]
        catalog_hash = hashlib.sha256(json.dumps(catalog, sort_keys=True).encode()).hexdigest()

        baseline = StreamingFrequencyBaseline(sketch_width)
        pass1_stats = ReadStats()
        rss_samples = [_process_rss_bytes()]
        for index, event in enumerate(iter_all(sources, max_records=max_records, stats=pass1_stats), 1):
            baseline.update(event)
            if index % 100_000 == 0:
                rss_samples.append(_process_rss_bytes())
        if baseline.total == 0:
            raise ValueError("supported sources contained no parseable events")

        writer = PartitionedCandidateWriter(output / "candidates")
        heap: list[tuple[float, int, dict[str, Any]]] = []
        candidate_count = weak_hit_count = 0
        pass2_stats = ReadStats()
        source_types: set[str] = set()
        latest_timestamp = ""
        try:
            for sequence, event in enumerate(iter_all(sources, max_records=max_records, stats=pass2_stats), 1):
                row = self.score_event(event, baseline, variant)
                source_types.add(event.source_type)
                latest_timestamp = max(latest_timestamp, event.timestamp)
                if row["weak_rules"]:
                    weak_hit_count += 1
                score = float(row["risk_score"])
                if score < self.config.event_threshold:
                    continue
                candidate_count += 1
                writer.write(row)
                entry = (score, sequence, row)
                if len(heap) < top_k:
                    heapq.heappush(heap, entry)
                elif entry[:2] > heap[0][:2]:
                    heapq.heapreplace(heap, entry)
                if sequence % 100_000 == 0:
                    rss_samples.append(_process_rss_bytes())
        finally:
            writer.close()

        top_rows = self.dashboard_safe_rows(
            [entry[2] for entry in sorted(heap, key=lambda item: (item[0], item[1]), reverse=True)]
        )
        windows = self._windows(top_rows)
        investigations = self._investigations(windows)
        write_jsonl(output / "logs.jsonl", top_rows)
        write_json(output / "windows.json", windows)
        write_json(output / "findings.json", windows)
        write_json(output / "investigations.json", investigations)
        write_json(output / "weak_rules.json", self.supervisor.manifest())
        write_json(output / "source_catalog.json", catalog)
        write_json(output / "log_sources.json", [{
            "id": f"SRC-{index:03d}", "name": source_type, "path": "multi-source catalog",
            "kind": source_type, "status": "online", "size": f"{sum(item.size_bytes for item in sources)} B",
            "lastRead": latest_timestamp,
        } for index, source_type in enumerate(sorted(source_types), 1)])
        elapsed = max(time.perf_counter() - started, 1e-9)
        rss_values = [value for value in rss_samples if value is not None]
        manifest = {
            "status": "COMPLETED", "execution_mode": "bounded_memory_two_pass", "input_roots": [str(root) for root in roots],
            "source_count": len(sources), "source_catalog_sha256": catalog_hash,
            "unique_source_bytes": sum(source.size_bytes for source in sources), "input_count": baseline.total,
            "candidate_count": candidate_count, "retained_top_k": len(top_rows), "finding_count": len(windows),
            "weak_hit_count": weak_hit_count, "rejected_count": pass1_stats.rejected,
            "labels_accessed": False, "excluded_target_paths": sum("label" in value.lower() for value in exclusions),
            "excluded_binary_or_nonlog_paths": len(exclusions), "passes": 2, "max_records_per_pass": max_records,
            "memory_contract": {"event_batch_size": 1, "max_retained_candidates": top_k,
                                "count_min_sketch_bytes": baseline.fixed_state_bytes,
                                "state_grows_with_input": False},
            "peak_sampled_working_set_bytes": max(rss_values) if rss_values else None,
            "candidate_partitions": writer.files, "variant": variant, "elapsed_seconds": elapsed,
            "records_per_second_two_pass": (baseline.total * 2) / elapsed,
            "bytes_read_two_pass": pass1_stats.bytes_read + pass2_stats.bytes_read,
            "source_bytes_per_second_two_pass": (pass1_stats.bytes_read + pass2_stats.bytes_read) / elapsed,
        }
        write_json(output / "detection_manifest.json", manifest)
        write_json(output / "scale_report.json", manifest)
        return DetectionResult(baseline.total, len(windows), elapsed, (baseline.total * 2) / elapsed, str(output), manifest)

    def run_roots_online(self, roots: list[str | Path], output_dir: str | Path, *, max_records: int = 0,
                         top_k: int = 20_000, sketch_width: int = 1 << 16,
                         variant: str = "full") -> DetectionResult:
        """Single-pass online baseline for sustained ingestion throughput."""
        started = time.perf_counter()
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        sources, exclusions = discover_sources(roots)
        if not sources:
            raise ValueError("no supported unlabelled log sources discovered")
        catalog = [{"path": source.path, "member": source.member, "kind": source.kind, "size_bytes": source.size_bytes} for source in sources]
        baseline = StreamingFrequencyBaseline(sketch_width)
        stats = ReadStats()
        writer = PartitionedCandidateWriter(output / "candidates")
        heap: list[tuple[float, int, dict[str, Any]]] = []
        candidate_count = weak_hit_count = 0
        source_types: set[str] = set()
        latest_timestamp = ""
        rss_samples = [_process_rss_bytes()]
        try:
            for sequence, event in enumerate(iter_all(sources, max_records=max_records, stats=stats), 1):
                row = self.score_event(event, baseline, variant)
                baseline.update(event)
                source_types.add(event.source_type)
                latest_timestamp = max(latest_timestamp, event.timestamp)
                if row["weak_rules"]:
                    weak_hit_count += 1
                score = float(row["risk_score"])
                if score >= self.config.event_threshold:
                    candidate_count += 1
                    writer.write(row)
                    entry = (score, sequence, row)
                    if len(heap) < top_k:
                        heapq.heappush(heap, entry)
                    elif entry[:2] > heap[0][:2]:
                        heapq.heapreplace(heap, entry)
                if sequence % 100_000 == 0:
                    rss_samples.append(_process_rss_bytes())
        finally:
            writer.close()
        if baseline.total == 0:
            raise ValueError("supported sources contained no parseable events")
        top_rows = self.dashboard_safe_rows(
            [entry[2] for entry in sorted(heap, key=lambda item: (item[0], item[1]), reverse=True)]
        )
        windows = self._windows(top_rows)
        investigations = self._investigations(windows)
        write_jsonl(output / "logs.jsonl", top_rows)
        write_json(output / "windows.json", windows)
        write_json(output / "findings.json", windows)
        write_json(output / "investigations.json", investigations)
        write_json(output / "weak_rules.json", self.supervisor.manifest())
        write_json(output / "source_catalog.json", catalog)
        write_json(output / "log_sources.json", [{
            "id": f"SRC-{index:03d}", "name": source_type, "path": "multi-source catalog",
            "kind": source_type, "status": "online", "size": f"{sum(item.size_bytes for item in sources)} B",
            "lastRead": latest_timestamp,
        } for index, source_type in enumerate(sorted(source_types), 1)])
        elapsed = max(time.perf_counter() - started, 1e-9)
        rss_values = [value for value in rss_samples if value is not None]
        manifest = {
            "status": "COMPLETED", "execution_mode": "bounded_memory_online_single_pass",
            "input_roots": [str(root) for root in roots], "source_count": len(sources),
            "source_catalog_sha256": hashlib.sha256(json.dumps(catalog, sort_keys=True).encode()).hexdigest(),
            "unique_source_bytes": sum(source.size_bytes for source in sources), "input_count": baseline.total,
            "candidate_count": candidate_count, "retained_top_k": len(top_rows), "finding_count": len(windows),
            "weak_hit_count": weak_hit_count, "rejected_count": stats.rejected, "labels_accessed": False,
            "excluded_target_paths": sum("label" in value.lower() for value in exclusions),
            "excluded_binary_or_nonlog_paths": len(exclusions), "passes": 1, "max_records_per_pass": max_records,
            "memory_contract": {"event_batch_size": 1, "max_retained_candidates": top_k,
                                "count_min_sketch_bytes": baseline.fixed_state_bytes, "state_grows_with_input": False},
            "peak_sampled_working_set_bytes": max(rss_values) if rss_values else None,
            "candidate_partitions": writer.files, "variant": variant, "elapsed_seconds": elapsed,
            "records_per_second": baseline.total / elapsed, "bytes_read": stats.bytes_read,
            "source_bytes_per_second": stats.bytes_read / elapsed,
            "projected_decimal_tb_per_day": (stats.bytes_read / elapsed) * 86400 / 1_000_000_000_000,
        }
        write_json(output / "detection_manifest.json", manifest)
        write_json(output / "scale_report.json", manifest)
        return DetectionResult(baseline.total, len(windows), elapsed, baseline.total / elapsed, str(output), manifest)
