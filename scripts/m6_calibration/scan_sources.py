"""四源真实日志全量统计扫描（只读、流式、固定内存）。

数据源（只读，绝不修改）：
  D:\\CODE\\santos                —— AIT santos 场景（gather/*/logs 文本 + Suricata eve.json）
  D:\\CODE\\russellmitchell       —— AIT russellmitchell 场景（同上结构）
  D:\\CODE\\EVTX-ATTACK-SAMPLES-master —— EVTX 攻击样本（结构化 evtx_data.csv）
  D:\\CODE\\ait_ads               —— AIT ADS（ait_ads.zip 内逐行 JSON 流）

隔离纪律：
  - labels/、labels.csv、EVTX_Tactic 列、ATT&CK 元数据、PCAP、规则、环境目录一律不读取；
  - 输出只含频率统计先验（实体/模板/行为/时间分布），不含任何标签或原始日志内容。

用法：
  python scripts/m6_calibration/scan_sources.py [--max-lines N] [--out outputs/m6_calibration/baseline.json]
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import multiprocessing as mp
import os
import re
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _scoring import (  # noqa: E402
    TIME_RE,
    clamp,
    entity_key,
    extract_entities,
    json_dump,
    serialize_counter,
    source_kind_from_name,
    template_fingerprint,
    weak_supervision,
)

SOURCES = [
    Path(r"D:\CODE\santos"),
    Path(r"D:\CODE\russellmitchell"),
    Path(r"D:\CODE\EVTX-ATTACK-SAMPLES-master"),
    Path(r"D:\CODE\ait_ads"),
]

# 排除的路径片段（目录或文件名命中即跳过，不读取）。
EXCLUDE_SEGMENTS = [
    "labels", "rules", "processing", "environment", "configs", "provisioning",
    "EVTX_ATT&CK_Metadata", "AutomatedTestingTools", "__pycache__", ".vscode",
    "model", "templates", "pam.d", "ssh", "cron", "sudoers", "audisp",
]
# 排除的扩展名（任何命中即跳过）。
EXCLUDE_SUFFIXES = {
    ".pcap", ".pcapng", ".evtx", ".etl", ".py", ".pyc", ".md", ".yml", ".yaml",
    ".j2", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".html", ".ipynb", ".conf",
    ".cfg", ".rules", ".map", ".txt", ".sh", ".json", ".lock", ".crt", ".key",
    ".pem", ".zip",
}
# gather 日志目录下仍可能出现的 JSON（eve.json 逐行 JSON 流）。
ALLOWED_JSON = {"eve.json"}


class Stats:
    def __init__(self) -> None:
        self.total_lines = 0
        self.total_bytes = 0
        self.files_scanned = 0
        self.files_excluded = 0
        self.entity_freq: dict[str, Counter[str]] = {kind: Counter() for kind in ("user", "host", "ip", "process")}
        self.template_freq: Counter[str] = Counter()
        self.weak_hist: Counter[int] = Counter()
        self.reason_freq: Counter[str] = Counter()
        self.source_kind: Counter[str] = Counter()
        self.hour_hist: Counter[str] = Counter()
        self.evtx_event_id: Counter[str] = Counter()
        self.labels_accessed = False

    def note_line(self, line: str, payload: dict[str, Any] | None, source_kind: str) -> None:
        text = line.rstrip("\r\n")
        if not text:
            return
        self.total_lines += 1
        self.total_bytes += len(text.encode("utf-8", "replace"))
        weak_score, reasons = weak_supervision(text)
        entities = extract_entities(text, payload)
        for entity_type, values in entities.items():
            for value in values:
                self.entity_freq[entity_type][value] += 1
        self.template_freq[template_fingerprint(text)] += 1
        self.weak_hist[round(weak_score * 10)] += 1
        for reason in reasons:
            self.reason_freq[reason] += 1
        self.source_kind[source_kind] += 1
        match = TIME_RE.search(text)
        if match:
            self.hour_hist[match.group(0)[:13]] += 1


def _iter_text_log(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    """普通文本日志：逐行产出 (raw_line, None)。"""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line, None


def _iter_json_log(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    """逐行 JSON 流（Suricata eve.json / AIT 的 aminer/wazuh JSONL）。"""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                yield line, None
                continue
            yield json.dumps(payload, ensure_ascii=False), payload


def _evtx_synthetic_row(row: dict[str, str]) -> tuple[str, dict[str, Any]]:
    """EVTX CSV 行 → 合成文本 + payload。EVTX_Tactic 列绝不读取。"""
    parts = []
    for key in ("SystemTime", "EventID", "ProviderName", "SubjectUserName", "TargetUserName",
                "IpAddress", "SourceAddress", "DestinationIp", "CommandLine", "ProcessName",
                "NewProcessName", "SourceHostname", "DestinationHostname", "WorkstationName"):
        value = row.get(key)
        if value and value not in ("-", "NULL"):
            parts.append(f"{key}={value}")
    text = " ".join(parts)
    return text, dict(row)


def _iter_evtx_csv(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            event_id = str(row.get("EventID", "") or "")
            yield event_id, None


def _iter_zip_json(zip_path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.namelist():
            if not member.lower().endswith(".json"):
                continue
            with archive.open(member) as raw:
                handle = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        yield line, None
                        continue
                    yield json.dumps(payload, ensure_ascii=False), payload


def _iter_log_file(path: Path) -> Iterator[tuple[str, dict[str, Any] | None]]:
    name = path.name.lower()
    if name == "eve.json":
        yield from _iter_json_log(path)
    else:
        yield from _iter_text_log(path)


def _walk_source(root: Path, stats: Stats, max_lines: int) -> None:
    # santos / russellmitchell：只扫描 gather/*/logs/ 下的日志文件。
    gather = root / "gather"
    if gather.exists():
        for host_dir in sorted(gather.iterdir()):
            logs = host_dir / "logs"
            if not logs.exists():
                continue
            for path in sorted(logs.rglob("*")):
                if not path.is_file():
                    continue
                if _should_exclude(path):
                    stats.files_excluded += 1
                    continue
                if stats.total_lines >= max_lines:
                    return
                kind = source_kind_from_name(str(path), path.name)
                stats.files_scanned += 1
                for line, payload in _iter_log_file(path):
                    stats.note_line(line, payload, kind)
                    if stats.total_lines >= max_lines:
                        return
    # EVTX：只读 evtx_data.csv 的事件 ID 统计（用于模板/事件稀有度先验）。
    csv_path = root / "evtx_data.csv"
    if csv_path.exists():
        stats.files_scanned += 1
        for event_id, _ in _iter_evtx_csv(csv_path):
            stats.evtx_event_id[event_id] += 1
            stats.source_kind["evtx"] += 1
            stats.total_lines += 1
            if stats.total_lines >= max_lines:
                return
    # AIT ADS：压缩包内逐行 JSON。
    zip_path = root / "ait_ads.zip"
    if zip_path.exists():
        stats.files_scanned += 1
        for line, payload in _iter_zip_json(zip_path):
            kind = source_kind_from_name(zip_path.name, zip_path.name)
            stats.note_line(line, payload, kind)
            if stats.total_lines >= max_lines:
                return


def _should_exclude(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    for segment in EXCLUDE_SEGMENTS:
        if segment.lower() in parts:
            return True
    if path.suffix.lower() in EXCLUDE_SUFFIXES:
        return True
    if path.name.lower() not in ALLOWED_JSON and path.suffix.lower() == ".json":
        return True
    return False


# ---- 多进程并行扫描（按 gather/*/logs 主机目录 + EVTX CSV + ADS ZIP 分片）----


def _collect_tasks() -> list[tuple[str, Path]]:
    tasks: list[tuple[str, Path]] = []
    for root in SOURCES:
        if not root.exists():
            continue
        gather = root / "gather"
        if gather.exists():
            for host_dir in sorted(gather.iterdir()):
                logs = host_dir / "logs"
                if logs.exists():
                    tasks.append(("logs_dir", logs))
        csv_path = root / "evtx_data.csv"
        if csv_path.exists():
            tasks.append(("evtx_csv", csv_path))
        zip_path = root / "ait_ads.zip"
        if zip_path.exists():
            tasks.append(("zip_json", zip_path))
    return tasks


def _run_task(task: tuple[str, Path]) -> Stats:
    kind, path = task
    stats = Stats()
    if kind == "logs_dir":
        for entry in sorted(path.rglob("*")):
            if not entry.is_file():
                continue
            if _should_exclude(entry):
                stats.files_excluded += 1
                continue
            stats.files_scanned += 1
            source_kind = source_kind_from_name(str(entry), entry.name)
            for line, payload in _iter_log_file(entry):
                stats.note_line(line, payload, source_kind)
    elif kind == "evtx_csv":
        stats.files_scanned += 1
        for event_id, _ in _iter_evtx_csv(path):
            stats.evtx_event_id[event_id] += 1
            stats.source_kind["evtx"] += 1
            stats.total_lines += 1
    elif kind == "zip_json":
        stats.files_scanned += 1
        source_kind = source_kind_from_name(path.name, path.name)
        for line, payload in _iter_zip_json(path):
            stats.note_line(line, payload, source_kind)
    return stats


def _merge_stats(results: list[Stats]) -> Stats:
    merged = Stats()
    for stats in results:
        merged.total_lines += stats.total_lines
        merged.total_bytes += stats.total_bytes
        merged.files_scanned += stats.files_scanned
        merged.files_excluded += stats.files_excluded
        for kind in merged.entity_freq:
            merged.entity_freq[kind].update(stats.entity_freq[kind])
        merged.template_freq.update(stats.template_freq)
        merged.weak_hist.update(stats.weak_hist)
        merged.reason_freq.update(stats.reason_freq)
        merged.source_kind.update(stats.source_kind)
        merged.hour_hist.update(stats.hour_hist)
        merged.evtx_event_id.update(stats.evtx_event_id)
    return merged


def _scan_parallel(workers: int) -> Stats:
    tasks = _collect_tasks()
    print(f"[parallel] workers={workers} tasks={len(tasks)}")
    with mp.Pool(processes=workers) as pool:
        results = pool.map(_run_task, tasks)
    return _merge_stats(results)


def main() -> None:
    parser = argparse.ArgumentParser(description="四源真实日志全量统计扫描")
    parser.add_argument("--max-lines", type=int, default=0, help="调试用：最多处理行数，0 表示全量（全量走多进程并行）")
    parser.add_argument("--workers", type=int, default=mp.cpu_count(), help="并行 worker 数，默认等于 CPU 核数")
    parser.add_argument("--out", type=str, default=str(ROOT / "outputs/m6_calibration/baseline.json"))
    args = parser.parse_args()

    stats = Stats()
    started = time.perf_counter()
    if args.max_lines and args.max_lines > 0:
        # 调试路径：单线程顺序扫描（保证 max-lines 全局截断语义）。
        max_lines = args.max_lines
        for root in SOURCES:
            if not root.exists():
                print(f"[skip] 数据源不存在: {root}", file=sys.stderr)
                continue
            print(f"[scan] {root}")
            _walk_source(root, stats, max_lines)
            if stats.total_lines >= max_lines:
                print(f"[limit] 达到行数上限 {max_lines}，提前结束", file=sys.stderr)
                break
    else:
        stats = _scan_parallel(args.workers)

    elapsed = round(time.perf_counter() - started, 2)
    total_entities = sum(sum(counter.values()) for counter in stats.entity_freq.values())
    baseline = {
        "schema_version": "m6_calibration_v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sources": [str(path) for path in SOURCES],
        "scope": "read_only_statistical_calibration",
        "labels_accessed": False,
        "labels_audit": {
            "explicit_exclusions": EXCLUDE_SEGMENTS,
            "excluded_file_count": stats.files_excluded,
            "evtx_tactic_column_never_read": True,
        },
        "counts": {
            "lines_scanned": stats.total_lines,
            "bytes_scanned": stats.total_bytes,
            "files_scanned": stats.files_scanned,
            "entity_occurrences": total_entities,
        },
        "elapsed_seconds": elapsed,
        "distributions": {
            "source_kind": dict(stats.source_kind.most_common()),
            "entity_frequency": {kind: serialize_counter(counter) for kind, counter in stats.entity_freq.items()},
            "template_frequency": serialize_counter(stats.template_freq, limit=80000),
            "weak_score_histogram": {str(key): value for key, value in sorted(stats.weak_hist.items())},
            "weak_reason_frequency": dict(stats.reason_freq.most_common()),
            "hour_histogram": dict(stats.hour_hist.most_common()),
            "evtx_event_id_frequency": dict(stats.evtx_event_id.most_common()),
        },
    }
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    json_dump(str(output), baseline)
    print(json.dumps({
        "output": str(output),
        "lines": stats.total_lines,
        "bytes": stats.total_bytes,
        "elapsed_seconds": elapsed,
        "labels_accessed": False,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
