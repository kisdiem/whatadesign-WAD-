from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


TIME_FMT = "%Y-%m-%d %H:%M:%S"


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, TIME_FMT)
    except ValueError:
        return None


def format_time(value: datetime | None, fallback: str | None = None) -> str:
    if value is None:
        return fallback or ""
    return value.strftime(TIME_FMT)


def shift_window_times(windows: list[dict[str, Any]], target_latest: datetime) -> list[dict[str, Any]]:
    latest = None
    for item in windows:
        current = parse_time(item.get("end"))
        if current and (latest is None or current > latest):
            latest = current
    if latest is None:
        return windows

    delta = target_latest - latest
    shifted: list[dict[str, Any]] = []
    for item in windows:
        updated = dict(item)
        for key in ("start", "end"):
            current = parse_time(updated.get(key))
            if current:
                updated[key] = format_time(current + delta)
        events = []
        for event in item.get("events", []):
            next_event = dict(event)
            current = parse_time(next_event.get("time"))
            if current:
                next_event["time"] = format_time(current + delta)
                next_event["raw"] = str(next_event.get("raw", "")).replace(current.strftime(TIME_FMT), next_event["time"])
            events.append(next_event)
        updated["events"] = events
        shifted.append(updated)
    return shifted


def shift_investigations(investigations: list[dict[str, Any]], windows_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    shifted: list[dict[str, Any]] = []
    for item in investigations:
        updated = dict(item)
        starts = [windows_by_id[window_id]["start"] for window_id in item.get("windowIds", []) if window_id in windows_by_id]
        updated["createdAt"] = min(starts) if starts else updated.get("createdAt", "")
        shifted.append(updated)
    return shifted


def main() -> None:
    parser = argparse.ArgumentParser(description="Export generated platform data into frontend mock extension JSON.")
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-file", required=True)
    parser.add_argument("--target-latest", default="2026-08-07 20:30:00")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_file = Path(args.output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    windows = json.loads((input_dir / "windows.json").read_text(encoding="utf-8"))
    investigations = json.loads((input_dir / "investigations.json").read_text(encoding="utf-8"))
    log_sources = json.loads((input_dir / "log_sources.json").read_text(encoding="utf-8"))
    knowledge_documents = json.loads((input_dir / "knowledge_documents.json").read_text(encoding="utf-8"))

    shifted_windows = shift_window_times(windows, datetime.strptime(args.target_latest, TIME_FMT))
    windows_by_id = {item["id"]: item for item in shifted_windows}
    shifted_investigations = shift_investigations(investigations, windows_by_id)

    payload = {
        "anomalyWindows": shifted_windows,
        "investigations": shifted_investigations,
        "logSources": log_sources,
        "knowledgeDocs": knowledge_documents,
    }
    output_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "status": "ok",
        "output_file": str(output_file),
        "anomalyWindows": len(shifted_windows),
        "investigations": len(shifted_investigations),
        "logSources": len(log_sources),
        "knowledgeDocs": len(knowledge_documents),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
