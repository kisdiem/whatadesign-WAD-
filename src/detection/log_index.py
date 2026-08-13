from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .sources import discover_sources, iter_all


SUSPICIOUS_PAYLOAD = re.compile(
    r"powershell|encodedcommand|frombase64|mimikatz|regsvr32|rundll32|certutil|invoke-expression",
    re.IGNORECASE,
)
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{48,}")
RANGE_SECONDS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
REPLAY_TIMEZONE = timezone(timedelta(hours=8))
REPLAY_PROFILE = "business-cycle-bursts-v2"


def safe_preview(message: str, limit: int = 768) -> str:
    """Create a UI-safe preview without persisting executable attack strings."""
    digest = hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest()
    if SUSPICIOUS_PAYLOAD.search(message):
        return f"Security payload quarantined; sha256={digest}; original_length={len(message)}"
    preview = LONG_TOKEN.sub("[LONG_TOKEN_REDACTED]", message[:limit])
    return preview.replace("\x00", "")


def _weighted_choice(weights: list[float], sample: int) -> int:
    """Map a stable 64-bit sample to a weighted categorical choice."""
    total = sum(weights)
    cursor = (sample / ((1 << 64) - 1)) * total
    for index, weight in enumerate(weights):
        cursor -= weight
        if cursor <= 0:
            return index
    return len(weights) - 1


def projected_timestamp(event_id: str, sequence: int, anchor: datetime) -> str:
    """Project an event onto a deterministic non-uniform 30-day replay."""
    digest = hashlib.blake2b(f"{event_id}|{sequence}".encode(), digest_size=32).digest()
    samples = [int.from_bytes(digest[index:index + 8], "big") for index in range(0, 32, 8)]
    local_anchor = anchor.astimezone(REPLAY_TIMEZONE)

    day_weights: list[float] = []
    incident_days = {1, 5, 12, 19, 26}
    quiet_days = {8, 15, 22}
    for age_day in range(30):
        date = local_anchor.date() - timedelta(days=age_day)
        weight = 0.48 if date.weekday() >= 5 else 1.0
        if age_day in incident_days:
            weight *= 2.8
        if age_day in quiet_days:
            weight *= 0.24
        day_weights.append(weight)
    age_day = _weighted_choice(day_weights, samples[0])

    hour_weights = [0.20] * 24
    for hour in range(7, 9):
        hour_weights[hour] = 1.15
    for hour in range(9, 12):
        hour_weights[hour] = 2.55
    for hour in range(12, 14):
        hour_weights[hour] = 1.45
    for hour in range(14, 19):
        hour_weights[hour] = 3.15
    for hour in range(19, 22):
        hour_weights[hour] = 0.78
    if age_day in incident_days:
        hour_weights[1] = 1.35
        hour_weights[2] = 1.65
        hour_weights[22] = 1.55
        hour_weights[23] = 1.25
    if age_day == 0:
        for hour in range(local_anchor.hour + 1, 24):
            hour_weights[hour] = 0.0
    hour = _weighted_choice(hour_weights, samples[1])

    minute_weights = [0.55] * 60
    for minute in range(5, 15):
        minute_weights[minute] = 2.10
    for minute in range(32, 38):
        minute_weights[minute] = 3.20
    for minute in range(48, 53):
        minute_weights[minute] = 1.75
    if age_day == 0 and hour == local_anchor.hour:
        for minute in range(local_anchor.minute + 1, 60):
            minute_weights[minute] = 0.0
    minute = _weighted_choice(minute_weights, samples[2])
    second = samples[3] % 60
    local_date = local_anchor.date() - timedelta(days=age_day)
    projected = datetime(
        local_date.year, local_date.month, local_date.day, hour, minute, second,
        tzinfo=REPLAY_TIMEZONE,
    )
    return projected.astimezone(timezone.utc).isoformat()


def build_log_index(
    roots: Iterable[str | Path],
    database_path: str | Path,
    *,
    max_records_per_root: int = 200_000,
) -> dict[str, Any]:
    target = Path(database_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    connection = sqlite3.connect(temporary)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.executescript(
        """
        CREATE TABLE events (
          sequence INTEGER PRIMARY KEY,
          event_id TEXT NOT NULL,
          timestamp TEXT NOT NULL,
          original_timestamp TEXT NOT NULL,
          source_type TEXT NOT NULL,
          action TEXT NOT NULL,
          preview TEXT NOT NULL,
          raw_log_ref TEXT NOT NULL,
          entities_json TEXT NOT NULL,
          search_text TEXT NOT NULL
        );
        CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
        CREATE INDEX idx_events_source_timestamp ON events(source_type, timestamp DESC);
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """
    )
    sequence = 0
    source_count = 0
    excluded_count = 0
    batch: list[tuple[Any, ...]] = []
    replay_anchor = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    try:
        for root in roots:
            sources, exclusions = discover_sources([root])
            source_count += len(sources)
            excluded_count += len(exclusions)
            for event in iter_all(sources, max_records=max_records_per_root):
                sequence += 1
                replay_time = projected_timestamp(event.event_id, sequence, replay_anchor)
                preview = safe_preview(event.message)
                entities = list(event.entities)
                search_text = " ".join((event.source_type, preview, event.source_file, *entities)).lower()
                batch.append((
                    sequence, event.event_id, replay_time, event.timestamp, event.source_type, event.source_type,
                    preview, f"{event.source_file}:{event.source_line}",
                    json.dumps(entities, ensure_ascii=False), search_text,
                ))
                if len(batch) >= 2_000:
                    connection.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
                    connection.commit()
                    batch.clear()
        if batch:
            connection.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
        source_types = [row[0] for row in connection.execute("SELECT DISTINCT source_type FROM events ORDER BY source_type")]
        metadata = {
            "indexed_records": sequence,
            "source_count": source_count,
            "excluded_count": excluded_count,
            "source_types": source_types,
            "max_records_per_root": max_records_per_root,
            "labels_accessed": False,
            "time_mode": "scenario_replay",
            "replay_profile": REPLAY_PROFILE,
            "replay_timezone": "Asia/Shanghai (+08:00)",
            "replay_anchor": replay_anchor.isoformat(),
        }
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            [(key, json.dumps(value, ensure_ascii=False)) for key, value in metadata.items()],
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    os.replace(temporary, target)
    return metadata


def index_metadata(database_path: str | Path) -> dict[str, Any]:
    with sqlite3.connect(f"file:{Path(database_path).resolve()}?mode=ro", uri=True) as connection:
        metadata = {key: json.loads(value) for key, value in connection.execute("SELECT key, value FROM metadata")}
        metadata["source_type_counts"] = {
            source: count for source, count in connection.execute(
                "SELECT source_type, COUNT(*) FROM events GROUP BY source_type ORDER BY COUNT(*) DESC"
            )
        }
        metadata["timeline"] = [
            {"time": day, "events": count}
            for day, count in connection.execute(
                "SELECT substr(timestamp, 1, 10), COUNT(*) FROM events GROUP BY substr(timestamp, 1, 10) ORDER BY 1"
            )
        ]
        return metadata


def index_overview(database_path: str | Path, time_range: str) -> dict[str, Any]:
    seconds = RANGE_SECONDS.get(time_range, RANGE_SECONDS["24h"])
    database = Path(database_path).resolve()
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        anchor_row = connection.execute("SELECT value FROM metadata WHERE key = 'replay_anchor'").fetchone()
        anchor_text = json.loads(anchor_row[0]) if anchor_row else connection.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
        anchor = datetime.fromisoformat(anchor_text)
        cutoff = (anchor - timedelta(seconds=seconds)).isoformat()
        total = int(connection.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (cutoff,)).fetchone()[0])
        source_counts = {
            source: count for source, count in connection.execute(
                "SELECT source_type, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY source_type ORDER BY COUNT(*) DESC",
                (cutoff,),
            )
        }
        if time_range == "1h":
            bucket = "substr(timestamp,1,15) || '0:00'"
        elif time_range == "24h":
            bucket = "substr(timestamp,1,13) || ':00:00'"
        else:
            bucket = "substr(timestamp,1,10)"
        timeline = [
            {"time": label, "events": count}
            for label, count in connection.execute(
                f"SELECT {bucket}, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY 1 ORDER BY 1", (cutoff,)
            )
        ]
    return {
        "time_range": time_range, "time_mode": "scenario_replay", "replay_profile": REPLAY_PROFILE,
        "replay_anchor": anchor_text,
        "event_count": total, "source_type_counts": source_counts, "timeline": timeline,
    }


def search_log_index(
    database_path: str | Path,
    *,
    entities: list[str],
    source_types: list[str],
    keywords: list[str],
    start_time: str | None,
    end_time: str | None,
    limit: int,
    offset: int,
    time_range: str | None = None,
) -> dict[str, Any]:
    where: list[str] = []
    parameters: list[Any] = []
    if source_types:
        placeholders = ",".join("?" for _ in source_types)
        where.append(f"source_type IN ({placeholders})")
        parameters.extend(source_types)
    for needle in [*entities, *keywords]:
        if needle.strip():
            where.append("search_text LIKE ?")
            parameters.append(f"%{needle.strip().lower()}%")
    if start_time:
        where.append("timestamp >= ?")
        parameters.append(start_time)
    if end_time:
        where.append("timestamp <= ?")
        parameters.append(end_time)
    if time_range in RANGE_SECONDS:
        with sqlite3.connect(f"file:{Path(database_path).resolve()}?mode=ro", uri=True) as anchor_connection:
            anchor_row = anchor_connection.execute("SELECT value FROM metadata WHERE key = 'replay_anchor'").fetchone()
            anchor_text = json.loads(anchor_row[0]) if anchor_row else anchor_connection.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
        cutoff = datetime.fromisoformat(anchor_text) - timedelta(seconds=RANGE_SECONDS[time_range])
        where.append("timestamp >= ?")
        parameters.append(cutoff.isoformat())
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    with sqlite3.connect(f"file:{Path(database_path).resolve()}?mode=ro", uri=True) as connection:
        total = int(connection.execute(f"SELECT COUNT(*) FROM events {clause}", parameters).fetchone()[0])
        rows = connection.execute(
            f"""SELECT event_id, timestamp, original_timestamp, source_type, action, preview, raw_log_ref, entities_json
                FROM events {clause} ORDER BY sequence DESC LIMIT ? OFFSET ?""",
            [*parameters, limit, offset],
        ).fetchall()
    events = [{
        "id": row[0], "event_id": row[0], "timestamp": row[1], "time": row[1],
        "original_timestamp": row[2], "source": row[3], "source_type": row[3], "labels": [row[4]],
        "text": row[5], "raw": row[5], "raw_log_ref": row[6],
        "entities": json.loads(row[7]), "indexed_event": True, "time_mode": "scenario_replay",
    } for row in rows]
    return {"count": total, "events": events, "offset": offset, "limit": limit, "has_more": offset + len(events) < total}
