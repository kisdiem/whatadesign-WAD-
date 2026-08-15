"""Build traceable, human-scale frontend replay packages from AIT v2 logs.

The package is deliberately a UI demonstration dataset.  It preserves source
timestamps and messages, never reads the AIT labels, and marks all threat
levels as analyst-curated projections rather than model execution results.
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1] / "frontend" / "public" / "demo-data"
SOURCE = Path(r"E:\shaw.zip")
PREFIX = "gather/monitoring/logs/logstash/intranet-server/"
LONG_START = datetime(2022, 1, 24, 13, 30, tzinfo=timezone.utc)
LONG_END = LONG_START + timedelta(days=7)
SHORT_START = datetime(2022, 1, 24, 13, 30, tzinfo=timezone.utc)
SHORT_END = SHORT_START + timedelta(minutes=30)
USER_RE = re.compile(r"(?:for user |for |user=|user )([a-z_][a-z0-9_-]{1,31})", re.I)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def compact_message(row: dict[str, Any]) -> str:
    if isinstance(row.get("message"), str):
        return row["message"]
    event = row.get("event", {})
    metricset = row.get("metricset", {})
    network = row.get("system", {}).get("network", {})
    if event.get("dataset") == "system.network":
        inbound = network.get("in", {})
        outbound = network.get("out", {})
        return (
            f"metricbeat system.network interface={network.get('name', 'unknown')} "
            f"in_bytes={inbound.get('bytes', 0)} out_bytes={outbound.get('bytes', 0)} "
            f"period_ms={metricset.get('period', 0)}"
        )
    return json.dumps(row, ensure_ascii=False, sort_keys=True)[:1000]


def read_source_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with zipfile.ZipFile(SOURCE) as archive:
        members = sorted(
            name for name in archive.namelist()
            if name.startswith(PREFIX)
            and re.search(r"2022-01-(2[4-9]|3[01])-system\.(auth|network|syslog)\.log$", name)
        )
        for member in members:
            for line_number, line in enumerate(archive.read(member).decode("utf-8", "replace").splitlines(), start=1):
                try:
                    row = json.loads(line)
                    timestamp = datetime.fromisoformat(row["@timestamp"].replace("Z", "+00:00"))
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
                if LONG_START <= timestamp < LONG_END:
                    events.append({
                        "timestamp": timestamp,
                        "source_file": member,
                        "source_line": line_number,
                        "raw": compact_message(row),
                        "dataset": row.get("event", {}).get("dataset", "unknown"),
                        "host": row.get("host", {}).get("name", "intranet-server"),
                    })
    return sorted(events, key=lambda item: (item["timestamp"], item["source_file"], item["source_line"]))


def entities_for(event_id: str, event: dict[str, Any]) -> list[dict[str, Any]]:
    output = [{"event_id": event_id, "entity_type": "host", "canonical_value": event["host"], "role": "host", "confidence": 0.98}]
    users = {match.group(1).lower() for match in USER_RE.finditer(event["raw"])}
    for user in sorted(users):
        role = "actor" if " by " in event["raw"].lower() else "target_user"
        output.append({"event_id": event_id, "entity_type": "user", "canonical_value": user, "role": role, "confidence": 0.9})
    return output


def projection(event_id: str, timestamp: datetime, raw: str) -> dict[str, Any]:
    text = raw.lower()
    score, level, reason = 0.04, "info", "常规系统或网络遥测"
    if "failed password" in text or "authentication failure" in text:
        score, level, reason = 0.52, "medium", "出现认证失败，需要结合后续尝试核查"
    if "sudo" in text or "su for" in text:
        score, level, reason = 0.61, "medium", "出现权限上下文切换，需要确认操作来源"
    if "useradd" in text or "add 'ait'" in text:
        score, level, reason = 0.77, "high", "出现账户创建或组成员变更"
    if "www-data" in text and ("su for" in text or "sudo" in text):
        score, level, reason = 0.88, "high", "Web 服务账户进入交互式或高权限上下文"
    if "session opened for user root" in text:
        score, level, reason = 0.16, "low", "root 定时任务会话，保留为上下文"
    return {
        "event_id": event_id, "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "threat_level": level, "alert_level": level, "final_score": score,
        "raw_event_score": score, "micro_window_score": score,
        "macro_window_score": score, "long_horizon_score": score,
        "reasons": [reason],
        "module_projection": {
            "M1": "演示：单事件语义已整理", "M2": "演示：实体角色已从事实字段提取",
            "M3": "演示：历史上下文可查询", "M4": "演示：当前事件多尺度上下文评分",
            "M5": "演示：未确认跨时段攻击链", "M6": "演示：人工整理告警级别",
        },
        "provenance": {"kind": "analyst_curated_demo_projection", "model_execution": False, "synthetic_scores": True, "formal_evaluation": False},
    }


def build_package(name: str, source_events: Iterable[dict[str, Any]], start: datetime, end: datetime) -> None:
    selected = [event for event in source_events if start <= event["timestamp"] < end]
    if name == "Short" and len(selected) < 300:
        raise RuntimeError(f"Short replay has only {len(selected)} events; choose a denser 30-minute interval")
    if name == "Long" and len(selected) < 20_000:
        raise RuntimeError(f"Long replay has only {len(selected)} events; source selection is insufficient")
    target = ROOT / name
    timeline, detections, entities = [], [], []
    high_events: list[str] = []
    for index, event in enumerate(selected, start=1):
        event_id = f"{name.upper()}-{index:06d}"
        projected = projection(event_id, event["timestamp"], event["raw"])
        related = entities_for(event_id, event)
        timeline.append({
            "event_id": event_id, "timestamp": projected["timestamp"], "source_file": event["source_file"],
            "source_line": event["source_line"], "raw": event["raw"], "facts_only": True,
            "system_projection": projected, "related_entities": related, "outgoing_relations": [], "incoming_relations": [],
        })
        detections.append(projected)
        entities.extend(related)
        if projected["threat_level"] in {"high", "critical"}:
            high_events.append(event_id)

    chain_ids = high_events[:6]
    relations = [
        {"source_event_id": left, "target_event_id": right, "relation_type": "temporal_review_candidate", "confidence": 0.55,
         "evidence": {"reason": "按时间排序的高风险人工复核候选", "formal_model_relation": False}}
        for left, right in zip(chain_ids, chain_ids[1:])
    ]
    chain = {
        "chain_id": f"{name.upper()}-CANDIDATE-001", "status": "candidate", "claim_type": "analyst_curated_replay",
        "steps": ([{"sequence": index + 1, "label": "需要人工复核的高风险事件", "evidence_event_ids": [event_id]} for index, event_id in enumerate(chain_ids)]),
        "limitations": ["这是基于原始日志的演示回放，不是模型预测。", "候选关联只供人工调查，不是攻击事实。", "未读取 AIT 标签或场景真值。"],
    }
    counts = Counter(item["threat_level"] for item in detections)
    events_log = "\n".join(item["raw"] for item in timeline) + "\n"
    members = sorted({item["source_file"] for item in selected})
    write_json(target / "timeline.json", timeline)
    write_json(target / "events.json", [{key: item[key] for key in ("event_id", "timestamp", "source_file", "source_line", "raw", "facts_only")} for item in timeline])
    write_json(target / "detection_results.json", detections)
    write_json(target / "entities.json", entities)
    write_json(target / "event_relations.json", relations)
    write_json(target / "attack_chain.json", chain)
    write_json(target / "summary.json", {
        "dataset_id": name, "kind": "demo_system_projection", "model_execution": False, "synthetic_scores": True,
        "formal_evaluation": False, "event_count": len(timeline), "threat_level_counts": dict(counts),
        "time_range": f"{start.isoformat().replace('+00:00', 'Z')}/{end.isoformat().replace('+00:00', 'Z')}",
        "candidate_chain_id": chain["chain_id"], "candidate_chain_status": "candidate",
    })
    write_json(target / "demo_projection.json", {
        "dataset_id": name, "kind": "demo_system_projection", "model_execution": False, "synthetic_scores": True,
        "formal_evaluation": False, "labels_read": False, "event_count": len(timeline),
        "threat_level_policy": {"info": "常规系统或网络遥测", "low": "保留为上下文的低风险事件", "medium": "需要结合上下文核查", "high": "需要人工优先复核"},
    })
    write_json(target / "manifest.json", {
        "dataset_id": name, "kind": "demo_replay", "source_archive": SOURCE.name, "source_members": members,
        "source_slice": f"{start.isoformat().replace('+00:00', 'Z')}/{end.isoformat().replace('+00:00', 'Z')}",
        "event_count": len(timeline), "sha256_events_log": hashlib.sha256(events_log.encode()).hexdigest(),
        "contains_labels": False, "contains_facts_json": False, "preserves_real_source_timestamps": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })


def main() -> None:
    events = read_source_events()
    build_package("Long", events, LONG_START, LONG_END)
    build_package("Short", events, SHORT_START, SHORT_END)


if __name__ == "__main__":
    main()
