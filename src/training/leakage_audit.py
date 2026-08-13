from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class AuditResult:
    passed: bool
    findings: tuple[str, ...]


def audit_records(records: Iterable[dict[str, Any]], *, target_names: tuple[str, ...] = ("ait", "ait_lds", "ait_ads")) -> AuditResult:
    findings: list[str] = []
    seen: set[str] = set()
    for row in records:
        record_id = str(row.get("record_id", ""))
        if record_id and record_id in seen:
            findings.append(f"duplicate_record_id:{record_id}")
        seen.add(record_id)
        source = str(row.get("source_dataset", "")).lower()
        path = str(row.get("source_file", "")).lower()
        if any(name in source or name in path for name in target_names):
            findings.append(f"target_access:{record_id or source}")
        if row.get("split") == "test" and row.get("label_used_for_training"):
            findings.append(f"test_label_training:{record_id}")
    return AuditResult(not findings, tuple(findings))
