from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .models import RepositoryResult
from .project_knowledge import search_project_knowledge


class SecurityRepository(ABC):
    @abstractmethod
    async def get_finding(self, finding_id: str) -> RepositoryResult: ...

    @abstractmethod
    async def search_logs(self, *, entities: list[str], source_types: list[str], keywords: list[str], start_time: str | None, end_time: str | None, limit: int) -> RepositoryResult: ...

    @abstractmethod
    async def get_entity(self, entity_id: str) -> RepositoryResult: ...

    @abstractmethod
    async def get_entity_history(self, entity_id: str, time_range: str) -> RepositoryResult: ...

    @abstractmethod
    async def get_baseline(self, entity_id: str, time_range: str) -> RepositoryResult: ...

    @abstractmethod
    async def get_attack_timeline(self, *, finding_ids: list[str], entity_ids: list[str], time_range: str) -> RepositoryResult: ...

    @abstractmethod
    async def get_investigation(self, investigation_id: str) -> RepositoryResult: ...

    @abstractmethod
    async def search_knowledge(self, query: str, top_k: int, scope: list[str]) -> RepositoryResult: ...


class UnavailableRepository(SecurityRepository):
    def _fail(self) -> RepositoryResult:
        return RepositoryResult(ok=False, message="安全数据仓库尚未配置，无法读取真实环境数据。")

    async def get_finding(self, finding_id: str) -> RepositoryResult: return self._fail()
    async def search_logs(self, **kwargs: Any) -> RepositoryResult: return self._fail()
    async def get_entity(self, entity_id: str) -> RepositoryResult: return self._fail()
    async def get_entity_history(self, entity_id: str, time_range: str) -> RepositoryResult: return self._fail()
    async def get_baseline(self, entity_id: str, time_range: str) -> RepositoryResult: return self._fail()
    async def get_attack_timeline(self, **kwargs: Any) -> RepositoryResult: return self._fail()
    async def get_investigation(self, investigation_id: str) -> RepositoryResult: return self._fail()
    async def search_knowledge(self, query: str, top_k: int, scope: list[str]) -> RepositoryResult:
        selected = search_project_knowledge(query, top_k=top_k, scope=scope)
        refs = [str(document.get("document_id", "")) for document in selected]
        return RepositoryResult(
            ok=bool(selected),
            data={"documents": selected, "retrieval": "hybrid_lexical_cjk_v1"},
            message="ok" if selected else "项目知识库中未检索到相关内容。",
            evidence_refs=[ref for ref in refs if ref],
        )


class JsonDirectoryRepository(SecurityRepository):
    """Read-only adapter for exported WAD security state.

    Expected optional files under WAD_AGENT_DATA_DIR:
      findings.json, entities.json, investigations.json, baselines.json,
      knowledge.json and logs.jsonl.
    This adapter never executes SQL, shell commands or arbitrary HTTP requests.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _json(self, name: str, default: Any) -> Any:
        path = self.root / name
        if not path.exists():
            return default
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _logs(self) -> list[dict[str, Any]]:
        path = self.root / "logs.jsonl"
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    @staticmethod
    def _find(items: Any, key: str, value: str) -> dict[str, Any] | None:
        if isinstance(items, dict):
            item = items.get(value)
            return item if isinstance(item, dict) else None
        for item in items if isinstance(items, list) else []:
            if str(item.get(key, "")) == value:
                return item
        return None

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace(" ", "T"))
        except ValueError:
            return None

    @classmethod
    def _sort_by_recent(cls, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            rows,
            key=lambda row: (
                cls._parse_timestamp(str(row.get("time", row.get("timestamp", "")))) or datetime.min,
                str(row.get("event_id", row.get("id", ""))),
            ),
            reverse=True,
        )

    @staticmethod
    def _range_delta(value: str | None) -> timedelta | None:
        if not value:
            return None
        if value.endswith("h") and value[:-1].isdigit():
            return timedelta(hours=int(value[:-1]))
        if value.endswith("d") and value[:-1].isdigit():
            return timedelta(days=int(value[:-1]))
        return None

    async def get_finding(self, finding_id: str) -> RepositoryResult:
        item = self._find(self._json("findings.json", []), "finding_id", finding_id) or self._find(self._json("findings.json", []), "id", finding_id)
        if not item:
            return RepositoryResult(ok=False, message=f"未找到 Finding {finding_id}。")
        refs = list(dict.fromkeys([finding_id, *item.get("evidence_refs", [])]))
        return RepositoryResult(ok=True, data=item, evidence_refs=refs)

    async def search_logs(self, *, entities: list[str], source_types: list[str], keywords: list[str], start_time: str | None, end_time: str | None, limit: int) -> RepositoryResult:
        limit = max(1, min(limit, 200))
        rows = self._logs()
        needles = [x.lower() for x in [*entities, *keywords] if x]
        sources = {x.lower() for x in source_types if x}
        start_bound = self._parse_timestamp(start_time)
        end_bound = self._parse_timestamp(end_time)
        matched: list[dict[str, Any]] = []
        for row in rows:
            text = json.dumps(row, ensure_ascii=False).lower()
            if needles and not all(value in text for value in needles):
                continue
            source = str(row.get("source", row.get("source_type", ""))).lower()
            if sources and source not in sources:
                continue
            timestamp = str(row.get("time", row.get("timestamp", "")))
            parsed_timestamp = self._parse_timestamp(timestamp)
            if start_bound and parsed_timestamp and parsed_timestamp < start_bound:
                continue
            if end_bound and parsed_timestamp and parsed_timestamp > end_bound:
                continue
            if start_time and not parsed_timestamp and timestamp and timestamp < start_time:
                continue
            if end_time and not parsed_timestamp and timestamp and timestamp > end_time:
                continue
            matched.append(row)
        matched = self._sort_by_recent(matched)[:limit]
        refs = [str(row.get("event_id", row.get("id", ""))) for row in matched]
        refs = [ref for ref in refs if ref]
        return RepositoryResult(ok=True, data={"count": len(matched), "events": matched}, evidence_refs=refs)

    async def get_entity(self, entity_id: str) -> RepositoryResult:
        item = self._find(self._json("entities.json", []), "entity_id", entity_id) or self._find(self._json("entities.json", []), "id", entity_id)
        if not item:
            return RepositoryResult(ok=False, message=f"未找到实体 {entity_id}。")
        return RepositoryResult(ok=True, data=item, evidence_refs=[entity_id])

    async def get_entity_history(self, entity_id: str, time_range: str) -> RepositoryResult:
        rows = [
            row
            for row in self._logs()
            if entity_id.lower() in json.dumps(row, ensure_ascii=False).lower()
        ]
        rows = self._sort_by_recent(rows)
        delta = self._range_delta(time_range)
        latest_timestamp = None
        if rows:
            latest_timestamp = self._parse_timestamp(str(rows[0].get("time", rows[0].get("timestamp", ""))))
        if delta and latest_timestamp:
            cutoff = latest_timestamp - delta
            rows = [
                row
                for row in rows
                if (self._parse_timestamp(str(row.get("time", row.get("timestamp", "")))) or datetime.min) >= cutoff
            ]
        rows = rows[:200]
        refs = [str(row.get("event_id", row.get("id", ""))) for row in rows]
        return RepositoryResult(
            ok=True,
            data={"entity_id": entity_id, "range": time_range, "count": len(rows), "events": rows},
            evidence_refs=[ref for ref in refs if ref],
        )

    async def get_baseline(self, entity_id: str, time_range: str) -> RepositoryResult:
        baselines = self._json("baselines.json", {})
        item = self._find(baselines, "entity_id", entity_id)
        if not item:
            return RepositoryResult(ok=False, message=f"实体 {entity_id} 暂无历史基线。")
        return RepositoryResult(ok=True, data={"range": time_range, **item}, evidence_refs=[f"baseline:{entity_id}"])

    async def get_attack_timeline(self, *, finding_ids: list[str], entity_ids: list[str], time_range: str) -> RepositoryResult:
        rows = self._logs()
        needles = [x.lower() for x in [*finding_ids, *entity_ids] if x]
        matched = [row for row in rows if not needles or any(value in json.dumps(row, ensure_ascii=False).lower() for value in needles)]
        matched = self._sort_by_recent(matched)
        delta = self._range_delta(time_range)
        latest_timestamp = None
        if matched:
            latest_timestamp = self._parse_timestamp(str(matched[0].get("time", matched[0].get("timestamp", ""))))
        if delta and latest_timestamp:
            cutoff = latest_timestamp - delta
            matched = [
                row
                for row in matched
                if (self._parse_timestamp(str(row.get("time", row.get("timestamp", "")))) or datetime.min) >= cutoff
            ]
        matched = matched[:200]
        refs = [str(row.get("event_id", row.get("id", ""))) for row in matched]
        return RepositoryResult(ok=True, data={"range": time_range, "events": matched}, evidence_refs=[x for x in refs if x])

    async def get_investigation(self, investigation_id: str) -> RepositoryResult:
        item = self._find(self._json("investigations.json", []), "investigation_id", investigation_id) or self._find(self._json("investigations.json", []), "id", investigation_id)
        if not item:
            return RepositoryResult(ok=False, message=f"未找到 Investigation {investigation_id}。")
        refs = [investigation_id, *item.get("finding_ids", item.get("windowIds", []))]
        return RepositoryResult(ok=True, data=item, evidence_refs=list(dict.fromkeys(refs)))

    async def search_knowledge(self, query: str, top_k: int, scope: list[str]) -> RepositoryResult:
        docs = self._json("knowledge.json", [])
        external = docs if isinstance(docs, list) else []
        selected = search_project_knowledge(
            query,
            top_k=top_k,
            scope=scope,
            external=external,
        )
        refs = [str(doc.get("document_id", doc.get("id", ""))) for doc in selected]
        return RepositoryResult(
            ok=bool(selected),
            data={"documents": selected, "retrieval": "hybrid_lexical_cjk_v1"},
            message="ok" if selected else "知识库中未检索到相关内容。",
            evidence_refs=[ref for ref in refs if ref],
        )


class DemoRepository(JsonDirectoryRepository):
    """Explicit demo-only repository. Enabled only with WAD_AGENT_USE_MOCKS=true."""

    def __init__(self):
        super().__init__(".")
        self.finding = {
            "finding_id": "WIN-20260809-1422",
            "title": "敏感文件访问与外联",
            "risk_score": 94,
            "entities": ["Alice", "HOST-18", "archive.exe", "91.92.18.4"],
            "summary": "敏感文件访问后出现压缩与异常外联。",
            "evidence_refs": ["EVT-10418", "EVT-10424", "EVT-10431"],
        }

    async def get_finding(self, finding_id: str) -> RepositoryResult:
        if finding_id != self.finding["finding_id"]:
            return RepositoryResult(ok=False, message=f"Demo 中没有 {finding_id}。")
        return RepositoryResult(ok=True, data=self.finding, evidence_refs=[finding_id, *self.finding["evidence_refs"]])

    async def search_logs(self, **kwargs: Any) -> RepositoryResult:
        events = [
            {"event_id": "EVT-10418", "time": "14:22:11", "host": "HOST-18", "action": "FILE_READ", "process": "archive.exe"},
            {"event_id": "EVT-10424", "time": "14:24:02", "host": "HOST-18", "action": "PROCESS_BURST", "process": "archive.exe"},
            {"event_id": "EVT-10431", "time": "14:27:36", "host": "HOST-18", "action": "NETWORK_BURST", "ip": "91.92.18.4"},
        ]
        return RepositoryResult(ok=True, data={"count": len(events), "events": events}, evidence_refs=[e["event_id"] for e in events])

    async def get_entity(self, entity_id: str) -> RepositoryResult:
        return RepositoryResult(ok=True, data={"entity_id": entity_id, "risk": 94 if entity_id == "HOST-18" else 55}, evidence_refs=[entity_id])

    async def get_entity_history(self, entity_id: str, time_range: str) -> RepositoryResult:
        logs = await self.search_logs()
        return RepositoryResult(ok=True, data={"entity_id": entity_id, "range": time_range, **logs.data}, evidence_refs=logs.evidence_refs)

    async def get_baseline(self, entity_id: str, time_range: str) -> RepositoryResult:
        return RepositoryResult(ok=True, data={"entity_id": entity_id, "range": time_range, "new_relations": ["91.92.18.4"], "common_processes": ["explorer.exe", "chrome.exe"]}, evidence_refs=[f"baseline:{entity_id}"])

    async def get_attack_timeline(self, **kwargs: Any) -> RepositoryResult:
        logs = await self.search_logs()
        return RepositoryResult(ok=True, data={"range": kwargs.get("time_range", "24h"), "events": logs.data["events"]}, evidence_refs=logs.evidence_refs)

    async def get_investigation(self, investigation_id: str) -> RepositoryResult:
        return RepositoryResult(ok=True, data={"investigation_id": investigation_id, "finding_ids": [self.finding["finding_id"]]}, evidence_refs=[investigation_id, self.finding["finding_id"]])

    async def search_knowledge(self, query: str, top_k: int, scope: list[str]) -> RepositoryResult:
        return await super().search_knowledge(query, top_k, scope)


def build_repository() -> SecurityRepository:
    if os.getenv("WAD_AGENT_USE_MOCKS", "false").lower() == "true":
        return DemoRepository()
    root = os.getenv("WAD_AGENT_DATA_DIR")
    if root and Path(root).exists():
        return JsonDirectoryRepository(root)
    return UnavailableRepository()
