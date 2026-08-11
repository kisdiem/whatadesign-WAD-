from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from agents import RunContextWrapper, function_tool

from .models import ToolEvent
from .repository import SecurityRepository

StatusCallback = Callable[[str], Awaitable[None]]


@dataclass
class AgentContext:
    repository: SecurityRepository
    finding_ids: list[str] = field(default_factory=list)
    investigation_id: str | None = None
    entity_ids: list[str] = field(default_factory=list)
    requested_time_range: str | None = None
    status_callback: StatusCallback | None = None
    tool_events: list[ToolEvent] = field(default_factory=list)
    evidence_refs: set[str] = field(default_factory=set)
    evidence_payloads: list[dict[str, Any]] = field(default_factory=list)

    async def notify(self, label: str) -> None:
        if self.status_callback:
            await self.status_callback(label)

    def record(self, tool: str, result: Any) -> str:
        refs = list(dict.fromkeys(result.evidence_refs))
        self.evidence_refs.update(refs)
        if result.ok and result.data is not None:
            self.evidence_payloads.append({"tool": tool, "data": result.data, "evidence_refs": refs})
        self.tool_events.append(ToolEvent(tool=tool, ok=result.ok, message=result.message or ("ok" if result.ok else "failed"), evidence_refs=refs))
        payload = {"ok": result.ok, "message": result.message, "data": result.data, "evidence_refs": refs}
        return json.dumps(payload, ensure_ascii=False)


@function_tool
async def security_get_finding(wrapper: RunContextWrapper[AgentContext], finding_id: str) -> str:
    """Read one persisted security Finding by ID. Use this before making claims about a concrete Finding."""
    await wrapper.context.notify("正在读取 Finding")
    result = await wrapper.context.repository.get_finding(finding_id)
    return wrapper.context.record("security.get_finding", result)


@function_tool
async def security_search_logs(
    wrapper: RunContextWrapper[AgentContext],
    entities: list[str] | None = None,
    source_types: list[str] | None = None,
    keywords: list[str] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 50,
) -> str:
    """Search already indexed raw/normalized security logs using structured filters only. Limit is capped at 200."""
    await wrapper.context.notify("正在查询相关日志")
    result = await wrapper.context.repository.search_logs(
        entities=entities or [],
        source_types=source_types or [],
        keywords=keywords or [],
        start_time=start_time,
        end_time=end_time,
        limit=max(1, min(limit, 200)),
    )
    return wrapper.context.record("security.search_logs", result)


@function_tool
async def security_get_entity(wrapper: RunContextWrapper[AgentContext], entity_id: str) -> str:
    """Read a host, user, IP, process or other resolved security entity and its current stored attributes."""
    await wrapper.context.notify("正在读取实体信息")
    result = await wrapper.context.repository.get_entity(entity_id)
    return wrapper.context.record("security.get_entity", result)


@function_tool
async def security_get_entity_history(wrapper: RunContextWrapper[AgentContext], entity_id: str, time_range: str = "7d") -> str:
    """Read a bounded historical summary for an entity. Prefer 24h first; use 7d for deep traceback."""
    await wrapper.context.notify(f"正在检查实体历史 · {time_range}")
    result = await wrapper.context.repository.get_entity_history(entity_id, time_range)
    return wrapper.context.record("security.get_entity_history", result)


@function_tool
async def security_get_baseline(wrapper: RunContextWrapper[AgentContext], entity_id: str, time_range: str = "30d") -> str:
    """Read aggregated historical behavior baseline features. This does not re-run all historical logs."""
    await wrapper.context.notify(f"正在检查历史行为基线 · {time_range}")
    result = await wrapper.context.repository.get_baseline(entity_id, time_range)
    return wrapper.context.record("security.get_baseline", result)


@function_tool
async def security_get_attack_timeline(
    wrapper: RunContextWrapper[AgentContext],
    finding_ids: list[str] | None = None,
    entity_ids: list[str] | None = None,
    time_range: str = "24h",
) -> str:
    """Return a time-ordered attack/evidence timeline for selected Findings or entities."""
    await wrapper.context.notify(f"正在整理攻击时间线 · {time_range}")
    result = await wrapper.context.repository.get_attack_timeline(
        finding_ids=finding_ids or wrapper.context.finding_ids,
        entity_ids=entity_ids or wrapper.context.entity_ids,
        time_range=time_range,
    )
    return wrapper.context.record("security.get_attack_timeline", result)


@function_tool
async def security_get_investigation(wrapper: RunContextWrapper[AgentContext], investigation_id: str) -> str:
    """Read a persisted Investigation, its linked Findings, entities, notes and existing conclusions."""
    await wrapper.context.notify("正在读取 Investigation")
    result = await wrapper.context.repository.get_investigation(investigation_id)
    return wrapper.context.record("security.get_investigation", result)


@function_tool
async def knowledge_search(
    wrapper: RunContextWrapper[AgentContext],
    query: str,
    top_k: int = 5,
    scope: list[str] | None = None,
) -> str:
    """Search curated security/organization/historical-case knowledge. Use for grounded knowledge questions."""
    await wrapper.context.notify("正在检索安全知识库")
    result = await wrapper.context.repository.search_knowledge(
        query=query,
        top_k=max(1, min(top_k, 10)),
        scope=scope or ["security", "organization", "historical_cases"],
    )
    return wrapper.context.record("knowledge.search", result)


SECURITY_TOOLS = [
    security_get_finding,
    security_search_logs,
    security_get_entity,
    security_get_entity_history,
    security_get_baseline,
    security_get_attack_timeline,
    security_get_investigation,
    knowledge_search,
]

KNOWLEDGE_TOOLS = [knowledge_search]
