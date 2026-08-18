from __future__ import annotations

import json
import os
import re
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


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_PROCESS_EXTS = (".exe", ".php", ".sh", ".py", ".ps1", ".bin", ".dll", ".dat", ".sql", ".gz", ".tar")
_FIELD_TYPES = {"host": "host", "actor": "user", "process": "process", "ip": "ip"}


def _infer_entity_type(name: str) -> str:
    if _IP_RE.match(name):
        return "ip"
    if "/" in name or "\\" in name or name.endswith(_PROCESS_EXTS):
        return "process"
    return "host"


def _merge_by_id(base: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """与前端 data.ts 的 mergeById 保持一致：base 优先，extra 中 id 冲突者被过滤。"""
    seen = {str(item.get("id")) for item in base if item.get("id")}
    return [*base, *[item for item in extra if item.get("id") not in seen]]


def _merge_entities(base: list[dict[str, Any]], extra: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """合并两批实体：同名实体叠加事件数、合并窗口、首末时间取并集。

    data.ts 手工演示数据与 demo-data（Short/Long/APT）存在同名实体（如 svc_backup、
    WEB-01），此前直接 extend 会产生重复记录，导致 get_entity 只返回 data.ts 的旧画像。
    这里按 entity_id 合并，避免 APT 关键实体（后门账户、攻击者主机）的画像丢失。
    """
    merged: dict[str, dict[str, Any]] = {}
    for item in base:
        key = str(item.get("entity_id") or "")
        if key:
            merged[key] = dict(item)
    for key, item in extra.items():
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(item)
            continue
        existing["event_count"] = int(existing.get("event_count") or 0) + int(item.get("event_count") or 0)
        existing["risk"] = max(int(existing.get("risk") or 0), int(item.get("risk") or 0))
        existing["windows"] = list(dict.fromkeys([*existing.get("windows", []), *item.get("windows", [])]))
        if item.get("first_seen") and (not existing.get("first_seen") or str(item["first_seen"]) < str(existing["first_seen"])):
            existing["first_seen"] = item["first_seen"]
        if item.get("last_seen") and (not existing.get("last_seen") or str(item["last_seen"]) > str(existing["last_seen"])):
            existing["last_seen"] = item["last_seen"]
        # 类型优先保留更具体的（host 是兜底，遇到 user/ip/process 时升级）。
        if existing.get("type") == "host" and item.get("type") not in ("host", "", None):
            existing["type"] = item["type"]
    return list(merged.values())


# 前端 data.ts 中手工演示数据的核心部分（Alice/HOST-18/CASE-001 横向移动链）。
# 时间统一补全为完整日期，便于后端的只读适配器按时间排序与过滤。
_BASE_WINDOWS: list[dict[str, Any]] = [
    {
        "id": "WIN-20260803-1042", "title": "外部侦察与目录探测", "severity": "medium", "score": 0.701,
        "start": "2026-08-03 10:42:13", "end": "2026-08-03 10:58:44", "status": "reviewing",
        "eventCount": 53, "entities": ["WEB-01", "185.199.110.42", "/wp-admin", "dirb"], "hosts": ["WEB-01"],
        "sourceTypes": ["WAF", "Suricata", "Wazuh"],
        "summary": "Web 服务在 7 天窗口内出现高频目录探测与异常请求路径访问。",
        "events": [
            {"id": "EVT-09001", "time": "2026-08-03 10:42:13", "action": "DIR_SCAN", "host": "WEB-01", "ip": "185.199.110.42", "source": "WAF", "confidence": 0.9},
            {"id": "EVT-09002", "time": "2026-08-03 10:49:27", "action": "RECON_BURST", "host": "WEB-01", "ip": "185.199.110.42", "source": "Suricata", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260805-1854", "title": "可疑 WebShell 落地", "severity": "high", "score": 0.889,
        "start": "2026-08-05 18:54:08", "end": "2026-08-05 19:07:42", "status": "new",
        "eventCount": 27, "entities": ["WEB-01", "www-data", "shell.php", "185.199.110.42"], "hosts": ["WEB-01"],
        "sourceTypes": ["Wazuh", "WAF", "Linux Audit"],
        "summary": "目录探测两天后，Web 目录出现新脚本文件并伴随异常执行行为。",
        "events": [
            {"id": "EVT-09121", "time": "2026-08-05 18:54:08", "action": "FILE_CREATE", "actor": "www-data", "host": "WEB-01", "process": "php-fpm", "source": "Wazuh", "confidence": 0.9},
            {"id": "EVT-09122", "time": "2026-08-05 19:02:31", "action": "REMOTE_EXECUTION", "actor": "www-data", "host": "WEB-01", "process": "shell.php", "ip": "185.199.110.42", "source": "Linux Audit", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260808-0826", "title": "提权与凭据访问尝试", "severity": "high", "score": 0.918,
        "start": "2026-08-08 08:26:33", "end": "2026-08-08 08:40:15", "status": "new",
        "eventCount": 34, "entities": ["Alice", "HOST-16", "lsass.exe", "procdump.exe"], "hosts": ["HOST-16"],
        "sourceTypes": ["EDR", "Windows EVTX", "Wazuh"],
        "summary": "与脚本解释器行为相邻，出现提权后访问高价值进程的迹象。",
        "events": [
            {"id": "EVT-10381", "time": "2026-08-08 08:26:33", "action": "PRIVILEGE_ESCALATION", "actor": "Alice", "host": "HOST-16", "process": "powershell.exe", "source": "EDR", "confidence": 0.9},
            {"id": "EVT-10382", "time": "2026-08-08 08:34:19", "action": "CREDENTIAL_ACCESS", "actor": "Alice", "host": "HOST-16", "process": "procdump.exe", "source": "Wazuh", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-0112", "title": "异常远程登录尝试", "severity": "medium", "score": 0.734,
        "start": "2026-08-09 01:12:08", "end": "2026-08-09 01:18:42", "status": "reviewing",
        "eventCount": 37, "entities": ["svc_ops", "HOST-02", "172.16.4.22"], "hosts": ["HOST-02"],
        "sourceTypes": ["Windows EVTX", "Firewall"],
        "summary": "短时间内连续出现远程登录失败与来源地址切换。",
        "events": [
            {"id": "EVT-10001", "time": "2026-08-09 01:12:08", "action": "LOGIN_FAILURE", "actor": "svc_ops", "host": "HOST-02", "ip": "172.16.4.22", "source": "Windows EVTX", "confidence": 0.9},
            {"id": "EVT-10002", "time": "2026-08-09 01:15:14", "action": "LOGIN_FAILURE", "actor": "svc_ops", "host": "HOST-02", "ip": "172.16.4.31", "source": "Windows EVTX", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-0248", "title": "可疑端口扫描", "severity": "low", "score": 0.612,
        "start": "2026-08-09 02:48:11", "end": "2026-08-09 02:56:30", "status": "new",
        "eventCount": 64, "entities": ["HOST-05", "10.1.7.19"], "hosts": ["HOST-05"],
        "sourceTypes": ["Firewall", "Network Flow"],
        "summary": "单一源地址在短时段内访问多个非常用端口。",
        "events": [
            {"id": "EVT-10015", "time": "2026-08-09 02:48:11", "action": "NETWORK_CONNECT", "host": "HOST-05", "ip": "10.1.7.19", "source": "Firewall", "confidence": 0.9},
            {"id": "EVT-10016", "time": "2026-08-09 02:52:49", "action": "PORT_BURST", "host": "HOST-05", "ip": "10.1.7.19", "source": "Network Flow", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-0321", "title": "可疑 PowerShell 执行", "severity": "high", "score": 0.913,
        "start": "2026-08-09 03:21:14", "end": "2026-08-09 03:26:14", "status": "new",
        "eventCount": 23, "entities": ["Alice", "powershell.exe", "10.2.3.7", "HOST-07"], "hosts": ["HOST-07"],
        "sourceTypes": ["Windows EVTX", "EDR", "Firewall"],
        "summary": "同一用户完成网络登录后，以高权限启动 PowerShell 并建立外联。",
        "events": [
            {"id": "EVT-10031", "time": "2026-08-09 03:21:14", "action": "LOGIN", "actor": "Alice", "host": "HOST-07", "source": "Windows EVTX", "confidence": 0.96},
            {"id": "EVT-10032", "time": "2026-08-09 03:22:03", "action": "PROCESS_START", "actor": "Alice", "host": "HOST-07", "process": "powershell.exe", "source": "EDR", "confidence": 0.94},
            {"id": "EVT-10033", "time": "2026-08-09 03:23:18", "action": "NETWORK_CONNECT", "host": "HOST-07", "process": "powershell.exe", "ip": "10.2.3.7", "source": "Firewall", "confidence": 0.91},
        ],
    },
    {
        "id": "WIN-20260809-0516", "title": "计划任务异常创建", "severity": "medium", "score": 0.768,
        "start": "2026-08-09 05:16:25", "end": "2026-08-09 05:24:12", "status": "new",
        "eventCount": 19, "entities": ["SYSTEM", "schtasks.exe", "HOST-09"], "hosts": ["HOST-09"],
        "sourceTypes": ["Windows EVTX", "EDR"],
        "summary": "系统账户创建新的计划任务并调用非常用命令。",
        "events": [
            {"id": "EVT-10051", "time": "2026-08-09 05:16:25", "action": "TASK_CREATE", "actor": "SYSTEM", "host": "HOST-09", "source": "Windows EVTX", "confidence": 0.9},
            {"id": "EVT-10052", "time": "2026-08-09 05:19:03", "action": "PROCESS_START", "host": "HOST-09", "process": "schtasks.exe", "source": "EDR", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-0744", "title": "未知进程异常外联", "severity": "high", "score": 0.861,
        "start": "2026-08-09 07:44:38", "end": "2026-08-09 07:53:06", "status": "new",
        "eventCount": 28, "entities": ["syncsvc.exe", "HOST-11", "45.77.21.19"], "hosts": ["HOST-11"],
        "sourceTypes": ["EDR", "Network Flow", "Firewall"],
        "summary": "新出现进程持续访问外部地址并绕过常用代理路径。",
        "events": [
            {"id": "EVT-10074", "time": "2026-08-09 07:44:38", "action": "PROCESS_START", "host": "HOST-11", "process": "syncsvc.exe", "source": "EDR", "confidence": 0.9},
            {"id": "EVT-10075", "time": "2026-08-09 07:47:10", "action": "NETWORK_CONNECT", "host": "HOST-11", "process": "syncsvc.exe", "ip": "45.77.21.19", "source": "Network Flow", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-0935", "title": "跨主机身份连续行为", "severity": "high", "score": 0.887,
        "start": "2026-08-09 09:35:02", "end": "2026-08-09 09:41:38", "status": "investigating",
        "eventCount": 18, "entities": ["Alice", "cmd.exe", "HOST-12", "10.2.8.19"], "hosts": ["HOST-12"],
        "sourceTypes": ["Windows EVTX", "EDR"],
        "summary": "Alice 在约 6 小时后出现在第二台主机，实体与行为链存在长时关联。",
        "events": [
            {"id": "EVT-10172", "time": "2026-08-09 09:35:02", "action": "LOGIN", "actor": "Alice", "host": "HOST-12", "source": "Windows EVTX", "confidence": 0.95},
            {"id": "EVT-10175", "time": "2026-08-09 09:37:49", "action": "PROCESS_START", "actor": "Alice", "host": "HOST-12", "process": "cmd.exe", "source": "EDR", "confidence": 0.92},
        ],
    },
    {
        "id": "WIN-20260809-0938", "title": "命令执行密集升高", "severity": "medium", "score": 0.779,
        "start": "2026-08-09 09:38:20", "end": "2026-08-09 09:45:16", "status": "new",
        "eventCount": 46, "entities": ["HOST-12", "cmd.exe", "whoami.exe"], "hosts": ["HOST-12"],
        "sourceTypes": ["EDR", "Windows EVTX"],
        "summary": "与相邻异常窗口重叠，命令执行频率明显升高。",
        "events": [
            {"id": "EVT-10181", "time": "2026-08-09 09:38:20", "action": "PROCESS_START", "host": "HOST-12", "process": "whoami.exe", "source": "EDR", "confidence": 0.9},
            {"id": "EVT-10182", "time": "2026-08-09 09:41:12", "action": "PROCESS_START", "host": "HOST-12", "process": "cmd.exe", "source": "EDR", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-1022", "title": "异常 DNS 请求聚集", "severity": "low", "score": 0.648,
        "start": "2026-08-09 10:22:04", "end": "2026-08-09 10:31:52", "status": "reviewing",
        "eventCount": 73, "entities": ["HOST-14", "dns-cache", "10.10.3.8"], "hosts": ["HOST-14"],
        "sourceTypes": ["Network Flow"],
        "summary": "同一主机出现高频、短周期 DNS 请求。",
        "events": [
            {"id": "EVT-10203", "time": "2026-08-09 10:22:04", "action": "DNS_BURST", "host": "HOST-14", "ip": "10.10.3.8", "source": "Network Flow", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-1148", "title": "异常认证失败聚集", "severity": "medium", "score": 0.721,
        "start": "2026-08-09 11:48:00", "end": "2026-08-09 11:53:00", "status": "reviewing",
        "eventCount": 41, "entities": ["svc_backup", "HOST-03", "172.16.2.44"], "hosts": ["HOST-03"],
        "sourceTypes": ["Windows EVTX"],
        "summary": "短窗口内出现高频认证失败，尚未观察到后续高风险进程或文件行为。",
        "events": [
            {"id": "EVT-10241", "time": "2026-08-09 11:48:03", "action": "LOGIN_FAILURE", "actor": "svc_backup", "host": "HOST-03", "ip": "172.16.2.44", "source": "Windows EVTX", "confidence": 0.89},
        ],
    },
    {
        "id": "WIN-20260809-1236", "title": "脚本解释器链式启动", "severity": "high", "score": 0.902,
        "start": "2026-08-09 12:36:17", "end": "2026-08-09 12:44:09", "status": "new",
        "eventCount": 32, "entities": ["wscript.exe", "powershell.exe", "HOST-16"], "hosts": ["HOST-16"],
        "sourceTypes": ["EDR", "Windows EVTX"],
        "summary": "脚本解释器连续拉起 PowerShell，执行链偏离基线。",
        "events": [
            {"id": "EVT-10301", "time": "2026-08-09 12:36:17", "action": "PROCESS_START", "host": "HOST-16", "process": "wscript.exe", "source": "EDR", "confidence": 0.9},
            {"id": "EVT-10302", "time": "2026-08-09 12:37:41", "action": "PROCESS_START", "host": "HOST-16", "process": "powershell.exe", "source": "EDR", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-1422", "title": "敏感文件访问与外联", "severity": "critical", "score": 0.948,
        "start": "2026-08-09 14:22:11", "end": "2026-08-09 14:29:45", "status": "new",
        "eventCount": 29, "entities": ["Alice", "HOST-18", "archive.exe", "sensitive.dat"], "hosts": ["HOST-18"],
        "sourceTypes": ["Linux Audit", "Network Flow", "EDR"],
        "summary": "用户实体再次出现，并在敏感文件访问后产生新的外部网络连接。",
        "events": [
            {"id": "EVT-10418", "time": "2026-08-09 14:22:11", "action": "FILE_READ", "actor": "Alice", "host": "HOST-18", "process": "archive.exe", "source": "Linux Audit", "confidence": 0.93},
            {"id": "EVT-10419", "time": "2026-08-09 14:26:44", "action": "NETWORK_CONNECT", "host": "HOST-18", "process": "archive.exe", "ip": "91.92.18.4", "source": "Network Flow", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-1424", "title": "压缩进程异常聚集", "severity": "high", "score": 0.906,
        "start": "2026-08-09 14:24:02", "end": "2026-08-09 14:31:18", "status": "new",
        "eventCount": 36, "entities": ["archive.exe", "HOST-18", "/data/export"], "hosts": ["HOST-18"],
        "sourceTypes": ["EDR", "Linux Audit"],
        "summary": "与敏感文件窗口交织，压缩进程短时访问多个目录。",
        "events": [
            {"id": "EVT-10424", "time": "2026-08-09 14:24:02", "action": "PROCESS_BURST", "host": "HOST-18", "process": "archive.exe", "source": "EDR", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-1427", "title": "外联流量突增", "severity": "critical", "score": 0.961,
        "start": "2026-08-09 14:27:36", "end": "2026-08-09 14:35:50", "status": "new",
        "eventCount": 58, "entities": ["HOST-18", "91.92.18.4", "443"], "hosts": ["HOST-18"],
        "sourceTypes": ["Network Flow", "Firewall"],
        "summary": "与文件访问和压缩窗口重叠，外联流量持续快速增长。",
        "events": [
            {"id": "EVT-10431", "time": "2026-08-09 14:27:36", "action": "NETWORK_BURST", "host": "HOST-18", "ip": "91.92.18.4", "source": "Network Flow", "confidence": 0.9},
            {"id": "EVT-10432", "time": "2026-08-09 14:30:22", "action": "NETWORK_CONNECT", "host": "HOST-18", "ip": "91.92.18.4", "source": "Firewall", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-1606", "title": "高权限令牌使用异常", "severity": "medium", "score": 0.792,
        "start": "2026-08-09 16:06:18", "end": "2026-08-09 16:13:39", "status": "reviewing",
        "eventCount": 21, "entities": ["Administrator", "HOST-21", "services.exe"], "hosts": ["HOST-21"],
        "sourceTypes": ["Windows EVTX", "EDR"],
        "summary": "管理员令牌在非常用服务进程中被使用。",
        "events": [
            {"id": "EVT-10520", "time": "2026-08-09 16:06:18", "action": "TOKEN_USE", "actor": "Administrator", "host": "HOST-21", "process": "services.exe", "source": "Windows EVTX", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-1818", "title": "可疑 SSH 会话", "severity": "high", "score": 0.874,
        "start": "2026-08-09 18:18:09", "end": "2026-08-09 18:27:46", "status": "new",
        "eventCount": 26, "entities": ["ops", "srv-db-02", "185.42.18.9"], "hosts": ["srv-db-02"],
        "sourceTypes": ["Linux Audit", "Firewall"],
        "summary": "运维账户从非常用外部地址建立 SSH 会话。",
        "events": [
            {"id": "EVT-10601", "time": "2026-08-09 18:18:09", "action": "SSH_LOGIN", "actor": "ops", "host": "srv-db-02", "ip": "185.42.18.9", "source": "Linux Audit", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-2002", "title": "数据库导出行为异常", "severity": "critical", "score": 0.953,
        "start": "2026-08-09 20:02:21", "end": "2026-08-09 20:12:58", "status": "new",
        "eventCount": 44, "entities": ["dbadmin", "srv-db-02", "dump.sql"], "hosts": ["srv-db-02"],
        "sourceTypes": ["Linux Audit", "EDR"],
        "summary": "数据库主机出现大规模导出并伴随新文件生成。",
        "events": [
            {"id": "EVT-10644", "time": "2026-08-09 20:02:21", "action": "DB_EXPORT", "actor": "dbadmin", "host": "srv-db-02", "source": "Linux Audit", "confidence": 0.9},
            {"id": "EVT-10645", "time": "2026-08-09 20:08:34", "action": "FILE_CREATE", "host": "srv-db-02", "process": "mysqldump", "source": "EDR", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-2137", "title": "异常服务启动", "severity": "medium", "score": 0.754,
        "start": "2026-08-09 21:37:05", "end": "2026-08-09 21:43:40", "status": "new",
        "eventCount": 17, "entities": ["updater-svc", "HOST-25", "sc.exe"], "hosts": ["HOST-25"],
        "sourceTypes": ["Windows EVTX", "EDR"],
        "summary": "新服务在非维护窗口启动并创建常驻进程。",
        "events": [
            {"id": "EVT-10710", "time": "2026-08-09 21:37:05", "action": "SERVICE_START", "host": "HOST-25", "process": "sc.exe", "source": "Windows EVTX", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-2250", "title": "异常域名访问", "severity": "low", "score": 0.633,
        "start": "2026-08-09 22:50:11", "end": "2026-08-09 22:58:52", "status": "reviewing",
        "eventCount": 39, "entities": ["HOST-28", "cdn-update.example"], "hosts": ["HOST-28"],
        "sourceTypes": ["Network Flow", "Firewall"],
        "summary": "终端访问低频域名，暂未发现后续执行行为。",
        "events": [
            {"id": "EVT-10752", "time": "2026-08-09 22:50:11", "action": "DNS_QUERY", "host": "HOST-28", "source": "Network Flow", "confidence": 0.9},
        ],
    },
    {
        "id": "WIN-20260809-2318", "title": "疑似数据外传收尾", "severity": "critical", "score": 0.941,
        "start": "2026-08-09 23:18:09", "end": "2026-08-09 23:29:41", "status": "new",
        "eventCount": 31, "entities": ["WEB-01", "185.199.110.42", "archive.tar.gz"], "hosts": ["WEB-01"],
        "sourceTypes": ["Suricata", "Network Flow", "Wazuh"],
        "summary": "多日 Web 攻击链末端出现归档文件生成与持续外联，具备数据外传特征。",
        "events": [
            {"id": "EVT-10811", "time": "2026-08-09 23:18:09", "action": "ARCHIVE_CREATE", "host": "WEB-01", "process": "tar", "ip": "185.199.110.42", "source": "Wazuh", "confidence": 0.9},
            {"id": "EVT-10812", "time": "2026-08-09 23:24:57", "action": "DATA_EXFIL", "host": "WEB-01", "ip": "185.199.110.42", "source": "Suricata", "confidence": 0.9},
        ],
    },
]

_BASE_INVESTIGATIONS: list[dict[str, Any]] = [
    {
        "id": "CASE-001", "investigation_id": "CASE-001", "title": "疑似横向移动与数据访问",
        "severity": "critical", "status": "investigating", "owner": "Analyst-01", "createdAt": "2026-08-09 09:44",
        "windowIds": ["WIN-20260809-0321", "WIN-20260809-0935", "WIN-20260809-1422", "WIN-20260809-1424", "WIN-20260809-1427"],
        "finding_ids": ["WIN-20260809-0321", "WIN-20260809-0935", "WIN-20260809-1422", "WIN-20260809-1424", "WIN-20260809-1427"],
        "summary": "同一用户在多个主机与长时间窗口中持续出现，行为从登录、命令执行延伸至敏感文件访问。",
    },
    {
        "id": "CASE-002", "investigation_id": "CASE-002", "title": "服务账号异常认证",
        "severity": "medium", "status": "investigating", "owner": "Analyst-02", "createdAt": "2026-08-09 12:02",
        "windowIds": ["WIN-20260809-0112", "WIN-20260809-1148"],
        "summary": "持续观察服务账号失败认证是否出现后续执行行为。",
    },
    {
        "id": "CASE-003", "investigation_id": "CASE-003", "title": "多日 Web 入侵与外传链",
        "severity": "critical", "status": "investigating", "owner": "Analyst-03", "createdAt": "2026-08-09 23:32",
        "windowIds": ["WIN-20260803-1042", "WIN-20260805-1854", "WIN-20260809-2318"],
        "summary": "基于多日告警与主机事件重建 Web 侦察、落地和数据外传的长程链路。",
    },
]


def _build_entities(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entities: dict[str, dict[str, Any]] = {}

    def entry(name: str, etype: str) -> dict[str, Any]:
        item = entities.get(name)
        if item is None:
            item = {"entity_id": name, "type": etype, "event_count": 0, "risk": 0, "windows": [], "first_seen": None, "last_seen": None}
            entities[name] = item
        elif etype != "host" and item["type"] == "host":
            item["type"] = etype
        return item

    for window in windows:
        window_id = window.get("id")
        risk = int(round(float(window.get("score") or 0) * 100))
        for name in [*window.get("hosts", []), *window.get("entities", [])]:
            if not name:
                continue
            item = entry(str(name), _infer_entity_type(str(name)))
            if window_id not in item["windows"]:
                item["windows"].append(window_id)
            item["risk"] = max(item["risk"], risk)
        for event in window.get("events", []):
            for field, etype in _FIELD_TYPES.items():
                name = event.get(field)
                if not name:
                    continue
                name = str(name)
                inferred = _infer_entity_type(name)
                item = entry(name, inferred if inferred != "host" else etype)
                item["event_count"] += 1
                timestamp = event.get("time")
                if timestamp:
                    if not item["first_seen"] or timestamp < item["first_seen"]:
                        item["first_seen"] = timestamp
                    if not item["last_seen"] or timestamp > item["last_seen"]:
                        item["last_seen"] = timestamp
    return list(entities.values())


def _norm_time(value: str) -> str:
    """规范化 ISO 时间戳为 YYYY-MM-DD HH:MM:SS，便于只读适配器按时间排序与过滤。"""
    text = (value or "").strip()
    if not text:
        return ""
    text = text.replace("T", " ").replace("Z", "")
    if "." in text:
        text = text.split(".")[0]
    return text[:19]


def _extract_host(related_entities: Any) -> str:
    if isinstance(related_entities, list):
        for item in related_entities:
            if isinstance(item, dict) and item.get("entity_type") == "host":
                value = item.get("canonical_value")
                if value:
                    return str(value)
    return ""


def _extract_entities(related_entities: Any) -> list[tuple[str, str]]:
    """提取 related_entities 中全部实体（名称、类型），供小影按 IP/账号/进程等维度查询。"""
    result: list[tuple[str, str]] = []
    if not isinstance(related_entities, list):
        return result
    for item in related_entities:
        if not isinstance(item, dict):
            continue
        value = item.get("canonical_value")
        etype = str(item.get("entity_type", "") or "")
        if not value or not etype:
            continue
        name = str(value)
        if not any(existing == name for existing, _ in result):
            result.append((name, etype))
    return result


class DemoRepository(JsonDirectoryRepository):
    """内置演示库：加载 generatedDataset.json（AIT-ADS / EVTX 公开数据集提取）与前端手工演示数据。

    启用方式：设置 WAD_AGENT_USE_MOCKS=true。数据随仓库内置，安全工具查询复用
    JsonDirectoryRepository 的只读适配器逻辑（以内存索引替代文件读取）。
    """

    def __init__(self) -> None:
        super().__init__(".")
        dataset = self._load_dataset()
        windows = _merge_by_id(_BASE_WINDOWS, dataset.get("anomalyWindows", []))
        investigations = _merge_by_id(_BASE_INVESTIGATIONS, dataset.get("investigations", []))

        self._findings: list[dict[str, Any]] = []
        self._events: list[dict[str, Any]] = []
        self._investigations: list[dict[str, Any]] = []
        self._demo_entities: dict[str, dict[str, Any]] = {}
        for window in windows:
            finding = dict(window)
            finding["finding_id"] = window.get("id")
            finding["evidence_refs"] = [str(event.get("id")) for event in window.get("events", []) if event.get("id")]
            self._findings.append(finding)
            for event in window.get("events", []):
                row = dict(event)
                row.setdefault("event_id", event.get("id"))
                row.setdefault("source_type", event.get("source"))
                self._events.append(row)

        for item in investigations:
            investigation = dict(item)
            investigation["investigation_id"] = item.get("id") or item.get("investigation_id")
            self._investigations.append(investigation)

        # 追加前端 demo-data（Short/Long）真实日志，供链重组候选的原始事件复核。
        self._load_demo_data()

        self._entities = _merge_entities(_build_entities(windows), self._demo_entities)
        self._baselines: dict[str, dict[str, Any]] = {
            item["entity_id"]: {**item, "note": "由演示数据合成的历史行为基线。"}
            for item in self._entities
        }

    def _load_demo_data(self) -> None:
        """加载前端 demo-data（Short/Long）真实日志，追加 findings/events/entities/investigations。

        前端链重组图的候选节点（如 SHORT-000003）来自 frontend/public/demo-data 的
        timeline.json；此前后端仓库没有这批数据，导致小影调 get_finding 复核候选时
        查不到原始证据。这里把整条时间线纳入，并按 attack_chain 步骤生成候选 Finding。
        """
        base = Path(__file__).resolve().parents[1] / "frontend" / "public" / "demo-data"
        for dataset in ("Short", "Long", "APT"):
            timeline_path = base / dataset / "timeline.json"
            chain_path = base / dataset / "attack_chain.json"
            if not timeline_path.exists() or not chain_path.exists():
                continue
            try:
                timeline = json.loads(timeline_path.read_text(encoding="utf-8"))
                chain = json.loads(chain_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue

            # 前端 anomalyWindow（WIN-{event_id}）来自 final_score>=0.5 的检测结果。
            # 后端需把这些高分事件也建成 finding，否则 AUTO/DISP 调查窗口复核会“未找到”。
            detection_path = base / dataset / "detection_results.json"
            detection_by_event: dict[str, dict[str, Any]] = {}
            if detection_path.exists():
                try:
                    detections = json.loads(detection_path.read_text(encoding="utf-8"))
                    detection_by_event = {
                        str(item.get("event_id", "") or ""): item
                        for item in detections
                        if isinstance(item, dict) and item.get("event_id")
                    }
                except (OSError, ValueError):
                    detection_by_event = {}

            step_by_event: dict[str, str] = {}
            chain_event_ids: list[str] = []
            for step in chain.get("steps", []):
                label = str(step.get("label", "") or "")
                for event_id in step.get("evidence_event_ids", []):
                    key = str(event_id)
                    step_by_event[key] = label
                    chain_event_ids.append(key)

            for event in timeline:
                event_id = str(event.get("event_id", "") or "")
                if not event_id:
                    continue
                timestamp = _norm_time(event.get("timestamp", ""))
                raw = str(event.get("raw", "") or "")
                source = str(event.get("source_file", "") or "")
                host = _extract_host(event.get("related_entities"))
                log = {
                    "event_id": event_id,
                    "win_id": f"WIN-{event_id}",
                    "time": timestamp,
                    "source": source,
                    "source_type": source,
                    "raw": raw,
                    "host": host,
                }
                self._events.append(log)

                detection = detection_by_event.get(event_id, {})
                is_chain = event_id in step_by_event
                is_high_score = float(detection.get("final_score") or 0) >= 0.5
                if is_chain or is_high_score:
                    threat = str(detection.get("threat_level", "") or "")
                    severity = {"info": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}.get(threat, "high" if is_chain else "medium")
                    if is_chain:
                        title = step_by_event[event_id]
                    else:
                        reasons = detection.get("reasons") or []
                        title = str(reasons[0]) if reasons else (threat or raw[:40])
                    self._findings.append({
                        "id": event_id,
                        "finding_id": event_id,
                        "title": title,
                        "severity": severity,
                        "score": float(detection.get("final_score") or event.get("system_projection", {}).get("final_score") or 0),
                        "start": timestamp,
                        "end": timestamp,
                        "status": "new",
                        "eventCount": 1,
                        "entities": [host] if host else [],
                        "hosts": [host] if host else [],
                        "sourceTypes": [source],
                        "summary": raw,
                        "events": [log],
                        "evidence_refs": [event_id],
                    })

                # 全部相关实体（IP/账号/进程/主机/资产）都写入实体索引，
                # 使小影可按攻击者 IP、后门账户等维度查询 APT 关键实体。
                for name, etype in _extract_entities(event.get("related_entities")):
                    entity = self._demo_entities.setdefault(
                        name,
                        {"entity_id": name, "type": etype, "event_count": 0, "risk": 0, "windows": [], "first_seen": None, "last_seen": None},
                    )
                    entity["event_count"] += 1
                    if timestamp:
                        if not entity["first_seen"] or timestamp < entity["first_seen"]:
                            entity["first_seen"] = timestamp
                        if not entity["last_seen"] or timestamp > entity["last_seen"]:
                            entity["last_seen"] = timestamp

            chain_id = str(chain.get("chain_id", "") or "")
            if chain_id and chain_event_ids:
                self._investigations.append({
                    "id": chain_id,
                    "investigation_id": chain_id,
                    "title": f"{dataset} 人工整理基准攻击链",
                    "severity": "critical",
                    "status": "investigating",
                    "owner": "analyst-01",
                    "windowIds": [f"WIN-{event_id}" for event_id in chain_event_ids],
                    "finding_ids": chain_event_ids,
                    "summary": str(chain.get("claim_type", "") or "分析员整理的基准候选链。"),
                })

    async def get_finding(self, finding_id: str) -> RepositoryResult:
        result = await super().get_finding(finding_id)
        if result.ok:
            return result
        # 前端 finding id 形如 WIN-{event_id}，而 demo-data 事件 id 是 event_id，剥离前缀重试。
        stripped = finding_id[4:] if finding_id.startswith("WIN-") else finding_id
        if stripped != finding_id:
            result = await super().get_finding(stripped)
            if result.ok:
                return result
        # 兜底：模型可能截取 id 尾部数字（如 000003）。
        if len(finding_id) >= 5:
            for item in self._findings:
                if str(item.get("id", "") or "").endswith(finding_id) or str(item.get("finding_id", "") or "").endswith(finding_id):
                    refs = list(dict.fromkeys([str(item.get("id", "") or ""), *item.get("evidence_refs", [])]))
                    return RepositoryResult(ok=True, data=item, evidence_refs=refs)
        return result

    async def get_investigation(self, investigation_id: str) -> RepositoryResult:
        result = await super().get_investigation(investigation_id)
        if result.ok:
            return result
        # 前端动态生成的调查 id（如 LONG-AUTO-002、LONG-DISP-003）由运行时聚类产生，
        # 后端未持久化其成员明细。这里降级为提示模型改用 finding_ids 回查原始证据，
        # 避免因“未找到 Investigation”而把可用数据误判为不可用。
        if "-AUTO-" in investigation_id or "-DISP-" in investigation_id:
            data = {
                "investigation_id": investigation_id,
                "title": "前端动态生成的调查（后端未持久化成员明细）",
                "status": "investigating",
                "note": "该调查 id 由前端按共享实体/时间窗运行时聚类生成，后端仓库未同步其 windowIds 明细。请改用 finding_ids 逐个读取原始证据，或按实体/时间范围查时间线。",
                "windowIds": [],
            }
            return RepositoryResult(ok=True, data=data, evidence_refs=[], message="前端动态调查，后端无持久化记录；请用 finding_ids 查具体证据。")
        return result

    def _load_dataset(self) -> dict[str, Any]:
        candidates = [
            Path(__file__).resolve().parents[1] / "frontend" / "src" / "mocks" / "generatedDataset.json",
            Path(__file__).resolve().parent / "demo_data" / "generatedDataset.json",
        ]
        for path in candidates:
            if path.exists():
                with path.open("r", encoding="utf-8") as handle:
                    return json.load(handle)
        return {"anomalyWindows": [], "investigations": []}

    def _json(self, name: str, default: Any) -> Any:
        if name == "findings.json":
            return self._findings
        if name == "entities.json":
            return self._entities
        if name == "investigations.json":
            return self._investigations
        if name == "baselines.json":
            return self._baselines
        if name == "knowledge.json":
            return []
        return default

    def _logs(self) -> list[dict[str, Any]]:
        return self._events


def build_repository() -> SecurityRepository:
    if os.getenv("WAD_AGENT_USE_MOCKS", "false").lower() == "true":
        return DemoRepository()
    root = os.getenv("WAD_AGENT_DATA_DIR")
    if root and Path(root).exists():
        return JsonDirectoryRepository(root)
    return UnavailableRepository()
