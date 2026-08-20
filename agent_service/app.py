from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agents import set_default_openai_client, set_tracing_disabled
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from .ingestion import ingestion_store
from .models import AgentQueryRequest, AgentRequestContext
from .project_knowledge import knowledge_document_catalog, knowledge_manifest
from .runtime import AgentRuntime, configure_model

logger = logging.getLogger("wad.agent")

app = FastAPI(title="链影寻踪 Agent Service", version="1.1")

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "WAD_AGENT_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5179,http://127.0.0.1:5179",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

runtime = AgentRuntime()
_runtime_openai_configured = False


class LegacyAssistantRequest(BaseModel):
    question: str
    context: dict[str, Any] = Field(default_factory=dict)


class AgentProviderRequest(BaseModel):
    api_key: str = Field(min_length=8, max_length=4096)
    provider: str = "openai"
    base_url: str | None = None
    model: str = Field(default="gpt-4o-mini", min_length=1, max_length=200)


class ApiLogSourceRequest(BaseModel):
    type: str = "api"
    name: str = Field(min_length=1, max_length=200)
    endpoint: str = Field(min_length=1, max_length=2048)
    method: str = "GET"
    authType: str = "none"
    token: str | None = None
    pollInterval: int = Field(default=60, ge=10, le=86400)


class SecurityLogSearchRequest(BaseModel):
    entities: list[str] = Field(default_factory=list)
    source_types: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    start_time: str | None = None
    end_time: str | None = None
    limit: int = Field(default=50, ge=1, le=200)


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)
    top_k: int = Field(default=5, ge=1, le=10)
    scope: list[str] = Field(default_factory=lambda: ["project", "security", "organization", "historical_cases"])


class IngestFileRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1)
    content_type: str = Field(default="", max_length=200)


_api_log_sources: list[dict[str, Any]] = []
_runtime_provider = "none"
_runtime_model = ""
_runtime_base_url: str | None = None

_demo_windows: list[dict[str, Any]] = [
    {
        "id": "WIN-20260809-0321",
        "title": "可疑 PowerShell 执行",
        "severity": "high",
        "score": 0.913,
        "start": "03:21:14",
        "end": "03:26:14",
        "status": "new",
        "eventCount": 23,
        "entities": ["Alice", "powershell.exe", "10.2.3.7", "HOST-07"],
        "hosts": ["HOST-07"],
        "sourceTypes": ["Windows EVTX", "EDR", "Firewall"],
        "summary": "同一用户完成网络登录后，以高权限启动 PowerShell 并建立外联。",
        "events": [
            {"id": "EVT-10031", "time": "03:21:14", "action": "LOGIN", "actor": "Alice", "host": "HOST-07", "source": "Windows EVTX", "raw": "03:21:14 LOGIN", "confidence": 0.96},
            {"id": "EVT-10032", "time": "03:22:03", "action": "PROCESS_START", "actor": "Alice", "host": "HOST-07", "process": "powershell.exe", "source": "EDR", "raw": "03:22:03 PROCESS_START", "confidence": 0.94},
            {"id": "EVT-10033", "time": "03:23:18", "action": "NETWORK_CONNECT", "host": "HOST-07", "process": "powershell.exe", "ip": "10.2.3.7", "source": "Firewall", "raw": "03:23:18 NETWORK_CONNECT", "confidence": 0.91},
        ],
    },
    {
        "id": "WIN-20260809-0935",
        "title": "跨主机身份连续行为",
        "severity": "high",
        "score": 0.887,
        "start": "09:35:02",
        "end": "09:41:38",
        "status": "investigating",
        "eventCount": 18,
        "entities": ["Alice", "cmd.exe", "HOST-12", "10.2.8.19"],
        "hosts": ["HOST-12"],
        "sourceTypes": ["Windows EVTX", "EDR"],
        "summary": "Alice 在约 6 小时后出现在第二台主机，实体与行为链存在长时关联。",
        "events": [
            {"id": "EVT-10172", "time": "09:35:02", "action": "LOGIN", "actor": "Alice", "host": "HOST-12", "source": "Windows EVTX", "raw": "09:35:02 LOGIN", "confidence": 0.95},
            {"id": "EVT-10175", "time": "09:37:49", "action": "PROCESS_START", "actor": "Alice", "host": "HOST-12", "process": "cmd.exe", "source": "EDR", "raw": "09:37:49 PROCESS_START", "confidence": 0.92},
        ],
    },
    {
        "id": "WIN-20260809-1148",
        "title": "异常认证失败聚集",
        "severity": "medium",
        "score": 0.721,
        "start": "11:48:00",
        "end": "11:53:00",
        "status": "reviewing",
        "eventCount": 41,
        "entities": ["svc_backup", "HOST-03", "172.16.2.44"],
        "hosts": ["HOST-03"],
        "sourceTypes": ["Windows EVTX"],
        "summary": "短窗口内出现高频认证失败，尚未观察到后续高风险进程或文件行为。",
        "events": [
            {"id": "EVT-10241", "time": "11:48:03", "action": "LOGIN_FAILURE", "actor": "svc_backup", "host": "HOST-03", "ip": "172.16.2.44", "source": "Windows EVTX", "raw": "11:48:03 LOGIN_FAILURE", "confidence": 0.89},
        ],
    },
    {
        "id": "WIN-20260809-1422",
        "title": "敏感文件访问与外联",
        "severity": "critical",
        "score": 0.948,
        "start": "14:22:11",
        "end": "14:29:45",
        "status": "new",
        "eventCount": 29,
        "entities": ["Alice", "HOST-18", "archive.exe", "sensitive.dat"],
        "hosts": ["HOST-18"],
        "sourceTypes": ["Linux Audit", "Network Flow", "EDR"],
        "summary": "用户实体再次出现，并在敏感文件访问后产生新的外部网络连接。",
        "events": [
            {"id": "EVT-10418", "time": "14:22:11", "action": "FILE_READ", "actor": "Alice", "host": "HOST-18", "process": "archive.exe", "source": "Linux Audit", "raw": "14:22:11 FILE_READ", "confidence": 0.93},
            {"id": "EVT-10419", "time": "14:26:44", "action": "NETWORK_CONNECT", "host": "HOST-18", "process": "archive.exe", "ip": "91.92.18.4", "source": "Network Flow", "raw": "14:26:44 NETWORK_CONNECT", "confidence": 0.91},
        ],
    },
    {
        "id": "WIN-20260809-1427",
        "title": "外联流量突增",
        "severity": "critical",
        "score": 0.961,
        "start": "14:27:36",
        "end": "14:35:50",
        "status": "new",
        "eventCount": 58,
        "entities": ["HOST-18", "91.92.18.4", "443"],
        "hosts": ["HOST-18"],
        "sourceTypes": ["Network Flow", "Firewall"],
        "summary": "与文件访问和压缩窗口重叠，外联流量持续快速增长。",
        "events": [
            {"id": "EVT-10431", "time": "14:27:36", "action": "NETWORK_BURST", "host": "HOST-18", "ip": "91.92.18.4", "source": "Network Flow", "raw": "14:27:36 NETWORK_BURST", "confidence": 0.93},
            {"id": "EVT-10432", "time": "14:30:22", "action": "NETWORK_CONNECT", "host": "HOST-18", "ip": "91.92.18.4", "source": "Firewall", "raw": "14:30:22 NETWORK_CONNECT", "confidence": 0.9},
        ],
    },
]

_demo_investigations: list[dict[str, Any]] = [
    {
        "id": "CASE-001",
        "title": "疑似横向移动与数据访问",
        "severity": "critical",
        "status": "investigating",
        "owner": "Analyst-01",
        "createdAt": "2026-08-09 09:44",
        "windowIds": ["WIN-20260809-0321", "WIN-20260809-0935", "WIN-20260809-1422", "WIN-20260809-1427"],
        "summary": "同一用户在多个主机与长时间窗口中持续出现，行为从登录、命令执行延伸至敏感文件访问。",
    },
    {
        "id": "CASE-002",
        "title": "服务账号异常认证",
        "severity": "medium",
        "status": "investigating",
        "owner": "Analyst-02",
        "createdAt": "2026-08-09 12:02",
        "windowIds": ["WIN-20260809-1148"],
        "summary": "持续观察服务账号失败认证是否出现后续执行行为。",
    },
]

_demo_log_sources: list[dict[str, Any]] = [
    {"id": "SRC-01", "name": "Windows Server Logs", "path": "C:\\SecurityLogs\\Windows\\", "kind": "EVTX", "status": "online", "size": "12.7 GB", "lastRead": "05:27:13"},
    {"id": "SRC-02", "name": "Linux Audit", "path": "/var/log/audit/", "kind": "LOG", "status": "online", "size": "4.2 GB", "lastRead": "05:27:11"},
    {"id": "SRC-03", "name": "Firewall", "path": "/data/firewall/", "kind": "CSV", "status": "online", "size": "21.4 GB", "lastRead": "05:27:09"},
    {"id": "SRC-04", "name": "EDR Backup", "path": "/mnt/edr/", "kind": "JSONL", "status": "warning", "size": "8.9 GB", "lastRead": "05:19:41"},
]

_demo_knowledge_docs: list[dict[str, Any]] = [
    {"id": "KB-01", "name": "Windows_Event_ID.md", "category": "运维知识", "kind": "Markdown", "status": "indexed", "chunks": 317, "updatedAt": "2026-08-09"},
    {"id": "KB-02", "name": "Network_Architecture.pdf", "category": "组织环境", "kind": "PDF", "status": "indexed", "chunks": 84, "updatedAt": "2026-08-08"},
    {"id": "KB-03", "name": "Asset_List.csv", "category": "组织环境", "kind": "CSV", "status": "indexed", "chunks": 126, "updatedAt": "2026-08-09"},
    {"id": "KB-04", "name": "MITRE_ATTACK.md", "category": "攻击知识", "kind": "Markdown", "status": "indexed", "chunks": 503, "updatedAt": "2026-08-07"},
]


def _api_headers(request: ApiLogSourceRequest) -> dict[str, str]:
    if not request.token:
        return {}
    if request.authType == "bearer":
        return {"Authorization": f"Bearer {request.token}"}
    if request.authType == "api-key":
        return {"X-API-Key": request.token}
    return {}


def _test_api_endpoint(request: ApiLogSourceRequest) -> dict[str, Any]:
    if not request.endpoint.startswith(("http://", "https://")):
        return {"ok": False, "message": "API 地址必须使用 http:// 或 https://。"}
    method = request.method.upper()
    if method not in {"GET", "POST"}:
        return {"ok": False, "message": "仅支持 GET 或 POST 请求。"}
    try:
        probe = urllib.request.Request(request.endpoint, method=method, headers=_api_headers(request))
        with urllib.request.urlopen(probe, timeout=5) as response:
            status = int(response.status)
        return {"ok": 200 <= status < 400, "message": f"API 后端连通，HTTP {status}。"}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "message": f"API 已响应，但返回 HTTP {exc.code}。"}
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"ok": False, "message": f"无法连接 API：{reason}"}


def _provider_configured() -> bool:
    return _runtime_openai_configured or bool(os.getenv("OPENAI_API_KEY"))


def _provider_source() -> str:
    # A runtime key intentionally overrides a possibly stale environment key/client.
    if _runtime_openai_configured:
        return "runtime-memory"
    if os.getenv("OPENAI_API_KEY"):
        return "environment"
    return "none"


def _safe_agent_error(exc: Exception) -> tuple[str, str]:
    """Return a user-safe error code/message without leaking keys, prompts or tracebacks."""
    name = type(exc).__name__.lower()
    text = str(exc).lower()

    if "authentication" in name or "authentication" in text or "401" in text or "invalid api key" in text:
        return "AUTH_FAILED", "模型服务认证失败，请检查 API Key 是否有效。"
    if "permission" in name or "403" in text:
        return "PERMISSION_DENIED", "当前 API Key 没有访问所配置模型的权限。"
    if "ratelimit" in name or "rate limit" in text or "429" in text:
        return "RATE_LIMITED", "模型服务当前触发限流，请稍后重试。"
    if "notfound" in name or "model_not_found" in text or "model not found" in text or "404" in text:
        return "MODEL_NOT_FOUND", "模型不可用或当前 API Key 无该模型权限，请检查模型配置。"
    if "timeout" in name or "timed out" in text:
        return "MODEL_TIMEOUT", "模型服务响应超时，请稍后重试。"
    if "connection" in name or "connection" in text:
        return "MODEL_CONNECTION_FAILED", "Agent 后端已运行，但无法连接模型服务。"
    return "AGENT_FAILED", f"Agent 执行失败：{type(exc).__name__}"


def _dashboard_data_root() -> Path | None:
    root = os.getenv("WAD_AGENT_DATA_DIR")
    if not root:
        return None
    path = Path(root)
    return path if path.exists() else None


def _mock_dashboard_enabled() -> bool:
    return os.getenv("WAD_AGENT_USE_MOCKS", "false").lower() == "true"


def _load_dashboard_collection(filename: str, fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    root = _dashboard_data_root()
    if root:
        path = root / filename
        if path.exists():
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload if isinstance(payload, list) else []
    if _mock_dashboard_enabled():
        return fallback
    raise HTTPException(status_code=503, detail=f"{filename} 尚未配置。请设置 WAD_AGENT_DATA_DIR，或显式启用 WAD_AGENT_USE_MOCKS=true。")


@app.get("/api/agent/health")
async def health() -> dict[str, Any]:
    ingestion = ingestion_store.manifest()
    return {
        "ok": True,
        "openai_configured": _provider_configured(),
        "provider_source": _provider_source(),
        "provider": _runtime_provider if _runtime_provider != "none" else "openai",
        "model": _runtime_model or os.getenv("WAD_GENERAL_MODEL", "gpt-4o-mini"),
        "base_url": _runtime_base_url,
        "repository_type": type(runtime.repository).__name__,
        "modes": ["auto", "security", "knowledge", "general"],
        "production_mock_fallback": False,
        "ingestion_pipeline": ingestion["pipeline"],
        "ingestion_counts": ingestion["counts"],
        "labels_used_for_detection": ingestion["labels_used_for_detection"],
        "knowledge_base": knowledge_manifest(),
    }


@app.get("/api/windows")
async def list_windows() -> list[dict[str, Any]]:
    try:
        persisted = _load_dashboard_collection("windows.json", _demo_windows)
    except HTTPException as error:
        if error.status_code != 503:
            raise
        persisted = []
    return [*persisted, *ingestion_store.snapshot(event_limit=1)["windows"]]


@app.get("/api/investigations")
async def list_investigations() -> list[dict[str, Any]]:
    try:
        persisted = _load_dashboard_collection("investigations.json", _demo_investigations)
    except HTTPException as error:
        if error.status_code != 503:
            raise
        persisted = []
    return [*persisted, *ingestion_store.snapshot(event_limit=1)["investigations"]]


@app.get("/api/knowledge/documents")
async def list_knowledge_documents() -> list[dict[str, Any]]:
    try:
        external = _load_dashboard_collection("knowledge_documents.json", _demo_knowledge_docs)
    except HTTPException as error:
        if error.status_code != 503:
            raise
        external = []
    project = knowledge_document_catalog()
    project_ids = {entry["id"] for entry in project}
    return [*project, *(item for item in external if str(item.get("id", "")) not in project_ids)]


@app.post("/api/knowledge/search")
async def search_knowledge(request: KnowledgeSearchRequest) -> dict[str, Any]:
    result = await runtime.repository.search_knowledge(request.query, request.top_k, request.scope)
    if not result.ok:
        return {"documents": [], "count": 0, "retrieval": "hybrid_lexical_cjk_v1", "message": result.message}
    data = result.data if isinstance(result.data, dict) else {"documents": []}
    documents = data.get("documents", [])
    return {
        "documents": documents,
        "count": len(documents),
        "retrieval": data.get("retrieval", "hybrid_lexical_cjk_v1"),
        "evidence_refs": result.evidence_refs,
    }


@app.post("/api/settings/log-sources/test")
async def test_log_source(request: ApiLogSourceRequest) -> dict[str, Any]:
    return await asyncio.to_thread(_test_api_endpoint, request)


@app.get("/api/settings/log-sources")
async def list_log_sources() -> list[dict[str, Any]]:
    try:
        base_sources = _load_dashboard_collection("log_sources.json", _demo_log_sources)
    except HTTPException as error:
        if error.status_code != 503:
            raise
        base_sources = []
    return [*base_sources, *ingestion_store.snapshot(event_limit=1)["sources"], *_api_log_sources]


@app.post("/api/settings/log-sources")
async def create_log_source(request: ApiLogSourceRequest) -> dict[str, Any]:
    result = await asyncio.to_thread(_test_api_endpoint, request)
    source = {
        "id": f"SRC-API-{len(_api_log_sources) + 1:04d}",
        "name": request.name,
        "path": request.endpoint,
        "kind": "API",
        "status": "online" if result["ok"] else "offline",
        "size": "0 B",
        "lastRead": datetime.now(timezone.utc).isoformat(),
    }
    _api_log_sources.append(source)
    return source


@app.post("/api/security/logs/search")
async def search_security_logs(request: SecurityLogSearchRequest) -> dict[str, Any]:
    uploaded = await asyncio.to_thread(
        ingestion_store.search,
        entities=request.entities,
        source_types=request.source_types,
        keywords=request.keywords,
        start_time=request.start_time,
        end_time=request.end_time,
        limit=request.limit,
    )
    result = await runtime.repository.search_logs(
        entities=request.entities,
        source_types=request.source_types,
        keywords=request.keywords,
        start_time=request.start_time,
        end_time=request.end_time,
        limit=request.limit,
    )
    repository_events = result.data.get("events", []) if result.ok and isinstance(result.data, dict) else []
    events = [*uploaded["events"], *repository_events]
    events.sort(key=lambda item: str(item.get("timestamp", item.get("time", ""))), reverse=True)
    deduplicated = list({str(item.get("event_id", item.get("id", index))): item for index, item in enumerate(events)}.values())[:request.limit]
    if not deduplicated and not result.ok:
        raise HTTPException(status_code=404, detail=result.message or "日志查询失败。")
    return {"events": deduplicated, "count": len(deduplicated)}


@app.post("/api/ingest/files")
async def ingest_file(request: IngestFileRequest) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(
            ingestion_store.ingest_base64,
            request.filename,
            request.content_base64,
            request.content_type,
        )
    except (ValueError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/api/ingest/snapshot")
async def ingestion_snapshot(event_limit: int = 5000) -> dict[str, Any]:
    return await asyncio.to_thread(ingestion_store.snapshot, event_limit)


@app.get("/api/ingest/jobs")
async def ingestion_jobs() -> list[dict[str, Any]]:
    return (await asyncio.to_thread(ingestion_store.snapshot, 1))["jobs"]


@app.delete("/api/ingest/sources/{source_id}")
async def delete_ingested_source(source_id: str) -> dict[str, Any]:
    result = await asyncio.to_thread(ingestion_store.delete_source, source_id)
    if result is None:
        raise HTTPException(status_code=404, detail="上传数据源不存在或已经删除。")
    return result


@app.get("/api/detection/manifest")
async def detection_manifest() -> dict[str, Any]:
    return await asyncio.to_thread(ingestion_store.manifest)


@app.get("/api/log-index/overview")
async def log_index_overview(time_range: str = "7d") -> dict[str, Any]:
    snapshot = await asyncio.to_thread(ingestion_store.snapshot, 20_000)
    events = snapshot["events"]
    hours = 24 if time_range == "24h" else 1 if time_range == "1h" else 24 * 7 if time_range == "7d" else 24 * 30
    parsed_times: list[datetime] = []
    for event in events:
        try:
            parsed_times.append(datetime.fromisoformat(str(event.get("timestamp", "")).replace("Z", "+00:00")))
        except ValueError:
            pass
    cutoff = max(parsed_times) - timedelta(hours=hours) if parsed_times else None
    buckets: dict[str, dict[str, Any]] = {}
    visible = []
    for event in events:
        try:
            timestamp = datetime.fromisoformat(str(event.get("timestamp", "")).replace("Z", "+00:00"))
        except ValueError:
            timestamp = None
        if cutoff and timestamp and timestamp < cutoff:
            continue
        visible.append(event)
        key = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:00") if timestamp else "unknown"
        bucket = buckets.setdefault(key, {"time": key, "logs": 0, "anomalies": 0})
        bucket["logs"] += 1
        if float(event.get("score", 0)) >= 0.55:
            bucket["anomalies"] += 1
    return {
        "time_range": time_range,
        "event_count": snapshot["event_count"],
        "visible_count": len(visible),
        "series": sorted(buckets.values(), key=lambda item: item["time"]),
        "scope": "realtime_upload_store_only",
    }


@app.get("/api/scale/report")
async def scale_report() -> dict[str, Any]:
    jobs = (await asyncio.to_thread(ingestion_store.snapshot, 1))["jobs"]
    total_events = sum(int(job.get("event_count", 0)) for job in jobs)
    total_bytes = sum(int(job.get("size", 0)) for job in jobs)
    total_duration = sum(float(job.get("duration_seconds", 0)) for job in jobs)
    return {
        "scope": "small_file_functional_measurement",
        "jobs": len(jobs),
        "bytes_processed": total_bytes,
        "events_processed": total_events,
        "duration_seconds": round(total_duration, 4),
        "observed_events_per_second": round(total_events / total_duration, 2) if total_duration else 0,
        "tb_processed": False,
        "tb_claim": "未进行 TB 实测；不得将小文件吞吐直接宣称为 TB 处理结果。",
    }


@app.get("/api/evaluation/report")
async def evaluation_report() -> dict[str, Any]:
    manifest = await asyncio.to_thread(ingestion_store.manifest)
    return {
        "formal_evaluation": False,
        "labels_used_for_detection": False,
        "prediction_count": manifest["counts"]["events"],
        "reason": "文件接入事件流不读取真实标签；需在预测冻结后提供独立标签文件才能计算召回率和误报率。",
        "metrics": None,
    }


@app.get("/api/security/entities/{entity_id}")
async def get_security_entity(entity_id: str) -> dict[str, Any]:
    result = await runtime.repository.get_entity(entity_id)
    if not result.ok:
        raise HTTPException(status_code=404, detail=result.message or f"未找到实体 {entity_id}。")
    return result.data if isinstance(result.data, dict) else {}


@app.get("/api/security/entities/{entity_id}/history")
async def get_security_entity_history(entity_id: str, time_range: str = "24h") -> dict[str, Any]:
    result = await runtime.repository.get_entity_history(entity_id, time_range)
    if not result.ok:
        raise HTTPException(status_code=404, detail=result.message or f"未找到实体 {entity_id} 的历史记录。")
    return result.data if isinstance(result.data, dict) else {"events": [], "count": 0}


@app.get("/api/security/entities/{entity_id}/baseline")
async def get_security_entity_baseline(entity_id: str, time_range: str = "30d") -> dict[str, Any]:
    result = await runtime.repository.get_baseline(entity_id, time_range)
    if not result.ok:
        raise HTTPException(status_code=404, detail=result.message or f"实体 {entity_id} 暂无历史基线。")
    return result.data if isinstance(result.data, dict) else {}


@app.get("/api/security/investigations/{investigation_id}")
async def get_security_investigation(investigation_id: str) -> dict[str, Any]:
    result = await runtime.repository.get_investigation(investigation_id)
    if not result.ok:
        raise HTTPException(status_code=404, detail=result.message or f"未找到 Investigation {investigation_id}。")
    return result.data if isinstance(result.data, dict) else {}


@app.post("/api/agent/provider")
async def configure_provider(request: AgentProviderRequest) -> dict[str, Any]:
    """Configure the OpenAI key for this backend process only.

    The secret is loaded into an in-memory AsyncOpenAI client and is never returned, written to
    the repository, or persisted by this service. Restarting the backend clears this runtime key.
    """
    global _runtime_openai_configured, _runtime_provider, _runtime_model, _runtime_base_url

    key = request.api_key.strip()
    if key.lower().startswith("bearer "):
        key = key[7:].strip()
    if not key.isascii():
        raise HTTPException(status_code=422, detail="API Key 只能包含 ASCII 字符，请粘贴纯 Key，不要包含中文说明或 Bearer 标签。")
    providers = {"openai", "deepseek", "qwen", "siliconflow", "custom"}
    if request.provider not in providers:
        raise HTTPException(status_code=422, detail="Unsupported model provider.")
    base_url = request.base_url.strip() if request.base_url else None
    if base_url and not base_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="Base URL must use http:// or https://.")
    if len(key) < 8:
        raise HTTPException(status_code=422, detail="API Key 格式无效。")

    # Using a fresh client makes this endpoint able to replace a stale/invalid environment client
    # even after an earlier model request has already initialized the SDK provider.
    client = AsyncOpenAI(api_key=key, base_url=base_url)
    set_default_openai_client(client, use_for_tracing=False)
    set_tracing_disabled(True)
    configure_model(request.model, client, use_chat_completions=bool(base_url or request.provider != "openai"))
    _runtime_openai_configured = True
    _runtime_provider = request.provider
    _runtime_model = request.model
    _runtime_base_url = base_url

    return {
        "ok": True,
        "openai_configured": True,
        "provider_source": "runtime-memory",
        "provider": request.provider,
        "model": request.model,
        "base_url": base_url,
        "message": "模型 API Key 已加载到 Agent 后端内存；重启后端后需要重新配置。",
    }


@app.post("/api/agent/query")
async def query(request: AgentQueryRequest):
    if not _provider_configured():
        raise HTTPException(
            status_code=503,
            detail="模型 API Key 未配置。请设置 OPENAI_API_KEY，或在 AI 分析页配置模型服务。",
        )
    try:
        return await runtime.run(request)
    except Exception as exc:
        logger.exception("agent query failed: %s", type(exc).__name__)
        code, message = _safe_agent_error(exc)
        raise HTTPException(status_code=502, detail={"code": code, "message": message}) from exc


def _sse(event_type: str, payload: dict[str, Any]) -> str:
    body = json.dumps({"type": event_type, **payload}, ensure_ascii=False)
    return f"data: {body}\n\n"


@app.post("/api/agent/query/stream")
async def query_stream(request: AgentQueryRequest):
    if not _provider_configured():
        raise HTTPException(
            status_code=503,
            detail="模型 API Key 未配置。请设置 OPENAI_API_KEY，或在 AI 分析页配置模型服务。",
        )

    async def events():
        try:
            decision = await runtime.resolve_mode(request)
        except Exception as exc:
            code, message = _safe_agent_error(exc)
            yield _sse("error", {"code": code, "message": message})
            return

        yield _sse(
            "route",
            {
                "mode": decision.mode,
                "confidence": decision.confidence,
                "reason_code": decision.reason_code,
            },
        )

        status_queue: asyncio.Queue[str] = asyncio.Queue()

        async def status_callback(label: str) -> None:
            await status_queue.put(label)

        task = asyncio.create_task(
            runtime.run(request, decision=decision, status_callback=status_callback)
        )

        try:
            while not task.done() or not status_queue.empty():
                try:
                    label = await asyncio.wait_for(status_queue.get(), timeout=0.2)
                    yield _sse("status", {"label": label})
                except TimeoutError:
                    continue

            result = await task
            for evidence in result.evidence:
                yield _sse("citation", evidence.model_dump())
            yield _sse("final", result.model_dump())
        except Exception as exc:
            if not task.done():
                task.cancel()
            logger.exception("agent stream failed: %s", type(exc).__name__)
            code, message = _safe_agent_error(exc)
            yield _sse("error", {"code": code, "message": message})

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/assistant/query")
async def legacy_query(request: LegacyAssistantRequest):
    """Backward-compatible bridge for the first frontend assistant endpoint."""
    context = request.context or {}
    normalized = AgentQueryRequest(
        conversation_id=str(context.get("conversation_id") or "legacy-default"),
        mode="auto",
        message=request.question,
        context=AgentRequestContext(
            finding_ids=list(context.get("windowIds") or context.get("finding_ids") or []),
            investigation_id=context.get("caseId") or context.get("investigation_id"),
            entity_ids=list(context.get("entityIds") or context.get("entity_ids") or []),
            time_range=context.get("time_range"),
            evidence_snapshot=context.get("evidenceSnapshot") or context.get("evidence_snapshot"),
        ),
    )
    response = await query(normalized)
    return {
        "answer": response.answer,
        "evidence": [e.model_dump() for e in response.evidence],
        "mode": response.mode,
        "run_id": response.run_id,
    }
