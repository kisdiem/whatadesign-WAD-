from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from agents import set_default_openai_client, set_tracing_disabled
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from .models import AgentQueryRequest, AgentRequestContext
from .runtime import AgentRuntime

app = FastAPI(title="链影寻踪 Agent Service", version="1.0")

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "WAD_AGENT_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
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


@app.get("/api/agent/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "openai_configured": _provider_configured(),
        "provider_source": _provider_source(),
        "repository": type(runtime.repository).__name__,
        "modes": ["auto", "security", "knowledge", "general"],
        "production_mock_fallback": False,
    }


@app.post("/api/agent/provider")
async def configure_provider(request: AgentProviderRequest) -> dict[str, Any]:
    """Configure the OpenAI key for this backend process only.

    The secret is loaded into an in-memory AsyncOpenAI client and is never returned, written to
    the repository, or persisted by this service. Restarting the backend clears this runtime key.
    """
    global _runtime_openai_configured

    key = request.api_key.strip()
    if len(key) < 8:
        raise HTTPException(status_code=422, detail="API Key 格式无效。")

    # Using a fresh client makes this endpoint able to replace a stale/invalid environment client
    # even after an earlier model request has already initialized the SDK provider.
    client = AsyncOpenAI(api_key=key)
    set_default_openai_client(client, use_for_tracing=False)
    set_tracing_disabled(True)
    _runtime_openai_configured = True

    return {
        "ok": True,
        "openai_configured": True,
        "provider_source": "runtime-memory",
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
        ),
    )
    response = await query(normalized)
    return {
        "answer": response.answer,
        "evidence": [e.model_dump() for e in response.evidence],
        "mode": response.mode,
        "run_id": response.run_id,
    }
