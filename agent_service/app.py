from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .models import AgentQueryRequest, AgentRequestContext
from .runtime import AgentRuntime

app = FastAPI(title="链影寻踪 Agent Service", version="1.0")

allowed_origins = [
    origin.strip()
    for origin in os.getenv("WAD_AGENT_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
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


class LegacyAssistantRequest(BaseModel):
    question: str
    context: dict[str, Any] = Field(default_factory=dict)


@app.get("/api/agent/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "openai_configured": bool(os.getenv("OPENAI_API_KEY")),
        "repository": type(runtime.repository).__name__,
        "modes": ["auto", "security", "knowledge", "general"],
        "production_mock_fallback": False,
    }


@app.post("/api/agent/query")
async def query(request: AgentQueryRequest):
    if not os.getenv("OPENAI_API_KEY"):
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY 未在 Agent 服务端配置。")
    try:
        return await runtime.run(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Agent 执行失败：{type(exc).__name__}") from exc


def _sse(event_type: str, payload: dict[str, Any]) -> str:
    body = json.dumps({"type": event_type, **payload}, ensure_ascii=False)
    return f"data: {body}\n\n"


@app.post("/api/agent/query/stream")
async def query_stream(request: AgentQueryRequest):
    if not os.getenv("OPENAI_API_KEY"):
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY 未在 Agent 服务端配置。")

    async def events():
        decision = await runtime.resolve_mode(request)
        yield _sse("route", {"mode": decision.mode, "confidence": decision.confidence, "reason_code": decision.reason_code})

        status_queue: asyncio.Queue[str] = asyncio.Queue()

        async def status_callback(label: str) -> None:
            await status_queue.put(label)

        task = asyncio.create_task(runtime.run(request, decision=decision, status_callback=status_callback))

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
            yield _sse("error", {"message": f"Agent 执行失败：{type(exc).__name__}"})

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
