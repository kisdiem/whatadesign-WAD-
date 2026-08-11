from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

from agents import Agent, ModelSettings, Runner, SQLiteSession
from openai.types.shared import Reasoning

from .models import (
    AgentQueryRequest,
    AgentQueryResponse,
    EvidenceRef,
    RouterDecision,
    SecurityDraft,
    VerificationResult,
)
from .repository import SecurityRepository, build_repository
from .tools import AgentContext, KNOWLEDGE_TOOLS, SECURITY_TOOLS

ROUTER_MODEL = os.getenv("WAD_ROUTER_MODEL", "gpt-5.4-mini")
ANALYST_MODEL = os.getenv("WAD_ANALYST_MODEL", "gpt-5.6-sol")
GENERAL_MODEL = os.getenv("WAD_GENERAL_MODEL", "gpt-5.4-mini")
VERIFIER_MODEL = os.getenv("WAD_VERIFIER_MODEL", "gpt-5.6-sol")
SESSION_DB = os.getenv("WAD_AGENT_SESSION_DB", "run_state/agent_sessions.db")

STRONG_SECURITY_MARKERS = re.compile(
    r"(HOST[-_]?\w+|CASE[-_]?\w+|WIN[-_]?\w+|EVT[-_]?\w+|finding|investigation|"
    r"当前|最近|这个事件|该事件|这个告警|该告警|该用户|这个用户|该IP|这个IP|"
    r"风险分|风险评分|攻击链|查询日志|查日志|分析日志|异常日志|告警详情|本系统|我们的系统|"
    r"是否被入侵|是否入侵|有没有异常|有什么异常|为什么高风险|为什么风险)",
    re.IGNORECASE,
)
KNOWLEDGE_MARKERS = re.compile(
    r"(什么是|是什么意思|解释一下|概念|原理|定义|MITRE|ATT&CK|T\d{4}(?:\.\d{3})?|"
    r"4625|4624|Kerberos|横向移动|凭据访问|PowerShell|日志是什么|主机是什么)",
    re.IGNORECASE,
)
HIGH_RISK_MARKERS = re.compile(r"(入侵|攻击|攻陷|横向移动|数据泄露|外泄|隔离|封禁|处置)", re.IGNORECASE)


def _settings(effort: str, verbosity: str = "low") -> ModelSettings:
    return ModelSettings(reasoning=Reasoning(effort=effort), verbosity=verbosity, truncation="auto")


router_agent = Agent(
    name="WAD Mode Router",
    model=ROUTER_MODEL,
    model_settings=_settings("none", "low"),
    output_type=RouterDecision,
    instructions=(
        "Classify exactly one user message for a security operations assistant. "
        "security = requires facts from the current WAD environment, logs, Findings, Investigations, entities, risk or timelines. "
        "knowledge = security/domain knowledge that does not require current environment facts. "
        "general = ordinary conversation or writing. Return only the structured decision."
    ),
)

security_agent = Agent[AgentContext](
    name="WAD Security Analyst",
    model=ANALYST_MODEL,
    model_settings=_settings("high", "medium"),
    tools=SECURITY_TOOLS,
    output_type=SecurityDraft,
    instructions=(
        "You are the evidence-grounded security analyst for 链影寻踪. "
        "For any claim about the current environment you MUST call at least one internal security tool before answering. "
        "Prefer persisted Finding/Investigation/entity results before raw logs. Use 24h as the default event context, "
        "expand to 7d only for high-risk/cross-host/incomplete cases, and use 30d baseline only as aggregated behavior context. "
        "Never invent logs, entities, baselines or attack steps. If a tool is unavailable, say which evidence is missing. "
        "Do not equate a high risk score with confirmed compromise. Distinguish observed facts, inference and uncertainty. "
        "Write a compact Chinese answer with: 结论, 主要证据, 判断依据, 建议下一步. "
        "claims must contain only the important factual/inferential claims that a verifier should check."
    ),
)

knowledge_agent = Agent[AgentContext](
    name="WAD Knowledge Analyst",
    model=ANALYST_MODEL,
    model_settings=_settings("medium", "medium"),
    tools=KNOWLEDGE_TOOLS,
    instructions=(
        "Answer security knowledge questions naturally in Chinese. Always call knowledge_search first. "
        "Prefer retrieved organization/security/history knowledge. If the repository is unavailable and the question is a general public concept, "
        "you may answer from model knowledge but explicitly state that no internal knowledge-base source was available. "
        "Do not pretend current-environment facts were checked."
    ),
)

general_agent = Agent(
    name="WAD General Assistant",
    model=GENERAL_MODEL,
    model_settings=_settings("low", "medium"),
    instructions=(
        "You are the general conversation mode of 链影寻踪. Answer naturally and directly in the user's language. "
        "You have no access to internal logs, Findings, entities or Investigations. Never imply that you checked them."
    ),
)

verifier_agent = Agent(
    name="WAD Evidence Verifier",
    model=VERIFIER_MODEL,
    model_settings=_settings("high", "low"),
    output_type=VerificationResult,
    instructions=(
        "Check each proposed security claim only against the supplied evidence payload. "
        "Mark a claim supported only when the evidence actually entails it. Treat risk scores as risk scores, not proof of compromise. "
        "List contradictions explicitly. Be conservative."
    ),
)

repair_agent = Agent(
    name="WAD Verified Answer Editor",
    model=ANALYST_MODEL,
    model_settings=_settings("medium", "medium"),
    instructions=(
        "Rewrite the supplied Chinese security answer so every important claim is supported by the verifier result and evidence. "
        "Remove or downgrade unsupported claims using phrases such as '存在迹象', '与……一致', or '目前尚不能确认'. "
        "Preserve the structure: 结论, 主要证据, 判断依据, 建议下一步. Do not add new facts."
    ),
)


class AgentRuntime:
    def __init__(self, repository: SecurityRepository | None = None):
        self.repository = repository or build_repository()
        Path(SESSION_DB).parent.mkdir(parents=True, exist_ok=True)

    async def resolve_mode(self, request: AgentQueryRequest) -> RouterDecision:
        if request.mode != "auto":
            return RouterDecision(mode=request.mode, confidence=1.0, reason_code="USER_SELECTED")

        context = request.context
        if context.finding_ids or context.investigation_id or context.entity_ids:
            return RouterDecision(mode="security", confidence=1.0, reason_code="BOUND_SECURITY_CONTEXT")

        text = request.message.strip()
        if STRONG_SECURITY_MARKERS.search(text):
            return RouterDecision(mode="security", confidence=0.98, reason_code="ENVIRONMENT_QUERY_RULE")
        if KNOWLEDGE_MARKERS.search(text):
            return RouterDecision(mode="knowledge", confidence=0.96, reason_code="SECURITY_KNOWLEDGE_RULE")

        try:
            result = await Runner.run(router_agent, text, max_turns=2)
            return result.final_output
        except Exception:
            return RouterDecision(mode="general", confidence=0.5, reason_code="ROUTER_FALLBACK_GENERAL")

    def _context(self, request: AgentQueryRequest) -> AgentContext:
        return AgentContext(
            repository=self.repository,
            finding_ids=request.context.finding_ids,
            investigation_id=request.context.investigation_id,
            entity_ids=request.context.entity_ids,
            requested_time_range=request.context.time_range,
        )

    @staticmethod
    def _context_hint(request: AgentQueryRequest) -> str:
        payload = {
            "finding_ids": request.context.finding_ids,
            "investigation_id": request.context.investigation_id,
            "entity_ids": request.context.entity_ids,
            "time_range": request.context.time_range,
        }
        return json.dumps(payload, ensure_ascii=False)

    async def run(self, request: AgentQueryRequest, decision: RouterDecision | None = None) -> AgentQueryResponse:
        decision = decision or await self.resolve_mode(request)
        run_id = f"RUN-{uuid.uuid4().hex[:12].upper()}"
        context = self._context(request)
        session = SQLiteSession(request.conversation_id, SESSION_DB)
        prompt = f"用户问题：{request.message}\n当前前端安全上下文：{self._context_hint(request)}"

        if decision.mode == "security":
            result = await Runner.run(
                security_agent,
                prompt,
                context=context,
                session=session,
                max_turns=16 if (request.context.time_range == "7d" or "溯源" in request.message) else 8,
            )
            draft: SecurityDraft = result.final_output
            if not context.tool_events:
                answer = "当前问题需要读取真实安全数据，但本次 Agent 未获得任何内部工具证据，因此不生成环境事实判断。"
                verified = False
                confidence = 0.0
            else:
                needs_verification = (
                    (draft.risk_score or 0) >= 80
                    or draft.confidence < 0.75
                    or bool(HIGH_RISK_MARKERS.search(request.message + " " + draft.answer))
                )
                answer = draft.answer
                verified = False
                confidence = draft.confidence
                if needs_verification:
                    verification_input = json.dumps(
                        {"claims": draft.claims, "evidence": context.evidence_payloads},
                        ensure_ascii=False,
                    )
                    verification_run = await Runner.run(verifier_agent, verification_input, max_turns=3)
                    verification: VerificationResult = verification_run.final_output
                    verified = not verification.unsupported and not verification.contradictions
                    confidence = min(confidence, verification.confidence)
                    if not verified:
                        repair_input = json.dumps(
                            {
                                "draft": draft.answer,
                                "verification": verification.model_dump(),
                                "evidence": context.evidence_payloads,
                            },
                            ensure_ascii=False,
                        )
                        repair = await Runner.run(repair_agent, repair_input, max_turns=3)
                        answer = str(repair.final_output)

        elif decision.mode == "knowledge":
            result = await Runner.run(knowledge_agent, prompt, context=context, session=session, max_turns=6)
            answer = str(result.final_output)
            verified = bool(context.tool_events and context.tool_events[0].ok)
            confidence = decision.confidence

        else:
            result = await Runner.run(general_agent, request.message, session=session, max_turns=4)
            answer = str(result.final_output)
            verified = False
            confidence = decision.confidence

        evidence = [EvidenceRef(label=ref, ref=ref) for ref in sorted(context.evidence_refs)]
        return AgentQueryResponse(
            run_id=run_id,
            conversation_id=request.conversation_id,
            requested_mode=request.mode,
            mode=decision.mode,
            answer=answer,
            evidence=evidence,
            tool_events=context.tool_events,
            verified=verified,
            confidence=confidence,
        )
