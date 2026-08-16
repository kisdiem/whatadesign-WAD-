from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

AgentMode = Literal["auto", "security", "knowledge", "general"]
ResolvedMode = Literal["security", "knowledge", "general"]


class AgentRequestContext(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)
    investigation_id: str | None = None
    entity_ids: list[str] = Field(default_factory=list)
    time_range: str | None = None


class AgentQueryRequest(BaseModel):
    conversation_id: str
    mode: AgentMode = "auto"
    message: str = Field(min_length=1, max_length=12000)
    context: AgentRequestContext = Field(default_factory=AgentRequestContext)


class RouterDecision(BaseModel):
    mode: ResolvedMode
    confidence: float = Field(ge=0, le=1)
    reason_code: str


class EvidenceRef(BaseModel):
    label: str
    ref: str
    source: str | None = None


class ToolEvent(BaseModel):
    tool: str
    ok: bool
    message: str
    evidence_refs: list[str] = Field(default_factory=list)


class StructuredItem(BaseModel):
    text: str
    evidence_ids: list[str] = Field(default_factory=list)


class StructuredAnalysis(BaseModel):
    facts: list[StructuredItem] = Field(default_factory=list)
    assessments: list[StructuredItem] = Field(default_factory=list)
    uncertainties: list[StructuredItem] = Field(default_factory=list)
    recommended_queries: list[StructuredItem] = Field(default_factory=list)


class VerificationSummary(BaseModel):
    totalItems: int = 0
    verifiedItems: int = 0
    downgradedItems: int = 0


class AgentQueryResponse(BaseModel):
    run_id: str
    conversation_id: str
    requested_mode: AgentMode
    mode: ResolvedMode
    answer: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    tool_events: list[ToolEvent] = Field(default_factory=list)
    verified: bool = False
    confidence: float | None = None
    structured: StructuredAnalysis | None = None
    verification_summary: VerificationSummary | None = None


class SecurityDraft(BaseModel):
    answer: str
    claims: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    structured: StructuredAnalysis = Field(default_factory=StructuredAnalysis)


class VerificationResult(BaseModel):
    supported: list[str] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class RepositoryResult(BaseModel):
    ok: bool
    data: Any = None
    message: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
