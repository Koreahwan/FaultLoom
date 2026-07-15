from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from faultloom_protocol import (
    ActionClass,
    EvidenceRef,
    ObservationRef,
    ScopeEpoch,
    SubjectRef,
)
from faultloom_llm import (
    AgentToolRequest,
    ContentSource,
    PromptSelection,
    PromptTrace,
    RetrievalDocument,
    RetrievalIndex,
    RetrievalQuery,
    RetrievalTraceRequest,
    ToolActionCompiler,
    ToolDescriptor,
    ToolPolicy,
    ToolTransport,
    UntrustedContent,
)

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
D1 = "sha256:" + "11" * 32
D2 = "sha256:" + "22" * 32
D3 = "sha256:" + "33" * 32
D4 = "sha256:" + "44" * 32
D5 = "sha256:" + "55" * 32
D6 = "sha256:" + "66" * 32
D7 = "sha256:" + "77" * 32


@dataclass(frozen=True, slots=True)
class LlmAgentFixture:
    subject: SubjectRef
    web_content: UntrustedContent
    prompt_evidence: EvidenceRef
    documents: tuple[RetrievalDocument, ...]
    query: RetrievalQuery
    tool_policy: ToolPolicy
    tool_request: AgentToolRequest
    active_epoch: ScopeEpoch
    revoked_epoch: ScopeEpoch

    def harness_parts(self) -> tuple[RetrievalIndex, ToolActionCompiler]:
        return RetrievalIndex(self.documents), ToolActionCompiler(self.tool_policy)


def llm_agent_fixture() -> LlmAgentFixture:
    web_observation = _observation("observation.web.untrusted", D1)
    web_content = UntrustedContent(
        content_id="content.web.untrusted",
        run_id="run.llm.lab",
        tenant_id="tenant.alpha",
        source=ContentSource.WEB_INPUT,
        content_digest=D1,
        source_observation=web_observation,
    )
    subject = SubjectRef(
        schema_version="0.1.0",
        subject_id="subject.web.user",
        subject_kind="operator_test_identity",
        identity_id="identity.alpha",
        tenant_id="tenant.alpha",
    )
    descriptor = ToolDescriptor(
        tool_id="tool.mcp.canary_read",
        action_kind="llm.tool.safe_probe",
        action_class=ActionClass.SAFE_PROBE,
        target_id="target.llm.loopback",
        resource_id="resource.mcp.canary",
        resource_kind="inert_canary",
        transport=ToolTransport.MCP,
        method="CALL",
        path="/mcp/canary/read",
    )
    policy = ToolPolicy(
        policy_id="policy.llm.lab",
        descriptors=(descriptor,),
        allowed_identity_ids=("identity.alpha",),
        allowed_tenant_ids=("tenant.alpha",),
        scope_epoch=7,
    )
    return LlmAgentFixture(
        subject=subject,
        web_content=web_content,
        prompt_evidence=_evidence("evidence.prompt", web_observation),
        documents=(
            _document("alpha", "tenant.alpha", D2),
            _document("beta", "tenant.beta", D3),
        ),
        query=RetrievalQuery(
            query_id="query.alpha",
            run_id="run.llm.lab",
            tenant_id="tenant.alpha",
            collection_id="collection.knowledge",
            query_digest=D4,
        ),
        tool_policy=policy,
        tool_request=AgentToolRequest(
            request_id="action.llm.tool",
            run_id="run.llm.lab",
            tool_id=descriptor.tool_id,
            subject=subject,
            payload_digest=D5,
            requested_at=NOW,
            parent_action_ids=("action.web.submit",),
        ),
        active_epoch=ScopeEpoch(
            schema_version="0.1.0",
            grant_id="grant.llm.lab",
            epoch=7,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        ),
        revoked_epoch=ScopeEpoch(
            schema_version="0.1.0",
            grant_id="grant.llm.lab",
            epoch=8,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            revoked=True,
            revocation_reason="operator revoke fixture",
        ),
    )


def prompt_trace(fixture: LlmAgentFixture, selected: bool) -> PromptTrace:
    return PromptTrace(
        trace_id="trace.prompt.selected" if selected else "trace.prompt.rejected",
        content=fixture.web_content,
        selection=(
            PromptSelection.TOOL_SELECTED if selected else PromptSelection.TOOL_REJECTED
        ),
        tool_request_id=fixture.tool_request.request_id if selected else None,
        evidence_refs=(fixture.prompt_evidence,),
    )


def foreign_retrieval_request(fixture: LlmAgentFixture) -> RetrievalTraceRequest:
    return RetrievalTraceRequest(
        query=fixture.query,
        selected_document_ids=("document.beta",),
    )


def _document(label: str, tenant_id: str, digest: str) -> RetrievalDocument:
    observation = _observation(f"observation.rag.{label}", digest)
    return RetrievalDocument(
        document_id=f"document.{label}",
        collection_id="collection.knowledge",
        tenant_id=tenant_id,
        content=UntrustedContent(
            content_id=f"content.rag.{label}",
            run_id="run.llm.lab",
            tenant_id=tenant_id,
            source=ContentSource.RAG_DOCUMENT,
            content_digest=digest,
            source_observation=observation,
        ),
    )


def _observation(observation_id: str, digest: str) -> ObservationRef:
    return ObservationRef(
        schema_version="0.1.0",
        observation_id=observation_id,
        run_id="run.llm.lab",
        cas_digest=digest,
        media_type="application/json",
        byte_length=32,
        created_at=NOW,
    )


def _evidence(evidence_id: str, observation: ObservationRef) -> EvidenceRef:
    return EvidenceRef(
        schema_version="0.1.0",
        evidence_id=evidence_id,
        run_id=observation.run_id,
        cas_digest=observation.cas_digest,
        observation_ids=(observation.observation_id,),
        created_at=NOW,
    )
