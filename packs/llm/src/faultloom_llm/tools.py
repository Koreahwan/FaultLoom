from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self, assert_never

from pydantic import Field, model_validator

from faultloom_protocol import (
    ActionClass,
    ActionIntent,
    ActionLease,
    ResourceRef,
    ScopeEpoch,
    StateRef,
    SubjectRef,
    sha256_digest,
)
from faultloom_protocol.base import AwareDatetime, Identifier, NonEmptyStr, Sha256Digest, ShortStr

from ._base import LlmPackModel
from .errors import LlmPackError


class ToolTransport(StrEnum):
    MCP = "mcp"
    AGENT_LOCAL = "agent_local"


class ToolDescriptor(LlmPackModel):
    tool_id: Identifier
    action_kind: Identifier
    action_class: ActionClass
    target_id: Identifier
    resource_id: Identifier
    resource_kind: Identifier
    transport: ToolTransport
    method: ShortStr
    path: NonEmptyStr

    @model_validator(mode="after")
    def _supports_v01_action(self) -> Self:
        match self.action_class:
            case ActionClass.OBSERVE | ActionClass.SAFE_PROBE | ActionClass.STATE_CHANGE:
                pass
            case ActionClass.HIGH_LOAD | ActionClass.DESTRUCTIVE:
                raise LlmPackError(
                    "llm.tool_action_unsupported",
                    "high-load and destructive agent tools are unsupported",
                )
            case unreachable:
                assert_never(unreachable)
        return self


class ToolPolicy(LlmPackModel):
    policy_id: Identifier
    pack_id: Literal["pack.llm.agent"] = "pack.llm.agent"
    descriptors: tuple[ToolDescriptor, ...] = Field(min_length=1)
    allowed_identity_ids: tuple[Identifier, ...] = Field(min_length=1)
    allowed_tenant_ids: tuple[Identifier, ...] = Field(min_length=1)
    scope_epoch: int = Field(ge=1)

    @model_validator(mode="after")
    def _allowlists_are_unique(self) -> Self:
        collections = (
            tuple(item.tool_id for item in self.descriptors),
            tuple(item.action_kind for item in self.descriptors),
            self.allowed_identity_ids,
            self.allowed_tenant_ids,
        )
        if any(len(values) != len(set(values)) for values in collections):
            raise LlmPackError(
                "llm.tool_allowlist_duplicate",
                "tool, action, identity, and tenant allowlists must be unique",
            )
        return self


class AgentToolRequest(LlmPackModel):
    request_id: Identifier
    run_id: Identifier
    tool_id: Identifier
    subject: SubjectRef
    payload_digest: Sha256Digest
    requested_at: AwareDatetime
    input_state: StateRef | None = None
    parent_action_ids: tuple[Identifier, ...] = ()
    canary_ref: Identifier | None = None
    checkpoint_ref: Identifier | None = None
    cleanup_plan_ref: Identifier | None = None


class CompiledToolAction(LlmPackModel):
    intent: ActionIntent
    compiler_id: Literal["llm.agent_tool_compiler.v1"] = "llm.agent_tool_compiler.v1"
    requires_action_lease: Literal[True] = True
    direct_dispatch_permitted: Literal[False] = False


class LeaseBindingRequest(LlmPackModel):
    compiled: CompiledToolAction
    lease: ActionLease
    scope_epoch: ScopeEpoch
    evaluated_at: AwareDatetime


class LeasedToolAction(LlmPackModel):
    compiled: CompiledToolAction
    lease_id: Identifier
    correlation_id: Identifier
    scope_epoch: int = Field(ge=1)
    gateway_dispatch_required: Literal[True] = True
    direct_dispatch_permitted: Literal[False] = False


class ToolActionCompiler:
    def __init__(self, policy: ToolPolicy) -> None:
        self._policy = policy

    def compile(self, request: AgentToolRequest) -> CompiledToolAction:
        descriptor = self._descriptor(request.tool_id)
        identity_id = request.subject.identity_id
        tenant_id = request.subject.tenant_id
        if identity_id not in self._policy.allowed_identity_ids:
            raise LlmPackError(
                "llm.tool_identity_denied",
                "agent tool identity is absent from the allowlist",
            )
        if tenant_id not in self._policy.allowed_tenant_ids:
            raise LlmPackError(
                "llm.tool_tenant_denied",
                "agent tool tenant is absent from the allowlist",
            )
        resource = ResourceRef(
            schema_version="0.1.0",
            resource_id=descriptor.resource_id,
            resource_kind=descriptor.resource_kind,
            target_id=descriptor.target_id,
            tenant_id=tenant_id,
        )
        intent = ActionIntent(
            schema_version="0.1.0",
            action_id=request.request_id,
            run_id=request.run_id,
            target_id=descriptor.target_id,
            pack_id=self._policy.pack_id,
            action_kind=descriptor.action_kind,
            action_class=descriptor.action_class,
            subject=request.subject,
            resource=resource,
            state=request.input_state,
            protocol=descriptor.transport.value,
            method=descriptor.method,
            path=descriptor.path,
            payload_digest=request.payload_digest,
            requested_at=request.requested_at,
            parent_action_ids=request.parent_action_ids,
            canary_ref=request.canary_ref,
            checkpoint_ref=request.checkpoint_ref,
            cleanup_plan_ref=request.cleanup_plan_ref,
        )
        return CompiledToolAction(intent=intent)

    def admit(self, request: LeaseBindingRequest) -> LeasedToolAction:
        intent = request.compiled.intent
        lease = request.lease
        epoch = request.scope_epoch
        if epoch.revoked:
            raise LlmPackError(
                "llm.scope_revoked",
                "revoked scope cannot admit an agent tool action",
            )
        if epoch.epoch != self._policy.scope_epoch or lease.scope_epoch != epoch.epoch:
            raise LlmPackError(
                "llm.scope_epoch_mismatch",
                "tool policy, scope epoch, and ActionLease must match",
            )
        if lease.grant_id != epoch.grant_id:
            raise LlmPackError(
                "llm.scope_grant_mismatch",
                "ActionLease belongs to another authority grant",
            )
        expected = (
            intent.action_id,
            sha256_digest(intent),
            intent.target_id,
            intent.subject.identity_id,
            intent.subject.tenant_id,
            intent.action_kind,
            intent.payload_digest,
        )
        observed = (
            lease.action_id,
            lease.intent_digest,
            lease.target_id,
            lease.identity_id,
            lease.tenant_id,
            lease.action_kind,
            lease.semantic_action_digest,
        )
        if expected != observed:
            raise LlmPackError(
                "llm.action_lease_mismatch",
                "ActionLease fields differ from the compiled agent tool intent",
            )
        if not (
            lease.issued_at <= request.evaluated_at < lease.expires_at
            and epoch.issued_at <= request.evaluated_at < epoch.expires_at
        ):
            raise LlmPackError(
                "llm.action_lease_expired",
                "agent tool lease or scope epoch is not active",
            )
        return LeasedToolAction(
            compiled=request.compiled,
            lease_id=lease.lease_id,
            correlation_id=lease.correlation_id,
            scope_epoch=epoch.epoch,
        )

    def _descriptor(self, tool_id: str) -> ToolDescriptor:
        for descriptor in self._policy.descriptors:
            if descriptor.tool_id == tool_id:
                return descriptor
        raise LlmPackError(
            "llm.tool_not_allowlisted",
            "agent-selected tool is absent from the allowlist",
        )
