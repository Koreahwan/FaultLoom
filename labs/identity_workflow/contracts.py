"""Versioned identity/workflow lab descriptor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    AuthSession,
    IdentityContext,
    IdentityProfile,
    IdentityRelationship,
    RoleGrant,
    TenantRef,
)
from faultloom_protocol.base import Identifier
from faultloom_web.identity_workflow import (
    AuthSemanticTrace,
    DifferentialVariant,
    WorkflowKind,
    WorkflowTrace,
)


class _LabModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


@dataclass(frozen=True, slots=True)
class LabFixtureError(ValueError):
    detail: str

    def __str__(self) -> str:
        return self.detail


class IdorFixtureCase(_LabModel):
    case_id: Identifier
    resource_id: Identifier
    resource_tenant_id: Identifier
    owner_context_id: Identifier
    outsider_context_id: Identifier


class IdentityWorkflowFixture(_LabModel):
    schema_version: Literal["0.1.0"]
    namespace: Literal["faultloom.lab.web.identity_workflow.v1"]
    fixture_id: Identifier
    fixture_version: Literal["1.0.0"]
    target_id: Identifier
    run_id: Identifier
    identities: tuple[IdentityProfile, ...] = Field(min_length=3)
    tenants: tuple[TenantRef, ...] = Field(min_length=2)
    role_grants: tuple[RoleGrant, ...] = Field(min_length=3)
    relationships: tuple[IdentityRelationship, ...] = Field(min_length=3)
    auth_sessions: tuple[AuthSession, ...] = Field(min_length=6)
    identity_contexts: tuple[IdentityContext, ...] = Field(min_length=6)
    workflows: tuple[WorkflowTrace, ...] = Field(min_length=4)
    differential_variants: tuple[DifferentialVariant, ...] = Field(min_length=6)
    auth_traces: tuple[AuthSemanticTrace, ...] = Field(min_length=1)
    idor_case: IdorFixtureCase

    @model_validator(mode="after")
    def _meets_public_fixture_contract(self) -> Self:
        identity_ids = {identity.identity_id for identity in self.identities}
        tenant_ids = {tenant.tenant_id for tenant in self.tenants}
        context_ids = {context.identity_context_id for context in self.identity_contexts}
        workflow_kinds = {workflow.workflow_kind for workflow in self.workflows}
        required_workflows = {
            WorkflowKind.INVITE,
            WorkflowKind.ADMIN,
            WorkflowKind.BILLING,
            WorkflowKind.RECOVERY,
        }
        if len(identity_ids) < 3 or len(tenant_ids) < 2:
            raise LabFixtureError(
                "identity fixture requires three identities and two tenants"
            )
        if not required_workflows.issubset(workflow_kinds):
            raise LabFixtureError("identity fixture lacks required workflow families")
        if any(
            context.identity_id not in identity_ids
            or context.tenant_id not in tenant_ids
            for context in self.identity_contexts
        ):
            raise LabFixtureError("identity fixture contains a dangling context")
        if {
            self.idor_case.owner_context_id,
            self.idor_case.outsider_context_id,
        }.difference(context_ids):
            raise LabFixtureError(
                "IDOR fixture references an unknown identity context"
            )
        return self
