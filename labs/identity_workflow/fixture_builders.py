"""Typed builders for the public identity/workflow fixture."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Final, assert_never

from faultloom_protocol import (
    AuthSession,
    EvidenceRef,
    IdentityContext,
    IdentityProfile,
    ResourceRef,
    SCHEMA_VERSION,
    SecretRef,
    WorkflowState,
)
from faultloom_web.identity_workflow import (
    DifferentialDimension,
    DifferentialVariant,
    ExpectedRelation,
    SessionChannel,
    WorkflowKind,
    WorkflowTrace,
    WorkflowTraceStep,
)

NOW: Final = datetime(2032, 1, 1, tzinfo=timezone.utc)
LATER: Final = NOW + timedelta(hours=4)
TARGET_ID: Final = "target.identity-workflow.lab"
RUN_ID: Final = "run.identity-workflow.lab"


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _profile(
    identity_id: str,
    tenant_id: str,
    role_ids: tuple[str, ...],
) -> IdentityProfile:
    return IdentityProfile(
        schema_version=SCHEMA_VERSION,
        identity_id=identity_id,
        account_ref=f"account.{identity_id}",
        display_label=identity_id,
        tenant_ids=(tenant_id,),
        role_ids=role_ids,
        credential_ref=SecretRef(
            schema_version=SCHEMA_VERSION,
            uri=f"secret://lab/credential/{identity_id}",
            purpose="test credential",
        ),
        mfa_state="satisfied",
        status="active",
    )


def _session_context(
    profile: IdentityProfile,
    channel: SessionChannel,
) -> tuple[AuthSession, IdentityContext]:
    suffix = channel.value
    session_id = f"session.{profile.identity_id}.{suffix}"
    session = AuthSession(
        schema_version=SCHEMA_VERSION,
        auth_session_id=session_id,
        identity_id=profile.identity_id,
        tenant_id=profile.tenant_ids[0],
        session_handle_ref=SecretRef(
            schema_version=SCHEMA_VERSION,
            uri=f"secret://lab/session/{profile.identity_id}/{suffix}",
            purpose=f"{suffix} session handle",
        ),
        issued_at=NOW,
        expires_at=LATER,
        mfa_satisfied=True,
    )
    channel_ref = SecretRef(
        schema_version=SCHEMA_VERSION,
        uri=f"secret://lab/context/{profile.identity_id}/{suffix}",
        purpose=f"isolated {suffix} context",
    )
    match channel:
        case SessionChannel.BROWSER:
            browser_ref = channel_ref
            api_ref = None
        case SessionChannel.API:
            browser_ref = None
            api_ref = channel_ref
        case unreachable:
            assert_never(unreachable)
    context = IdentityContext(
        schema_version=SCHEMA_VERSION,
        identity_context_id=f"context.{profile.identity_id}.{suffix}",
        identity_id=profile.identity_id,
        tenant_id=profile.tenant_ids[0],
        role_ids=profile.role_ids,
        auth_session_id=session_id,
        browser_context_ref=browser_ref,
        api_session_ref=api_ref,
    )
    return session, context


def _workflow(
    kind: WorkflowKind,
    actor_context_id: str,
    index: int,
) -> WorkflowTrace:
    workflow_id = f"workflow.{kind.value}"
    resource = ResourceRef(
        schema_version=SCHEMA_VERSION,
        resource_id=f"resource.{kind.value}.canary",
        resource_kind="workflow_canary",
        target_id=TARGET_ID,
        tenant_id="tenant.alpha",
    )
    from_state = WorkflowState(
        schema_version=SCHEMA_VERSION,
        workflow_state_id=f"state.{kind.value}.before",
        workflow_id=workflow_id,
        state_name=f"{kind.value}.before",
        tenant_id="tenant.alpha",
        resource=resource,
    )
    to_state = WorkflowState(
        schema_version=SCHEMA_VERSION,
        workflow_state_id=f"state.{kind.value}.after",
        workflow_id=workflow_id,
        state_name=f"{kind.value}.after",
        tenant_id="tenant.alpha",
        resource=resource,
        terminal=True,
    )
    evidence = EvidenceRef(
        schema_version=SCHEMA_VERSION,
        evidence_id=f"evidence.{kind.value}",
        run_id=RUN_ID,
        cas_digest=_digest(f"evidence:{kind.value}"),
        observation_ids=(f"observation.{kind.value}",),
        created_at=NOW + timedelta(minutes=index),
    )
    step = WorkflowTraceStep(
        transition_id=f"transition.{kind.value}",
        workflow_id=workflow_id,
        from_state_id=from_state.workflow_state_id,
        to_state_id=to_state.workflow_state_id,
        ui_action_id=f"ui.{kind.value}.submit",
        backend_operation_id=f"operation.{kind.value}.apply",
        identity_context_id=actor_context_id,
        occurred_at=NOW + timedelta(minutes=index),
        action_intent_digest=_digest(f"intent:{kind.value}"),
        dispatch_receipt_digest=_digest(f"receipt:{kind.value}"),
        evidence_refs=(evidence,),
    )
    return WorkflowTrace(
        graph_id=f"graph.{kind.value}",
        run_id=RUN_ID,
        workflow_id=workflow_id,
        workflow_kind=kind,
        states=(from_state, to_state),
        steps=(step,),
        version=1,
    )


def _variant(
    dimension: DifferentialDimension,
    comparison_context_id: str,
    expected_relation: ExpectedRelation,
) -> DifferentialVariant:
    return DifferentialVariant(
        case_id=f"case.{dimension.value}",
        operation_id="operation.resource.read",
        baseline_identity_context_id="context.identity.owner.browser",
        comparison_identity_context_id=comparison_context_id,
        dimension=dimension,
        baseline_value_digest=_digest(f"baseline:{dimension.value}"),
        comparison_value_digest=_digest(f"comparison:{dimension.value}"),
        expected_invariant_id="invariant.workflow.invite.tenant_isolation",
        expected_relation=expected_relation,
        negative_control=dimension is DifferentialDimension.SESSION,
    )
