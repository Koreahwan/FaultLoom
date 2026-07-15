"""Stable public fixture data for identity/workflow research."""

from faultloom_protocol import (
    IdentityRelationship,
    RoleGrant,
    SCHEMA_VERSION,
    TenantRef,
)
from faultloom_web.identity_workflow import (
    AuthBinding,
    AuthProtocol,
    AuthSemanticTrace,
    DifferentialDimension,
    ExpectedRelation,
    SessionChannel,
    WorkflowKind,
)

from .contracts import IdentityWorkflowFixture, IdorFixtureCase
from .fixture_builders import (
    NOW,
    RUN_ID,
    TARGET_ID,
    _digest,
    _profile,
    _session_context,
    _variant,
    _workflow,
)


def identity_workflow_fixture() -> IdentityWorkflowFixture:
    """Return the immutable three-identity, two-tenant T32 fixture."""

    profiles = (
        _profile("identity.owner", "tenant.alpha", ("role.owner", "role.admin")),
        _profile("identity.member", "tenant.alpha", ("role.member", "role.billing")),
        _profile("identity.outsider", "tenant.beta", ("role.member",)),
    )
    pairs = tuple(
        _session_context(profile, channel)
        for profile in profiles
        for channel in (SessionChannel.BROWSER, SessionChannel.API)
    )
    grants = tuple(
        RoleGrant(
            schema_version=SCHEMA_VERSION,
            role_grant_id=f"grant.{profile.identity_id}.{role_id}",
            identity_id=profile.identity_id,
            tenant_id=profile.tenant_ids[0],
            role_id=role_id,
            granted_at=NOW,
        )
        for profile in profiles
        for role_id in profile.role_ids
    )
    relationships = tuple(
        IdentityRelationship(
            schema_version=SCHEMA_VERSION,
            relationship_id=f"relationship.{profile.identity_id}",
            source_id=profile.identity_id,
            target_id=profile.tenant_ids[0],
            relationship_kind=(
                "ownership"
                if profile.identity_id == "identity.owner"
                else "membership"
            ),
        )
        for profile in profiles
    )
    workflows = (
        _workflow(WorkflowKind.INVITE, "context.identity.owner.browser", 1),
        _workflow(WorkflowKind.ADMIN, "context.identity.owner.browser", 2),
        _workflow(WorkflowKind.BILLING, "context.identity.member.browser", 3),
        _workflow(WorkflowKind.RECOVERY, "context.identity.owner.api", 4),
    )
    variants = (
        _variant(
            DifferentialDimension.IDENTITY,
            "context.identity.outsider.browser",
            ExpectedRelation.ISOLATED,
        ),
        _variant(
            DifferentialDimension.TENANT,
            "context.identity.outsider.browser",
            ExpectedRelation.ISOLATED,
        ),
        _variant(
            DifferentialDimension.ROLE,
            "context.identity.member.browser",
            ExpectedRelation.ISOLATED,
        ),
        _variant(
            DifferentialDimension.SESSION,
            "context.identity.owner.api",
            ExpectedRelation.EQUIVALENT,
        ),
        _variant(
            DifferentialDimension.OBJECT,
            "context.identity.owner.browser",
            ExpectedRelation.ISOLATED,
        ),
        _variant(
            DifferentialDimension.ORDER,
            "context.identity.owner.browser",
            ExpectedRelation.ISOLATED,
        ),
    )
    auth_trace = AuthSemanticTrace(
        flow_id="auth.oidc.owner",
        protocol=AuthProtocol.OIDC,
        expected_correlation_digest=_digest("state"),
        observed_correlation_digest=_digest("state"),
        expected_nonce_digest=_digest("nonce"),
        observed_nonce_digest=_digest("nonce"),
        expected_redirect_digest=_digest("redirect"),
        observed_redirect_digest=_digest("redirect"),
        expected_audiences=("audience.lab",),
        observed_audiences=("audience.lab",),
        expected_issuer="issuer.lab",
        observed_issuer="issuer.lab",
        expected_subject_binding_digest=_digest("subject"),
        observed_subject_binding_digest=_digest("subject"),
        expected_binding=AuthBinding.REDIRECT,
        observed_binding=AuthBinding.REDIRECT,
    )
    return IdentityWorkflowFixture(
        schema_version=SCHEMA_VERSION,
        namespace="faultloom.lab.web.identity_workflow.v1",
        fixture_id="fixture.identity-workflow",
        fixture_version="1.0.0",
        target_id=TARGET_ID,
        run_id=RUN_ID,
        identities=profiles,
        tenants=(
            TenantRef(
                schema_version=SCHEMA_VERSION,
                tenant_id="tenant.alpha",
                tenant_kind="workspace",
                target_id=TARGET_ID,
            ),
            TenantRef(
                schema_version=SCHEMA_VERSION,
                tenant_id="tenant.beta",
                tenant_kind="workspace",
                target_id=TARGET_ID,
            ),
        ),
        role_grants=grants,
        relationships=relationships,
        auth_sessions=tuple(pair[0] for pair in pairs),
        identity_contexts=tuple(pair[1] for pair in pairs),
        workflows=workflows,
        differential_variants=variants,
        auth_traces=(auth_trace,),
        idor_case=IdorFixtureCase(
            case_id="idor.cross-tenant",
            resource_id="resource.tenant-alpha.canary",
            resource_tenant_id="tenant.alpha",
            owner_context_id="context.identity.owner.browser",
            outsider_context_id="context.identity.outsider.browser",
        ),
    )
