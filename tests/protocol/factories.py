"""Deterministic complete protocol object graph used by contract tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import faultloom_protocol.models as m
from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    SecretRef,
    sha256_digest,
    sign_authority_grant,
)

NOW = datetime(2030, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc)
LATER = NOW + timedelta(hours=2)
D1 = "sha256:" + "11" * 32
D2 = "sha256:" + "22" * 32
D3 = "sha256:" + "33" * 32
D4 = "sha256:" + "44" * 32


def _model(model_type: type[m.ProtocolModel], /, **values: object) -> m.ProtocolModel:
    return model_type(schema_version=SCHEMA_VERSION, **values)


def sample_models() -> dict[str, m.ProtocolModel]:  # type: ignore[name-defined]
    target = _model(
        m.TargetAsset,
        target_id="target.lab",
        hostnames=("loopback.test",),
        ports=(443,),
        protocols=("https",),
        paths=("/api",),
        methods=("GET", "POST"),
    )
    deny = _model(
        m.ExplicitDeny,
        deny_id="deny.external-message",
        target_id="target.lab",
        action_families=("external_message",),
        reason="External messages are not approved.",
    )
    action_policy = _model(
        m.ActionPolicy,
        allowed_classes=(m.ActionClass.OBSERVE, m.ActionClass.SAFE_PROBE),
        allowed_families=("http.semantic", "browser.observe"),
        allowed_methods=("GET", "POST"),
        allowed_path_patterns=("/api/*",),
        denied=(deny,),
    )
    budget = _model(
        m.ActionBudget,
        total_actions=100,
        rate_per_minute=10,
        max_concurrency=2,
        max_request_bytes=4096,
        max_response_bytes=65536,
        max_duration_seconds=3600,
    )
    callback_policy = _model(
        m.CallbackPolicy,
        owned_domains=("callbacks.loopback.test",), maximum_ttl_seconds=300
    )
    provider_policy = _model(
        m.ProviderPolicy,
        allowed_providers=("provider.test",),
        allowed_model_snapshots=("frontier-2030-01-01",),
        data_policy_id="policy.no-training",
    )
    retention = _model(
        m.RetentionPolicy,
        policy_id="retention.short", retain_until=LATER, delete_after_seconds=60
    )
    state_change = _model(m.StateChangePolicy)
    window = _model(m.TimeWindow, starts_at=NOW, ends_at=LATER)
    draft = _model(
        m.ScopeContractDraft,
        draft_id="draft.1",
        revision=1,
        title="Owned loopback lab",
        created_at=NOW,
        created_by="operator.1",
        targets=(target,),
        adapter_ids=("adapter.http",),
        action_policy=action_policy,
        identities=("identity.owner",),
        tenants=("tenant.alpha",),
        execution_windows=(window,),
        budget=budget,
        callback_policy=callback_policy,
        provider_policy=provider_policy,
        retention_policy=retention,
        state_change_policy=state_change,
        emergency_contact_ref="contact.stop",
    )
    grant = _model(
        m.AuthorityGrant,
        grant_id="grant.1",
        grant_version=3,
        draft_digest=sha256_digest(draft),
        issued_at=NOW,
        not_before=NOW,
        expires_at=LATER,
        issued_to="researcher.1",
        approved_by="operator.1",
        targets=(target,),
        pack_ids=("pack.web",),
        adapter_ids=("adapter.http",),
        action_policy=action_policy,
        identities=("identity.owner",),
        roles=("role.owner",),
        tenants=("tenant.alpha",),
        execution_windows=(window,),
        budget=budget,
        callback_policy=callback_policy,
        provider_policy=provider_policy,
        retention_policy=retention,
        state_change_policy=state_change,
        emergency_contact_ref="contact.stop",
    )
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    signed_grant = sign_authority_grant(grant, authority_signer, signed_at=NOW)
    epoch = _model(
        m.ScopeEpoch,
        grant_id="grant.1", epoch=7, issued_at=NOW, expires_at=LATER
    )
    subject = _model(
        m.SubjectRef,
        subject_id="subject.owner",
        subject_kind="human",
        identity_id="identity.owner",
        tenant_id="tenant.alpha",
    )
    resource = _model(
        m.ResourceRef,
        resource_id="resource.invoice-1",
        resource_kind="invoice",
        target_id="target.lab",
        tenant_id="tenant.alpha",
    )
    state_before = _model(
        m.StateRef,
        state_id="state.invoice-1", state_kind="draft", state_version=1, state_digest=D1
    )
    intent = _model(
        m.ActionIntent,
        action_id="action.1",
        run_id="run.1",
        target_id="target.lab",
        pack_id="pack.web",
        action_kind="http.semantic",
        action_class=m.ActionClass.SAFE_PROBE,
        subject=subject,
        resource=resource,
        state=state_before,
        protocol="https",
        method="GET",
        path="/api/invoices/1",
        requested_at=NOW,
    )
    reservation = _model(m.BudgetReservation, duration_seconds=10)
    lease = _model(
        m.ActionLease,
        lease_id="lease.1",
        intent_digest=sha256_digest(intent),
        grant_id="grant.1",
        grant_version=3,
        scope_epoch=7,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        reservation=reservation,
    )
    decision = _model(
        m.PolicyDecision,
        decision_id="decision.1",
        intent_digest=sha256_digest(intent),
        grant_id="grant.1",
        grant_version=3,
        scope_epoch=7,
        outcome=m.DecisionOutcome.ALLOW,
        reason_codes=("explicit.allow",),
        evaluated_at=NOW,
        lease_id="lease.1",
    )
    receipt = _model(
        m.DispatchReceipt,
        receipt_id="receipt.1",
        lease_id="lease.1",
        intent_digest=sha256_digest(intent),
        decision_digest=sha256_digest(decision),
        scope_epoch=7,
        request_digest=D1,
        response_digest=D2,
        outcome=m.DispatchOutcome.COMPLETED,
        dispatched_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        response_status=200,
        bytes_sent=120,
        bytes_received=240,
    )
    observation = _model(
        m.ObservationRef,
        observation_id="observation.1",
        run_id="run.1",
        cas_digest=D1,
        media_type="application/json",
        byte_length=240,
        cursor="cursor.1",
        created_at=NOW,
    )
    evidence = _model(
        m.EvidenceRef,
        evidence_id="evidence.1",
        run_id="run.1",
        cas_digest=D2,
        observation_ids=("observation.1",),
        redaction_digest=D3,
        created_at=NOW,
    )
    delta = _model(
        m.ResearchDelta,
        delta_id="delta.1",
        run_id="run.1",
        actor_id="researcher.1",
        sequence=1,
        created_at=NOW,
        summary="Observed an authorization differential.",
        provenance=(m.ProvenanceKind.BEHAVIOR,),
        evidence_refs=(evidence,),
        introduced_hypothesis_ids=("hypothesis.1",),
    )
    hypothesis = _model(
        m.HypothesisRecord,
        hypothesis_id="hypothesis.1",
        run_id="run.1",
        statement="Object authorization differs by tenant.",
        provenance=(m.ProvenanceKind.BEHAVIOR,),
        status=m.HypothesisStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
        supporting_evidence=(evidence,),
    )
    negative = _model(
        m.NegativeResult,
        negative_result_id="negative.1",
        run_id="run.1",
        hypothesis_id="hypothesis.1",
        experiment_digest=D3,
        conclusion="The negative control was denied as expected.",
        evidence_refs=(evidence,),
        recorded_at=NOW,
    )
    primitive = _model(
        m.PrimitiveRecord,
        primitive_id="primitive.1",
        run_id="run.1",
        primitive_kind="cross_tenant_read",
        subject=subject,
        resource=resource,
        pre_state=state_before,
        post_state=state_before,
        action_intent_digest=sha256_digest(intent),
        dispatch_receipt_digest=sha256_digest(receipt),
        evidence_refs=(evidence,),
        verified=True,
    )
    effect = _model(
        m.EffectRecord,
        effect_id="effect.1",
        run_id="run.1",
        effect_kind="metadata_disclosed",
        subject=subject,
        resource=resource,
        state=state_before,
        observed_at=NOW,
        evidence_refs=(evidence,),
        reversible=True,
        cleanup_receipt_digest=D4,
    )
    candidate = _model(
        m.FindingCandidate,
        candidate_id="candidate.1",
        run_id="run.1",
        finding_class=m.FindingClass.ZERO_DAY_LIKE,
        title="Cross-tenant invoice metadata access",
        hypothesis_ids=("hypothesis.1",),
        primitive_ids=("primitive.1",),
        effect_ids=("effect.1",),
        evidence_refs=(evidence,),
        created_at=NOW,
        confidence_bps=8500,
        final_effect_observed=True,
    )
    claim = _model(
        m.ClaimPacket,
        claim_id="claim.1",
        candidate_id="candidate.1",
        run_id="run.1",
        claim="Owned tenant A can read canary metadata from owned tenant B.",
        prerequisites=("Two operator-provisioned tenants",),
        evidence_refs=(evidence,),
        negative_control_refs=(evidence,),
        replay_plan_id="replay.1",
        created_at=NOW,
    )
    verdict = _model(
        m.VerificationVerdict,
        verdict_id="verdict.1",
        run_id="run.1",
        claim_id="claim.1",
        claim_packet_digest=sha256_digest(claim),
        verifier_run_id="verify.1",
        outcome=m.VerdictOutcome.VERIFIED,
        independent_replay=True,
        reasons=("Fresh-state replay matched the claimed effect.",),
        evidence_refs=(evidence,),
        verified_at=NOW,
    )
    remaining = _model(
        m.RemainingBudget,
        actions=80, duration_seconds=3000, model_tokens=100000, cost_microunits=500000
    )
    cursor = _model(m.RetrievalCursor, index_id="evidence-index", cursor="cursor.1", watermark=10)
    checkpoint = _model(
        m.ContextCheckpoint,
        checkpoint_id="checkpoint.1",
        run_id="run.1",
        sequence=1,
        goal_digest=D1,
        plan_digest=D2,
        authority_digest=sha256_digest(signed_grant),
        scope_epoch=7,
        active_hypothesis_ids=("hypothesis.1",),
        important_negative_result_ids=("negative.1",),
        identity_graph_id="identity-graph.1",
        workflow_graph_id="workflow-graph.1",
        surface_graph_id="surface-graph.1",
        chain_graph_id="chain-graph.1",
        secret_refs=(
            _model(
                SecretRef,
                uri="secret://run/identity-owner",
                purpose="owned identity",
            ),
        ),
        recent_evidence_refs=(evidence,),
        retrieval_cursors=(cursor,),
        remaining_budget=remaining,
        stable_watermark=10,
        created_at=NOW,
    )
    model_identity = _model(
        m.ModelIdentity,
        provider_id="provider.test",
        requested_alias="frontier",
        actual_snapshot="frontier-2030-01-01",
        runtime_version="runtime-1.0.0",
        context_window=200000,
        prompt_digest=D1,
        tool_schema_digest=D2,
    )
    run_manifest = _model(
        m.RunManifest,
        run_id="run.1",
        engagement_id="engagement.1",
        target_id="target.lab",
        authority_digest=sha256_digest(signed_grant),
        scope_epoch=7,
        pack_ids=("pack.web",),
        adapter_ids=("adapter.http",),
        model=model_identity,
        plan_digest=D2,
        started_at=NOW,
    )
    adapter_manifest = _model(
        m.AdapterManifest,
        adapter_id="adapter.http",
        adapter_version="0.1.0",
        upstream_version="0.28.1",
        upstream_commit="0123456789abcdef",
        license_class=m.LicenseClass.BUNDLED_OPEN_SOURCE,
        capabilities=("semantic_http",),
        action_classes=(m.ActionClass.OBSERVE, m.ActionClass.SAFE_PROBE),
        network_mode="gateway_only",
        input_schema_digest=D1,
        output_schema_digest=D2,
        budget=_model(
            m.AdapterBudget,
            rate_per_minute=10, timeout_seconds=30, max_bytes=65536, max_concurrency=2
        ),
        telemetry_policy="telemetry.disabled",
        evidence_capability=m.EvidenceCapability.EVIDENCE_CAPABLE,
    )
    pack_manifest = _model(
        m.PackManifest,
        pack_id="pack.web",
        pack_version="0.1.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.web.v1",
        capability_descriptors=("identity.workflow",),
        action_compilers=("semantic.http",),
        observation_normalizers=("http.response",),
        hypothesis_providers=("authorization.differential",),
        verifier_descriptors=("clean.replay",),
        evaluation_descriptors=("web.identity",),
        required_gateway_features=("scope.epoch",),
        required_adapter_capabilities=("semantic_http",),
    )

    tenant = _model(
        m.TenantRef,
        tenant_id="tenant.alpha",
        tenant_kind="workspace",
        target_id="target.lab",
    )
    role_grant = _model(
        m.RoleGrant,
        role_grant_id="role-grant.1",
        identity_id="identity.owner",
        tenant_id="tenant.alpha",
        role_id="role.owner",
        granted_at=NOW,
    )
    identity_profile = _model(
        m.IdentityProfile,
        identity_id="identity.owner",
        account_ref="account.owner",
        display_label="Lab owner",
        tenant_ids=("tenant.alpha",),
        role_ids=("role.owner",),
        credential_ref=_model(
            SecretRef,
            uri="secret://engagement/owner-credential",
            purpose="login",
        ),
        mfa_state="satisfied",
        status="active",
    )
    auth_session = _model(
        m.AuthSession,
        auth_session_id="auth-session.1",
        identity_id="identity.owner",
        tenant_id="tenant.alpha",
        session_handle_ref=_model(
            SecretRef,
            uri="secret://session/owner-browser",
            purpose="session",
        ),
        issued_at=NOW,
        expires_at=LATER,
        mfa_satisfied=True,
    )
    identity_context = _model(
        m.IdentityContext,
        identity_context_id="identity-context.1",
        identity_id="identity.owner",
        tenant_id="tenant.alpha",
        role_ids=("role.owner",),
        auth_session_id="auth-session.1",
        browser_context_ref=_model(
            SecretRef,
            uri="secret://browser/context-owner",
            purpose="browser",
        ),
    )
    relationship = _model(
        m.IdentityRelationship,
        relationship_id="relationship.1",
        source_id="identity.owner",
        target_id="tenant.alpha",
        relationship_kind="ownership",
        evidence_refs=(evidence,),
    )
    identity_graph = _model(
        m.IdentityGraph,
        graph_id="identity-graph.1",
        run_id="run.1",
        identities=(identity_profile,),
        tenants=(tenant,),
        role_grants=(role_grant,),
        relationships=(relationship,),
        version=1,
    )
    workflow_state_1 = _model(
        m.WorkflowState,
        workflow_state_id="workflow-state.draft",
        workflow_id="workflow.invoice",
        state_name="draft",
        tenant_id="tenant.alpha",
        resource=resource,
    )
    workflow_state_2 = _model(
        m.WorkflowState,
        workflow_state_id="workflow-state.viewed",
        workflow_id="workflow.invoice",
        state_name="viewed",
        tenant_id="tenant.alpha",
        resource=resource,
    )
    transition = _model(
        m.TransitionRecord,
        transition_id="transition.1",
        workflow_id="workflow.invoice",
        from_state_id="workflow-state.draft",
        to_state_id="workflow-state.viewed",
        operation_id="operation.get-invoice",
        identity_context_id="identity-context.1",
        occurred_at=NOW,
        action_intent_digest=sha256_digest(intent),
        dispatch_receipt_digest=sha256_digest(receipt),
        evidence_refs=(evidence,),
    )
    workflow_graph = _model(
        m.WorkflowGraph,
        graph_id="workflow-graph.1",
        run_id="run.1",
        workflow_kind="billing",
        states=(workflow_state_1, workflow_state_2),
        transitions=(transition,),
        invariant_ids=("invariant.tenant-isolation",),
        version=1,
    )
    differential_case = _model(
        m.DifferentialCase,
        case_id="differential.1",
        operation_id="operation.get-invoice",
        baseline_identity_context_id="identity-context.1",
        comparison_identity_context_id="identity-context.2",
        varied_dimension="tenant",
        expected_invariant_id="invariant.tenant-isolation",
    )
    differential_plan = _model(
        m.DifferentialPlan,
        plan_id="differential-plan.1",
        run_id="run.1",
        workflow_graph_id="workflow-graph.1",
        cases=(differential_case,),
        negative_control_case_ids=("differential.1",),
        created_at=NOW,
    )

    operation = _model(

        m.OperationRef,
        operation_id="operation.get-invoice",
        target_id="target.lab",
        operation_kind=m.OperationKind.REST,
        method="GET",
        path="/api/invoices/{id}",
        schema_namespace="openapi.v1",
        documented=True,
    )
    schema_evidence = _model(
        m.SchemaEvidence,
        schema_evidence_id="schema-evidence.1",
        source_kind="openapi",
        source_digest=D1,
        operation_ids=("operation.get-invoice",),
        observed_at=NOW,
    )
    correlation = _model(
        m.CorrelationRef,
        correlation_id="correlation.1", correlation_kind="request_id", opaque_value_digest=D2
    )
    message = _model(
        m.MessageEnvelope,
        message_id="message.1",
        channel_id="channel.1",
        direction="server_to_client",
        message_type="invoice.updated",
        payload_schema_digest=D1,
        payload_digest=D2,
        correlation_refs=(correlation,),
        observed_at=NOW,
    )
    async_flow = _model(
        m.AsyncFlow,
        async_flow_id="async-flow.1",
        initiating_operation_id="operation.get-invoice",
        terminal_operation_id="operation.get-invoice",
        operation_ids=("operation.get-invoice",),
        correlation_refs=(correlation,),
        pending=False,
        initiated_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
    )
    callback_lease = _model(
        m.CallbackLease,
        callback_lease_id="callback-lease.1",
        engagement_id="engagement.1",
        grant_id="grant.1",
        scope_epoch=7,
        owned_domain="callbacks.loopback.test",
        callback_path_digest=D1,
        callback_token_ref=_model(
            SecretRef,
            uri="secret://callback/lease-1",
            purpose="callback token",
        ),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    job = _model(
        m.JobObservation,
        job_observation_id="job-observation.1",
        async_flow_id="async-flow.1",
        job_id_digest=D3,
        identity_context_id="identity-context.1",
        status="complete",
        state=state_before,
        evidence_refs=(evidence,),
        observed_at=NOW,
    )
    file_stage = _model(
        m.FileStage,
        stage_id="file-stage.1",
        stage_kind="upload",
        operation_id="operation.get-invoice",
        artifact_digest=D4,
        tenant_id="tenant.alpha",
        observed_at=NOW,
    )
    file_pipeline = _model(
        m.FilePipeline,
        file_pipeline_id="file-pipeline.1",
        run_id="run.1",
        canary_id="canary.inert-1",
        media_type="text/plain",
        stages=(file_stage,),
        correlation_refs=(correlation,),
        evidence_refs=(evidence,),
    )
    surface_edge = _model(
        m.SurfaceEdge,
        edge_id="surface-edge.1",
        source_operation_id="operation.get-invoice",
        target_operation_id="operation.get-invoice",
        edge_kind="job",
        correlation_refs=(correlation,),
    )
    surface_graph = _model(
        m.SurfaceGraph,
        graph_id="surface-graph.1",
        run_id="run.1",
        operations=(operation,),
        schema_evidence=(schema_evidence,),
        async_flows=(async_flow,),
        edges=(surface_edge,),
        version=1,
    )

    fingerprint = _model(

        m.ComponentFingerprint,
        fingerprint_id="fingerprint.1",
        target_id="target.lab",
        component_name="example-component",
        evidence_kinds=("header", "behavior"),
        evidence_refs=(evidence,),
        observed_at=NOW,
    )
    version_hypothesis = _model(
        m.VersionHypothesis,
        version_hypothesis_id="version-hypothesis.1",
        fingerprint_id="fingerprint.1",
        version_range=">=1.2.0,<1.3.0",
        confidence_bps=7000,
        backport_possible=True,
        evidence_refs=(evidence,),
    )
    advisory = _model(
        m.AdvisoryMatch,
        advisory_match_id="advisory-match.1",
        version_hypothesis_id="version-hypothesis.1",
        advisory_id="CVE-2030-0001",
        advisory_url_digest=D1,
        vendor_advisory_digest=D2,
        security_commit="abcdef0123456789",
        match_confidence_bps=8000,
    )
    reachability = _model(
        m.ReachabilityClaim,
        reachability_claim_id="reachability.1",
        advisory_match_id="advisory-match.1",
        component_present=True,
        vulnerable_path_exposed=True,
        prerequisites_satisfied=True,
        patch_or_backport_present=False,
        evidence_refs=(evidence,),
        conclusion="reachable",
    )
    patch_delta = _model(
        m.PatchDelta,
        patch_delta_id="patch-delta.1",
        advisory_match_id="advisory-match.1",
        vulnerable_revision="rev-vulnerable",
        fixed_revision="rev-fixed",
        source_diff_digest=D3,
        test_diff_digest=D4,
        evidence_refs=(evidence,),
    )
    invariant = _model(
        m.InvariantChange,
        invariant_change_id="invariant-change.1",
        patch_delta_id="patch-delta.1",
        invariant="Tenant binding must precede object lookup.",
        changed_condition="Tenant ID is now included in lookup.",
        sink_or_boundary="Invoice repository boundary",
        evidence_refs=(evidence,),
    )
    variant = _model(
        m.VariantHypothesis,
        variant_hypothesis_id="variant.1",
        invariant_change_id="invariant-change.1",
        variant_kind="sibling_path",
        statement="The export sibling route may lack the tenant binding.",
        confidence_class=m.ConfidenceClass.SIMILAR,
        source_query_digest=D4,
        evidence_refs=(evidence,),
    )
    adaptation = _model(
        m.DeploymentAdaptation,
        adaptation_id="adaptation.1",
        advisory_match_id="advisory-match.1",
        target_id="target.lab",
        version_hypothesis_id="version-hypothesis.1",
        route_ref=resource,
        identity_context_id="identity-context.1",
        transport="https",
        prerequisite_ids=("prerequisite.owned-object",),
        removed_unsafe_step_digests=(D1,),
        evidence_refs=(evidence,),
    )
    poc_step = _model(
        m.PoCStep,
        step_id="poc-step.1",
        action_intent=intent,
        expected_effect="Read only the inert canary metadata.",
        negative_control="An unrelated object identifier is denied.",
    )
    poc = _model(
        m.PoCRecipe,
        recipe_id="poc.1",
        adaptation_id="adaptation.1",
        prerequisites=("Owned identities and canary object",),
        steps=(poc_step,),
        expected_observable_effect="The owned cross-tenant canary marker is returned.",
        negative_controls=("Unknown object remains unavailable.",),
        evidence_refs=(evidence,),
    )

    capability = _model(

        m.CapabilityPrimitive,
        capability_id="capability.1",
        primitive=primitive,
        capability_kind="read_owned_cross_tenant_canary",
        source_pack_id="pack.web",
        verified=True,
        precondition_ids=("prerequisite.owned-object",),
        effect_ids=("effect.1",),
    )
    chain_edge = _model(
        m.ChainEdge,
        edge_id="chain-edge.1",
        source_capability_id="capability.1",
        target_capability_id="capability.1",
        preconditions=("Owned canary exists",),
        input_subject=subject,
        input_resource=resource,
        input_state=state_before,
        action_intent=intent,
        action_lease_id="lease.1",
        scope_decision_digest=sha256_digest(decision),
        expected_effect=effect,
        observed_effect=effect,
        evidence_refs=(evidence,),
        negative_control_refs=(evidence,),
        reversible=True,
        cleanup_receipt_digest=D4,
        action_cost=1,
        time_cost_seconds=1,
        confidence_bps=9000,
    )
    chain_graph = _model(
        m.ChainGraph,
        graph_id="chain-graph.1",
        run_id="run.1",
        capabilities=(capability,),
        edges=(chain_edge,),
        impact_goal="Demonstrate owned cross-tenant canary disclosure.",
        action_budget=10,
        time_budget_seconds=60,
        version=1,
    )
    chain_plan = _model(
        m.ChainPlan,
        chain_plan_id="chain-plan.1",
        chain_graph_id="chain-graph.1",
        edge_ids=("chain-edge.1",),
        search_modes=("forward", "backward"),
        final_effect_id="effect.1",
        total_action_cost=1,
        total_time_cost_seconds=1,
    )
    missing = _model(
        m.MissingLink,
        missing_link_id="missing-link.1",
        chain_graph_id="chain-graph.1",
        source_capability_id="capability.1",
        target_capability_id="capability.1",
        missing_precondition="Confirm the fresh session tenant binding.",
        minimum_experiment_intent=intent,
        expected_information_gain_bps=5000,
    )
    replay = _model(
        m.ReplayPlan,
        replay_plan_id="replay.1",
        chain_plan_id="chain-plan.1",
        fresh_identity_context_ids=("identity-context.1",),
        reset_state_refs=(state_before,),
        edge_ids=("chain-edge.1",),
        negative_control_edge_ids=("chain-edge.1",),
    )
    chain_verdict = _model(
        m.ChainVerdict,
        chain_verdict_id="chain-verdict.1",
        run_id="run.1",
        replay_plan_id="replay.1",
        outcome=m.VerdictOutcome.VERIFIED,
        verified_edge_ids=("chain-edge.1",),
        longest_verified_prefix=1,
        final_effect_verified=True,
        evidence_refs=(evidence,),
        verified_at=NOW,
    )

    engagement = _model(

        m.EngagementBundle,
        bundle_id="engagement-bundle.1",
        bundle_version=1,
        engagement_id="engagement.1",
        authority_grant=signed_grant,
        run_manifest=run_manifest,
        identity_profiles=(identity_profile,),
        pack_manifests=(pack_manifest,),
        adapter_manifests=(adapter_manifest,),
        technical_policy_refs=("policy.scope-first",),
        created_at=NOW,
        expires_at=LATER,
    )
    result = _model(
        m.RunResultBundle,
        bundle_id="result-bundle.1",
        bundle_version=2,
        engagement_id="engagement.1",
        run_id="run.1",
        run_manifest_digest=sha256_digest(run_manifest),
        authority_digest=sha256_digest(signed_grant),
        finding_candidates=(candidate,),
        claim_packets=(claim,),
        verification_verdicts=(verdict,),
        chain_verdicts=(chain_verdict,),
        evidence_refs=(evidence,),
        final_checkpoint_digest=sha256_digest(checkpoint),
        generated_at=NOW,
        cleanup_receipt_digests=(D4,),
    )

    values = {
        cls.__name__: value
        for cls, value in (
            (m.ScopeContractDraft, draft),
            (m.AuthorityGrant, grant),
            (m.ScopeEpoch, epoch),
            (m.ActionIntent, intent),
            (m.ActionLease, lease),
            (m.PolicyDecision, decision),
            (m.DispatchReceipt, receipt),
            (m.ObservationRef, observation),
            (m.EvidenceRef, evidence),
            (m.ResearchDelta, delta),
            (m.HypothesisRecord, hypothesis),
            (m.NegativeResult, negative),
            (m.SubjectRef, subject),
            (m.ResourceRef, resource),
            (m.StateRef, state_before),
            (m.PrimitiveRecord, primitive),
            (m.EffectRecord, effect),
            (m.FindingCandidate, candidate),
            (m.ClaimPacket, claim),
            (m.VerificationVerdict, verdict),
            (m.ContextCheckpoint, checkpoint),
            (m.RunManifest, run_manifest),
            (m.AdapterManifest, adapter_manifest),
            (m.PackManifest, pack_manifest),
            (m.EngagementBundle, engagement),
            (m.RunResultBundle, result),
            (m.IdentityProfile, identity_profile),
            (m.IdentityContext, identity_context),
            (m.TenantRef, tenant),
            (m.RoleGrant, role_grant),
            (m.AuthSession, auth_session),
            (m.IdentityGraph, identity_graph),
            (m.WorkflowGraph, workflow_graph),
            (m.WorkflowState, workflow_state_1),
            (m.TransitionRecord, transition),
            (m.DifferentialPlan, differential_plan),
            (m.SurfaceGraph, surface_graph),
            (m.OperationRef, operation),
            (m.SchemaEvidence, schema_evidence),
            (m.AsyncFlow, async_flow),
            (m.MessageEnvelope, message),
            (m.CorrelationRef, correlation),
            (m.CallbackLease, callback_lease),
            (m.JobObservation, job),
            (m.FilePipeline, file_pipeline),
            (m.ComponentFingerprint, fingerprint),
            (m.VersionHypothesis, version_hypothesis),
            (m.AdvisoryMatch, advisory),
            (m.ReachabilityClaim, reachability),
            (m.PatchDelta, patch_delta),
            (m.InvariantChange, invariant),
            (m.VariantHypothesis, variant),
            (m.DeploymentAdaptation, adaptation),
            (m.PoCRecipe, poc),
            (m.CapabilityPrimitive, capability),
            (m.ChainGraph, chain_graph),
            (m.ChainEdge, chain_edge),
            (m.ChainPlan, chain_plan),
            (m.MissingLink, missing),
            (m.ReplayPlan, replay),
            (m.ChainVerdict, chain_verdict),
        )
    }
    assert len(values) == len(m.REQUIRED_MODEL_TYPES)
    return values
