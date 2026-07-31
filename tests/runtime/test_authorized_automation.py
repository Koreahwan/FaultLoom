from __future__ import annotations

import json
import hashlib
from collections.abc import Callable
from datetime import timedelta

import pytest

from faultloom.automation import (
    ActionContext,
    AuthorizedAutomationCoordinator,
    AuthorizedAutomationError,
    AutomationLimits,
    AutomationRequest,
    ModelDisclosureApproval,
    ObservationBundle,
    ObservationExcerpt,
    ReasoningTurnRequest,
    SafePoCContext,
    sign_model_disclosure_approval,
)
from faultloom.tool_planner import PlanningBudget, ToolPlanner
from faultloom_protocol import AuthorityGrant, AuthoritySigner, sha256_digest
from faultloom_sdk import (
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdmissionGate,
    AdmissionOutcome,
    ManifestRegistry,
    reference_registry,
)
from tests.protocol.factories import NOW, sample_models
from tests.sdk.model_utility_admission_support import record_verified, verified_proof


DISCLOSURE_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("42" * 32))
_EXCERPT_CONTENT = "Owned response: invoice normalizer returned two digests."


def _admitted(registry: ManifestRegistry) -> AdapterAdmissionRegistry:
    admission = AdapterAdmissionRegistry(registry)
    manifest = registry.adapters[0]
    digest = sha256_digest(manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        admission.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
            )
        )
    proof, producer_signer, verifier_signer, producer, verifier, _ = verified_proof(
        manifest=manifest
    )
    record_verified(admission, proof, producer_signer, verifier_signer, producer, verifier)
    return admission


def _request(*, limits: AutomationLimits | None = None) -> AutomationRequest:
    samples = sample_models()
    source_intent = samples["ActionIntent"]
    source_grant = samples["AuthorityGrant"]
    policy = source_grant.action_policy.model_copy(
        update={"allowed_families": ("reference.digest",)}
    )
    grant = AuthorityGrant.model_validate(
        source_grant.model_copy(
            update={
                "targets": (
                    source_grant.targets[0].model_copy(update={"paths": ("/api/*",)}),
                ),
                "pack_ids": ("pack.reference",),
                "adapter_ids": ("adapter.reference",),
                "action_policy": policy,
            }
        ).model_dump(mode="python")
    )
    evidence = samples["EvidenceRef"]
    assert evidence.redaction_digest is not None
    content_digest = "sha256:" + hashlib.sha256(_EXCERPT_CONTENT.encode()).hexdigest()
    disclosure = sign_model_disclosure_approval(
        ModelDisclosureApproval(
            approval_id="model-disclosure.1",
            run_id="run.1",
            evidence_id=evidence.evidence_id,
            source_cas_digest=evidence.cas_digest,
            redaction_digest=evidence.redaction_digest,
            content_digest=content_digest,
            media_type="text/plain",
            data_policy_id=grant.provider_policy.data_policy_id,
            allowed_provider_ids=("provider.test",),
            approved_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            approver_key_id=DISCLOSURE_SIGNER.key_id,
        ),
        DISCLOSURE_SIGNER,
    )
    context = ActionContext(
        run_id="run.1",
        target_id=source_intent.target_id,
        pack_id="pack.reference",
        subject=source_intent.subject,
        resource=source_intent.resource,
        protocol=source_intent.protocol,
        method=source_intent.method,
        path=source_intent.path,
        payload_digest="sha256:" + "a" * 64,
        cleanup_plan_ref="cleanup.1",
    )
    poc_context = SafePoCContext(
        run_id="run.1",
        target_id=source_intent.target_id,
        pack_id="pack.reference",
        route_ref=source_intent.resource,
        route_path="/api/invoices/1",
        subject=source_intent.subject,
        transport=source_intent.protocol,
        prerequisite_ids=("identity.owner",),
        prerequisites=("Use the owner identity only.",),
        cleanup_plan_ref="cleanup.1",
        advisory_match_id="advisory.match.1",
    )
    return AutomationRequest(
        observations=ObservationBundle(
            run_id="run.1",
            evidence_refs=(evidence,),
            excerpts=(
                ObservationExcerpt(
                    evidence_id=evidence.evidence_id,
                    media_type="text/plain",
                    content=_EXCERPT_CONTENT,
                    content_digest=content_digest,
                    redacted=True,
                    untrusted=True,
                    model_disclosure_approved=True,
                    approval=disclosure,
                ),
            ),
            observed_experiment_digests=("sha256:" + "1" * 64,),
        ),
        issued_at=NOW,
        authority_grant=grant,
        planning_budget=PlanningBudget(
            rate_slots=3,
            duration_seconds=20,
            bytes=2_000,
            concurrency=2,
            actions=3,
            cost_microunits=100,
        ),
        action_context=context,
        poc_context=poc_context,
        limits=limits or AutomationLimits(),
        provider_network_access="provider_only",
    )


def _turn(*, action: dict[str, object] | None = None, poc: dict[str, object] | None = None) -> bytes:
    evidence_id = sample_models()["EvidenceRef"].evidence_id
    document: dict[str, object] = {
        "hypotheses": [
            {
                "proposal_id": "hypothesis.1",
                "statement": "The owned route has a bounded normalization difference.",
                "provenance": ["behavior"],
                "supporting_evidence_ids": [evidence_id],
                "contradicting_evidence_ids": [],
                "prerequisite_ids": ["identity.owner"],
            }
        ],
        "negative_results": [],
        "actions": [] if action is None else [action],
        "poc": poc,
        "finding_draft": {
            "hypothesis_proposal_id": "hypothesis.1",
            "poc_recipe_id": None if poc is None else "recipe.1",
            "title": "Bounded normalization candidate",
            "severity": "low",
            "summary": "A candidate needs independent replay.",
            "impact": "No impact is verified yet.",
            "reproduction_steps": ["Run the admitted candidate only."],
            "remediation": "Confirm with an independent replay before remediation.",
        },
        "stop_reason": "Await independent verification.",
    }
    return json.dumps(document).encode("utf-8")


def _safe_action(*, adapter_id: str = "adapter.reference", action_class: str = "safe_probe") -> dict[str, object]:
    return {
        "candidate_id": "candidate.1",
        "hypothesis_proposal_id": "hypothesis.1",
        "adapter_id": adapter_id,
        "capability": "reference.digest_normalizer",
        "action_kind": "reference.digest",
        "action_class": action_class,
        "expected_information_gain_bps": 7_000,
        "estimate": {
            "rate_slots": 1,
            "duration_seconds": 2,
            "bytes": 200,
            "concurrency": 1,
            "cost_microunits": 1,
        },
    }


def _safe_poc() -> dict[str, object]:
    evidence_id = sample_models()["EvidenceRef"].evidence_id
    return {
        "adaptation_id": "adaptation.1",
        "recipe_id": "recipe.1",
        "hypothesis_proposal_id": "hypothesis.1",
        "expected_observable_effect": "The local normalizer returns a deterministic digest.",
        "negative_controls": ["An unrelated digest remains unchanged."],
        "evidence_ids": [evidence_id],
        "steps": [
            {
                "step_id": "step.1",
                "action_class": "safe_probe",
                "action_kind": "reference.digest",
                "method": "GET",
                "expected_effect": "A digest is returned.",
                "negative_control": "The unrelated input is unchanged.",
                "required": True,
                "hazard": "safe",
            }
        ],
    }


def _coordinator() -> AuthorizedAutomationCoordinator:
    registry = reference_registry()
    return AuthorizedAutomationCoordinator(
        planner=ToolPlanner(registry, _admitted(registry)),
    )


def test_owned_turn_compiles_candidate_plan_safe_poc_and_unverified_draft() -> None:
    request = _request()
    result = _coordinator().run(
        request=request,
        raw_model_turn=_turn(action=_safe_action(), poc=_safe_poc()),
    )

    assert len(result.hypotheses) == 1
    assert len(result.admitted_plans) == 1
    assert result.poc is not None
    assert result.poc.adaptation.removed_unsafe_step_digests == ()
    assert result.finding_draft is not None
    assert result.finding_draft.status == "draft_unverified"
    assert result.target_dispatch_performed is False
    assert result.automatic_submission_performed is False
    assert result.provider_network_access == "provider_only"
    assert result.authority_grant_id == request.authority_grant.grant_id
    assert result.authority_grant_version == request.authority_grant.grant_version
    assert (
        result.admitted_plans[0].selected.candidate.intent.payload_digest
        == request.action_context.payload_digest
    )

    context = ReasoningTurnRequest.from_request(request)
    assert context.run_id == "run.1"
    assert context.evidence[0].cas_digest == request.observations.evidence_refs[0].cas_digest
    assert "invoice normalizer" in context.evidence[0].content
    assert context.evidence[0].untrusted is True
    assert context.output_schema_digest.startswith("sha256:")


def test_negative_only_turn_compiles_negative_without_an_action() -> None:
    evidence_id = sample_models()["EvidenceRef"].evidence_id
    raw = _turn()
    document = json.loads(raw)
    document["negative_results"] = [
        {
            "hypothesis_proposal_id": "hypothesis.1",
            "experiment_digest": "sha256:" + "1" * 64,
            "conclusion": "The negative control did not reproduce the candidate.",
            "evidence_ids": [evidence_id],
        }
    ]
    document["finding_draft"] = None
    result = _coordinator().run(
        request=_request(), raw_model_turn=json.dumps(document).encode()
    )
    assert len(result.negative_results) == 1
    assert result.admitted_plans == ()


@pytest.mark.parametrize(
    "raw",
    [
        lambda: _turn(action=_safe_action(action_class="destructive")),
        lambda: _turn(action=_safe_action(adapter_id="adapter.invented")),
        lambda: b'{"hypotheses":[],"hypotheses":[]}',
    ],
)
def test_bad_model_output_is_rejected_before_a_candidate_result(
    raw: Callable[[], bytes],
) -> None:
    request = _request()
    with pytest.raises(AuthorizedAutomationError):
        _coordinator().run(request=request, raw_model_turn=raw())


def test_oversized_model_output_is_rejected() -> None:
    with pytest.raises(AuthorizedAutomationError, match="byte limit"):
        _coordinator().run(
            request=_request(limits=AutomationLimits(max_response_bytes=512)),
            raw_model_turn=_turn() + b" " * 400,
        )


def test_outside_evidence_and_cross_run_context_are_rejected() -> None:
    document = json.loads(_turn())
    document["hypotheses"][0]["supporting_evidence_ids"] = ["evidence.outside"]
    with pytest.raises(AuthorizedAutomationError, match="outside"):
        _coordinator().run(
            request=_request(), raw_model_turn=json.dumps(document).encode()
        )

    cross_run = _request().model_copy(
        update={"action_context": _request().action_context.model_copy(update={"run_id": "run.2"})}
    )
    with pytest.raises(AuthorizedAutomationError):
        _coordinator().run(
            request=cross_run, raw_model_turn=_turn(action=_safe_action())
        )


def test_poc_without_action_cannot_escape_target_pack_or_identity_grant() -> None:
    base = _request()
    outside_pack = base.model_copy(
        update={
            "action_context": base.action_context.model_copy(
                update={"pack_id": "pack.outside"}
            ),
            "poc_context": base.poc_context.model_copy(
                update={"pack_id": "pack.outside"}
            ),
        }
    )
    with pytest.raises(AuthorizedAutomationError, match="pack"):
        _coordinator().run(request=outside_pack, raw_model_turn=_turn(poc=_safe_poc()))

    outside_subject = base.action_context.subject.model_copy(
        update={"identity_id": "identity.outside"}
    )
    outside_identity = base.model_copy(
        update={
            "action_context": base.action_context.model_copy(
                update={"subject": outside_subject}
            ),
            "poc_context": base.poc_context.model_copy(
                update={"subject": outside_subject}
            ),
        }
    )
    with pytest.raises(AuthorizedAutomationError, match="identity"):
        _coordinator().run(request=outside_identity, raw_model_turn=_turn(poc=_safe_poc()))


def test_unobserved_negative_and_mismatched_excerpt_are_rejected() -> None:
    evidence_id = sample_models()["EvidenceRef"].evidence_id
    document = json.loads(_turn())
    document["negative_results"] = [
        {
            "hypothesis_proposal_id": "hypothesis.1",
            "experiment_digest": "sha256:" + "9" * 64,
            "conclusion": "Invented negative.",
            "evidence_ids": [evidence_id],
        }
    ]
    with pytest.raises(AuthorizedAutomationError, match="unobserved experiment"):
        _coordinator().run(
            request=_request(), raw_model_turn=json.dumps(document).encode()
        )

    request = _request()
    excerpt = request.observations.excerpts[0]
    with pytest.raises(ValueError, match="digest mismatch"):
        ObservationExcerpt.model_validate(
            excerpt.model_copy(update={"content": "changed"}).model_dump(mode="python")
        )


@pytest.mark.parametrize(
    "raw_model_turn",
    (
        _turn(action=_safe_action()),
        _turn(poc=_safe_poc()),
    ),
)
def test_explicit_deny_blocks_model_action_and_poc_step(
    raw_model_turn: bytes,
) -> None:
    request = _request()
    existing_deny = request.authority_grant.action_policy.denied[0]
    policy = request.authority_grant.action_policy.model_copy(
        update={
            "denied": (
                existing_deny.model_copy(
                    update={"action_families": ("reference.digest",)}
                ),
            )
        }
    )
    grant = request.authority_grant.model_copy(update={"action_policy": policy})

    with pytest.raises(AuthorizedAutomationError, match="explicit deny"):
        _coordinator().run(
            request=request.model_copy(update={"authority_grant": grant}),
            raw_model_turn=raw_model_turn,
        )


def test_family_agnostic_explicit_deny_blocks_context_only_candidate() -> None:
    request = _request()
    existing_deny = request.authority_grant.action_policy.denied[0]
    policy = request.authority_grant.action_policy.model_copy(
        update={
            "denied": (
                existing_deny.model_copy(
                    update={
                        "action_families": (),
                        "path_pattern": request.action_context.path,
                        "methods": (request.action_context.method,),
                    }
                ),
            )
        }
    )
    grant = request.authority_grant.model_copy(update={"action_policy": policy})

    with pytest.raises(AuthorizedAutomationError, match="context matches an explicit deny"):
        _coordinator().run(
            request=request.model_copy(update={"authority_grant": grant}),
            raw_model_turn=_turn(),
        )
