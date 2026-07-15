from __future__ import annotations

from faultloom.patch_variant import (
    AdaptationRequest,
    CandidatePoCStep,
    StepHazard,
)
from faultloom_protocol import ActionClass, ResourceRef, SubjectRef

from .contracts import PatchVariantFixtureCase
from .fixture_support import NOW, RUN_ID, evidence


def build_adaptation_request(
    fixture_case: PatchVariantFixtureCase,
) -> AdaptationRequest:
    safe_step = CandidatePoCStep(
        step_id="step.safe-canary",
        action_class=ActionClass.SAFE_PROBE,
        action_kind="semantic_http",
        method="GET",
        expected_effect="read only the inert owned canary marker",
        negative_control="patched route denies the inert canary",
    )
    optional_step = safe_step.model_copy(
        update={"step_id": "step.optional-banner", "required": False}
    )
    shell_step = safe_step.model_copy(
        update={"step_id": "step.shell", "hazard": StepHazard.SHELL}
    )
    dump_step = safe_step.model_copy(
        update={"step_id": "step.dump", "hazard": StepHazard.DATA_DUMP}
    )
    destructive_step = safe_step.model_copy(
        update={
            "step_id": "step.destructive",
            "action_class": ActionClass.DESTRUCTIVE,
            "hazard": StepHazard.DESTRUCTIVE,
        }
    )
    return AdaptationRequest(
        adaptation_id=f"{fixture_case.case_id}.adaptation",
        recipe_id=f"{fixture_case.case_id}.recipe",
        run_id=RUN_ID,
        target_id="target.patch-variant-lab",
        pack_id="faultloom.web",
        route_ref=ResourceRef(
            schema_version="0.1.0",
            resource_id="resource.inert-canary",
            resource_kind="owned_canary",
            target_id="target.patch-variant-lab",
            tenant_id="tenant.alpha",
        ),
        route_path="/owned/canary",
        identity_context_id="identity-context.owner",
        subject=SubjectRef(
            schema_version="0.1.0",
            subject_id="subject.owner",
            subject_kind="operator_provisioned_identity",
            identity_id="identity.owner",
            tenant_id="tenant.alpha",
        ),
        transport="https",
        prerequisite_ids=("prerequisite.owned-canary",),
        prerequisites=("owned test identity and inert canary are provisioned",),
        candidate_steps=(
            safe_step,
            optional_step,
            shell_step,
            dump_step,
            destructive_step,
        ),
        expected_observable_effect="the inert owned canary marker is returned",
        negative_controls=("patched route denies the inert canary",),
        cleanup_plan_ref="cleanup.canary-reset",
        requested_at=NOW,
        evidence_refs=(evidence("adaptation.provenance"),),
    )
