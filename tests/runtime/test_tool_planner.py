from __future__ import annotations

import pytest

from faultloom.hypothesis import HypothesisSeed
from faultloom.tool_planner import (
    PlanningBudget,
    ToolCandidate,
    ToolEstimate,
    ToolEvidenceRole,
    ToolPlanner,
    ToolPlanningError,
    ToolPlanningUnavailableError,
)
from faultloom_protocol import (
    ActionIntent,
    AuthorityGrant,
    EvidenceCapability,
    ProvenanceKind,
    sha256_digest,
)
from faultloom_sdk import (
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdmissionGate,
    AdmissionOutcome,
    ManifestRegistry,
    reference_registry,
)
from tests.protocol.factories import NOW, sample_models


def _admitted(
    registry: ManifestRegistry,
) -> AdapterAdmissionRegistry:
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
    admission.record(
        AdapterAdmissionReceipt(
            adapter_id=manifest.adapter_id,
            manifest_digest=digest,
            gate=AdmissionGate.MODEL_UTILITY,
            outcome=AdmissionOutcome.PASSED,
            artifact_digest=manifest.output_schema_digest,
            unique_verified_positives=2,
        )
    )
    return admission


def _grant(*, action_kind: str = "reference.digest") -> AuthorityGrant:
    source = sample_models()["AuthorityGrant"]
    policy = source.action_policy.model_copy(
        update={"allowed_families": (action_kind,)}
    )
    return AuthorityGrant.model_validate(
        source.model_copy(
            update={
                "pack_ids": ("pack.reference",),
                "adapter_ids": ("adapter.reference",),
                "action_policy": policy,
            }
        ).model_dump(mode="python")
    )


def _hypothesis():
    return HypothesisSeed(
        run_id="run.1",
        statement="A bounded local transform may increase information.",
        provenance=(ProvenanceKind.BEHAVIOR,),
        created_at=NOW,
    ).as_record()


def _candidate(
    candidate_id: str,
    *,
    gain: int,
    cost: int,
    action_kind: str = "reference.digest",
    adapter_id: str = "adapter.reference",
) -> ToolCandidate:
    source = sample_models()["ActionIntent"]
    intent = ActionIntent.model_validate(
        source.model_copy(
            update={
                "action_id": f"action.{candidate_id}",
                "pack_id": "pack.reference",
                "action_kind": action_kind,
            }
        ).model_dump(mode="python")
    )
    return ToolCandidate(
        candidate_id=candidate_id,
        hypothesis_id=_hypothesis().hypothesis_id,
        intent=intent,
        adapter_id=adapter_id,
        capability="reference.digest_normalizer",
        expected_information_gain_bps=gain,
        estimate=ToolEstimate(
            rate_slots=1,
            duration_seconds=2,
            bytes=200,
            concurrency=1,
            actions=1,
            cost_microunits=cost,
        ),
    )


def _budget(*, cost: int = 100) -> PlanningBudget:
    return PlanningBudget(
        rate_slots=3,
        duration_seconds=20,
        bytes=2_000,
        concurrency=2,
        actions=3,
        cost_microunits=cost,
    )


def test_planner_deterministically_selects_feasible_information_gain() -> None:
    registry = reference_registry()
    admission = _admitted(registry)
    planner = ToolPlanner(registry, admission)
    infeasible = _candidate("high", gain=9_000, cost=101)
    selected = _candidate("feasible", gain=7_000, cost=10)

    first = planner.select(
        hypothesis=_hypothesis(),
        grant=_grant(),
        budget=_budget(),
        candidates=(infeasible, selected),
    )
    second = planner.select(
        hypothesis=_hypothesis(),
        grant=_grant(),
        budget=_budget(),
        candidates=(selected, infeasible),
    )

    assert first == second
    assert first.selected.candidate == selected
    assert first.selected.evidence_role is ToolEvidenceRole.CANDIDATE
    assert first.remaining == PlanningBudget(
        rate_slots=2,
        duration_seconds=18,
        bytes=1_800,
        concurrency=1,
        actions=2,
        cost_microunits=90,
    )
    snapshot = admission.doctor(selected.adapter_id)
    assert first.selected.receipt.admission_snapshot_digest == sha256_digest(
        snapshot.model_dump(mode="json")
    )
    assert first.selected.receipt.utility_receipt_digest == sha256_digest(
        snapshot.receipts[-1].model_dump(mode="json")
    )


def test_planner_fails_closed_for_unknown_or_unadmitted_adapter() -> None:
    registry = reference_registry()
    planner = ToolPlanner(registry, _admitted(registry))
    unknown = _candidate("unknown", gain=5_000, cost=1, adapter_id="adapter.unknown")
    with pytest.raises(ToolPlanningError, match="adapter"):
        planner.select(
            hypothesis=_hypothesis(),
            grant=_grant(),
            budget=_budget(),
            candidates=(unknown,),
        )

    pending = ToolPlanner(registry, AdapterAdmissionRegistry(registry))
    with pytest.raises(ToolPlanningError, match="admission"):
        pending.select(
            hypothesis=_hypothesis(),
            grant=_grant(),
            budget=_budget(),
            candidates=(_candidate("pending", gain=5_000, cost=1),),
        )


def test_planner_rejects_unknown_action_and_exhausted_budget() -> None:
    registry = reference_registry()
    planner = ToolPlanner(registry, _admitted(registry))
    unknown = _candidate("action", gain=5_000, cost=1, action_kind="unknown.action")
    with pytest.raises(ToolPlanningError, match="action"):
        planner.select(
            hypothesis=_hypothesis(),
            grant=_grant(action_kind="unknown.action"),
            budget=_budget(),
            candidates=(unknown,),
        )

    with pytest.raises(ToolPlanningUnavailableError, match="budget"):
        planner.select(
            hypothesis=_hypothesis(),
            grant=_grant(),
            budget=_budget(cost=0),
            candidates=(_candidate("cost", gain=5_000, cost=1),),
        )


def test_evidence_capable_adapter_still_requires_independent_replay() -> None:
    base = reference_registry()
    pack = base.packs[0]
    evidence_manifest = base.adapters[0].model_copy(
        update={"evidence_capability": EvidenceCapability.EVIDENCE_CAPABLE}
    )
    registry = ManifestRegistry(
        known_capability_descriptors=pack.capability_descriptors,
        known_action_compilers=pack.action_compilers,
        known_observation_normalizers=pack.observation_normalizers,
        known_hypothesis_providers=pack.hypothesis_providers,
        known_verifier_descriptors=pack.verifier_descriptors,
        known_evaluation_descriptors=pack.evaluation_descriptors,
        known_adapter_capabilities=evidence_manifest.capabilities,
        available_gateway_features=pack.required_gateway_features,
    )
    registry.install_pack(pack)
    registry.install_adapter(evidence_manifest)

    plan = ToolPlanner(registry, _admitted(registry)).select(
        hypothesis=_hypothesis(),
        grant=_grant(),
        budget=_budget(),
        candidates=(_candidate("evidence", gain=5_000, cost=1),),
    )

    assert (
        plan.selected.evidence_role
        is ToolEvidenceRole.CORROBORATING_REQUIRES_INDEPENDENT_REPLAY
    )
    assert all("verified" not in role.value for role in ToolEvidenceRole)
