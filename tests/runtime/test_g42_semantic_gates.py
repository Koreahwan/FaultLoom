from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import pytest
from faultloom_protocol import AuthoritySigner

from faultloom.g42_semantic_gates import (
    ExternalInertAdmissionError,
    ExternalInertAdmissionVerifier,
    InertDepthFixture,
    InertEdgeAdmission,
    SignedInertEdgeAdmission,
    build_inert_depth_fixture,
    execute_inert_gate,
    inert_edge_admission_bytes,
    inert_edge_fingerprint,
    inert_fixture_run_id,
)
from faultloom.semantic_depth import BudgetVector, SemanticDepthEngine


NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
EXPIRES_AT = "2030-01-01T00:10:00Z"
AUTHORITY_ID = "authority.g42.external"


def _signed_tokens(
    fixture: InertDepthFixture,
    signer: AuthoritySigner,
    *,
    clean_replay: bool = False,
    expires_at: str = EXPIRES_AT,
) -> tuple[SignedInertEdgeAdmission, ...]:
    report = SemanticDepthEngine(fixture.graph).search(fixture.config)
    assert report.witness is not None
    edge_by_id = {edge.edge_id: edge for edge in fixture.graph.edges}
    remaining = fixture.config.budget
    tokens = []
    run_id = inert_fixture_run_id(fixture, clean_replay=clean_replay)
    for index, edge_id in enumerate(report.witness.edge_ids):
        edge = edge_by_id[edge_id]
        admission = InertEdgeAdmission(
            authority_id=AUTHORITY_ID,
            edge_id=edge.edge_id,
            edge_fingerprint=inert_edge_fingerprint(edge),
            run_id=run_id,
            run_class=fixture.config.run_class,
            expires_at=expires_at,
            remaining_budget=remaining,
            lease_id=f"external-admission.{run_id}.{index}",
            lease_epoch=fixture.config.authority_epoch,
            verifier_key_id=signer.key_id,
        )
        tokens.append(
            SignedInertEdgeAdmission(
                admission=admission,
                signature=signer.sign(inert_edge_admission_bytes(admission)),
            )
        )
        remaining = BudgetVector(
            *(
                left - right
                for left, right in zip(
                    remaining.as_tuple(), edge.budget.as_tuple()
                )
            )
        )
    return tuple(tokens)


def _execute(fixture: InertDepthFixture, signer: AuthoritySigner):
    primary_verifier, replay_verifier = _verifiers(fixture, signer)
    return execute_inert_gate(
        fixture,
        admission_tokens=_signed_tokens(fixture, signer),
        clean_replay_admission_tokens=_signed_tokens(
            fixture, signer, clean_replay=True
        ),
        admission_verifier=primary_verifier,
        clean_replay_admission_verifier=replay_verifier,
    )


def _verifiers(
    fixture: InertDepthFixture,
    signer: AuthoritySigner,
) -> tuple[ExternalInertAdmissionVerifier, ExternalInertAdmissionVerifier]:
    def build(*, clean_replay: bool) -> ExternalInertAdmissionVerifier:
        return ExternalInertAdmissionVerifier(
            trusted_verifier_key=signer.public_key_record,
            verification_time=NOW,
            authority_id=AUTHORITY_ID,
            run_id=inert_fixture_run_id(fixture, clean_replay=clean_replay),
            run_class=fixture.config.run_class,
            lease_epoch=fixture.config.authority_epoch,
        )

    return build(clean_replay=False), build(clean_replay=True)


@pytest.mark.parametrize("depth", (4, 5, 6))
def test_v02_exact_fixtures_require_external_admissions(depth: int) -> None:
    fixture = build_inert_depth_fixture(depth)
    receipt = _execute(fixture, AuthoritySigner.generate())

    assert fixture.provenance == "fully_simulated"
    assert receipt.expected_depth == depth
    assert receipt.witness.semantic_depth == depth
    assert receipt.clean_replay_witness == receipt.witness
    assert receipt.clean_replay_run_id != receipt.run_id
    assert receipt.negative_terminal_reason == "unreachable"
    assert receipt.run_class is None
    assert receipt.lost_ids == 0
    assert receipt.duplicate_effects == 0
    assert receipt.cleanup_result == "initial_state_restored"

    assert tuple(item.edge_id for item in receipt.edge_admission_receipts) == (
        receipt.witness.edge_ids
    )
    assert {item.disposition for item in receipt.edge_admission_receipts} == {
        "externally_admitted_inert_edge"
    }
    assert {item.gateway_lease for item in receipt.edge_admission_receipts} == {False}
    assert len(receipt.clean_replay_edge_admission_receipts) == depth
    assert len(receipt.budget_receipts) == depth * 3
    assert len(receipt.clean_replay_budget_receipts) == depth * 3
    for offset, edge_id in enumerate(receipt.witness.edge_ids):
        edge_receipts = receipt.budget_receipts[offset * 3 : offset * 3 + 3]
        assert tuple(item.operation for item in edge_receipts) == (
            "reserve",
            "consume",
            "release",
        )
        assert {item.edge_id for item in edge_receipts} == {edge_id}
        assert len({item.admission_token_id for item in edge_receipts}) == 1
        assert len({item.reservation_id for item in edge_receipts}) == 1
        assert edge_receipts[0].amount.as_tuple() == (1, 2, 3, 1)
        assert edge_receipts[1].amount == edge_receipts[0].amount
        assert edge_receipts[2].amount.as_tuple() == (0, 0, 0, 0)
    assert receipt.budget_receipts[-1].remaining.as_tuple() == (0, 0, 0, 0)


@pytest.mark.parametrize("depth", (7, 8, 9, 10))
def test_v02_stress_bounds_replay_with_separate_run_admissions(depth: int) -> None:
    fixture = build_inert_depth_fixture(depth)
    signer = AuthoritySigner.generate()
    first = _execute(fixture, signer)
    second = _execute(build_inert_depth_fixture(depth), signer)

    assert first.witness.semantic_depth == depth
    assert first.clean_replay_witness == first.witness
    assert first.clean_replay_run_id != first.run_id
    assert first.checkpoint_json == second.checkpoint_json
    assert first == second
    assert first.to_json() == second.to_json()
    assert json.dumps(
        json.loads(first.to_json()), sort_keys=True, separators=(",", ":")
    ) == first.to_json()
    assert first.lost_ids == 0
    assert first.duplicate_effects == 0
    assert first.cleanup_result == "initial_state_restored"


@pytest.mark.parametrize("depth", (11, 16, 24))
def test_generated_structural_conformance_has_no_depth_ceiling(depth: int) -> None:
    fixture = build_inert_depth_fixture(depth)
    receipt = _execute(fixture, AuthoritySigner.generate())

    assert fixture.config.run_class == "generated_structural_conformance"
    assert receipt.run_class == "generated_structural_conformance"
    assert receipt.witness.semantic_depth == depth
    assert receipt.clean_replay_witness.semantic_depth == depth
    assert receipt.negative_terminal_reason == "unreachable"
    assert receipt.lost_ids == 0
    assert receipt.duplicate_effects == 0
    assert receipt.cleanup_result == "initial_state_restored"

    with pytest.raises(FrozenInstanceError):
        setattr(fixture.config, "run_class", "exploratory_research_run")


def test_missing_tampered_expired_cross_edge_and_budget_admissions_fail_closed() -> None:
    fixture = build_inert_depth_fixture(4)
    signer = AuthoritySigner.generate()
    primary = _signed_tokens(fixture, signer)
    replay = _signed_tokens(fixture, signer, clean_replay=True)
    primary_verifier, replay_verifier = _verifiers(fixture, signer)

    def execute_primary(tokens: tuple[SignedInertEdgeAdmission, ...]):
        return execute_inert_gate(
            fixture,
            admission_tokens=tokens,
            clean_replay_admission_tokens=replay,
            admission_verifier=primary_verifier,
            clean_replay_admission_verifier=replay_verifier,
        )

    def resign(admission: InertEdgeAdmission) -> SignedInertEdgeAdmission:
        return SignedInertEdgeAdmission(
            admission,
            signer.sign(inert_edge_admission_bytes(admission)),
        )

    with pytest.raises(ExternalInertAdmissionError, match="exactly one"):
        execute_primary(primary[:-1])

    tampered_payload = replace(
        primary[0].admission, edge_fingerprint="inert-edge-fingerprint.tampered"
    )
    tampered = (
        SignedInertEdgeAdmission(tampered_payload, primary[0].signature),
        *primary[1:],
    )
    with pytest.raises(ExternalInertAdmissionError, match="signature"):
        execute_primary(tampered)

    expired = _signed_tokens(
        fixture, signer, expires_at="2030-01-01T00:00:00Z"
    )
    with pytest.raises(ExternalInertAdmissionError, match="expired"):
        execute_primary(expired)

    cross_edge = (primary[1], primary[0], *primary[2:])
    with pytest.raises(ExternalInertAdmissionError, match="another edge"):
        execute_primary(cross_edge)

    over_budget_payload = replace(
        primary[0].admission, remaining_budget=BudgetVector(0, 0, 0, 0)
    )
    over_budget = (
        SignedInertEdgeAdmission(
            over_budget_payload,
            signer.sign(inert_edge_admission_bytes(over_budget_payload)),
        ),
        *primary[1:],
    )
    with pytest.raises(ExternalInertAdmissionError, match="budget is exceeded"):
        execute_primary(over_budget)

    wrong_authority = (
        resign(replace(primary[0].admission, authority_id="authority.other")),
        *primary[1:],
    )
    with pytest.raises(ExternalInertAdmissionError, match="authority"):
        execute_primary(wrong_authority)

    wrong_epoch = (
        resign(replace(primary[0].admission, lease_epoch="epoch.other")),
        *primary[1:],
    )
    with pytest.raises(ExternalInertAdmissionError, match="lease epoch"):
        execute_primary(wrong_epoch)

    reused_external_lease = (
        primary[0],
        resign(replace(primary[1].admission, lease_id=primary[0].admission.lease_id)),
        *primary[2:],
    )
    with pytest.raises(ExternalInertAdmissionError, match="already consumed"):
        execute_primary(reused_external_lease)

    with pytest.raises(ExternalInertAdmissionError, match="signature"):
        wrong_verifiers = _verifiers(fixture, AuthoritySigner.generate())
        execute_inert_gate(
            fixture,
            admission_tokens=primary,
            clean_replay_admission_tokens=replay,
            admission_verifier=wrong_verifiers[0],
            clean_replay_admission_verifier=wrong_verifiers[1],
        )


def test_admission_is_one_time_and_primary_token_cannot_cross_replay_run() -> None:
    fixture = build_inert_depth_fixture(4)
    signer = AuthoritySigner.generate()
    token = _signed_tokens(fixture, signer)[0]
    edge = next(edge for edge in fixture.graph.edges if edge.edge_id == token.admission.edge_id)
    verifier = ExternalInertAdmissionVerifier(
        trusted_verifier_key=signer.public_key_record,
        verification_time=NOW,
        authority_id=AUTHORITY_ID,
        run_id=inert_fixture_run_id(fixture),
        run_class=fixture.config.run_class,
        lease_epoch=fixture.config.authority_epoch,
    )

    verifier.admit(token, edge=edge, expected_remaining=fixture.config.budget)
    with pytest.raises(ExternalInertAdmissionError, match="already consumed"):
        verifier.admit(token, edge=edge, expected_remaining=fixture.config.budget)

    primary = _signed_tokens(fixture, signer)
    replay = _signed_tokens(fixture, signer, clean_replay=True)
    primary_verifier, replay_verifier = _verifiers(fixture, signer)
    execute_inert_gate(
        fixture,
        admission_tokens=primary,
        clean_replay_admission_tokens=replay,
        admission_verifier=primary_verifier,
        clean_replay_admission_verifier=replay_verifier,
    )
    with pytest.raises(ExternalInertAdmissionError, match="already consumed"):
        execute_inert_gate(
            fixture,
            admission_tokens=primary,
            clean_replay_admission_tokens=replay,
            admission_verifier=primary_verifier,
            clean_replay_admission_verifier=replay_verifier,
        )

    fresh_primary_verifier, fresh_replay_verifier = _verifiers(fixture, signer)
    with pytest.raises(ExternalInertAdmissionError, match="run binding"):
        execute_inert_gate(
            fixture,
            admission_tokens=primary,
            clean_replay_admission_tokens=primary,
            admission_verifier=fresh_primary_verifier,
            clean_replay_admission_verifier=fresh_replay_verifier,
        )
