from __future__ import annotations

import socket
from dataclasses import replace
from urllib import request

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from faultloom_mobile import (
    G46_PINNED_MANIFEST,
    G46_PINNED_MANIFEST_DIGEST,
    G46AdmissionToken,
    G46AuthorityVerifier,
    G46SignedAuthorityAdmission,
    G46SyntheticIdentities,
    assert_g46_no_secrets,
    prepare_g46_gateway_command,
)
from labs.mobile_api import G46FixtureState, OwnedG46MobileApiFixture
from labs.mobile_api import fixture as mobile_fixture


NOW = 1_800_000_000


def _public_bytes(signer: Ed25519PrivateKey) -> bytes:
    return signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _signed_admission(
    signer: Ed25519PrivateKey,
    identities: G46SyntheticIdentities,
    *,
    nonce: str = "synthetic.g46.nonce.1",
    issued_at_epoch_seconds: int = NOW - 1,
    expires_at_epoch_seconds: int = NOW + 60,
) -> G46SignedAuthorityAdmission:
    unsigned = G46SignedAuthorityAdmission(
        authority_id=G46_PINNED_MANIFEST.authority_id,
        scope_id=G46_PINNED_MANIFEST.scope_id,
        device_id=identities.device_id,
        application_id=identities.application_id,
        api_id=identities.api_id,
        action_budget=G46_PINNED_MANIFEST.action_budget,
        nonce=nonce,
        issued_at_epoch_seconds=issued_at_epoch_seconds,
        expires_at_epoch_seconds=expires_at_epoch_seconds,
        signature=b"",
    )
    return replace(
        unsigned,
        signature=signer.sign(unsigned.canonical_authority_scope_budget_bytes()),
    )


def _fixture() -> tuple[OwnedG46MobileApiFixture, G46AuthorityVerifier]:
    signer = Ed25519PrivateKey.generate()
    identities = G46SyntheticIdentities()
    verifier = G46AuthorityVerifier(G46_PINNED_MANIFEST, _public_bytes(signer), NOW)
    token = verifier.admit(_signed_admission(signer, identities), identities)
    return OwnedG46MobileApiFixture(token, _public_bytes(signer), NOW), verifier


def test_g46_positive_candidate_is_admitted_bounded_inert_and_deterministic() -> None:
    first_fixture, _ = _fixture()
    second_fixture, _ = _fixture()

    with first_fixture:
        first = first_fixture.run("mismatch")
        first_state = first_fixture.state
        first_fixture.assert_fully_simulated()
        first_fixture.assert_no_secrets()
    with second_fixture:
        second = second_fixture.run("mismatch")
        second_fixture.assert_fully_simulated()

    assert G46_PINNED_MANIFEST.manifest_digest == G46_PINNED_MANIFEST_DIGEST
    assert first.observation.evidence.classification == "diagnostic_candidate"
    assert first.observation.evidence.link_matches
    assert not first.observation.evidence.audience_matches
    assert first.command is not None
    assert second.command is not None
    assert first.command.dispatch_required
    assert not first.command.dispatched
    assert first.command.execution_mode == "inert_preparation_only"
    assert first.command.target_origin == "fixture://owned-g46-mobile-api"
    assert first.command.action_budget == 1
    assert first.receipt.fixture_invariants_passed
    assert first.receipt.classification == "candidate_only"
    assert not first.receipt.security_verified
    assert not first.receipt.command_dispatched
    assert first_state == G46FixtureState(phase="completed", runs=1)
    assert first.command.command_digest == second.command.command_digest
    assert first.receipt.receipt_digest == second.receipt.receipt_digest
    assert first_fixture.state == first_fixture.initial_state
    assert second_fixture.state == second_fixture.initial_state


def test_g46_matched_audience_link_and_api_negative_control_prepares_nothing() -> None:
    fixture, _ = _fixture()

    with fixture:
        run = fixture.run("negative")
        fixture.assert_fully_simulated()

    assert run.observation.evidence.classification == "matched_negative_control"
    assert run.observation.evidence.audience_matches
    assert run.observation.evidence.link_matches
    assert run.observation.evidence.app_link_application_id == fixture.identities.application_id
    assert run.observation.evidence.api_binding_id == fixture.identities.api_id
    assert run.command is None
    assert run.receipt.control == "matched_negative_control"
    assert not run.receipt.command_prepared
    assert not run.receipt.command_dispatched
    assert run.receipt.classification == "candidate_only"
    assert not run.receipt.security_verified
    assert fixture.state == fixture.initial_state


def test_g46_rejects_wrong_key_tamper_replay_expiry_and_target_mismatch() -> None:
    signer = Ed25519PrivateKey.generate()
    wrong_signer = Ed25519PrivateKey.generate()
    identities = G46SyntheticIdentities()
    admission = _signed_admission(signer, identities)

    with pytest.raises(ValueError, match="signature"):
        G46AuthorityVerifier(G46_PINNED_MANIFEST, _public_bytes(wrong_signer), NOW).admit(
            admission, identities
        )

    verifier = G46AuthorityVerifier(G46_PINNED_MANIFEST, _public_bytes(signer), NOW)
    with pytest.raises(ValueError, match="signature"):
        verifier.admit(replace(admission, nonce="synthetic.g46.nonce.tampered"), identities)
    token = verifier.admit(admission, identities)
    with pytest.raises(ValueError, match="replay"):
        verifier.admit(admission, identities)

    expired = _signed_admission(
        signer,
        identities,
        nonce="synthetic.g46.nonce.expired",
        expires_at_epoch_seconds=NOW,
    )
    with pytest.raises(ValueError, match="expired"):
        G46AuthorityVerifier(G46_PINNED_MANIFEST, _public_bytes(signer), NOW).admit(
            expired, identities
        )

    fixture = OwnedG46MobileApiFixture(token, _public_bytes(signer), NOW)
    with fixture:
        observation = fixture.run("mismatch").observation
    outside_target = replace(
        observation,
        evidence=replace(
            observation.evidence, app_link_application_id="synthetic.g46.application.other"
        ),
    )
    with pytest.raises(ValueError, match="outside the admitted scope"):
        prepare_g46_gateway_command(
            outside_target,
            G46_PINNED_MANIFEST,
            token,
            _public_bytes(signer),
            NOW,
        )


def test_g46_directly_constructed_token_is_rechecked_before_consumption() -> None:
    signer = Ed25519PrivateKey.generate()
    identities = G46SyntheticIdentities()
    authority_public_key = _public_bytes(signer)
    valid_admission = _signed_admission(signer, identities)
    valid_token = G46AuthorityVerifier(
        G46_PINNED_MANIFEST, authority_public_key, NOW
    ).admit(valid_admission, identities)
    fixture = OwnedG46MobileApiFixture(valid_token, authority_public_key, NOW)
    with fixture:
        observation = fixture.run("mismatch").observation

    forged_token = G46AdmissionToken(replace(valid_admission, signature=b"\x00" * 64))
    with pytest.raises(ValueError, match="signature"):
        prepare_g46_gateway_command(
            observation,
            G46_PINNED_MANIFEST,
            forged_token,
            authority_public_key,
            NOW,
        )


def test_g46_rejects_reuse_until_reset_and_cleanup_restores_initial_state() -> None:
    fixture, _ = _fixture()
    _ = fixture.run("mismatch")

    with pytest.raises(RuntimeError, match="reset or cleanup"):
        _ = fixture.run("negative")

    fixture.reset()
    assert fixture.state == fixture.initial_state
    _ = fixture.run("negative")
    fixture.cleanup()
    assert fixture.state == fixture.initial_state


def test_g46_uses_no_direct_egress_under_socket_http_sentinels(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("direct egress is forbidden in G46")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(request, "urlopen", denied)
    monkeypatch.setattr(mobile_fixture, "urlopen", denied)
    fixture, _ = _fixture()
    with fixture:
        run = fixture.run("mismatch")

    assert run.command is not None
    assert not run.command.dispatched


def test_g46_secret_guard_is_explicit() -> None:
    with pytest.raises(AssertionError, match="secret material"):
        assert_g46_no_secrets({"access_token": "not-allowed"})
