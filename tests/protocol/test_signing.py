from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from faultloom_protocol import (
    ActionClass,
    AuthorityRevokedError,
    AuthoritySigner,
    SignatureExpiredError,
    SignatureNotYetValidError,
    SignatureRollbackError,
    SignatureTamperError,
    UnknownKeyError,
    sign_authority_grant,
    sign_scope_epoch,
    verify_authority_grant,
    verify_scope_epoch,
)

from .factories import NOW, sample_models


def test_authority_signature_round_trip() -> None:
    grant = sample_models()["AuthorityGrant"]
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    envelope = sign_authority_grant(grant, signer, signed_at=NOW)

    encoded = envelope.model_dump_json()
    restored = type(envelope).model_validate_json(encoded)
    verified = verify_authority_grant(
        restored,
        signer.public_key_record,
        now=NOW + timedelta(minutes=1),
        minimum_version=3,
        expected_grant_id="grant.1",
    )
    assert verified == grant


def test_payload_tamper_is_rejected() -> None:
    grant = sample_models()["AuthorityGrant"]
    signer = AuthoritySigner.generate()
    envelope = sign_authority_grant(grant, signer, signed_at=NOW)
    tampered_payload = grant.model_copy(update={"issued_to": "attacker.1"})
    tampered = envelope.model_copy(update={"payload": tampered_payload})

    with pytest.raises(SignatureTamperError, match="payload digest"):
        verify_authority_grant(tampered, signer.public_key_record, now=NOW)


def test_signature_forgery_and_unknown_key_are_rejected() -> None:
    grant = sample_models()["AuthorityGrant"]
    trusted = AuthoritySigner.generate()
    attacker = AuthoritySigner.generate()
    forged = sign_authority_grant(grant, attacker, signed_at=NOW)

    with pytest.raises(UnknownKeyError, match="trusted key"):
        verify_authority_grant(forged, trusted.public_key_record, now=NOW)

    valid = sign_authority_grant(grant, trusted, signed_at=NOW)
    bad_signature = valid.signature.model_copy(update={"signature": "A" * 86})
    tampered = valid.model_copy(update={"signature": bad_signature})
    with pytest.raises(SignatureTamperError, match="verification failed"):
        verify_authority_grant(tampered, trusted.public_key_record, now=NOW)


def test_expiry_future_time_and_rollback_fail_closed() -> None:
    grant = sample_models()["AuthorityGrant"]
    signer = AuthoritySigner.generate()
    envelope = sign_authority_grant(grant, signer, signed_at=NOW)

    with pytest.raises(SignatureExpiredError, match="expired"):
        verify_authority_grant(envelope, signer.public_key_record, now=grant.expires_at)
    with pytest.raises(SignatureRollbackError, match="below trusted minimum"):
        verify_authority_grant(envelope, signer.public_key_record, now=NOW, minimum_version=4)

    future_envelope = sign_authority_grant(
        grant, signer, signed_at=NOW + timedelta(minutes=10)
    )
    with pytest.raises(SignatureNotYetValidError, match="future"):
        verify_authority_grant(
            future_envelope,
            signer.public_key_record,
            now=NOW,
            maximum_clock_skew=timedelta(0),
        )


def test_signed_expiry_cannot_diverge_from_authority_expiry() -> None:
    grant = sample_models()["AuthorityGrant"]
    signer = AuthoritySigner.generate()
    envelope = sign_authority_grant(grant, signer, signed_at=NOW)
    divergent = envelope.signature.model_copy(
        update={"expires_at": grant.expires_at - timedelta(minutes=1)}
    )
    tampered = envelope.model_copy(update={"signature": divergent})
    with pytest.raises(SignatureTamperError):
        verify_authority_grant(tampered, signer.public_key_record, now=NOW)


def test_artifact_cannot_be_signed_before_issuance() -> None:
    grant = sample_models()["AuthorityGrant"]
    signer = AuthoritySigner.generate()
    with pytest.raises(ValueError, match="before it is issued"):
        sign_authority_grant(grant, signer, signed_at=NOW - timedelta(seconds=1))


def test_signing_revalidates_model_copy_and_nested_policy() -> None:
    grant = sample_models()["AuthorityGrant"]
    invalid_policy = grant.action_policy.model_copy(
        update={"allowed_classes": (ActionClass.DESTRUCTIVE,)}
    )
    invalid_grant = grant.model_copy(update={"action_policy": invalid_policy})
    signer = AuthoritySigner.generate()
    with pytest.raises(ValidationError):
        sign_authority_grant(invalid_grant, signer, signed_at=NOW)


def test_not_before_is_enforced() -> None:
    grant = sample_models()["AuthorityGrant"]
    future_grant = grant.model_copy(update={"not_before": NOW + timedelta(minutes=5)})
    signer = AuthoritySigner.generate()
    envelope = sign_authority_grant(future_grant, signer, signed_at=NOW)
    with pytest.raises(SignatureNotYetValidError, match="not active"):
        verify_authority_grant(envelope, signer.public_key_record, now=NOW)


def test_scope_epoch_rollback_and_revocation_are_enforced() -> None:
    epoch = sample_models()["ScopeEpoch"]
    signer = AuthoritySigner.generate()
    envelope = sign_scope_epoch(epoch, signer, signed_at=NOW)
    assert verify_scope_epoch(
        envelope,
        signer.public_key_record,
        now=NOW,
        minimum_epoch=7,
        expected_grant_id="grant.1",
    ) == epoch

    with pytest.raises(SignatureRollbackError):
        verify_scope_epoch(envelope, signer.public_key_record, now=NOW, minimum_epoch=8)

    revoked = epoch.model_copy(
        update={"epoch": 8, "revoked": True, "revocation_reason": "operator stop"}
    )
    revoked_envelope = sign_scope_epoch(revoked, signer, signed_at=NOW)
    with pytest.raises(AuthorityRevokedError, match="operator stop"):
        verify_scope_epoch(revoked_envelope, signer.public_key_record, now=NOW)


def test_private_signer_is_not_a_serializable_protocol_model() -> None:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    representation = repr(signer)
    assert "private_key=<redacted>" in representation
    assert bytes(range(32)).hex() not in representation
    assert not hasattr(signer, "model_dump")
