from __future__ import annotations

from datetime import timedelta

import pytest

from faultloom.automation import (
    ModelDisclosureApproval,
    ModelDisclosureError,
    sign_model_disclosure_approval,
    verify_model_disclosure_approval,
)
from faultloom_protocol import AuthoritySigner
from tests.protocol.factories import NOW


SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("51" * 32))
OTHER_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("52" * 32))


def _payload() -> ModelDisclosureApproval:
    return ModelDisclosureApproval(
        approval_id="model-disclosure.test",
        run_id="run.1",
        evidence_id="evidence.1",
        source_cas_digest="sha256:" + "1" * 64,
        redaction_digest="sha256:" + "2" * 64,
        content_digest="sha256:" + "3" * 64,
        media_type="text/plain",
        data_policy_id="policy.no-training",
        allowed_provider_ids=("provider.test",),
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        approver_key_id=SIGNER.key_id,
    )


def _verify(envelope, trust_registry):
    return verify_model_disclosure_approval(
        envelope,
        trust_registry,
        expected_run_id="run.1",
        expected_evidence_id="evidence.1",
        expected_source_cas_digest="sha256:" + "1" * 64,
        expected_redaction_digest="sha256:" + "2" * 64,
        expected_content_digest="sha256:" + "3" * 64,
        expected_media_type="text/plain",
        expected_data_policy_id="policy.no-training",
        expected_provider_id="provider.test",
        verification_time=NOW,
    )


def test_signed_disclosure_verifies_all_bindings() -> None:
    envelope = sign_model_disclosure_approval(_payload(), SIGNER)

    verified = _verify(envelope, {SIGNER.key_id: SIGNER.public_key_record})

    assert verified == _payload()


def test_disclosure_rejects_unknown_key_and_tampered_payload() -> None:
    envelope = sign_model_disclosure_approval(_payload(), SIGNER)
    with pytest.raises(ModelDisclosureError, match="absent"):
        _ = _verify(envelope, {OTHER_SIGNER.key_id: OTHER_SIGNER.public_key_record})

    tampered_payload = envelope.payload.model_copy(
        update={"allowed_provider_ids": ("provider.outside",)}
    )
    tampered = envelope.model_copy(
        update={
            "payload": tampered_payload,
            "payload_digest": "sha256:" + "4" * 64,
        }
    )
    with pytest.raises((ModelDisclosureError, ValueError)):
        _ = _verify(tampered, {SIGNER.key_id: SIGNER.public_key_record})


def test_disclosure_rejects_provider_or_time_outside_approval() -> None:
    envelope = sign_model_disclosure_approval(_payload(), SIGNER)
    trust = {SIGNER.key_id: SIGNER.public_key_record}

    with pytest.raises(ModelDisclosureError, match="provider"):
        _ = verify_model_disclosure_approval(
            envelope,
            trust,
            expected_run_id="run.1",
            expected_evidence_id="evidence.1",
            expected_source_cas_digest="sha256:" + "1" * 64,
            expected_redaction_digest="sha256:" + "2" * 64,
            expected_content_digest="sha256:" + "3" * 64,
            expected_media_type="text/plain",
            expected_data_policy_id="policy.no-training",
            expected_provider_id="provider.outside",
            verification_time=NOW,
        )
    with pytest.raises(ModelDisclosureError, match="validity window"):
        _ = verify_model_disclosure_approval(
            envelope,
            trust,
            expected_run_id="run.1",
            expected_evidence_id="evidence.1",
            expected_source_cas_digest="sha256:" + "1" * 64,
            expected_redaction_digest="sha256:" + "2" * 64,
            expected_content_digest="sha256:" + "3" * 64,
            expected_media_type="text/plain",
            expected_data_policy_id="policy.no-training",
            expected_provider_id="provider.test",
            verification_time=NOW + timedelta(hours=1),
        )
