from __future__ import annotations

from datetime import timedelta

import pytest

from faultloom_protocol import (
    AuthoritySigner,
    SignatureRollbackError,
    SignatureTamperError,
    SignedEngagementBundle,
    SignedRunResultBundle,
    sign_engagement_bundle,
    sign_run_result_bundle,
    verify_engagement_bundle,
    verify_run_result_bundle,
)

from .factories import NOW, sample_models


def test_signed_engagement_bundle_json_round_trip() -> None:
    bundle = sample_models()["EngagementBundle"]
    signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    signed = sign_engagement_bundle(bundle, signer, signed_at=NOW)
    restored = SignedEngagementBundle.model_validate_json(signed.model_dump_json())

    assert verify_engagement_bundle(
        restored,
        signer.public_key_record,
        now=NOW + timedelta(minutes=1),
        expected_engagement_id="engagement.1",
    ) == bundle


def test_signed_run_result_bundle_json_round_trip() -> None:
    bundle = sample_models()["RunResultBundle"]
    signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    signed = sign_run_result_bundle(
        bundle,
        signer,
        signed_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    restored = SignedRunResultBundle.model_validate_json(signed.model_dump_json())

    assert verify_run_result_bundle(
        restored,
        signer.public_key_record,
        now=NOW + timedelta(minutes=1),
        minimum_version=2,
        expected_engagement_id="engagement.1",
    ) == bundle


def test_bundle_identity_and_monotonic_version_are_bound() -> None:
    bundle = sample_models()["RunResultBundle"]
    signer = AuthoritySigner.generate()
    signed = sign_run_result_bundle(bundle, signer, signed_at=NOW)

    with pytest.raises(SignatureRollbackError):
        verify_run_result_bundle(
            signed, signer.public_key_record, now=NOW, minimum_version=3
        )
    with pytest.raises(SignatureTamperError, match="different engagement"):
        verify_run_result_bundle(
            signed,
            signer.public_key_record,
            now=NOW,
            expected_engagement_id="engagement.other",
        )
