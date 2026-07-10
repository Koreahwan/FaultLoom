from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from faultloom_protocol import (
    AuthoritySigner,
    SignatureNotYetValidError,
    SignatureTamperError,
    UnknownKeyError,
    signing_bytes,
    sha256_digest,
    sign_authority_grant,
    sign_engagement_bundle,
    sign_run_result_bundle,
    verify_engagement_bundle,
    verify_run_result_bundle,
)

from .factories import D1, NOW, sample_models


def _replace(model: object, **updates: object) -> object:
    document = model.model_dump(mode="python")  # type: ignore[attr-defined]
    document.update(updates)
    return type(model).model_validate(document)


def test_engagement_preserves_and_verifies_independently_signed_authority() -> None:
    bundle = sample_models()["EngagementBundle"]
    embedded = bundle.authority_grant
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    signed = sign_engagement_bundle(bundle, outer_signer, signed_at=NOW)

    verified = verify_engagement_bundle(
        signed,
        outer_signer.public_key_record,
        authority_public_key=authority_signer.public_key_record,
        now=NOW,
        expected_engagement_id=bundle.engagement_id,
        expected_grant_id=embedded.payload.grant_id,
        minimum_authority_version=embedded.payload.grant_version,
    )
    assert verified.authority_grant == embedded


def test_engagement_verifier_requires_a_separate_authority_trust_key() -> None:
    bundle = sample_models()["EngagementBundle"]
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    signed = sign_engagement_bundle(bundle, outer_signer, signed_at=NOW)

    with pytest.raises(TypeError, match="authority_public_key"):
        verify_engagement_bundle(
            signed,
            outer_signer.public_key_record,
            now=NOW,
        )


def test_outer_bundle_signer_cannot_substitute_for_authority_signer() -> None:
    bundle = sample_models()["EngagementBundle"]
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    forged_authority = sign_authority_grant(
        bundle.authority_grant.payload,
        outer_signer,
        signed_at=NOW,
    )
    manifest = _replace(
        bundle.run_manifest,
        authority_digest=sha256_digest(forged_authority),
    )
    forged_bundle = _replace(
        bundle,
        authority_grant=forged_authority,
        run_manifest=manifest,
    )
    signed = sign_engagement_bundle(forged_bundle, outer_signer, signed_at=NOW)

    with pytest.raises(UnknownKeyError, match="trusted key"):
        verify_engagement_bundle(
            signed,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
        )


def test_engagement_verifier_rejects_tampered_embedded_authority() -> None:
    bundle = sample_models()["EngagementBundle"]
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    tampered_grant = bundle.authority_grant.payload.model_copy(
        update={"issued_to": "identity.attacker"}
    )
    tampered_authority = bundle.authority_grant.model_copy(update={"payload": tampered_grant})
    manifest = _replace(
        bundle.run_manifest, authority_digest=sha256_digest(tampered_authority)
    )
    tampered_bundle = _replace(
        bundle, authority_grant=tampered_authority, run_manifest=manifest
    )
    signed = sign_engagement_bundle(tampered_bundle, outer_signer, signed_at=NOW)

    with pytest.raises(SignatureTamperError, match="payload digest"):
        verify_engagement_bundle(
            signed,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW,
        )


def test_engagement_verifier_enforces_embedded_grant_activation_time() -> None:
    bundle = sample_models()["EngagementBundle"]
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    future_grant = _replace(
        bundle.authority_grant.payload,
        not_before=NOW + timedelta(minutes=5),
    )
    future_authority = sign_authority_grant(future_grant, authority_signer, signed_at=NOW)
    manifest = _replace(
        bundle.run_manifest,
        authority_digest=sha256_digest(future_authority),
        started_at=future_grant.not_before,
    )
    future_bundle = _replace(
        bundle, authority_grant=future_authority, run_manifest=manifest
    )
    signed = sign_engagement_bundle(future_bundle, outer_signer, signed_at=NOW)

    with pytest.raises(SignatureNotYetValidError, match="not active"):
        verify_engagement_bundle(
            signed,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW + timedelta(minutes=1),
        )


def test_engagement_rejects_authority_signed_after_run_start() -> None:
    bundle = sample_models()["EngagementBundle"]
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    late_authority = sign_authority_grant(
        bundle.authority_grant.payload,
        authority_signer,
        signed_at=NOW + timedelta(hours=1),
    )
    document = bundle.model_dump(mode="python")
    document["authority_grant"] = late_authority
    document["run_manifest"] = _replace(
        bundle.run_manifest,
        authority_digest=sha256_digest(late_authority),
    )
    with pytest.raises(ValidationError, match="authority grant was signed after"):
        type(bundle).model_validate(document)


def test_engagement_signer_rejects_retroactive_bundle_authorization() -> None:
    bundle = sample_models()["EngagementBundle"]
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    with pytest.raises(ValueError, match="after the run starts"):
        sign_engagement_bundle(
            bundle,
            outer_signer,
            signed_at=NOW + timedelta(hours=1),
        )


def test_engagement_verifier_rejects_valid_retroactive_bundle_signature() -> None:
    bundle = sample_models()["EngagementBundle"]
    outer_signer = AuthoritySigner.from_private_bytes(bytes(reversed(range(32))))
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    signed = sign_engagement_bundle(bundle, outer_signer, signed_at=NOW)
    late_block = signed.signature.model_copy(
        update={"signed_at": NOW + timedelta(hours=1)}
    )
    late_block = late_block.model_copy(
        update={"signature": outer_signer.sign(signing_bytes(bundle, late_block))}
    )
    retroactive = signed.model_copy(update={"signature": late_block})

    with pytest.raises(SignatureTamperError, match="signed after the run started"):
        verify_engagement_bundle(
            retroactive,
            outer_signer.public_key_record,
            authority_public_key=authority_signer.public_key_record,
            now=NOW + timedelta(hours=1),
        )


def test_engagement_rejects_run_started_outside_grant_validity() -> None:
    bundle = sample_models()["EngagementBundle"]
    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    grant = _replace(
        bundle.authority_grant.payload,
        not_before=NOW + timedelta(minutes=1),
    )
    signed_grant = sign_authority_grant(grant, authority_signer, signed_at=NOW)
    document = bundle.model_dump(mode="python")
    document["run_manifest"] = _replace(
        bundle.run_manifest,
        authority_digest=sha256_digest(signed_grant),
        started_at=NOW,
    )
    document["authority_grant"] = signed_grant
    with pytest.raises(ValidationError, match="outside authority validity"):
        type(bundle).model_validate(document)


@pytest.mark.parametrize(
    "started_at",
    [NOW - timedelta(seconds=1), NOW + timedelta(hours=2)],
)
def test_engagement_rejects_run_started_outside_bundle_validity(started_at: object) -> None:
    bundle = sample_models()["EngagementBundle"]
    document = bundle.model_dump(mode="python")
    document["run_manifest"] = _replace(bundle.run_manifest, started_at=started_at)
    with pytest.raises(ValidationError, match="outside engagement bundle validity"):
        type(bundle).model_validate(document)


@pytest.mark.parametrize(
    ("dimension", "expected_message"),
    [
        ("target", "target is absent"),
        ("pack", "unauthorized or absent pack"),
        ("identity", "unauthorized identity"),
        ("tenant", "unauthorized tenant"),
        ("role", "unauthorized role"),
        ("adapter", "unauthorized or absent adapter"),
    ],
)
def test_engagement_rejects_unauthorized_run_material(
    dimension: str, expected_message: str
) -> None:
    bundle = sample_models()["EngagementBundle"]
    document = bundle.model_dump(mode="python")
    if dimension == "target":
        document["run_manifest"] = _replace(
            bundle.run_manifest, target_id="target.unauthorized"
        )
    elif dimension == "pack":
        document["run_manifest"] = _replace(
            bundle.run_manifest, pack_ids=("pack.unauthorized",)
        )
    elif dimension == "adapter":
        document["run_manifest"] = _replace(
            bundle.run_manifest, adapter_ids=("adapter.unauthorized",)
        )
    elif dimension == "tenant":
        unauthorized = bundle.identity_profiles[0].model_copy(
            update={"tenant_ids": ("tenant.unauthorized",)}
        )
        document["identity_profiles"] = (unauthorized,)
    elif dimension == "role":
        unauthorized = bundle.identity_profiles[0].model_copy(
            update={"role_ids": ("role.unauthorized",)}
        )
        document["identity_profiles"] = (unauthorized,)
    else:
        unauthorized = bundle.identity_profiles[0].model_copy(
            update={"identity_id": "identity.unauthorized"}
        )
        document["identity_profiles"] = (unauthorized,)
    with pytest.raises(ValidationError, match=expected_message):
        type(bundle).model_validate(document)


@pytest.mark.parametrize(
    "collection",
    [
        "finding_candidates",
        "claim_packets",
        "verification_verdicts",
        "chain_verdicts",
        "evidence_refs",
    ],
)
def test_result_rejects_top_level_record_from_another_run(collection: str) -> None:
    bundle = sample_models()["RunResultBundle"]
    document = bundle.model_dump(mode="python")
    original = getattr(bundle, collection)[0]
    document[collection] = (original.model_copy(update={"run_id": "run.other"}),)
    with pytest.raises(ValidationError, match="record from a different run"):
        type(bundle).model_validate(document)


def test_result_rejects_nested_evidence_from_another_run() -> None:
    bundle = sample_models()["RunResultBundle"]
    candidate = bundle.finding_candidates[0]
    foreign_evidence = candidate.evidence_refs[0].model_copy(update={"run_id": "run.other"})
    foreign_candidate = candidate.model_copy(update={"evidence_refs": (foreign_evidence,)})
    document = bundle.model_dump(mode="python")
    document["finding_candidates"] = (foreign_candidate,)
    with pytest.raises(ValidationError, match="nested evidence from a different run"):
        type(bundle).model_validate(document)


def test_result_rejects_verdict_for_wrong_claim_digest() -> None:
    bundle = sample_models()["RunResultBundle"]
    verdict = bundle.verification_verdicts[0].model_copy(
        update={"claim_packet_digest": D1}
    )
    document = bundle.model_dump(mode="python")
    document["verification_verdicts"] = (verdict,)
    with pytest.raises(ValidationError, match="claim digest"):
        type(bundle).model_validate(document)


@pytest.mark.parametrize(
    ("binding", "wrong_value", "expected_message"),
    [
        ("run_id", "run.other", "different run"),
        ("run_manifest_digest", D1, "manifest digest"),
        ("authority_digest", D1, "authority digest"),
    ],
)
def test_result_verifier_checks_external_expected_bindings(
    binding: str, wrong_value: str, expected_message: str
) -> None:
    bundle = sample_models()["RunResultBundle"]
    signer = AuthoritySigner.from_private_bytes(bytes([7]) * 32)
    signed = sign_run_result_bundle(bundle, signer, signed_at=NOW)
    expected = {
        "expected_run_id": bundle.run_id,
        "expected_run_manifest_digest": bundle.run_manifest_digest,
        "expected_authority_digest": bundle.authority_digest,
    }
    expected[f"expected_{binding}"] = wrong_value
    with pytest.raises(SignatureTamperError, match=expected_message):
        verify_run_result_bundle(
            signed,
            signer.public_key_record,
            now=NOW,
            **expected,
        )
