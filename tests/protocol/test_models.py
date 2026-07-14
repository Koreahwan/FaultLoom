from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

import faultloom_protocol.models as m
from faultloom_protocol import SCHEMA_VERSION, schema_catalog, sha256_digest

from .factories import D1, D2, LATER, NOW, sample_models


def test_all_required_models_round_trip_strict_json() -> None:
    samples = sample_models()
    assert set(samples) == {model.__name__ for model in m.REQUIRED_MODEL_TYPES}

    for model_type in m.REQUIRED_MODEL_TYPES:
        original = samples[model_type.__name__]
        restored = model_type.model_validate_json(original.model_dump_json())
        assert restored == original, model_type.__name__
        assert restored.schema_version == SCHEMA_VERSION


def test_all_required_models_publish_closed_json_schemas() -> None:
    catalog = schema_catalog()
    assert {model.__name__ for model in m.REQUIRED_MODEL_TYPES}.issubset(catalog)
    assert {model.__name__ for model in m.WIRE_MODEL_TYPES}.issubset(catalog)

    for name, schema in catalog.items():
        assert schema["type"] == "object", name
        assert schema["additionalProperties"] is False, name
        assert "schema_version" in schema["properties"], name
        assert "schema_version" in schema["required"], name


def test_models_forbid_unknown_fields_and_schema_downgrade() -> None:
    subject = sample_models()["SubjectRef"]
    document = subject.model_dump(mode="json")
    document["unexpected"] = "value"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        m.SubjectRef.model_validate(document)
    document.pop("unexpected")
    document["schema_version"] = "0.0.9"
    with pytest.raises(ValidationError, match="Input should be '0.1.0'"):
        m.SubjectRef.model_validate(document)


def test_every_required_payload_rejects_omitted_schema_version() -> None:
    for sample in sample_models().values():
        document = sample.model_dump(mode="python")
        document.pop("schema_version")
        with pytest.raises(ValidationError, match="Field required"):
            type(sample).model_validate(document)


def test_unsupported_action_classes_cannot_be_enabled() -> None:
    with pytest.raises(ValidationError, match="unsupported v0.1 action classes"):
        m.ActionPolicy(
            schema_version=SCHEMA_VERSION,
            allowed_classes=(m.ActionClass.DESTRUCTIVE,),
            allowed_families=("unsafe",),
        )


def test_state_change_requires_canary_and_cleanup_plan() -> None:
    samples = sample_models()
    safe_intent = samples["ActionIntent"]
    document = safe_intent.model_dump(mode="python")
    document["action_class"] = m.ActionClass.STATE_CHANGE
    with pytest.raises(ValidationError, match="state_change requires"):
        m.ActionIntent.model_validate(document)


def test_unknown_dispatch_outcome_requires_reconciliation() -> None:
    samples = sample_models()
    receipt = samples["DispatchReceipt"]
    document = receipt.model_dump(mode="python")
    document.update(
        outcome=m.DispatchOutcome.UNKNOWN_OUTCOME,
        completed_at=None,
        response_digest=None,
        reconciliation_required=False,
    )
    with pytest.raises(ValidationError, match="unknown_outcome requires reconciliation"):
        m.DispatchReceipt.model_validate(document)


def test_dispatch_receipt_requires_gateway_authentication_tag() -> None:
    receipt = sample_models()["DispatchReceipt"].model_dump(mode="python")
    receipt.pop("receipt_authentication_tag")
    with pytest.raises(ValidationError, match="receipt_authentication_tag"):
        m.DispatchReceipt.model_validate(receipt)


def test_action_lease_and_receipt_bind_nonce_ttl_budget_and_retry_alias() -> None:
    samples = sample_models()
    lease = samples["ActionLease"].model_dump(mode="python")
    lease["dispatch_nonce"] = "00" * 16
    with pytest.raises(ValidationError, match="four distinct bytes"):
        m.ActionLease.model_validate(lease)

    lease = samples["ActionLease"].model_dump(mode="python")
    lease["expires_at"] = lease["issued_at"] + timedelta(seconds=61)
    with pytest.raises(ValidationError, match="sixty seconds"):
        m.ActionLease.model_validate(lease)

    lease = samples["ActionLease"].model_dump(mode="python")
    lease["retry_of_intent_digest"] = lease["intent_digest"]
    with pytest.raises(ValidationError, match="fresh intent digest"):
        m.ActionLease.model_validate(lease)

    receipt = samples["DispatchReceipt"].model_dump(mode="python")
    receipt["reservation"]["action_count"] = 2
    with pytest.raises(ValidationError, match="exactly one action"):
        m.DispatchReceipt.model_validate(receipt)


def test_engagement_bundle_binds_embedded_grant_digest() -> None:
    bundle = sample_models()["EngagementBundle"]
    wrong_manifest = bundle.run_manifest.model_copy(update={"authority_digest": D1})
    document = bundle.model_dump(mode="python")
    document["run_manifest"] = wrong_manifest
    with pytest.raises(ValidationError, match="does not identify the embedded grant"):
        m.EngagementBundle.model_validate(document)


def test_naive_wire_datetime_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        m.ScopeEpoch(
            schema_version=SCHEMA_VERSION,
            grant_id="grant.1",
            epoch=1,
            issued_at=NOW.replace(tzinfo=None),
            expires_at=LATER,
        )


def test_verified_results_require_independent_final_effect_proof() -> None:
    samples = sample_models()
    verdict = samples["VerificationVerdict"].model_dump(mode="python")
    verdict["independent_replay"] = False
    with pytest.raises(ValidationError, match="independent replay"):
        m.VerificationVerdict.model_validate(verdict)

    chain = samples["ChainVerdict"].model_dump(mode="python")
    chain["final_effect_verified"] = False
    with pytest.raises(ValidationError, match="requires the final effect"):
        m.ChainVerdict.model_validate(chain)


def test_scope_epoch_revocation_state_is_unambiguous() -> None:
    with pytest.raises(ValidationError, match="exactly when revoked"):
        m.ScopeEpoch(
            schema_version=SCHEMA_VERSION,
            grant_id="grant.1",
            epoch=2,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            revoked=True,
        )


def test_protocol_models_do_not_expose_raw_secret_fields() -> None:
    forbidden = {
        "password",
        "cookie",
        "authorization",
        "api_key",
        "access_token",
        "refresh_token",
        "private_key",
        "client_secret",
    }
    for model_type in m.REQUIRED_MODEL_TYPES:
        assert forbidden.isdisjoint(model_type.model_fields), model_type.__name__

    engagement_json = sample_models()["EngagementBundle"].model_dump_json()
    assert "secret://" in engagement_json
    assert "owned-password" not in engagement_json
    assert sha256_digest({"safe": D2}).startswith("sha256:")


def test_pack_manifest_must_admit_local_protocol() -> None:
    manifest = sample_models()["PackManifest"].model_dump(mode="python")
    manifest["protocol_range"] = ">=0.2.0,<0.3.0"
    with pytest.raises(ValidationError, match="outside supported range"):
        m.PackManifest.model_validate(manifest)
