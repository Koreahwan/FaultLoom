from __future__ import annotations

from datetime import date, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    ScopeEpoch,
    SignatureBlock,
    SignatureNotYetValidError,
    SignedAuthorityGrant,
    SignedEngagementBundle,
    SignedRunResultBundle,
    SignedScopeEpoch,
    canonical_json_bytes,
    load_public_key,
    schema_catalog,
    sha256_digest,
    sign_authority_grant,
    signing_bytes,
    verify_authority_grant,
)
from faultloom_protocol.signing import SignaturePurpose

from .factories import NOW, sample_models


def test_schema_version_is_required_on_payload_and_signed_wire_schemas() -> None:
    catalog = schema_catalog()
    wire_names = {
        "SignatureBlock",
        "Ed25519PublicKeyRecord",
        "SignedAuthorityGrant",
        "SignedScopeEpoch",
        "SignedEngagementBundle",
        "SignedRunResultBundle",
    }
    assert wire_names.issubset(catalog)
    for name, schema in catalog.items():
        assert "schema_version" in schema.get("required", []), name


def test_protocol_model_rejects_integer_outside_canonical_int64() -> None:
    with pytest.raises(ValidationError):
        ScopeEpoch(
            schema_version=SCHEMA_VERSION,
            grant_id="grant.1",
            epoch=2**63,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )


def test_every_catalog_integer_schema_is_bounded_to_canonical_int64() -> None:
    def walk(value: object) -> list[dict[str, object]]:
        if isinstance(value, dict):
            found = [value] if value.get("type") == "integer" else []
            return found + [item for child in value.values() for item in walk(child)]
        if isinstance(value, list):
            return [item for child in value for item in walk(child)]
        return []

    integer_schemas = [
        integer
        for schema in schema_catalog().values()
        for integer in walk(schema)
    ]
    assert integer_schemas
    assert all(
        integer.get("maximum") is not None or isinstance(integer.get("const"), int)
        for integer in integer_schemas
    )
    assert all(
        int(integer["maximum"] if "maximum" in integer else integer["const"])
        <= 2**63 - 1
        for integer in integer_schemas
    )


@pytest.mark.parametrize("value", [date(2030, 1, 1), UUID(int=0)])
def test_canonical_profile_rejects_undocumented_scalar_types(value: object) -> None:
    with pytest.raises(TypeError, match="unsupported canonical JSON value"):
        canonical_json_bytes({"value": value})


@pytest.mark.parametrize(
    "field",
    [
        "token",
        "session_cookie",
        "request_body",
        "set-cookie",
        "proxy-authorization",
        "id_token",
        "auth_token",
        "x-api-key",
        "aws_secret_access_key",
        "secret",
        "xAPIKey",
        "XAPIKey",
        "AWSSecretAccessKey",
    ],
)
def test_raw_secret_guard_rejects_sensitive_key_vocabulary(field: str) -> None:
    with pytest.raises(ValueError, match="raw secret field"):
        canonical_json_bytes({field: "sensitive"})


def test_raw_secret_guard_allows_typed_references_and_digests() -> None:
    canonical_json_bytes(
        {
            "credential_ref": "secret://engagement/credential",
            "callback_token_ref": "secret://engagement/callback",
            "secret_refs": ["secret://engagement/credential"],
            "request_digest": "sha256:" + "00" * 32,
            "model_tokens": 1024,
        }
    )


def test_raw_secret_guard_detects_key_value_header_shape() -> None:
    with pytest.raises(ValueError, match="raw secret field"):
        canonical_json_bytes({"headers": [{"key": "Set-Cookie", "value": "sensitive"}]})


def test_public_key_base64url_must_be_canonical() -> None:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    record = signer.public_key_record
    replacement = "h" if record.public_key[-1] == "g" else "B"
    noncanonical = record.model_copy(
        update={"public_key": record.public_key[:-1] + replacement}
    )
    assert noncanonical.public_key != record.public_key
    with pytest.raises(ValueError, match="canonical"):
        load_public_key(noncanonical)


@pytest.mark.parametrize("suffix", [" ", "\n", "\t"])
def test_base64url_wire_values_reject_surrounding_whitespace(suffix: str) -> None:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    document = signer.public_key_record.model_dump(mode="python")
    document["public_key"] += suffix
    with pytest.raises(ValidationError, match="surrounding whitespace"):
        Ed25519PublicKeyRecord.model_validate(document)


def test_verifier_rejects_cryptographically_valid_backdated_authority() -> None:
    grant = sample_models()["AuthorityGrant"]
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    block = SignatureBlock(
        schema_version=SCHEMA_VERSION,
        purpose=SignaturePurpose.AUTHORITY_GRANT,
        key_id=signer.key_id,
        sequence=grant.grant_version,
        signed_at=grant.issued_at - timedelta(seconds=1),
        expires_at=grant.expires_at,
        payload_digest=sha256_digest(grant),
        signature="AA",
    )
    block = block.model_copy(update={"signature": signer.sign(signing_bytes(grant, block))})
    envelope = SignedAuthorityGrant(
        schema_version=SCHEMA_VERSION,
        payload=grant,
        signature=block,
    )
    with pytest.raises(SignatureNotYetValidError, match="before payload issuance"):
        verify_authority_grant(envelope, signer.public_key_record, now=NOW)


@pytest.mark.parametrize("minimum_version", [True, 1.0, 2**63])
def test_verifier_rejects_noncanonical_minimum_sequence(
    minimum_version: object,
) -> None:
    grant = sample_models()["AuthorityGrant"]
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    envelope = sign_authority_grant(grant, signer, signed_at=NOW)
    with pytest.raises(ValueError, match="within signed int64"):
        verify_authority_grant(
            envelope,
            signer.public_key_record,
            now=NOW,
            minimum_version=minimum_version,  # type: ignore[arg-type]
        )


def test_signed_wire_classes_are_actual_protocol_models() -> None:
    for model in (
        SignatureBlock,
        Ed25519PublicKeyRecord,
        SignedAuthorityGrant,
        SignedScopeEpoch,
        SignedEngagementBundle,
        SignedRunResultBundle,
    ):
        assert model.model_fields["schema_version"].is_required()
