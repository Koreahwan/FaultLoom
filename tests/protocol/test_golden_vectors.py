from __future__ import annotations

import json
from pathlib import Path

from faultloom_protocol import (
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    ScopeEpoch,
    SignatureBlock,
    SignedScopeEpoch,
    canonical_json_bytes,
    sha256_digest,
    sign_scope_epoch,
    signing_bytes,
    verify_scope_epoch,
)

FIXTURE = (
    Path(__file__).parents[2]
    / "packages"
    / "protocol"
    / "tests"
    / "fixtures"
    / "scope_epoch_ed25519_v0_1.json"
)


def test_scope_epoch_golden_bytes_digest_and_signature() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload = ScopeEpoch.model_validate_json(json.dumps(fixture["payload"]))
    signer = AuthoritySigner.from_private_bytes(bytes.fromhex(fixture["test_private_seed_hex"]))
    expected_public = Ed25519PublicKeyRecord.model_validate_json(
        json.dumps(fixture["public_key_record"])
    )
    expected_block = SignatureBlock.model_validate_json(
        json.dumps(fixture["signature_block"])
    )

    assert signer.public_key_record == expected_public
    assert canonical_json_bytes(payload).hex() == fixture["payload_canonical_utf8_hex"]
    assert sha256_digest(payload) == fixture["payload_digest"]

    envelope = sign_scope_epoch(payload, signer, signed_at=expected_block.signed_at)
    assert envelope.signature == expected_block
    assert signing_bytes(payload, envelope.signature).hex() == fixture["signing_bytes_utf8_hex"]
    assert sha256_digest(
        json.loads(signing_bytes(payload, envelope.signature))
    ) == fixture["signing_digest"]
    assert verify_scope_epoch(
        SignedScopeEpoch(payload=payload, signature=expected_block),
        expected_public,
        now=expected_block.signed_at,
        minimum_epoch=7,
        expected_grant_id="grant.golden",
    ) == payload
