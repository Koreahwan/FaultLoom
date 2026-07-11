from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from faultloom_protocol import (
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    GatewayEpochReceiptIssuer,
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
SIGNED_ENVELOPE_FIXTURE = FIXTURE.with_name("scope_epoch_signed_envelope_v0_1.json")
GATEWAY_RECEIPT_FIXTURE = FIXTURE.with_name("scope_epoch_gateway_receipt_v0_1.hex")
GOLDEN_VERIFICATION_TIME = datetime(
    2030, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc
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
    assert canonical_json_bytes(envelope) == SIGNED_ENVELOPE_FIXTURE.read_bytes().rstrip(b"\n")
    assert signing_bytes(payload, envelope.signature).hex() == fixture["signing_bytes_utf8_hex"]
    assert sha256_digest(
        json.loads(signing_bytes(payload, envelope.signature))
    ) == fixture["signing_digest"]
    assert verify_scope_epoch(
        SignedScopeEpoch(
            schema_version="0.1.0", payload=payload, signature=expected_block
        ),
        expected_public,
        now=GOLDEN_VERIFICATION_TIME,
        minimum_epoch=7,
        expected_grant_id="grant.golden",
    ) == payload


def test_gateway_receipt_matches_the_rust_channel_golden() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    envelope = SignedScopeEpoch.model_validate_json(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "payload": fixture["payload"],
                "signature": fixture["signature_block"],
            }
        )
    )
    public_key = Ed25519PublicKeyRecord.model_validate_json(
        json.dumps(fixture["public_key_record"])
    )
    issuer = GatewayEpochReceiptIssuer(
        channel_key_id="gateway-channel:test",
        channel_key=bytes(range(32)),
        gateway_boot_id="gateway-boot:test-1",
        gateway_challenge=bytes(range(0x80, 0xA0)),
    )
    verified_at = GOLDEN_VERIFICATION_TIME.replace(microsecond=679_000)
    receipt = issuer.issue_scope_epoch_receipt(
        envelope,
        public_key,
        minimum_epoch=7,
        expected_grant_id="grant.golden",
        verified_at=verified_at,
        receipt_expires_at=verified_at + timedelta(seconds=4),
        nonce=bytes(range(0xA0, 0xB0)),
    )

    assert receipt.hex() == GATEWAY_RECEIPT_FIXTURE.read_text(encoding="ascii").strip()
    assert "channel_key=<redacted>" in repr(issuer)
    assert bytes(range(32)).hex() not in repr(issuer)
    assert not hasattr(issuer, "model_dump")
