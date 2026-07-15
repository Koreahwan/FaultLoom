use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use super::trust::{
    CHANNEL_KEY, CHANNEL_KEY_ID, GATEWAY_BOOT_ID, GATEWAY_CHALLENGE, NOW_MILLIS, key_id,
};
use crate::Digest;
use crate::scope::SignedEpochEnvelope;

#[derive(Clone)]
pub(super) struct EpochSpec {
    pub(super) epoch: u64,
    pub(super) sequence: u64,
    pub(super) grant_id: String,
    pub(super) issued_at: String,
    pub(super) signed_at: String,
    pub(super) expires_at: String,
    pub(super) purpose: String,
    pub(super) revoked: bool,
    pub(super) revocation_reason: Option<String>,
    pub(super) key_id_override: Option<String>,
    pub(super) signature_override: Option<String>,
}

impl EpochSpec {
    pub(super) fn valid(epoch: u64) -> Self {
        Self {
            epoch,
            sequence: epoch,
            grant_id: "grant.test".to_owned(),
            issued_at: "2030-01-02T03:04:05.678000Z".to_owned(),
            signed_at: "2030-01-02T03:04:05.678901Z".to_owned(),
            expires_at: "2030-01-02T04:04:05.678901Z".to_owned(),
            purpose: "scope_epoch".to_owned(),
            revoked: false,
            revocation_reason: None,
            key_id_override: None,
            signature_override: None,
        }
    }
}

pub(super) struct SignedArtifact {
    pub(super) bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    key_id: String,
    spec: EpochSpec,
}

#[derive(Clone, Copy)]
pub(super) enum ReceiptCase {
    Valid,
    CorruptMac,
    PreviousBoot,
    Stale,
    Future,
    LongTtl,
}

pub(super) fn sign(spec: &EpochSpec, signer: &SigningKey) -> SignedArtifact {
    let payload = json!({
        "epoch": spec.epoch,
        "expires_at": spec.expires_at,
        "grant_id": spec.grant_id,
        "issued_at": spec.issued_at,
        "revocation_reason": spec.revocation_reason,
        "revoked": spec.revoked,
        "schema_version": "0.1.0"
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("canonical test payload");
    let payload_digest = format!("sha256:{}", Digest::of(&payload_bytes).to_hex());
    let signing_key_id = spec
        .key_id_override
        .clone()
        .unwrap_or_else(|| key_id(signer));
    let signing_document = json!({
        "algorithm": "Ed25519",
        "expires_at": spec.expires_at,
        "key_id": signing_key_id,
        "payload": payload,
        "payload_digest": payload_digest,
        "protocol_version": "0.1.0",
        "purpose": spec.purpose,
        "sequence": spec.sequence,
        "signed_at": spec.signed_at
    });
    let signing_bytes =
        serde_json::to_vec(&signing_document).expect("canonical test signing bytes");
    let signature = spec
        .signature_override
        .clone()
        .unwrap_or_else(|| signature_base64url(&signer.sign(&signing_bytes).to_bytes()));
    let bytes = serde_json::to_vec(&json!({
        "payload": payload,
        "schema_version": "0.1.0",
        "signature": {
            "algorithm": "Ed25519",
            "expires_at": spec.expires_at,
            "key_id": signing_key_id,
            "payload_digest": payload_digest,
            "protocol_version": "0.1.0",
            "purpose": spec.purpose,
            "schema_version": "0.1.0",
            "sequence": spec.sequence,
            "signature": signature,
            "signed_at": spec.signed_at
        }
    }))
    .expect("canonical test envelope");
    SignedArtifact {
        bytes,
        payload_bytes,
        key_id: signing_key_id,
        spec: spec.clone(),
    }
}

pub(super) fn wrapped(artifact: &SignedArtifact, receipt_case: ReceiptCase) -> SignedEpochEnvelope {
    let mut receipt = Vec::with_capacity(1_024);
    receipt.extend_from_slice(b"FLER");
    receipt.push(1);
    push_string(&mut receipt, CHANNEL_KEY_ID);
    let boot_id = match receipt_case {
        ReceiptCase::PreviousBoot => "gateway-boot:test-0",
        ReceiptCase::Valid
        | ReceiptCase::CorruptMac
        | ReceiptCase::Stale
        | ReceiptCase::Future
        | ReceiptCase::LongTtl => GATEWAY_BOOT_ID,
    };
    push_string(&mut receipt, boot_id);
    receipt.extend_from_slice(&GATEWAY_CHALLENGE);
    for value in ["0.1.0", "0.1.0", artifact.spec.purpose.as_str()] {
        push_string(&mut receipt, value);
    }
    receipt.extend_from_slice(
        &u32::try_from(artifact.bytes.len())
            .expect("test envelope size")
            .to_be_bytes(),
    );
    receipt.extend_from_slice(&artifact.bytes);
    receipt.extend_from_slice(Digest::of(&artifact.bytes).as_bytes());
    receipt.extend_from_slice(Digest::of(&artifact.payload_bytes).as_bytes());
    push_string(&mut receipt, &artifact.key_id);
    push_string(&mut receipt, &artifact.spec.grant_id);
    receipt.extend_from_slice(&artifact.spec.epoch.to_be_bytes());
    receipt.extend_from_slice(&artifact.spec.sequence.to_be_bytes());
    push_string(&mut receipt, &artifact.spec.issued_at);
    push_string(&mut receipt, &artifact.spec.expires_at);
    receipt.push(u8::from(artifact.spec.revoked));
    match artifact.spec.revocation_reason.as_deref() {
        Some(reason) => {
            receipt.push(1);
            push_string(&mut receipt, reason);
        }
        None => receipt.push(0),
    }
    let (verified_at, expires_at) = receipt_times(&receipt_case);
    receipt.extend_from_slice(&verified_at.to_be_bytes());
    receipt.extend_from_slice(&expires_at.to_be_bytes());
    let nonce: [u8; 16] = std::array::from_fn(|index| {
        artifact.spec.epoch.to_le_bytes()[0]
            .wrapping_add(u8::try_from(index).expect("receipt nonce index"))
    });
    receipt.extend_from_slice(&nonce);
    let mac = hmac_sha256(&CHANNEL_KEY, &receipt);
    receipt.extend_from_slice(mac.as_bytes());
    if matches!(receipt_case, ReceiptCase::CorruptMac) {
        let last = receipt.last_mut().expect("receipt MAC");
        *last ^= 1;
    }
    SignedEpochEnvelope::with_verifier_receipt(artifact.bytes.clone(), receipt)
        .expect("test signed epoch")
}

pub(super) fn golden() -> SignedEpochEnvelope {
    let envelope = include_bytes!(
        "../../../../packages/protocol/tests/fixtures/scope_epoch_signed_envelope_v0_1.json"
    )
    .strip_suffix(b"\n")
    .expect("golden envelope newline")
    .to_vec();
    let encoded = include_str!(
        "../../../../packages/protocol/tests/fixtures/scope_epoch_gateway_receipt_v0_1.hex"
    )
    .trim();
    let receipt = (0..encoded.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).expect("hex receipt"))
        .collect();
    SignedEpochEnvelope::with_verifier_receipt(envelope, receipt).expect("golden signed epoch")
}

fn receipt_times(receipt_case: &ReceiptCase) -> (u64, u64) {
    match receipt_case {
        ReceiptCase::Valid | ReceiptCase::CorruptMac | ReceiptCase::PreviousBoot => {
            (NOW_MILLIS, NOW_MILLIS + 4_000)
        }
        ReceiptCase::Stale => (NOW_MILLIS - 1_000, NOW_MILLIS),
        ReceiptCase::Future => (NOW_MILLIS + 1_001, NOW_MILLIS + 1_002),
        ReceiptCase::LongTtl => (NOW_MILLIS, NOW_MILLIS + 5_001),
    }
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("test string length")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> Digest {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let inner = [inner_pad.as_slice(), message].concat();
    let inner_digest = Digest::of(&inner);
    let outer = [outer_pad.as_slice(), inner_digest.as_bytes()].concat();
    Digest::of(&outer)
}

fn signature_base64url(raw: &[u8; 64]) -> String {
    let mut encoded = [0_u8; 86];
    let length = URL_SAFE_NO_PAD
        .encode_slice(raw, &mut encoded)
        .expect("signature base64url");
    std::str::from_utf8(&encoded[..length])
        .expect("base64url UTF-8")
        .to_owned()
}
