use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Map, Number, Value};

use crate::Digest;
use crate::canonical_json::{canonical_json_bytes, parse_canonical_json};
use crate::protocol_time::ProtocolTime;
use crate::signed_protocol::{SignaturePurpose, SignedProtocolError};

const SCHEMA_VERSION: &str = "0.1.0";
const ALGORITHM: &str = "Ed25519";
const MAX_SIGNED_ENVELOPE_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    payload: Value,
    schema_version: String,
    signature: RawSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    algorithm: String,
    expires_at: String,
    key_id: String,
    payload_digest: String,
    protocol_version: String,
    purpose: String,
    schema_version: String,
    sequence: i64,
    signature: String,
    signed_at: String,
}

pub(super) struct ParsedEnvelope {
    pub(super) payload: Value,
    pub(super) payload_bytes: Vec<u8>,
    pub(super) purpose: SignaturePurpose,
    pub(super) key_id: String,
    pub(super) sequence: u64,
    signed_at_text: String,
    pub(super) signed_at: ProtocolTime,
    expires_at_text: String,
    pub(super) expires_at: ProtocolTime,
    payload_digest_text: String,
    pub(super) payload_digest: Digest,
    pub(super) signature: [u8; 64],
}

impl ParsedEnvelope {
    pub(super) fn signing_bytes(&self) -> Result<Vec<u8>, SignedProtocolError> {
        let mut fields = Map::new();
        fields.insert("algorithm".to_owned(), Value::String(ALGORITHM.to_owned()));
        fields.insert(
            "expires_at".to_owned(),
            Value::String(self.expires_at_text.clone()),
        );
        fields.insert("key_id".to_owned(), Value::String(self.key_id.clone()));
        fields.insert("payload".to_owned(), self.payload.clone());
        fields.insert(
            "payload_digest".to_owned(),
            Value::String(self.payload_digest_text.clone()),
        );
        fields.insert(
            "protocol_version".to_owned(),
            Value::String(SCHEMA_VERSION.to_owned()),
        );
        fields.insert(
            "purpose".to_owned(),
            Value::String(self.purpose.as_str().to_owned()),
        );
        fields.insert(
            "sequence".to_owned(),
            Value::Number(Number::from(self.sequence)),
        );
        fields.insert(
            "signed_at".to_owned(),
            Value::String(self.signed_at_text.clone()),
        );
        canonical_json_bytes(&Value::Object(fields), MAX_SIGNED_ENVELOPE_BYTES).map_err(Into::into)
    }
}

pub(super) fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope, SignedProtocolError> {
    let value = parse_canonical_json(bytes, MAX_SIGNED_ENVELOPE_BYTES)?;
    let raw: RawEnvelope =
        serde_json::from_value(value).map_err(|_| SignedProtocolError::EnvelopeShape)?;
    if raw.schema_version != SCHEMA_VERSION || raw.signature.schema_version != SCHEMA_VERSION {
        return Err(SignedProtocolError::UnsupportedSchemaVersion);
    }
    if raw.signature.protocol_version != SCHEMA_VERSION {
        return Err(SignedProtocolError::UnsupportedProtocolVersion);
    }
    if raw.signature.algorithm != ALGORITHM {
        return Err(SignedProtocolError::UnsupportedAlgorithm);
    }
    if !raw.payload.is_object() {
        return Err(SignedProtocolError::EnvelopeShape);
    }
    if !valid_prefixed_hex(&raw.signature.key_id, "ed25519:sha256:") {
        return Err(SignedProtocolError::InvalidKeyId);
    }
    if !valid_prefixed_hex(&raw.signature.payload_digest, "sha256:") {
        return Err(SignedProtocolError::InvalidPayloadDigest);
    }
    let sequence = u64::try_from(raw.signature.sequence)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(SignedProtocolError::InvalidSequence)?;
    let signed_at = ProtocolTime::parse_canonical(&raw.signature.signed_at)
        .map_err(|_| SignedProtocolError::InvalidTimestamp)?;
    let expires_at = ProtocolTime::parse_canonical(&raw.signature.expires_at)
        .map_err(|_| SignedProtocolError::InvalidTimestamp)?;
    if expires_at <= signed_at {
        return Err(SignedProtocolError::InvalidTimeOrder);
    }
    let signature = decode_base64url::<64, 86>(&raw.signature.signature)?;
    let payload_bytes = canonical_json_bytes(&raw.payload, MAX_SIGNED_ENVELOPE_BYTES)?;
    let payload_digest = Digest::of(&payload_bytes);
    if raw.signature.payload_digest != format!("sha256:{}", payload_digest.to_hex()) {
        return Err(SignedProtocolError::PayloadDigestMismatch);
    }
    Ok(ParsedEnvelope {
        payload: raw.payload,
        payload_bytes,
        purpose: SignaturePurpose::parse(&raw.signature.purpose)?,
        key_id: raw.signature.key_id,
        sequence,
        signed_at_text: raw.signature.signed_at,
        signed_at,
        expires_at_text: raw.signature.expires_at,
        expires_at,
        payload_digest_text: raw.signature.payload_digest,
        payload_digest,
        signature,
    })
}

pub(super) fn decode_base64url<const RAW: usize, const ENCODED: usize>(
    value: &str,
) -> Result<[u8; RAW], SignedProtocolError> {
    if value.len() != ENCODED {
        return Err(SignedProtocolError::InvalidBase64Url);
    }
    let mut raw = [0_u8; RAW];
    let decoded = URL_SAFE_NO_PAD
        .decode_slice(value.as_bytes(), &mut raw)
        .map_err(|_| SignedProtocolError::InvalidBase64Url)?;
    if decoded != RAW {
        return Err(SignedProtocolError::InvalidBase64Url);
    }
    let mut canonical = [0_u8; ENCODED];
    let encoded = URL_SAFE_NO_PAD
        .encode_slice(raw, &mut canonical)
        .map_err(|_| SignedProtocolError::InvalidBase64Url)?;
    if encoded != ENCODED || canonical.as_slice() != value.as_bytes() {
        return Err(SignedProtocolError::InvalidBase64Url);
    }
    Ok(raw)
}

pub(super) fn valid_prefixed_hex(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
