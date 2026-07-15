use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::Digest;
use crate::canonical_json::CanonicalJsonError;
use crate::protocol_time::ProtocolTime;
use crate::signed_protocol_parse::{decode_base64url, parse_envelope, valid_prefixed_hex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedKeyStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignaturePurpose {
    AuthorityGrant,
    ScopeEpoch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignedProtocolError {
    CanonicalJson(CanonicalJsonError),
    EnvelopeShape,
    UnsupportedSchemaVersion,
    UnsupportedProtocolVersion,
    UnsupportedAlgorithm,
    UnsupportedPurpose,
    PurposeMismatch,
    InvalidKeyId,
    InvalidPublicKey,
    KeyIdMismatch,
    RevokedKey,
    InvalidBase64Url,
    InvalidPayloadDigest,
    PayloadDigestMismatch,
    InvalidSequence,
    Rollback,
    InvalidTimestamp,
    InvalidTimeOrder,
    InvalidControls,
    NotYetValid,
    Expired,
    SignatureInvalid,
}

pub(crate) struct TrustedEd25519Key {
    key_id: String,
    verifying_key: VerifyingKey,
    status: TrustedKeyStatus,
}

impl TrustedEd25519Key {
    pub(crate) fn from_base64(
        key_id: String,
        public_key_base64url: &str,
        status: TrustedKeyStatus,
    ) -> Result<Self, SignedProtocolError> {
        if !valid_prefixed_hex(&key_id, "ed25519:sha256:") {
            return Err(SignedProtocolError::InvalidKeyId);
        }
        let raw = decode_base64url::<32, 43>(public_key_base64url)?;
        if key_id != format!("ed25519:sha256:{}", Digest::of(&raw).to_hex()) {
            return Err(SignedProtocolError::KeyIdMismatch);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&raw).map_err(|_| SignedProtocolError::InvalidPublicKey)?;
        Ok(Self {
            key_id,
            verifying_key,
            status,
        })
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) const fn status(&self) -> TrustedKeyStatus {
        self.status
    }

    pub(crate) fn verify_strict(
        &self,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), SignedProtocolError> {
        match self.status {
            TrustedKeyStatus::Active => {}
            TrustedKeyStatus::Revoked => return Err(SignedProtocolError::RevokedKey),
        }
        self.verifying_key
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| SignedProtocolError::SignatureInvalid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SignatureControls {
    expected_purpose: SignaturePurpose,
    now: ProtocolTime,
    latest_signed_at: ProtocolTime,
    minimum_sequence: u64,
}

impl SignatureControls {
    pub(crate) fn new(
        expected_purpose: SignaturePurpose,
        now: ProtocolTime,
        maximum_clock_skew_micros: u64,
        minimum_sequence: u64,
    ) -> Result<Self, SignedProtocolError> {
        if minimum_sequence == 0 || minimum_sequence > i64::MAX.unsigned_abs() {
            return Err(SignedProtocolError::InvalidControls);
        }
        let latest_signed_at = now
            .checked_add_micros(maximum_clock_skew_micros)
            .ok_or(SignedProtocolError::InvalidControls)?;
        Ok(Self {
            expected_purpose,
            now,
            latest_signed_at,
            minimum_sequence,
        })
    }
}

pub(crate) struct VerifiedSignedEnvelope {
    payload_bytes: Vec<u8>,
    key_id: String,
    sequence: u64,
    signed_at: ProtocolTime,
    expires_at: ProtocolTime,
    payload_digest: Digest,
    envelope_digest: Digest,
}

impl VerifiedSignedEnvelope {
    pub(crate) fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) const fn signed_at(&self) -> ProtocolTime {
        self.signed_at
    }
    pub(crate) const fn expires_at(&self) -> ProtocolTime {
        self.expires_at
    }
    pub(crate) const fn payload_digest(&self) -> Digest {
        self.payload_digest
    }
    pub(crate) const fn envelope_digest(&self) -> Digest {
        self.envelope_digest
    }
}

/// Returns untrusted metadata for pinned-key candidate selection, never authorization.
pub(crate) fn untrusted_signing_key_id(bytes: &[u8]) -> Result<String, SignedProtocolError> {
    Ok(parse_envelope(bytes)?.key_id)
}

pub(crate) fn verify_signed_envelope(
    bytes: &[u8],
    trusted_key: &TrustedEd25519Key,
    controls: &SignatureControls,
) -> Result<VerifiedSignedEnvelope, SignedProtocolError> {
    let parsed = parse_envelope(bytes)?;
    if parsed.purpose != controls.expected_purpose {
        return Err(SignedProtocolError::PurposeMismatch);
    }
    if parsed.sequence < controls.minimum_sequence {
        return Err(SignedProtocolError::Rollback);
    }
    if parsed.key_id != trusted_key.key_id() {
        return Err(SignedProtocolError::KeyIdMismatch);
    }
    if parsed.signed_at > controls.latest_signed_at {
        return Err(SignedProtocolError::NotYetValid);
    }
    if controls.now >= parsed.expires_at {
        return Err(SignedProtocolError::Expired);
    }
    let signing_bytes = parsed.signing_bytes()?;
    trusted_key.verify_strict(&signing_bytes, &parsed.signature)?;
    Ok(VerifiedSignedEnvelope {
        payload_bytes: parsed.payload_bytes,
        key_id: parsed.key_id,
        sequence: parsed.sequence,
        signed_at: parsed.signed_at,
        expires_at: parsed.expires_at,
        payload_digest: parsed.payload_digest,
        envelope_digest: Digest::of(bytes),
    })
}

impl SignaturePurpose {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityGrant => "authority_grant",
            Self::ScopeEpoch => "scope_epoch",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, SignedProtocolError> {
        match value {
            "authority_grant" => Ok(Self::AuthorityGrant),
            "scope_epoch" => Ok(Self::ScopeEpoch),
            _ => Err(SignedProtocolError::UnsupportedPurpose),
        }
    }
}

impl From<CanonicalJsonError> for SignedProtocolError {
    fn from(value: CanonicalJsonError) -> Self {
        Self::CanonicalJson(value)
    }
}

impl fmt::Display for SignedProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "signed protocol verification failed: {self:?}")
    }
}

impl std::error::Error for SignedProtocolError {}
