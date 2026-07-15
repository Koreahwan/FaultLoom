use crate::Digest;

const MAX_SIGNED_EPOCH_BYTES: usize = 16_384;
const MAX_EPOCH_RECEIPT_BYTES: usize = MAX_SIGNED_EPOCH_BYTES * 2 + 4_096;

pub(crate) mod epoch_verifier_private {
    pub trait Sealed {}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEpochEnvelope {
    canonical_bytes: Vec<u8>,
    verifier_receipt: Option<Vec<u8>>,
}

impl SignedEpochEnvelope {
    pub fn new(canonical_bytes: Vec<u8>) -> Result<Self, EpochAdmissionError> {
        if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_SIGNED_EPOCH_BYTES {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        Ok(Self {
            canonical_bytes,
            verifier_receipt: None,
        })
    }

    pub fn with_verifier_receipt(
        canonical_bytes: Vec<u8>,
        verifier_receipt: Vec<u8>,
    ) -> Result<Self, EpochAdmissionError> {
        let mut envelope = Self::new(canonical_bytes)?;
        if verifier_receipt.is_empty() || verifier_receipt.len() > MAX_EPOCH_RECEIPT_BYTES {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        envelope.verifier_receipt = Some(verifier_receipt);
        Ok(envelope)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn digest(&self) -> Digest {
        Digest::of(&self.canonical_bytes)
    }

    pub fn verifier_receipt_bytes(&self) -> Option<&[u8]> {
        self.verifier_receipt.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedScopeEpoch {
    pub(super) grant_id: String,
    pub(super) epoch: u64,
    pub(super) issued_at_millis: u64,
    pub(super) expires_at_millis: u64,
    pub(super) revoked: bool,
    pub(super) revocation_reason: Option<String>,
    pub(super) key_id: String,
    pub(super) signature_sequence: u64,
    pub(super) envelope_digest: Digest,
    pub(super) payload_digest: Digest,
    pub(super) verifier_receipt_digest: Digest,
    pub(super) gateway_boot_id: String,
    pub(super) verification_nonce: [u8; 16],
}

impl VerifiedScopeEpoch {
    pub(crate) fn from_trusted_verifier(parts: VerifiedScopeEpochParts) -> Self {
        Self {
            grant_id: parts.grant_id,
            epoch: parts.epoch,
            issued_at_millis: parts.issued_at_millis,
            expires_at_millis: parts.expires_at_millis,
            revoked: parts.revoked,
            revocation_reason: parts.revocation_reason,
            key_id: parts.key_id,
            signature_sequence: parts.signature_sequence,
            envelope_digest: parts.envelope_digest,
            payload_digest: parts.payload_digest,
            verifier_receipt_digest: parts.verifier_receipt_digest,
            gateway_boot_id: parts.gateway_boot_id,
            verification_nonce: parts.verification_nonce,
        }
    }

    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

pub(crate) struct VerifiedScopeEpochParts {
    pub(crate) grant_id: String,
    pub(crate) epoch: u64,
    pub(crate) issued_at_millis: u64,
    pub(crate) expires_at_millis: u64,
    pub(crate) revoked: bool,
    pub(crate) revocation_reason: Option<String>,
    pub(crate) key_id: String,
    pub(crate) signature_sequence: u64,
    pub(crate) envelope_digest: Digest,
    pub(crate) payload_digest: Digest,
    pub(crate) verifier_receipt_digest: Digest,
    pub(crate) gateway_boot_id: String,
    pub(crate) verification_nonce: [u8; 16],
}

pub trait EpochVerifier: epoch_verifier_private::Sealed {
    fn verify(
        &self,
        envelope: &SignedEpochEnvelope,
        now_millis: u64,
    ) -> Result<VerifiedScopeEpoch, EpochAdmissionError>;
}

pub struct UnavailableEpochVerifier;

impl epoch_verifier_private::Sealed for UnavailableEpochVerifier {}

impl EpochVerifier for UnavailableEpochVerifier {
    fn verify(
        &self,
        _envelope: &SignedEpochEnvelope,
        _now_millis: u64,
    ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
        Err(EpochAdmissionError::VerifierUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochAdmissionError {
    InvalidEnvelope,
    VerifierUnavailable,
    VerificationFailed,
    UnknownKey,
    TrustAnchorRevoked,
    GrantMismatch,
    NotYetValid,
    Expired,
    InvalidValidity,
    InvalidVerificationReceipt,
    Rollback,
    Replay,
    StateUnavailable,
}

pub(super) fn verified_epoch_binding(epoch: &VerifiedScopeEpoch) -> Digest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(b"faultloom-verified-scope-epoch-v1\0");
    bytes.extend_from_slice(epoch.envelope_digest.as_bytes());
    bytes.extend_from_slice(epoch.payload_digest.as_bytes());
    bytes.extend_from_slice(epoch.verifier_receipt_digest.as_bytes());
    bytes.extend_from_slice(&(epoch.grant_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(epoch.grant_id.as_bytes());
    bytes.extend_from_slice(&epoch.epoch.to_be_bytes());
    bytes.extend_from_slice(&epoch.issued_at_millis.to_be_bytes());
    bytes.extend_from_slice(&epoch.expires_at_millis.to_be_bytes());
    bytes.push(u8::from(epoch.revoked));
    bytes.extend_from_slice(&(epoch.key_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(epoch.key_id.as_bytes());
    Digest::of(&bytes)
}
