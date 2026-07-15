use std::sync::Arc;

use crate::Digest;
use crate::installed_trust::InstalledTrustStore;
use crate::protocol_time::ProtocolTime;
use crate::scope::{
    EpochAdmissionError, EpochVerifier, SignedEpochEnvelope, VerifiedScopeEpoch,
    VerifiedScopeEpochParts, epoch_verifier_private,
};
use crate::signed_protocol::{
    SignatureControls, SignaturePurpose, untrusted_signing_key_id, verify_signed_envelope,
};

#[path = "t13_epoch/channel.rs"]
mod channel;
#[path = "t13_epoch/error.rs"]
mod error;
#[path = "t13_epoch/payload.rs"]
mod payload;
#[path = "t13_epoch/receipt.rs"]
mod receipt;
#[path = "t13_epoch/receipt_crypto.rs"]
mod receipt_crypto;
#[path = "t13_epoch/receipt_cursor.rs"]
mod receipt_cursor;

pub(crate) use channel::{ChannelTrustError, GatewayBootBinding, ReceiptAuthenticationChannel};
use error::{map_grant_pin, map_key_lookup, map_signed_error};
use payload::ScopeEpochPayload;
use receipt::ParsedReceipt;

const MAXIMUM_SIGNATURE_CLOCK_SKEW_MILLIS: u64 = 300_000;

pub(crate) struct ExpectedScopeEpochGrant {
    grant_id: String,
    grant_version: u64,
}

impl ExpectedScopeEpochGrant {
    pub(crate) fn new(grant_id: String, grant_version: u64) -> Result<Self, ChannelTrustError> {
        if !crate::ipc::valid_identifier(&grant_id)
            || grant_version == 0
            || grant_version > i64::MAX.unsigned_abs()
        {
            return Err(ChannelTrustError::InvalidExpectedGrant);
        }
        Ok(Self {
            grant_id,
            grant_version,
        })
    }
}

pub(crate) struct T13EpochVerifierConfig {
    channel: ReceiptAuthenticationChannel,
    installed_trust: Arc<InstalledTrustStore>,
    expected_grant: ExpectedScopeEpochGrant,
}

impl T13EpochVerifierConfig {
    pub(crate) fn new(
        channel: ReceiptAuthenticationChannel,
        installed_trust: Arc<InstalledTrustStore>,
        expected_grant: ExpectedScopeEpochGrant,
    ) -> Self {
        Self {
            channel,
            installed_trust,
            expected_grant,
        }
    }
}

pub struct T13ReceiptEpochVerifier {
    channel: ReceiptAuthenticationChannel,
    installed_trust: Arc<InstalledTrustStore>,
    expected_grant: ExpectedScopeEpochGrant,
}

impl T13ReceiptEpochVerifier {
    pub(crate) fn new(config: T13EpochVerifierConfig) -> Self {
        Self {
            channel: config.channel,
            installed_trust: config.installed_trust,
            expected_grant: config.expected_grant,
        }
    }
}

impl epoch_verifier_private::Sealed for T13ReceiptEpochVerifier {}

impl EpochVerifier for T13ReceiptEpochVerifier {
    fn verify(
        &self,
        envelope: &SignedEpochEnvelope,
        now_millis: u64,
    ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
        let now = ProtocolTime::from_unix_millis(now_millis)
            .map_err(|_| EpochAdmissionError::InvalidValidity)?;
        let raw = envelope.canonical_bytes();
        let candidate_key_id = untrusted_signing_key_id(raw).map_err(map_signed_error)?;
        let installed_key = self
            .installed_trust
            .authority_root(&candidate_key_id)
            .map_err(map_key_lookup)?;
        let skew_micros = MAXIMUM_SIGNATURE_CLOCK_SKEW_MILLIS
            .checked_mul(1_000)
            .ok_or(EpochAdmissionError::InvalidValidity)?;
        let controls = SignatureControls::new(SignaturePurpose::ScopeEpoch, now, skew_micros, 1)
            .map_err(map_signed_error)?;
        let signed =
            verify_signed_envelope(raw, installed_key, &controls).map_err(map_signed_error)?;
        self.installed_trust
            .require_grant_authority(
                &self.expected_grant.grant_id,
                self.expected_grant.grant_version,
                signed.key_id(),
            )
            .map_err(map_grant_pin)?;
        let payload = ScopeEpochPayload::correlate(&signed, &self.expected_grant)?;
        let receipt_bytes = envelope
            .verifier_receipt_bytes()
            .ok_or(EpochAdmissionError::InvalidVerificationReceipt)?;
        let receipt = ParsedReceipt::parse(receipt_bytes)?;
        receipt.correlate_channel(&self.channel)?;
        receipt.correlate_epoch(raw, &signed, &payload)?;
        receipt.require_freshness(now_millis, &signed, &payload)?;
        receipt.authenticate(&self.channel)?;

        Ok(VerifiedScopeEpoch::from_trusted_verifier(
            VerifiedScopeEpochParts {
                grant_id: payload.grant_id,
                epoch: payload.epoch,
                issued_at_millis: payload.issued_at.ceil_millis(),
                expires_at_millis: payload.expires_at.floor_millis(),
                revoked: payload.revoked,
                revocation_reason: payload.revocation_reason,
                key_id: signed.key_id().to_owned(),
                signature_sequence: signed.sequence(),
                envelope_digest: signed.envelope_digest(),
                payload_digest: signed.payload_digest(),
                verifier_receipt_digest: Digest::of(receipt_bytes),
                gateway_boot_id: receipt.gateway_boot_id,
                verification_nonce: receipt.nonce,
            },
        ))
    }
}

#[cfg(test)]
#[path = "t13_epoch/tests/mod.rs"]
mod tests;
