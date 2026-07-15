use super::channel::ReceiptAuthenticationChannel;
use super::payload::ScopeEpochPayload;
use super::receipt_crypto::{constant_time_equal, hmac_sha256};
use super::receipt_cursor::ReceiptCursor;
use crate::Digest;
use crate::ipc::valid_identifier;
use crate::scope::EpochAdmissionError;
use crate::signed_protocol::VerifiedSignedEnvelope;
use crate::signed_protocol_parse::valid_prefixed_hex;

const MAGIC: &[u8; 4] = b"FLER";
const VERSION: u8 = 1;
const MAXIMUM_RECEIPT_CLOCK_SKEW_MILLIS: u64 = 1_000;
const MAXIMUM_RECEIPT_TTL_MILLIS: u64 = 5_000;
const MAXIMUM_TEXT_BYTES: usize = 256;
const MAXIMUM_REASON_BYTES: usize = 16_384;

pub(super) struct ParsedReceipt<'a> {
    channel_key_id: String,
    pub(super) gateway_boot_id: String,
    gateway_challenge: [u8; 32],
    protocol_version: String,
    schema_version: String,
    purpose: String,
    canonical_envelope: &'a [u8],
    envelope_digest: Digest,
    payload_digest: Digest,
    authority_key_id: String,
    grant_id: String,
    epoch: u64,
    sequence: u64,
    issued_at: String,
    expires_at: String,
    revoked: bool,
    revocation_reason: Option<String>,
    verified_at_millis: u64,
    expires_at_millis: u64,
    pub(super) nonce: [u8; 16],
    authenticated_bytes: &'a [u8],
    mac: [u8; 32],
}

impl<'a> ParsedReceipt<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self, EpochAdmissionError> {
        let mut cursor = ReceiptCursor::new(bytes);
        cursor.literal(MAGIC)?;
        if cursor.byte()? != VERSION {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        let channel_key_id = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let gateway_boot_id = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let gateway_challenge = cursor.array()?;
        let protocol_version = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let schema_version = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let purpose = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let canonical_envelope = cursor.envelope_bytes()?;
        let envelope_digest = Digest::from_bytes(cursor.array()?);
        let payload_digest = Digest::from_bytes(cursor.array()?);
        let authority_key_id = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let grant_id = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let epoch = cursor.u64()?;
        let sequence = cursor.u64()?;
        let issued_at = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let expires_at = cursor.string(MAXIMUM_TEXT_BYTES)?;
        let revoked = match cursor.byte()? {
            0 => false,
            1 => true,
            _ => return Err(EpochAdmissionError::InvalidVerificationReceipt),
        };
        let revocation_reason = cursor.optional_string(MAXIMUM_REASON_BYTES)?;
        let verified_at_millis = cursor.u64()?;
        let expires_at_millis = cursor.u64()?;
        let nonce = cursor.array()?;
        let authenticated_length = cursor.offset;
        let mac = cursor.array()?;
        cursor.finish()?;
        if !valid_identifier(&channel_key_id)
            || !valid_identifier(&gateway_boot_id)
            || !valid_prefixed_hex(&authority_key_id, "ed25519:sha256:")
            || !valid_identifier(&grant_id)
            || !(1..=i64::MAX.unsigned_abs()).contains(&epoch)
            || !(1..=i64::MAX.unsigned_abs()).contains(&sequence)
            || revoked != revocation_reason.is_some()
            || !valid_nonce(&nonce)
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        Ok(Self {
            channel_key_id,
            gateway_boot_id,
            gateway_challenge,
            protocol_version,
            schema_version,
            purpose,
            canonical_envelope,
            envelope_digest,
            payload_digest,
            authority_key_id,
            grant_id,
            epoch,
            sequence,
            issued_at,
            expires_at,
            revoked,
            revocation_reason,
            verified_at_millis,
            expires_at_millis,
            nonce,
            authenticated_bytes: &bytes[..authenticated_length],
            mac,
        })
    }

    pub(super) fn correlate_channel(
        &self,
        channel: &ReceiptAuthenticationChannel,
    ) -> Result<(), EpochAdmissionError> {
        if self.channel_key_id != channel.key_id()
            || self.gateway_boot_id != channel.boot().id()
            || self.gateway_challenge != *channel.boot().challenge()
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        Ok(())
    }

    pub(super) fn correlate_epoch(
        &self,
        raw: &[u8],
        signed: &VerifiedSignedEnvelope,
        payload: &ScopeEpochPayload,
    ) -> Result<(), EpochAdmissionError> {
        if self.protocol_version != "0.1.0"
            || self.schema_version != "0.1.0"
            || self.purpose != "scope_epoch"
            || self.canonical_envelope != raw
            || self.envelope_digest != signed.envelope_digest()
            || self.payload_digest != signed.payload_digest()
            || self.authority_key_id != signed.key_id()
            || self.grant_id != payload.grant_id.as_str()
            || self.epoch != payload.epoch
            || self.sequence != signed.sequence()
            || self.issued_at != payload.issued_at_text
            || self.expires_at != payload.expires_at_text
            || self.revoked != payload.revoked
            || self.revocation_reason.as_deref() != payload.revocation_reason.as_deref()
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        Ok(())
    }

    pub(super) fn require_freshness(
        &self,
        now_millis: u64,
        signed: &VerifiedSignedEnvelope,
        payload: &ScopeEpochPayload,
    ) -> Result<(), EpochAdmissionError> {
        let earliest_verification = payload
            .issued_at
            .ceil_millis()
            .max(signed.signed_at().ceil_millis());
        if self.expires_at_millis <= self.verified_at_millis
            || self.verified_at_millis < earliest_verification
            || self.verified_at_millis
                > now_millis.saturating_add(MAXIMUM_RECEIPT_CLOCK_SKEW_MILLIS)
            || now_millis >= self.expires_at_millis
            || self.expires_at_millis > payload.expires_at.floor_millis()
            || self.expires_at_millis - self.verified_at_millis > MAXIMUM_RECEIPT_TTL_MILLIS
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        Ok(())
    }

    pub(super) fn authenticate(
        &self,
        channel: &ReceiptAuthenticationChannel,
    ) -> Result<(), EpochAdmissionError> {
        let expected = hmac_sha256(channel.key(), self.authenticated_bytes);
        if constant_time_equal(expected.as_bytes(), &self.mac) {
            Ok(())
        } else {
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        }
    }
}

fn valid_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}
