use serde::{Deserialize, Deserializer};

use super::ExpectedScopeEpochGrant;
use crate::ipc::valid_identifier;
use crate::protocol_time::ProtocolTime;
use crate::scope::EpochAdmissionError;
use crate::signed_protocol::VerifiedSignedEnvelope;

const MAXIMUM_REASON_BYTES: usize = 16_384;

#[derive(Clone, Copy, Deserialize)]
enum SchemaVersion {
    #[serde(rename = "0.1.0")]
    V0_1_0,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScopeEpoch {
    epoch: u64,
    expires_at: String,
    grant_id: String,
    issued_at: String,
    #[serde(deserialize_with = "required_option")]
    revocation_reason: Option<String>,
    revoked: bool,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

pub(super) struct ScopeEpochPayload {
    pub(super) epoch: u64,
    pub(super) expires_at_text: String,
    pub(super) expires_at: ProtocolTime,
    pub(super) grant_id: String,
    pub(super) issued_at_text: String,
    pub(super) issued_at: ProtocolTime,
    pub(super) revocation_reason: Option<String>,
    pub(super) revoked: bool,
}

impl ScopeEpochPayload {
    pub(super) fn correlate(
        signed: &VerifiedSignedEnvelope,
        expected: &ExpectedScopeEpochGrant,
    ) -> Result<Self, EpochAdmissionError> {
        let wire = serde_json::from_slice::<WireScopeEpoch>(signed.payload_bytes())
            .map_err(|_| EpochAdmissionError::InvalidEnvelope)?;
        if wire.grant_id != expected.grant_id.as_str() {
            return Err(EpochAdmissionError::GrantMismatch);
        }
        if wire.epoch == 0
            || wire.epoch > i64::MAX.unsigned_abs()
            || signed.sequence() != wire.epoch
            || !valid_identifier(&wire.grant_id)
            || wire.revoked != wire.revocation_reason.is_some()
            || !valid_reason(wire.revocation_reason.as_deref())
        {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        let issued_at = ProtocolTime::parse_canonical(&wire.issued_at)
            .map_err(|_| EpochAdmissionError::InvalidEnvelope)?;
        let expires_at = ProtocolTime::parse_canonical(&wire.expires_at)
            .map_err(|_| EpochAdmissionError::InvalidEnvelope)?;
        if expires_at <= issued_at
            || signed.expires_at() != expires_at
            || signed.signed_at() < issued_at
        {
            return Err(EpochAdmissionError::InvalidValidity);
        }
        Ok(Self {
            epoch: wire.epoch,
            expires_at_text: wire.expires_at,
            expires_at,
            grant_id: wire.grant_id,
            issued_at_text: wire.issued_at,
            issued_at,
            revocation_reason: wire.revocation_reason,
            revoked: wire.revoked,
        })
    }
}

fn valid_reason(reason: Option<&str>) -> bool {
    reason.is_none_or(|value| {
        !value.is_empty() && value.len() <= MAXIMUM_REASON_BYTES && value.trim() == value
    })
}

fn required_option<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}
