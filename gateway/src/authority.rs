#[path = "authority_model.rs"]
mod model;
#[path = "authority_policy.rs"]
mod policy;
#[path = "authority_policy_build.rs"]
mod policy_build;
#[path = "authority_policy_values.rs"]
mod policy_values;
#[path = "authority_validation.rs"]
mod validation;

use crate::Digest;
use crate::installed_trust::{InstalledTrustError, InstalledTrustStore};
use crate::protocol_time::ProtocolTime;
use crate::scope::TimeWindow;
use crate::signed_protocol::{
    SignatureControls, SignaturePurpose, SignedProtocolError, untrusted_signing_key_id,
    verify_signed_envelope,
};

pub(crate) use policy::{RequestedSelection, RequestedSelectionParts};
pub(crate) use policy_build::{AuthorizedRunPolicy, authorize_selection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityError {
    InvalidEnvelope,
    UntrustedSigningKey,
    SignatureInvalid,
    TrustUnavailable,
    InvalidProtocol,
    UnsupportedActionClass,
    GrantNotPinned,
    GrantVersionRollback,
    NotYetValid,
    Expired,
    InvalidValidity,
    InvalidSelection,
    SelectionNotAuthorized,
    NetworkNotAuthorized,
    EmptyMethodIntersection,
    EmptyPathIntersection,
}

pub(crate) struct VerifiedAuthorityGrant {
    model: model::AuthorityGrantModel,
    authority_key_id: String,
    payload_digest: Digest,
    envelope_digest: Digest,
    trust_generation: u64,
    execution_windows: Vec<TimeWindow>,
}

pub(crate) struct AuthorityVerifier;

impl AuthorityVerifier {
    pub(crate) fn verify(
        raw: &[u8],
        trust: &InstalledTrustStore,
        now_millis: u64,
        maximum_clock_skew_millis: u64,
    ) -> Result<VerifiedAuthorityGrant, AuthorityError> {
        let key_id = untrusted_signing_key_id(raw).map_err(map_signed_error)?;
        let key = trust.authority_root(&key_id).map_err(map_key_lookup)?;
        let now = ProtocolTime::from_unix_millis(now_millis)
            .map_err(|_| AuthorityError::InvalidProtocol)?;
        let skew_micros = maximum_clock_skew_millis
            .checked_mul(1_000)
            .ok_or(AuthorityError::InvalidProtocol)?;
        let controls =
            SignatureControls::new(SignaturePurpose::AuthorityGrant, now, skew_micros, 1)
                .map_err(map_signed_error)?;
        let envelope = verify_signed_envelope(raw, key, &controls).map_err(map_signed_error)?;
        let model = serde_json::from_slice::<model::AuthorityGrantModel>(envelope.payload_bytes())
            .map_err(|_| AuthorityError::InvalidProtocol)?;
        trust
            .require_grant_authority(&model.grant_id, model.grant_version, envelope.key_id())
            .map_err(map_grant_pin)?;
        let times = validation::validate_grant_semantics(&model, &envelope, now)?;
        policy_build::validate_grant_scope(&model, &times.execution_windows)?;
        Ok(VerifiedAuthorityGrant {
            model,
            authority_key_id: envelope.key_id().to_owned(),
            payload_digest: envelope.payload_digest(),
            envelope_digest: envelope.envelope_digest(),
            trust_generation: trust.generation(),
            execution_windows: times.execution_windows,
        })
    }
}

fn map_signed_error(error: SignedProtocolError) -> AuthorityError {
    match error {
        SignedProtocolError::SignatureInvalid => AuthorityError::SignatureInvalid,
        SignedProtocolError::NotYetValid => AuthorityError::NotYetValid,
        SignedProtocolError::Expired => AuthorityError::Expired,
        SignedProtocolError::Rollback => AuthorityError::GrantVersionRollback,
        SignedProtocolError::RevokedKey => AuthorityError::UntrustedSigningKey,
        SignedProtocolError::CanonicalJson(_)
        | SignedProtocolError::EnvelopeShape
        | SignedProtocolError::UnsupportedSchemaVersion
        | SignedProtocolError::UnsupportedProtocolVersion
        | SignedProtocolError::UnsupportedAlgorithm
        | SignedProtocolError::UnsupportedPurpose
        | SignedProtocolError::PurposeMismatch
        | SignedProtocolError::InvalidKeyId
        | SignedProtocolError::InvalidPublicKey
        | SignedProtocolError::KeyIdMismatch
        | SignedProtocolError::InvalidBase64Url
        | SignedProtocolError::InvalidPayloadDigest
        | SignedProtocolError::PayloadDigestMismatch
        | SignedProtocolError::InvalidSequence
        | SignedProtocolError::InvalidTimestamp
        | SignedProtocolError::InvalidTimeOrder
        | SignedProtocolError::InvalidControls => AuthorityError::InvalidEnvelope,
    }
}

fn map_key_lookup(error: InstalledTrustError) -> AuthorityError {
    match error {
        InstalledTrustError::UnknownAuthorityRoot | InstalledTrustError::RevokedAuthorityRoot => {
            AuthorityError::UntrustedSigningKey
        }
        _ => AuthorityError::TrustUnavailable,
    }
}

fn map_grant_pin(error: InstalledTrustError) -> AuthorityError {
    match error {
        InstalledTrustError::MissingGrantPin | InstalledTrustError::UnpinnedAuthorityRoot => {
            AuthorityError::GrantNotPinned
        }
        InstalledTrustError::GrantVersionBelowMinimum => AuthorityError::GrantVersionRollback,
        InstalledTrustError::UnknownAuthorityRoot | InstalledTrustError::RevokedAuthorityRoot => {
            AuthorityError::UntrustedSigningKey
        }
        _ => AuthorityError::TrustUnavailable,
    }
}

#[cfg(test)]
#[path = "authority_policy_tests.rs"]
mod policy_tests;
#[cfg(test)]
#[path = "authority_test_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
