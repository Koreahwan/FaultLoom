use crate::installed_trust::InstalledTrustError;
use crate::scope::EpochAdmissionError;
use crate::signed_protocol::SignedProtocolError;

pub(super) fn map_signed_error(error: SignedProtocolError) -> EpochAdmissionError {
    match error {
        SignedProtocolError::SignatureInvalid => EpochAdmissionError::VerificationFailed,
        SignedProtocolError::RevokedKey => EpochAdmissionError::TrustAnchorRevoked,
        SignedProtocolError::Rollback => EpochAdmissionError::Rollback,
        SignedProtocolError::NotYetValid => EpochAdmissionError::NotYetValid,
        SignedProtocolError::Expired => EpochAdmissionError::Expired,
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
        | SignedProtocolError::InvalidControls => EpochAdmissionError::InvalidEnvelope,
    }
}

pub(super) fn map_key_lookup(error: InstalledTrustError) -> EpochAdmissionError {
    match error {
        InstalledTrustError::UnknownAuthorityRoot => EpochAdmissionError::UnknownKey,
        InstalledTrustError::RevokedAuthorityRoot => EpochAdmissionError::TrustAnchorRevoked,
        InstalledTrustError::TrustStoreUnavailable
        | InstalledTrustError::UnsafeFilesystem
        | InstalledTrustError::TrustStoreTooLarge
        | InstalledTrustError::NonCanonicalDocument
        | InstalledTrustError::InvalidDocument
        | InstalledTrustError::UnsupportedSchemaVersion
        | InstalledTrustError::InvalidGeneration
        | InstalledTrustError::InvalidKey
        | InstalledTrustError::DuplicateKeyId
        | InstalledTrustError::InvalidGrantPin
        | InstalledTrustError::DuplicateGrantPin
        | InstalledTrustError::MissingGrantPin
        | InstalledTrustError::GrantVersionBelowMinimum
        | InstalledTrustError::UnpinnedAuthorityRoot
        | InstalledTrustError::UnknownControllerRoot
        | InstalledTrustError::RevokedControllerRoot
        | InstalledTrustError::UnpinnedControllerRoot => EpochAdmissionError::StateUnavailable,
    }
}

pub(super) fn map_grant_pin(error: InstalledTrustError) -> EpochAdmissionError {
    match error {
        InstalledTrustError::MissingGrantPin | InstalledTrustError::UnpinnedAuthorityRoot => {
            EpochAdmissionError::GrantMismatch
        }
        InstalledTrustError::GrantVersionBelowMinimum => EpochAdmissionError::Rollback,
        InstalledTrustError::UnknownAuthorityRoot => EpochAdmissionError::UnknownKey,
        InstalledTrustError::RevokedAuthorityRoot => EpochAdmissionError::TrustAnchorRevoked,
        InstalledTrustError::TrustStoreUnavailable
        | InstalledTrustError::UnsafeFilesystem
        | InstalledTrustError::TrustStoreTooLarge
        | InstalledTrustError::NonCanonicalDocument
        | InstalledTrustError::InvalidDocument
        | InstalledTrustError::UnsupportedSchemaVersion
        | InstalledTrustError::InvalidGeneration
        | InstalledTrustError::InvalidKey
        | InstalledTrustError::DuplicateKeyId
        | InstalledTrustError::InvalidGrantPin
        | InstalledTrustError::DuplicateGrantPin
        | InstalledTrustError::UnknownControllerRoot
        | InstalledTrustError::RevokedControllerRoot
        | InstalledTrustError::UnpinnedControllerRoot => EpochAdmissionError::StateUnavailable,
    }
}
