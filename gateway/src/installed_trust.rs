use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::signed_protocol::{TrustedEd25519Key, TrustedKeyStatus};

#[path = "installed_trust_schema.rs"]
mod schema;

const INSTALLED_TRUST_PATH: &str = "/etc/faultloom/gateway-trust-v1.json";
const MAXIMUM_TRUST_STORE_BYTES: usize = 64 * 1024;
const MAXIMUM_TRUST_STORE_BYTES_U64: u64 = 64 * 1024;

pub(crate) struct InstalledTrustStore {
    generation: u64,
    authority_keys: Vec<TrustedEd25519Key>,
    controller_keys: Vec<TrustedEd25519Key>,
    grant_pins: Vec<GrantPin>,
}

pub(crate) struct GrantPin {
    grant_id: String,
    minimum_version: u64,
    authority_key_ids: Vec<String>,
    controller_key_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstalledTrustError {
    TrustStoreUnavailable,
    UnsafeFilesystem,
    TrustStoreTooLarge,
    NonCanonicalDocument,
    InvalidDocument,
    UnsupportedSchemaVersion,
    InvalidGeneration,
    InvalidKey,
    DuplicateKeyId,
    InvalidGrantPin,
    DuplicateGrantPin,
    UnknownAuthorityRoot,
    RevokedAuthorityRoot,
    MissingGrantPin,
    GrantVersionBelowMinimum,
    UnpinnedAuthorityRoot,
    UnknownControllerRoot,
    RevokedControllerRoot,
    UnpinnedControllerRoot,
}

impl InstalledTrustStore {
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn authority_root(
        &self,
        key_id: &str,
    ) -> Result<&TrustedEd25519Key, InstalledTrustError> {
        let key = self
            .authority_keys
            .iter()
            .find(|candidate| candidate.key_id() == key_id)
            .ok_or(InstalledTrustError::UnknownAuthorityRoot)?;
        match key.status() {
            TrustedKeyStatus::Active => Ok(key),
            TrustedKeyStatus::Revoked => Err(InstalledTrustError::RevokedAuthorityRoot),
        }
    }

    pub(crate) fn require_grant_authority(
        &self,
        grant_id: &str,
        grant_version: u64,
        key_id: &str,
    ) -> Result<(), InstalledTrustError> {
        let pin = self.pin_for(grant_id, grant_version)?;
        if !pin.authority_key_ids.iter().any(|pinned| pinned == key_id) {
            return Err(InstalledTrustError::UnpinnedAuthorityRoot);
        }
        self.authority_root(key_id).map(|_| ())
    }

    pub(crate) fn controller_for_grant(
        &self,
        grant_id: &str,
        grant_version: u64,
        key_id: &str,
    ) -> Result<&TrustedEd25519Key, InstalledTrustError> {
        let pin = self.pin_for(grant_id, grant_version)?;
        if !pin.controller_key_ids.iter().any(|pinned| pinned == key_id) {
            return Err(InstalledTrustError::UnpinnedControllerRoot);
        }
        let key = self
            .controller_keys
            .iter()
            .find(|candidate| candidate.key_id() == key_id)
            .ok_or(InstalledTrustError::UnknownControllerRoot)?;
        match key.status() {
            TrustedKeyStatus::Active => Ok(key),
            TrustedKeyStatus::Revoked => Err(InstalledTrustError::RevokedControllerRoot),
        }
    }

    fn pin_for(
        &self,
        grant_id: &str,
        grant_version: u64,
    ) -> Result<&GrantPin, InstalledTrustError> {
        let pin = self
            .grant_pins
            .iter()
            .find(|candidate| candidate.grant_id == grant_id)
            .ok_or(InstalledTrustError::MissingGrantPin)?;
        if grant_version < pin.minimum_version {
            return Err(InstalledTrustError::GrantVersionBelowMinimum);
        }
        Ok(pin)
    }
}

pub(crate) fn load_installed_trust_store() -> Result<InstalledTrustStore, InstalledTrustError> {
    let path = Path::new(INSTALLED_TRUST_PATH);
    validate_parent_chain(path)?;
    let before_open =
        fs::symlink_metadata(path).map_err(|_| InstalledTrustError::TrustStoreUnavailable)?;
    validate_metadata(&before_open, ExpectedNode::RegularFile)?;
    if before_open.len() > MAXIMUM_TRUST_STORE_BYTES_U64 {
        return Err(InstalledTrustError::TrustStoreTooLarge);
    }

    let file = File::open(path).map_err(|_| InstalledTrustError::TrustStoreUnavailable)?;
    let after_open = file
        .metadata()
        .map_err(|_| InstalledTrustError::TrustStoreUnavailable)?;
    validate_metadata(&after_open, ExpectedNode::RegularFile)?;
    if before_open.dev() != after_open.dev() || before_open.ino() != after_open.ino() {
        return Err(InstalledTrustError::UnsafeFilesystem);
    }

    let capacity = usize::try_from(after_open.len()).map_or(MAXIMUM_TRUST_STORE_BYTES, |length| {
        length.min(MAXIMUM_TRUST_STORE_BYTES)
    });
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAXIMUM_TRUST_STORE_BYTES_U64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstalledTrustError::TrustStoreUnavailable)?;
    if bytes.len() > MAXIMUM_TRUST_STORE_BYTES {
        return Err(InstalledTrustError::TrustStoreTooLarge);
    }
    parse_installed_trust_store(&bytes)
}

fn parse_installed_trust_store(bytes: &[u8]) -> Result<InstalledTrustStore, InstalledTrustError> {
    schema::parse(bytes, MAXIMUM_TRUST_STORE_BYTES)
}

#[cfg(test)]
pub(crate) fn installed_trust_store_from_canonical_bytes_for_test(
    bytes: &[u8],
) -> Result<InstalledTrustStore, InstalledTrustError> {
    parse_installed_trust_store(bytes)
}

fn validate_parent_chain(path: &Path) -> Result<(), InstalledTrustError> {
    let parent = path.parent().ok_or(InstalledTrustError::UnsafeFilesystem)?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| InstalledTrustError::TrustStoreUnavailable)?;
        validate_metadata(&metadata, ExpectedNode::Directory)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ExpectedNode {
    Directory,
    RegularFile,
}

fn validate_metadata(
    metadata: &Metadata,
    expected: ExpectedNode,
) -> Result<(), InstalledTrustError> {
    let matches_type = match expected {
        ExpectedNode::Directory => metadata.file_type().is_dir(),
        ExpectedNode::RegularFile => metadata.file_type().is_file(),
    };
    if !matches_type || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(InstalledTrustError::UnsafeFilesystem);
    }
    Ok(())
}

impl fmt::Display for InstalledTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TrustStoreUnavailable => "installed trust store is unavailable",
            Self::UnsafeFilesystem => "installed trust store filesystem boundary is unsafe",
            Self::TrustStoreTooLarge => "installed trust store exceeds its byte limit",
            Self::NonCanonicalDocument => "installed trust store is not canonical JSON",
            Self::InvalidDocument => "installed trust store does not match schema v1",
            Self::UnsupportedSchemaVersion => "installed trust store schema version is unsupported",
            Self::InvalidGeneration => "installed trust store generation is invalid",
            Self::InvalidKey => "installed trust store contains an invalid key",
            Self::DuplicateKeyId => "installed trust store contains a duplicate key ID",
            Self::InvalidGrantPin => "installed trust store contains an invalid grant pin",
            Self::DuplicateGrantPin => "installed trust store contains a duplicate grant pin",
            Self::UnknownAuthorityRoot => "authority root is not installed",
            Self::RevokedAuthorityRoot => "authority root is revoked",
            Self::MissingGrantPin => "grant is not pinned",
            Self::GrantVersionBelowMinimum => "grant version is below the installed minimum",
            Self::UnpinnedAuthorityRoot => "authority root is not pinned for this grant",
            Self::UnknownControllerRoot => "controller root is not installed",
            Self::RevokedControllerRoot => "controller root is revoked",
            Self::UnpinnedControllerRoot => "controller root is not pinned for this grant",
        })
    }
}

impl std::error::Error for InstalledTrustError {}

#[cfg(test)]
#[path = "installed_trust_tests.rs"]
mod tests;
