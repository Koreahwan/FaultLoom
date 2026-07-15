use std::collections::HashSet;

use serde::Deserialize;

use super::{GrantPin, InstalledTrustError, InstalledTrustStore};
use crate::canonical_json::{CanonicalJsonError, parse_canonical_json};
use crate::signed_protocol::{TrustedEd25519Key, TrustedKeyStatus};

const SCHEMA_VERSION: u64 = 1;
const MAXIMUM_KEYS_PER_ROLE: usize = 32;
const MAXIMUM_GRANT_PINS: usize = 256;
const MAXIMUM_KEYS_PER_PIN: usize = 32;
const MAXIMUM_GRANT_ID_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTrustStore {
    authority_keys: Vec<WireKey>,
    controller_keys: Vec<WireKey>,
    generation: u64,
    grant_pins: Vec<WireGrantPin>,
    schema_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireKey {
    key_id: String,
    public_key_base64url: String,
    status: WireKeyStatus,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireKeyStatus {
    Active,
    Revoked,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGrantPin {
    authority_key_ids: Vec<String>,
    controller_key_ids: Vec<String>,
    grant_id: String,
    minimum_version: u64,
}

pub(super) fn parse(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<InstalledTrustStore, InstalledTrustError> {
    let value = parse_canonical_json(bytes, maximum_bytes).map_err(map_canonical_error)?;
    let wire: WireTrustStore =
        serde_json::from_value(value).map_err(|_| InstalledTrustError::InvalidDocument)?;
    validate_header(&wire)?;
    validate_unique_key_ids(&wire.authority_keys, &wire.controller_keys)?;
    validate_pins(&wire)?;

    let authority_keys = parse_keys(wire.authority_keys)?;
    let controller_keys = parse_keys(wire.controller_keys)?;
    let grant_pins = wire
        .grant_pins
        .into_iter()
        .map(|pin| GrantPin {
            grant_id: pin.grant_id,
            minimum_version: pin.minimum_version,
            authority_key_ids: pin.authority_key_ids,
            controller_key_ids: pin.controller_key_ids,
        })
        .collect();
    Ok(InstalledTrustStore {
        generation: wire.generation,
        authority_keys,
        controller_keys,
        grant_pins,
    })
}

fn map_canonical_error(error: CanonicalJsonError) -> InstalledTrustError {
    match error {
        CanonicalJsonError::TooLarge { .. } => InstalledTrustError::TrustStoreTooLarge,
        CanonicalJsonError::NonCanonical => InstalledTrustError::NonCanonicalDocument,
        CanonicalJsonError::Empty
        | CanonicalJsonError::InvalidUtf8
        | CanonicalJsonError::Malformed
        | CanonicalJsonError::InvalidNumber => InstalledTrustError::InvalidDocument,
    }
}

fn validate_header(wire: &WireTrustStore) -> Result<(), InstalledTrustError> {
    if wire.schema_version != SCHEMA_VERSION {
        return Err(InstalledTrustError::UnsupportedSchemaVersion);
    }
    if wire.generation == 0 {
        return Err(InstalledTrustError::InvalidGeneration);
    }
    if wire.authority_keys.is_empty()
        || wire.authority_keys.len() > MAXIMUM_KEYS_PER_ROLE
        || wire.controller_keys.is_empty()
        || wire.controller_keys.len() > MAXIMUM_KEYS_PER_ROLE
        || wire.grant_pins.is_empty()
        || wire.grant_pins.len() > MAXIMUM_GRANT_PINS
    {
        return Err(InstalledTrustError::InvalidDocument);
    }
    Ok(())
}

fn validate_unique_key_ids(
    authority_keys: &[WireKey],
    controller_keys: &[WireKey],
) -> Result<(), InstalledTrustError> {
    let mut seen = HashSet::with_capacity(authority_keys.len() + controller_keys.len());
    for key in authority_keys.iter().chain(controller_keys) {
        if !seen.insert(key.key_id.as_str()) {
            return Err(InstalledTrustError::DuplicateKeyId);
        }
    }
    Ok(())
}

fn validate_pins(wire: &WireTrustStore) -> Result<(), InstalledTrustError> {
    let authority_ids: HashSet<&str> = wire
        .authority_keys
        .iter()
        .map(|key| key.key_id.as_str())
        .collect();
    let controller_ids: HashSet<&str> = wire
        .controller_keys
        .iter()
        .map(|key| key.key_id.as_str())
        .collect();
    let mut grants = HashSet::with_capacity(wire.grant_pins.len());
    for pin in &wire.grant_pins {
        if !grants.insert(pin.grant_id.as_str()) {
            return Err(InstalledTrustError::DuplicateGrantPin);
        }
        if !valid_grant_id(&pin.grant_id)
            || pin.minimum_version == 0
            || !valid_pinned_ids(&pin.authority_key_ids, &authority_ids)
            || !valid_pinned_ids(&pin.controller_key_ids, &controller_ids)
        {
            return Err(InstalledTrustError::InvalidGrantPin);
        }
    }
    Ok(())
}

fn valid_pinned_ids(ids: &[String], installed: &HashSet<&str>) -> bool {
    if ids.is_empty() || ids.len() > MAXIMUM_KEYS_PER_PIN {
        return false;
    }
    let mut seen = HashSet::with_capacity(ids.len());
    ids.iter()
        .all(|key_id| installed.contains(key_id.as_str()) && seen.insert(key_id.as_str()))
}

fn valid_grant_id(grant_id: &str) -> bool {
    !grant_id.is_empty()
        && grant_id.len() <= MAXIMUM_GRANT_ID_BYTES
        && grant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
}

fn parse_keys(keys: Vec<WireKey>) -> Result<Vec<TrustedEd25519Key>, InstalledTrustError> {
    keys.into_iter()
        .map(|key| {
            let status = match key.status {
                WireKeyStatus::Active => TrustedKeyStatus::Active,
                WireKeyStatus::Revoked => TrustedKeyStatus::Revoked,
            };
            TrustedEd25519Key::from_base64(key.key_id, &key.public_key_base64url, status)
                .map_err(|_| InstalledTrustError::InvalidKey)
        })
        .collect()
}
