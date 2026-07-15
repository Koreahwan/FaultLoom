use crate::Digest;
use crate::authority::RequestedSelection;
use crate::installed_trust::InstalledTrustStore;
use crate::ipc::{DenialCode, valid_identifier};

use super::supervisor_bootstrap_v4::{BootAuthorization, SupervisorSecretsV4};
use super::supervisor_wire::Encoder;

pub(crate) const MAX_BOOT_AUTHORIZATION_TTL_MILLIS: u64 = 30_000;

pub(crate) struct BootBindingContext<'a> {
    pub(crate) trust_generation: u64,
    pub(crate) grant_envelope_digest: Digest,
    pub(crate) grant_payload_digest: Digest,
    pub(crate) grant_id: &'a str,
    pub(crate) grant_version: u64,
    pub(crate) selection: &'a RequestedSelection,
    pub(crate) selection_digest: Digest,
    pub(crate) secrets: &'a SupervisorSecretsV4,
    pub(crate) expected_journal_anchor: Digest,
    pub(crate) executable_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct VerifiedBootAuthorization {
    boot_sequence: u64,
    nonce: [u8; 16],
}

impl VerifiedBootAuthorization {
    pub(crate) const fn boot_sequence(&self) -> u64 {
        self.boot_sequence
    }

    pub(crate) const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
}

pub(crate) fn verify_boot_authorization(
    trust: &InstalledTrustStore,
    context: &BootBindingContext<'_>,
    authorization: &BootAuthorization,
    now_millis: u64,
) -> Result<VerifiedBootAuthorization, DenialCode> {
    if trust.generation() != context.trust_generation
        || now_millis < authorization.issued_at_millis
        || now_millis >= authorization.expires_at_millis
    {
        return Err(DenialCode::IpcAuthenticationFailed);
    }
    let message = boot_authorization_signing_bytes(context, authorization)?;
    let controller = trust
        .controller_for_grant(
            context.grant_id,
            context.grant_version,
            &authorization.controller_key_id,
        )
        .map_err(|_| DenialCode::IpcAuthenticationFailed)?;
    controller
        .verify_strict(&message, &authorization.signature)
        .map_err(|_| DenialCode::IpcAuthenticationFailed)?;
    Ok(VerifiedBootAuthorization {
        boot_sequence: authorization.boot_sequence,
        nonce: authorization.nonce,
    })
}

pub(super) fn boot_authorization_signing_bytes(
    context: &BootBindingContext<'_>,
    authorization: &BootAuthorization,
) -> Result<Vec<u8>, DenialCode> {
    validate_context(context)?;
    validate_authorization_shape(authorization)?;
    let mut encoder = Encoder::new(b"FLBA", 1, 1);
    encoder.u64(context.trust_generation);
    encoder.digest(context.grant_envelope_digest);
    encoder.digest(context.grant_payload_digest);
    encoder.string(context.grant_id)?;
    encoder.u64(context.grant_version);
    encoder.digest(context.selection_digest);
    encode_secret_fingerprints(&mut encoder, context.secrets)?;
    encoder.digest(context.secrets.channel_challenge()?.challenge_id());
    encoder.string(&context.secrets.gateway_boot_id)?;
    encoder.digest(gateway_challenge_digest(context.secrets.gateway_challenge));
    encoder.digest(context.expected_journal_anchor);
    encoder.digest(context.executable_digest);
    encoder.string(&authorization.controller_key_id)?;
    encoder.u64(authorization.issued_at_millis);
    encoder.u64(authorization.expires_at_millis);
    encoder.u64(authorization.boot_sequence);
    encoder.nonce(authorization.nonce);
    encoder.finish()
}

fn validate_context(context: &BootBindingContext<'_>) -> Result<(), DenialCode> {
    if context.trust_generation == 0
        || context.grant_envelope_digest == Digest::ZERO
        || context.grant_payload_digest == Digest::ZERO
        || !valid_identifier(context.grant_id)
        || context.grant_version == 0
        || context.selection_digest == Digest::ZERO
        || context.selection_digest != context.selection.binding_digest()
        || context.executable_digest == Digest::ZERO
    {
        return Err(DenialCode::IpcAuthenticationFailed);
    }
    context.secrets.validate_separation()
}

fn validate_authorization_shape(authorization: &BootAuthorization) -> Result<(), DenialCode> {
    let valid_key_id = authorization
        .controller_key_id
        .strip_prefix("ed25519:sha256:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        });
    if !valid_key_id
        || authorization.issued_at_millis == 0
        || authorization.issued_at_millis >= authorization.expires_at_millis
        || authorization
            .expires_at_millis
            .saturating_sub(authorization.issued_at_millis)
            > MAX_BOOT_AUTHORIZATION_TTL_MILLIS
        || authorization.boot_sequence == 0
        || !strong_nonce(&authorization.nonce)
    {
        Err(DenialCode::IpcAuthenticationFailed)
    } else {
        Ok(())
    }
}

fn encode_secret_fingerprints(
    encoder: &mut Encoder,
    secrets: &SupervisorSecretsV4,
) -> Result<(), DenialCode> {
    let values = [
        (1, secrets.channel_key_id.as_str(), secrets.channel_key),
        (
            2,
            secrets.epoch_channel_key_id.as_str(),
            secrets.epoch_channel_key,
        ),
        (3, secrets.lease_key_id.as_str(), secrets.lease_key),
        (4, secrets.compiler_key_id.as_str(), secrets.compiler_key),
        (5, secrets.journal_key_id.as_str(), secrets.journal_key),
        (
            6,
            secrets.reconciliation_key_id.as_str(),
            secrets.reconciliation_verification_key,
        ),
    ];
    for (kind, key_id, secret) in values {
        encoder.digest(secret_fingerprint(kind, key_id, secret)?);
    }
    Ok(())
}

fn secret_fingerprint(kind: u8, key_id: &str, secret: [u8; 32]) -> Result<Digest, DenialCode> {
    let mut encoder = Encoder::new(b"FLKF", 1, kind);
    encoder.string(key_id)?;
    encoder.key(secret);
    encoder.finish().map(|bytes| Digest::of(&bytes))
}

fn gateway_challenge_digest(challenge: [u8; 32]) -> Digest {
    const DOMAIN: &[u8] = b"faultloom-gateway-boot-challenge-v1\0";
    let mut bytes = Vec::with_capacity(DOMAIN.len() + challenge.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&challenge);
    Digest::of(&bytes)
}

fn strong_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

#[cfg(test)]
#[path = "boot_binding_tests.rs"]
mod tests;
