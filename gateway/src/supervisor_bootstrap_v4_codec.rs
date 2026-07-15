use crate::authority::{RequestedSelection, RequestedSelectionParts};
use crate::ipc::DenialCode;

use super::boot_binding::MAX_BOOT_AUTHORIZATION_TTL_MILLIS;
use super::supervisor_bootstrap_v4::{
    BootAuthorization, MAX_SIGNED_AUTHORITY_GRANT_BYTES, SupervisorSecretsV4,
    UnverifiedSupervisorBootstrapV4,
};
use super::supervisor_wire::{Decoder, Encoder};

const MAGIC: &[u8; 4] = b"FLBS";
const VERSION: u8 = 4;
const BOOTSTRAP: u8 = 1;

pub(super) fn encode(bootstrap: &UnverifiedSupervisorBootstrapV4) -> Result<Vec<u8>, DenialCode> {
    validate_bootstrap(bootstrap, DenialCode::InvalidRequest)?;
    let mut encoder = Encoder::new(MAGIC, VERSION, BOOTSTRAP);
    encoder.bytes(&bootstrap.signed_authority_grant)?;
    encode_selection(&mut encoder, &bootstrap.selection)?;
    encode_secrets(&mut encoder, &bootstrap.secrets)?;
    encoder.digest(bootstrap.expected_journal_anchor);
    encode_authorization(&mut encoder, &bootstrap.boot_authorization)?;
    encoder.finish()
}

pub(super) fn decode(encoded: &[u8]) -> Result<UnverifiedSupervisorBootstrapV4, DenialCode> {
    let mut decoder = Decoder::new(encoded, MAGIC, VERSION)?;
    if decoder.byte()? != BOOTSTRAP {
        return Err(DenialCode::MalformedFrame);
    }
    let signed_authority_grant = decoder.bytes(MAX_SIGNED_AUTHORITY_GRANT_BYTES)?;
    let selection = decode_selection(&mut decoder)?;
    let secrets = decode_secrets(&mut decoder)?;
    let expected_journal_anchor = decoder.digest()?;
    let boot_authorization = decode_authorization(&mut decoder)?;
    decoder.finish()?;
    let bootstrap = UnverifiedSupervisorBootstrapV4 {
        signed_authority_grant,
        selection,
        secrets,
        expected_journal_anchor,
        boot_authorization,
    };
    validate_bootstrap(&bootstrap, DenialCode::MalformedFrame)?;
    if encode(&bootstrap)?.as_slice() != encoded {
        return Err(DenialCode::MalformedFrame);
    }
    Ok(bootstrap)
}

fn validate_bootstrap(
    bootstrap: &UnverifiedSupervisorBootstrapV4,
    denial: DenialCode,
) -> Result<(), DenialCode> {
    if bootstrap.signed_authority_grant.is_empty()
        || bootstrap.signed_authority_grant.len() > MAX_SIGNED_AUTHORITY_GRANT_BYTES
        || bootstrap.secrets.validate_separation().is_err()
        || !valid_authorization_shape(&bootstrap.boot_authorization)
    {
        Err(denial)
    } else {
        Ok(())
    }
}

fn encode_selection(
    encoder: &mut Encoder,
    selection: &RequestedSelection,
) -> Result<(), DenialCode> {
    encoder.string(selection.target_id())?;
    encoder.string(selection.hostname())?;
    encoder.socket(selection.socket());
    encoder.string(selection.protocol())?;
    encoder.string(selection.pack_id())?;
    encoder.string(selection.action_family())?;
    encoder.string(selection.identity_id())?;
    encoder.optional_string(selection.tenant_id())
}

fn decode_selection(decoder: &mut Decoder<'_>) -> Result<RequestedSelection, DenialCode> {
    RequestedSelection::from_untrusted_parts(RequestedSelectionParts {
        target_id: decoder.string()?,
        hostname: decoder.string()?,
        socket: decoder.socket()?,
        protocol: decoder.string()?,
        pack_id: decoder.string()?,
        action_family: decoder.string()?,
        identity_id: decoder.string()?,
        tenant_id: decoder.optional_string()?,
    })
    .map_err(|_| DenialCode::MalformedFrame)
}

fn encode_secrets(encoder: &mut Encoder, secrets: &SupervisorSecretsV4) -> Result<(), DenialCode> {
    encoder.string(&secrets.channel_key_id)?;
    encoder.key(secrets.channel_key);
    encoder.string(&secrets.channel_boot_id)?;
    encoder.nonce(secrets.channel_nonce);
    encoder.u64(secrets.channel_issued_at_millis);
    encoder.u64(secrets.channel_expires_at_millis);
    encoder.string(&secrets.epoch_channel_key_id)?;
    encoder.key(secrets.epoch_channel_key);
    encoder.string(&secrets.gateway_boot_id)?;
    encoder.key(secrets.gateway_challenge);
    encoder.string(&secrets.lease_key_id)?;
    encoder.key(secrets.lease_key);
    encoder.string(&secrets.compiler_key_id)?;
    encoder.key(secrets.compiler_key);
    encoder.string(&secrets.journal_key_id)?;
    encoder.key(secrets.journal_key);
    encoder.string(&secrets.reconciliation_key_id)?;
    encoder.key(secrets.reconciliation_verification_key);
    Ok(())
}

fn decode_secrets(decoder: &mut Decoder<'_>) -> Result<SupervisorSecretsV4, DenialCode> {
    Ok(SupervisorSecretsV4 {
        channel_key_id: decoder.string()?,
        channel_key: decoder.key()?,
        channel_boot_id: decoder.string()?,
        channel_nonce: decoder.nonce()?,
        channel_issued_at_millis: decoder.u64()?,
        channel_expires_at_millis: decoder.u64()?,
        epoch_channel_key_id: decoder.string()?,
        epoch_channel_key: decoder.key()?,
        gateway_boot_id: decoder.string()?,
        gateway_challenge: decoder.key()?,
        lease_key_id: decoder.string()?,
        lease_key: decoder.key()?,
        compiler_key_id: decoder.string()?,
        compiler_key: decoder.key()?,
        journal_key_id: decoder.string()?,
        journal_key: decoder.key()?,
        reconciliation_key_id: decoder.string()?,
        reconciliation_verification_key: decoder.key()?,
    })
}

fn encode_authorization(
    encoder: &mut Encoder,
    authorization: &BootAuthorization,
) -> Result<(), DenialCode> {
    encoder.string(&authorization.controller_key_id)?;
    encoder.u64(authorization.issued_at_millis);
    encoder.u64(authorization.expires_at_millis);
    encoder.u64(authorization.boot_sequence);
    encoder.nonce(authorization.nonce);
    encoder.bytes(&authorization.signature)
}

fn decode_authorization(decoder: &mut Decoder<'_>) -> Result<BootAuthorization, DenialCode> {
    let controller_key_id = decoder.string()?;
    let issued_at_millis = decoder.u64()?;
    let expires_at_millis = decoder.u64()?;
    let boot_sequence = decoder.u64()?;
    let nonce = decoder.nonce()?;
    let signature = decoder
        .bytes(64)?
        .try_into()
        .map_err(|_| DenialCode::MalformedFrame)?;
    Ok(BootAuthorization {
        controller_key_id,
        issued_at_millis,
        expires_at_millis,
        boot_sequence,
        nonce,
        signature,
    })
}

fn valid_authorization_shape(authorization: &BootAuthorization) -> bool {
    authorization
        .controller_key_id
        .strip_prefix("ed25519:sha256:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        && authorization.issued_at_millis > 0
        && authorization.issued_at_millis < authorization.expires_at_millis
        && authorization
            .expires_at_millis
            .saturating_sub(authorization.issued_at_millis)
            <= MAX_BOOT_AUTHORIZATION_TTL_MILLIS
        && authorization.boot_sequence > 0
        && strong_nonce(&authorization.nonce)
        && authorization.signature.iter().any(|byte| *byte != 0)
}

fn strong_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}
