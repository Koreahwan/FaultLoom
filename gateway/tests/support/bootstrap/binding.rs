use ed25519_dalek::{Signer, SigningKey};
use faultloom_gateway::Digest;
use faultloom_gateway::ipc::DenialCode;

use super::grant::{key_id, secret, signed_grant};
use super::wire::Wire;
use super::{TestBootstrap, TestSecrets, TestTarget};

pub(super) fn encode_bootstrap(
    bootstrap: &TestBootstrap,
    executable_digest: Digest,
) -> Result<Vec<u8>, DenialCode> {
    let (signed_grant, grant_payload_digest) = signed_grant(bootstrap);
    let mut wire = Wire::new(b"FLBS", 4, 1);
    wire.bytes(&signed_grant)?;
    encode_selection(&mut wire, &bootstrap.target)?;
    encode_secrets(&mut wire, &bootstrap.secrets)?;
    wire.digest(bootstrap.expected_journal_anchor);
    let controller_key_id = key_id(bootstrap.boot.controller_seed);
    let signing_bytes = boot_signing_bytes(
        bootstrap,
        Digest::of(&signed_grant),
        grant_payload_digest,
        bootstrap
            .boot
            .signed_executable_digest
            .unwrap_or(executable_digest),
        bootstrap
            .boot
            .signed_anchor
            .unwrap_or(bootstrap.expected_journal_anchor),
        &controller_key_id,
    )?;
    let signer = SigningKey::from_bytes(&secret(bootstrap.boot.signing_seed));
    let signature = signer.sign(&signing_bytes).to_bytes();
    wire.string(&controller_key_id)?;
    wire.u64(bootstrap.boot.issued_at_millis);
    wire.u64(bootstrap.boot.expires_at_millis);
    wire.u64(bootstrap.boot.sequence);
    wire.nonce(bootstrap.boot.nonce);
    wire.bytes(&signature)?;
    wire.finish()
}

pub(super) fn durability_binding(bootstrap: &TestBootstrap) -> Result<Digest, DenialCode> {
    let (_, payload_digest) = signed_grant(bootstrap);
    let mut wire = Wire::new(b"FLDB", 4, 1);
    wire.string(&key_id(bootstrap.authority_seed))?;
    wire.digest(payload_digest);
    wire.string(&bootstrap.grant_id)?;
    wire.u64(bootstrap.grant_version);
    wire.digest(selection_digest(&bootstrap.target));
    for (kind, key_id, key) in stable_keys(&bootstrap.secrets) {
        wire.byte(kind);
        wire.string(key_id)?;
        wire.key(key);
    }
    wire.finish().map(|bytes| Digest::of(&bytes))
}

fn boot_signing_bytes(
    bootstrap: &TestBootstrap,
    grant_envelope_digest: Digest,
    grant_payload_digest: Digest,
    executable_digest: Digest,
    expected_anchor: Digest,
    controller_key_id: &str,
) -> Result<Vec<u8>, DenialCode> {
    let mut wire = Wire::new(b"FLBA", 1, 1);
    wire.u64(bootstrap.trust.generation);
    wire.digest(grant_envelope_digest);
    wire.digest(grant_payload_digest);
    wire.string(&bootstrap.grant_id)?;
    wire.u64(bootstrap.grant_version);
    wire.digest(selection_digest(&bootstrap.target));
    for (kind, key_id, key) in all_keys(&bootstrap.secrets) {
        let mut fingerprint = Wire::new(b"FLKF", 1, kind);
        fingerprint.string(key_id)?;
        fingerprint.key(key);
        wire.digest(Digest::of(&fingerprint.finish()?));
    }
    wire.digest(bootstrap.channel_challenge()?.challenge_id());
    wire.string(&bootstrap.secrets.gateway_boot_id)?;
    wire.digest(gateway_challenge_digest(
        bootstrap.secrets.gateway_challenge,
    ));
    wire.digest(expected_anchor);
    wire.digest(executable_digest);
    wire.string(controller_key_id)?;
    wire.u64(bootstrap.boot.issued_at_millis);
    wire.u64(bootstrap.boot.expires_at_millis);
    wire.u64(bootstrap.boot.sequence);
    wire.nonce(bootstrap.boot.nonce);
    wire.finish()
}

fn encode_selection(wire: &mut Wire, target: &TestTarget) -> Result<(), DenialCode> {
    for value in [&target.target_id, &target.hostname] {
        wire.string(value)?;
    }
    wire.socket(target.socket);
    for value in [
        &target.protocol,
        &target.pack_id,
        &target.action_family,
        &target.identity_id,
    ] {
        wire.string(value)?;
    }
    wire.optional_string(target.tenant_id.as_deref())
}

fn encode_secrets(wire: &mut Wire, secrets: &TestSecrets) -> Result<(), DenialCode> {
    wire.string(&secrets.channel_key_id)?;
    wire.key(secrets.channel_key);
    wire.string(&secrets.channel_boot_id)?;
    wire.nonce(secrets.channel_nonce);
    wire.u64(secrets.channel_issued_at_millis);
    wire.u64(secrets.channel_expires_at_millis);
    wire.string(&secrets.epoch_channel_key_id)?;
    wire.key(secrets.epoch_channel_key);
    wire.string(&secrets.gateway_boot_id)?;
    wire.key(secrets.gateway_challenge);
    for (_, key_id, key) in stable_keys(secrets) {
        wire.string(key_id)?;
        wire.key(key);
    }
    Ok(())
}

fn selection_digest(target: &TestTarget) -> Digest {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(b"faultloom-requested-selection-v1\0");
    push_u64_string(&mut bytes, &target.target_id);
    push_u64_string(&mut bytes, &target.hostname);
    match target.socket.ip() {
        std::net::IpAddr::V4(address) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.octets());
        }
    }
    bytes.extend_from_slice(&target.socket.port().to_be_bytes());
    for value in [
        &target.protocol,
        &target.pack_id,
        &target.action_family,
        &target.identity_id,
    ] {
        push_u64_string(&mut bytes, value);
    }
    bytes.push(u8::from(target.tenant_id.is_some()));
    if let Some(tenant) = &target.tenant_id {
        push_u64_string(&mut bytes, tenant);
    }
    Digest::of(&bytes)
}

fn push_u64_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn gateway_challenge_digest(challenge: [u8; 32]) -> Digest {
    let mut bytes = Vec::with_capacity(68);
    bytes.extend_from_slice(b"faultloom-gateway-boot-challenge-v1\0");
    bytes.extend_from_slice(&challenge);
    Digest::of(&bytes)
}

fn all_keys(secrets: &TestSecrets) -> [(u8, &str, [u8; 32]); 6] {
    [
        (1, &secrets.channel_key_id, secrets.channel_key),
        (2, &secrets.epoch_channel_key_id, secrets.epoch_channel_key),
        (3, &secrets.lease_key_id, secrets.lease_key),
        (4, &secrets.compiler_key_id, secrets.compiler_key),
        (5, &secrets.journal_key_id, secrets.journal_key),
        (
            6,
            &secrets.reconciliation_key_id,
            secrets.reconciliation_verification_key,
        ),
    ]
}

fn stable_keys(secrets: &TestSecrets) -> [(u8, &str, [u8; 32]); 4] {
    [
        (1, &secrets.lease_key_id, secrets.lease_key),
        (2, &secrets.compiler_key_id, secrets.compiler_key),
        (3, &secrets.journal_key_id, secrets.journal_key),
        (
            4,
            &secrets.reconciliation_key_id,
            secrets.reconciliation_verification_key,
        ),
    ]
}
