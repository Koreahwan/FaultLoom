use std::net::{Ipv4Addr, SocketAddr};

use ed25519_dalek::{Signer, SigningKey};

use crate::Digest;
use crate::authority::{RequestedSelection, RequestedSelectionParts};

use super::super::{
    BootAuthorization, BootBindingContext, SupervisorSecretsV4, boot_authorization_signing_bytes,
};

#[derive(Clone)]
pub(super) struct Fixture {
    pub(super) trust_generation: u64,
    pub(super) grant_envelope_digest: Digest,
    pub(super) grant_payload_digest: Digest,
    pub(super) grant_id: String,
    pub(super) grant_version: u64,
    pub(super) selection: RequestedSelection,
    pub(super) selection_digest: Digest,
    pub(super) secrets: SupervisorSecretsV4,
    pub(super) journal_anchor: Digest,
    pub(super) executable_digest: Digest,
    pub(super) authorization: BootAuthorization,
}

impl Fixture {
    pub(super) fn context(&self) -> BootBindingContext<'_> {
        BootBindingContext {
            trust_generation: self.trust_generation,
            grant_envelope_digest: self.grant_envelope_digest,
            grant_payload_digest: self.grant_payload_digest,
            grant_id: &self.grant_id,
            grant_version: self.grant_version,
            selection: &self.selection,
            selection_digest: self.selection_digest,
            secrets: &self.secrets,
            expected_journal_anchor: self.journal_anchor,
            executable_digest: self.executable_digest,
        }
    }
}

fn secret(seed: u8) -> [u8; 32] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

pub(super) fn nonce(seed: u8) -> [u8; 16] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

pub(super) fn fixture() -> Fixture {
    let selection = RequestedSelection::from_untrusted_parts(RequestedSelectionParts {
        target_id: "loopback-lab".into(),
        hostname: "localhost".into(),
        socket: SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
        protocol: "http".into(),
        pack_id: "web".into(),
        action_family: "semantic-http".into(),
        identity_id: "operator-owned".into(),
        tenant_id: Some("tenant-a".into()),
    })
    .unwrap();
    let selection_digest = selection.binding_digest();
    Fixture {
        trust_generation: 4,
        grant_envelope_digest: Digest::of(b"signed-envelope"),
        grant_payload_digest: Digest::of(b"grant-payload"),
        grant_id: "grant-a".into(),
        grant_version: 9,
        selection,
        selection_digest,
        secrets: SupervisorSecretsV4 {
            channel_key_id: "channel-key".into(),
            channel_key: secret(1),
            channel_boot_id: "channel-boot".into(),
            channel_nonce: nonce(0x21),
            channel_issued_at_millis: 1_000,
            channel_expires_at_millis: 31_000,
            epoch_channel_key_id: "epoch-key".into(),
            epoch_channel_key: secret(33),
            gateway_boot_id: "gateway-boot".into(),
            gateway_challenge: secret(65),
            lease_key_id: "lease-key".into(),
            lease_key: secret(97),
            compiler_key_id: "compiler-key".into(),
            compiler_key: secret(129),
            journal_key_id: "journal-key".into(),
            journal_key: secret(161),
            reconciliation_key_id: "reconciliation-key".into(),
            reconciliation_verification_key: secret(193),
        },
        journal_anchor: Digest::of(b"journal-anchor"),
        executable_digest: Digest::of(b"installed-executable"),
        authorization: BootAuthorization {
            controller_key_id: format!("ed25519:sha256:{}", "11".repeat(32)),
            issued_at_millis: 2_000,
            expires_at_millis: 32_000,
            boot_sequence: 7,
            nonce: nonce(0x52),
            signature: [0; 64],
        },
    }
}

pub(super) fn signed_fixture() -> (Fixture, SigningKey) {
    let mut fixture = fixture();
    let signing_key = SigningKey::from_bytes(&[0x44; 32]);
    fixture.authorization.controller_key_id = key_id(&signing_key);
    let message =
        boot_authorization_signing_bytes(&fixture.context(), &fixture.authorization).unwrap();
    fixture.authorization.signature = signing_key.sign(&message).to_bytes();
    (fixture, signing_key)
}

pub(super) fn key_id(key: &SigningKey) -> String {
    format!(
        "ed25519:sha256:{}",
        Digest::of(key.verifying_key().as_bytes()).to_hex()
    )
}

pub(super) fn signature_accepts(fixture: &Fixture, signing_key: &SigningKey) -> bool {
    let Ok(message) = boot_authorization_signing_bytes(&fixture.context(), &fixture.authorization)
    else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&fixture.authorization.signature);
    signing_key
        .verifying_key()
        .verify_strict(&message, &signature)
        .is_ok()
}
