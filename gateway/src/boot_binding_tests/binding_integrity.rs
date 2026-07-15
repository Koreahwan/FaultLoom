use std::net::{Ipv4Addr, SocketAddr};

use ed25519_dalek::{Signer, SigningKey};

use crate::Digest;
use crate::authority::{RequestedSelection, RequestedSelectionParts};

use super::super::boot_authorization_signing_bytes;
use super::support::{fixture, key_id, signature_accepts, signed_fixture};

#[test]
fn signed_fresh_journal_zero_anchor_is_valid_but_cannot_be_changed() {
    // Given: a first-start ZERO anchor signed with every other binding held fixed.
    let signing_key = SigningKey::from_bytes(&[0x44; 32]);
    let mut fresh = fixture();
    fresh.journal_anchor = Digest::ZERO;
    fresh.authorization.controller_key_id = key_id(&signing_key);
    let message = boot_authorization_signing_bytes(&fresh.context(), &fresh.authorization).unwrap();
    fresh.authorization.signature = signing_key.sign(&message).to_bytes();

    // When: the exact fresh state and a forged nonzero replacement are checked.
    let exact_is_valid = signature_accepts(&fresh, &signing_key);
    let mut changed = fresh.clone();
    changed.journal_anchor = Digest::of(b"invented-existing-journal");

    // Then: ZERO is valid data in the binding, not an unsigned wildcard.
    assert!(exact_is_valid);
    assert!(!signature_accepts(&changed, &signing_key));
}

#[test]
fn binding_rejects_tampering_across_every_authority_and_runtime_dimension() {
    // Given: one valid controller authorization.
    let (fixture, signing_key) = signed_fixture();
    let mut tampered = Vec::new();

    // When: every independently security-relevant dimension is changed.
    let mut changed = fixture.clone();
    changed.trust_generation += 1;
    tampered.push(("trust generation", changed));
    let mut changed = fixture.clone();
    changed.grant_envelope_digest = Digest::of(b"other-envelope");
    tampered.push(("grant envelope", changed));
    let mut changed = fixture.clone();
    changed.grant_payload_digest = Digest::of(b"other-payload");
    tampered.push(("grant payload", changed));
    let mut changed = fixture.clone();
    changed.grant_id.push('x');
    tampered.push(("grant id", changed));
    let mut changed = fixture.clone();
    changed.grant_version += 1;
    tampered.push(("grant version", changed));
    let mut changed = fixture.clone();
    changed.selection_digest = Digest::of(b"other-selection");
    tampered.push(("selection digest", changed));
    let mut changed = fixture.clone();
    changed.selection = RequestedSelection::from_untrusted_parts(RequestedSelectionParts {
        target_id: "other-loopback-lab".into(),
        hostname: "localhost".into(),
        socket: SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
        protocol: "http".into(),
        pack_id: "web".into(),
        action_family: "semantic-http".into(),
        identity_id: "operator-owned".into(),
        tenant_id: Some("tenant-a".into()),
    })
    .unwrap();
    changed.selection_digest = changed.selection.binding_digest();
    tampered.push(("selection", changed));
    let mut changed = fixture.clone();
    changed.secrets.channel_key_id.push('x');
    tampered.push(("channel key id", changed));
    let mut changed = fixture.clone();
    changed.secrets.channel_key[0] ^= 1;
    tampered.push(("channel key", changed));
    let mut changed = fixture.clone();
    changed.secrets.channel_boot_id.push('x');
    tampered.push(("channel boot", changed));
    let mut changed = fixture.clone();
    changed.secrets.epoch_channel_key[0] ^= 1;
    tampered.push(("epoch receipt key", changed));
    let mut changed = fixture.clone();
    changed.secrets.epoch_channel_key_id.push('x');
    tampered.push(("epoch receipt key id", changed));
    let mut changed = fixture.clone();
    changed.secrets.lease_key[0] ^= 1;
    tampered.push(("lease key", changed));
    let mut changed = fixture.clone();
    changed.secrets.lease_key_id.push('x');
    tampered.push(("lease key id", changed));
    let mut changed = fixture.clone();
    changed.secrets.compiler_key[0] ^= 1;
    tampered.push(("compiler key", changed));
    let mut changed = fixture.clone();
    changed.secrets.compiler_key_id.push('x');
    tampered.push(("compiler key id", changed));
    let mut changed = fixture.clone();
    changed.secrets.journal_key[0] ^= 1;
    tampered.push(("journal key", changed));
    let mut changed = fixture.clone();
    changed.secrets.journal_key_id.push('x');
    tampered.push(("journal key id", changed));
    let mut changed = fixture.clone();
    changed.secrets.reconciliation_verification_key[0] ^= 1;
    tampered.push(("reconciliation key", changed));
    let mut changed = fixture.clone();
    changed.secrets.reconciliation_key_id.push('x');
    tampered.push(("reconciliation key id", changed));
    let mut changed = fixture.clone();
    changed.secrets.channel_nonce[0] ^= 1;
    tampered.push(("channel challenge nonce", changed));
    let mut changed = fixture.clone();
    changed.secrets.channel_issued_at_millis += 1;
    tampered.push(("channel challenge issued time", changed));
    let mut changed = fixture.clone();
    changed.secrets.channel_expires_at_millis -= 1;
    tampered.push(("channel challenge expiry time", changed));
    let mut changed = fixture.clone();
    changed.secrets.gateway_boot_id.push('x');
    tampered.push(("gateway boot", changed));
    let mut changed = fixture.clone();
    changed.secrets.gateway_challenge[0] ^= 1;
    tampered.push(("gateway challenge", changed));
    let mut changed = fixture.clone();
    changed.journal_anchor = Digest::of(b"other-anchor");
    tampered.push(("journal anchor", changed));
    let mut changed = fixture.clone();
    changed.executable_digest = Digest::of(b"other-executable");
    tampered.push(("executable", changed));
    let mut changed = fixture.clone();
    changed.authorization.issued_at_millis += 1;
    tampered.push(("issued time", changed));
    let mut changed = fixture.clone();
    changed.authorization.expires_at_millis -= 1;
    tampered.push(("expiry time", changed));
    let mut changed = fixture.clone();
    changed.authorization.boot_sequence += 1;
    tampered.push(("boot sequence", changed));
    let mut changed = fixture.clone();
    changed.authorization.nonce[0] ^= 1;
    tampered.push(("boot nonce", changed));
    let mut changed = fixture.clone();
    changed.authorization.controller_key_id = format!("ed25519:sha256:{}", "22".repeat(32));
    tampered.push(("controller key", changed));

    // Then: no unchanged signature authorizes any tampered context.
    for (dimension, changed) in tampered {
        assert!(
            !signature_accepts(&changed, &signing_key),
            "signature accepted tampered {dimension}"
        );
    }
}
