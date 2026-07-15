use std::net::{Ipv4Addr, SocketAddr};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

use crate::Digest;
use crate::authority::{
    AuthorityVerifier, RequestedSelection, RequestedSelectionParts, authorize_selection,
};
use crate::boot_binding::{BootBindingContext, boot_authorization_signing_bytes};
use crate::installed_trust::{
    InstalledTrustStore, installed_trust_store_from_canonical_bytes_for_test,
};
use crate::supervisor_bootstrap_v4::{
    BootAuthorization, SupervisorSecretsV4, UnverifiedSupervisorBootstrapV4,
};

pub(super) const NOW_MILLIS: u64 = 1_893_553_500_000;

#[derive(Clone, Copy)]
pub(super) struct FixtureOptions {
    pub(super) trust_generation: u64,
    pub(super) authority_seed: u8,
    pub(super) controller_seed: u8,
    pub(super) selection_port: u16,
    pub(super) channel_seed: u8,
    pub(super) epoch_seed: u8,
    pub(super) gateway_seed: u8,
    pub(super) lease_seed: u8,
    pub(super) compiler_seed: u8,
    pub(super) journal_seed: u8,
    pub(super) reconciliation_seed: u8,
    pub(super) journal_anchor_seed: u8,
    pub(super) executable_seed: u8,
    pub(super) boot_sequence: u64,
    pub(super) boot_nonce_seed: u8,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            trust_generation: 7,
            authority_seed: 7,
            controller_seed: 91,
            selection_port: 8080,
            channel_seed: 1,
            epoch_seed: 33,
            gateway_seed: 65,
            lease_seed: 97,
            compiler_seed: 129,
            journal_seed: 161,
            reconciliation_seed: 193,
            journal_anchor_seed: 7,
            executable_seed: 9,
            boot_sequence: 17,
            boot_nonce_seed: 0x52,
        }
    }
}

pub(super) struct Fixture {
    pub(super) trust: InstalledTrustStore,
    pub(super) bootstrap: UnverifiedSupervisorBootstrapV4,
    pub(super) executable_digest: Digest,
    pub(super) now_millis: u64,
}

pub(super) fn fixture(options: FixtureOptions) -> Fixture {
    let authority = SigningKey::from_bytes(&[options.authority_seed; 32]);
    let controller = SigningKey::from_bytes(&[options.controller_seed; 32]);
    let trust = trust_store(options.trust_generation, &authority, &controller);
    let signed_authority_grant = signed_grant(&grant_payload(), &authority);
    let selection = RequestedSelection::from_untrusted_parts(RequestedSelectionParts {
        target_id: "target-alpha".into(),
        hostname: "loopback.test".into(),
        socket: SocketAddr::from((Ipv4Addr::LOCALHOST, options.selection_port)),
        protocol: "http".into(),
        pack_id: "web".into(),
        action_family: "semantic-http".into(),
        identity_id: "identity-alpha".into(),
        tenant_id: Some("tenant-alpha".into()),
    })
    .expect("selection");
    let secrets = secrets(options);
    let executable_digest = Digest::of(&[options.executable_seed; 64]);
    let expected_journal_anchor = Digest::of(&[options.journal_anchor_seed; 32]);
    let verified = AuthorityVerifier::verify(&signed_authority_grant, &trust, NOW_MILLIS, 300_000)
        .expect("verified grant");
    let policy = authorize_selection(&verified, selection.clone()).expect("authorized selection");
    let mut boot_authorization = BootAuthorization {
        controller_key_id: key_id(&controller),
        issued_at_millis: NOW_MILLIS - 1_000,
        expires_at_millis: NOW_MILLIS + 10_000,
        boot_sequence: options.boot_sequence,
        nonce: nonce(options.boot_nonce_seed),
        signature: [1; 64],
    };
    let context = BootBindingContext {
        trust_generation: trust.generation(),
        grant_envelope_digest: policy.signed_grant_digest(),
        grant_payload_digest: policy.authority_payload_digest(),
        grant_id: &policy.scope_policy().grant_id,
        grant_version: policy.scope_policy().grant_version,
        selection: policy.selection(),
        selection_digest: policy.selection().binding_digest(),
        secrets: &secrets,
        expected_journal_anchor,
        executable_digest,
    };
    let message = boot_authorization_signing_bytes(&context, &boot_authorization)
        .expect("boot authorization bytes");
    boot_authorization.signature = controller.sign(&message).to_bytes();
    Fixture {
        trust,
        bootstrap: UnverifiedSupervisorBootstrapV4 {
            signed_authority_grant,
            selection,
            secrets,
            expected_journal_anchor,
            boot_authorization,
        },
        executable_digest,
        now_millis: NOW_MILLIS,
    }
}

fn grant_payload() -> Value {
    json!({
        "action_policy": {"allowed_classes":["observe","safe_probe","state_change"],"allowed_families":["semantic-http"],"allowed_methods":["GET","POST"],"allowed_path_patterns":["/api/*"],"denied":[],"schema_version":"0.1.0"},
        "adapter_ids":[],"approved_by":"operator-alpha",
        "budget":{"max_concurrency":2,"max_duration_seconds":30,"max_request_bytes":4096,"max_response_bytes":8192,"rate_per_minute":8,"schema_version":"0.1.0","total_actions":8},
        "callback_policy":{"maximum_ttl_seconds":60,"owned_domains":[],"schema_version":"0.1.0"},
        "draft_digest":format!("sha256:{}", "aa".repeat(32)),
        "emergency_contact_ref":"contact-alpha",
        "execution_windows":[{"ends_at":"2030-01-02T04:04:05.000000Z","schema_version":"0.1.0","starts_at":"2030-01-02T03:05:00.000000Z"}],
        "expires_at":"2030-01-02T05:04:05.000000Z","grant_id":"grant-alpha","grant_version":3,
        "identities":["identity-alpha"],"issued_at":"2030-01-02T03:04:05.000000Z","issued_to":"researcher-alpha","not_before":"2030-01-02T03:05:00.000000Z","pack_ids":["web"],
        "provider_policy":{"allowed_model_snapshots":["model-alpha"],"allowed_providers":["provider-alpha"],"arbitrary_provider_web_tools":false,"data_policy_id":"data-alpha","schema_version":"0.1.0"},
        "retention_policy":{"delete_after_seconds":0,"policy_id":"retention-alpha","retain_until":"2030-01-02T05:04:05.000000Z","schema_version":"0.1.0"},
        "roles":["researcher"],"schema_version":"0.1.0",
        "state_change_policy":{"allowed_families":["semantic-http"],"canary_required":true,"cleanup_plan_required":true,"external_messages_allowed":false,"payment_or_real_asset_change_allowed":false,"schema_version":"0.1.0"},
        "targets":[{"cidrs":["127.0.0.0/8"],"hostnames":["loopback.test"],"methods":["GET","POST"],"paths":["/api/*"],"ports":[8080,8081],"protocols":["http"],"schema_version":"0.1.0","supporting_read_only":false,"target_id":"target-alpha"}],
        "tenants":["tenant-alpha"]
    })
}

fn signed_grant(payload: &Value, signer: &SigningKey) -> Vec<u8> {
    let payload_bytes = serde_json::to_vec(payload).expect("payload");
    let payload_digest = format!("sha256:{}", Digest::of(&payload_bytes).to_hex());
    let signing_document = json!({"algorithm":"Ed25519","expires_at":payload["expires_at"],"key_id":key_id(signer),"payload":payload,"payload_digest":payload_digest,"protocol_version":"0.1.0","purpose":"authority_grant","sequence":payload["grant_version"],"signed_at":"2030-01-02T03:05:00.000000Z"});
    let signature = signer.sign(&serde_json::to_vec(&signing_document).expect("signing bytes"));
    json_bytes(
        json!({"payload":payload,"schema_version":"0.1.0","signature":{"algorithm":"Ed25519","expires_at":payload["expires_at"],"key_id":key_id(signer),"payload_digest":payload_digest,"protocol_version":"0.1.0","purpose":"authority_grant","schema_version":"0.1.0","sequence":payload["grant_version"],"signature":base64url(signature.to_bytes().as_slice()),"signed_at":"2030-01-02T03:05:00.000000Z"}}),
    )
}

fn trust_store(
    generation: u64,
    authority: &SigningKey,
    controller: &SigningKey,
) -> InstalledTrustStore {
    let raw = json_bytes(
        json!({"authority_keys":[{"key_id":key_id(authority),"public_key_base64url":base64url(authority.verifying_key().as_bytes()),"status":"active"}],"controller_keys":[{"key_id":key_id(controller),"public_key_base64url":base64url(controller.verifying_key().as_bytes()),"status":"active"}],"generation":generation,"grant_pins":[{"authority_key_ids":[key_id(authority)],"controller_key_ids":[key_id(controller)],"grant_id":"grant-alpha","minimum_version":3}],"schema_version":1}),
    );
    installed_trust_store_from_canonical_bytes_for_test(&raw).expect("trust store")
}

fn secrets(options: FixtureOptions) -> SupervisorSecretsV4 {
    SupervisorSecretsV4 {
        channel_key_id: format!("channel-key-{}", options.channel_seed),
        channel_key: secret(options.channel_seed),
        channel_boot_id: format!("channel-boot-{}", options.channel_seed),
        channel_nonce: nonce(options.channel_seed),
        channel_issued_at_millis: NOW_MILLIS - 2_000,
        channel_expires_at_millis: NOW_MILLIS + 30_000,
        epoch_channel_key_id: format!("epoch-key-{}", options.epoch_seed),
        epoch_channel_key: secret(options.epoch_seed),
        gateway_boot_id: format!("gateway-boot-{}", options.gateway_seed),
        gateway_challenge: secret(options.gateway_seed),
        lease_key_id: "lease-key".into(),
        lease_key: secret(options.lease_seed),
        compiler_key_id: "compiler-key".into(),
        compiler_key: secret(options.compiler_seed),
        journal_key_id: "journal-key".into(),
        journal_key: secret(options.journal_seed),
        reconciliation_key_id: "reconciliation-key".into(),
        reconciliation_verification_key: secret(options.reconciliation_seed),
    }
}

fn secret(seed: u8) -> [u8; 32] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

fn nonce(seed: u8) -> [u8; 16] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

fn key_id(key: &SigningKey) -> String {
    format!(
        "ed25519:sha256:{}",
        Digest::of(key.verifying_key().as_bytes()).to_hex()
    )
}

fn base64url(raw: &[u8]) -> String {
    let mut encoded = [0_u8; 86];
    let length = URL_SAFE_NO_PAD
        .encode_slice(raw, &mut encoded)
        .expect("base64url buffer");
    std::str::from_utf8(&encoded[..length])
        .expect("base64url ASCII")
        .to_owned()
}

fn json_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("canonical JSON")
}
