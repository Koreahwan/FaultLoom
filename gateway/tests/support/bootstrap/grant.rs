use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use faultloom_gateway::Digest;
use faultloom_gateway::ipc::ActionClass;
use serde_json::{Value, json};

use super::{TestBootstrap, TestTrust};

pub(super) fn signed_grant(bootstrap: &TestBootstrap) -> (Vec<u8>, Digest) {
    let payload = grant_payload(bootstrap);
    let payload_bytes = json_bytes(payload.clone());
    let payload_digest = Digest::of(&payload_bytes);
    let signer = SigningKey::from_bytes(&secret(bootstrap.authority_seed));
    let expires_at = protocol_time(bootstrap.execution_window.ends_at_millis);
    let signed_at = protocol_time(bootstrap.grant_signed_at_millis);
    let digest_text = format!("sha256:{}", payload_digest.to_hex());
    let signing_document = json!({
        "algorithm":"Ed25519", "expires_at":expires_at, "key_id":key_id_for(&signer),
        "payload":payload, "payload_digest":digest_text, "protocol_version":"0.1.0",
        "purpose":"authority_grant", "sequence":bootstrap.grant_version,
        "signed_at":signed_at,
    });
    let signature = signer.sign(&json_bytes(signing_document));
    let envelope = json!({
        "payload":grant_payload(bootstrap), "schema_version":"0.1.0",
        "signature":{
            "algorithm":"Ed25519", "expires_at":expires_at, "key_id":key_id_for(&signer),
            "payload_digest":digest_text, "protocol_version":"0.1.0",
            "purpose":"authority_grant", "schema_version":"0.1.0",
            "sequence":bootstrap.grant_version,
            "signature":base64url(signature.to_bytes().as_slice()), "signed_at":signed_at,
        }
    });
    (json_bytes(envelope), payload_digest)
}

pub(super) fn trust_document(trust: &TestTrust) -> Vec<u8> {
    let keys = |roots: &[super::TestRoot]| {
        roots
            .iter()
            .map(|root| {
                let signer = SigningKey::from_bytes(&secret(root.seed));
                json!({
                    "key_id":key_id_for(&signer),
                    "public_key_base64url":base64url(signer.verifying_key().as_bytes()),
                    "status":if root.active { "active" } else { "revoked" },
                })
            })
            .collect::<Vec<_>>()
    };
    json_bytes(json!({
        "authority_keys":keys(&trust.authority_roots),
        "controller_keys":keys(&trust.controller_roots),
        "generation":trust.generation,
        "grant_pins":[{
            "authority_key_ids":trust.pinned_authority_seeds.iter().map(|seed| key_id(*seed)).collect::<Vec<_>>(),
            "controller_key_ids":trust.pinned_controller_seeds.iter().map(|seed| key_id(*seed)).collect::<Vec<_>>(),
            "grant_id":trust.pinned_grant_id,
            "minimum_version":trust.minimum_grant_version,
        }],
        "schema_version":1,
    }))
}

fn grant_payload(bootstrap: &TestBootstrap) -> Value {
    let target = bootstrap
        .granted_target
        .as_ref()
        .unwrap_or(&bootstrap.target);
    let start = protocol_time(bootstrap.execution_window.starts_at_millis);
    let end = protocol_time(bootstrap.execution_window.ends_at_millis);
    let classes = target
        .allowed_classes
        .iter()
        .map(|class| match class {
            ActionClass::Observe => "observe",
            ActionClass::SafeProbe => "safe_probe",
            ActionClass::StateChange => "state_change",
        })
        .collect::<Vec<_>>();
    json!({
        "action_policy":{"allowed_classes":classes,"allowed_families":[target.action_family.clone()],"allowed_methods":target.methods.clone(),"allowed_path_patterns":target.path_patterns.clone(),"denied":[],"schema_version":"0.1.0"},
        "adapter_ids":[],"approved_by":"operator-owned",
        "budget":{"max_concurrency":bootstrap.budget.max_concurrency,"max_duration_seconds":bootstrap.budget.max_duration_seconds,"max_request_bytes":bootstrap.budget.max_request_bytes,"max_response_bytes":bootstrap.budget.max_response_bytes,"rate_per_minute":bootstrap.budget.rate_per_minute,"schema_version":"0.1.0","total_actions":bootstrap.budget.total_actions},
        "callback_policy":{"maximum_ttl_seconds":60,"owned_domains":[],"schema_version":"0.1.0"},
        "draft_digest":format!("sha256:{}", "aa".repeat(32)),
        "emergency_contact_ref":"contact-owned",
        "execution_windows":[{"ends_at":end,"schema_version":"0.1.0","starts_at":start}],
        "expires_at":end,"grant_id":bootstrap.grant_id,"grant_version":bootstrap.grant_version,
        "identities":[target.identity_id.clone()],"issued_at":protocol_time(bootstrap.grant_issued_at_millis),"issued_to":"researcher-owned","not_before":start,"pack_ids":[target.pack_id.clone()],
        "provider_policy":{"allowed_model_snapshots":[],"allowed_providers":[],"arbitrary_provider_web_tools":false,"data_policy_id":"data-owned","schema_version":"0.1.0"},
        "retention_policy":{"delete_after_seconds":0,"policy_id":"retention-owned","retain_until":end,"schema_version":"0.1.0"},
        "roles":["researcher"],"schema_version":"0.1.0",
        "state_change_policy":{"allowed_families":[target.action_family.clone()],"canary_required":true,"cleanup_plan_required":true,"external_messages_allowed":false,"payment_or_real_asset_change_allowed":false,"schema_version":"0.1.0"},
        "targets":[{"cidrs":[loopback_cidr(target.socket)],"hostnames":[target.hostname.clone()],"methods":target.methods.clone(),"paths":target.path_patterns.clone(),"ports":[target.socket.port()],"protocols":[target.protocol.clone()],"schema_version":"0.1.0","supporting_read_only":false,"target_id":target.target_id}],
        "tenants":target.tenant_id.clone().into_iter().collect::<Vec<_>>(),
    })
}

fn loopback_cidr(socket: std::net::SocketAddr) -> &'static str {
    if socket.is_ipv4() {
        "127.0.0.0/8"
    } else {
        "::1/128"
    }
}

pub(super) fn secret(seed: u8) -> [u8; 32] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

pub(super) fn key_id(seed: u8) -> String {
    key_id_for(&SigningKey::from_bytes(&secret(seed)))
}

fn key_id_for(key: &SigningKey) -> String {
    format!(
        "ed25519:sha256:{}",
        Digest::of(key.verifying_key().as_bytes()).to_hex()
    )
}

fn base64url(raw: &[u8]) -> String {
    let mut encoded = [0_u8; 86];
    let length = URL_SAFE_NO_PAD
        .encode_slice(raw, &mut encoded)
        .expect("base64url fixture buffer");
    std::str::from_utf8(&encoded[..length])
        .expect("base64url ASCII")
        .to_owned()
}

fn json_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("canonical fixture JSON")
}

pub(crate) fn protocol_time(millis: u64) -> String {
    let total_seconds = millis / 1_000;
    let mut days = total_seconds / 86_400;
    let day_seconds = total_seconds % 86_400;
    let mut year = 1970_u64;
    while days >= days_in_year(year) {
        days -= days_in_year(year);
        year += 1;
    }
    let months = [
        31,
        28 + u64::from(leap_year(year)),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1_u64;
    for length in months {
        if days < length {
            break;
        }
        days -= length;
        month += 1;
    }
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let micros = (millis % 1_000) * 1_000;
    format!(
        "{year:04}-{month:02}-{:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z",
        days + 1
    )
}

const fn days_in_year(year: u64) -> u64 {
    if leap_year(year) { 366 } else { 365 }
}
const fn leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
