use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use faultloom_gateway::Digest;
use faultloom_gateway::ipc::ActionClass;
use faultloom_gateway::lease::GrantBudget;
use faultloom_gateway::scope::TimeWindow;

use crate::bootstrap_fixture::{
    TestBootAuthorization, TestBootstrap, TestRoot, TestSecrets, TestTarget, TestTrust, test_key,
};

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis()
        .try_into()
        .expect("millisecond clock")
}

pub fn nonce(seed: u8) -> [u8; 16] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

pub fn bootstrap(target: SocketAddr, now: u64) -> TestBootstrap {
    const AUTHORITY_SEED: u8 = 0;
    const CONTROLLER_SEED: u8 = 0x60;
    let grant_id = "grant:supervisor-test".to_owned();
    TestBootstrap {
        secrets: TestSecrets {
            channel_key_id: "channel-key:supervisor-test".to_owned(),
            channel_key: test_key(0x10),
            channel_boot_id: "channel-boot:supervisor-test".to_owned(),
            channel_nonce: nonce(0x20),
            channel_issued_at_millis: now.saturating_sub(1_000),
            channel_expires_at_millis: now + 120_000,
            epoch_channel_key_id: "epoch-key:supervisor-test".to_owned(),
            epoch_channel_key: test_key(0x40),
            gateway_boot_id: "gateway-boot:supervisor-test".to_owned(),
            gateway_challenge: test_key(0x70),
            lease_key_id: "lease-key:supervisor-test".to_owned(),
            lease_key: test_key(0xa0),
            compiler_key_id: "compiler-key:supervisor-test".to_owned(),
            compiler_key: test_key(0xd0),
            journal_key_id: "journal-key:supervisor-test".to_owned(),
            journal_key: test_key(0xf0),
            reconciliation_key_id: "reconciliation-key:supervisor-test".to_owned(),
            reconciliation_verification_key: test_key(0x90),
        },
        grant_id: grant_id.clone(),
        grant_version: 1,
        grant_issued_at_millis: now.saturating_sub(6_000),
        grant_signed_at_millis: now.saturating_sub(1_000),
        authority_seed: AUTHORITY_SEED,
        granted_target: None,
        target: TestTarget {
            target_id: "target:owned-loopback".to_owned(),
            hostname: "127.0.0.1".to_owned(),
            socket: target,
            protocol: "http".to_owned(),
            pack_id: "web".to_owned(),
            action_family: "http.semantic".to_owned(),
            identity_id: "identity:operator".to_owned(),
            tenant_id: Some("tenant:owned".to_owned()),
            methods: vec!["POST".to_owned()],
            path_patterns: vec!["/probe".to_owned()],
            allowed_classes: vec![ActionClass::Observe, ActionClass::SafeProbe],
        },
        budget: GrantBudget {
            total_actions: 16,
            rate_per_minute: 16,
            max_concurrency: 4,
            max_request_bytes: 65_536,
            max_response_bytes: 65_536,
            max_duration_seconds: 30,
        },
        execution_window: TimeWindow {
            starts_at_millis: now.saturating_sub(5_000),
            ends_at_millis: now + 120_000,
        },
        expected_journal_anchor: Digest::ZERO,
        trust: TestTrust {
            generation: 7,
            authority_roots: vec![TestRoot {
                seed: AUTHORITY_SEED,
                active: true,
            }],
            controller_roots: vec![TestRoot {
                seed: CONTROLLER_SEED,
                active: true,
            }],
            pinned_grant_id: grant_id,
            minimum_grant_version: 1,
            pinned_authority_seeds: vec![AUTHORITY_SEED],
            pinned_controller_seeds: vec![CONTROLLER_SEED],
        },
        boot: TestBootAuthorization {
            controller_seed: CONTROLLER_SEED,
            signing_seed: CONTROLLER_SEED,
            issued_at_millis: now.saturating_sub(1_000),
            expires_at_millis: now + 20_000,
            sequence: 1,
            nonce: nonce(0x55),
            signed_executable_digest: None,
            signed_anchor: None,
        },
    }
}
