use std::net::{SocketAddr, TcpListener};

use faultloom_gateway::Digest;

use crate::bootstrap_fixture::{TestBootstrap, TestRoot};
use crate::process::{LaunchOptions, bootstrap, now_millis};
use crate::startup_support::assert_denied_before_journal;

#[test]
fn unknown_revoked_and_unpinned_authorities_fail_before_journal_or_egress() {
    for scenario in ["unknown", "revoked", "unpinned"] {
        let listener = owned_listener();
        let mut fixture = fixture(&listener);
        match scenario {
            "unknown" => fixture.authority_seed = 1,
            "revoked" => fixture.trust.authority_roots[0].active = false,
            "unpinned" => {
                fixture.trust.authority_roots.push(TestRoot {
                    seed: 1,
                    active: true,
                });
                fixture.trust.pinned_authority_seeds = vec![1];
            }
            _ => unreachable!(),
        }
        assert_denied_before_journal(&listener, &fixture, LaunchOptions::default());
    }
}

#[test]
fn unknown_revoked_and_unpinned_controllers_fail_before_journal_or_egress() {
    for scenario in ["unknown", "revoked", "unpinned"] {
        let listener = owned_listener();
        let mut fixture = fixture(&listener);
        match scenario {
            "unknown" => {
                fixture.boot.controller_seed = 0x61;
                fixture.boot.signing_seed = 0x61;
            }
            "revoked" => fixture.trust.controller_roots[0].active = false,
            "unpinned" => {
                fixture.trust.controller_roots.push(TestRoot {
                    seed: 0x61,
                    active: true,
                });
                fixture.trust.pinned_controller_seeds = vec![0x61];
            }
            _ => unreachable!(),
        }
        assert_denied_before_journal(&listener, &fixture, LaunchOptions::default());
    }
}

#[test]
fn not_yet_valid_expired_and_rollback_grants_fail_before_journal_or_egress() {
    for scenario in ["not-yet-valid", "expired", "rollback"] {
        let listener = owned_listener();
        let now = now_millis();
        let mut fixture = bootstrap(listener.local_addr().expect("listener address"), now);
        match scenario {
            "not-yet-valid" => {
                fixture.grant_issued_at_millis = now.saturating_sub(1_000);
                fixture.grant_signed_at_millis = now;
                fixture.execution_window.starts_at_millis = now + 400_000;
                fixture.execution_window.ends_at_millis = now + 520_000;
            }
            "expired" => {
                fixture.grant_issued_at_millis = now.saturating_sub(80_000);
                fixture.grant_signed_at_millis = now.saturating_sub(70_000);
                fixture.execution_window.starts_at_millis = now.saturating_sub(60_000);
                fixture.execution_window.ends_at_millis = now.saturating_sub(1_000);
            }
            "rollback" => fixture.trust.minimum_grant_version = 2,
            _ => unreachable!(),
        }
        assert_denied_before_journal(&listener, &fixture, LaunchOptions::default());
    }
}

#[test]
fn every_widened_selection_dimension_fails_before_journal_or_egress() {
    for dimension in [
        "target", "hostname", "socket", "protocol", "pack", "family", "identity", "tenant",
    ] {
        let listener = owned_listener();
        let mut fixture = fixture(&listener);
        fixture.granted_target = Some(fixture.target.clone());
        widen(&mut fixture, dimension);
        assert_denied_before_journal(&listener, &fixture, LaunchOptions::default());
    }
}

#[test]
fn unsupported_protocol_and_oversized_response_capacity_fail_before_journal_or_egress() {
    for scenario in ["protocol", "capacity"] {
        let listener = owned_listener();
        let mut fixture = fixture(&listener);
        match scenario {
            "protocol" => fixture.target.protocol = "https".to_owned(),
            "capacity" => fixture.budget.total_actions = 65,
            _ => unreachable!(),
        }
        assert_denied_before_journal(&listener, &fixture, LaunchOptions::default());
    }
}

#[test]
fn bad_boot_signature_anchor_and_executable_binding_fail_before_journal_or_egress() {
    for scenario in ["signature", "anchor", "executable"] {
        let listener = owned_listener();
        let mut fixture = fixture(&listener);
        match scenario {
            "signature" => fixture.boot.signing_seed = 0x61,
            "anchor" => fixture.boot.signed_anchor = Some(Digest::of(b"wrong boot anchor")),
            "executable" => {
                fixture.boot.signed_executable_digest = Some(Digest::of(b"wrong executable"));
            }
            _ => unreachable!(),
        }
        assert_denied_before_journal(&listener, &fixture, LaunchOptions::default());
    }
}

fn widen(fixture: &mut TestBootstrap, dimension: &str) {
    match dimension {
        "target" => fixture.target.target_id = "target:other".to_owned(),
        "hostname" => fixture.target.hostname = "localhost".to_owned(),
        "socket" => {
            let port = fixture.target.socket.port().checked_add(1).unwrap_or(1);
            fixture.target.socket = SocketAddr::from(([127, 0, 0, 1], port));
        }
        "protocol" => fixture.target.protocol = "https".to_owned(),
        "pack" => fixture.target.pack_id = "api".to_owned(),
        "family" => fixture.target.action_family = "http.other".to_owned(),
        "identity" => fixture.target.identity_id = "identity:other".to_owned(),
        "tenant" => fixture.target.tenant_id = Some("tenant:other".to_owned()),
        _ => unreachable!(),
    }
}

fn owned_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("owned loopback listener")
}

fn fixture(listener: &TcpListener) -> TestBootstrap {
    bootstrap(
        listener.local_addr().expect("owned listener address"),
        now_millis(),
    )
}
