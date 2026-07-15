use std::net::TcpListener;

use crate::process::{LaunchOptions, bootstrap, now_millis};
use crate::startup_support::{assert_denied_before_journal, encoded_bootstrap};

#[test]
fn legacy_v3_bootstrap_is_rejected_before_journal_or_egress() {
    let listener = owned_listener();
    let fixture = fixture(&listener);
    let mut bytes = encoded_bootstrap(&fixture);
    bytes[4] = 3;
    let launch = LaunchOptions {
        bootstrap_bytes: Some(bytes),
        ..LaunchOptions::default()
    };
    assert_denied_before_journal(&listener, &fixture, launch);
}

#[test]
fn noncanonical_v4_bootstrap_is_rejected_before_journal_or_egress() {
    let listener = owned_listener();
    let fixture = fixture(&listener);
    let mut bytes = encoded_bootstrap(&fixture);
    bytes.push(0);
    let launch = LaunchOptions {
        bootstrap_bytes: Some(bytes),
        ..LaunchOptions::default()
    };
    assert_denied_before_journal(&listener, &fixture, launch);
}

#[test]
fn missing_installed_trust_is_rejected_before_journal_or_egress() {
    let listener = owned_listener();
    let fixture = fixture(&listener);
    let launch = LaunchOptions {
        trust_permissions: None,
        ..LaunchOptions::default()
    };
    assert_denied_before_journal(&listener, &fixture, launch);
}

#[test]
fn unsafe_installed_trust_permissions_are_rejected_before_journal_or_egress() {
    let listener = owned_listener();
    let fixture = fixture(&listener);
    let launch = LaunchOptions {
        trust_permissions: Some(0o666),
        ..LaunchOptions::default()
    };
    assert_denied_before_journal(&listener, &fixture, launch);
}

#[test]
fn noncanonical_installed_trust_is_rejected_before_journal_or_egress() {
    let listener = owned_listener();
    let fixture = fixture(&listener);
    let mut trust = fixture.trust_document();
    trust.push(b'\n');
    let launch = LaunchOptions {
        trust_bytes: Some(trust),
        ..LaunchOptions::default()
    };
    assert_denied_before_journal(&listener, &fixture, launch);
}

#[test]
fn missing_journal_descriptors_fail_without_journal_or_egress() {
    let listener = owned_listener();
    let fixture = fixture(&listener);
    let launch = LaunchOptions {
        journal_descriptors: false,
        ..LaunchOptions::default()
    };
    assert_denied_before_journal(&listener, &fixture, launch);
}

fn owned_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("owned loopback listener")
}

fn fixture(listener: &TcpListener) -> crate::bootstrap_fixture::TestBootstrap {
    bootstrap(
        listener.local_addr().expect("owned listener address"),
        now_millis(),
    )
}
