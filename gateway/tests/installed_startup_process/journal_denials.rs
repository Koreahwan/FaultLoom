use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use faultloom_gateway::Digest;

use crate::bootstrap_fixture::{TestBootstrap, test_key};
use crate::journal::FakeJournal;
use crate::process::{ProcessHarness, bootstrap, now_millis};
use crate::startup_support::{
    assert_failed_silently, assert_no_connection, assert_one_open_without_mutation, journal_for,
    rotated_bootstrap,
};

#[test]
fn stale_anchor_performs_one_open_without_mutation_or_egress() {
    let listener = owned_listener();
    let (initial, journal) = seeded_journal(&listener);
    let stale = rotated_bootstrap(&initial, Digest::ZERO);
    let before = journal.observation();

    let gateway = ProcessHarness::spawn_with_journal(&stale, Arc::clone(&journal));
    assert_failed_silently(gateway.observe_failure());

    assert_one_open_without_mutation(&before, &journal.observation());
    assert_no_connection(&listener);
}

#[test]
fn changed_policy_or_stable_key_performs_one_open_without_mutation_or_egress() {
    let listener = owned_listener();
    let (initial, journal) = seeded_journal(&listener);
    let anchor = journal
        .observation()
        .current_anchor
        .expect("seed journal anchor");
    for scenario in ["policy", "stable-key"] {
        let mut changed = rotated_bootstrap(&initial, anchor);
        match scenario {
            "policy" => {
                changed.target.target_id = "target:changed-policy".to_owned();
                let port = changed.target.socket.port().checked_add(1).unwrap_or(1);
                changed.target.socket = SocketAddr::from(([127, 0, 0, 1], port));
            }
            "stable-key" => changed.secrets.lease_key = test_key(0xb1),
            _ => unreachable!(),
        }
        assert_ne!(
            initial.durability_binding().expect("initial binding"),
            changed.durability_binding().expect("changed binding"),
        );
        let before = journal.observation();
        let gateway = ProcessHarness::spawn_with_journal(&changed, Arc::clone(&journal));
        assert_failed_silently(gateway.observe_failure());
        assert_one_open_without_mutation(&before, &journal.observation());
        assert_no_connection(&listener);
    }
}

fn owned_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("owned loopback listener")
}

fn seeded_journal(listener: &TcpListener) -> (TestBootstrap, Arc<FakeJournal>) {
    let initial = bootstrap(
        listener.local_addr().expect("listener address"),
        now_millis(),
    );
    let journal = journal_for(&initial);
    ProcessHarness::spawn_with_journal(&initial, Arc::clone(&journal)).finish();
    assert!(journal.observation().current_anchor.is_some());
    (initial, journal)
}
