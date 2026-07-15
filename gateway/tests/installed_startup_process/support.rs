use std::net::TcpListener;
use std::sync::Arc;

use faultloom_gateway::Digest;

use crate::bootstrap_fixture::{TestBootstrap, test_key};
use crate::journal::FakeJournal;
use crate::journal_observation::JournalObservation;
use crate::process::{FailureObservation, LaunchOptions, ProcessHarness};

pub(super) fn encoded_bootstrap(bootstrap: &TestBootstrap) -> Vec<u8> {
    let executable = std::fs::canonicalize(env!("CARGO_BIN_EXE_faultloom-gateway"))
        .expect("exact Cargo gateway binary");
    let executable_bytes = std::fs::read(executable).expect("read exact gateway binary");
    bootstrap
        .encode_for_fd3(Digest::of(&executable_bytes))
        .expect("encode signed FLBS v4 bootstrap")
}

pub(super) fn journal_for(bootstrap: &TestBootstrap) -> Arc<FakeJournal> {
    Arc::new(
        FakeJournal::new(
            bootstrap.secrets.journal_key,
            bootstrap.durability_binding().expect("durability binding"),
        )
        .expect("fake journal"),
    )
}

pub(super) fn rotated_bootstrap(
    initial: &TestBootstrap,
    expected_journal_anchor: Digest,
) -> TestBootstrap {
    let now = crate::process::now_millis();
    let mut rotated = initial.clone();
    rotated.secrets.channel_key_id = "channel-key:restart".to_owned();
    rotated.secrets.channel_key = test_key(0x11);
    rotated.secrets.channel_boot_id = "channel-boot:restart".to_owned();
    rotated.secrets.channel_nonce = crate::process::nonce(0x21);
    rotated.secrets.channel_issued_at_millis = now.saturating_sub(1_000);
    rotated.secrets.channel_expires_at_millis = now + 120_000;
    rotated.secrets.gateway_boot_id = "gateway-boot:restart".to_owned();
    rotated.secrets.gateway_challenge = test_key(0x71);
    rotated.expected_journal_anchor = expected_journal_anchor;
    rotated.boot.issued_at_millis = now.saturating_sub(1_000);
    rotated.boot.expires_at_millis = now + 20_000;
    rotated.boot.sequence = initial.boot.sequence + 1;
    rotated.boot.nonce = crate::process::nonce(0x56);
    rotated
}

pub(super) fn assert_denied_before_journal(
    listener: &TcpListener,
    bootstrap: &TestBootstrap,
    launch: LaunchOptions,
) {
    let journal = journal_for(bootstrap);
    let before = journal.observation();
    let gateway = ProcessHarness::spawn_configured(bootstrap, Arc::clone(&journal), launch);
    assert!(Arc::ptr_eq(&gateway.journal(), &journal));
    assert_failed_silently(gateway.observe_failure());
    assert_eq!(
        journal.observation(),
        before,
        "startup denial touched durable journal"
    );
    assert_no_connection(listener);
}

pub(super) fn assert_failed_silently(observation: FailureObservation) {
    assert_eq!(
        observation.status.code(),
        Some(1),
        "wrong startup exit status"
    );
    assert!(observation.stdout.is_empty(), "startup denial wrote stdout");
    assert!(observation.stderr.is_empty(), "startup denial wrote stderr");
}

pub(super) fn assert_no_connection(listener: &TcpListener) {
    listener
        .set_nonblocking(true)
        .expect("nonblocking owned listener");
    assert_eq!(
        listener
            .accept()
            .expect_err("startup denial made target egress")
            .kind(),
        std::io::ErrorKind::WouldBlock,
    );
}

pub(super) fn assert_one_open_without_mutation(
    before: &JournalObservation,
    after: &JournalObservation,
) {
    assert_eq!(after.frames, before.frames + 1);
    assert_eq!(after.opens, before.opens + 1);
    assert_eq!(after.commits, before.commits);
    assert_eq!(after.durable_sequence, before.durable_sequence);
    assert_eq!(after.current_anchor, before.current_anchor);
    assert_eq!(after.snapshot, before.snapshot);
}
