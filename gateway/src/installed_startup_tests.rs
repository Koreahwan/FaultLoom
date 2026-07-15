#[path = "installed_startup_test_support.rs"]
mod support;

use crate::ipc::DenialCode;

use super::{authorize_loaded_startup, measure_running_executable};
use support::{FixtureOptions, fixture};

#[test]
fn executable_measurement_hashes_proc_self_exe_bytes() {
    // Given: the exact executable exposed by the running Linux process.
    let executable = std::fs::read("/proc/self/exe").expect("running executable");

    // When: installed startup measures its fixed executable boundary.
    let measured = measure_running_executable().expect("executable measurement");

    // Then: the controller binding receives SHA-256 of the real executable bytes.
    assert_eq!(measured, crate::Digest::of(&executable));
}

#[test]
fn verified_startup_preserves_t19_boot_sequence_and_nonce() {
    // Given: a pinned authority grant and exact controller-signed boot context.
    let fixture = fixture(FixtureOptions::default());
    let expected_sequence = fixture.bootstrap.boot_authorization.boot_sequence;
    let expected_nonce = fixture.bootstrap.boot_authorization.nonce;

    // When: the complete local startup boundary authorizes the fixture.
    let startup = authorize_loaded_startup(
        fixture.trust,
        fixture.bootstrap,
        fixture.executable_digest,
        fixture.now_millis,
    )
    .expect("authorized startup");

    // Then: replay inputs survive as data without claiming global one-use.
    assert_eq!(
        startup.verified_boot_authorization.boot_sequence(),
        expected_sequence
    );
    assert_eq!(startup.verified_boot_authorization.nonce(), expected_nonce);
}

#[test]
fn stable_binding_excludes_every_rotating_boot_dimension() {
    // Given: two valid boots with the same grant and durable keys but rotated boot material.
    let first = fixture(FixtureOptions::default());
    let second = fixture(FixtureOptions {
        trust_generation: 9,
        controller_seed: 92,
        channel_seed: 2,
        epoch_seed: 34,
        gateway_seed: 66,
        journal_anchor_seed: 8,
        executable_seed: 10,
        boot_sequence: 18,
        boot_nonce_seed: 0x53,
        ..FixtureOptions::default()
    });

    // When: both exact boot contexts cross authority and controller verification.
    let first = authorize_loaded_startup(
        first.trust,
        first.bootstrap,
        first.executable_digest,
        first.now_millis,
    )
    .expect("first startup");
    let second = authorize_loaded_startup(
        second.trust,
        second.bootstrap,
        second.executable_digest,
        second.now_millis,
    )
    .expect("rotated startup");

    // Then: channel, epoch, boot, anchor, executable, controller, and trust rotation is stable.
    assert_eq!(
        first.durability_binding().expect("first binding"),
        second.durability_binding().expect("second binding")
    );
}

#[test]
fn stable_binding_changes_with_authority_selection_or_each_durable_key() {
    // Given: one authorized baseline and independent stable-identity mutations.
    let baseline = fixture(FixtureOptions::default());
    let baseline = authorize_loaded_startup(
        baseline.trust,
        baseline.bootstrap,
        baseline.executable_digest,
        baseline.now_millis,
    )
    .expect("baseline startup")
    .durability_binding()
    .expect("baseline binding");
    let changes = [
        (
            "authority",
            FixtureOptions {
                authority_seed: 8,
                ..FixtureOptions::default()
            },
        ),
        (
            "selection",
            FixtureOptions {
                selection_port: 8081,
                ..FixtureOptions::default()
            },
        ),
        (
            "lease",
            FixtureOptions {
                lease_seed: 98,
                ..FixtureOptions::default()
            },
        ),
        (
            "compiler",
            FixtureOptions {
                compiler_seed: 130,
                ..FixtureOptions::default()
            },
        ),
        (
            "journal",
            FixtureOptions {
                journal_seed: 162,
                ..FixtureOptions::default()
            },
        ),
        (
            "reconciliation",
            FixtureOptions {
                reconciliation_seed: 194,
                ..FixtureOptions::default()
            },
        ),
    ];

    // When/Then: every verified authority or durable dimension changes the identity.
    for (dimension, changed) in changes {
        let changed = fixture(changed);
        let binding = authorize_loaded_startup(
            changed.trust,
            changed.bootstrap,
            changed.executable_digest,
            changed.now_millis,
        )
        .expect("changed startup")
        .durability_binding()
        .expect("changed binding");
        assert_ne!(baseline, binding, "stable binding ignored {dimension}");
    }
}

#[test]
fn stable_binding_changes_with_verified_grant_payload() {
    // Given
    let baseline = fixture(FixtureOptions::default());
    let changed = fixture(FixtureOptions::default());
    let baseline = authorize_loaded_startup(
        baseline.trust,
        baseline.bootstrap,
        baseline.executable_digest,
        baseline.now_millis,
    )
    .expect("baseline startup");
    let mut changed = authorize_loaded_startup(
        changed.trust,
        changed.bootstrap,
        changed.executable_digest,
        changed.now_millis,
    )
    .expect("changed startup");

    // When
    changed.stable.grant_payload_digest = crate::Digest::of(b"changed verified payload");

    // Then
    assert_ne!(
        baseline.durability_binding().expect("baseline binding"),
        changed.durability_binding().expect("changed binding")
    );
}

#[test]
fn invalid_controller_signature_never_creates_authorized_startup() {
    // Given: an otherwise exact startup whose detached controller signature is altered.
    let mut fixture = fixture(FixtureOptions::default());
    fixture.bootstrap.boot_authorization.signature[0] ^= 1;

    // When: the final local authorization gate verifies the bootstrap.
    let result = authorize_loaded_startup(
        fixture.trust,
        fixture.bootstrap,
        fixture.executable_digest,
        fixture.now_millis,
    );

    // Then: no capability-bearing startup value is produced.
    assert!(matches!(result, Err(DenialCode::IpcAuthenticationFailed)));
}
