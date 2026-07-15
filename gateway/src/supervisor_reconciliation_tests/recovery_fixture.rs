use std::sync::Arc;

use crate::Digest;
use crate::lease::{LeaseAuthority, LeaseRecoveryCheckpoint, LeaseSpec};
use crate::supervisor_journal::JournalSnapshot;

use super::active_fixture::{LEASE_KEY, RECONCILIATION_KEY};

pub(super) fn restored_lease(
    snapshot: &JournalSnapshot,
    gateway_boot_id: &str,
) -> Arc<LeaseAuthority> {
    let checkpoint = LeaseRecoveryCheckpoint::from_bytes(snapshot.lease_checkpoint.clone())
        .expect("decode journal checkpoint");
    restored_checkpoint(&checkpoint, snapshot.lease_checkpoint_id, gateway_boot_id)
}

fn restored_checkpoint(
    checkpoint: &LeaseRecoveryCheckpoint,
    expected_checkpoint_id: Digest,
    gateway_boot_id: &str,
) -> Arc<LeaseAuthority> {
    let lease = Arc::new(
        LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            LEASE_KEY,
            gateway_boot_id.to_owned(),
            Digest::of(gateway_boot_id.as_bytes()),
            "reconciliation-key:test".to_owned(),
            RECONCILIATION_KEY,
        )
        .expect("restarted lease authority"),
    );
    lease
        .restore_checkpoint(checkpoint, expected_checkpoint_id)
        .expect("restore journal checkpoint");
    lease
}

pub(super) fn checkpoint_sequence(checkpoint: &LeaseRecoveryCheckpoint) -> u64 {
    let encoded = checkpoint.as_bytes();
    let mut cursor = 9 + b"faultloom-lease-recovery-state-v6\0".len();
    for _ in 0..2 {
        let length = u32::from_be_bytes(
            encoded[cursor..cursor + 4]
                .try_into()
                .expect("checkpoint string length"),
        );
        cursor += 4 + usize::try_from(length).expect("checkpoint string length fits usize");
    }
    cursor += Digest::ZERO.as_bytes().len();
    u64::from_be_bytes(
        encoded[cursor..cursor + 8]
            .try_into()
            .expect("checkpoint sequence"),
    )
}

pub(super) fn assert_same_restored_state(
    expected: &LeaseRecoveryCheckpoint,
    observed: &LeaseRecoveryCheckpoint,
    spec: &LeaseSpec,
    label: &str,
) {
    let expected_lease = restored_checkpoint(
        expected,
        expected.checkpoint_id(),
        &format!("gateway:boot:{label}:expected"),
    );
    let observed_lease = restored_checkpoint(
        observed,
        observed.checkpoint_id(),
        &format!("gateway:boot:{label}:observed"),
    );
    assert_eq!(
        expected_lease.reconciliation_receipt(
            &spec.grant_id,
            spec.grant_version,
            spec.intent_digest,
        ),
        observed_lease.reconciliation_receipt(
            &spec.grant_id,
            spec.grant_version,
            spec.intent_digest,
        )
    );
    assert_eq!(
        expected_lease.interrupt_grant(&spec.grant_id, spec.grant_version),
        observed_lease.interrupt_grant(&spec.grant_id, spec.grant_version)
    );
}
