#[cfg(test)]
use std::sync::{Arc, Mutex};

use super::{WorkerAdmission, WorkerPermit};
use crate::ipc::DenialCode;

#[test]
fn worker_permit_rejects_a_worker_at_the_configured_maximum() {
    // Given: one permit already consumes the sole worker slot.
    let active = Arc::new(Mutex::new(0));
    let _first = WorkerPermit::acquire(Arc::clone(&active), 1).expect("first permit");

    // When: another worker attempts to acquire a permit.
    let second = WorkerPermit::acquire(active, 1);

    // Then: the worker is rejected without exceeding the bound.
    assert!(second.is_none());
}

#[test]
fn worker_permit_rejects_zero_and_overflowed_counters() {
    // Given: a zero bound and a counter that cannot be incremented.
    let zero = Arc::new(Mutex::new(0));
    let overflowed = Arc::new(Mutex::new(usize::MAX));

    // When: permits are requested for both fail-closed states.
    let permits = [
        WorkerPermit::acquire(zero, 0),
        WorkerPermit::acquire(overflowed, usize::MAX),
    ];

    // Then: neither state can create a worker permit.
    assert!(permits.into_iter().all(|permit| permit.is_none()));
}

#[test]
fn worker_permit_acquire_fails_closed_after_counter_poisoning() {
    // Given: a worker counter whose mutex was poisoned.
    let active = Arc::new(Mutex::new(0));
    let poison_target = Arc::clone(&active);
    let _ = std::panic::catch_unwind(move || {
        let _guard = poison_target.lock().expect("counter lock");
        panic!("poison worker counter");
    });

    // When: a worker attempts to acquire from the poisoned counter.
    let permit = WorkerPermit::acquire(active, 1);

    // Then: acquisition fails closed.
    assert!(permit.is_none());
}

#[test]
fn worker_permit_drop_recovers_poison_without_underflow() {
    // Given: a held permit whose shared counter is subsequently poisoned.
    let active = Arc::new(Mutex::new(0));
    let permit = WorkerPermit::acquire(Arc::clone(&active), 1).expect("held permit");
    let poison_target = Arc::clone(&active);
    let _ = std::panic::catch_unwind(move || {
        let _guard = poison_target.lock().expect("counter lock");
        panic!("poison worker counter");
    });

    // When: the held permit is released.
    drop(permit);

    // Then: Drop recovers the lock and decrements exactly to zero.
    let current = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(*current, 0);
}

#[test]
fn reconciliation_preflight_denial_does_not_acquire_a_worker_permit() {
    // Given: no active workers and a reconciliation hold denial produced by
    // the authenticated main-thread preflight.
    let active = Arc::new(Mutex::new(0));
    let coordination = Mutex::new(());

    // When: worker admission consumes the typed preflight result.
    let admission = WorkerAdmission::new(Arc::clone(&active), &coordination, 1);
    let result = admission.after(Err::<(), _>(DenialCode::LeaseReconciliationRequired));

    // Then: the denial remains exact and the worker counter is untouched.
    assert!(matches!(
        result,
        Err(DenialCode::LeaseReconciliationRequired)
    ));
    assert_eq!(*active.lock().expect("active workers"), 0);
}

#[test]
fn successful_preflight_is_the_only_state_that_can_acquire_a_worker() {
    // Given: a typed successful preflight and one available worker slot.
    let active = Arc::new(Mutex::new(0));
    let coordination = Mutex::new(());

    // When: worker admission consumes that successful state.
    let admission = WorkerAdmission::new(Arc::clone(&active), &coordination, 1);
    let (marker, permit) = admission
        .after(Ok("preflighted"))
        .expect("preflighted worker");

    // Then: the marker reaches the worker and the permit owns exactly one slot.
    assert_eq!(marker, "preflighted");
    assert_eq!(*active.lock().expect("active workers"), 1);
    drop(permit);
    assert_eq!(*active.lock().expect("released workers"), 0);
}
