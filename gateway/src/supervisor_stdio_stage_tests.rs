use std::cell::{Cell, RefCell};

use super::{ReconciliationGuard, SupervisorStageError, finish_processing};

#[derive(Default)]
struct FakeMutationJournal {
    events: RefCell<Vec<&'static str>>,
}

impl FakeMutationJournal {
    fn record(&self, event: &'static str) {
        self.events.borrow_mut().push(event);
    }
}

#[test]
fn persist_failure_is_last_mutation_without_checkpoint_or_ack() {
    // Given
    let journal = FakeMutationJournal::default();
    journal.record("persist-failed");

    // When
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        finish_processing(
            Err(SupervisorStageError::Persist(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced journal failure",
            ))),
            || {
                journal.record("shutdown");
                journal.record("checkpoint");
                journal.record("ack");
                Ok(())
            },
            test_fail_stop,
        )
    }));

    // Then
    assert!(result.is_err());
    assert_eq!(&*journal.events.borrow(), &["persist-failed"]);
}

#[test]
fn output_failure_fail_stops_without_cleanup_mutation() {
    // Given
    let journal = FakeMutationJournal::default();
    journal.record("output-failed");

    // When
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        finish_processing(
            Err(SupervisorStageError::Output(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "forced output failure",
            ))),
            || {
                journal.record("shutdown");
                journal.record("checkpoint");
                Ok(())
            },
            test_fail_stop,
        )
    }));

    // Then
    assert!(result.is_err());
    assert_eq!(&*journal.events.borrow(), &["output-failed"]);
}

#[test]
fn active_worker_gate_never_enters_forced_reconciliation_failure() {
    // Given
    let coordination = std::sync::Mutex::new(());
    let active = std::sync::Mutex::new(1_usize);
    let guard = ReconciliationGuard::lock(&coordination).expect("coordination gate");
    let entered = Cell::new(false);
    let journal = FakeMutationJournal::default();

    // When
    let result = guard.run_when_quiescent(&active, || {
        entered.set(true);
        journal.record("reconciliation-commit");
        Err::<(), _>(SupervisorStageError::Persist(std::io::Error::other(
            "forced reconciliation failure",
        )))
    });

    // Then
    assert_eq!(
        result
            .expect_err("active worker must block reconciliation")
            .kind(),
        std::io::ErrorKind::Other
    );
    assert!(!entered.get());
    assert!(journal.events.borrow().is_empty());
}

fn test_fail_stop() -> ! {
    panic!("test fail-stop boundary")
}
