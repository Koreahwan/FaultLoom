use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::ipc::DenialCode;

use super::SupervisorStageError;

pub(super) type ScopedWorker<'scope> = std::thread::ScopedJoinHandle<'scope, ()>;

pub(super) struct WorkerPermit {
    active: Arc<Mutex<usize>>,
}

impl WorkerPermit {
    pub(super) fn acquire(active: Arc<Mutex<usize>>, maximum: usize) -> Option<Self> {
        let mut current = active.lock().ok()?;
        let next = current.checked_add(1)?;
        if next > maximum {
            return None;
        }
        *current = next;
        drop(current);
        Some(Self { active })
    }

    fn acquire_coordinated(
        active: Arc<Mutex<usize>>,
        coordination: &Mutex<()>,
        maximum: usize,
    ) -> Option<Self> {
        let _coordination = coordination.lock().ok()?;
        Self::acquire(active, maximum)
    }
}

pub(super) struct WorkerAdmission<'a> {
    active: Arc<Mutex<usize>>,
    coordination: &'a Mutex<()>,
    maximum: usize,
}

impl<'a> WorkerAdmission<'a> {
    pub(super) fn new(
        active: Arc<Mutex<usize>>,
        coordination: &'a Mutex<()>,
        maximum: usize,
    ) -> Self {
        Self {
            active,
            coordination,
            maximum,
        }
    }

    pub(super) fn after_preflight<T>(
        self,
        preflighted: T,
    ) -> Result<(T, WorkerPermit), (T, DenialCode)> {
        match WorkerPermit::acquire_coordinated(self.active, self.coordination, self.maximum) {
            Some(permit) => Ok((preflighted, permit)),
            None => Err((preflighted, DenialCode::LeaseConcurrencyExceeded)),
        }
    }

    #[cfg(test)]
    pub(super) fn after<T>(
        self,
        preflighted: Result<T, DenialCode>,
    ) -> Result<(T, WorkerPermit), DenialCode> {
        let preflighted = preflighted?;
        let permit =
            WorkerPermit::acquire_coordinated(self.active, self.coordination, self.maximum)
                .ok_or(DenialCode::LeaseConcurrencyExceeded)?;
        Ok((preflighted, permit))
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut current = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(next) = current.checked_sub(1) {
            *current = next;
        }
    }
}

pub(super) struct ReconciliationGuard<'a> {
    _coordination: MutexGuard<'a, ()>,
}

impl<'a> ReconciliationGuard<'a> {
    pub(super) fn lock(coordination: &'a Mutex<()>) -> io::Result<Self> {
        coordination
            .lock()
            .map(|guard| Self {
                _coordination: guard,
            })
            .map_err(|_| io::Error::other("worker coordination lock poisoned"))
    }

    fn require_quiescent(&self, active: &Mutex<usize>) -> io::Result<()> {
        let active = active
            .lock()
            .map_err(|_| io::Error::other("active worker lock poisoned"))?;
        if *active == 0 {
            Ok(())
        } else {
            Err(io::Error::other(
                "reconciliation requires a quiescent worker set",
            ))
        }
    }

    pub(super) fn run_when_quiescent<T>(
        &self,
        active: &Mutex<usize>,
        operation: impl FnOnce() -> T,
    ) -> io::Result<T> {
        self.require_quiescent(active)?;
        Ok(operation())
    }
}

pub(super) fn join_finished(
    workers: &mut Vec<ScopedWorker<'_>>,
) -> Result<(), SupervisorStageError> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            if workers.swap_remove(index).join().is_err() {
                return Err(io::Error::other("supervisor dispatch worker panicked").into());
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

pub(super) fn join_all(workers: &mut Vec<ScopedWorker<'_>>) -> Result<(), SupervisorStageError> {
    let mut panicked = false;
    for worker in workers.drain(..) {
        if worker.join().is_err() {
            panicked = true;
        }
    }
    if panicked {
        Err(io::Error::other("supervisor dispatch worker panicked").into())
    } else {
        Ok(())
    }
}
