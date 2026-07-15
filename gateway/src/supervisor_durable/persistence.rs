use std::io;

use crate::Digest;
use crate::ipc::DenialCode;
use crate::lease::LeaseRecoveryCheckpoint;

use super::super::supervisor_journal::JournalSnapshot;
use super::{DurableState, DurableSupervisorState};

impl DurableSupervisorState {
    pub(crate) fn recovery_checkpoint(
        snapshot: &Option<JournalSnapshot>,
    ) -> Result<Option<LeaseRecoveryCheckpoint>, DenialCode> {
        snapshot
            .as_ref()
            .map(|value| {
                let checkpoint =
                    LeaseRecoveryCheckpoint::from_bytes(value.lease_checkpoint.clone())?;
                if checkpoint.checkpoint_id() != value.lease_checkpoint_id {
                    return Err(DenialCode::RecoveryCheckpointInvalid);
                }
                Ok(checkpoint)
            })
            .transpose()
    }

    pub(crate) fn persist_checkpoint(&self) -> io::Result<()> {
        self.mutate(|_| Ok(()))
    }

    fn mutate(
        &self,
        update: impl FnOnce(&mut JournalSnapshot) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut state = self.lock_state()?;
        if self.journal.is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal channel is terminal",
            ));
        }
        let mut next = state.snapshot.clone().unwrap_or_else(empty_snapshot);
        update(&mut next)?;
        self.commit_next(&mut state, next)
    }

    pub(super) fn commit_next(
        &self,
        state: &mut DurableState,
        mut next: JournalSnapshot,
    ) -> io::Result<()> {
        let checkpoint = self.lease.checkpoint().map_err(|reason| {
            io::Error::other(format!("cannot checkpoint lease state: {reason:?}"))
        })?;
        next.lease_checkpoint_id = checkpoint.checkpoint_id();
        next.lease_checkpoint = checkpoint.as_bytes().to_vec();
        next.prepared_dispatches.sort_by(|left, right| {
            left.request_frame_digest
                .as_bytes()
                .cmp(right.request_frame_digest.as_bytes())
        });
        next.pending_responses.sort_by(|left, right| {
            left.original_request_envelope_id
                .as_bytes()
                .cmp(right.original_request_envelope_id.as_bytes())
        });
        let anchor = self
            .journal
            .commit(state.anchor, next.clone())
            .inspect_err(|_| self.journal.mark_terminal())?;
        state.anchor = Some(anchor);
        state.snapshot = Some(next);
        Ok(())
    }
}

pub(super) fn empty_snapshot() -> JournalSnapshot {
    JournalSnapshot {
        lease_checkpoint_id: Digest::ZERO,
        lease_checkpoint: Vec::new(),
        prepared_dispatches: Vec::new(),
        pending_responses: Vec::new(),
        acknowledged_responses: Vec::new(),
    }
}
