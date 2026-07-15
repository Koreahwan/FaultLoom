use std::io;

use faultloom_gateway::Digest;
use faultloom_gateway::supervisor_journal::{JournalResult, JournalSnapshot};

use crate::journal::{FakeJournal, session};

impl FakeJournal {
    pub fn current_anchor(&self) -> Option<Digest> {
        let state = self.state.lock().expect("fake journal state");
        state.current_anchor
    }

    pub fn durable_sequence(&self) -> u64 {
        self.state
            .lock()
            .expect("fake journal state")
            .durable_sequence
    }

    pub fn commit_snapshot(&self, snapshot: JournalSnapshot) -> io::Result<Digest> {
        let mut state = self.state.lock().map_err(poisoned)?;
        let previous_anchor = state.current_anchor;
        match session::commit(&mut state, previous_anchor, snapshot)? {
            JournalResult::Committed { current_anchor, .. } => Ok(current_anchor),
            _ => Err(io::Error::other("fixture snapshot commit was not accepted")),
        }
    }

    pub fn corrupt_next_ack(&self) {
        self.state
            .lock()
            .expect("fake journal state")
            .corrupt_next_ack = true;
    }
}

fn poisoned<T>(_error: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("fake journal state poisoned")
}
