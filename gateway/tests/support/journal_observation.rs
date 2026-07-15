use faultloom_gateway::Digest;
use faultloom_gateway::supervisor_journal::JournalSnapshot;

use crate::journal::FakeJournal;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalObservation {
    pub frames: u64,
    pub opens: u64,
    pub commits: u64,
    pub durable_sequence: u64,
    pub current_anchor: Option<Digest>,
    pub snapshot: Option<JournalSnapshot>,
}

impl FakeJournal {
    pub fn observation(&self) -> JournalObservation {
        let state = self.state.lock().expect("fake journal observation");
        JournalObservation {
            frames: state.received_frames,
            opens: state.open_requests,
            commits: state.commit_requests,
            durable_sequence: state.durable_sequence,
            current_anchor: state.current_anchor,
            snapshot: state.snapshot.clone(),
        }
    }
}
