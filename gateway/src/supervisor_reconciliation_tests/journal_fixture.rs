use std::io::ErrorKind;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::DurableSupervisorState;
use crate::Digest;
use crate::lease::LeaseAuthority;
use crate::supervisor_journal::{
    AcknowledgedResponseTombstone, JournalClient, JournalDenial, JournalOperation, JournalReply,
    JournalRequest, JournalResult, JournalSnapshot, read_journal_frame, write_journal_frame,
};

const JOURNAL_KEY: [u8; 32] = *b"journal-key-0123456789abcdef0123";

pub(super) fn fill_acknowledged(snapshot: &mut JournalSnapshot, count: usize) {
    snapshot.acknowledged_responses = (0..count)
        .map(|index| AcknowledgedResponseTombstone {
            original_request_envelope_id: Digest::of(format!("full request {index}").as_bytes()),
            inner_response_digest: Digest::of(format!("full response {index}").as_bytes()),
        })
        .collect();
}

#[derive(Default)]
pub(super) struct TestJournalState {
    anchor: Option<Digest>,
    pub(super) snapshot: Option<JournalSnapshot>,
    pub(super) commits: u64,
    pub(super) fail_next_commit: bool,
}

pub(super) fn durable_state(
    lease: Arc<LeaseAuthority>,
    snapshot: JournalSnapshot,
) -> (DurableSupervisorState, Arc<Mutex<TestJournalState>>) {
    let state = Arc::new(Mutex::new(TestJournalState::default()));
    let client = journal_client(Arc::clone(&state), "journal-session:test");
    assert_eq!(client.open(None).expect("open journal"), (None, None));
    let anchor = client
        .commit(None, snapshot.clone())
        .expect("seed snapshot");
    let durable = DurableSupervisorState::new(lease, client, Some(anchor), Some(snapshot))
        .expect("durable state");
    (durable, state)
}

pub(super) fn restart_durable(
    lease: Arc<LeaseAuthority>,
    state: Arc<Mutex<TestJournalState>>,
) -> DurableSupervisorState {
    let (anchor, expected_snapshot) = {
        let state = state.lock().expect("journal state");
        (state.anchor, state.snapshot.clone())
    };
    let client = journal_client(state, "journal-session:restart");
    let (opened_anchor, opened_snapshot) = client.open(anchor).expect("reopen journal");
    assert_eq!(opened_anchor, anchor);
    assert_eq!(opened_snapshot, expected_snapshot);
    DurableSupervisorState::new(lease, client, opened_anchor, opened_snapshot)
        .expect("restarted durable state")
}

fn journal_client(state: Arc<Mutex<TestJournalState>>, session_id: &str) -> JournalClient {
    let (client_stream, server_stream) = UnixStream::pair().expect("journal socket pair");
    let reader = client_stream.try_clone().expect("clone journal client");
    std::thread::spawn(move || serve_journal(server_stream, state));
    JournalClient::new(
        reader,
        client_stream,
        JOURNAL_KEY,
        session_id.to_owned(),
        Digest::of(b"stable test binding"),
        Duration::from_secs(1),
    )
    .expect("journal client")
}

fn serve_journal(mut stream: UnixStream, shared: Arc<Mutex<TestJournalState>>) {
    let mut sequence = 1_u64;
    loop {
        let frame = match read_journal_frame(&mut stream) {
            Ok(frame) => frame,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                ) =>
            {
                return;
            }
            Err(_) => return,
        };
        let Ok(request) = JournalRequest::from_bytes(&frame, &JOURNAL_KEY) else {
            return;
        };
        let result = if request.sequence != sequence {
            JournalResult::Denied(JournalDenial::SequenceRejected)
        } else {
            process_journal_request(&request, &shared)
        };
        let denied = matches!(result, JournalResult::Denied(_));
        let Ok(reply) = JournalReply::for_request(&request, result) else {
            return;
        };
        let Ok(encoded) = reply.to_bytes(&JOURNAL_KEY) else {
            return;
        };
        if write_journal_frame(&mut stream, &encoded).is_err() || denied {
            return;
        }
        sequence = match sequence.checked_add(1) {
            Some(next) => next,
            None => return,
        };
    }
}

fn process_journal_request(
    request: &JournalRequest,
    shared: &Mutex<TestJournalState>,
) -> JournalResult {
    let mut state = shared.lock().expect("journal state");
    match &request.operation {
        JournalOperation::Open { expected_anchor } if *expected_anchor == state.anchor => {
            JournalResult::Opened {
                current_anchor: state.anchor,
                snapshot: state.snapshot.clone(),
            }
        }
        JournalOperation::Open { .. } => JournalResult::Denied(JournalDenial::AnchorMismatch),
        JournalOperation::Commit { .. } if std::mem::take(&mut state.fail_next_commit) => {
            JournalResult::Denied(JournalDenial::StorageUnavailable)
        }
        JournalOperation::Commit {
            previous_anchor,
            snapshot,
        } if *previous_anchor == state.anchor => {
            let snapshot_digest = snapshot.snapshot_digest().expect("valid snapshot");
            let mut material = Vec::new();
            material.extend_from_slice(previous_anchor.unwrap_or(Digest::ZERO).as_bytes());
            material.extend_from_slice(snapshot_digest.as_bytes());
            material.extend_from_slice(&request.sequence.to_be_bytes());
            let current_anchor = Digest::of(&material);
            state.anchor = Some(current_anchor);
            state.snapshot = Some(snapshot.clone());
            state.commits += 1;
            JournalResult::Committed {
                previous_anchor: *previous_anchor,
                current_anchor,
                snapshot_digest,
            }
        }
        JournalOperation::Commit { .. } => JournalResult::Denied(JournalDenial::AnchorMismatch),
    }
}
