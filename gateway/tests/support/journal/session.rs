use std::io::{self, ErrorKind, Write};
use std::path::Path;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use faultloom_gateway::Digest;
use faultloom_gateway::supervisor_journal::{
    JournalDenial, JournalOperation, JournalReply, JournalRequest, JournalResult, JournalSnapshot,
    read_journal_frame, write_journal_frame,
};

use super::{AckGate, DurableState};

pub(super) fn serve_session(
    request_path: &Path,
    reply_path: &Path,
    key: [u8; 32],
    state: Arc<Mutex<DurableState>>,
) -> io::Result<()> {
    let mut input = std::fs::OpenOptions::new().read(true).open(request_path)?;
    let mut output = std::fs::OpenOptions::new().write(true).open(reply_path)?;
    let mut session_id = None::<String>;
    let mut expected_sequence = 1_u64;
    loop {
        let frame = match read_journal_frame(&mut input) {
            Ok(frame) => frame,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        {
            let mut durable = state.lock().map_err(poisoned)?;
            durable.received_frames = durable
                .received_frames
                .checked_add(1)
                .ok_or_else(|| io::Error::other("journal frame counter exhausted"))?;
        }
        let request = JournalRequest::from_bytes(&frame, &key).map_err(protocol_error)?;
        let wrong_session = session_id
            .as_ref()
            .is_some_and(|known| known != &request.session_id);
        let denial = (request.sequence != expected_sequence || wrong_session)
            .then_some(JournalDenial::SequenceRejected);
        session_id.get_or_insert_with(|| request.session_id.clone());
        let (result, corrupt, ack_gate) = {
            let mut durable = state.lock().map_err(poisoned)?;
            let corrupt = std::mem::take(&mut durable.corrupt_next_ack);
            let ack_gate = durable.next_ack_gate.take();
            let result = denial.map_or_else(
                || process_request(&request, &mut durable),
                |reason| Ok(JournalResult::Denied(reason)),
            )?;
            (result, corrupt, ack_gate)
        };
        pause_after_commit(ack_gate)?;
        let denied = matches!(result, JournalResult::Denied(_));
        let mut reply = JournalReply::for_request(&request, result).map_err(protocol_error)?;
        if corrupt {
            reply.request_id = Digest::of(b"faultloom-corrupt-journal-ack");
        }
        write_journal_frame(&mut output, &reply.to_bytes(&key).map_err(protocol_error)?)?;
        if denied {
            return Ok(());
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("journal sequence exhausted"))?;
    }
}

fn pause_after_commit(gate: Option<AckGate>) -> io::Result<()> {
    let Some(gate) = gate else { return Ok(()) };
    gate.committed
        .send(())
        .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "journal ACK gate observer stopped"))?;
    match gate.release.recv_timeout(Duration::from_secs(5)) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => Ok(()),
        Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
            ErrorKind::TimedOut,
            "journal ACK gate release timed out",
        )),
    }
}

fn process_request(
    request: &JournalRequest,
    state: &mut DurableState,
) -> io::Result<JournalResult> {
    match &request.operation {
        JournalOperation::Open { .. } => increment(&mut state.open_requests, "open")?,
        JournalOperation::Commit { .. } => increment(&mut state.commit_requests, "commit")?,
    }
    if request.stable_binding != state.stable_binding {
        return Ok(JournalResult::Denied(JournalDenial::StableBindingMismatch));
    }
    match &request.operation {
        JournalOperation::Open { expected_anchor } if *expected_anchor != state.current_anchor => {
            Ok(JournalResult::Denied(JournalDenial::AnchorMismatch))
        }
        JournalOperation::Open { .. } => Ok(JournalResult::Opened {
            current_anchor: state.current_anchor,
            snapshot: state.snapshot.clone(),
        }),
        JournalOperation::Commit {
            previous_anchor,
            snapshot,
        } => commit(state, *previous_anchor, snapshot.clone()),
    }
}

fn increment(counter: &mut u64, kind: &str) -> io::Result<()> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| io::Error::other(format!("journal {kind} counter exhausted")))?;
    Ok(())
}

pub(crate) fn commit(
    state: &mut DurableState,
    previous_anchor: Option<Digest>,
    snapshot: JournalSnapshot,
) -> io::Result<JournalResult> {
    if previous_anchor != state.current_anchor {
        return Ok(JournalResult::Denied(JournalDenial::AnchorMismatch));
    }
    let snapshot_digest = snapshot.snapshot_digest().map_err(protocol_error)?;
    let durable_sequence = state
        .durable_sequence
        .checked_add(1)
        .ok_or_else(|| io::Error::other("durable sequence exhausted"))?;
    let material = anchor_material(
        previous_anchor,
        state.stable_binding,
        snapshot_digest,
        durable_sequence,
    );
    let current_anchor = Digest::of(&material);
    state.audit.write_all(&material)?;
    state.audit.write_all(current_anchor.as_bytes())?;
    state.audit.sync_all()?;
    state.current_anchor = Some(current_anchor);
    state.snapshot = Some(snapshot);
    state.durable_sequence = durable_sequence;
    Ok(JournalResult::Committed {
        previous_anchor,
        current_anchor,
        snapshot_digest,
    })
}

fn anchor_material(
    previous_anchor: Option<Digest>,
    stable_binding: Digest,
    snapshot_digest: Digest,
    durable_sequence: u64,
) -> Vec<u8> {
    let mut material = Vec::with_capacity(114);
    material.extend_from_slice(b"faultloom-fake-durable-anchor-v1\0");
    material.push(u8::from(previous_anchor.is_some()));
    material.extend_from_slice(previous_anchor.unwrap_or(Digest::ZERO).as_bytes());
    material.extend_from_slice(stable_binding.as_bytes());
    material.extend_from_slice(snapshot_digest.as_bytes());
    material.extend_from_slice(&durable_sequence.to_be_bytes());
    material
}

fn protocol_error(reason: faultloom_gateway::ipc::DenialCode) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, format!("protocol: {reason:?}"))
}

fn poisoned<T>(_error: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("fake journal state poisoned")
}
