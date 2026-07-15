use crate::Digest;
use crate::ipc::{DenialCode, valid_identifier};

use super::super::supervisor_journal::{
    JournalDenial, JournalOperation, JournalReply, JournalRequest, JournalResult,
};
use super::snapshot::encode_snapshot;
use super::wire::Encoder;
use super::{COMMIT, COMMITTED, DENIED, OPEN, OPENED, REPLY, REQUEST};

pub(super) fn unsigned_request(request: &JournalRequest) -> Result<Vec<u8>, DenialCode> {
    validate_header(
        &request.session_id,
        request.stable_binding,
        request.sequence,
    )?;
    if request.nonce.iter().all(|byte| *byte == 0) {
        return Err(DenialCode::InvalidRequest);
    }
    let mut encoder = Encoder::new(REQUEST);
    encoder.string(&request.session_id)?;
    encoder.digest(request.stable_binding);
    encoder.u64(request.sequence);
    encoder.nonce(request.nonce);
    match &request.operation {
        JournalOperation::Open { expected_anchor } => {
            encoder.byte(OPEN);
            encoder.optional_digest(*expected_anchor)?;
        }
        JournalOperation::Commit {
            previous_anchor,
            snapshot,
        } => {
            encoder.byte(COMMIT);
            encoder.optional_digest(*previous_anchor)?;
            encode_snapshot(&mut encoder, snapshot)?;
        }
    }
    encoder.finish()
}

pub(super) fn unsigned_reply(reply: &JournalReply) -> Result<Vec<u8>, DenialCode> {
    validate_header(&reply.session_id, reply.stable_binding, reply.sequence)?;
    if reply.request_id == Digest::ZERO {
        return Err(DenialCode::InvalidRequest);
    }
    let mut encoder = Encoder::new(REPLY);
    encoder.string(&reply.session_id)?;
    encoder.digest(reply.stable_binding);
    encoder.u64(reply.sequence);
    encoder.digest(reply.request_id);
    match &reply.result {
        JournalResult::Opened {
            current_anchor,
            snapshot,
        } => {
            if current_anchor.is_some() != snapshot.is_some() {
                return Err(DenialCode::InvalidRequest);
            }
            encoder.byte(OPENED);
            encoder.optional_digest(*current_anchor)?;
            encoder.bool(snapshot.is_some());
            if let Some(snapshot) = snapshot {
                encode_snapshot(&mut encoder, snapshot)?;
            }
        }
        JournalResult::Committed {
            previous_anchor,
            current_anchor,
            snapshot_digest,
        } => {
            if *current_anchor == Digest::ZERO
                || *snapshot_digest == Digest::ZERO
                || Some(*current_anchor) == *previous_anchor
            {
                return Err(DenialCode::InvalidRequest);
            }
            encoder.byte(COMMITTED);
            encoder.optional_digest(*previous_anchor)?;
            encoder.digest(*current_anchor);
            encoder.digest(*snapshot_digest);
        }
        JournalResult::Denied(reason) => {
            encoder.byte(DENIED);
            encoder.byte(*reason as u8);
        }
    }
    encoder.finish()
}

fn validate_header(session: &str, binding: Digest, sequence: u64) -> Result<(), DenialCode> {
    if !valid_identifier(session) || binding == Digest::ZERO || sequence == 0 {
        Err(DenialCode::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(super) fn decode_denial(value: u8) -> Result<JournalDenial, DenialCode> {
    match value {
        1 => Ok(JournalDenial::StorageUnavailable),
        2 => Ok(JournalDenial::AnchorMismatch),
        3 => Ok(JournalDenial::SnapshotInvalid),
        4 => Ok(JournalDenial::AuthenticationFailed),
        5 => Ok(JournalDenial::SequenceRejected),
        6 => Ok(JournalDenial::StableBindingMismatch),
        7 => Ok(JournalDenial::PendingResponseMissing),
        _ => Err(DenialCode::MalformedFrame),
    }
}
