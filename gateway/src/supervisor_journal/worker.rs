use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};

use crate::Digest;
use crate::ipc::DenialCode;

use super::{
    JournalOperation, JournalReply, JournalRequest, JournalResult, read_journal_frame,
    write_journal_frame,
};

pub(super) struct WorkerCommand {
    pub(super) operation: JournalOperation,
    pub(super) reply: SyncSender<io::Result<JournalResult>>,
}

pub(super) fn run_worker(
    mut reader: impl Read,
    mut writer: impl Write,
    commands: Receiver<WorkerCommand>,
    key: [u8; 32],
    session_id: String,
    stable_binding: Digest,
    terminal: Arc<AtomicBool>,
) {
    let mut sequence = 1_u64;
    while let Ok(command) = commands.recv() {
        let request = JournalRequest {
            session_id: session_id.clone(),
            stable_binding,
            sequence,
            nonce: request_nonce(&session_id, stable_binding, sequence),
            operation: command.operation,
        };
        let result = exchange(&mut reader, &mut writer, &key, &request);
        let failed = result.is_err();
        let _ = command.reply.send(result);
        if failed || terminal.load(Ordering::Acquire) {
            terminal.store(true, Ordering::Release);
            break;
        }
        let Some(next) = sequence.checked_add(1) else {
            terminal.store(true, Ordering::Release);
            break;
        };
        sequence = next;
    }
}

fn exchange(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &[u8; 32],
    request: &JournalRequest,
) -> io::Result<JournalResult> {
    write_journal_frame(writer, &request.to_bytes(key).map_err(protocol_error)?)?;
    let reply =
        JournalReply::from_bytes(&read_journal_frame(reader)?, key).map_err(protocol_error)?;
    reply.validate_for(request).map_err(|_| binding_error())?;
    match reply.result {
        JournalResult::Denied(reason) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("journal denied: {reason:?}"),
        )),
        result => Ok(result),
    }
}

fn request_nonce(session_id: &str, stable_binding: Digest, sequence: u64) -> [u8; 16] {
    let mut material = Vec::with_capacity(session_id.len() + 72);
    material.extend_from_slice(b"faultloom-journal-request-nonce-v1\0");
    material.extend_from_slice(session_id.as_bytes());
    material.extend_from_slice(stable_binding.as_bytes());
    material.extend_from_slice(&sequence.to_be_bytes());
    Digest::of(&material).as_bytes()[..16]
        .try_into()
        .unwrap_or([0; 16])
}

pub(super) fn protocol_error(reason: DenialCode) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("journal protocol error: {reason:?}"),
    )
}

pub(super) fn binding_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "journal reply binding mismatch")
}
