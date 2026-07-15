use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::Digest;
use crate::ipc::valid_identifier;

use super::worker::{WorkerCommand, binding_error, protocol_error, run_worker};
use super::{JournalClient, JournalOperation, JournalResult, JournalSnapshot};

const JOURNAL_QUEUE_DEPTH: usize = 32;

impl JournalClient {
    pub(crate) fn new(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        key: [u8; 32],
        session_id: String,
        stable_binding: Digest,
        timeout: Duration,
    ) -> io::Result<Self> {
        if !valid_identifier(&session_id)
            || stable_binding == Digest::ZERO
            || timeout.is_zero()
            || key.iter().all(|byte| *byte == key[0])
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid journal channel",
            ));
        }
        let (commands, receiver) = mpsc::sync_channel(JOURNAL_QUEUE_DEPTH);
        let terminal = Arc::new(AtomicBool::new(false));
        let worker_terminal = Arc::clone(&terminal);
        std::thread::Builder::new()
            .name("faultloom-journal".to_owned())
            .spawn(move || {
                run_worker(
                    reader,
                    writer,
                    receiver,
                    key,
                    session_id,
                    stable_binding,
                    worker_terminal,
                )
            })?;
        Ok(Self {
            commands,
            terminal,
            timeout,
        })
    }

    pub(crate) fn open(
        &self,
        expected_anchor: Option<Digest>,
    ) -> io::Result<(Option<Digest>, Option<JournalSnapshot>)> {
        match self.transact(JournalOperation::Open { expected_anchor })? {
            JournalResult::Opened {
                current_anchor,
                snapshot,
            } if current_anchor == expected_anchor => Ok((current_anchor, snapshot)),
            _ => Err(binding_error()),
        }
    }

    pub(crate) fn commit(
        &self,
        previous_anchor: Option<Digest>,
        snapshot: JournalSnapshot,
    ) -> io::Result<Digest> {
        let snapshot_digest = snapshot.snapshot_digest().map_err(protocol_error)?;
        match self.transact(JournalOperation::Commit {
            previous_anchor,
            snapshot,
        })? {
            JournalResult::Committed {
                previous_anchor: supplied,
                current_anchor,
                snapshot_digest: supplied_digest,
            } if supplied == previous_anchor
                && supplied_digest == snapshot_digest
                && current_anchor != Digest::ZERO
                && Some(current_anchor) != previous_anchor =>
            {
                Ok(current_anchor)
            }
            _ => Err(binding_error()),
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    pub(crate) fn mark_terminal(&self) {
        self.terminal.store(true, Ordering::Release);
    }

    fn transact(&self, operation: JournalOperation) -> io::Result<JournalResult> {
        if self.terminal.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal channel is terminal",
            ));
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(WorkerCommand { operation, reply })
            .map_err(|_| {
                self.terminal.store(true, Ordering::Release);
                io::Error::new(io::ErrorKind::BrokenPipe, "journal worker stopped")
            })?;
        match response.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(error) => {
                self.terminal.store(true, Ordering::Release);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("journal ACK unavailable: {error}"),
                ))
            }
        }
    }
}
