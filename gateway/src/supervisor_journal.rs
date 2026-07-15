mod client;
mod frame;
mod worker;

pub use frame::{read_journal_frame, write_journal_frame};

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::SyncSender;
use std::time::Duration;

use crate::Digest;
use crate::ipc::DenialCode;

use self::worker::WorkerCommand;

pub const MAX_JOURNAL_FRAME_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_DURABLE_RESPONSE_SLOTS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedDispatchBinding {
    pub request_frame_digest: Digest,
    pub control_envelope_id: Digest,
    pub hold_binding_digest: Digest,
    pub action_id: String,
    pub correlation_id: String,
    pub grant_id: String,
    pub grant_version: u64,
    pub scope_epoch: u64,
    pub lease_id: String,
    pub intent_digest: Digest,
    pub effect_digest: Digest,
    pub compiled_request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingInnerResponse {
    pub original_request_envelope_id: Digest,
    pub inner_response_digest: Digest,
    pub inner_response: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgedResponseTombstone {
    pub original_request_envelope_id: Digest,
    pub inner_response_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalSnapshot {
    pub lease_checkpoint_id: Digest,
    pub lease_checkpoint: Vec<u8>,
    pub prepared_dispatches: Vec<PreparedDispatchBinding>,
    pub pending_responses: Vec<PendingInnerResponse>,
    pub acknowledged_responses: Vec<AcknowledgedResponseTombstone>,
}

impl JournalSnapshot {
    pub fn snapshot_digest(&self) -> Result<Digest, DenialCode> {
        super::supervisor_journal_codec::snapshot_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalOperation {
    Open {
        expected_anchor: Option<Digest>,
    },
    Commit {
        previous_anchor: Option<Digest>,
        snapshot: JournalSnapshot,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRequest {
    pub session_id: String,
    pub stable_binding: Digest,
    pub sequence: u64,
    pub nonce: [u8; 16],
    pub operation: JournalOperation,
}

impl JournalRequest {
    pub fn to_bytes(&self, key: &[u8; 32]) -> Result<Vec<u8>, DenialCode> {
        super::supervisor_journal_codec::encode_request(self, key)
    }

    pub fn from_bytes(encoded: &[u8], key: &[u8; 32]) -> Result<Self, DenialCode> {
        super::supervisor_journal_codec::decode_request(encoded, key)
    }

    pub fn request_id(&self) -> Result<Digest, DenialCode> {
        super::supervisor_journal_codec::request_id(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JournalDenial {
    StorageUnavailable = 1,
    AnchorMismatch = 2,
    SnapshotInvalid = 3,
    AuthenticationFailed = 4,
    SequenceRejected = 5,
    StableBindingMismatch = 6,
    PendingResponseMissing = 7,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalResult {
    Opened {
        current_anchor: Option<Digest>,
        snapshot: Option<JournalSnapshot>,
    },
    Committed {
        previous_anchor: Option<Digest>,
        current_anchor: Digest,
        snapshot_digest: Digest,
    },
    Denied(JournalDenial),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalReply {
    pub session_id: String,
    pub stable_binding: Digest,
    pub sequence: u64,
    pub request_id: Digest,
    pub result: JournalResult,
}

impl JournalReply {
    pub fn for_request(
        request: &JournalRequest,
        result: JournalResult,
    ) -> Result<Self, DenialCode> {
        Ok(Self {
            session_id: request.session_id.clone(),
            stable_binding: request.stable_binding,
            sequence: request.sequence,
            request_id: request.request_id()?,
            result,
        })
    }

    pub fn to_bytes(&self, key: &[u8; 32]) -> Result<Vec<u8>, DenialCode> {
        super::supervisor_journal_codec::encode_reply(self, key)
    }

    pub fn from_bytes(encoded: &[u8], key: &[u8; 32]) -> Result<Self, DenialCode> {
        super::supervisor_journal_codec::decode_reply(encoded, key)
    }

    pub fn validate_for(&self, request: &JournalRequest) -> Result<(), DenialCode> {
        if self.session_id == request.session_id
            && self.stable_binding == request.stable_binding
            && self.sequence == request.sequence
            && self.request_id == request.request_id()?
        {
            Ok(())
        } else {
            Err(DenialCode::DurabilityAnchorMismatch)
        }
    }
}

#[derive(Clone)]
pub(crate) struct JournalClient {
    commands: SyncSender<WorkerCommand>,
    terminal: Arc<AtomicBool>,
    timeout: Duration,
}
