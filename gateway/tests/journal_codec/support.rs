use faultloom_gateway::Digest;
use faultloom_gateway::lease::LeaseAuthority;
use faultloom_gateway::supervisor_journal::{
    AcknowledgedResponseTombstone, JournalOperation, JournalRequest, JournalSnapshot,
    PendingInnerResponse, PreparedDispatchBinding,
};

pub(super) const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

pub(super) fn request(operation: JournalOperation) -> JournalRequest {
    JournalRequest {
        session_id: "journal-session:1".to_owned(),
        stable_binding: Digest::of(b"stable durability binding"),
        sequence: 7,
        nonce: [0x5a; 16],
        operation,
    }
}

pub(super) fn sample_snapshot() -> JournalSnapshot {
    let checkpoint = LeaseAuthority::new(
        "lease-key:journal-codec".to_owned(),
        KEY,
        "gateway-boot:journal-codec".to_owned(),
        Digest::of(b"journal codec boot challenge"),
    )
    .expect("lease authority")
    .checkpoint()
    .expect("lease checkpoint");
    let inner_response = b"exact inner response".to_vec();
    JournalSnapshot {
        lease_checkpoint_id: checkpoint.checkpoint_id(),
        lease_checkpoint: checkpoint.as_bytes().to_vec(),
        prepared_dispatches: vec![PreparedDispatchBinding {
            request_frame_digest: Digest::from_bytes([1; 32]),
            control_envelope_id: Digest::of(b"authenticated control envelope"),
            hold_binding_digest: Digest::of(b"exact reconciliation hold binding"),
            action_id: "action:1".to_owned(),
            correlation_id: "correlation:1".to_owned(),
            grant_id: "grant:1".to_owned(),
            grant_version: 1,
            scope_epoch: 1,
            lease_id: "lease:1".to_owned(),
            intent_digest: Digest::of(b"intent"),
            effect_digest: Digest::of(b"effect"),
            compiled_request_digest: Digest::of(b"compiled request"),
        }],
        pending_responses: vec![PendingInnerResponse {
            original_request_envelope_id: Digest::of(b"original request envelope"),
            inner_response_digest: Digest::of(&inner_response),
            inner_response,
        }],
        acknowledged_responses: vec![AcknowledgedResponseTombstone {
            original_request_envelope_id: Digest::of(b"acknowledged request envelope"),
            inner_response_digest: Digest::of(b"acknowledged exact response"),
        }],
    }
}
