use crate::Digest;
use crate::ipc::{ActionClass, DenialCode, DispatchReceipt, GatewayResponse};
use crate::lease::ReconciliationReceipt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorDispatch {
    pub action_id: String,
    pub correlation_id: String,
    pub lease_id: String,
    pub target_id: String,
    pub scope_epoch: u64,
    pub action_class: ActionClass,
    pub method: String,
    pub path: String,
    pub intent_digest: Digest,
    pub decision_digest: Digest,
    pub dispatch_nonce: [u8; 16],
    pub issued_at_millis: u64,
    pub expires_at_millis: u64,
    pub retry_of_intent_digest: Option<Digest>,
    pub payload: Vec<u8>,
    pub canary_ref: Option<String>,
    pub checkpoint_ref: Option<String>,
    pub cleanup_plan_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorCommand {
    AdmitEpoch {
        canonical_envelope: Vec<u8>,
        verifier_receipt: Vec<u8>,
    },
    Dispatch(Box<SupervisorDispatch>),
    ReconcileExpiry,
    RecoverPendingResponse {
        original_request_id: Digest,
    },
    AcknowledgePendingResponse {
        original_request_id: Digest,
        response_digest: Digest,
    },
    ReconcileHold(Box<SupervisorReconciliation>),
}

impl SupervisorCommand {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DenialCode> {
        super::supervisor_protocol_codec::encode_command(self)
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self, DenialCode> {
        super::supervisor_protocol_codec::decode_command(encoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorReconciliation {
    DispatchReceipt {
        unknown_receipt: Box<DispatchReceipt>,
        reconciliation: ReconciliationReceipt,
    },
    ControlPlane {
        reconciliation: ReconciliationReceipt,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlEgressDisposition {
    NoActiveEgress,
    TargetOutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorControlReceipt {
    EpochAdmitted {
        previous_epoch: Option<u64>,
        current_epoch: u64,
        revoked: bool,
        interrupted_resources: u64,
        egress_disposition: ControlEgressDisposition,
    },
    ExpiryReconciled {
        interrupted_resources: u64,
        egress_disposition: ControlEgressDisposition,
    },
    HoldReconciled {
        reconciliation_id: Digest,
        removed_prepared_dispatches: u64,
        egress_disposition: ControlEgressDisposition,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorResponse {
    Control(SupervisorControlReceipt),
    Gateway(Box<GatewayResponse>),
}

impl SupervisorResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DenialCode> {
        super::supervisor_protocol_codec::encode_response(self)
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self, DenialCode> {
        super::supervisor_protocol_codec::decode_response(encoded)
    }
}
