use crate::Digest;
use crate::ipc::DispatchReceipt;
use crate::supervisor_durable::{
    DurableReconciliationError, ReconciliationAdmission, ReconciliationResponseSlot,
    ReservedResponseSlot,
};
use crate::supervisor_journal::PendingInnerResponse;
use crate::supervisor_protocol::SupervisorReconciliation;

use super::SupervisorRuntime;

impl SupervisorRuntime {
    pub(crate) fn persist_shutdown_checkpoint(&self) -> std::io::Result<()> {
        self.durable.persist_checkpoint()
    }

    pub(crate) fn persist_response(
        &self,
        response_slot: ReservedResponseSlot,
        completed_receipt: Option<&DispatchReceipt>,
        inner_response: Vec<u8>,
    ) -> std::io::Result<Digest> {
        self.durable
            .persist_response(response_slot, completed_receipt, inner_response)
    }

    pub(crate) fn reserve_response(
        &self,
        request_envelope_id: Digest,
    ) -> std::io::Result<ReservedResponseSlot> {
        self.durable.reserve_fresh_response(request_envelope_id)
    }

    pub(crate) fn reconcile_hold(
        &self,
        response_slot: ReconciliationResponseSlot,
        reconciliation: &SupervisorReconciliation,
    ) -> Result<Vec<u8>, DurableReconciliationError> {
        self.durable.reconcile_hold(response_slot, reconciliation)
    }

    pub(crate) fn admit_reconciliation(
        &self,
        request_envelope_id: Digest,
        reconciliation: &SupervisorReconciliation,
    ) -> std::io::Result<ReconciliationAdmission> {
        self.durable
            .admit_reconciliation(request_envelope_id, reconciliation)
    }

    pub(crate) fn pending_response(
        &self,
        original_request_envelope_id: Digest,
    ) -> std::io::Result<Option<PendingInnerResponse>> {
        self.durable.pending_response(original_request_envelope_id)
    }

    pub(crate) fn has_pending_responses(&self) -> std::io::Result<bool> {
        self.durable.has_pending_responses()
    }

    pub(crate) fn acknowledge_response(
        &self,
        original_request_envelope_id: Digest,
        response_digest: Digest,
    ) -> std::io::Result<()> {
        self.durable
            .acknowledge_response(original_request_envelope_id, response_digest)
    }
}
