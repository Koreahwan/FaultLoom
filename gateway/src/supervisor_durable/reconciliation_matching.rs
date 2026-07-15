use crate::Digest;
use crate::ipc::{DenialCode, DispatchReceipt, GatewayResponse};

use super::super::supervisor_journal::{JournalSnapshot, PreparedDispatchBinding};
use super::super::supervisor_protocol::{SupervisorReconciliation, SupervisorResponse};
use super::DurableSupervisorState;

impl DurableSupervisorState {
    pub(super) fn inspect_reconciliation(
        &self,
        snapshot: &JournalSnapshot,
        reconciliation: &SupervisorReconciliation,
    ) -> Result<(Digest, Vec<usize>), DenialCode> {
        let (reconciliation_id, matches, reconciliation_exists) = match reconciliation {
            SupervisorReconciliation::DispatchReceipt {
                unknown_receipt,
                reconciliation,
            } => {
                self.lease.verify_dispatch_receipt(unknown_receipt)?;
                if !dispatch_reconciliation_matches(unknown_receipt, reconciliation) {
                    return Err(DenialCode::LeaseReconciliationRequired);
                }
                let reconciliation_exists = self
                    .lease
                    .reconciliation_receipt(
                        &reconciliation.grant_id,
                        reconciliation.grant_version,
                        reconciliation.intent_digest,
                    )?
                    .is_some();
                let matches = snapshot
                    .prepared_dispatches
                    .iter()
                    .enumerate()
                    .filter_map(|(index, binding)| {
                        prepared_matches_receipt(binding, unknown_receipt).then_some(index)
                    })
                    .collect::<Vec<_>>();
                match matches.len() {
                    1 => {}
                    0 if reconciliation_exists => {}
                    0 if acknowledged_dispatch_response(snapshot, unknown_receipt)? => {}
                    0 => {
                        return Err(DenialCode::LeaseBindingMismatch);
                    }
                    _ => return Err(DenialCode::RecoveryCheckpointInvalid),
                }
                (
                    reconciliation.reconciliation_id,
                    matches,
                    reconciliation_exists,
                )
            }
            SupervisorReconciliation::ControlPlane { reconciliation } => {
                if !reconciliation.valid_shape()
                    || reconciliation.unknown_dispatch_receipt_id.is_some()
                {
                    return Err(DenialCode::LeaseReconciliationRequired);
                }
                let reconciliation_exists = self
                    .lease
                    .reconciliation_receipt(
                        &reconciliation.grant_id,
                        reconciliation.grant_version,
                        reconciliation.intent_digest,
                    )?
                    .is_some();
                let matches = snapshot
                    .prepared_dispatches
                    .iter()
                    .enumerate()
                    .filter_map(|(index, binding)| {
                        prepared_matches_control(binding, reconciliation).then_some(index)
                    })
                    .collect::<Vec<_>>();
                let has_mismatched_binding = snapshot.prepared_dispatches.iter().any(|binding| {
                    binding.grant_id == reconciliation.grant_id
                        && binding.grant_version == reconciliation.grant_version
                        && binding.intent_digest == reconciliation.intent_digest
                        && !prepared_matches_control(binding, reconciliation)
                });
                if has_mismatched_binding || matches.len() > 1 {
                    return Err(DenialCode::LeaseBindingMismatch);
                }
                (
                    reconciliation.reconciliation_id,
                    matches,
                    reconciliation_exists,
                )
            }
        };
        if reconciliation_exists {
            return Err(DenialCode::LeaseReplay);
        }
        Ok((reconciliation_id, matches))
    }
}

pub(super) fn prepared_matches_receipt(
    binding: &PreparedDispatchBinding,
    receipt: &DispatchReceipt,
) -> bool {
    binding.request_frame_digest == receipt.request_frame_digest
        && binding.control_envelope_id == receipt.control_envelope_id
        && binding.hold_binding_digest == receipt.hold_binding_digest
        && binding.action_id == receipt.action_id
        && binding.correlation_id == receipt.correlation_id
        && binding.grant_id == receipt.grant_id
        && binding.grant_version == receipt.grant_version
        && binding.scope_epoch == receipt.scope_epoch
        && binding.lease_id == receipt.lease_id
        && binding.intent_digest == receipt.intent_digest
        && binding.effect_digest == receipt.effect_digest
        && binding.compiled_request_digest == receipt.request_digest
}

fn prepared_matches_control(
    binding: &PreparedDispatchBinding,
    reconciliation: &crate::lease::ReconciliationReceipt,
) -> bool {
    binding.hold_binding_digest == reconciliation.hold_binding_digest
        && binding.grant_id == reconciliation.grant_id
        && binding.grant_version == reconciliation.grant_version
        && binding.intent_digest == reconciliation.intent_digest
        && binding.effect_digest == reconciliation.effect_digest
}

fn dispatch_reconciliation_matches(
    receipt: &DispatchReceipt,
    reconciliation: &crate::lease::ReconciliationReceipt,
) -> bool {
    receipt.outcome == crate::ipc::DispatchOutcome::UnknownOutcome
        && receipt.reconciliation_required
        && reconciliation.valid_shape()
        && reconciliation.unknown_dispatch_receipt_id == Some(receipt.receipt_id)
        && reconciliation.grant_id == receipt.grant_id
        && reconciliation.grant_version == receipt.grant_version
        && reconciliation.intent_digest == receipt.intent_digest
        && reconciliation.effect_digest == receipt.effect_digest
        && reconciliation.hold_binding_digest == receipt.hold_binding_digest
        && reconciliation.resolved_at_millis >= receipt.completed_at_millis
}

fn acknowledged_dispatch_response(
    snapshot: &JournalSnapshot,
    receipt: &DispatchReceipt,
) -> Result<bool, DenialCode> {
    let encoded = SupervisorResponse::Gateway(Box::new(GatewayResponse::Receipt {
        action_id: receipt.action_id.clone(),
        receipt: receipt.clone(),
        semantic_http: None,
    }))
    .to_bytes()?;
    let response_digest = Digest::of(&encoded);
    Ok(snapshot.acknowledged_responses.iter().any(|tombstone| {
        tombstone.original_request_envelope_id == receipt.control_envelope_id
            && tombstone.inner_response_digest == response_digest
    }))
}
