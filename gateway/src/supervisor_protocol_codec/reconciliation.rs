use crate::ipc::{
    DenialCode, DispatchOutcome, GatewayResponse, decode_response as decode_gateway_response,
    encode_response as encode_gateway_response,
};
use crate::lease::ReconciliationReceipt;

use super::super::supervisor_protocol::SupervisorReconciliation;
use super::super::supervisor_wire::{Decoder, Encoder, MAX_SUPERVISOR_FRAME_BYTES};

const DISPATCH_RECEIPT_RECONCILIATION: u8 = 1;
const CONTROL_PLANE_RECONCILIATION: u8 = 2;

pub(super) fn encode_supervisor_reconciliation(
    encoder: &mut Encoder,
    evidence: &SupervisorReconciliation,
) -> Result<(), DenialCode> {
    match evidence {
        SupervisorReconciliation::DispatchReceipt {
            unknown_receipt,
            reconciliation,
        } => {
            if !valid_dispatch_reconciliation(unknown_receipt, reconciliation) {
                return Err(DenialCode::InvalidRequest);
            }
            let gateway = GatewayResponse::Receipt {
                action_id: unknown_receipt.action_id.clone(),
                receipt: (**unknown_receipt).clone(),
                semantic_http: None,
            };
            encoder.byte(DISPATCH_RECEIPT_RECONCILIATION);
            encoder.bytes(&encode_gateway_response(&gateway)?)?;
            encode_reconciliation_receipt(encoder, reconciliation)?;
        }
        SupervisorReconciliation::ControlPlane { reconciliation } => {
            if !reconciliation.valid_shape()
                || reconciliation.reconciliation_id == crate::Digest::ZERO
                || reconciliation.unknown_dispatch_receipt_id.is_some()
            {
                return Err(DenialCode::InvalidRequest);
            }
            encoder.byte(CONTROL_PLANE_RECONCILIATION);
            encode_reconciliation_receipt(encoder, reconciliation)?;
        }
    }
    Ok(())
}

pub(super) fn decode_supervisor_reconciliation(
    decoder: &mut Decoder<'_>,
) -> Result<SupervisorReconciliation, DenialCode> {
    let evidence = match decoder.byte()? {
        DISPATCH_RECEIPT_RECONCILIATION => {
            let encoded_receipt = decoder.bytes(MAX_SUPERVISOR_FRAME_BYTES)?;
            let gateway = decode_gateway_response(&encoded_receipt)
                .map_err(|_| DenialCode::MalformedFrame)?;
            let unknown_receipt = match gateway {
                GatewayResponse::Receipt { receipt, .. } => receipt,
                GatewayResponse::Denied(_) => return Err(DenialCode::MalformedFrame),
            };
            let reconciliation = decode_reconciliation_receipt(decoder)?;
            if !valid_dispatch_reconciliation(&unknown_receipt, &reconciliation) {
                return Err(DenialCode::MalformedFrame);
            }
            SupervisorReconciliation::DispatchReceipt {
                unknown_receipt: Box::new(unknown_receipt),
                reconciliation,
            }
        }
        CONTROL_PLANE_RECONCILIATION => {
            let reconciliation = decode_reconciliation_receipt(decoder)?;
            if reconciliation.unknown_dispatch_receipt_id.is_some() {
                return Err(DenialCode::MalformedFrame);
            }
            SupervisorReconciliation::ControlPlane { reconciliation }
        }
        _ => return Err(DenialCode::MalformedFrame),
    };
    Ok(evidence)
}

fn valid_dispatch_reconciliation(
    unknown_receipt: &crate::ipc::DispatchReceipt,
    reconciliation: &ReconciliationReceipt,
) -> bool {
    unknown_receipt.validate()
        && unknown_receipt.receipt_id != crate::Digest::ZERO
        && unknown_receipt.outcome == DispatchOutcome::UnknownOutcome
        && unknown_receipt.reconciliation_required
        && reconciliation.valid_shape()
        && reconciliation.reconciliation_id != crate::Digest::ZERO
        && reconciliation.unknown_dispatch_receipt_id == Some(unknown_receipt.receipt_id)
        && reconciliation.grant_id == unknown_receipt.grant_id
        && reconciliation.grant_version == unknown_receipt.grant_version
        && reconciliation.intent_digest == unknown_receipt.intent_digest
        && reconciliation.effect_digest == unknown_receipt.effect_digest
        && reconciliation.hold_binding_digest == unknown_receipt.hold_binding_digest
        && reconciliation.resolved_at_millis >= unknown_receipt.completed_at_millis
}

fn encode_reconciliation_receipt(
    encoder: &mut Encoder,
    receipt: &ReconciliationReceipt,
) -> Result<(), DenialCode> {
    if !receipt.valid_shape() || receipt.reconciliation_id == crate::Digest::ZERO {
        return Err(DenialCode::InvalidRequest);
    }
    encoder.digest(receipt.reconciliation_id);
    encoder.string(&receipt.key_id)?;
    encoder.string(&receipt.grant_id)?;
    encoder.u64(receipt.grant_version);
    encoder.digest(receipt.intent_digest);
    encoder.digest(receipt.effect_digest);
    encoder.digest(receipt.hold_binding_digest);
    encoder.optional_digest(receipt.unknown_dispatch_receipt_id);
    encoder.byte(receipt.terminal_outcome as u8);
    encoder.digest(receipt.terminal_evidence_digest);
    encoder.nonce(receipt.nonce);
    encoder.u64(receipt.resolved_at_millis);
    encoder.digest(receipt.authentication_tag);
    Ok(())
}

fn decode_reconciliation_receipt(
    decoder: &mut Decoder<'_>,
) -> Result<ReconciliationReceipt, DenialCode> {
    let reconciliation_id = decoder.digest()?;
    let key_id = decoder.string()?;
    let grant_id = decoder.string()?;
    let grant_version = decoder.u64()?;
    let intent_digest = decoder.digest()?;
    let effect_digest = decoder.digest()?;
    let hold_binding_digest = decoder.digest()?;
    let unknown_dispatch_receipt_id = decoder.optional_digest()?;
    let terminal_outcome = match decoder.byte()? {
        1 => DispatchOutcome::Completed,
        2 => DispatchOutcome::Failed,
        3 => DispatchOutcome::UnknownOutcome,
        _ => return Err(DenialCode::MalformedFrame),
    };
    let receipt = ReconciliationReceipt {
        reconciliation_id,
        key_id,
        grant_id,
        grant_version,
        intent_digest,
        effect_digest,
        hold_binding_digest,
        unknown_dispatch_receipt_id,
        terminal_outcome,
        terminal_evidence_digest: decoder.digest()?,
        nonce: decoder.nonce()?,
        resolved_at_millis: decoder.u64()?,
        authentication_tag: decoder.digest()?,
    };
    if !receipt.valid_shape() || receipt.reconciliation_id == crate::Digest::ZERO {
        return Err(DenialCode::MalformedFrame);
    }
    Ok(receipt)
}
