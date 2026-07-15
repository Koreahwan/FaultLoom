use crate::ipc::DenialCode;

use super::super::supervisor_protocol::SupervisorCommand;
use super::super::supervisor_wire::{Decoder, Encoder};
use super::{MAGIC, VERSION, dispatch, reconciliation};

const COMMAND: u8 = 1;
const ADMIT_EPOCH: u8 = 1;
const DISPATCH: u8 = 2;
const RECONCILE_EXPIRY: u8 = 3;
const RECOVER_PENDING_RESPONSE: u8 = 4;
const ACKNOWLEDGE_PENDING_RESPONSE: u8 = 5;
const RECONCILE_HOLD: u8 = 6;
const MAX_EPOCH_PART_BYTES: usize = 36_864;

pub(super) fn encode_command(command: &SupervisorCommand) -> Result<Vec<u8>, DenialCode> {
    let mut encoder = Encoder::new(MAGIC, VERSION, COMMAND);
    match command {
        SupervisorCommand::AdmitEpoch {
            canonical_envelope,
            verifier_receipt,
        } => {
            if canonical_envelope.len() > MAX_EPOCH_PART_BYTES
                || verifier_receipt.len() > MAX_EPOCH_PART_BYTES
            {
                return Err(DenialCode::InvalidRequest);
            }
            encoder.byte(ADMIT_EPOCH);
            encoder.bytes(canonical_envelope)?;
            encoder.bytes(verifier_receipt)?;
        }
        SupervisorCommand::Dispatch(dispatch) => {
            encoder.byte(DISPATCH);
            dispatch::encode_dispatch(&mut encoder, dispatch)?;
        }
        SupervisorCommand::ReconcileExpiry => encoder.byte(RECONCILE_EXPIRY),
        SupervisorCommand::RecoverPendingResponse {
            original_request_id,
        } => {
            if *original_request_id == crate::Digest::ZERO {
                return Err(DenialCode::InvalidRequest);
            }
            encoder.byte(RECOVER_PENDING_RESPONSE);
            encoder.digest(*original_request_id);
        }
        SupervisorCommand::AcknowledgePendingResponse {
            original_request_id,
            response_digest,
        } => {
            if *original_request_id == crate::Digest::ZERO
                || *response_digest == crate::Digest::ZERO
            {
                return Err(DenialCode::InvalidRequest);
            }
            encoder.byte(ACKNOWLEDGE_PENDING_RESPONSE);
            encoder.digest(*original_request_id);
            encoder.digest(*response_digest);
        }
        SupervisorCommand::ReconcileHold(reconciliation) => {
            encoder.byte(RECONCILE_HOLD);
            reconciliation::encode_supervisor_reconciliation(&mut encoder, reconciliation)?;
        }
    }
    encoder.finish()
}

pub(super) fn decode_command(encoded: &[u8]) -> Result<SupervisorCommand, DenialCode> {
    let mut decoder = Decoder::new(encoded, MAGIC, VERSION)?;
    if decoder.byte()? != COMMAND {
        return Err(DenialCode::MalformedFrame);
    }
    let command = match decoder.byte()? {
        ADMIT_EPOCH => SupervisorCommand::AdmitEpoch {
            canonical_envelope: decoder.bytes(MAX_EPOCH_PART_BYTES)?,
            verifier_receipt: decoder.bytes(MAX_EPOCH_PART_BYTES)?,
        },
        DISPATCH => SupervisorCommand::Dispatch(Box::new(dispatch::decode_dispatch(&mut decoder)?)),
        RECONCILE_EXPIRY => SupervisorCommand::ReconcileExpiry,
        RECOVER_PENDING_RESPONSE => SupervisorCommand::RecoverPendingResponse {
            original_request_id: decoder.digest()?,
        },
        ACKNOWLEDGE_PENDING_RESPONSE => SupervisorCommand::AcknowledgePendingResponse {
            original_request_id: decoder.digest()?,
            response_digest: decoder.digest()?,
        },
        RECONCILE_HOLD => SupervisorCommand::ReconcileHold(Box::new(
            reconciliation::decode_supervisor_reconciliation(&mut decoder)?,
        )),
        _ => return Err(DenialCode::MalformedFrame),
    };
    decoder.finish()?;
    if encode_command(&command)?.as_slice() != encoded {
        return Err(DenialCode::MalformedFrame);
    }
    Ok(command)
}
