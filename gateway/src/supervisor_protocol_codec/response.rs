use crate::ipc::{
    DenialCode, decode_response as decode_gateway_response,
    encode_response as encode_gateway_response,
};

use super::super::supervisor_protocol::{
    ControlEgressDisposition, SupervisorControlReceipt, SupervisorResponse,
};
use super::super::supervisor_wire::{Decoder, Encoder, MAX_SUPERVISOR_FRAME_BYTES};
use super::{MAGIC, VERSION};

const RESPONSE: u8 = 2;
const CONTROL_RESPONSE: u8 = 1;
const GATEWAY_RESPONSE: u8 = 2;
const EPOCH_ADMITTED: u8 = 1;
const EXPIRY_RECONCILED: u8 = 2;
const HOLD_RECONCILED: u8 = 3;
const NO_ACTIVE_EGRESS: u8 = 1;
const TARGET_OUTCOME_UNKNOWN: u8 = 2;

pub(super) fn encode_response(response: &SupervisorResponse) -> Result<Vec<u8>, DenialCode> {
    let mut encoder = Encoder::new(MAGIC, VERSION, RESPONSE);
    match response {
        SupervisorResponse::Control(control) => {
            encoder.byte(CONTROL_RESPONSE);
            match control {
                SupervisorControlReceipt::EpochAdmitted {
                    previous_epoch,
                    current_epoch,
                    revoked,
                    interrupted_resources,
                    egress_disposition,
                } => {
                    encoder.byte(EPOCH_ADMITTED);
                    encoder.bool(previous_epoch.is_some());
                    if let Some(epoch) = previous_epoch {
                        encoder.u64(*epoch);
                    }
                    encoder.u64(*current_epoch);
                    encoder.bool(*revoked);
                    encoder.u64(*interrupted_resources);
                    encode_disposition(&mut encoder, egress_disposition);
                }
                SupervisorControlReceipt::ExpiryReconciled {
                    interrupted_resources,
                    egress_disposition,
                } => {
                    encoder.byte(EXPIRY_RECONCILED);
                    encoder.u64(*interrupted_resources);
                    encode_disposition(&mut encoder, egress_disposition);
                }
                SupervisorControlReceipt::HoldReconciled {
                    reconciliation_id,
                    removed_prepared_dispatches,
                    egress_disposition,
                } => {
                    if *reconciliation_id == crate::Digest::ZERO
                        || *egress_disposition != ControlEgressDisposition::NoActiveEgress
                    {
                        return Err(DenialCode::InvalidRequest);
                    }
                    encoder.byte(HOLD_RECONCILED);
                    encoder.digest(*reconciliation_id);
                    encoder.u64(*removed_prepared_dispatches);
                    encode_disposition(&mut encoder, egress_disposition);
                }
            }
        }
        SupervisorResponse::Gateway(gateway) => {
            encoder.byte(GATEWAY_RESPONSE);
            encoder.bytes(&encode_gateway_response(gateway)?)?;
        }
    }
    encoder.finish()
}

pub(super) fn decode_response(encoded: &[u8]) -> Result<SupervisorResponse, DenialCode> {
    let mut decoder = Decoder::new(encoded, MAGIC, VERSION)?;
    if decoder.byte()? != RESPONSE {
        return Err(DenialCode::MalformedFrame);
    }
    let response = match decoder.byte()? {
        CONTROL_RESPONSE => SupervisorResponse::Control(match decoder.byte()? {
            EPOCH_ADMITTED => {
                let previous_epoch = if decoder.bool()? {
                    Some(decoder.u64()?)
                } else {
                    None
                };
                SupervisorControlReceipt::EpochAdmitted {
                    previous_epoch,
                    current_epoch: decoder.u64()?,
                    revoked: decoder.bool()?,
                    interrupted_resources: decoder.u64()?,
                    egress_disposition: decode_disposition(&mut decoder)?,
                }
            }
            EXPIRY_RECONCILED => SupervisorControlReceipt::ExpiryReconciled {
                interrupted_resources: decoder.u64()?,
                egress_disposition: decode_disposition(&mut decoder)?,
            },
            HOLD_RECONCILED => {
                let reconciliation_id = decoder.digest()?;
                let removed_prepared_dispatches = decoder.u64()?;
                let egress_disposition = decode_disposition(&mut decoder)?;
                if reconciliation_id == crate::Digest::ZERO
                    || egress_disposition != ControlEgressDisposition::NoActiveEgress
                {
                    return Err(DenialCode::MalformedFrame);
                }
                SupervisorControlReceipt::HoldReconciled {
                    reconciliation_id,
                    removed_prepared_dispatches,
                    egress_disposition,
                }
            }
            _ => return Err(DenialCode::MalformedFrame),
        }),
        GATEWAY_RESPONSE => {
            let gateway = decoder.bytes(MAX_SUPERVISOR_FRAME_BYTES)?;
            SupervisorResponse::Gateway(Box::new(
                decode_gateway_response(&gateway).map_err(|error| error.reason)?,
            ))
        }
        _ => return Err(DenialCode::MalformedFrame),
    };
    decoder.finish()?;
    if encode_response(&response)?.as_slice() != encoded {
        return Err(DenialCode::MalformedFrame);
    }
    Ok(response)
}

fn encode_disposition(encoder: &mut Encoder, disposition: &ControlEgressDisposition) {
    encoder.byte(match disposition {
        ControlEgressDisposition::NoActiveEgress => NO_ACTIVE_EGRESS,
        ControlEgressDisposition::TargetOutcomeUnknown => TARGET_OUTCOME_UNKNOWN,
    });
}

fn decode_disposition(decoder: &mut Decoder<'_>) -> Result<ControlEgressDisposition, DenialCode> {
    match decoder.byte()? {
        NO_ACTIVE_EGRESS => Ok(ControlEgressDisposition::NoActiveEgress),
        TARGET_OUTCOME_UNKNOWN => Ok(ControlEgressDisposition::TargetOutcomeUnknown),
        _ => Err(DenialCode::MalformedFrame),
    }
}
