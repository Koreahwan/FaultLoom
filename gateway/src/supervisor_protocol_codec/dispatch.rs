use crate::ipc::{ActionClass, DenialCode, FlowKind};

use super::super::supervisor_protocol::SupervisorDispatch;
use super::super::supervisor_wire::{Decoder, Encoder};

const MAX_PAYLOAD_BYTES: usize = 32_768;

pub(super) fn encode_dispatch(
    encoder: &mut Encoder,
    dispatch: &SupervisorDispatch,
) -> Result<(), DenialCode> {
    if dispatch.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(DenialCode::InvalidRequest);
    }
    encoder.string(&dispatch.action_id)?;
    encoder.string(&dispatch.correlation_id)?;
    encoder.string(&dispatch.lease_id)?;
    encoder.string(&dispatch.target_id)?;
    encoder.u64(dispatch.scope_epoch);
    encoder.byte(dispatch.action_class as u8);
    encoder.byte(dispatch.flow_kind as u8);
    encoder.optional_string(dispatch.parent_action_id.as_deref())?;
    encoder.string(&dispatch.method)?;
    encoder.string(&dispatch.path)?;
    encoder.digest(dispatch.intent_digest);
    encoder.digest(dispatch.decision_digest);
    encoder.nonce(dispatch.dispatch_nonce);
    encoder.u64(dispatch.issued_at_millis);
    encoder.u64(dispatch.expires_at_millis);
    encoder.optional_digest(dispatch.retry_of_intent_digest);
    encoder.bytes(&dispatch.payload)?;
    encoder.optional_string(dispatch.canary_ref.as_deref())?;
    encoder.optional_string(dispatch.checkpoint_ref.as_deref())?;
    encoder.optional_string(dispatch.cleanup_plan_ref.as_deref())?;
    Ok(())
}

pub(super) fn decode_dispatch(decoder: &mut Decoder<'_>) -> Result<SupervisorDispatch, DenialCode> {
    let action_id = decoder.string()?;
    let correlation_id = decoder.string()?;
    let lease_id = decoder.string()?;
    let target_id = decoder.string()?;
    let scope_epoch = decoder.u64()?;
    let action_class = match decoder.byte()? {
        1 => ActionClass::Observe,
        2 => ActionClass::SafeProbe,
        3 => ActionClass::StateChange,
        _ => return Err(DenialCode::UnsupportedActionClass),
    };
    let flow_kind = match decoder.byte()? {
        1 => FlowKind::TopLevel,
        3 => FlowKind::Redirect,
        4 => FlowKind::BrowserSubresource,
        5 => FlowKind::BrowserIframe,
        6 => FlowKind::ServiceWorker,
        8 => FlowKind::Download,
        _ => return Err(DenialCode::InvalidChildFlow),
    };
    let parent_action_id = decoder.optional_string()?;
    Ok(SupervisorDispatch {
        action_id,
        correlation_id,
        lease_id,
        target_id,
        scope_epoch,
        action_class,
        flow_kind,
        parent_action_id,
        method: decoder.string()?,
        path: decoder.string()?,
        intent_digest: decoder.digest()?,
        decision_digest: decoder.digest()?,
        dispatch_nonce: decoder.nonce()?,
        issued_at_millis: decoder.u64()?,
        expires_at_millis: decoder.u64()?,
        retry_of_intent_digest: decoder.optional_digest()?,
        payload: decoder.bytes(MAX_PAYLOAD_BYTES)?,
        canary_ref: decoder.optional_string()?,
        checkpoint_ref: decoder.optional_string()?,
        cleanup_plan_ref: decoder.optional_string()?,
    })
}
