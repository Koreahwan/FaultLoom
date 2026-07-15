use crate::Digest;
use crate::ipc::{DenialCode, valid_identifier};
use crate::lease::LeaseRecoveryCheckpoint;

use super::super::supervisor_journal::{
    AcknowledgedResponseTombstone, JournalSnapshot, MAX_DURABLE_RESPONSE_SLOTS,
    PendingInnerResponse, PreparedDispatchBinding,
};
use super::MAX_ITEMS;
use super::wire::{Decoder, Encoder};

const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
const MAX_INNER_RESPONSE_BYTES: usize = 65_536;

pub(super) fn encode_snapshot(
    encoder: &mut Encoder,
    snapshot: &JournalSnapshot,
) -> Result<(), DenialCode> {
    validate_snapshot(snapshot)?;
    encoder.digest(snapshot.lease_checkpoint_id);
    encoder.bytes(&snapshot.lease_checkpoint, MAX_CHECKPOINT_BYTES)?;
    encoder.count(snapshot.prepared_dispatches.len())?;
    for item in &snapshot.prepared_dispatches {
        encoder.digest(item.request_frame_digest);
        encoder.digest(item.control_envelope_id);
        encoder.digest(item.hold_binding_digest);
        encoder.string(&item.action_id)?;
        encoder.string(&item.correlation_id)?;
        encoder.string(&item.grant_id)?;
        encoder.u64(item.grant_version);
        encoder.u64(item.scope_epoch);
        encoder.string(&item.lease_id)?;
        encoder.digest(item.intent_digest);
        encoder.digest(item.effect_digest);
        encoder.digest(item.compiled_request_digest);
    }
    encoder.count(snapshot.pending_responses.len())?;
    for item in &snapshot.pending_responses {
        encoder.digest(item.original_request_envelope_id);
        encoder.digest(item.inner_response_digest);
        encoder.bytes(&item.inner_response, MAX_INNER_RESPONSE_BYTES)?;
    }
    encoder.count(snapshot.acknowledged_responses.len())?;
    for item in &snapshot.acknowledged_responses {
        encoder.digest(item.original_request_envelope_id);
        encoder.digest(item.inner_response_digest);
    }
    Ok(())
}

pub(super) fn decode_snapshot(decoder: &mut Decoder<'_>) -> Result<JournalSnapshot, DenialCode> {
    let lease_checkpoint_id = decoder.digest()?;
    let lease_checkpoint = decoder.bytes(MAX_CHECKPOINT_BYTES)?;
    let prepared_dispatches = (0..decoder.count()?)
        .map(|_| {
            Ok(PreparedDispatchBinding {
                request_frame_digest: decoder.digest()?,
                control_envelope_id: decoder.digest()?,
                hold_binding_digest: decoder.digest()?,
                action_id: decoder.string()?,
                correlation_id: decoder.string()?,
                grant_id: decoder.string()?,
                grant_version: decoder.u64()?,
                scope_epoch: decoder.u64()?,
                lease_id: decoder.string()?,
                intent_digest: decoder.digest()?,
                effect_digest: decoder.digest()?,
                compiled_request_digest: decoder.digest()?,
            })
        })
        .collect::<Result<Vec<_>, DenialCode>>()?;
    let pending_responses = (0..decoder.count()?)
        .map(|_| {
            Ok(PendingInnerResponse {
                original_request_envelope_id: decoder.digest()?,
                inner_response_digest: decoder.digest()?,
                inner_response: decoder.bytes(MAX_INNER_RESPONSE_BYTES)?,
            })
        })
        .collect::<Result<Vec<_>, DenialCode>>()?;
    let acknowledged_responses = (0..decoder.count()?)
        .map(|_| {
            Ok(AcknowledgedResponseTombstone {
                original_request_envelope_id: decoder.digest()?,
                inner_response_digest: decoder.digest()?,
            })
        })
        .collect::<Result<Vec<_>, DenialCode>>()?;
    let snapshot = JournalSnapshot {
        lease_checkpoint_id,
        lease_checkpoint,
        prepared_dispatches,
        pending_responses,
        acknowledged_responses,
    };
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn validate_snapshot(snapshot: &JournalSnapshot) -> Result<(), DenialCode> {
    let checkpoint = LeaseRecoveryCheckpoint::from_bytes(snapshot.lease_checkpoint.clone())?;
    let response_slots = snapshot
        .prepared_dispatches
        .len()
        .checked_add(snapshot.pending_responses.len())
        .and_then(|count| count.checked_add(snapshot.acknowledged_responses.len()));
    if snapshot.lease_checkpoint_id == Digest::ZERO
        || checkpoint.checkpoint_id() != snapshot.lease_checkpoint_id
        || snapshot.prepared_dispatches.len() > MAX_ITEMS
        || snapshot.pending_responses.len() > MAX_ITEMS
        || snapshot.acknowledged_responses.len() > MAX_ITEMS
        || response_slots.is_none_or(|count| count > MAX_DURABLE_RESPONSE_SLOTS)
        || !ordered(
            snapshot
                .prepared_dispatches
                .iter()
                .map(|item| item.request_frame_digest),
        )
        || !ordered(
            snapshot
                .pending_responses
                .iter()
                .map(|item| item.original_request_envelope_id),
        )
        || snapshot.prepared_dispatches.iter().any(|item| {
            !valid_identifier(&item.action_id)
                || !valid_identifier(&item.correlation_id)
                || !valid_identifier(&item.grant_id)
                || item.grant_version == 0
                || item.scope_epoch == 0
                || !valid_identifier(&item.lease_id)
                || [
                    item.request_frame_digest,
                    item.control_envelope_id,
                    item.hold_binding_digest,
                    item.intent_digest,
                    item.effect_digest,
                    item.compiled_request_digest,
                ]
                .contains(&Digest::ZERO)
        })
        || snapshot.pending_responses.iter().any(|item| {
            item.original_request_envelope_id == Digest::ZERO
                || item.inner_response.is_empty()
                || Digest::of(&item.inner_response) != item.inner_response_digest
        })
        || snapshot.acknowledged_responses.iter().any(|item| {
            item.original_request_envelope_id == Digest::ZERO
                || item.inner_response_digest == Digest::ZERO
        })
        || !unique(
            snapshot
                .prepared_dispatches
                .iter()
                .map(|item| item.control_envelope_id)
                .chain(
                    snapshot
                        .pending_responses
                        .iter()
                        .map(|item| item.original_request_envelope_id),
                )
                .chain(
                    snapshot
                        .acknowledged_responses
                        .iter()
                        .map(|item| item.original_request_envelope_id),
                ),
        )
    {
        return Err(DenialCode::RecoveryCheckpointInvalid);
    }
    Ok(())
}

fn ordered(values: impl Iterator<Item = Digest>) -> bool {
    let values = values.map(|value| *value.as_bytes()).collect::<Vec<_>>();
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn unique(values: impl Iterator<Item = Digest>) -> bool {
    let values = values.collect::<Vec<_>>();
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}
