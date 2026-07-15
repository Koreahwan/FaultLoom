use super::*;

pub(super) fn push_count(output: &mut Vec<u8>, count: usize) -> Result<(), DenialCode> {
    if count > MAX_RECOVERY_ITEMS {
        return Err(DenialCode::RecoveryCheckpointInvalid);
    }
    output.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?
            .to_be_bytes(),
    );
    Ok(())
}

pub(super) fn push_reconciliation_holds(
    output: &mut Vec<u8>,
    values: &HashMap<ReconciliationKey, ReconciliationHold>,
) -> Result<(), DenialCode> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by(|(left, _), (right, _)| left.canonical_cmp(right));
    push_count(output, values.len())?;
    for (reconciliation_key, hold) in values {
        if hold.binding_digest == Digest::ZERO || hold.retry_invariant_digest == Digest::ZERO {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        push_reconciliation_key(output, reconciliation_key);
        output.push(hold.kind as u8);
        output.extend_from_slice(hold.binding_digest.as_bytes());
        output.extend_from_slice(hold.retry_invariant_digest.as_bytes());
    }
    Ok(())
}

pub(super) fn push_reconciliation_receipts(
    output: &mut Vec<u8>,
    values: &HashMap<ReconciliationKey, ReconciliationResolution>,
) -> Result<(), DenialCode> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by(|(left, _), (right, _)| left.canonical_cmp(right));
    push_count(output, values.len())?;
    for (key, resolution) in values {
        if resolution.receipt_id == Digest::ZERO
            || resolution.terminal_outcome == DispatchOutcome::UnknownOutcome
            || resolution.hold_binding_digest == Digest::ZERO
            || resolution.effect_digest == Digest::ZERO
            || resolution.retry_invariant_digest == Digest::ZERO
            || (resolution.terminal_outcome == DispatchOutcome::Completed
                && resolution.retry_consumed)
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        push_reconciliation_key(output, key);
        output.extend_from_slice(resolution.receipt_id.as_bytes());
        output.push(resolution.terminal_outcome as u8);
        output.extend_from_slice(resolution.hold_binding_digest.as_bytes());
        output.extend_from_slice(resolution.effect_digest.as_bytes());
        output.extend_from_slice(resolution.retry_invariant_digest.as_bytes());
        output.push(u8::from(resolution.retry_consumed));
    }
    Ok(())
}

pub(super) fn push_effect_digests(
    output: &mut Vec<u8>,
    values: &HashMap<ReconciliationKey, Digest>,
) -> Result<(), DenialCode> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by(|(left, _), (right, _)| left.canonical_cmp(right));
    push_count(output, values.len())?;
    for (key, value) in values {
        if *value == Digest::ZERO {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        push_reconciliation_key(output, key);
        output.extend_from_slice(value.as_bytes());
    }
    Ok(())
}

pub(super) fn push_retry_aliases(
    output: &mut Vec<u8>,
    values: &HashMap<ReconciliationKey, ReconciliationKey>,
) -> Result<(), DenialCode> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by(|(left, _), (right, _)| left.canonical_cmp(right));
    push_count(output, values.len())?;
    for (retry, parent) in values {
        push_reconciliation_key(output, retry);
        push_reconciliation_key(output, parent);
    }
    Ok(())
}

pub(super) fn push_reconciliation_key(output: &mut Vec<u8>, value: &ReconciliationKey) {
    push_string(output, &value.grant_id);
    output.extend_from_slice(&value.grant_version.to_be_bytes());
    output.extend_from_slice(value.intent_digest.as_bytes());
}

pub(super) fn recovery_checkpoint_id(encoded: &[u8]) -> Digest {
    let mut canonical = Vec::with_capacity(encoded.len() + 48);
    canonical.extend_from_slice(b"faultloom-lease-recovery-checkpoint-id-v7\0");
    canonical.extend_from_slice(encoded);
    Digest::of(&canonical)
}
