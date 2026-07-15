use super::*;

impl LeaseRecoveryCheckpoint {
    pub fn from_bytes(encoded: Vec<u8>) -> Result<Self, DenialCode> {
        if encoded.len() < 4 + 1 + 4 + 32 || encoded.len() > MAX_RECOVERY_BYTES {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        if &encoded[..4] != RECOVERY_MAGIC || encoded[4] != RECOVERY_VERSION {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let payload_len = u32::from_be_bytes(
            encoded[5..9]
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ) as usize;
        if payload_len.checked_add(4 + 1 + 4 + 32) != Some(encoded.len()) {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let checkpoint_id = recovery_checkpoint_id(&encoded);
        Ok(Self {
            encoded,
            checkpoint_id,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    pub const fn checkpoint_id(&self) -> Digest {
        self.checkpoint_id
    }
}

impl LeaseAuthority {
    /// Seal the durable accounting state. Active reservations are restored as
    /// unknown outcomes, never as dispatchable leases.
    pub fn checkpoint(&self) -> Result<LeaseRecoveryCheckpoint, DenialCode> {
        let mut state = self.lock_state()?;
        for count in [
            state.grants.len(),
            state.reconciliation_required.len(),
            state.held_effects.len(),
            state.reconciliation_receipts.len(),
            state.retry_aliases.len(),
            state.dispatch_nonces.len(),
            state.retired_lease_ids.len(),
            state.retired_intents.len(),
        ] {
            if count > MAX_RECOVERY_ITEMS {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        if state.retired_intents.len() != state.dispatch_nonces.len()
            || state.retired_intents.len() != state.retired_lease_ids.len()
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let checkpoint_sequence = state
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(DenialCode::RecoveryCheckpointInvalid)?;

        let mut payload = Vec::new();
        payload.extend_from_slice(b"faultloom-lease-recovery-state-v7\0");
        push_string(&mut payload, &self.lease_key_id);
        push_string(&mut payload, &self.gateway_boot_id);
        payload.extend_from_slice(self.boot_challenge_digest.as_bytes());
        payload.extend_from_slice(&checkpoint_sequence.to_be_bytes());

        let mut grants: Vec<_> = state.grants.iter().collect();
        grants.sort_by(|(left, _), (right, _)| {
            left.grant_id
                .cmp(&right.grant_id)
                .then(left.grant_version.cmp(&right.grant_version))
        });
        push_count(&mut payload, grants.len())?;
        for (key, account) in grants {
            push_string(&mut payload, &key.grant_id);
            payload.extend_from_slice(&key.grant_version.to_be_bytes());
            for value in [
                account.budget.total_actions,
                account.budget.rate_per_minute,
                account.budget.max_concurrency,
                account.budget.max_request_bytes,
                account.budget.max_response_bytes,
                account.budget.max_duration_seconds,
                account.usage.dispatched_actions,
                account.usage.actual_request_bytes,
                account.usage.actual_response_bytes,
                account.usage.actual_duration_millis,
                account.last_clock_millis,
            ] {
                payload.extend_from_slice(&value.to_be_bytes());
            }
            push_optional_u64(&mut payload, account.revoked_at_epoch);
            push_count(&mut payload, account.dispatch_times.len())?;
            for timestamp in &account.dispatch_times {
                payload.extend_from_slice(&timestamp.to_be_bytes());
            }
        }

        let mut holds = state.reconciliation_required.clone();
        let mut held_effects = state.held_effects.clone();
        if holds.keys().collect::<HashSet<_>>() != held_effects.keys().collect::<HashSet<_>>() {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        for entry in state
            .leases
            .values()
            .filter(|entry| matches!(entry.status, LeaseStatus::Active { .. }))
        {
            let reconciliation_key = ReconciliationKey::from_spec(&entry.spec);
            let effect_digest = entry.spec.effect_digest;
            let hold = ReconciliationHold {
                kind: ReconciliationHoldKind::ControlPlane,
                binding_digest: entry
                    .spec
                    .hold_binding_digest(&self.lease_key_id, self.boot_challenge_digest),
                retry_invariant_digest: entry
                    .retry_invariant_digest
                    .ok_or(DenialCode::RecoveryCheckpointInvalid)?,
            };
            if held_effects
                .get(&reconciliation_key)
                .is_some_and(|held| *held != effect_digest)
            {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
            if holds
                .get(&reconciliation_key)
                .is_some_and(|existing| *existing != hold)
            {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
            holds.entry(reconciliation_key.clone()).or_insert(hold);
            held_effects
                .entry(reconciliation_key)
                .or_insert(effect_digest);
        }
        if holds.keys().any(|key| !state.retired_intents.contains(key))
            || state
                .reconciliation_receipts
                .keys()
                .any(|key| !state.retired_intents.contains(key))
            || state.retry_aliases.iter().any(|(retry, parent)| {
                !state.retired_intents.contains(retry) || !state.retired_intents.contains(parent)
            })
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        push_reconciliation_holds(&mut payload, &holds)?;
        push_effect_digests(&mut payload, &held_effects)?;
        push_reconciliation_receipts(&mut payload, &state.reconciliation_receipts)?;
        push_retry_aliases(&mut payload, &state.retry_aliases)?;

        let mut nonces: Vec<_> = state.dispatch_nonces.iter().copied().collect();
        nonces.sort_unstable();
        push_count(&mut payload, nonces.len())?;
        for nonce in nonces {
            payload.extend_from_slice(&nonce);
        }

        let mut retired: Vec<_> = state.retired_lease_ids.iter().collect();
        retired.sort_unstable();
        push_count(&mut payload, retired.len())?;
        for lease_id in retired {
            push_string(&mut payload, lease_id);
        }

        let mut retired_intents: Vec<_> = state.retired_intents.iter().collect();
        retired_intents.sort_unstable_by(|left, right| left.canonical_cmp(right));
        push_count(&mut payload, retired_intents.len())?;
        for intent_key in retired_intents {
            if intent_key.intent_digest == Digest::ZERO
                || !state.grants.contains_key(&GrantKey {
                    grant_id: intent_key.grant_id.clone(),
                    grant_version: intent_key.grant_version,
                })
            {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
            push_reconciliation_key(&mut payload, intent_key);
        }

        let mut authenticated = Vec::with_capacity(payload.len() + 48);
        authenticated.extend_from_slice(b"faultloom-lease-recovery-checkpoint-v7\0");
        authenticated.extend_from_slice(&payload);
        let tag = hmac_sha256(&self.signing_key, &authenticated);
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| DenialCode::RecoveryCheckpointInvalid)?;
        let mut encoded = Vec::with_capacity(9 + payload.len() + 32);
        encoded.extend_from_slice(RECOVERY_MAGIC);
        encoded.push(RECOVERY_VERSION);
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&payload);
        encoded.extend_from_slice(tag.as_bytes());
        if encoded.len() > MAX_RECOVERY_BYTES {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let checkpoint = LeaseRecoveryCheckpoint::from_bytes(encoded)?;
        state.checkpoint_sequence = checkpoint_sequence;
        Ok(checkpoint)
    }
}
