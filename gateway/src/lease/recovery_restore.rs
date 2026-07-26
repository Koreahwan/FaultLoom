use super::*;

impl LeaseAuthority {
    /// Restore only into a fresh authority boot and only for the externally
    /// anchored checkpoint digest supplied by the durable control plane.
    pub fn restore_checkpoint(
        &self,
        checkpoint: &LeaseRecoveryCheckpoint,
        expected_checkpoint_id: Digest,
    ) -> Result<(), DenialCode> {
        if checkpoint.checkpoint_id() != expected_checkpoint_id {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let encoded = checkpoint.as_bytes();
        let payload_len = u32::from_be_bytes(
            encoded[5..9]
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ) as usize;
        let payload = &encoded[9..9 + payload_len];
        let supplied_tag = &encoded[9 + payload_len..];
        let mut authenticated = Vec::with_capacity(payload.len() + 48);
        authenticated.extend_from_slice(b"faultloom-lease-recovery-checkpoint-v7\0");
        authenticated.extend_from_slice(payload);
        let expected_tag = hmac_sha256(&self.signing_key, &authenticated);
        if !constant_time_eq(expected_tag.as_bytes(), supplied_tag) {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }

        let mut decoder = RecoveryDecoder::new(payload);
        decoder.expect_prefix(b"faultloom-lease-recovery-state-v7\0")?;
        let key_id = decoder.string()?;
        let source_boot_id = decoder.string()?;
        let source_challenge = decoder.digest()?;
        let checkpoint_sequence = decoder.u64()?;
        if key_id != self.lease_key_id
            || source_boot_id == self.gateway_boot_id
            || !valid_identifier(&source_boot_id)
            || source_challenge == Digest::ZERO
            || checkpoint_sequence == 0
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }

        let mut restored = LeaseState {
            checkpoint_sequence,
            ..LeaseState::default()
        };
        let grant_count = decoder.count()?;
        for _ in 0..grant_count {
            let key = GrantKey {
                grant_id: decoder.string()?,
                grant_version: decoder.u64()?,
            };
            let budget = GrantBudget {
                total_actions: decoder.u64()?,
                rate_per_minute: decoder.u64()?,
                max_concurrency: decoder.u64()?,
                max_request_bytes: decoder.u64()?,
                max_response_bytes: decoder.u64()?,
                max_duration_seconds: decoder.u64()?,
            };
            let usage = GrantUsage {
                dispatched_actions: decoder.u64()?,
                actual_request_bytes: decoder.u64()?,
                actual_response_bytes: decoder.u64()?,
                actual_duration_millis: decoder.u64()?,
                ..GrantUsage::default()
            };
            let last_clock_millis = decoder.u64()?;
            let revoked_at_epoch = decoder.optional_u64()?;
            let dispatch_count = decoder.count()?;
            let mut dispatch_times = VecDeque::with_capacity(dispatch_count);
            for _ in 0..dispatch_count {
                dispatch_times.push_back(decoder.u64()?);
            }
            if !valid_identifier(&key.grant_id)
                || key.grant_version == 0
                || !budget.valid()
                || usage.dispatched_actions > budget.total_actions
                || dispatch_times.len() > MAX_RECOVERY_ITEMS
                || dispatch_times
                    .iter()
                    .any(|timestamp| *timestamp > last_clock_millis)
                || !dispatch_times
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .all(|pair| pair[0] <= pair[1])
                || restored
                    .grants
                    .insert(
                        key,
                        GrantAccount {
                            budget,
                            usage,
                            dispatch_times,
                            last_clock_millis,
                            revoked_at_epoch,
                        },
                    )
                    .is_some()
            {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }

        restored.reconciliation_required = decoder.reconciliation_holds()?;
        restored.held_effects = decoder.effect_digests()?;
        restored.reconciliation_receipts = decoder.reconciliation_receipts()?;
        restored.retry_aliases = decoder.retry_aliases()?;
        let registered_grant = |key: &ReconciliationKey| {
            restored.grants.contains_key(&GrantKey {
                grant_id: key.grant_id.clone(),
                grant_version: key.grant_version,
            })
        };
        let unique_receipt_count = restored
            .reconciliation_receipts
            .values()
            .map(|resolution| resolution.receipt_id)
            .collect::<HashSet<_>>()
            .len();
        let alias_parents: HashSet<_> = restored.retry_aliases.values().cloned().collect();
        let consumed_parents: HashSet<_> = restored
            .reconciliation_receipts
            .iter()
            .filter(|(_, resolution)| resolution.retry_consumed)
            .map(|(key, _)| key.clone())
            .collect();
        if restored.reconciliation_required.iter().any(|(key, hold)| {
            !registered_grant(key)
                || restored.reconciliation_receipts.contains_key(key)
                || hold.binding_digest == Digest::ZERO
                || hold.retry_invariant_digest == Digest::ZERO
        }) || restored
            .reconciliation_required
            .keys()
            .collect::<HashSet<_>>()
            != restored.held_effects.keys().collect::<HashSet<_>>()
            || restored
                .held_effects
                .values()
                .any(|digest| *digest == Digest::ZERO)
            || restored
                .reconciliation_receipts
                .iter()
                .any(|(key, resolution)| {
                    !registered_grant(key)
                        || resolution.receipt_id == Digest::ZERO
                        || resolution.terminal_outcome == DispatchOutcome::UnknownOutcome
                        || resolution.hold_binding_digest == Digest::ZERO
                        || resolution.effect_digest == Digest::ZERO
                        || resolution.retry_invariant_digest == Digest::ZERO
                        || (resolution.terminal_outcome == DispatchOutcome::Completed
                            && resolution.retry_consumed)
                })
            || unique_receipt_count != restored.reconciliation_receipts.len()
            || alias_parents.len() != restored.retry_aliases.len()
            || alias_parents != consumed_parents
            || restored.retry_aliases.iter().any(|(retry, parent)| {
                !registered_grant(retry)
                    || !registered_grant(parent)
                    || retry == parent
                    || retry.grant_id != parent.grant_id
                    || retry.grant_version != parent.grant_version
                    || restored
                        .reconciliation_receipts
                        .get(parent)
                        .is_none_or(|resolution| {
                            resolution.terminal_outcome != DispatchOutcome::Failed
                                || !resolution.retry_consumed
                        })
            })
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let nonce_count = decoder.count()?;
        for _ in 0..nonce_count {
            let nonce = decoder.nonce()?;
            if !valid_nonce(&nonce) || !restored.dispatch_nonces.insert(nonce) {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        let retired_count = decoder.count()?;
        for _ in 0..retired_count {
            let lease_id = decoder.string()?;
            if !valid_identifier(&lease_id) || !restored.retired_lease_ids.insert(lease_id) {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        let retired_intent_count = decoder.count()?;
        for _ in 0..retired_intent_count {
            let intent_key = decoder.reconciliation_key()?;
            if !restored.retired_intents.insert(intent_key) {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        decoder.finish()?;
        if restored.retired_intents.len() != restored.dispatch_nonces.len()
            || restored.retired_intents.len() != restored.retired_lease_ids.len()
            || restored.retired_intents.iter().any(|key| {
                !restored.grants.contains_key(&GrantKey {
                    grant_id: key.grant_id.clone(),
                    grant_version: key.grant_version,
                })
            })
            || restored
                .reconciliation_required
                .keys()
                .any(|key| !restored.retired_intents.contains(key))
            || restored
                .reconciliation_receipts
                .keys()
                .any(|key| !restored.retired_intents.contains(key))
            || restored.retry_aliases.iter().any(|(retry, parent)| {
                !restored.retired_intents.contains(retry)
                    || !restored.retired_intents.contains(parent)
            })
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }

        let mut state = self.lock_state()?;
        if !state.grants.is_empty()
            || !state.leases.is_empty()
            || !state.reconciliation_required.is_empty()
            || !state.held_effects.is_empty()
            || !state.reconciliation_receipts.is_empty()
            || !state.retry_aliases.is_empty()
            || !state.dispatch_nonces.is_empty()
            || !state.retired_lease_ids.is_empty()
            || !state.retired_intents.is_empty()
            || state.checkpoint_sequence != 0
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        *state = restored;
        Ok(())
    }
}
