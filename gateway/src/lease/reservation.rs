use super::*;

impl LeaseAuthority {
    pub(super) fn reserve_dispatch(
        &self,
        request: &DispatchRequest,
        now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        let mut state = self.lock_state()?;
        let entry = state
            .leases
            .get(&request.lease_id)
            .cloned()
            .ok_or(DenialCode::LeaseDenied)?;
        if !constant_time_eq(entry.proof.as_bytes(), &request.lease_proof) {
            return Err(DenialCode::LeaseDenied);
        }
        if entry.spec.intent_digest != request.intent_digest
            || entry.spec.decision_digest != request.decision_digest
            || entry.spec.grant_id != request.grant_id
            || entry.spec.grant_version != request.grant_version
            || entry.spec.scope_epoch != request.scope_epoch
            || entry.spec.request_binding_digest != request.lease_binding_digest()
            || entry.spec.semantic_action_digest != request.semantic_action_digest
            || entry.spec.resolution_digest != request.resolution_digest
            || entry.spec.correlation_id != request.correlation_id
            || entry.spec.egress_plane != request.egress_plane
            || entry.spec.dispatch_nonce != request.dispatch_nonce
            || entry.spec.issued_at_millis != request.request_issued_at_millis
            || entry.spec.expires_at_millis != request.request_expires_at_millis
            || entry.spec.retry_of_intent_digest != request.retry_of_intent_digest
        {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        if now_millis < entry.spec.issued_at_millis {
            return Err(DenialCode::LeaseNotYetValid);
        }
        if now_millis >= entry.spec.expires_at_millis {
            return Err(DenialCode::LeaseExpired);
        }
        if entry.status != LeaseStatus::Available {
            return Err(DenialCode::LeaseReplay);
        }
        let intent_key = ReconciliationKey::from_spec(&entry.spec);
        if state.reconciliation_required.contains_key(&intent_key) {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        if state.held_effects.iter().any(|(key, effect)| {
            key.grant_id == entry.spec.grant_id
                && key.grant_version == entry.spec.grant_version
                && *effect == entry.spec.effect_digest
        }) {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        let retry_invariant_digest = self.retry_invariant_digest(request, &entry.spec);
        let retry_parent_key = if let Some(parent) = entry.spec.retry_of_intent_digest {
            let parent_key = ReconciliationKey::new(
                entry.spec.grant_id.clone(),
                entry.spec.grant_version,
                parent,
            );
            if state.retry_aliases.contains_key(&intent_key)
                || state
                    .reconciliation_receipts
                    .get(&parent_key)
                    .is_none_or(|resolution| {
                        resolution.terminal_outcome != DispatchOutcome::Failed
                            || resolution.retry_consumed
                            || resolution.effect_digest != entry.spec.effect_digest
                            || resolution.retry_invariant_digest != retry_invariant_digest
                    })
            {
                return Err(DenialCode::RetryAliasInvalid);
            }
            Some(parent_key)
        } else {
            None
        };
        let request_bytes = u64::try_from(request.payload.len())
            .map_err(|_| DenialCode::LeaseReservationExceeded)?;
        if request_bytes > entry.spec.reservation.request_bytes {
            return Err(DenialCode::LeaseReservationExceeded);
        }

        let key = GrantKey {
            grant_id: entry.spec.grant_id.clone(),
            grant_version: entry.spec.grant_version,
        };
        let (reserved_request_bytes, reserved_response_bytes, reserved_duration_seconds) = {
            let account = state
                .grants
                .get_mut(&key)
                .ok_or(DenialCode::LeaseBindingMismatch)?;
            if account.revoked_at_epoch.is_some() {
                return Err(DenialCode::LeaseRevoked);
            }
            if now_millis < account.last_clock_millis {
                return Err(DenialCode::LeaseAccountingUnavailable);
            }
            account.last_clock_millis = now_millis;
            let cutoff = now_millis.saturating_sub(RATE_WINDOW_MILLIS);
            while account
                .dispatch_times
                .front()
                .is_some_and(|timestamp| *timestamp <= cutoff)
            {
                account.dispatch_times.pop_front();
            }
            if account.usage.dispatched_actions >= account.budget.total_actions {
                return Err(DenialCode::GrantBudgetExhausted);
            }
            if u64::try_from(account.dispatch_times.len()).unwrap_or(u64::MAX)
                >= account.budget.rate_per_minute
            {
                return Err(DenialCode::LeaseRateExceeded);
            }
            if account.usage.active_dispatches >= account.budget.max_concurrency {
                return Err(DenialCode::LeaseConcurrencyExceeded);
            }

            let reserved_request_bytes = account
                .usage
                .active_reserved_request_bytes
                .checked_add(entry.spec.reservation.request_bytes)
                .ok_or(DenialCode::LeaseAccountingUnavailable)?;
            let reserved_response_bytes = account
                .usage
                .active_reserved_response_bytes
                .checked_add(entry.spec.reservation.response_bytes)
                .ok_or(DenialCode::LeaseAccountingUnavailable)?;
            let reserved_duration_seconds = account
                .usage
                .active_reserved_duration_seconds
                .checked_add(entry.spec.reservation.duration_seconds)
                .ok_or(DenialCode::LeaseAccountingUnavailable)?;
            (
                reserved_request_bytes,
                reserved_response_bytes,
                reserved_duration_seconds,
            )
        };

        let reservation_token = self.reservation_token(&entry, now_millis);
        let cancellation = DispatchCancellation::new();
        let hold_binding_digest = entry
            .spec
            .hold_binding_digest(&self.lease_key_id, self.boot_challenge_digest);
        if let Some(parent_key) = retry_parent_key {
            state
                .reconciliation_receipts
                .get_mut(&parent_key)
                .expect("retry parent was validated while the state lock is held")
                .retry_consumed = true;
            state.retry_aliases.insert(intent_key, parent_key);
        }
        let account = state
            .grants
            .get_mut(&key)
            .expect("grant existence was checked while the state lock is held");
        account.usage.dispatched_actions += 1;
        account.usage.active_dispatches += 1;
        account.usage.active_reserved_request_bytes = reserved_request_bytes;
        account.usage.active_reserved_response_bytes = reserved_response_bytes;
        account.usage.active_reserved_duration_seconds = reserved_duration_seconds;
        account.dispatch_times.push_back(now_millis);
        let active_entry = state
            .leases
            .get_mut(&entry.spec.lease_id)
            .expect("lease exists while state lock is held");
        active_entry.status = LeaseStatus::Active {
            reservation_token,
            cancellation: cancellation.clone(),
        };
        active_entry.retry_invariant_digest = Some(retry_invariant_digest);

        Ok(LeaseApproval {
            intent_digest: entry.spec.intent_digest,
            decision_digest: entry.spec.decision_digest,
            grant_id: entry.spec.grant_id,
            grant_version: entry.spec.grant_version,
            lease_id: entry.spec.lease_id,
            scope_epoch: entry.spec.scope_epoch,
            authority_key_id: entry.spec.authority_key_id,
            scope_epoch_binding_digest: entry.spec.scope_epoch_binding_digest,
            lease_key_id: self.lease_key_id.clone(),
            gateway_boot_id: entry.spec.gateway_boot_id,
            boot_challenge_digest: self.boot_challenge_digest,
            control_envelope_id: entry.spec.control_envelope_id,
            request_binding_digest: entry.spec.request_binding_digest,
            semantic_action_digest: entry.spec.semantic_action_digest,
            resolution_digest: entry.spec.resolution_digest,
            compiled_request_digest: entry.spec.compiled_request_digest,
            effect_digest: entry.spec.effect_digest,
            hold_binding_digest,
            retry_invariant_digest,
            correlation_id: entry.spec.correlation_id,
            egress_plane: entry.spec.egress_plane,
            dispatch_nonce: entry.spec.dispatch_nonce,
            issued_at_millis: entry.spec.issued_at_millis,
            expires_at_millis: entry.spec.expires_at_millis,
            retry_of_intent_digest: entry.spec.retry_of_intent_digest,
            maximum_dispatches: 1,
            reservation: entry.spec.reservation,
            reservation_token,
            cancellation,
        })
    }
}
