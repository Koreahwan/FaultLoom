use super::*;

impl LeaseAuthority {
    fn active_spec_and_key(
        state: &mut LeaseState,
        approval: &LeaseApproval,
    ) -> Result<(LeaseSpec, GrantKey), DenialCode> {
        let entry = state
            .leases
            .get(&approval.lease_id)
            .ok_or(DenialCode::LeaseAccountingUnavailable)?;
        if entry.spec.intent_digest != approval.intent_digest
            || entry.spec.decision_digest != approval.decision_digest
            || entry.spec.grant_id != approval.grant_id
            || entry.spec.grant_version != approval.grant_version
            || entry.spec.scope_epoch != approval.scope_epoch
            || entry.spec.authority_key_id != approval.authority_key_id
            || entry.spec.scope_epoch_binding_digest != approval.scope_epoch_binding_digest
            || approval.lease_key_id.is_empty()
            || entry.spec.gateway_boot_id != approval.gateway_boot_id
            || entry.spec.control_envelope_id != approval.control_envelope_id
            || entry.spec.request_binding_digest != approval.request_binding_digest
            || entry.spec.semantic_action_digest != approval.semantic_action_digest
            || entry.spec.resolution_digest != approval.resolution_digest
            || entry.spec.compiled_request_digest != approval.compiled_request_digest
            || entry.spec.effect_digest != approval.effect_digest
            || approval.retry_invariant_digest == Digest::ZERO
            || entry.retry_invariant_digest != Some(approval.retry_invariant_digest)
            || entry
                .spec
                .hold_binding_digest(&approval.lease_key_id, approval.boot_challenge_digest)
                != approval.hold_binding_digest
            || entry.spec.correlation_id != approval.correlation_id
            || entry.spec.egress_plane != approval.egress_plane
            || entry.spec.dispatch_nonce != approval.dispatch_nonce
            || entry.spec.issued_at_millis != approval.issued_at_millis
            || entry.spec.expires_at_millis != approval.expires_at_millis
            || entry.spec.retry_of_intent_digest != approval.retry_of_intent_digest
            || entry.spec.reservation != approval.reservation
            || entry.status
                != (LeaseStatus::Active {
                    reservation_token: approval.reservation_token,
                    cancellation: approval.cancellation.clone(),
                })
        {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        let spec = entry.spec.clone();
        let key = GrantKey {
            grant_id: spec.grant_id.clone(),
            grant_version: spec.grant_version,
        };
        let account = state
            .grants
            .get(&key)
            .ok_or(DenialCode::LeaseAccountingUnavailable)?;
        if account.usage.active_dispatches == 0
            || account.usage.active_reserved_request_bytes < spec.reservation.request_bytes
            || account.usage.active_reserved_response_bytes < spec.reservation.response_bytes
            || account.usage.active_reserved_duration_seconds < spec.reservation.duration_seconds
        {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        Ok((spec, key))
    }

    fn release_active(
        state: &mut LeaseState,
        approval: &LeaseApproval,
    ) -> Result<(LeaseSpec, GrantKey), DenialCode> {
        let (spec, key) = Self::active_spec_and_key(state, approval)?;
        state
            .leases
            .get_mut(&approval.lease_id)
            .expect("lease existence was checked while the state lock is held")
            .status = LeaseStatus::Consumed;
        let account = state
            .grants
            .get_mut(&key)
            .expect("grant existence was checked while the state lock is held");
        account.usage.active_dispatches -= 1;
        account.usage.active_reserved_request_bytes -= spec.reservation.request_bytes;
        account.usage.active_reserved_response_bytes -= spec.reservation.response_bytes;
        account.usage.active_reserved_duration_seconds -= spec.reservation.duration_seconds;
        Ok((spec, key))
    }

    pub(super) fn abandon_dispatch(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        let mut state = self.lock_state()?;
        Self::release_active(&mut state, approval)?;
        Ok(())
    }

    pub(super) fn finalize_dispatch(
        &self,
        approval: &LeaseApproval,
        completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        let mut state = self.lock_state()?;
        let (spec, key) = Self::active_spec_and_key(&mut state, approval)?;
        let account = state
            .grants
            .get(&key)
            .ok_or(DenialCode::LeaseAccountingUnavailable)?;
        let request_total = account
            .usage
            .actual_request_bytes
            .checked_add(completion.bytes_sent);
        let response_total = account
            .usage
            .actual_response_bytes
            .checked_add(completion.bytes_received);
        let duration_total = account
            .usage
            .actual_duration_millis
            .checked_add(completion.elapsed_millis);
        let accounting_overflow =
            request_total.is_none() || response_total.is_none() || duration_total.is_none();
        let duration_limit_millis = spec.reservation.duration_seconds.saturating_mul(1_000);
        let reservation_overrun = completion.bytes_sent > spec.reservation.request_bytes
            || completion.bytes_received > spec.reservation.response_bytes
            || completion.elapsed_millis > duration_limit_millis
            || accounting_overflow;
        let reconciliation_required =
            completion.outcome == DispatchOutcome::UnknownOutcome || reservation_overrun;
        let reconciliation_key = ReconciliationKey::from_spec(&spec);
        let hold = ReconciliationHold {
            kind: ReconciliationHoldKind::DispatchReceipt,
            binding_digest: approval.hold_binding_digest,
            retry_invariant_digest: approval.retry_invariant_digest,
        };
        if reconciliation_required
            && (state.held_effects.contains_key(&reconciliation_key)
                || state
                    .reconciliation_required
                    .contains_key(&reconciliation_key)
                || state
                    .reconciliation_receipts
                    .contains_key(&reconciliation_key))
        {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }

        Self::release_active(&mut state, approval)?;
        let account = state
            .grants
            .get_mut(&key)
            .expect("grant existence was validated while the state lock is held");
        account.usage.actual_request_bytes = request_total.unwrap_or(u64::MAX);
        account.usage.actual_response_bytes = response_total.unwrap_or(u64::MAX);
        account.usage.actual_duration_millis = duration_total.unwrap_or(u64::MAX);
        if reconciliation_required {
            state
                .reconciliation_required
                .insert(reconciliation_key.clone(), hold);
            state
                .held_effects
                .entry(reconciliation_key)
                .or_insert(spec.effect_digest);
        }
        Ok(LeaseFinalization {
            reconciliation_required,
            reservation_overrun,
        })
    }

    pub(super) fn authenticate_dispatch_receipt(
        &self,
        approval: &LeaseApproval,
        receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        if receipt.receipt_id != receipt.canonical_id()
            || receipt.receipt_authentication_tag != Digest::ZERO
            || !Self::receipt_matches_approval(receipt, approval)
        {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        Ok(self.dispatch_receipt_authentication_tag(receipt))
    }
}
