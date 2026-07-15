use super::*;

impl LeaseAuthority {
    pub fn register_grant(
        &self,
        grant_id: &str,
        grant_version: u64,
        budget: GrantBudget,
    ) -> Result<(), DenialCode> {
        if !valid_identifier(grant_id) || grant_version == 0 || !budget.valid() {
            return Err(DenialCode::LeaseReservationExceeded);
        }
        let key = GrantKey {
            grant_id: grant_id.to_owned(),
            grant_version,
        };
        let mut state = self.lock_state()?;
        if state.grants.contains_key(&key) {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        state.grants.insert(
            key,
            GrantAccount {
                budget,
                usage: GrantUsage::default(),
                dispatch_times: VecDeque::new(),
                last_clock_millis: 0,
                revoked_at_epoch: None,
            },
        );
        Ok(())
    }

    pub(crate) fn preflight_issue(
        &self,
        grant_id: &str,
        grant_version: u64,
        intent_digest: Digest,
    ) -> Result<(), DenialCode> {
        if !valid_identifier(grant_id) || grant_version == 0 || intent_digest == Digest::ZERO {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        let state = self.lock_state()?;
        let key = ReconciliationKey::new(grant_id.to_owned(), grant_version, intent_digest);
        match held_effect_for_exact_key(&state, &key)? {
            Some(_) => Err(DenialCode::LeaseReconciliationRequired),
            None => Ok(()),
        }
    }

    pub fn issue(&self, spec: LeaseSpec) -> Result<IssuedLease, DenialCode> {
        if !valid_identifier(&spec.lease_id)
            || !valid_identifier(&spec.grant_id)
            || !valid_identifier(&spec.authority_key_id)
            || !valid_identifier(&spec.gateway_boot_id)
            || !valid_identifier(&spec.correlation_id)
            || spec.grant_version == 0
            || spec.scope_epoch == 0
            || spec.scope_epoch_binding_digest == Digest::ZERO
            || spec.control_envelope_id == Digest::ZERO
            || spec.request_binding_digest == Digest::ZERO
            || spec.semantic_action_digest == Digest::ZERO
            || spec.resolution_digest == Digest::ZERO
            || spec.compiled_request_digest == Digest::ZERO
            || spec.effect_digest == Digest::ZERO
            || !valid_nonce(&spec.dispatch_nonce)
            || spec.retry_of_intent_digest == Some(Digest::ZERO)
            || spec.retry_of_intent_digest == Some(spec.intent_digest)
            || spec.gateway_boot_id != self.gateway_boot_id
            || spec.issued_at_millis >= spec.expires_at_millis
            || spec.expires_at_millis.saturating_sub(spec.issued_at_millis) > MAX_LEASE_TTL_MILLIS
            || spec.intent_digest == Digest::ZERO
            || spec.decision_digest == Digest::ZERO
        {
            return Err(DenialCode::LeaseBindingMismatch);
        }

        let grant_key = GrantKey {
            grant_id: spec.grant_id.clone(),
            grant_version: spec.grant_version,
        };
        let mut state = self.lock_state()?;
        let account = state
            .grants
            .get(&grant_key)
            .ok_or(DenialCode::LeaseBindingMismatch)?;
        if account.revoked_at_epoch.is_some() {
            return Err(DenialCode::LeaseRevoked);
        }
        if spec.reservation.action_count != 1
            || spec.reservation.request_bytes == 0
            || spec.reservation.request_bytes > account.budget.max_request_bytes
            || spec.reservation.response_bytes > account.budget.max_response_bytes
            || spec.reservation.duration_seconds == 0
            || spec.reservation.duration_seconds > account.budget.max_duration_seconds
        {
            return Err(DenialCode::LeaseReservationExceeded);
        }
        if state.leases.contains_key(&spec.lease_id)
            || state.retired_lease_ids.contains(&spec.lease_id)
            || state.dispatch_nonces.contains(&spec.dispatch_nonce)
        {
            return Err(DenialCode::LeaseReplay);
        }
        let intent_key = ReconciliationKey::from_spec(&spec);
        match held_effect_for_exact_key(&state, &intent_key)? {
            Some(held_effect) if held_effect == spec.effect_digest => {
                return Err(DenialCode::LeaseReconciliationRequired);
            }
            Some(_) => return Err(DenialCode::LeaseBindingMismatch),
            None => {}
        }
        if state
            .leases
            .values()
            .any(|entry| ReconciliationKey::from_spec(&entry.spec) == intent_key)
            || state.reconciliation_required.contains_key(&intent_key)
            || state.reconciliation_receipts.contains_key(&intent_key)
            || state.retry_aliases.contains_key(&intent_key)
            || state.retired_intents.contains(&intent_key)
        {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        if let Some(parent_intent) = spec.retry_of_intent_digest {
            let parent_key =
                ReconciliationKey::new(spec.grant_id.clone(), spec.grant_version, parent_intent);
            if state
                .reconciliation_receipts
                .get(&parent_key)
                .is_none_or(|resolution| {
                    resolution.terminal_outcome != DispatchOutcome::Failed
                        || resolution.retry_consumed
                })
                || state.retry_aliases.contains_key(&intent_key)
            {
                return Err(DenialCode::RetryAliasInvalid);
            }
        }

        let proof = self.sign_spec(&spec);
        let lease_id = spec.lease_id.clone();
        state.retired_intents.insert(intent_key);
        state.dispatch_nonces.insert(spec.dispatch_nonce);
        state.retired_lease_ids.insert(lease_id.clone());
        state.leases.insert(
            lease_id.clone(),
            LeaseEntry {
                spec,
                proof,
                status: LeaseStatus::Available,
                retry_invariant_digest: None,
            },
        );
        Ok(IssuedLease {
            lease_id,
            lease_key_id: self.lease_key_id.clone(),
            gateway_boot_id: self.gateway_boot_id.clone(),
            boot_challenge_digest: self.boot_challenge_digest,
            proof: proof.as_bytes().to_vec(),
        })
    }

    pub fn usage(&self, grant_id: &str, grant_version: u64) -> Result<GrantUsage, DenialCode> {
        let state = self.lock_state()?;
        let key = GrantKey {
            grant_id: grant_id.to_owned(),
            grant_version,
        };
        state
            .grants
            .get(&key)
            .map(|account| {
                let mut usage = account.usage.clone();
                usage.rate_window_actions =
                    u64::try_from(account.dispatch_times.len()).unwrap_or(u64::MAX);
                usage
            })
            .ok_or(DenialCode::LeaseBindingMismatch)
    }
}
