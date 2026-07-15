use super::*;

impl LeaseAuthority {
    pub fn revoke_grant(
        &self,
        grant_id: &str,
        grant_version: u64,
        revoked_at_epoch: u64,
    ) -> Result<LeaseRevocationSummary, DenialCode> {
        self.cancel_grant_scope(grant_id, grant_version, revoked_at_epoch, true)
    }

    pub fn interrupt_grant(
        &self,
        grant_id: &str,
        grant_version: u64,
    ) -> Result<LeaseRevocationSummary, DenialCode> {
        self.cancel_grant_scope(grant_id, grant_version, u64::MAX, false)
    }

    fn cancel_grant_scope(
        &self,
        grant_id: &str,
        grant_version: u64,
        invalidated_through_epoch: u64,
        revoke_grant: bool,
    ) -> Result<LeaseRevocationSummary, DenialCode> {
        if !valid_identifier(grant_id) || grant_version == 0 || invalidated_through_epoch == 0 {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        let key = GrantKey {
            grant_id: grant_id.to_owned(),
            grant_version,
        };
        let mut state = self.lock_state()?;
        let previous = state
            .grants
            .get(&key)
            .ok_or(DenialCode::LeaseBindingMismatch)?
            .revoked_at_epoch;
        if previous.is_some_and(|epoch| invalidated_through_epoch <= epoch) {
            return Err(DenialCode::LeaseRevoked);
        }

        let mut available_ids = Vec::new();
        let mut interrupted = Vec::new();
        for (lease_id, entry) in state.leases.iter().filter(|(_, entry)| {
            entry.spec.grant_id == grant_id
                && entry.spec.grant_version == grant_version
                && (revoke_grant || entry.spec.scope_epoch <= invalidated_through_epoch)
        }) {
            match &entry.status {
                LeaseStatus::Available => available_ids.push(lease_id.clone()),
                LeaseStatus::Active { cancellation, .. } => {
                    let retry_invariant_digest = entry
                        .retry_invariant_digest
                        .ok_or(DenialCode::LeaseAccountingUnavailable)?;
                    interrupted.push((
                        lease_id.clone(),
                        entry.spec.intent_digest,
                        entry.spec.effect_digest,
                        entry
                            .spec
                            .hold_binding_digest(&self.lease_key_id, self.boot_challenge_digest),
                        retry_invariant_digest,
                        entry.spec.reservation.clone(),
                        cancellation.clone(),
                    ));
                }
                LeaseStatus::Consumed => {}
            }
        }
        let totals = interrupted
            .iter()
            .try_fold(
                (0_u64, 0_u64, 0_u64, 0_u64),
                |(actions, requests, responses, durations), (_, _, _, _, _, reservation, _)| {
                    Some((
                        actions.checked_add(1)?,
                        requests.checked_add(reservation.request_bytes)?,
                        responses.checked_add(reservation.response_bytes)?,
                        durations.checked_add(reservation.duration_seconds)?,
                    ))
                },
            )
            .ok_or(DenialCode::LeaseAccountingUnavailable)?;
        let account = state
            .grants
            .get(&key)
            .expect("grant existence was checked while the state lock is held");
        if account.usage.active_dispatches < totals.0
            || account.usage.active_reserved_request_bytes < totals.1
            || account.usage.active_reserved_response_bytes < totals.2
            || account.usage.active_reserved_duration_seconds < totals.3
        {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        let mut interrupted_holds = HashMap::with_capacity(interrupted.len());
        for (_, intent, effect, binding_digest, retry_invariant_digest, _, _) in &interrupted {
            let reconciliation_key =
                ReconciliationKey::new(grant_id.to_owned(), grant_version, *intent);
            let hold = ReconciliationHold {
                kind: ReconciliationHoldKind::ControlPlane,
                binding_digest: *binding_digest,
                retry_invariant_digest: *retry_invariant_digest,
            };
            if state
                .held_effects
                .get(&reconciliation_key)
                .is_some_and(|held| held != effect)
                || state
                    .reconciliation_required
                    .get(&reconciliation_key)
                    .is_some_and(|existing| *existing != hold)
                || interrupted_holds
                    .insert(reconciliation_key, hold)
                    .is_some_and(|existing| existing != hold)
            {
                return Err(DenialCode::LeaseAccountingUnavailable);
            }
        }
        for lease_id in available_ids
            .iter()
            .chain(interrupted.iter().map(|value| &value.0))
        {
            state
                .leases
                .get_mut(lease_id)
                .expect("collected lease remains present while state is locked")
                .status = LeaseStatus::Consumed;
        }
        for (_, intent, effect, hold_binding_digest, retry_invariant_digest, _, _) in &interrupted {
            let reconciliation_key =
                ReconciliationKey::new(grant_id.to_owned(), grant_version, *intent);
            state
                .reconciliation_required
                .entry(reconciliation_key.clone())
                .or_insert(ReconciliationHold {
                    kind: ReconciliationHoldKind::ControlPlane,
                    binding_digest: *hold_binding_digest,
                    retry_invariant_digest: *retry_invariant_digest,
                });
            state
                .held_effects
                .entry(reconciliation_key)
                .or_insert(*effect);
        }
        let account = state
            .grants
            .get_mut(&key)
            .expect("grant existence was checked while the state lock is held");
        account.usage.active_dispatches -= totals.0;
        account.usage.active_reserved_request_bytes -= totals.1;
        account.usage.active_reserved_response_bytes -= totals.2;
        account.usage.active_reserved_duration_seconds -= totals.3;
        if revoke_grant {
            account.revoked_at_epoch = Some(invalidated_through_epoch);
        }
        let summary = LeaseRevocationSummary {
            canceled_available: u64::try_from(available_ids.len()).unwrap_or(u64::MAX),
            interrupted_active: u64::try_from(interrupted.len()).unwrap_or(u64::MAX),
        };
        drop(state);
        let mut cancellation_failed = false;
        for (_, _, _, _, _, _, cancellation) in interrupted {
            cancellation_failed |= cancellation.cancel().is_err();
        }
        if cancellation_failed {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        Ok(summary)
    }
}

impl ScopeCancellationSink for LeaseAuthority {
    fn cancel_scope(&self, cancellation: &ScopeCancellation) -> Result<(), DenialCode> {
        self.cancel_scope_with_report(cancellation).map(|_| ())
    }

    fn cancel_scope_with_report(
        &self,
        cancellation: &ScopeCancellation,
    ) -> Result<ScopeCancellationReport, DenialCode> {
        let revoke_grant = match (cancellation.cause, cancellation.revoked_at_epoch) {
            (CancellationCause::ScopeRevoked, Some(epoch))
                if epoch == cancellation.invalidated_through_epoch =>
            {
                true
            }
            (CancellationCause::EpochAdvanced | CancellationCause::EpochExpired, None) => false,
            _ => return Err(DenialCode::LeaseBindingMismatch),
        };
        let summary = self.cancel_grant_scope(
            &cancellation.grant_id,
            cancellation.grant_version,
            cancellation.invalidated_through_epoch,
            revoke_grant,
        )?;
        Ok(ScopeCancellationReport {
            interrupted_active: summary.interrupted_active,
        })
    }
}
