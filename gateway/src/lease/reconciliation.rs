use super::*;

impl LeaseAuthority {
    pub fn reconcile(
        &self,
        unknown_receipt: &DispatchReceipt,
        reconciliation: &ReconciliationReceipt,
    ) -> Result<(), DenialCode> {
        self.verify_dispatch_receipt(unknown_receipt)?;
        if unknown_receipt.outcome != DispatchOutcome::UnknownOutcome
            || !unknown_receipt.reconciliation_required
        {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        self.reconcile_bound(Some(unknown_receipt), reconciliation)
    }

    pub fn reconcile_control_plane_hold(
        &self,
        reconciliation: &ReconciliationReceipt,
    ) -> Result<(), DenialCode> {
        self.reconcile_bound(None, reconciliation)
    }

    fn reconcile_bound(
        &self,
        unknown_receipt: Option<&DispatchReceipt>,
        reconciliation: &ReconciliationReceipt,
    ) -> Result<(), DenialCode> {
        self.verify_reconciliation_authorization(unknown_receipt, reconciliation)?;
        let expected_hold_kind = if unknown_receipt.is_some() {
            ReconciliationHoldKind::DispatchReceipt
        } else {
            ReconciliationHoldKind::ControlPlane
        };
        let reconciliation_key = ReconciliationKey::new(
            reconciliation.grant_id.clone(),
            reconciliation.grant_version,
            reconciliation.intent_digest,
        );
        let mut state = self.lock_state()?;
        if state
            .reconciliation_receipts
            .contains_key(&reconciliation_key)
        {
            return Err(DenialCode::LeaseReplay);
        }
        if state
            .reconciliation_receipts
            .values()
            .any(|resolution| resolution.receipt_id == reconciliation.reconciliation_id)
        {
            return Err(DenialCode::LeaseReplay);
        }
        let hold = match state
            .reconciliation_required
            .get(&reconciliation_key)
            .copied()
        {
            None => return Err(DenialCode::LeaseBindingMismatch),
            Some(actual_hold)
                if actual_hold.kind != expected_hold_kind
                    || actual_hold.binding_digest != reconciliation.hold_binding_digest =>
            {
                return Err(DenialCode::LeaseReconciliationRequired);
            }
            Some(actual_hold) => actual_hold,
        };
        if state.held_effects.get(&reconciliation_key) != Some(&reconciliation.effect_digest) {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        state.reconciliation_required.remove(&reconciliation_key);
        state.held_effects.remove(&reconciliation_key);
        state.reconciliation_receipts.insert(
            reconciliation_key,
            ReconciliationResolution {
                receipt_id: reconciliation.reconciliation_id,
                terminal_outcome: reconciliation.terminal_outcome,
                hold_binding_digest: hold.binding_digest,
                effect_digest: reconciliation.effect_digest,
                retry_invariant_digest: hold.retry_invariant_digest,
                retry_consumed: false,
            },
        );
        for entry in state.leases.values_mut().filter(|entry| {
            entry.spec.grant_id == reconciliation.grant_id
                && entry.spec.grant_version == reconciliation.grant_version
                && entry.spec.intent_digest == reconciliation.intent_digest
                && entry.status == LeaseStatus::Available
        }) {
            entry.status = LeaseStatus::Consumed;
        }
        Ok(())
    }

    fn verify_reconciliation_authorization(
        &self,
        unknown_receipt: Option<&DispatchReceipt>,
        reconciliation: &ReconciliationReceipt,
    ) -> Result<(), DenialCode> {
        let (key_id, verification_key) = self
            .reconciliation_key_id
            .as_ref()
            .zip(self.reconciliation_verification_key.as_ref())
            .ok_or(DenialCode::LeaseReconciliationRequired)?;
        let expected_dispatch_receipt_id = unknown_receipt.map(|receipt| receipt.receipt_id);
        if !reconciliation.valid_shape()
            || &reconciliation.key_id != key_id
            || reconciliation.unknown_dispatch_receipt_id != expected_dispatch_receipt_id
            || unknown_receipt.is_some_and(|receipt| {
                reconciliation.grant_id != receipt.grant_id
                    || reconciliation.grant_version != receipt.grant_version
                    || reconciliation.intent_digest != receipt.intent_digest
                    || reconciliation.effect_digest != receipt.effect_digest
                    || reconciliation.hold_binding_digest != receipt.hold_binding_digest
                    || reconciliation.resolved_at_millis < receipt.completed_at_millis
            })
        {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        let expected_tag = hmac_sha256(verification_key, &reconciliation.unsigned_bytes());
        if !constant_time_eq(
            expected_tag.as_bytes(),
            reconciliation.authentication_tag.as_bytes(),
        ) {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        Ok(())
    }

    pub fn verify_dispatch_receipt(&self, receipt: &DispatchReceipt) -> Result<(), DenialCode> {
        if !receipt.validate() || receipt.lease_key_id != self.lease_key_id {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        let expected_tag = self.dispatch_receipt_authentication_tag(receipt);
        if !constant_time_eq(
            expected_tag.as_bytes(),
            receipt.receipt_authentication_tag.as_bytes(),
        ) {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        Ok(())
    }

    pub fn reconciliation_receipt(
        &self,
        grant_id: &str,
        grant_version: u64,
        intent_digest: Digest,
    ) -> Result<Option<Digest>, DenialCode> {
        if !valid_identifier(grant_id) || grant_version == 0 || intent_digest == Digest::ZERO {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        let state = self.lock_state()?;
        Ok(state
            .reconciliation_receipts
            .get(&ReconciliationKey::new(
                grant_id.to_owned(),
                grant_version,
                intent_digest,
            ))
            .map(|resolution| resolution.receipt_id))
    }
}
