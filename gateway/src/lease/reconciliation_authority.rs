use super::*;

impl ReconciliationReceipt {
    pub(super) fn unsigned_bytes(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(256);
        message.extend_from_slice(b"faultloom-lease-reconciliation-v3\0");
        push_string(&mut message, &self.key_id);
        push_string(&mut message, &self.grant_id);
        message.extend_from_slice(&self.grant_version.to_be_bytes());
        message.extend_from_slice(self.intent_digest.as_bytes());
        message.extend_from_slice(self.effect_digest.as_bytes());
        message.extend_from_slice(self.hold_binding_digest.as_bytes());
        push_optional_digest(&mut message, self.unknown_dispatch_receipt_id);
        message.push(self.terminal_outcome as u8);
        message.extend_from_slice(self.terminal_evidence_digest.as_bytes());
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&self.resolved_at_millis.to_be_bytes());
        message
    }

    pub(super) fn canonical_id(&self) -> Digest {
        Digest::of(&self.unsigned_bytes())
    }

    pub(crate) fn valid_shape(&self) -> bool {
        valid_identifier(&self.key_id)
            && valid_identifier(&self.grant_id)
            && self.grant_version > 0
            && self.intent_digest != Digest::ZERO
            && self.effect_digest != Digest::ZERO
            && self.hold_binding_digest != Digest::ZERO
            && self.unknown_dispatch_receipt_id != Some(Digest::ZERO)
            && self.terminal_outcome != DispatchOutcome::UnknownOutcome
            && self.terminal_evidence_digest != Digest::ZERO
            && valid_nonce(&self.nonce)
            && self.resolved_at_millis > 0
            && self.reconciliation_id == self.canonical_id()
            && self.authentication_tag != Digest::ZERO
    }
}

impl ReconciliationAuthority {
    pub fn new(key_id: String, signing_key: [u8; 32]) -> Result<Self, DenialCode> {
        if !valid_identifier(&key_id) || !valid_boot_secret(&signing_key) {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        Ok(Self {
            key_id,
            signing_key,
        })
    }

    pub fn issue(
        &self,
        unknown_receipt: &DispatchReceipt,
        terminal_outcome: DispatchOutcome,
        terminal_evidence_digest: Digest,
        nonce: [u8; 16],
        resolved_at_millis: u64,
    ) -> Result<ReconciliationReceipt, DenialCode> {
        if !unknown_receipt.validate()
            || unknown_receipt.outcome != DispatchOutcome::UnknownOutcome
            || !unknown_receipt.reconciliation_required
            || terminal_outcome == DispatchOutcome::UnknownOutcome
            || terminal_evidence_digest == Digest::ZERO
            || !valid_nonce(&nonce)
            || resolved_at_millis < unknown_receipt.completed_at_millis
        {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        self.issue_bound(
            ReconciliationBinding {
                key: ReconciliationKey::new(
                    unknown_receipt.grant_id.clone(),
                    unknown_receipt.grant_version,
                    unknown_receipt.intent_digest,
                ),
                effect_digest: unknown_receipt.effect_digest,
                hold_binding_digest: unknown_receipt.hold_binding_digest,
                unknown_dispatch_receipt_id: Some(unknown_receipt.receipt_id),
            },
            ReconciliationTerminal {
                outcome: terminal_outcome,
                evidence_digest: terminal_evidence_digest,
                nonce,
                resolved_at_millis,
            },
        )
    }

    pub fn issue_control_plane_hold(
        &self,
        hold: ControlPlaneReconciliationHold,
        terminal: ReconciliationTerminal,
    ) -> Result<ReconciliationReceipt, DenialCode> {
        self.issue_bound(
            ReconciliationBinding {
                key: ReconciliationKey::new(hold.grant_id, hold.grant_version, hold.intent_digest),
                effect_digest: hold.effect_digest,
                hold_binding_digest: hold.hold_binding_digest,
                unknown_dispatch_receipt_id: None,
            },
            terminal,
        )
    }

    fn issue_bound(
        &self,
        binding: ReconciliationBinding,
        terminal: ReconciliationTerminal,
    ) -> Result<ReconciliationReceipt, DenialCode> {
        let mut receipt = ReconciliationReceipt {
            reconciliation_id: Digest::ZERO,
            key_id: self.key_id.clone(),
            grant_id: binding.key.grant_id,
            grant_version: binding.key.grant_version,
            intent_digest: binding.key.intent_digest,
            effect_digest: binding.effect_digest,
            hold_binding_digest: binding.hold_binding_digest,
            unknown_dispatch_receipt_id: binding.unknown_dispatch_receipt_id,
            terminal_outcome: terminal.outcome,
            terminal_evidence_digest: terminal.evidence_digest,
            nonce: terminal.nonce,
            resolved_at_millis: terminal.resolved_at_millis,
            authentication_tag: Digest::ZERO,
        };
        if !valid_identifier(&receipt.grant_id)
            || receipt.grant_version == 0
            || receipt.intent_digest == Digest::ZERO
            || receipt.effect_digest == Digest::ZERO
            || receipt.hold_binding_digest == Digest::ZERO
            || receipt.unknown_dispatch_receipt_id == Some(Digest::ZERO)
            || receipt.terminal_outcome == DispatchOutcome::UnknownOutcome
            || receipt.terminal_evidence_digest == Digest::ZERO
            || !valid_nonce(&receipt.nonce)
            || receipt.resolved_at_millis == 0
        {
            return Err(DenialCode::LeaseReconciliationRequired);
        }
        receipt.reconciliation_id = receipt.canonical_id();
        receipt.authentication_tag = hmac_sha256(&self.signing_key, &receipt.unsigned_bytes());
        Ok(receipt)
    }
}
