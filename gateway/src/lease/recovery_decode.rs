use super::*;

pub(super) struct RecoveryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecoveryDecoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DenialCode> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DenialCode::RecoveryCheckpointInvalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DenialCode::RecoveryCheckpointInvalid)?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn expect_prefix(&mut self, expected: &[u8]) -> Result<(), DenialCode> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(DenialCode::RecoveryCheckpointInvalid)
        }
    }

    fn byte(&mut self) -> Result<u8, DenialCode> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DenialCode> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ))
    }

    pub(super) fn u64(&mut self) -> Result<u64, DenialCode> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ))
    }

    pub(super) fn count(&mut self) -> Result<usize, DenialCode> {
        let count = self.u32()? as usize;
        if count > MAX_RECOVERY_ITEMS {
            Err(DenialCode::RecoveryCheckpointInvalid)
        } else {
            Ok(count)
        }
    }

    pub(super) fn string(&mut self) -> Result<String, DenialCode> {
        let length = self.u32()? as usize;
        if length == 0 || length > 256 {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| DenialCode::RecoveryCheckpointInvalid)
    }

    pub(super) fn digest(&mut self) -> Result<Digest, DenialCode> {
        Ok(Digest::from_bytes(
            self.take(32)?
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ))
    }

    pub(super) fn nonce(&mut self) -> Result<[u8; 16], DenialCode> {
        self.take(16)?
            .try_into()
            .map_err(|_| DenialCode::RecoveryCheckpointInvalid)
    }

    pub(super) fn optional_u64(&mut self) -> Result<Option<u64>, DenialCode> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(DenialCode::RecoveryCheckpointInvalid),
        }
    }

    pub(super) fn reconciliation_holds(
        &mut self,
    ) -> Result<HashMap<ReconciliationKey, ReconciliationHold>, DenialCode> {
        let count = self.count()?;
        let mut values = HashMap::with_capacity(count);
        for _ in 0..count {
            let reconciliation_key = self.reconciliation_key()?;
            let kind = match self.byte()? {
                1 => ReconciliationHoldKind::DispatchReceipt,
                2 => ReconciliationHoldKind::ControlPlane,
                _ => return Err(DenialCode::RecoveryCheckpointInvalid),
            };
            let binding_digest = self.digest()?;
            let retry_invariant_digest = self.digest()?;
            if binding_digest == Digest::ZERO
                || retry_invariant_digest == Digest::ZERO
                || values
                    .insert(
                        reconciliation_key,
                        ReconciliationHold {
                            kind,
                            binding_digest,
                            retry_invariant_digest,
                        },
                    )
                    .is_some()
            {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        Ok(values)
    }

    pub(super) fn reconciliation_receipts(
        &mut self,
    ) -> Result<HashMap<ReconciliationKey, ReconciliationResolution>, DenialCode> {
        let count = self.count()?;
        let mut values = HashMap::with_capacity(count);
        for _ in 0..count {
            let key = self.reconciliation_key()?;
            let receipt_id = self.digest()?;
            let terminal_outcome = match self.byte()? {
                1 => DispatchOutcome::Completed,
                2 => DispatchOutcome::Failed,
                3 => return Err(DenialCode::RecoveryCheckpointInvalid),
                _ => return Err(DenialCode::RecoveryCheckpointInvalid),
            };
            let hold_binding_digest = self.digest()?;
            let effect_digest = self.digest()?;
            let retry_invariant_digest = self.digest()?;
            let retry_consumed = match self.byte()? {
                0 => false,
                1 => true,
                _ => return Err(DenialCode::RecoveryCheckpointInvalid),
            };
            if receipt_id == Digest::ZERO
                || hold_binding_digest == Digest::ZERO
                || effect_digest == Digest::ZERO
                || retry_invariant_digest == Digest::ZERO
                || (terminal_outcome == DispatchOutcome::Completed && retry_consumed)
                || values
                    .insert(
                        key,
                        ReconciliationResolution {
                            receipt_id,
                            terminal_outcome,
                            hold_binding_digest,
                            effect_digest,
                            retry_invariant_digest,
                            retry_consumed,
                        },
                    )
                    .is_some()
            {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        Ok(values)
    }

    pub(super) fn effect_digests(
        &mut self,
    ) -> Result<HashMap<ReconciliationKey, Digest>, DenialCode> {
        let count = self.count()?;
        let mut values = HashMap::with_capacity(count);
        for _ in 0..count {
            let key = self.reconciliation_key()?;
            let value = self.digest()?;
            if value == Digest::ZERO || values.insert(key, value).is_some() {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        Ok(values)
    }

    pub(super) fn retry_aliases(
        &mut self,
    ) -> Result<HashMap<ReconciliationKey, ReconciliationKey>, DenialCode> {
        let count = self.count()?;
        let mut values = HashMap::with_capacity(count);
        for _ in 0..count {
            let retry = self.reconciliation_key()?;
            let parent = self.reconciliation_key()?;
            if retry == parent
                || retry.grant_id != parent.grant_id
                || retry.grant_version != parent.grant_version
                || values.insert(retry, parent).is_some()
            {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        Ok(values)
    }

    pub(super) fn reconciliation_key(&mut self) -> Result<ReconciliationKey, DenialCode> {
        let grant_id = self.string()?;
        let grant_version = self.u64()?;
        let intent_digest = self.digest()?;
        if !valid_identifier(&grant_id) || grant_version == 0 || intent_digest == Digest::ZERO {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        Ok(ReconciliationKey::new(
            grant_id,
            grant_version,
            intent_digest,
        ))
    }

    pub(super) fn finish(self) -> Result<(), DenialCode> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DenialCode::RecoveryCheckpointInvalid)
        }
    }
}
