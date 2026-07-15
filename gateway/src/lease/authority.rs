use super::*;

impl LeaseAuthority {
    pub fn new(
        lease_key_id: String,
        signing_key: [u8; 32],
        gateway_boot_id: String,
        boot_challenge_digest: Digest,
    ) -> Result<Self, DenialCode> {
        if !valid_identifier(&lease_key_id)
            || !valid_identifier(&gateway_boot_id)
            || !valid_boot_secret(&signing_key)
            || boot_challenge_digest == Digest::ZERO
            || boot_challenge_digest == Digest::of(&signing_key)
        {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        Ok(Self {
            lease_key_id,
            signing_key,
            gateway_boot_id,
            boot_challenge_digest,
            reconciliation_key_id: None,
            reconciliation_verification_key: None,
            state: Mutex::new(LeaseState::default()),
        })
    }

    pub fn new_with_reconciliation_verifier(
        lease_key_id: String,
        signing_key: [u8; 32],
        gateway_boot_id: String,
        boot_challenge_digest: Digest,
        reconciliation_key_id: String,
        reconciliation_verification_key: [u8; 32],
    ) -> Result<Self, DenialCode> {
        let mut authority = Self::new(
            lease_key_id,
            signing_key,
            gateway_boot_id,
            boot_challenge_digest,
        )?;
        if !valid_identifier(&reconciliation_key_id)
            || reconciliation_key_id == authority.lease_key_id
            || !valid_boot_secret(&reconciliation_verification_key)
            || reconciliation_verification_key == authority.signing_key
        {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        authority.reconciliation_key_id = Some(reconciliation_key_id);
        authority.reconciliation_verification_key = Some(reconciliation_verification_key);
        Ok(authority)
    }
}
