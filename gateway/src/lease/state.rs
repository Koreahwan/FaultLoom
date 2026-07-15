use super::*;

impl GrantBudget {
    pub(super) fn valid(&self) -> bool {
        self.total_actions > 0
            && self.rate_per_minute > 0
            && self.max_concurrency > 0
            && self.max_request_bytes > 0
            && self.max_response_bytes > 0
            && self.max_duration_seconds > 0
    }
}

impl ReconciliationKey {
    pub(super) fn new(grant_id: String, grant_version: u64, intent_digest: Digest) -> Self {
        Self {
            grant_id,
            grant_version,
            intent_digest,
        }
    }

    pub(super) fn from_spec(spec: &LeaseSpec) -> Self {
        Self::new(
            spec.grant_id.clone(),
            spec.grant_version,
            spec.intent_digest,
        )
    }

    pub(super) fn canonical_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.grant_id
            .cmp(&other.grant_id)
            .then(self.grant_version.cmp(&other.grant_version))
            .then_with(|| {
                self.intent_digest
                    .as_bytes()
                    .cmp(other.intent_digest.as_bytes())
            })
    }
}

pub(super) fn held_effect_for_exact_key(
    state: &LeaseState,
    key: &ReconciliationKey,
) -> Result<Option<Digest>, DenialCode> {
    match (
        state.reconciliation_required.get(key),
        state.held_effects.get(key),
    ) {
        (Some(_), Some(effect_digest)) => Ok(Some(*effect_digest)),
        (Some(_), None) | (None, Some(_)) => Err(DenialCode::LeaseAccountingUnavailable),
        (None, None) => Ok(None),
    }
}

impl LeaseAuthority {
    pub(super) fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, LeaseState>, DenialCode> {
        self.state
            .lock()
            .map_err(|_| DenialCode::LeaseAccountingUnavailable)
    }
}
