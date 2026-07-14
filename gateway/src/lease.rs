use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use crate::Digest;
use crate::ipc::{DenialCode, DispatchOutcome, DispatchReceipt, DispatchRequest, EgressPlane};
use crate::policy::{LeaseApproval, LeaseCompletion, LeaseFinalization, LeaseVerifier};
use crate::scope::{CancellationCause, ScopeCancellation, ScopeCancellationSink};
use crate::transport::DispatchCancellation;

const RATE_WINDOW_MILLIS: u64 = 60_000;
const MAX_LEASE_TTL_MILLIS: u64 = 60_000;
const HMAC_BLOCK_BYTES: usize = 64;
const RECOVERY_MAGIC: &[u8; 4] = b"FLRC";
const RECOVERY_VERSION: u8 = 3;
const MAX_RECOVERY_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECOVERY_ITEMS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantBudget {
    pub total_actions: u64,
    pub rate_per_minute: u64,
    pub max_concurrency: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_duration_seconds: u64,
}

impl GrantBudget {
    fn valid(&self) -> bool {
        self.total_actions > 0
            && self.rate_per_minute > 0
            && self.max_concurrency > 0
            && self.max_request_bytes > 0
            && self.max_response_bytes > 0
            && self.max_duration_seconds > 0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct GrantKey {
    grant_id: String,
    grant_version: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReconciliationKey {
    grant_id: String,
    grant_version: u64,
    intent_digest: Digest,
}

impl ReconciliationKey {
    fn new(grant_id: String, grant_version: u64, intent_digest: Digest) -> Self {
        Self {
            grant_id,
            grant_version,
            intent_digest,
        }
    }

    fn from_spec(spec: &LeaseSpec) -> Self {
        Self::new(
            spec.grant_id.clone(),
            spec.grant_version,
            spec.intent_digest,
        )
    }

    fn canonical_cmp(&self, other: &Self) -> std::cmp::Ordering {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseSpec {
    pub lease_id: String,
    pub intent_digest: Digest,
    pub decision_digest: Digest,
    pub grant_id: String,
    pub grant_version: u64,
    pub scope_epoch: u64,
    pub authority_key_id: String,
    pub scope_epoch_binding_digest: Digest,
    pub gateway_boot_id: String,
    pub request_binding_digest: Digest,
    pub semantic_action_digest: Digest,
    pub resolution_digest: Digest,
    pub correlation_id: String,
    pub egress_plane: EgressPlane,
    pub dispatch_nonce: [u8; 16],
    pub retry_of_intent_digest: Option<Digest>,
    pub issued_at_millis: u64,
    pub expires_at_millis: u64,
    pub reservation: LeaseBudgetReservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseBudgetReservation {
    pub action_count: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedLease {
    pub lease_id: String,
    pub lease_key_id: String,
    pub gateway_boot_id: String,
    pub boot_challenge_digest: Digest,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationReceipt {
    pub reconciliation_id: Digest,
    pub key_id: String,
    pub grant_id: String,
    pub grant_version: u64,
    pub intent_digest: Digest,
    pub unknown_dispatch_receipt_id: Option<Digest>,
    pub terminal_outcome: DispatchOutcome,
    pub terminal_evidence_digest: Digest,
    pub nonce: [u8; 16],
    pub resolved_at_millis: u64,
    pub authentication_tag: Digest,
}

impl ReconciliationReceipt {
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(256);
        message.extend_from_slice(b"faultloom-lease-reconciliation-v1\0");
        push_string(&mut message, &self.key_id);
        push_string(&mut message, &self.grant_id);
        message.extend_from_slice(&self.grant_version.to_be_bytes());
        message.extend_from_slice(self.intent_digest.as_bytes());
        push_optional_digest(&mut message, self.unknown_dispatch_receipt_id);
        message.push(self.terminal_outcome as u8);
        message.extend_from_slice(self.terminal_evidence_digest.as_bytes());
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&self.resolved_at_millis.to_be_bytes());
        message
    }

    fn canonical_id(&self) -> Digest {
        Digest::of(&self.unsigned_bytes())
    }

    fn valid_shape(&self) -> bool {
        valid_identifier(&self.key_id)
            && valid_identifier(&self.grant_id)
            && self.grant_version > 0
            && self.intent_digest != Digest::ZERO
            && self.unknown_dispatch_receipt_id != Some(Digest::ZERO)
            && self.terminal_outcome != DispatchOutcome::UnknownOutcome
            && self.terminal_evidence_digest != Digest::ZERO
            && valid_nonce(&self.nonce)
            && self.resolved_at_millis > 0
            && self.reconciliation_id == self.canonical_id()
            && self.authentication_tag != Digest::ZERO
    }
}

/// Separate capability for the durable control plane that resolves an
/// ambiguous dispatch. Holding a `LeaseAuthority` alone cannot manufacture a
/// reconciliation receipt.
pub struct ReconciliationAuthority {
    key_id: String,
    signing_key: [u8; 32],
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
            ReconciliationKey::new(
                unknown_receipt.grant_id.clone(),
                unknown_receipt.grant_version,
                unknown_receipt.intent_digest,
            ),
            Some(unknown_receipt.receipt_id),
            terminal_outcome,
            terminal_evidence_digest,
            nonce,
            resolved_at_millis,
        )
    }

    pub fn issue_control_plane_hold(
        &self,
        grant: (&str, u64),
        intent_digest: Digest,
        terminal_outcome: DispatchOutcome,
        terminal_evidence_digest: Digest,
        nonce: [u8; 16],
        resolved_at_millis: u64,
    ) -> Result<ReconciliationReceipt, DenialCode> {
        self.issue_bound(
            ReconciliationKey::new(grant.0.to_owned(), grant.1, intent_digest),
            None,
            terminal_outcome,
            terminal_evidence_digest,
            nonce,
            resolved_at_millis,
        )
    }

    fn issue_bound(
        &self,
        reconciliation_key: ReconciliationKey,
        unknown_dispatch_receipt_id: Option<Digest>,
        terminal_outcome: DispatchOutcome,
        terminal_evidence_digest: Digest,
        nonce: [u8; 16],
        resolved_at_millis: u64,
    ) -> Result<ReconciliationReceipt, DenialCode> {
        let mut receipt = ReconciliationReceipt {
            reconciliation_id: Digest::ZERO,
            key_id: self.key_id.clone(),
            grant_id: reconciliation_key.grant_id,
            grant_version: reconciliation_key.grant_version,
            intent_digest: reconciliation_key.intent_digest,
            unknown_dispatch_receipt_id,
            terminal_outcome,
            terminal_evidence_digest,
            nonce,
            resolved_at_millis,
            authentication_tag: Digest::ZERO,
        };
        if !valid_identifier(&receipt.grant_id)
            || receipt.grant_version == 0
            || receipt.intent_digest == Digest::ZERO
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrantUsage {
    pub dispatched_actions: u64,
    pub active_dispatches: u64,
    pub rate_window_actions: u64,
    pub active_reserved_request_bytes: u64,
    pub active_reserved_response_bytes: u64,
    pub active_reserved_duration_seconds: u64,
    pub actual_request_bytes: u64,
    pub actual_response_bytes: u64,
    pub actual_duration_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseStatus {
    Available,
    Active {
        reservation_token: Digest,
        cancellation: DispatchCancellation,
    },
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ReconciliationHoldKind {
    DispatchReceipt = 1,
    ControlPlane = 2,
}

#[derive(Clone, Debug)]
struct LeaseEntry {
    spec: LeaseSpec,
    proof: Digest,
    status: LeaseStatus,
}

#[derive(Clone, Debug)]
struct GrantAccount {
    budget: GrantBudget,
    usage: GrantUsage,
    dispatch_times: VecDeque<u64>,
    last_clock_millis: u64,
    revoked_at_epoch: Option<u64>,
}

#[derive(Default)]
struct LeaseState {
    grants: HashMap<GrantKey, GrantAccount>,
    leases: HashMap<String, LeaseEntry>,
    reconciliation_required: HashMap<ReconciliationKey, ReconciliationHoldKind>,
    reconciliation_receipts: HashMap<ReconciliationKey, Digest>,
    retry_aliases: HashMap<ReconciliationKey, ReconciliationKey>,
    dispatch_nonces: HashSet<[u8; 16]>,
    retired_lease_ids: HashSet<String>,
    checkpoint_sequence: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LeaseRevocationSummary {
    pub canceled_available: u64,
    pub interrupted_active: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseRecoveryCheckpoint {
    encoded: Vec<u8>,
    checkpoint_id: Digest,
}

impl LeaseRecoveryCheckpoint {
    pub fn from_bytes(encoded: Vec<u8>) -> Result<Self, DenialCode> {
        if encoded.len() < 4 + 1 + 4 + 32 || encoded.len() > MAX_RECOVERY_BYTES {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        if &encoded[..4] != RECOVERY_MAGIC || encoded[4] != RECOVERY_VERSION {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let payload_len = u32::from_be_bytes(
            encoded[5..9]
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ) as usize;
        if payload_len.checked_add(4 + 1 + 4 + 32) != Some(encoded.len()) {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        let checkpoint_id = recovery_checkpoint_id(&encoded);
        Ok(Self {
            encoded,
            checkpoint_id,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    pub const fn checkpoint_id(&self) -> Digest {
        self.checkpoint_id
    }
}

/// Gateway-owned capability issuer and atomic lease/budget accountant.
///
/// The key never crosses the local Gateway boundary. A restart forgets all
/// issued capabilities and therefore fails closed instead of accepting stale
/// leases or resetting their one-use state.
pub struct LeaseAuthority {
    lease_key_id: String,
    signing_key: [u8; 32],
    gateway_boot_id: String,
    boot_challenge_digest: Digest,
    reconciliation_key_id: Option<String>,
    reconciliation_verification_key: Option<[u8; 32]>,
    state: Mutex<LeaseState>,
}

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

    pub fn issue(&self, spec: LeaseSpec) -> Result<IssuedLease, DenialCode> {
        if !valid_identifier(&spec.lease_id)
            || !valid_identifier(&spec.grant_id)
            || !valid_identifier(&spec.authority_key_id)
            || !valid_identifier(&spec.gateway_boot_id)
            || !valid_identifier(&spec.correlation_id)
            || spec.grant_version == 0
            || spec.scope_epoch == 0
            || spec.scope_epoch_binding_digest == Digest::ZERO
            || spec.request_binding_digest == Digest::ZERO
            || spec.semantic_action_digest == Digest::ZERO
            || spec.resolution_digest == Digest::ZERO
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
        if let Some(parent_intent) = spec.retry_of_intent_digest {
            let parent_key =
                ReconciliationKey::new(spec.grant_id.clone(), spec.grant_version, parent_intent);
            if !state.reconciliation_receipts.contains_key(&parent_key)
                || state.retry_aliases.contains_key(&intent_key)
            {
                return Err(DenialCode::RetryAliasInvalid);
            }
        } else if state.reconciliation_receipts.contains_key(&intent_key) {
            return Err(DenialCode::RetryAliasInvalid);
        }

        let proof = self.sign_spec(&spec);
        let lease_id = spec.lease_id.clone();
        if let Some(parent_intent) = spec.retry_of_intent_digest {
            let parent_key =
                ReconciliationKey::new(spec.grant_id.clone(), spec.grant_version, parent_intent);
            state.retry_aliases.insert(intent_key, parent_key);
        }
        state.dispatch_nonces.insert(spec.dispatch_nonce);
        state.retired_lease_ids.insert(lease_id.clone());
        state.leases.insert(
            lease_id.clone(),
            LeaseEntry {
                spec,
                proof,
                status: LeaseStatus::Available,
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

    pub fn revoke_grant(
        &self,
        grant_id: &str,
        grant_version: u64,
        revoked_at_epoch: u64,
    ) -> Result<LeaseRevocationSummary, DenialCode> {
        self.cancel_grant_scope(grant_id, grant_version, revoked_at_epoch, true)
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
                    interrupted.push((
                        lease_id.clone(),
                        entry.spec.intent_digest,
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
                |(actions, requests, responses, durations), (_, _, reservation, _)| {
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
        for (_, intent, _, _) in &interrupted {
            state
                .reconciliation_required
                .entry(ReconciliationKey::new(
                    grant_id.to_owned(),
                    grant_version,
                    *intent,
                ))
                .or_insert(ReconciliationHoldKind::ControlPlane);
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
        for (_, _, _, cancellation) in interrupted {
            cancellation_failed |= cancellation.cancel().is_err();
        }
        if cancellation_failed {
            return Err(DenialCode::LeaseAccountingUnavailable);
        }
        Ok(summary)
    }

    fn cancel_scope_transports(
        &self,
        grant_id: &str,
        grant_version: u64,
        invalidated_through_epoch: u64,
        revoke_grant: bool,
    ) -> Result<(), DenialCode> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancellations = state
            .leases
            .values()
            .filter(|entry| {
                entry.spec.grant_id == grant_id
                    && entry.spec.grant_version == grant_version
                    && (revoke_grant || entry.spec.scope_epoch <= invalidated_through_epoch)
            })
            .filter_map(|entry| match &entry.status {
                LeaseStatus::Active { cancellation, .. } => Some(cancellation.clone()),
                LeaseStatus::Available | LeaseStatus::Consumed => None,
            })
            .collect::<Vec<_>>();
        drop(state);
        let mut cancellation_failed = false;
        for cancellation in cancellations {
            cancellation_failed |= cancellation.cancel().is_err();
        }
        if cancellation_failed {
            Err(DenialCode::LeaseAccountingUnavailable)
        } else {
            Ok(())
        }
    }

    /// Seal the durable accounting state. Active reservations are restored as
    /// unknown outcomes, never as dispatchable leases.
    pub fn checkpoint(&self) -> Result<LeaseRecoveryCheckpoint, DenialCode> {
        let mut state = self.lock_state()?;
        for count in [
            state.grants.len(),
            state.reconciliation_required.len(),
            state.reconciliation_receipts.len(),
            state.retry_aliases.len(),
            state.dispatch_nonces.len(),
            state.retired_lease_ids.len(),
        ] {
            if count > MAX_RECOVERY_ITEMS {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        state.checkpoint_sequence = state
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(DenialCode::RecoveryCheckpointInvalid)?;

        let mut payload = Vec::new();
        payload.extend_from_slice(b"faultloom-lease-recovery-state-v3\0");
        push_string(&mut payload, &self.lease_key_id);
        push_string(&mut payload, &self.gateway_boot_id);
        payload.extend_from_slice(self.boot_challenge_digest.as_bytes());
        payload.extend_from_slice(&state.checkpoint_sequence.to_be_bytes());

        let mut grants: Vec<_> = state.grants.iter().collect();
        grants.sort_by(|(left, _), (right, _)| {
            left.grant_id
                .cmp(&right.grant_id)
                .then(left.grant_version.cmp(&right.grant_version))
        });
        push_count(&mut payload, grants.len())?;
        for (key, account) in grants {
            push_string(&mut payload, &key.grant_id);
            payload.extend_from_slice(&key.grant_version.to_be_bytes());
            for value in [
                account.budget.total_actions,
                account.budget.rate_per_minute,
                account.budget.max_concurrency,
                account.budget.max_request_bytes,
                account.budget.max_response_bytes,
                account.budget.max_duration_seconds,
                account.usage.dispatched_actions,
                account.usage.actual_request_bytes,
                account.usage.actual_response_bytes,
                account.usage.actual_duration_millis,
                account.last_clock_millis,
            ] {
                payload.extend_from_slice(&value.to_be_bytes());
            }
            push_optional_u64(&mut payload, account.revoked_at_epoch);
            push_count(&mut payload, account.dispatch_times.len())?;
            for timestamp in &account.dispatch_times {
                payload.extend_from_slice(&timestamp.to_be_bytes());
            }
        }

        let mut holds = state.reconciliation_required.clone();
        for reconciliation_key in state
            .leases
            .values()
            .filter(|entry| matches!(entry.status, LeaseStatus::Active { .. }))
            .map(|entry| ReconciliationKey::from_spec(&entry.spec))
        {
            holds
                .entry(reconciliation_key)
                .or_insert(ReconciliationHoldKind::ControlPlane);
        }
        push_reconciliation_holds(&mut payload, &holds)?;
        push_reconciliation_receipts(&mut payload, &state.reconciliation_receipts)?;
        push_retry_aliases(&mut payload, &state.retry_aliases)?;

        let mut nonces: Vec<_> = state.dispatch_nonces.iter().copied().collect();
        nonces.sort_unstable();
        push_count(&mut payload, nonces.len())?;
        for nonce in nonces {
            payload.extend_from_slice(&nonce);
        }

        let mut retired: Vec<_> = state.retired_lease_ids.iter().collect();
        retired.sort_unstable();
        push_count(&mut payload, retired.len())?;
        for lease_id in retired {
            push_string(&mut payload, lease_id);
        }

        let mut authenticated = Vec::with_capacity(payload.len() + 48);
        authenticated.extend_from_slice(b"faultloom-lease-recovery-checkpoint-v3\0");
        authenticated.extend_from_slice(&payload);
        let tag = hmac_sha256(&self.signing_key, &authenticated);
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| DenialCode::RecoveryCheckpointInvalid)?;
        let mut encoded = Vec::with_capacity(9 + payload.len() + 32);
        encoded.extend_from_slice(RECOVERY_MAGIC);
        encoded.push(RECOVERY_VERSION);
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&payload);
        encoded.extend_from_slice(tag.as_bytes());
        if encoded.len() > MAX_RECOVERY_BYTES {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        LeaseRecoveryCheckpoint::from_bytes(encoded)
    }

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
        authenticated.extend_from_slice(b"faultloom-lease-recovery-checkpoint-v3\0");
        authenticated.extend_from_slice(payload);
        let expected_tag = hmac_sha256(&self.signing_key, &authenticated);
        if !constant_time_eq(expected_tag.as_bytes(), supplied_tag) {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }

        let mut decoder = RecoveryDecoder::new(payload);
        decoder.expect_prefix(b"faultloom-lease-recovery-state-v3\0")?;
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
            .copied()
            .collect::<HashSet<_>>()
            .len();
        if restored
            .reconciliation_required
            .keys()
            .any(|key| !registered_grant(key) || restored.reconciliation_receipts.contains_key(key))
            || restored
                .reconciliation_receipts
                .keys()
                .any(|key| !registered_grant(key))
            || unique_receipt_count != restored.reconciliation_receipts.len()
            || restored.retry_aliases.iter().any(|(retry, parent)| {
                !registered_grant(retry)
                    || !registered_grant(parent)
                    || retry == parent
                    || !restored.reconciliation_receipts.contains_key(parent)
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
        decoder.finish()?;

        let mut state = self.lock_state()?;
        if !state.grants.is_empty()
            || !state.leases.is_empty()
            || !state.reconciliation_required.is_empty()
            || !state.reconciliation_receipts.is_empty()
            || !state.retry_aliases.is_empty()
            || !state.dispatch_nonces.is_empty()
            || !state.retired_lease_ids.is_empty()
            || state.checkpoint_sequence != 0
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        *state = restored;
        Ok(())
    }

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
            .values()
            .any(|digest| *digest == reconciliation.reconciliation_id)
        {
            return Err(DenialCode::LeaseReplay);
        }
        match state
            .reconciliation_required
            .get(&reconciliation_key)
            .copied()
        {
            None => return Err(DenialCode::LeaseBindingMismatch),
            Some(actual_hold_kind) if actual_hold_kind != expected_hold_kind => {
                return Err(DenialCode::LeaseReconciliationRequired);
            }
            Some(_) => {}
        }
        state.reconciliation_required.remove(&reconciliation_key);
        state
            .reconciliation_receipts
            .insert(reconciliation_key, reconciliation.reconciliation_id);
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
            .copied())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, LeaseState>, DenialCode> {
        self.state
            .lock()
            .map_err(|_| DenialCode::LeaseAccountingUnavailable)
    }

    fn sign_spec(&self, spec: &LeaseSpec) -> Digest {
        let mut message = Vec::with_capacity(256);
        message.extend_from_slice(b"faultloom-action-lease-v2\0");
        push_string(&mut message, &self.lease_key_id);
        push_string(&mut message, &self.gateway_boot_id);
        message.extend_from_slice(self.boot_challenge_digest.as_bytes());
        push_string(&mut message, &spec.lease_id);
        message.extend_from_slice(spec.intent_digest.as_bytes());
        message.extend_from_slice(spec.decision_digest.as_bytes());
        push_string(&mut message, &spec.grant_id);
        message.extend_from_slice(&spec.grant_version.to_be_bytes());
        message.extend_from_slice(&spec.scope_epoch.to_be_bytes());
        push_string(&mut message, &spec.authority_key_id);
        message.extend_from_slice(spec.scope_epoch_binding_digest.as_bytes());
        push_string(&mut message, &spec.gateway_boot_id);
        message.extend_from_slice(spec.request_binding_digest.as_bytes());
        message.extend_from_slice(spec.semantic_action_digest.as_bytes());
        message.extend_from_slice(spec.resolution_digest.as_bytes());
        push_string(&mut message, &spec.correlation_id);
        message.push(spec.egress_plane as u8);
        message.extend_from_slice(&spec.dispatch_nonce);
        push_optional_digest(&mut message, spec.retry_of_intent_digest);
        message.extend_from_slice(&spec.issued_at_millis.to_be_bytes());
        message.extend_from_slice(&spec.expires_at_millis.to_be_bytes());
        message.extend_from_slice(&spec.reservation.action_count.to_be_bytes());
        message.extend_from_slice(&spec.reservation.request_bytes.to_be_bytes());
        message.extend_from_slice(&spec.reservation.response_bytes.to_be_bytes());
        message.extend_from_slice(&spec.reservation.duration_seconds.to_be_bytes());
        hmac_sha256(&self.signing_key, &message)
    }

    fn dispatch_receipt_authentication_tag(&self, receipt: &DispatchReceipt) -> Digest {
        let mut message = Vec::with_capacity(128);
        message.extend_from_slice(b"faultloom-dispatch-receipt-authentication-v1\0");
        push_string(&mut message, &self.lease_key_id);
        message.extend_from_slice(receipt.receipt_id.as_bytes());
        hmac_sha256(&self.signing_key, &message)
    }

    fn receipt_matches_approval(receipt: &DispatchReceipt, approval: &LeaseApproval) -> bool {
        receipt.intent_digest == approval.intent_digest
            && receipt.decision_digest == approval.decision_digest
            && receipt.grant_id == approval.grant_id
            && receipt.grant_version == approval.grant_version
            && receipt.lease_id == approval.lease_id
            && receipt.scope_epoch == approval.scope_epoch
            && receipt.authority_key_id == approval.authority_key_id
            && receipt.scope_epoch_binding_digest == approval.scope_epoch_binding_digest
            && receipt.lease_key_id == approval.lease_key_id
            && receipt.gateway_boot_id == approval.gateway_boot_id
            && receipt.boot_challenge_digest == approval.boot_challenge_digest
            && receipt.request_binding_digest == approval.request_binding_digest
            && receipt.semantic_action_digest == approval.semantic_action_digest
            && receipt.resolution_digest == approval.resolution_digest
            && receipt.correlation_id == approval.correlation_id
            && receipt.egress_plane == approval.egress_plane
            && receipt.dispatch_nonce == approval.dispatch_nonce
            && receipt.lease_issued_at_millis == approval.issued_at_millis
            && receipt.lease_expires_at_millis == approval.expires_at_millis
            && receipt.retry_of_intent_digest == approval.retry_of_intent_digest
            && receipt.reserved_action_count == approval.reservation.action_count
            && receipt.reserved_request_bytes == approval.reservation.request_bytes
            && receipt.reserved_response_bytes == approval.reservation.response_bytes
            && receipt.reserved_duration_seconds == approval.reservation.duration_seconds
    }

    fn reservation_token(&self, entry: &LeaseEntry, reserved_at_millis: u64) -> Digest {
        let mut message = Vec::with_capacity(128);
        message.extend_from_slice(b"faultloom-lease-reservation-v1\0");
        message.extend_from_slice(entry.proof.as_bytes());
        message.extend_from_slice(&reserved_at_millis.to_be_bytes());
        hmac_sha256(&self.signing_key, &message)
    }

    fn release_active(
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
            || entry.spec.request_binding_digest != approval.request_binding_digest
            || entry.spec.semantic_action_digest != approval.semantic_action_digest
            || entry.spec.resolution_digest != approval.resolution_digest
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
}

impl ScopeCancellationSink for LeaseAuthority {
    fn cancel_scope(&self, cancellation: &ScopeCancellation) -> Result<(), DenialCode> {
        let revoke_grant = match (cancellation.cause, cancellation.revoked_at_epoch) {
            (CancellationCause::ScopeRevoked, Some(epoch))
                if epoch == cancellation.invalidated_through_epoch =>
            {
                true
            }
            (CancellationCause::EpochAdvanced | CancellationCause::EpochExpired, None) => false,
            _ => return Err(DenialCode::LeaseBindingMismatch),
        };
        self.cancel_scope_transports(
            &cancellation.grant_id,
            cancellation.grant_version,
            cancellation.invalidated_through_epoch,
            revoke_grant,
        )?;
        self.cancel_grant_scope(
            &cancellation.grant_id,
            cancellation.grant_version,
            cancellation.invalidated_through_epoch,
            revoke_grant,
        )
        .map(|_| ())
    }
}

impl LeaseVerifier for LeaseAuthority {
    fn reserve(
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
        if let Some(parent) = entry.spec.retry_of_intent_digest
            && {
                let parent_key = ReconciliationKey::new(
                    entry.spec.grant_id.clone(),
                    entry.spec.grant_version,
                    parent,
                );
                state.retry_aliases.get(&intent_key) != Some(&parent_key)
                    || !state.reconciliation_receipts.contains_key(&parent_key)
            }
        {
            return Err(DenialCode::RetryAliasInvalid);
        }
        let request_bytes = u64::try_from(request.payload.len())
            .map_err(|_| DenialCode::LeaseReservationExceeded)?;
        if request_bytes > entry.spec.reservation.request_bytes {
            return Err(DenialCode::LeaseReservationExceeded);
        }

        let key = GrantKey {
            grant_id: entry.spec.grant_id.clone(),
            grant_version: entry.spec.grant_version,
        };
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

        let reservation_token = self.reservation_token(&entry, now_millis);
        let cancellation = DispatchCancellation::new();
        account.usage.dispatched_actions += 1;
        account.usage.active_dispatches += 1;
        account.usage.active_reserved_request_bytes = reserved_request_bytes;
        account.usage.active_reserved_response_bytes = reserved_response_bytes;
        account.usage.active_reserved_duration_seconds = reserved_duration_seconds;
        account.dispatch_times.push_back(now_millis);
        state
            .leases
            .get_mut(&entry.spec.lease_id)
            .expect("lease exists while state lock is held")
            .status = LeaseStatus::Active {
            reservation_token,
            cancellation: cancellation.clone(),
        };

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
            request_binding_digest: entry.spec.request_binding_digest,
            semantic_action_digest: entry.spec.semantic_action_digest,
            resolution_digest: entry.spec.resolution_digest,
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

    fn abandon(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        let mut state = self.lock_state()?;
        Self::release_active(&mut state, approval)?;
        Ok(())
    }

    fn finalize(
        &self,
        approval: &LeaseApproval,
        completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        let mut state = self.lock_state()?;
        let (spec, key) = Self::release_active(&mut state, approval)?;
        let account = state
            .grants
            .get_mut(&key)
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
        account.usage.actual_request_bytes = request_total.unwrap_or(u64::MAX);
        account.usage.actual_response_bytes = response_total.unwrap_or(u64::MAX);
        account.usage.actual_duration_millis = duration_total.unwrap_or(u64::MAX);

        let duration_limit_millis = spec.reservation.duration_seconds.saturating_mul(1_000);
        let reservation_overrun = completion.bytes_sent > spec.reservation.request_bytes
            || completion.bytes_received > spec.reservation.response_bytes
            || completion.elapsed_millis > duration_limit_millis
            || accounting_overflow;
        let reconciliation_required =
            completion.outcome == DispatchOutcome::UnknownOutcome || reservation_overrun;
        if reconciliation_required {
            state.reconciliation_required.insert(
                ReconciliationKey::from_spec(&spec),
                ReconciliationHoldKind::DispatchReceipt,
            );
        }
        Ok(LeaseFinalization {
            reconciliation_required,
            reservation_overrun,
        })
    }

    fn authenticate_receipt(
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

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 256
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_boot_secret(value: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

fn valid_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn push_optional_digest(output: &mut Vec<u8>, value: Option<Digest>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(value.as_bytes());
        }
        None => output.push(0),
    }
}

fn push_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn push_count(output: &mut Vec<u8>, count: usize) -> Result<(), DenialCode> {
    if count > MAX_RECOVERY_ITEMS {
        return Err(DenialCode::RecoveryCheckpointInvalid);
    }
    output.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_reconciliation_holds(
    output: &mut Vec<u8>,
    values: &HashMap<ReconciliationKey, ReconciliationHoldKind>,
) -> Result<(), DenialCode> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by(|(left, _), (right, _)| left.canonical_cmp(right));
    push_count(output, values.len())?;
    for (reconciliation_key, hold_kind) in values {
        push_reconciliation_key(output, reconciliation_key);
        output.push(*hold_kind as u8);
    }
    Ok(())
}

fn push_reconciliation_receipts(
    output: &mut Vec<u8>,
    values: &HashMap<ReconciliationKey, Digest>,
) -> Result<(), DenialCode> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by(|(left, _), (right, _)| left.canonical_cmp(right));
    push_count(output, values.len())?;
    for (key, value) in values {
        push_reconciliation_key(output, key);
        output.extend_from_slice(value.as_bytes());
    }
    Ok(())
}

fn push_retry_aliases(
    output: &mut Vec<u8>,
    values: &HashMap<ReconciliationKey, ReconciliationKey>,
) -> Result<(), DenialCode> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by(|(left, _), (right, _)| left.canonical_cmp(right));
    push_count(output, values.len())?;
    for (retry, parent) in values {
        push_reconciliation_key(output, retry);
        push_reconciliation_key(output, parent);
    }
    Ok(())
}

fn push_reconciliation_key(output: &mut Vec<u8>, value: &ReconciliationKey) {
    push_string(output, &value.grant_id);
    output.extend_from_slice(&value.grant_version.to_be_bytes());
    output.extend_from_slice(value.intent_digest.as_bytes());
}

fn recovery_checkpoint_id(encoded: &[u8]) -> Digest {
    let mut canonical = Vec::with_capacity(encoded.len() + 48);
    canonical.extend_from_slice(b"faultloom-lease-recovery-checkpoint-id-v3\0");
    canonical.extend_from_slice(encoded);
    Digest::of(&canonical)
}

struct RecoveryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecoveryDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
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

    fn expect_prefix(&mut self, expected: &[u8]) -> Result<(), DenialCode> {
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

    fn u64(&mut self) -> Result<u64, DenialCode> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ))
    }

    fn count(&mut self) -> Result<usize, DenialCode> {
        let count = self.u32()? as usize;
        if count > MAX_RECOVERY_ITEMS {
            Err(DenialCode::RecoveryCheckpointInvalid)
        } else {
            Ok(count)
        }
    }

    fn string(&mut self) -> Result<String, DenialCode> {
        let length = self.u32()? as usize;
        if length == 0 || length > 256 {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| DenialCode::RecoveryCheckpointInvalid)
    }

    fn digest(&mut self) -> Result<Digest, DenialCode> {
        Ok(Digest::from_bytes(
            self.take(32)?
                .try_into()
                .map_err(|_| DenialCode::RecoveryCheckpointInvalid)?,
        ))
    }

    fn nonce(&mut self) -> Result<[u8; 16], DenialCode> {
        self.take(16)?
            .try_into()
            .map_err(|_| DenialCode::RecoveryCheckpointInvalid)
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, DenialCode> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(DenialCode::RecoveryCheckpointInvalid),
        }
    }

    fn reconciliation_holds(
        &mut self,
    ) -> Result<HashMap<ReconciliationKey, ReconciliationHoldKind>, DenialCode> {
        let count = self.count()?;
        let mut values = HashMap::with_capacity(count);
        for _ in 0..count {
            let reconciliation_key = self.reconciliation_key()?;
            let hold_kind = match self.byte()? {
                1 => ReconciliationHoldKind::DispatchReceipt,
                2 => ReconciliationHoldKind::ControlPlane,
                _ => return Err(DenialCode::RecoveryCheckpointInvalid),
            };
            if values.insert(reconciliation_key, hold_kind).is_some() {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        Ok(values)
    }

    fn reconciliation_receipts(
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

    fn retry_aliases(
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

    fn reconciliation_key(&mut self) -> Result<ReconciliationKey, DenialCode> {
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

    fn finish(self) -> Result<(), DenialCode> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DenialCode::RecoveryCheckpointInvalid)
        }
    }
}

fn constant_time_eq(expected: &[u8; 32], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Digest {
    let mut key_block = [0_u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        key_block[..32].copy_from_slice(Digest::of(key).as_bytes());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in key_block.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(HMAC_BLOCK_BYTES + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = Digest::of(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_BYTES + 32);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(inner_digest.as_bytes());
    Digest::of(&outer)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::ipc::{
        ActionClass, ActionKind, DispatchReceipt, EgressPlane, FlowKind, RequiredFeature,
    };

    const NOW: u64 = 1_000_000;

    fn lease_key() -> [u8; 32] {
        std::array::from_fn(|index| u8::try_from(index + 1).expect("small key byte"))
    }

    fn budget() -> GrantBudget {
        GrantBudget {
            total_actions: 3,
            rate_per_minute: 2,
            max_concurrency: 1,
            max_request_bytes: 64,
            max_response_bytes: 128,
            max_duration_seconds: 5,
        }
    }

    fn authority(budget: GrantBudget) -> LeaseAuthority {
        authority_for_boot(budget, "gateway:boot:test", b"gateway challenge:test")
    }

    fn authority_for_boot(budget: GrantBudget, boot_id: &str, challenge: &[u8]) -> LeaseAuthority {
        let authority = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            boot_id.to_owned(),
            Digest::of(challenge),
        )
        .expect("valid key");
        authority
            .register_grant("grant:1", 3, budget)
            .expect("register grant");
        authority
    }

    fn spec(lease_id: &str, intent: &[u8]) -> LeaseSpec {
        let nonce_digest = Digest::of(lease_id.as_bytes());
        let mut dispatch_nonce = [0_u8; 16];
        dispatch_nonce.copy_from_slice(&nonce_digest.as_bytes()[..16]);
        let mut spec = LeaseSpec {
            lease_id: lease_id.to_owned(),
            intent_digest: Digest::of(intent),
            decision_digest: Digest::of(format!("decision:{lease_id}").as_bytes()),
            grant_id: "grant:1".to_owned(),
            grant_version: 3,
            scope_epoch: 7,
            authority_key_id: "authority-key:test".to_owned(),
            scope_epoch_binding_digest: Digest::of(b"scope epoch binding:test"),
            gateway_boot_id: "gateway:boot:test".to_owned(),
            request_binding_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            resolution_digest: Digest::ZERO,
            correlation_id: "correlation:1".to_owned(),
            egress_plane: EgressPlane::TargetGateway,
            dispatch_nonce,
            retry_of_intent_digest: None,
            issued_at_millis: NOW - 1,
            expires_at_millis: NOW + 5_000,
            reservation: LeaseBudgetReservation {
                action_count: 1,
                request_bytes: 4,
                response_bytes: 8,
                duration_seconds: 2,
            },
        };
        seal_spec(&mut spec);
        spec
    }

    fn seal_spec(spec: &mut LeaseSpec) {
        let bound = request(spec, vec![1]);
        spec.request_binding_digest = bound.lease_binding_digest();
        spec.semantic_action_digest = bound.semantic_action_digest;
        spec.resolution_digest = bound.resolution_digest;
    }

    fn request(spec: &LeaseSpec, proof: Vec<u8>) -> DispatchRequest {
        let mut request = DispatchRequest {
            action_id: "action:1".to_owned(),
            correlation_id: "correlation:1".to_owned(),
            target_id: "target:loopback".to_owned(),
            grant_id: spec.grant_id.clone(),
            grant_version: spec.grant_version,
            pack_id: "web".to_owned(),
            action_family: "http.semantic".to_owned(),
            identity_id: "identity:operator".to_owned(),
            tenant_id: Some("tenant:owned".to_owned()),
            intent_digest: spec.intent_digest,
            decision_digest: spec.decision_digest,
            lease_id: spec.lease_id.clone(),
            scope_epoch: spec.scope_epoch,
            action_kind: ActionKind::SemanticHttpV1,
            action_class: ActionClass::SafeProbe,
            egress_plane: EgressPlane::TargetGateway,
            flow_kind: FlowKind::TopLevel,
            parent_action_id: None,
            required_features: vec![RequiredFeature::GatewayDispatchV1],
            hostname: "localhost".to_owned(),
            protocol: "http".to_owned(),
            method: "GET".to_owned(),
            path: "/".to_owned(),
            target: "127.0.0.1:8080".parse().expect("address"),
            resolution_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            dispatch_nonce: spec.dispatch_nonce,
            request_issued_at_millis: spec.issued_at_millis,
            request_expires_at_millis: spec.expires_at_millis,
            retry_of_intent_digest: spec.retry_of_intent_digest,
            payload: b"PING".to_vec(),
            scope_proof: b"scope-proof".to_vec(),
            lease_proof: proof,
            compiler_proof: b"compiler-proof".to_vec(),
            canary_ref: None,
            checkpoint_ref: None,
            cleanup_plan_ref: None,
        };
        request.bind_canonical_semantics();
        request
    }

    fn spec_for_request(request: &DispatchRequest) -> LeaseSpec {
        LeaseSpec {
            lease_id: request.lease_id.clone(),
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            scope_epoch: request.scope_epoch,
            authority_key_id: "authority-key:test".to_owned(),
            scope_epoch_binding_digest: Digest::of(b"scope epoch binding:test"),
            gateway_boot_id: "gateway:boot:test".to_owned(),
            request_binding_digest: request.lease_binding_digest(),
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            correlation_id: request.correlation_id.clone(),
            egress_plane: request.egress_plane,
            dispatch_nonce: request.dispatch_nonce,
            retry_of_intent_digest: request.retry_of_intent_digest,
            issued_at_millis: request.request_issued_at_millis,
            expires_at_millis: request.request_expires_at_millis,
            reservation: LeaseBudgetReservation {
                action_count: 1,
                request_bytes: request.payload.len() as u64,
                response_bytes: 8,
                duration_seconds: 2,
            },
        }
    }

    fn completion(outcome: DispatchOutcome) -> LeaseCompletion {
        LeaseCompletion {
            outcome,
            bytes_sent: 4,
            bytes_received: 4,
            elapsed_millis: 50,
        }
    }

    fn reconciliation_key() -> [u8; 32] {
        std::array::from_fn(|index| u8::try_from(index + 65).expect("small key byte"))
    }

    fn authority_with_reconciliation(
        budget: GrantBudget,
    ) -> (LeaseAuthority, ReconciliationAuthority) {
        let authority = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:test".to_owned(),
            Digest::of(b"gateway challenge:test"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("valid lease and reconciliation keys");
        authority
            .register_grant("grant:1", 3, budget)
            .expect("register grant");
        let reconciler = ReconciliationAuthority::new(
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("valid reconciliation signer");
        (authority, reconciler)
    }

    fn authenticated_unknown_receipt(
        authority: &LeaseAuthority,
        lease: &LeaseSpec,
    ) -> DispatchReceipt {
        let issued = authority.issue(lease.clone()).expect("issue unknown lease");
        let request = request(lease, issued.proof.clone());
        let approval = authority
            .reserve(&request, NOW)
            .expect("reserve unknown lease");
        finalize_unknown_receipt(authority, lease, issued, request, approval)
    }

    fn finalize_unknown_receipt(
        authority: &LeaseAuthority,
        lease: &LeaseSpec,
        issued: IssuedLease,
        request: DispatchRequest,
        approval: LeaseApproval,
    ) -> DispatchReceipt {
        authority
            .finalize(&approval, completion(DispatchOutcome::UnknownOutcome))
            .expect("finalize unknown lease");
        let request_binding_digest = request.lease_binding_digest();
        let request_digest = Digest::of(&request.payload);
        let mut receipt = DispatchReceipt {
            receipt_id: Digest::ZERO,
            receipt_authentication_tag: Digest::ZERO,
            action_id: request.action_id,
            correlation_id: request.correlation_id,
            lease_id: request.lease_id,
            grant_id: request.grant_id,
            grant_version: request.grant_version,
            authority_key_id: lease.authority_key_id.clone(),
            scope_epoch_binding_digest: lease.scope_epoch_binding_digest,
            lease_key_id: issued.lease_key_id,
            gateway_boot_id: issued.gateway_boot_id,
            boot_challenge_digest: issued.boot_challenge_digest,
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            scope_epoch: request.scope_epoch,
            semantic_action_digest: request.semantic_action_digest,
            request_binding_digest,
            request_frame_digest: Digest::of(b"canonical request frame"),
            resolution_digest: request.resolution_digest,
            egress_plane: request.egress_plane,
            dispatch_nonce: request.dispatch_nonce,
            lease_issued_at_millis: request.request_issued_at_millis,
            lease_expires_at_millis: request.request_expires_at_millis,
            retry_of_intent_digest: request.retry_of_intent_digest,
            reserved_action_count: lease.reservation.action_count,
            reserved_request_bytes: lease.reservation.request_bytes,
            reserved_response_bytes: lease.reservation.response_bytes,
            reserved_duration_seconds: lease.reservation.duration_seconds,
            request_digest,
            response_digest: None,
            outcome: DispatchOutcome::UnknownOutcome,
            dispatched_at_millis: NOW,
            completed_at_millis: NOW + 1,
            bytes_sent: 4,
            bytes_received: 0,
            reconciliation_required: true,
        };
        receipt.receipt_id = receipt.canonical_id();
        receipt.receipt_authentication_tag = authority
            .authenticate_receipt(&approval, &receipt)
            .expect("authenticate exact receipt");
        receipt
    }

    fn same_intent_unknown_receipts(
        authority: &LeaseAuthority,
        second_grant_id: &str,
        second_grant_version: u64,
    ) -> (LeaseSpec, DispatchReceipt, LeaseSpec, DispatchReceipt) {
        authority
            .register_grant(second_grant_id, second_grant_version, budget())
            .expect("register second grant");
        let mut first = spec("lease:same-intent-grant-1", b"intent:shared-across-grants");
        seal_spec(&mut first);
        let mut second = spec("lease:same-intent-grant-2", b"intent:shared-across-grants");
        second.grant_id = second_grant_id.to_owned();
        second.grant_version = second_grant_version;
        seal_spec(&mut second);

        let first_issued = authority.issue(first.clone()).expect("issue first grant");
        let first_request = request(&first, first_issued.proof.clone());
        let first_approval = authority
            .reserve(&first_request, NOW)
            .expect("reserve first grant");
        let second_issued = authority.issue(second.clone()).expect("issue second grant");
        let second_request = request(&second, second_issued.proof.clone());
        let second_approval = authority
            .reserve(&second_request, NOW)
            .expect("reserve second grant before either finalization");

        let first_receipt = finalize_unknown_receipt(
            authority,
            &first,
            first_issued,
            first_request,
            first_approval,
        );
        let second_receipt = finalize_unknown_receipt(
            authority,
            &second,
            second_issued,
            second_request,
            second_approval,
        );
        (first, first_receipt, second, second_receipt)
    }

    #[test]
    fn recomputable_unkeyed_receipt_cannot_forge_gateway_authenticity() {
        let (authority, _) = authority_with_reconciliation(budget());
        let lease = spec(
            "lease:authenticated-receipt",
            b"intent:authenticated-receipt",
        );
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        authority
            .verify_dispatch_receipt(&receipt)
            .expect("gateway-authenticated receipt");

        let mut forged = receipt.clone();
        forged.bytes_received = 1;
        forged.receipt_id = forged.canonical_id();
        forged.receipt_authentication_tag = forged.receipt_id;
        assert_eq!(
            authority.verify_dispatch_receipt(&forged),
            Err(DenialCode::LeaseBindingMismatch)
        );
    }

    #[test]
    fn arbitrary_reconciliation_digest_cannot_clear_unknown_outcome_hold() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:reconciliation-proof", b"intent:reconciliation-proof");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let valid = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"durable terminal evidence"),
                *b"reconcile-proof1",
                NOW + 2,
            )
            .expect("issue exact reconciliation proof");

        let mut forged = valid.clone();
        forged.terminal_evidence_digest = Digest::of(b"attacker-selected digest");
        forged.reconciliation_id = forged.canonical_id();
        forged.authentication_tag = forged.reconciliation_id;
        assert_eq!(
            authority.reconcile(&receipt, &forged),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Ok(None)
        );

        authority
            .reconcile(&receipt, &valid)
            .expect("authenticated reconciliation");
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Ok(Some(valid.reconciliation_id))
        );
        assert_eq!(
            authority.reconcile(&receipt, &valid),
            Err(DenialCode::LeaseReplay)
        );
    }

    #[test]
    fn reconciliation_grant_binding_cannot_be_recomputed_without_the_control_plane_key() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        authority
            .register_grant("grant:2", 9, budget())
            .expect("register unrelated grant");
        let lease = spec("lease:grant-bound-proof", b"intent:grant-bound-proof");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let valid = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"grant-bound terminal evidence"),
                *b"grant-proof-0001",
                NOW + 2,
            )
            .expect("issue grant-bound reconciliation proof");

        let mut forged_grant = valid.clone();
        forged_grant.grant_id = "grant:2".to_owned();
        forged_grant.grant_version = 9;
        forged_grant.reconciliation_id = forged_grant.canonical_id();
        forged_grant.authentication_tag = forged_grant.reconciliation_id;
        assert_eq!(
            authority.reconcile(&receipt, &forged_grant),
            Err(DenialCode::LeaseReconciliationRequired)
        );

        let mut forged_version = valid.clone();
        forged_version.grant_version = lease.grant_version + 1;
        forged_version.reconciliation_id = forged_version.canonical_id();
        forged_version.authentication_tag = forged_version.reconciliation_id;
        assert_eq!(
            authority.reconcile(&receipt, &forged_version),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Ok(None),
            "forged grant bindings must leave the exact hold intact"
        );
        authority
            .reconcile(&receipt, &valid)
            .expect("unaltered authenticated proof still reconciles the exact hold");
    }

    #[test]
    fn concurrent_reconciliation_reuse_has_one_winner_and_one_replay() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:concurrent-reconcile", b"intent:concurrent-reconcile");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let reconciliation = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"concurrent terminal evidence"),
                *b"concurrent-proof",
                NOW + 2,
            )
            .expect("issue reusable reconciliation candidate");
        let authority = Arc::new(authority);
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let receipt = receipt.clone();
                let reconciliation = reconciliation.clone();
                thread::spawn(move || {
                    barrier.wait();
                    authority.reconcile(&receipt, &reconciliation)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("reconciliation thread"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DenialCode::LeaseReplay)))
                .count(),
            1
        );
    }

    #[test]
    fn control_plane_proof_cannot_bypass_dispatch_receipt_binding() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:receipt-bound-hold", b"intent:receipt-bound-hold");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let bypass = reconciler
            .issue_control_plane_hold(
                (&lease.grant_id, lease.grant_version),
                lease.intent_digest,
                DispatchOutcome::Completed,
                Digest::of(b"unbound terminal evidence"),
                *b"bypass-proof-001",
                NOW + 2,
            )
            .expect("well-formed but unbound proof");

        assert_eq!(
            authority.reconcile_control_plane_hold(&bypass),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Ok(None)
        );

        let checkpoint = authority.checkpoint().expect("typed hold checkpoint");
        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:restored".to_owned(),
            Digest::of(b"restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("restored authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore typed hold");
        assert_eq!(
            restored.reconcile_control_plane_hold(&bypass),
            Err(DenialCode::LeaseReconciliationRequired)
        );

        let exact = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"bound terminal evidence"),
                *b"exact-proof-0001",
                NOW + 3,
            )
            .expect("receipt-bound proof");
        restored
            .reconcile(&receipt, &exact)
            .expect("typed receipt hold survives recovery");
    }

    #[test]
    fn reconciliation_for_one_grant_cannot_authorize_same_intent_in_another_grant() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let (first, first_receipt, second, second_receipt) =
            same_intent_unknown_receipts(&authority, "grant:2", 9);
        let first_reconciliation = reconciler
            .issue(
                &first_receipt,
                DispatchOutcome::Completed,
                Digest::of(b"first grant terminal evidence"),
                *b"reconcile-grant1",
                NOW + 2,
            )
            .expect("first grant reconciliation");
        authority
            .reconcile(&first_receipt, &first_reconciliation)
            .expect("reconcile first grant only");

        let mut unauthorized_retry = spec(
            "lease:grant-2-unauthorized-retry",
            b"intent:grant-2-unauthorized-retry",
        );
        unauthorized_retry.grant_id = second.grant_id.clone();
        unauthorized_retry.grant_version = second.grant_version;
        unauthorized_retry.retry_of_intent_digest = Some(second.intent_digest);
        seal_spec(&mut unauthorized_retry);
        assert_eq!(
            authority.issue(unauthorized_retry),
            Err(DenialCode::RetryAliasInvalid),
            "grant-1 reconciliation must not authorize a grant-2 retry"
        );

        let second_reconciliation = reconciler
            .issue(
                &second_receipt,
                DispatchOutcome::Completed,
                Digest::of(b"second grant terminal evidence"),
                *b"reconcile-grant2",
                NOW + 2,
            )
            .expect("second grant reconciliation");
        authority
            .reconcile(&second_receipt, &second_reconciliation)
            .expect("second grant retains an independent hold");

        let mut authorized_retry = spec(
            "lease:grant-2-authorized-retry",
            b"intent:grant-2-authorized-retry",
        );
        authorized_retry.grant_id = second.grant_id;
        authorized_retry.grant_version = second.grant_version;
        authorized_retry.retry_of_intent_digest = Some(second.intent_digest);
        seal_spec(&mut authorized_retry);
        let proof = authority
            .issue(authorized_retry.clone())
            .expect("exact grant-2 reconciliation authorizes a fresh retry")
            .proof;
        authority
            .reserve(&request(&authorized_retry, proof), NOW + 3)
            .expect("fresh grant-2 retry reserves after exact reconciliation");
        assert_ne!(first.grant_id, authorized_retry.grant_id);
    }

    #[test]
    fn reconciliation_for_one_grant_version_cannot_clear_another_version() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let (first, first_receipt, second, second_receipt) =
            same_intent_unknown_receipts(&authority, "grant:1", 4);
        let first_reconciliation = reconciler
            .issue(
                &first_receipt,
                DispatchOutcome::Completed,
                Digest::of(b"first version terminal evidence"),
                *b"reconcile-vers01",
                NOW + 2,
            )
            .expect("first version reconciliation");
        authority
            .reconcile(&first_receipt, &first_reconciliation)
            .expect("reconcile first version only");
        assert_eq!(
            authority.reconciliation_receipt(
                &second.grant_id,
                second.grant_version,
                second.intent_digest,
            ),
            Ok(None)
        );

        let second_reconciliation = reconciler
            .issue(
                &second_receipt,
                DispatchOutcome::Failed,
                Digest::of(b"second version terminal evidence"),
                *b"reconcile-vers02",
                NOW + 2,
            )
            .expect("second version reconciliation");
        authority
            .reconcile(&second_receipt, &second_reconciliation)
            .expect("second version retains an independent hold");
        assert_eq!(first.grant_id, second.grant_id);
        assert_ne!(first.grant_version, second.grant_version);
    }

    #[test]
    fn same_intent_grant_holds_survive_checkpoint_and_reconcile_concurrently() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let (_, first_receipt, _, second_receipt) =
            same_intent_unknown_receipts(&authority, "grant:2", 9);
        let checkpoint = authority.checkpoint().expect("checkpoint both grant holds");
        let restored = Arc::new(
            LeaseAuthority::new_with_reconciliation_verifier(
                "lease-key:test".to_owned(),
                lease_key(),
                "gateway:boot:restored-grants".to_owned(),
                Digest::of(b"restored grant challenge"),
                "reconciliation-key:test".to_owned(),
                reconciliation_key(),
            )
            .expect("restored authority"),
        );
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore both scoped holds");
        let reconciliations = [
            reconciler
                .issue(
                    &first_receipt,
                    DispatchOutcome::Completed,
                    Digest::of(b"first restored terminal evidence"),
                    *b"checkpoint-one01",
                    NOW + 2,
                )
                .expect("first restored reconciliation"),
            reconciler
                .issue(
                    &second_receipt,
                    DispatchOutcome::Failed,
                    Digest::of(b"second restored terminal evidence"),
                    *b"checkpoint-two02",
                    NOW + 2,
                )
                .expect("second restored reconciliation"),
        ];
        let receipts = [first_receipt, second_receipt];
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = receipts
            .into_iter()
            .zip(reconciliations)
            .map(|(receipt, reconciliation)| {
                let authority = Arc::clone(&restored);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    authority.reconcile(&receipt, &reconciliation)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("reconciliation thread"))
            .collect();
        assert!(
            results.iter().all(Result::is_ok),
            "each grant must retain an independent durable hold: {results:?}"
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_case_one() {
        let digest = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            digest.to_hex(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn proof_is_bound_and_one_use_even_after_completion() {
        let authority = authority(budget());
        let lease = spec("lease:one", b"intent:one");
        let issued = authority.issue(lease.clone()).expect("issue lease");
        let dispatch_request = request(&lease, issued.proof);
        assert_eq!(
            lease.request_binding_digest,
            dispatch_request.lease_binding_digest()
        );
        assert_eq!(
            lease.semantic_action_digest,
            dispatch_request.semantic_action_digest
        );
        assert_eq!(lease.resolution_digest, dispatch_request.resolution_digest);
        assert_eq!(lease.correlation_id, dispatch_request.correlation_id);
        assert_eq!(lease.dispatch_nonce, dispatch_request.dispatch_nonce);
        assert_eq!(
            lease.issued_at_millis,
            dispatch_request.request_issued_at_millis
        );
        assert_eq!(
            lease.expires_at_millis,
            dispatch_request.request_expires_at_millis
        );
        let approval = authority
            .reserve(&dispatch_request, NOW)
            .expect("reserve once");
        authority
            .finalize(&approval, completion(DispatchOutcome::Completed))
            .expect("finalize");
        assert_eq!(
            authority.reserve(&dispatch_request, NOW + 1),
            Err(DenialCode::LeaseReplay)
        );

        let second = spec("lease:bound", b"intent:bound");
        let issued = authority.issue(second.clone()).expect("issue lease");
        let mut forged = request(&second, issued.proof);
        forged.intent_digest = Digest::of(b"different-intent");
        assert_eq!(
            authority.reserve(&forged, NOW),
            Err(DenialCode::LeaseBindingMismatch)
        );
    }

    #[test]
    fn every_authority_and_decision_binding_is_checked_before_consumption() {
        let authority = authority(budget());
        let lease = spec("lease:all-bindings", b"intent:all-bindings");
        let proof = authority.issue(lease.clone()).expect("issue lease").proof;
        let base = request(&lease, proof);
        let mut variants = Vec::new();
        let mut decision = base.clone();
        decision.decision_digest = Digest::of(b"different-decision");
        variants.push(decision);
        let mut grant = base.clone();
        grant.grant_id = "grant:other".to_owned();
        variants.push(grant);
        let mut version = base.clone();
        version.grant_version += 1;
        variants.push(version);
        let mut epoch = base.clone();
        epoch.scope_epoch += 1;
        variants.push(epoch);
        for variant in variants {
            assert_eq!(
                authority.reserve(&variant, NOW),
                Err(DenialCode::LeaseBindingMismatch)
            );
        }
        assert!(authority.reserve(&base, NOW).is_ok());
    }

    #[test]
    fn forged_not_yet_valid_and_expired_proofs_fail_closed() {
        let authority = authority(budget());
        let mut lease = spec("lease:time", b"intent:time");
        lease.issued_at_millis = NOW + 1;
        seal_spec(&mut lease);
        let issued = authority.issue(lease.clone()).expect("issue lease");
        let mut candidate = request(&lease, issued.proof);
        assert_eq!(
            authority.reserve(&candidate, NOW),
            Err(DenialCode::LeaseNotYetValid)
        );
        candidate.lease_proof[0] ^= 1;
        assert_eq!(
            authority.reserve(&candidate, NOW + 1),
            Err(DenialCode::LeaseDenied)
        );

        let mut expired = spec("lease:expired", b"intent:expired");
        expired.expires_at_millis = NOW;
        seal_spec(&mut expired);
        let issued = authority.issue(expired.clone()).expect("issue lease");
        assert_eq!(
            authority.reserve(&request(&expired, issued.proof), NOW),
            Err(DenialCode::LeaseExpired)
        );
    }

    #[test]
    fn invalid_reservations_and_oversized_requests_are_denied_before_consumption() {
        let authority = authority(budget());
        let mut excessive_ttl = spec("lease:ttl", b"intent:ttl");
        excessive_ttl.expires_at_millis = excessive_ttl.issued_at_millis + MAX_LEASE_TTL_MILLIS + 1;
        seal_spec(&mut excessive_ttl);
        assert_eq!(
            authority.issue(excessive_ttl),
            Err(DenialCode::LeaseBindingMismatch)
        );
        let mut invalid = spec("lease:zero-request", b"intent:zero-request");
        invalid.reservation.request_bytes = 0;
        assert_eq!(
            authority.issue(invalid),
            Err(DenialCode::LeaseReservationExceeded)
        );
        let mut excessive = spec("lease:excessive", b"intent:excessive");
        excessive.reservation.response_bytes = 129;
        assert_eq!(
            authority.issue(excessive),
            Err(DenialCode::LeaseReservationExceeded)
        );

        let lease = spec("lease:request-cap", b"intent:request-cap");
        let proof = authority
            .issue(lease.clone())
            .expect("issue valid lease")
            .proof;
        let mut oversized = request(&lease, proof);
        oversized.payload.push(b'!');
        assert_eq!(
            authority.reserve(&oversized, NOW),
            Err(DenialCode::LeaseReservationExceeded)
        );
        oversized.payload.pop();
        assert!(authority.reserve(&oversized, NOW).is_ok());
    }

    #[test]
    fn reservation_total_rate_and_concurrency_are_accounted_atomically() {
        let mut limits = budget();
        limits.total_actions = 2;
        limits.rate_per_minute = 1;
        let authority = authority(limits);

        let first = spec("lease:first", b"intent:first");
        let first_proof = authority.issue(first.clone()).expect("first").proof;
        let first_approval = authority
            .reserve(&request(&first, first_proof), NOW)
            .expect("reserve first");
        let concurrent = spec("lease:concurrent", b"intent:concurrent");
        let concurrent_proof = authority
            .issue(concurrent.clone())
            .expect("concurrent")
            .proof;
        assert_eq!(
            authority.reserve(&request(&concurrent, concurrent_proof), NOW),
            Err(DenialCode::LeaseRateExceeded)
        );
        authority
            .finalize(&first_approval, completion(DispatchOutcome::Completed))
            .expect("finalize first");

        let mut second = spec("lease:second", b"intent:second");
        second.issued_at_millis = NOW + RATE_WINDOW_MILLIS;
        second.expires_at_millis = second.issued_at_millis + 5_000;
        seal_spec(&mut second);
        let second_proof = authority.issue(second.clone()).expect("second").proof;
        let second_approval = authority
            .reserve(
                &request(&second, second_proof),
                NOW + RATE_WINDOW_MILLIS + 1,
            )
            .expect("reserve after rate window");
        authority
            .finalize(&second_approval, completion(DispatchOutcome::Completed))
            .expect("finalize second");

        let mut exhausted = spec("lease:exhausted", b"intent:exhausted");
        exhausted.issued_at_millis = NOW + RATE_WINDOW_MILLIS;
        exhausted.expires_at_millis = exhausted.issued_at_millis + 5_000;
        seal_spec(&mut exhausted);
        let exhausted_proof = authority.issue(exhausted.clone()).expect("exhausted").proof;
        assert_eq!(
            authority.reserve(
                &request(&exhausted, exhausted_proof),
                NOW + RATE_WINDOW_MILLIS + 2,
            ),
            Err(DenialCode::GrantBudgetExhausted)
        );
        let usage = authority.usage("grant:1", 3).expect("usage");
        assert_eq!(usage.dispatched_actions, 2);
        assert_eq!(usage.active_dispatches, 0);
        assert_eq!(usage.actual_request_bytes, 8);
    }

    #[test]
    fn concurrency_precedes_dispatch_and_abandon_still_consumes_lease() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        let authority = authority(limits);
        let first = spec("lease:active", b"intent:active");
        let first_proof = authority.issue(first.clone()).expect("first").proof;
        let first_approval = authority
            .reserve(&request(&first, first_proof), NOW)
            .expect("reserve first");
        let second = spec("lease:blocked", b"intent:blocked");
        let second_proof = authority.issue(second.clone()).expect("second").proof;
        assert_eq!(
            authority.reserve(&request(&second, second_proof), NOW + 1),
            Err(DenialCode::LeaseConcurrencyExceeded)
        );
        authority.abandon(&first_approval).expect("abandon");
        assert_eq!(
            authority.reserve(
                &request(&first, authority.sign_spec(&first).as_bytes().to_vec()),
                NOW + 2
            ),
            Err(DenialCode::LeaseReplay)
        );
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_the_grant_limit() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        let authority = Arc::new(authority(limits));
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for index in 0..2 {
            let lease = spec(
                &format!("lease:thread-{index}"),
                format!("intent:thread-{index}").as_bytes(),
            );
            let proof = authority
                .issue(lease.clone())
                .expect("issue concurrent lease")
                .proof;
            let request = request(&lease, proof);
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                authority.reserve(&request, NOW)
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("reservation worker"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| { matches!(result, Err(DenialCode::LeaseConcurrencyExceeded)) })
                .count(),
            1
        );
        let approval = results
            .into_iter()
            .find_map(Result::ok)
            .expect("one successful reservation");
        authority.abandon(&approval).expect("release reservation");
        assert_eq!(
            authority
                .usage("grant:1", 3)
                .expect("usage")
                .active_dispatches,
            0
        );
    }

    #[test]
    fn poisoned_lease_state_denies_every_authority_operation() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let unknown = spec("lease:poison-unknown", b"intent:poison-unknown");
        let receipt = authenticated_unknown_receipt(&authority, &unknown);
        let reconciliation = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"poison test terminal evidence"),
                *b"poison-proof-001",
                NOW + 2,
            )
            .expect("reconciliation proof before poison");
        let authority = Arc::new(authority);
        let lease = spec("lease:poison", b"intent:poison");
        let proof = authority
            .issue(lease.clone())
            .expect("issue before poison")
            .proof;
        let candidate = request(&lease, proof);

        let poisoner = Arc::clone(&authority);
        assert!(
            thread::spawn(move || {
                let _guard = poisoner.state.lock().expect("lock state before poison");
                panic!("poison lease accounting state");
            })
            .join()
            .is_err()
        );

        assert_eq!(
            authority.reserve(&candidate, NOW),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.issue(spec("lease:after-poison", b"intent:after-poison")),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.register_grant("grant:after-poison", 1, budget()),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.usage("grant:1", 3),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.reconcile(&receipt, &reconciliation),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
    }

    #[test]
    fn unknown_outcome_blocks_new_lease_until_explicit_reconciliation() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let first = spec("lease:unknown", b"intent:shared");
        let receipt = authenticated_unknown_receipt(&authority, &first);

        let mut retry = spec("lease:retry", b"intent:shared");
        retry.decision_digest = Digest::of(b"new-decision");
        seal_spec(&mut retry);
        let retry_proof = authority.issue(retry.clone()).expect("retry").proof;
        let retry_request = request(&retry, retry_proof);
        assert_eq!(
            authority.reserve(&retry_request, NOW + 1),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        let reconciliation = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"operator terminal evidence"),
                *b"operator-proof01",
                NOW + 2,
            )
            .expect("authenticated operator reconciliation");
        authority
            .reconcile(&receipt, &reconciliation)
            .expect("explicit reconciliation");
        assert_eq!(
            authority
                .reconciliation_receipt(&retry.grant_id, retry.grant_version, retry.intent_digest,)
                .expect("recorded reconciliation"),
            Some(reconciliation.reconciliation_id)
        );
        assert_eq!(
            authority.reserve(&retry_request, NOW + 2),
            Err(DenialCode::LeaseReplay)
        );
        let mut explicit_retry = spec("lease:retry-alias", b"intent:retry-alias");
        explicit_retry.retry_of_intent_digest = Some(retry.intent_digest);
        seal_spec(&mut explicit_retry);
        let proof = authority
            .issue(explicit_retry.clone())
            .expect("append-only retry alias")
            .proof;
        assert!(
            authority
                .reserve(&request(&explicit_retry, proof), NOW + 2)
                .is_ok()
        );
    }

    #[test]
    fn response_or_duration_overrun_forces_reconciliation() {
        let authority = authority(budget());
        let lease = spec("lease:overrun", b"intent:overrun");
        let proof = authority.issue(lease.clone()).expect("issue").proof;
        let approval = authority
            .reserve(&request(&lease, proof), NOW)
            .expect("reserve");
        let finalization = authority
            .finalize(
                &approval,
                LeaseCompletion {
                    outcome: DispatchOutcome::Completed,
                    bytes_sent: 4,
                    bytes_received: 9,
                    elapsed_millis: 50,
                },
            )
            .expect("finalize");
        assert!(finalization.reservation_overrun);
        assert!(finalization.reconciliation_required);
    }

    #[test]
    fn grant_revocation_cancels_available_and_active_leases_atomically() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        limits.max_concurrency = 2;
        let (authority, reconciler) = authority_with_reconciliation(limits);
        let active = spec("lease:revoke-active", b"intent:revoke-active");
        let active_proof = authority.issue(active.clone()).expect("active issue").proof;
        authority
            .reserve(&request(&active, active_proof), NOW)
            .expect("active reserve");
        let available = spec("lease:revoke-available", b"intent:revoke-available");
        let available_proof = authority
            .issue(available.clone())
            .expect("available issue")
            .proof;

        let summary = authority
            .revoke_grant("grant:1", 3, 7)
            .expect("revoke grant");
        assert_eq!(
            summary,
            LeaseRevocationSummary {
                canceled_available: 1,
                interrupted_active: 1,
            }
        );
        let usage = authority.usage("grant:1", 3).expect("revoked usage");
        assert_eq!(usage.active_dispatches, 0);
        assert_eq!(usage.active_reserved_request_bytes, 0);
        assert_eq!(
            authority.reserve(&request(&available, available_proof), NOW + 1),
            Err(DenialCode::LeaseReplay)
        );
        assert_eq!(
            authority.issue(spec("lease:after-revoke", b"intent:after-revoke")),
            Err(DenialCode::LeaseRevoked)
        );
        let reconciliation = reconciler
            .issue_control_plane_hold(
                (&active.grant_id, active.grant_version),
                active.intent_digest,
                DispatchOutcome::Failed,
                Digest::of(b"revocation terminal evidence"),
                *b"revoke-proof-001",
                NOW + 2,
            )
            .expect("revocation reconciliation proof");
        assert_eq!(
            authority.reconcile_control_plane_hold(&reconciliation),
            Ok(())
        );
    }

    #[test]
    fn nonce_and_lease_id_reservations_are_append_only() {
        let authority = authority(budget());
        let first = spec("lease:append-only", b"intent:append-only");
        authority.issue(first.clone()).expect("first issue");

        let mut reused_nonce = spec("lease:other", b"intent:other");
        reused_nonce.dispatch_nonce = first.dispatch_nonce;
        seal_spec(&mut reused_nonce);
        assert_eq!(authority.issue(reused_nonce), Err(DenialCode::LeaseReplay));
        let mut reused_id = spec("lease:append-only", b"intent:new");
        reused_id.dispatch_nonce = *b"fedcba9876543210";
        seal_spec(&mut reused_id);
        assert_eq!(authority.issue(reused_id), Err(DenialCode::LeaseReplay));
    }

    #[test]
    fn child_batch_and_state_change_each_require_their_own_exact_lease() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        limits.max_concurrency = 3;
        let authority = authority(limits);
        let parent = spec("lease:parent", b"intent:parent");
        let parent_proof = authority.issue(parent.clone()).expect("parent issue").proof;
        let parent_request = request(&parent, parent_proof.clone());

        let mut forged_child = parent_request.clone();
        forged_child.action_id = "action:batch-child-forged".to_owned();
        forged_child.flow_kind = FlowKind::BatchChild;
        forged_child.parent_action_id = Some(parent_request.action_id.clone());
        forged_child.bind_canonical_semantics();
        assert_eq!(
            authority.reserve(&forged_child, NOW),
            Err(DenialCode::LeaseBindingMismatch)
        );

        let mut child = forged_child;
        child.action_id = "action:batch-child".to_owned();
        child.lease_id = "lease:batch-child".to_owned();
        child.intent_digest = Digest::of(b"intent:batch-child");
        child.decision_digest = Digest::of(b"decision:batch-child");
        child.dispatch_nonce = *b"batch-child-0001";
        child.lease_proof = vec![1];
        child.bind_canonical_semantics();
        let child_spec = spec_for_request(&child);
        child.lease_proof = authority.issue(child_spec).expect("child issue").proof;
        let child_approval = authority
            .reserve(&child, NOW)
            .expect("child has independent lease");
        authority
            .finalize(&child_approval, completion(DispatchOutcome::Completed))
            .expect("finalize child");

        let mut state_change = parent_request;
        state_change.action_id = "action:state-change".to_owned();
        state_change.lease_id = "lease:state-change".to_owned();
        state_change.intent_digest = Digest::of(b"intent:state-change");
        state_change.decision_digest = Digest::of(b"decision:state-change");
        state_change.dispatch_nonce = *b"state-change-001";
        state_change.action_class = ActionClass::StateChange;
        state_change.canary_ref = Some("canary:state-change".to_owned());
        state_change.checkpoint_ref = Some("checkpoint:before-state-change".to_owned());
        state_change.cleanup_plan_ref = Some("cleanup:state-change".to_owned());
        state_change.lease_proof = vec![1];
        state_change.bind_canonical_semantics();
        let state_spec = spec_for_request(&state_change);
        state_change.lease_proof = authority.issue(state_spec).expect("state lease").proof;
        let mut forged_checkpoint = state_change.clone();
        forged_checkpoint.checkpoint_ref = Some("checkpoint:substituted".to_owned());
        forged_checkpoint.bind_canonical_semantics();
        assert_eq!(
            authority.reserve(&forged_checkpoint, NOW + 1),
            Err(DenialCode::LeaseBindingMismatch)
        );
        assert!(authority.reserve(&state_change, NOW + 1).is_ok());
    }

    #[test]
    fn sealed_checkpoint_preserves_budget_replay_and_unknown_outcome_across_boots() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        let source = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:source".to_owned(),
            Digest::of(b"source challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("source authority");
        source
            .register_grant("grant:1", 3, limits.clone())
            .expect("source grant");
        let mut active = spec("lease:crash-active", b"intent:crash-active");
        active.gateway_boot_id = "gateway:boot:source".to_owned();
        seal_spec(&mut active);
        let proof = source.issue(active.clone()).expect("issue active").proof;
        source
            .reserve(&request(&active, proof.clone()), NOW)
            .expect("reserve active before crash");
        let mut available = spec("lease:crash-available", b"intent:crash-available");
        available.gateway_boot_id = "gateway:boot:source".to_owned();
        seal_spec(&mut available);
        source.issue(available.clone()).expect("issue available");
        let checkpoint = source.checkpoint().expect("sealed checkpoint");

        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:restored".to_owned(),
            Digest::of(b"restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("fresh authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore checkpoint");
        let usage = restored.usage("grant:1", 3).expect("restored usage");
        assert_eq!(usage.dispatched_actions, 1);
        assert_eq!(usage.active_dispatches, 0);
        assert_eq!(
            restored.reserve(&request(&active, proof), NOW + 1),
            Err(DenialCode::LeaseDenied)
        );

        let mut retry = spec("lease:crash-retry", b"intent:crash-active");
        retry.gateway_boot_id = "gateway:boot:restored".to_owned();
        seal_spec(&mut retry);
        let retry_proof = restored.issue(retry.clone()).expect("new boot lease").proof;
        assert_eq!(
            restored.reserve(&request(&retry, retry_proof), NOW + 1),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        let reconciler = ReconciliationAuthority::new(
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("reconciliation signer");
        let reconciliation = reconciler
            .issue_control_plane_hold(
                (&active.grant_id, active.grant_version),
                active.intent_digest,
                DispatchOutcome::Failed,
                Digest::of(b"crash terminal evidence"),
                *b"crash-proof-0001",
                NOW + 2,
            )
            .expect("crash reconciliation proof");
        restored
            .reconcile_control_plane_hold(&reconciliation)
            .expect("reconcile crash uncertainty");

        let mut next = spec("lease:after-crash", b"intent:after-crash");
        next.gateway_boot_id = "gateway:boot:restored".to_owned();
        seal_spec(&mut next);
        let next_proof = restored
            .issue(next.clone())
            .expect("post-crash issue")
            .proof;
        assert!(
            restored
                .reserve(&request(&next, next_proof), NOW + 2)
                .is_ok()
        );
        let mut replayed_available = available;
        replayed_available.gateway_boot_id = "gateway:boot:restored".to_owned();
        seal_spec(&mut replayed_available);
        assert_eq!(
            restored.issue(replayed_available),
            Err(DenialCode::LeaseReplay)
        );
    }

    #[test]
    fn recovery_rejects_tamper_wrong_anchor_same_boot_and_wrong_key() {
        let source = authority_for_boot(budget(), "gateway:boot:source", b"source challenge");
        let checkpoint = source.checkpoint().expect("checkpoint");

        let same_boot = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:source".to_owned(),
            Digest::of(b"different challenge"),
        )
        .expect("same boot authority");
        assert_eq!(
            same_boot.restore_checkpoint(&checkpoint, checkpoint.checkpoint_id()),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );

        let wrong_anchor = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:wrong-anchor".to_owned(),
            Digest::of(b"wrong anchor challenge"),
        )
        .expect("wrong anchor authority");
        assert_eq!(
            wrong_anchor.restore_checkpoint(&checkpoint, Digest::of(b"older checkpoint")),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );

        let mut tampered = checkpoint.as_bytes().to_vec();
        tampered[20] ^= 1;
        let tampered =
            LeaseRecoveryCheckpoint::from_bytes(tampered).expect("outer shape remains valid");
        let target = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:tamper-target".to_owned(),
            Digest::of(b"tamper target challenge"),
        )
        .expect("tamper target");
        assert_eq!(
            target.restore_checkpoint(&tampered, tampered.checkpoint_id()),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );

        let wrong_key = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            std::array::from_fn(|index| u8::try_from(index + 65).expect("small wrong-key byte")),
            "gateway:boot:wrong-key".to_owned(),
            Digest::of(b"wrong key challenge"),
        )
        .expect("wrong key authority");
        assert_eq!(
            wrong_key.restore_checkpoint(&checkpoint, checkpoint.checkpoint_id()),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );
    }
}
