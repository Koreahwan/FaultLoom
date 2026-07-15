use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use crate::Digest;
use crate::ipc::{DenialCode, DispatchOutcome, DispatchReceipt, DispatchRequest, EgressPlane};
use crate::policy::{LeaseApproval, LeaseCompletion, LeaseFinalization, LeaseVerifier};
use crate::scope::{
    CancellationCause, ScopeCancellation, ScopeCancellationReport, ScopeCancellationSink,
};
use crate::transport::DispatchCancellation;

use self::crypto::{
    constant_time_eq, hmac_sha256, push_optional_digest, push_optional_string, push_optional_u64,
    push_string, valid_boot_secret, valid_identifier, valid_nonce,
};
use self::recovery_decode::RecoveryDecoder;
use self::recovery_encode::{
    push_count, push_effect_digests, push_reconciliation_holds, push_reconciliation_key,
    push_reconciliation_receipts, push_retry_aliases, recovery_checkpoint_id,
};
use self::state::held_effect_for_exact_key;

#[path = "lease/state.rs"]
mod state;

#[path = "lease/crypto.rs"]
mod crypto;

#[path = "lease/bindings.rs"]
mod bindings;

#[path = "lease/reconciliation_authority.rs"]
mod reconciliation_authority;

#[path = "lease/recovery_encode.rs"]
mod recovery_encode;

#[path = "lease/recovery_decode.rs"]
mod recovery_decode;

#[path = "lease/authority.rs"]
mod authority;

#[path = "lease/issuance.rs"]
mod issuance;

#[path = "lease/cancellation.rs"]
mod cancellation;

#[path = "lease/checkpoint.rs"]
mod checkpoint;

const RATE_WINDOW_MILLIS: u64 = 60_000;
const MAX_LEASE_TTL_MILLIS: u64 = 60_000;
const HMAC_BLOCK_BYTES: usize = 64;
const RECOVERY_MAGIC: &[u8; 4] = b"FLRC";
const RECOVERY_VERSION: u8 = 7;
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
    pub control_envelope_id: Digest,
    pub request_binding_digest: Digest,
    pub semantic_action_digest: Digest,
    pub resolution_digest: Digest,
    pub compiled_request_digest: Digest,
    pub effect_digest: Digest,
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
    pub effect_digest: Digest,
    pub hold_binding_digest: Digest,
    pub unknown_dispatch_receipt_id: Option<Digest>,
    pub terminal_outcome: DispatchOutcome,
    pub terminal_evidence_digest: Digest,
    pub nonce: [u8; 16],
    pub resolved_at_millis: u64,
    pub authentication_tag: Digest,
}

/// Separate capability for the durable control plane that resolves an
/// ambiguous dispatch. Holding a `LeaseAuthority` alone cannot manufacture a
/// reconciliation receipt.
pub struct ReconciliationAuthority {
    key_id: String,
    signing_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlPlaneReconciliationHold {
    pub grant_id: String,
    pub grant_version: u64,
    pub intent_digest: Digest,
    pub effect_digest: Digest,
    pub hold_binding_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationTerminal {
    pub outcome: DispatchOutcome,
    pub evidence_digest: Digest,
    pub nonce: [u8; 16],
    pub resolved_at_millis: u64,
}

struct ReconciliationBinding {
    key: ReconciliationKey,
    effect_digest: Digest,
    hold_binding_digest: Digest,
    unknown_dispatch_receipt_id: Option<Digest>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReconciliationHold {
    kind: ReconciliationHoldKind,
    binding_digest: Digest,
    retry_invariant_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReconciliationResolution {
    receipt_id: Digest,
    terminal_outcome: DispatchOutcome,
    hold_binding_digest: Digest,
    effect_digest: Digest,
    retry_invariant_digest: Digest,
    retry_consumed: bool,
}

#[derive(Clone, Debug)]
struct LeaseEntry {
    spec: LeaseSpec,
    proof: Digest,
    status: LeaseStatus,
    retry_invariant_digest: Option<Digest>,
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
    reconciliation_required: HashMap<ReconciliationKey, ReconciliationHold>,
    held_effects: HashMap<ReconciliationKey, Digest>,
    reconciliation_receipts: HashMap<ReconciliationKey, ReconciliationResolution>,
    retry_aliases: HashMap<ReconciliationKey, ReconciliationKey>,
    dispatch_nonces: HashSet<[u8; 16]>,
    retired_lease_ids: HashSet<String>,
    retired_intents: HashSet<ReconciliationKey>,
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

/// Gateway-owned capability issuer and atomic lease/budget accountant.
///
/// The key never crosses the local Gateway boundary. A fresh boot may restore
/// only an authenticated checkpoint whose digest was anchored by the external
/// durable control plane. Without that anchor, restart fails closed instead of
/// accepting stale leases or resetting one-use and budget state.
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
        authenticated.extend_from_slice(b"faultloom-lease-recovery-checkpoint-v7\0");
        authenticated.extend_from_slice(payload);
        let expected_tag = hmac_sha256(&self.signing_key, &authenticated);
        if !constant_time_eq(expected_tag.as_bytes(), supplied_tag) {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }

        let mut decoder = RecoveryDecoder::new(payload);
        decoder.expect_prefix(b"faultloom-lease-recovery-state-v7\0")?;
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
        restored.held_effects = decoder.effect_digests()?;
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
            .map(|resolution| resolution.receipt_id)
            .collect::<HashSet<_>>()
            .len();
        let alias_parents: HashSet<_> = restored.retry_aliases.values().cloned().collect();
        let consumed_parents: HashSet<_> = restored
            .reconciliation_receipts
            .iter()
            .filter(|(_, resolution)| resolution.retry_consumed)
            .map(|(key, _)| key.clone())
            .collect();
        if restored.reconciliation_required.iter().any(|(key, hold)| {
            !registered_grant(key)
                || restored.reconciliation_receipts.contains_key(key)
                || hold.binding_digest == Digest::ZERO
                || hold.retry_invariant_digest == Digest::ZERO
        }) || restored
            .reconciliation_required
            .keys()
            .collect::<HashSet<_>>()
            != restored.held_effects.keys().collect::<HashSet<_>>()
            || restored
                .held_effects
                .values()
                .any(|digest| *digest == Digest::ZERO)
            || restored
                .reconciliation_receipts
                .iter()
                .any(|(key, resolution)| {
                    !registered_grant(key)
                        || resolution.receipt_id == Digest::ZERO
                        || resolution.terminal_outcome == DispatchOutcome::UnknownOutcome
                        || resolution.hold_binding_digest == Digest::ZERO
                        || resolution.effect_digest == Digest::ZERO
                        || resolution.retry_invariant_digest == Digest::ZERO
                        || (resolution.terminal_outcome == DispatchOutcome::Completed
                            && resolution.retry_consumed)
                })
            || unique_receipt_count != restored.reconciliation_receipts.len()
            || alias_parents.len() != restored.retry_aliases.len()
            || alias_parents != consumed_parents
            || restored.retry_aliases.iter().any(|(retry, parent)| {
                !registered_grant(retry)
                    || !registered_grant(parent)
                    || retry == parent
                    || retry.grant_id != parent.grant_id
                    || retry.grant_version != parent.grant_version
                    || restored
                        .reconciliation_receipts
                        .get(parent)
                        .is_none_or(|resolution| {
                            resolution.terminal_outcome != DispatchOutcome::Failed
                                || !resolution.retry_consumed
                        })
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
        let retired_intent_count = decoder.count()?;
        for _ in 0..retired_intent_count {
            let intent_key = decoder.reconciliation_key()?;
            if !restored.retired_intents.insert(intent_key) {
                return Err(DenialCode::RecoveryCheckpointInvalid);
            }
        }
        decoder.finish()?;
        if restored.retired_intents.len() != restored.dispatch_nonces.len()
            || restored.retired_intents.len() != restored.retired_lease_ids.len()
            || restored.retired_intents.iter().any(|key| {
                !restored.grants.contains_key(&GrantKey {
                    grant_id: key.grant_id.clone(),
                    grant_version: key.grant_version,
                })
            })
            || restored
                .reconciliation_required
                .keys()
                .any(|key| !restored.retired_intents.contains(key))
            || restored
                .reconciliation_receipts
                .keys()
                .any(|key| !restored.retired_intents.contains(key))
            || restored.retry_aliases.iter().any(|(retry, parent)| {
                !restored.retired_intents.contains(retry)
                    || !restored.retired_intents.contains(parent)
            })
        {
            return Err(DenialCode::RecoveryCheckpointInvalid);
        }

        let mut state = self.lock_state()?;
        if !state.grants.is_empty()
            || !state.leases.is_empty()
            || !state.reconciliation_required.is_empty()
            || !state.held_effects.is_empty()
            || !state.reconciliation_receipts.is_empty()
            || !state.retry_aliases.is_empty()
            || !state.dispatch_nonces.is_empty()
            || !state.retired_lease_ids.is_empty()
            || !state.retired_intents.is_empty()
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
            control_envelope_id: Digest::of(format!("control-envelope:{lease_id}").as_bytes()),
            request_binding_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            resolution_digest: Digest::ZERO,
            compiled_request_digest: Digest::ZERO,
            effect_digest: Digest::ZERO,
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
        spec.compiled_request_digest = Digest::of(&bound.payload);
        spec.effect_digest = crate::policy::target_effect_digest(
            bound.action_kind,
            bound.egress_plane,
            bound.resolution_digest,
            Digest::of(&bound.payload),
        );
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
            control_envelope_id: Digest::of(b"control-envelope:request-fixture"),
            request_binding_digest: request.lease_binding_digest(),
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            compiled_request_digest: Digest::of(&request.payload),
            effect_digest: crate::policy::target_effect_digest(
                request.action_kind,
                request.egress_plane,
                request.resolution_digest,
                Digest::of(&request.payload),
            ),
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

    fn retry_candidate(
        parent: &LeaseSpec,
        coordinates: (&str, &[u8]),
        mutate: impl FnOnce(&mut DispatchRequest),
    ) -> (LeaseSpec, DispatchRequest) {
        let (lease_id, intent) = coordinates;
        let mut seed = spec(lease_id, intent);
        seed.decision_digest = parent.decision_digest;
        seed.grant_id.clone_from(&parent.grant_id);
        seed.grant_version = parent.grant_version;
        seed.scope_epoch = parent.scope_epoch;
        seed.authority_key_id.clone_from(&parent.authority_key_id);
        seed.scope_epoch_binding_digest = parent.scope_epoch_binding_digest;
        seed.gateway_boot_id.clone_from(&parent.gateway_boot_id);
        seed.retry_of_intent_digest = Some(parent.intent_digest);
        seal_spec(&mut seed);
        let mut candidate = request(&seed, vec![1]);
        mutate(&mut candidate);
        candidate.bind_canonical_semantics();
        let mut lease = spec_for_request(&candidate);
        lease.control_envelope_id =
            Digest::of(format!("retry-control-envelope:{lease_id}").as_bytes());
        (lease, candidate)
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
            control_envelope_id: approval.control_envelope_id,
            hold_binding_digest: approval.hold_binding_digest,
            resolution_digest: request.resolution_digest,
            action_kind: request.action_kind,
            egress_plane: request.egress_plane,
            effect_digest: lease.effect_digest,
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
    fn exact_hold_collision_is_rejected_before_active_accounting_changes() {
        let authority = authority(budget());
        let first = spec("lease:hold-collision-a", b"intent:hold-collision");
        let first_proof = authority
            .issue(first.clone())
            .expect("issue first lease")
            .proof;
        let first_request = request(&first, first_proof);
        let approval = authority
            .reserve(&first_request, NOW)
            .expect("reserve first lease");

        let second = spec("lease:hold-collision-b", b"intent:hold-collision");
        assert_eq!(
            authority.issue(second),
            Err(DenialCode::LeaseBindingMismatch),
            "one intent key cannot name two exact hold bindings"
        );

        let key = ReconciliationKey::from_spec(&first);
        let mut state = authority
            .state
            .lock()
            .expect("inject conflicting durable hold");
        state.reconciliation_required.insert(
            key.clone(),
            ReconciliationHold {
                kind: ReconciliationHoldKind::DispatchReceipt,
                binding_digest: Digest::of(b"conflicting exact hold"),
                retry_invariant_digest: Digest::of(b"conflicting retry invariant"),
            },
        );
        state.held_effects.insert(key, first.effect_digest);
        drop(state);

        let before = authority
            .usage("grant:1", 3)
            .expect("usage before collision");
        assert_eq!(
            authority.finalize(&approval, completion(DispatchOutcome::UnknownOutcome)),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        let after = authority
            .usage("grant:1", 3)
            .expect("usage after collision");
        assert_eq!(
            after, before,
            "failed finalization cannot consume accounting"
        );
        let state = authority
            .state
            .lock()
            .expect("inspect active lease after collision");
        assert!(matches!(
            state.leases.get(&first.lease_id).map(|entry| &entry.status),
            Some(LeaseStatus::Active { .. })
        ));
    }

    #[test]
    fn same_effect_reconciliation_hold_denies_issue_without_state_consumption() {
        let authority = authority(budget());
        let held = spec("lease:held-effect", b"intent:held-effect");
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let candidate = spec("lease:same-held-effect", b"intent:held-effect");
        assert_eq!(candidate.effect_digest, held.effect_digest);
        let usage_before = authority
            .usage(&candidate.grant_id, candidate.grant_version)
            .expect("usage before denied issue");

        assert_eq!(
            authority.issue(candidate.clone()),
            Err(DenialCode::LeaseReconciliationRequired)
        );

        assert_eq!(
            authority
                .usage(&candidate.grant_id, candidate.grant_version)
                .expect("usage after denied issue"),
            usage_before
        );
        let key = ReconciliationKey::from_spec(&candidate);
        let state = authority.state.lock().expect("inspect denied issue state");
        assert!(!state.leases.contains_key(&candidate.lease_id));
        assert!(!state.dispatch_nonces.contains(&candidate.dispatch_nonce));
        assert!(!state.retired_lease_ids.contains(&candidate.lease_id));
        assert!(state.reconciliation_required.contains_key(&key));
        assert_eq!(state.held_effects.get(&key), Some(&held.effect_digest));
    }

    #[test]
    fn preflight_denies_an_exact_held_intent_without_mutating_lease_state() {
        // Given: an exact intent key is held for reconciliation after an
        // ambiguous dispatch.
        let authority = authority(budget());
        let held = spec("lease:preflight-held", b"intent:preflight-held");
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let usage_before = authority
            .usage(&held.grant_id, held.grant_version)
            .expect("usage before preflight");
        let key = ReconciliationKey::from_spec(&held);
        let state_before = authority.state.lock().expect("inspect held state");
        let lease_count_before = state_before.leases.len();
        let nonce_count_before = state_before.dispatch_nonces.len();
        let retired_count_before = state_before.retired_lease_ids.len();
        let checkpoint_sequence_before = state_before.checkpoint_sequence;
        let hold_before = state_before
            .reconciliation_required
            .get(&key)
            .copied()
            .expect("exact reconciliation hold");
        let effect_before = *state_before
            .held_effects
            .get(&key)
            .expect("exact held effect");
        drop(state_before);

        // When: the main thread performs the read-only precompile check.
        let result =
            authority.preflight_issue(&held.grant_id, held.grant_version, held.intent_digest);

        // Then: reconciliation is required and no lease, proof, nonce, budget,
        // hold, or checkpoint state changes.
        assert_eq!(result, Err(DenialCode::LeaseReconciliationRequired));
        assert_eq!(
            authority
                .usage(&held.grant_id, held.grant_version)
                .expect("usage after preflight"),
            usage_before
        );
        let state_after = authority.state.lock().expect("inspect denied state");
        assert_eq!(state_after.leases.len(), lease_count_before);
        assert_eq!(state_after.dispatch_nonces.len(), nonce_count_before);
        assert_eq!(state_after.retired_lease_ids.len(), retired_count_before);
        assert_eq!(state_after.checkpoint_sequence, checkpoint_sequence_before);
        assert_eq!(
            state_after.reconciliation_required.get(&key),
            Some(&hold_before)
        );
        assert_eq!(state_after.held_effects.get(&key), Some(&effect_before));
    }

    #[test]
    fn preflight_conservatively_denies_a_held_intent_before_effect_compilation() {
        // Given: a held intent and a later request that would compile to a
        // different effect under the same exact intent key.
        let authority = authority(budget());
        let held = spec(
            "lease:preflight-effect-held",
            b"intent:preflight-effect-held",
        );
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let mut different_effect = spec(
            "lease:preflight-effect-different",
            b"intent:preflight-effect-held",
        );
        different_effect.effect_digest = Digest::of(b"different preflight effect");

        // When: the effect-free preflight and the later effect-aware issuance
        // inspect the same key.
        let preflight = authority.preflight_issue(
            &different_effect.grant_id,
            different_effect.grant_version,
            different_effect.intent_digest,
        );
        let issue = authority.issue(different_effect);

        // Then: preflight never guesses an effect mismatch, while issuance
        // retains the exact effect-aware precedence contract.
        assert_eq!(preflight, Err(DenialCode::LeaseReconciliationRequired));
        assert_eq!(issue, Err(DenialCode::LeaseBindingMismatch));
    }

    #[test]
    fn preflight_allows_a_distinct_nonheld_intent_to_reach_normal_issuance() {
        // Given: one intent is held and another well-formed intent is distinct.
        let authority = authority(budget());
        let held = spec(
            "lease:preflight-distinct-held",
            b"intent:preflight-distinct-held",
        );
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let candidate = spec(
            "lease:preflight-distinct-candidate",
            b"intent:preflight-distinct-candidate",
        );

        // When: the distinct intent is preflighted and issued normally.
        let preflight = authority.preflight_issue(
            &candidate.grant_id,
            candidate.grant_version,
            candidate.intent_digest,
        );
        let issue = authority.issue(candidate);

        // Then: the exact-key gate does not broaden the hold.
        assert_eq!(preflight, Ok(()));
        assert!(issue.is_ok());
    }

    #[test]
    fn preflight_fails_closed_for_one_sided_hold_state() {
        // Given: each impossible one-sided durable hold representation.
        for hold_present in [true, false] {
            let authority = authority(budget());
            let candidate = spec("lease:preflight-one-sided", b"intent:preflight-one-sided");
            let key = ReconciliationKey::from_spec(&candidate);
            let mut state = authority.state.lock().expect("inject one-sided hold");
            if hold_present {
                state.reconciliation_required.insert(
                    key,
                    ReconciliationHold {
                        kind: ReconciliationHoldKind::ControlPlane,
                        binding_digest: Digest::of(b"preflight one-sided binding"),
                        retry_invariant_digest: Digest::of(b"preflight one-sided retry"),
                    },
                );
            } else {
                state.held_effects.insert(key, candidate.effect_digest);
            }
            drop(state);

            // When: the key is preflighted.
            let result = authority.preflight_issue(
                &candidate.grant_id,
                candidate.grant_version,
                candidate.intent_digest,
            );

            // Then: corrupt paired state is never treated as unheld.
            assert_eq!(result, Err(DenialCode::LeaseAccountingUnavailable));
        }
    }

    #[test]
    fn different_effect_reconciliation_hold_remains_a_binding_mismatch() {
        let authority = authority(budget());
        let held = spec("lease:held-other-effect", b"intent:held-other-effect");
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let mut candidate = spec("lease:different-held-effect", b"intent:held-other-effect");
        candidate.effect_digest = Digest::of(b"different candidate effect");
        let usage_before = authority
            .usage(&candidate.grant_id, candidate.grant_version)
            .expect("usage before denied issue");

        assert_eq!(
            authority.issue(candidate.clone()),
            Err(DenialCode::LeaseBindingMismatch)
        );

        assert_eq!(
            authority
                .usage(&candidate.grant_id, candidate.grant_version)
                .expect("usage after denied issue"),
            usage_before
        );
        let key = ReconciliationKey::from_spec(&candidate);
        let state = authority.state.lock().expect("inspect denied issue state");
        assert!(!state.leases.contains_key(&candidate.lease_id));
        assert!(!state.dispatch_nonces.contains(&candidate.dispatch_nonce));
        assert!(!state.retired_lease_ids.contains(&candidate.lease_id));
        assert!(state.reconciliation_required.contains_key(&key));
        assert_eq!(state.held_effects.get(&key), Some(&held.effect_digest));
    }

    #[test]
    fn one_sided_reconciliation_hold_state_fails_closed() {
        for hold_present in [true, false] {
            let authority = authority(budget());
            let candidate = spec("lease:one-sided-hold", b"intent:one-sided-hold");
            let key = ReconciliationKey::from_spec(&candidate);
            let mut state = authority.state.lock().expect("inject one-sided hold");
            if hold_present {
                state.reconciliation_required.insert(
                    key,
                    ReconciliationHold {
                        kind: ReconciliationHoldKind::DispatchReceipt,
                        binding_digest: Digest::of(b"one-sided hold binding"),
                        retry_invariant_digest: Digest::of(b"one-sided retry invariant"),
                    },
                );
            } else {
                state.held_effects.insert(key, candidate.effect_digest);
            }
            drop(state);

            assert_eq!(
                authority.issue(candidate.clone()),
                Err(DenialCode::LeaseAccountingUnavailable)
            );
            let state = authority.state.lock().expect("inspect denied issue state");
            assert!(!state.leases.contains_key(&candidate.lease_id));
            assert!(!state.dispatch_nonces.contains(&candidate.dispatch_nonce));
            assert!(!state.retired_lease_ids.contains(&candidate.lease_id));
        }
    }

    #[test]
    fn completed_resolution_is_monotonic_and_checkpoint_remains_restorable() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:monotonic-resolution", b"intent:monotonic-resolution");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let completed = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"completed terminal evidence"),
                *b"completed-proof1",
                NOW + 2,
            )
            .expect("completed reconciliation");
        authority
            .reconcile(&receipt, &completed)
            .expect("store completed resolution");
        let failed = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Failed,
                Digest::of(b"later contradictory evidence"),
                *b"failed-proof-001",
                NOW + 3,
            )
            .expect("well-formed contradictory reconciliation");
        assert_eq!(
            authority.reconcile(&receipt, &failed),
            Err(DenialCode::LeaseReplay),
            "a terminal resolution cannot be overwritten"
        );

        let checkpoint = authority
            .checkpoint()
            .expect("checkpoint monotonic resolution");
        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:monotonic-restored".to_owned(),
            Digest::of(b"monotonic restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("fresh restore authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("every emitted checkpoint must restore");
        let state = restored.state.lock().expect("inspect restored resolution");
        let resolution = state
            .reconciliation_receipts
            .get(&ReconciliationKey::from_spec(&lease))
            .expect("restored resolution");
        assert_eq!(resolution.terminal_outcome, DispatchOutcome::Completed);
        assert!(!resolution.retry_consumed);
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
                ControlPlaneReconciliationHold {
                    grant_id: lease.grant_id.clone(),
                    grant_version: lease.grant_version,
                    intent_digest: lease.intent_digest,
                    effect_digest: lease.effect_digest,
                    hold_binding_digest: receipt.hold_binding_digest,
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Completed,
                    evidence_digest: Digest::of(b"unbound terminal evidence"),
                    nonce: *b"bypass-proof-001",
                    resolved_at_millis: NOW + 2,
                },
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
        let mut completed_retry = spec(
            "lease:grant-1-completed-retry",
            b"intent:grant-1-completed-retry",
        );
        completed_retry.retry_of_intent_digest = Some(first.intent_digest);
        seal_spec(&mut completed_retry);
        assert_eq!(
            authority.issue(completed_retry),
            Err(DenialCode::RetryAliasInvalid),
            "a terminally completed dispatch cannot be retried"
        );

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
                DispatchOutcome::Failed,
                Digest::of(b"second grant terminal evidence"),
                *b"reconcile-grant2",
                NOW + 2,
            )
            .expect("failed second-grant reconciliation");
        authority
            .reconcile(&second_receipt, &second_reconciliation)
            .expect("second grant retains an independent hold");

        let (authorized_retry, mut authorized_request) = retry_candidate(
            &second,
            (
                "lease:grant-2-authorized-retry",
                b"intent:grant-2-authorized-retry",
            ),
            |_| {},
        );
        let proof = authority
            .issue(authorized_retry.clone())
            .expect("exact failed reconciliation authorizes a fresh retry")
            .proof;
        authorized_request.lease_proof = proof;
        authority
            .reserve(&authorized_request, NOW + 3)
            .expect("fresh grant-2 retry reserves after exact failed reconciliation");
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
        assert_eq!(
            authority.issue(retry),
            Err(DenialCode::LeaseReconciliationRequired),
            "an exact-effect durable hold takes precedence over the general binding collision"
        );
        let relabelled = spec("lease:relabelled", b"intent:relabelled");
        assert_eq!(relabelled.effect_digest, first.effect_digest);
        let relabelled_proof = authority
            .issue(relabelled.clone())
            .expect("preissued relabelled lease")
            .proof;
        let relabelled_request = request(&relabelled, relabelled_proof);
        assert_eq!(
            authority.reserve(&relabelled_request, NOW + 1),
            Err(DenialCode::LeaseReconciliationRequired),
            "fresh intent and lease identifiers cannot bypass an exact-effect hold"
        );
        let reconciliation = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Failed,
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
                .reconciliation_receipt(&first.grant_id, first.grant_version, first.intent_digest,)
                .expect("recorded reconciliation"),
            Some(reconciliation.reconciliation_id)
        );
        let (explicit_retry, mut retry_request) =
            retry_candidate(&first, ("lease:retry-alias", b"intent:retry-alias"), |_| {});
        let proof = authority
            .issue(explicit_retry.clone())
            .expect("append-only retry alias")
            .proof;
        retry_request.lease_proof = proof;
        assert!(authority.reserve(&retry_request, NOW + 2).is_ok());
    }

    #[test]
    fn failed_resolution_authorizes_only_one_exact_retry_and_recovery_preserves_consumption() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let parent = spec("lease:retry-parent", b"intent:retry-parent");
        let receipt = authenticated_unknown_receipt(&authority, &parent);
        let failed = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Failed,
                Digest::of(b"failed parent terminal evidence"),
                *b"retry-proof-0001",
                NOW + 2,
            )
            .expect("failed parent reconciliation");
        authority
            .reconcile(&receipt, &failed)
            .expect("store failed parent resolution");

        let (cross_effect, mut cross_effect_request) = retry_candidate(
            &parent,
            ("lease:retry-cross-effect", b"intent:retry-cross-effect"),
            |request| request.payload = b"PONG".to_vec(),
        );
        cross_effect_request.lease_proof = authority
            .issue(cross_effect)
            .expect("admit pending cross-effect candidate")
            .proof;
        assert_eq!(
            authority.reserve(&cross_effect_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid)
        );

        let (cross_tenant, mut cross_tenant_request) = retry_candidate(
            &parent,
            ("lease:retry-cross-tenant", b"intent:retry-cross-tenant"),
            |request| request.tenant_id = Some("tenant:other".to_owned()),
        );
        cross_tenant_request.lease_proof = authority
            .issue(cross_tenant)
            .expect("admit pending cross-tenant candidate")
            .proof;
        assert_eq!(
            authority.reserve(&cross_tenant_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid)
        );

        let (cross_target, mut cross_target_request) = retry_candidate(
            &parent,
            ("lease:retry-cross-target", b"intent:retry-cross-target"),
            |request| {
                request.target_id = "target:other-loopback".to_owned();
                request.hostname = "other.localhost".to_owned();
                request.target = "127.0.0.1:8081".parse().expect("alternate address");
            },
        );
        cross_target_request.lease_proof = authority
            .issue(cross_target)
            .expect("admit pending cross-target candidate")
            .proof;
        assert_eq!(
            authority.reserve(&cross_target_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid)
        );

        let (first, mut first_request) = retry_candidate(
            &parent,
            ("lease:retry-exact-a", b"intent:retry-exact-a"),
            |request| {
                request.action_id = "action:retry-exact-a".to_owned();
                request.correlation_id = "correlation:retry-exact-a".to_owned();
                request.request_issued_at_millis = NOW;
                request.request_expires_at_millis = NOW + 4_000;
            },
        );
        first_request.lease_proof = authority
            .issue(first)
            .expect("admit first exact pending retry")
            .proof;
        let (second, mut second_request) = retry_candidate(
            &parent,
            ("lease:retry-exact-b", b"intent:retry-exact-b"),
            |request| {
                request.action_id = "action:retry-exact-b".to_owned();
                request.correlation_id = "correlation:retry-exact-b".to_owned();
                request.request_issued_at_millis = NOW + 1;
                request.request_expires_at_millis = NOW + 4_001;
            },
        );
        second_request.lease_proof = authority
            .issue(second)
            .expect("admit second exact pending retry")
            .proof;

        let first_approval = authority
            .reserve(&first_request, NOW + 3)
            .expect("first exact retry atomically consumes authorization");
        authority
            .abandon(&first_approval)
            .expect("release exact retry reservation");
        assert_eq!(
            authority.reserve(&second_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid),
            "a failed parent authorizes at most one exact retry"
        );

        let checkpoint = authority
            .checkpoint()
            .expect("checkpoint consumed retry parent");
        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:retry-restored".to_owned(),
            Digest::of(b"retry restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("fresh retry restore authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore consumed retry authorization");
        let (mut after_restart, _) = retry_candidate(
            &parent,
            ("lease:retry-after-restart", b"intent:retry-after-restart"),
            |_| {},
        );
        after_restart.gateway_boot_id = "gateway:boot:retry-restored".to_owned();
        seal_spec(&mut after_restart);
        assert_eq!(
            restored.issue(after_restart),
            Err(DenialCode::RetryAliasInvalid),
            "retry consumption survives recovery"
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
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: active.effect_digest,
                    hold_binding_digest: active.hold_binding_digest(
                        "lease-key:test",
                        Digest::of(b"gateway challenge:test"),
                    ),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"revocation terminal evidence"),
                    nonce: *b"revoke-proof-001",
                    resolved_at_millis: NOW + 2,
                },
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
        assert_eq!(
            restored.issue(retry),
            Err(DenialCode::LeaseReconciliationRequired),
            "a recovered exact-effect hold preserves reconciliation precedence"
        );
        let reconciler = ReconciliationAuthority::new(
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("reconciliation signer");
        let wrong_effect = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: Digest::of(b"wrong crash effect"),
                    hold_binding_digest: active
                        .hold_binding_digest("lease-key:test", Digest::of(b"source challenge")),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"wrong-effect terminal evidence"),
                    nonce: *b"wrong-effect-001",
                    resolved_at_millis: NOW + 2,
                },
            )
            .expect("authenticated wrong-effect proof");
        assert_eq!(
            restored.reconcile_control_plane_hold(&wrong_effect),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        let wrong_binding = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: active.effect_digest,
                    hold_binding_digest: Digest::of(b"wrong exact crash hold binding"),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"wrong-binding terminal evidence"),
                    nonce: *b"wrong-binding001",
                    resolved_at_millis: NOW + 2,
                },
            )
            .expect("authenticated wrong-binding proof");
        assert_eq!(
            restored.reconcile_control_plane_hold(&wrong_binding),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        let reconciliation = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: active.effect_digest,
                    hold_binding_digest: active
                        .hold_binding_digest("lease-key:test", Digest::of(b"source challenge")),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"crash terminal evidence"),
                    nonce: *b"crash-proof-0001",
                    resolved_at_millis: NOW + 2,
                },
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
    fn completed_intent_cannot_be_reissued_with_fresh_coordinates_after_restore() {
        // Given: a completed intent under a grant that still has action budget.
        let mut limits = budget();
        limits.total_actions = 2;
        let source = authority_for_boot(
            limits,
            "gateway:boot:retired-source",
            b"retired source challenge",
        );
        let mut completed = spec("lease:retired-original", b"intent:retired-terminal");
        completed.gateway_boot_id = "gateway:boot:retired-source".to_owned();
        seal_spec(&mut completed);
        let proof = source
            .issue(completed.clone())
            .expect("issue original intent")
            .proof;
        let approval = source
            .reserve(&request(&completed, proof), NOW)
            .expect("reserve original intent");
        source
            .finalize(&approval, completion(DispatchOutcome::Completed))
            .expect("acknowledge completed intent");
        assert_eq!(
            source
                .usage(&completed.grant_id, completed.grant_version)
                .expect("completed usage")
                .dispatched_actions,
            1
        );
        let checkpoint = source.checkpoint().expect("checkpoint completed intent");
        let restored = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:retired-restored".to_owned(),
            Digest::of(b"retired restored challenge"),
        )
        .expect("fresh restore authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore completed intent");

        // When: the new boot issues the same semantic intent with fresh coordinates.
        let mut replay = spec("lease:retired-replay", b"intent:retired-terminal");
        replay.gateway_boot_id = "gateway:boot:retired-restored".to_owned();
        seal_spec(&mut replay);
        assert_ne!(replay.lease_id, completed.lease_id);
        assert_ne!(replay.dispatch_nonce, completed.dispatch_nonce);

        // Then: semantic retirement, rather than exhausted budget, rejects it.
        assert_eq!(
            restored.issue(replay),
            Err(DenialCode::LeaseBindingMismatch)
        );
        let mut distinct = spec("lease:retired-distinct", b"intent:retired-distinct");
        distinct.gateway_boot_id = "gateway:boot:retired-restored".to_owned();
        seal_spec(&mut distinct);
        let distinct_proof = restored
            .issue(distinct.clone())
            .expect("remaining budget admits a distinct intent")
            .proof;
        assert!(
            restored
                .reserve(&request(&distinct, distinct_proof), NOW + 1)
                .is_ok()
        );
    }

    #[test]
    fn recovery_rejects_v6_format_rollback() {
        let source = authority_for_boot(
            budget(),
            "gateway:boot:rollback-source",
            b"rollback source challenge",
        );
        let checkpoint = source.checkpoint().expect("current checkpoint");
        let mut rollback = checkpoint.as_bytes().to_vec();
        rollback[4] = 6;

        assert_eq!(
            LeaseRecoveryCheckpoint::from_bytes(rollback),
            Err(DenialCode::RecoveryCheckpointInvalid)
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
