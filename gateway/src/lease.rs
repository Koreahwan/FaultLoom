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

#[path = "lease/recovery_restore.rs"]
mod recovery_restore;

#[path = "lease/reconciliation.rs"]
mod reconciliation;

#[path = "lease/reservation.rs"]
mod reservation;

#[path = "lease/finalization.rs"]
mod finalization;

#[path = "lease/verifier.rs"]
mod verifier;

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

#[cfg(test)]
#[path = "lease/tests/mod.rs"]
mod tests;
