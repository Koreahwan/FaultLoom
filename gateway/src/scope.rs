use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::Digest;
use crate::ipc::{ActionClass, DenialCode, DispatchRequest, FlowKind, valid_identifier};
use crate::policy::{LeaseApproval, ScopeApproval, ScopeVerifier};

mod clock;
mod epoch;
mod error;
mod network;
mod policy;
mod supervisor;

pub use clock::{ScopeClock, SystemScopeClock};
use epoch::verified_epoch_binding;
pub use epoch::{
    EpochAdmissionError, EpochVerifier, SignedEpochEnvelope, UnavailableEpochVerifier,
    VerifiedScopeEpoch,
};
pub(crate) use epoch::{VerifiedScopeEpochParts, epoch_verifier_private};
pub use error::ScopePolicyError;
pub use network::IpNetwork;
use network::is_special_address;
pub use policy::{ExplicitDenyRule, ScopePolicy, TargetRule, TimeWindow};
pub use supervisor::{
    CancellationCause, ScopeCancellation, ScopeCancellationReport, ScopeCancellationSink,
};

pub use crate::t13_epoch::T13ReceiptEpochVerifier;
pub(crate) use crate::t13_epoch::{
    ExpectedScopeEpochGrant, GatewayBootBinding, ReceiptAuthenticationChannel,
    T13EpochVerifierConfig,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceKind {
    QueuedAction,
    OpenConnection,
    WebSocket,
    CallbackLease,
    Polling,
    LongScannerJob,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedResource {
    pub resource_id: String,
    pub owner_action_id: String,
    pub kind: ResourceKind,
    pub scope_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationRecord {
    pub resource: ScopedResource,
    pub cancelled_by_epoch: u64,
    pub cause: CancellationCause,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochTransition {
    pub previous_epoch: Option<u64>,
    pub current_epoch: u64,
    pub revoked: bool,
    pub cancellations: Vec<CancellationRecord>,
    pub interrupted_active: u64,
}

impl EpochTransition {
    pub fn interrupted_resources(&self) -> u64 {
        u64::try_from(self.cancellations.len())
            .unwrap_or(u64::MAX)
            .max(self.interrupted_active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedScopeDispatch {
    pub(crate) scope_proof: Vec<u8>,
    pub(crate) authority_key_id: String,
    pub(crate) scope_epoch_binding_digest: Digest,
    pub(crate) gateway_boot_id: String,
}

#[derive(Clone, Debug)]
struct AdmittedEpoch {
    epoch: u64,
    issued_at_millis: u64,
    expires_at_millis: u64,
    revoked: bool,
    binding_digest: Digest,
    authority_key_id: String,
    gateway_boot_id: String,
    cancellation_applied: bool,
}

#[derive(Default)]
struct ScopeState {
    current_epoch: Option<AdmittedEpoch>,
    consumed_epoch_nonces: BTreeSet<[u8; 16]>,
    approved_actions: BTreeMap<String, u64>,
    resources: BTreeMap<String, ScopedResource>,
    cancellation_log: Vec<CancellationRecord>,
}

pub struct DeterministicScopeKernel<V, C> {
    policy: ScopePolicy,
    verifier: V,
    clock: C,
    cancellation_sink: Option<Arc<dyn ScopeCancellationSink>>,
    state: Mutex<ScopeState>,
}

impl<V, C> DeterministicScopeKernel<V, C>
where
    V: EpochVerifier,
    C: ScopeClock,
{
    pub fn new(policy: ScopePolicy, verifier: V, clock: C) -> Result<Self, ScopePolicyError> {
        Self::build(policy, verifier, clock, None)
    }

    fn build(
        policy: ScopePolicy,
        verifier: V,
        clock: C,
        cancellation_sink: Option<Arc<dyn ScopeCancellationSink>>,
    ) -> Result<Self, ScopePolicyError> {
        policy.validate()?;
        Ok(Self {
            policy,
            verifier,
            clock,
            cancellation_sink,
            state: Mutex::new(ScopeState::default()),
        })
    }

    pub fn admit_epoch(
        &self,
        envelope: &SignedEpochEnvelope,
    ) -> Result<EpochTransition, EpochAdmissionError> {
        // Serialize verification with the state transition so a short-lived
        // receipt cannot expire while waiting for the epoch lock.
        let mut state = self
            .state
            .lock()
            .map_err(|_| EpochAdmissionError::StateUnavailable)?;
        let now = self.clock.now_millis();
        let verified = self.verifier.verify(envelope, now)?;
        self.validate_verified_epoch(envelope, &verified, now)?;
        let previous_epoch = state.current_epoch.as_ref().map(|epoch| epoch.epoch);
        let previous_cancellation_applied = state
            .current_epoch
            .as_ref()
            .is_some_and(|epoch| epoch.cancellation_applied);
        if let Some(current) = &state.current_epoch {
            if verified.epoch < current.epoch {
                return Err(EpochAdmissionError::Rollback);
            }
            if verified.epoch == current.epoch {
                return Err(EpochAdmissionError::Replay);
            }
        }
        if state
            .consumed_epoch_nonces
            .contains(&verified.verification_nonce)
        {
            return Err(EpochAdmissionError::Replay);
        }
        let cause = if verified.revoked {
            CancellationCause::ScopeRevoked
        } else {
            CancellationCause::EpochAdvanced
        };
        let scope_cancellation = if verified.revoked {
            Some(ScopeCancellation {
                grant_id: self.policy.grant_id.clone(),
                grant_version: self.policy.grant_version,
                invalidated_through_epoch: verified.epoch,
                revoked_at_epoch: Some(verified.epoch),
                cause,
            })
        } else if previous_cancellation_applied {
            None
        } else {
            previous_epoch.map(|epoch| ScopeCancellation {
                grant_id: self.policy.grant_id.clone(),
                grant_version: self.policy.grant_version,
                invalidated_through_epoch: epoch,
                revoked_at_epoch: None,
                cause,
            })
        };
        let cancellation_report = if let Some(cancellation) = scope_cancellation.as_ref() {
            self.notify_cancellation(cancellation)
                .map_err(|_| EpochAdmissionError::StateUnavailable)?
        } else {
            ScopeCancellationReport::default()
        };
        let cancellations = cancel_all(&mut state, verified.epoch, cause);
        let binding_digest = verified_epoch_binding(&verified);
        state.current_epoch = Some(AdmittedEpoch {
            epoch: verified.epoch,
            issued_at_millis: verified.issued_at_millis,
            expires_at_millis: verified.expires_at_millis,
            revoked: verified.revoked,
            binding_digest,
            authority_key_id: verified.key_id,
            gateway_boot_id: verified.gateway_boot_id,
            cancellation_applied: verified.revoked,
        });
        state
            .consumed_epoch_nonces
            .insert(verified.verification_nonce);
        Ok(EpochTransition {
            previous_epoch,
            current_epoch: verified.epoch,
            revoked: verified.revoked,
            cancellations,
            interrupted_active: cancellation_report.interrupted_active,
        })
    }

    fn validate_verified_epoch(
        &self,
        envelope: &SignedEpochEnvelope,
        verified: &VerifiedScopeEpoch,
        now: u64,
    ) -> Result<(), EpochAdmissionError> {
        if verified.envelope_digest != envelope.digest()
            || verified.payload_digest == Digest::ZERO
            || verified.verifier_receipt_digest == Digest::ZERO
            || !valid_identifier(&verified.gateway_boot_id)
            || !valid_identifier(&verified.key_id)
            || verified.signature_sequence != verified.epoch
            || verified.epoch == 0
            || verified.revoked != verified.revocation_reason.is_some()
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        if verified.grant_id != self.policy.grant_id {
            return Err(EpochAdmissionError::GrantMismatch);
        }
        if verified.expires_at_millis <= verified.issued_at_millis {
            return Err(EpochAdmissionError::InvalidValidity);
        }
        if now < verified.issued_at_millis {
            return Err(EpochAdmissionError::NotYetValid);
        }
        if now >= verified.expires_at_millis {
            return Err(EpochAdmissionError::Expired);
        }
        Ok(())
    }

    pub fn issue_scope_proof(&self, request: &DispatchRequest) -> Result<Vec<u8>, DenialCode> {
        self.prepare_dispatch(request)
            .map(|prepared| prepared.scope_proof)
    }

    pub(crate) fn prepare_dispatch(
        &self,
        request: &DispatchRequest,
    ) -> Result<PreparedScopeDispatch, DenialCode> {
        let now = self.clock.now_millis();
        let mut state = self.state.lock().map_err(|_| DenialCode::ScopeDenied)?;
        self.reconcile_expiry(&mut state, now)?;
        let epoch = evaluate(&self.policy, &state, request, now)?;
        Ok(PreparedScopeDispatch {
            scope_proof: scope_proof(epoch.binding_digest, request)
                .as_bytes()
                .to_vec(),
            authority_key_id: epoch.authority_key_id.clone(),
            scope_epoch_binding_digest: epoch.binding_digest,
            gateway_boot_id: epoch.gateway_boot_id.clone(),
        })
    }

    pub fn reconcile_expiry_now(&self) -> Result<u64, DenialCode> {
        let now = self.clock.now_millis();
        let mut state = self.state.lock().map_err(|_| DenialCode::ScopeDenied)?;
        let cancellation_count = state.cancellation_log.len();
        let cancellation_report = self.reconcile_expiry(&mut state, now)?;
        let interrupted_resources = u64::try_from(
            state
                .cancellation_log
                .len()
                .saturating_sub(cancellation_count),
        )
        .map_err(|_| DenialCode::ScopeDenied)?;
        Ok(interrupted_resources.max(cancellation_report.interrupted_active))
    }

    pub fn register_resource(&self, resource: ScopedResource) -> Result<(), DenialCode> {
        if self.cancellation_sink.is_none() {
            return Err(DenialCode::ScopeDenied);
        }
        if !valid_identifier(&resource.resource_id) || !valid_identifier(&resource.owner_action_id)
        {
            return Err(DenialCode::InvalidRequest);
        }
        let now = self.clock.now_millis();
        let mut state = self.state.lock().map_err(|_| DenialCode::ScopeDenied)?;
        self.reconcile_expiry(&mut state, now)?;
        let epoch = state
            .current_epoch
            .as_ref()
            .ok_or(DenialCode::ScopeEpochUnavailable)?;
        if epoch.revoked {
            return Err(DenialCode::ScopeEpochRevoked);
        }
        if now >= epoch.expires_at_millis {
            return Err(DenialCode::ScopeEpochExpired);
        }
        if resource.scope_epoch != epoch.epoch {
            return Err(DenialCode::ScopeEpochStale);
        }
        if state.approved_actions.get(&resource.owner_action_id) != Some(&epoch.epoch) {
            return Err(DenialCode::InvalidChildFlow);
        }
        if state.resources.contains_key(&resource.resource_id) {
            return Err(DenialCode::ScopeProofInvalid);
        }
        state
            .resources
            .insert(resource.resource_id.clone(), resource);
        Ok(())
    }

    pub fn finish_resource(&self, resource_id: &str) -> Result<bool, DenialCode> {
        self.state
            .lock()
            .map(|mut state| state.resources.remove(resource_id).is_some())
            .map_err(|_| DenialCode::ScopeDenied)
    }

    pub fn take_cancellations(&self) -> Result<Vec<CancellationRecord>, DenialCode> {
        self.state
            .lock()
            .map(|mut state| std::mem::take(&mut state.cancellation_log))
            .map_err(|_| DenialCode::ScopeDenied)
    }

    pub fn active_resource_count(&self) -> Result<usize, DenialCode> {
        self.state
            .lock()
            .map(|state| state.resources.len())
            .map_err(|_| DenialCode::ScopeDenied)
    }

    fn reconcile_expiry(
        &self,
        state: &mut ScopeState,
        now: u64,
    ) -> Result<ScopeCancellationReport, DenialCode> {
        let Some(cancellation) = state.current_epoch.as_ref().and_then(|epoch| {
            (now >= epoch.expires_at_millis && !epoch.cancellation_applied).then(|| {
                ScopeCancellation {
                    grant_id: self.policy.grant_id.clone(),
                    grant_version: self.policy.grant_version,
                    invalidated_through_epoch: epoch.epoch,
                    revoked_at_epoch: None,
                    cause: CancellationCause::EpochExpired,
                }
            })
        }) else {
            return Ok(ScopeCancellationReport::default());
        };
        let cancellation_report = self.notify_cancellation(&cancellation)?;
        cancel_all(
            state,
            cancellation.invalidated_through_epoch,
            cancellation.cause,
        );
        if let Some(epoch) = state.current_epoch.as_mut() {
            epoch.cancellation_applied = true;
        }
        Ok(cancellation_report)
    }
}

impl<V, C> ScopeVerifier for DeterministicScopeKernel<V, C>
where
    V: EpochVerifier,
    C: ScopeClock,
{
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        let now = self.clock.now_millis();
        let mut state = self.state.lock().map_err(|_| DenialCode::ScopeDenied)?;
        self.reconcile_expiry(&mut state, now)?;
        let epoch = evaluate(&self.policy, &state, request, now)?;
        let authority_key_id = epoch.authority_key_id.clone();
        let scope_epoch_binding_digest = epoch.binding_digest;
        let gateway_boot_id = epoch.gateway_boot_id.clone();
        let valid_until_millis = self
            .policy
            .execution_windows
            .iter()
            .filter(|window| window.starts_at_millis <= now && now < window.ends_at_millis)
            .map(|window| window.ends_at_millis)
            .max()
            .unwrap_or(now)
            .min(epoch.expires_at_millis);
        let expected_proof = scope_proof(scope_epoch_binding_digest, request);
        if request.scope_proof.as_slice() != expected_proof.as_bytes() {
            return Err(DenialCode::ScopeProofInvalid);
        }
        if state.approved_actions.contains_key(&request.action_id) {
            return Err(DenialCode::ScopeProofInvalid);
        }
        state
            .approved_actions
            .insert(request.action_id.clone(), request.scope_epoch);
        Ok(ScopeApproval {
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            lease_id: request.lease_id.clone(),
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            scope_epoch: request.scope_epoch,
            authority_key_id,
            scope_epoch_binding_digest,
            gateway_boot_id,
            scope_binding_digest: request.scope_binding_digest(),
            target: request.target,
            action_kind: request.action_kind,
            action_class: request.action_class,
            required_features: request.required_features.clone(),
            valid_until_millis,
        })
    }

    fn register_dispatch(
        &self,
        request: &DispatchRequest,
        approval: &LeaseApproval,
    ) -> Result<(), DenialCode> {
        if self.cancellation_sink.is_none()
            || approval.lease_id != request.lease_id
            || approval.grant_id != request.grant_id
            || approval.grant_version != request.grant_version
            || approval.scope_epoch != request.scope_epoch
        {
            return Err(DenialCode::ScopeDenied);
        }
        self.register_resource(ScopedResource {
            resource_id: approval.lease_id.clone(),
            owner_action_id: request.action_id.clone(),
            kind: ResourceKind::OpenConnection,
            scope_epoch: approval.scope_epoch,
        })
    }

    fn finish_dispatch(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        match self.finish_resource(&approval.lease_id) {
            Ok(true) => Ok(()),
            Ok(false) => Err(DenialCode::ScopeDenied),
            Err(reason) => Err(reason),
        }
    }
}

fn evaluate<'a>(
    policy: &ScopePolicy,
    state: &'a ScopeState,
    request: &DispatchRequest,
    now: u64,
) -> Result<&'a AdmittedEpoch, DenialCode> {
    let epoch = state
        .current_epoch
        .as_ref()
        .ok_or(DenialCode::ScopeEpochUnavailable)?;
    if epoch.revoked {
        return Err(DenialCode::ScopeEpochRevoked);
    }
    if now < epoch.issued_at_millis || now >= epoch.expires_at_millis {
        return Err(DenialCode::ScopeEpochExpired);
    }
    if request.scope_epoch != epoch.epoch {
        return Err(DenialCode::ScopeEpochStale);
    }
    if request.grant_id != policy.grant_id || request.grant_version != policy.grant_version {
        return Err(DenialCode::ScopeDenied);
    }
    if explicit_deny_matches(&policy.denied, request) {
        return Err(DenialCode::ExplicitScopeDeny);
    }
    let target = policy
        .targets
        .iter()
        .find(|candidate| candidate.target_id == request.target_id)
        .ok_or(DenialCode::ScopeTargetDenied)?;
    if !target_matches(target, request) {
        return Err(DenialCode::ScopeTargetDenied);
    }
    if !policy.pack_ids.contains(&request.pack_id)
        || !policy.allowed_classes.contains(&request.action_class)
        || !policy.allowed_families.contains(&request.action_family)
        || !policy.allowed_methods.contains(&request.method)
        || !matches_any_path(&policy.allowed_path_patterns, &request.path)
        || (request.action_class == ActionClass::StateChange
            && !policy
                .state_change_families
                .contains(&request.action_family))
        || (target.supporting_read_only && request.action_class != ActionClass::Observe)
    {
        return Err(DenialCode::ScopeActionDenied);
    }
    if !policy.identities.contains(&request.identity_id) {
        return Err(DenialCode::ScopeIdentityDenied);
    }
    if match &request.tenant_id {
        Some(tenant) => !policy.tenants.contains(tenant),
        None => !policy.tenants.is_empty(),
    } {
        return Err(DenialCode::ScopeTenantDenied);
    }
    if !policy
        .execution_windows
        .iter()
        .any(|window| window.starts_at_millis <= now && now < window.ends_at_millis)
    {
        return Err(DenialCode::ScopeTimeDenied);
    }
    match request.flow_kind {
        FlowKind::TopLevel if request.parent_action_id.is_none() => {}
        FlowKind::TopLevel => return Err(DenialCode::InvalidChildFlow),
        _ => {
            let parent = request
                .parent_action_id
                .as_ref()
                .ok_or(DenialCode::InvalidChildFlow)?;
            if state.approved_actions.get(parent) != Some(&epoch.epoch) {
                return Err(DenialCode::InvalidChildFlow);
            }
        }
    }
    Ok(epoch)
}

fn explicit_deny_matches(denies: &[ExplicitDenyRule], request: &DispatchRequest) -> bool {
    denies.iter().any(|deny| {
        deny.target_id
            .as_ref()
            .is_none_or(|value| value == &request.target_id)
            && deny
                .host_pattern
                .as_ref()
                .is_none_or(|pattern| matches_host(pattern, &request.hostname))
            && deny
                .path_pattern
                .as_ref()
                .is_none_or(|pattern| matches_path(pattern, &request.path))
            && (deny.methods.is_empty() || deny.methods.contains(&request.method))
            && (deny.action_families.is_empty()
                || deny.action_families.contains(&request.action_family))
    })
}

fn target_matches(target: &TargetRule, request: &DispatchRequest) -> bool {
    let host_matches = if target.host_patterns.is_empty() {
        request
            .hostname
            .parse::<IpAddr>()
            .is_ok_and(|address| address == request.target.ip())
    } else {
        target
            .host_patterns
            .iter()
            .any(|pattern| matches_host(pattern, &request.hostname))
    };
    let network_matches = if target.networks.is_empty() {
        !is_special_address(request.target.ip())
    } else {
        target
            .networks
            .iter()
            .any(|network| network.contains(request.target.ip()))
    };
    host_matches
        && network_matches
        && target.ports.contains(&request.target.port())
        && target.protocols.contains(&request.protocol)
        && target.methods.contains(&request.method)
        && matches_any_path(&target.path_patterns, &request.path)
}

fn matches_host(pattern: &str, hostname: &str) -> bool {
    pattern.strip_prefix("*.").map_or_else(
        || pattern == hostname,
        |suffix| {
            hostname != suffix
                && hostname
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        },
    )
}

fn matches_any_path(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pattern| matches_path(pattern, path))
}

fn matches_path(pattern: &str, path: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or_else(|| pattern == path, |prefix| path.starts_with(prefix))
}

fn scope_proof(epoch_binding: Digest, request: &DispatchRequest) -> Digest {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(b"faultloom-scope-proof-v1\0");
    bytes.extend_from_slice(epoch_binding.as_bytes());
    bytes.extend_from_slice(request.scope_binding_digest().as_bytes());
    bytes.extend_from_slice(request.intent_digest.as_bytes());
    bytes.extend_from_slice(request.decision_digest.as_bytes());
    bytes.extend_from_slice(&(request.lease_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(request.lease_id.as_bytes());
    Digest::of(&bytes)
}

fn cancel_all(
    state: &mut ScopeState,
    cancelled_by_epoch: u64,
    cause: CancellationCause,
) -> Vec<CancellationRecord> {
    state.approved_actions.clear();
    let cancellations = std::mem::take(&mut state.resources)
        .into_values()
        .map(|resource| CancellationRecord {
            resource,
            cancelled_by_epoch,
            cause,
        })
        .collect::<Vec<_>>();
    state.cancellation_log.extend(cancellations.clone());
    cancellations
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::Mutex as TestMutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;

    use super::*;
    use crate::ipc::{
        ActionKind, DispatchOutcome, EgressPlane, GatewayResponse, RequiredFeature, encode_request,
    };
    use crate::kernel::{Clock, Gateway};
    use crate::lease::{
        GrantBudget, LeaseAuthority, LeaseBudgetReservation, LeaseSpec, ReconciliationAuthority,
    };
    use crate::policy::{ActionCompiler, CompiledAction};
    use crate::transport::TcpTargetTransport;

    #[derive(Clone)]
    struct FixedClock(Arc<AtomicU64>);

    impl FixedClock {
        fn new(now: u64) -> Self {
            Self(Arc::new(AtomicU64::new(now)))
        }

        fn set(&self, now: u64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl ScopeClock for FixedClock {
        fn now_millis(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Clock for FixedClock {
        fn now_millis(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct ExactCompiler;

    impl ActionCompiler for ExactCompiler {
        fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
            Ok(CompiledAction {
                intent_digest: request.intent_digest,
                action_kind: request.action_kind,
                target: request.target,
                egress_plane: request.egress_plane,
                semantic_action_digest: request.semantic_action_digest,
                resolution_digest: request.resolution_digest,
                request_binding_digest: request.lease_binding_digest(),
                effect_digest: crate::policy::target_effect_digest(
                    request.action_kind,
                    request.egress_plane,
                    request.resolution_digest,
                    Digest::of(&request.payload),
                ),
                bytes: request.payload.clone(),
            })
        }
    }

    struct BlockingCompiler {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }

    impl ActionCompiler for BlockingCompiler {
        fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
            self.entered
                .send(())
                .map_err(|_| DenialCode::CompilerUnavailable)?;
            self.release
                .recv()
                .map_err(|_| DenialCode::CompilerUnavailable)?;
            ExactCompiler.compile(request)
        }
    }

    fn cancellation_authority() -> (Arc<LeaseAuthority>, ReconciliationAuthority) {
        let signing_key = std::array::from_fn(|index| {
            u8::try_from(index + 1).expect("small lease signing key byte")
        });
        let reconciliation_key = std::array::from_fn(|index| {
            u8::try_from(index + 65).expect("small reconciliation key byte")
        });
        let authority = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:scope-cancellation".to_owned(),
            signing_key,
            "gateway-boot:fixture".to_owned(),
            Digest::of(b"scope cancellation gateway challenge"),
            "reconciliation-key:scope-cancellation".to_owned(),
            reconciliation_key,
        )
        .expect("cancellation-aware lease authority");
        authority
            .register_grant(
                "grant:owned",
                3,
                GrantBudget {
                    total_actions: 8,
                    rate_per_minute: 8,
                    max_concurrency: 2,
                    max_request_bytes: 256,
                    max_response_bytes: 256,
                    max_duration_seconds: 5,
                },
            )
            .expect("scope cancellation grant");
        let reconciler = ReconciliationAuthority::new(
            "reconciliation-key:scope-cancellation".to_owned(),
            reconciliation_key,
        )
        .expect("scope cancellation reconciler");
        (Arc::new(authority), reconciler)
    }

    fn cancellation_lease_spec(
        request: &DispatchRequest,
        scope_epoch_binding_digest: Digest,
    ) -> LeaseSpec {
        LeaseSpec {
            lease_id: request.lease_id.clone(),
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            scope_epoch: request.scope_epoch,
            authority_key_id: "authority-key:1".to_owned(),
            scope_epoch_binding_digest,
            gateway_boot_id: "gateway-boot:fixture".to_owned(),
            control_envelope_id: Digest::of(b"fixture authenticated control envelope"),
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
                response_bytes: 64,
                duration_seconds: 2,
            },
        }
    }

    #[derive(Default)]
    struct RecordingCancellationSink {
        events: TestMutex<Vec<ScopeCancellation>>,
    }

    impl ScopeCancellationSink for RecordingCancellationSink {
        fn cancel_scope(&self, cancellation: &ScopeCancellation) -> Result<(), DenialCode> {
            self.events
                .lock()
                .map_err(|_| DenialCode::ScopeDenied)?
                .push(cancellation.clone());
            Ok(())
        }
    }

    struct FailingCancellationSink;

    impl ScopeCancellationSink for FailingCancellationSink {
        fn cancel_scope(&self, _cancellation: &ScopeCancellation) -> Result<(), DenialCode> {
            Err(DenialCode::LeaseAccountingUnavailable)
        }
    }

    struct ReportingCancellationSink {
        interrupted_active: u64,
    }

    impl ScopeCancellationSink for ReportingCancellationSink {
        fn cancel_scope(&self, _cancellation: &ScopeCancellation) -> Result<(), DenialCode> {
            Ok(())
        }

        fn cancel_scope_with_report(
            &self,
            _cancellation: &ScopeCancellation,
        ) -> Result<ScopeCancellationReport, DenialCode> {
            Ok(ScopeCancellationReport {
                interrupted_active: self.interrupted_active,
            })
        }
    }

    #[derive(Clone)]
    struct FixtureVerifier {
        envelope_digest: Digest,
        epoch: u64,
        revoked: bool,
    }

    impl super::epoch_verifier_private::Sealed for FixtureVerifier {}

    impl EpochVerifier for FixtureVerifier {
        fn verify(
            &self,
            envelope: &SignedEpochEnvelope,
            _now_millis: u64,
        ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
            if envelope.digest() != self.envelope_digest {
                return Err(EpochAdmissionError::VerificationFailed);
            }
            Ok(VerifiedScopeEpoch::from_trusted_verifier(
                VerifiedScopeEpochParts {
                    grant_id: "grant:owned".to_owned(),
                    epoch: self.epoch,
                    issued_at_millis: 900,
                    expires_at_millis: 2_000,
                    revoked: self.revoked,
                    revocation_reason: self.revoked.then(|| "operator revoke".to_owned()),
                    key_id: "authority-key:1".to_owned(),
                    signature_sequence: self.epoch,
                    envelope_digest: envelope.digest(),
                    payload_digest: Digest::of(b"signed-payload"),
                    verifier_receipt_digest: Digest::of(b"t13-verification-receipt"),
                    gateway_boot_id: "gateway-boot:fixture".to_owned(),
                    verification_nonce: [self.epoch as u8; 16],
                },
            ))
        }
    }

    #[derive(Clone)]
    struct SequenceVerifier {
        accepted: Vec<(Digest, u64, bool)>,
    }

    struct AtomicAdmissionVerifier {
        accepted: Vec<(Digest, String, u64, [u8; 16])>,
    }

    impl super::epoch_verifier_private::Sealed for AtomicAdmissionVerifier {}

    impl EpochVerifier for AtomicAdmissionVerifier {
        fn verify(
            &self,
            envelope: &SignedEpochEnvelope,
            _now_millis: u64,
        ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
            let digest = envelope.digest();
            let (_, grant_id, epoch, nonce) = self
                .accepted
                .iter()
                .find(|(candidate, _, _, _)| *candidate == digest)
                .ok_or(EpochAdmissionError::VerificationFailed)?;
            Ok(VerifiedScopeEpoch::from_trusted_verifier(
                VerifiedScopeEpochParts {
                    grant_id: grant_id.clone(),
                    epoch: *epoch,
                    issued_at_millis: 900,
                    expires_at_millis: 2_000,
                    revoked: false,
                    revocation_reason: None,
                    key_id: "authority-key:1".to_owned(),
                    signature_sequence: *epoch,
                    envelope_digest: digest,
                    payload_digest: Digest::of(b"signed-payload"),
                    verifier_receipt_digest: Digest::of(envelope.canonical_bytes()),
                    gateway_boot_id: "gateway-boot:fixture".to_owned(),
                    verification_nonce: *nonce,
                },
            ))
        }
    }

    impl super::epoch_verifier_private::Sealed for SequenceVerifier {}

    impl EpochVerifier for SequenceVerifier {
        fn verify(
            &self,
            envelope: &SignedEpochEnvelope,
            _now_millis: u64,
        ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
            let digest = envelope.digest();
            let (_, epoch, revoked) = self
                .accepted
                .iter()
                .find(|(candidate, _, _)| *candidate == digest)
                .ok_or(EpochAdmissionError::VerificationFailed)?;
            Ok(VerifiedScopeEpoch::from_trusted_verifier(
                VerifiedScopeEpochParts {
                    grant_id: "grant:owned".to_owned(),
                    epoch: *epoch,
                    issued_at_millis: 900,
                    expires_at_millis: 2_000_u64
                        .saturating_add(epoch.saturating_sub(7).saturating_mul(1_000)),
                    revoked: *revoked,
                    revocation_reason: revoked.then(|| "operator revoke".to_owned()),
                    key_id: "authority-key:1".to_owned(),
                    signature_sequence: *epoch,
                    envelope_digest: digest,
                    payload_digest: Digest::of(b"signed-payload"),
                    verifier_receipt_digest: Digest::of(b"t13-verification-receipt"),
                    gateway_boot_id: "gateway-boot:fixture".to_owned(),
                    verification_nonce: [*epoch as u8; 16],
                },
            ))
        }
    }

    fn policy() -> ScopePolicy {
        ScopePolicy {
            grant_id: "grant:owned".to_owned(),
            grant_version: 3,
            targets: vec![TargetRule {
                target_id: "target:loopback".to_owned(),
                host_patterns: vec!["lab.example.test".to_owned()],
                networks: vec![IpNetwork::new("127.0.0.0".parse().unwrap(), 8).unwrap()],
                ports: vec![8080],
                protocols: vec!["http".to_owned()],
                path_patterns: vec!["/api/*".to_owned()],
                methods: vec!["GET".to_owned(), "POST".to_owned()],
                supporting_read_only: false,
            }],
            pack_ids: vec!["web".to_owned()],
            allowed_classes: vec![ActionClass::Observe, ActionClass::SafeProbe],
            allowed_families: vec!["http.semantic".to_owned()],
            allowed_methods: vec!["GET".to_owned(), "POST".to_owned()],
            allowed_path_patterns: vec!["/api/*".to_owned()],
            denied: vec![ExplicitDenyRule {
                deny_id: "deny:admin".to_owned(),
                target_id: Some("target:loopback".to_owned()),
                host_pattern: None,
                path_pattern: Some("/api/admin/*".to_owned()),
                methods: Vec::new(),
                action_families: Vec::new(),
            }],
            identities: vec!["identity:owner".to_owned(), "identity:member".to_owned()],
            tenants: vec!["tenant:alpha".to_owned()],
            execution_windows: vec![TimeWindow {
                starts_at_millis: 800,
                ends_at_millis: 1_800,
            }],
            state_change_families: Vec::new(),
        }
    }

    fn envelope(epoch: u64, revoked: bool) -> (SignedEpochEnvelope, FixtureVerifier) {
        let bytes = format!("signed-scope-epoch:{epoch}:revoked={revoked}").into_bytes();
        let envelope = SignedEpochEnvelope::new(bytes).unwrap();
        let verifier = FixtureVerifier {
            envelope_digest: envelope.digest(),
            epoch,
            revoked,
        };
        (envelope, verifier)
    }

    fn request() -> DispatchRequest {
        let mut request = DispatchRequest {
            action_id: "action:root".to_owned(),
            correlation_id: "correlation:root".to_owned(),
            grant_id: "grant:owned".to_owned(),
            grant_version: 3,
            target_id: "target:loopback".to_owned(),
            pack_id: "web".to_owned(),
            action_family: "http.semantic".to_owned(),
            identity_id: "identity:owner".to_owned(),
            tenant_id: Some("tenant:alpha".to_owned()),
            intent_digest: Digest::of(b"intent"),
            decision_digest: Digest::of(b"decision"),
            lease_id: "lease:1".to_owned(),
            scope_epoch: 7,
            action_kind: ActionKind::SemanticHttpV1,
            action_class: ActionClass::SafeProbe,
            egress_plane: EgressPlane::TargetGateway,
            flow_kind: FlowKind::TopLevel,
            parent_action_id: None,
            required_features: vec![RequiredFeature::GatewayDispatchV1],
            hostname: "lab.example.test".to_owned(),
            protocol: "http".to_owned(),
            method: "GET".to_owned(),
            path: "/api/item".to_owned(),
            target: "127.0.0.1:8080".parse().unwrap(),
            resolution_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            dispatch_nonce: *b"0123456789abcdef",
            request_issued_at_millis: 999,
            request_expires_at_millis: 6_000,
            retry_of_intent_digest: None,
            payload: b"GET /api/item HTTP/1.1\r\n\r\n".to_vec(),
            scope_proof: vec![1],
            lease_proof: b"lease-proof".to_vec(),
            compiler_proof: b"compiler-proof".to_vec(),
            canary_ref: None,
            checkpoint_ref: None,
            cleanup_plan_ref: None,
        };
        request.bind_canonical_semantics();
        request
    }

    fn make_kernel(
        verifier: FixtureVerifier,
        clock: FixedClock,
    ) -> DeterministicScopeKernel<FixtureVerifier, FixedClock> {
        DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock,
            Arc::new(RecordingCancellationSink::default()),
        )
        .unwrap()
    }

    fn authorize<V: EpochVerifier, C: ScopeClock>(
        kernel: &DeterministicScopeKernel<V, C>,
        request: &mut DispatchRequest,
    ) -> Result<ScopeApproval, DenialCode> {
        request.scope_proof = kernel.issue_scope_proof(request)?;
        kernel.verify(request)
    }

    #[test]
    fn verified_current_epoch_allows_only_an_exact_scope_match() {
        let clock = FixedClock::new(1_000);
        let (envelope, verifier) = envelope(7, false);
        let kernel = make_kernel(verifier, clock);
        assert_eq!(kernel.admit_epoch(&envelope).unwrap().current_epoch, 7);
        let mut allowed = request();
        let approval = authorize(&kernel, &mut allowed).unwrap();
        assert_eq!(
            approval.scope_binding_digest,
            allowed.scope_binding_digest()
        );

        let mut forged_proof = request();
        forged_proof.action_id = "action:forged-proof".to_owned();
        forged_proof.scope_proof = kernel.issue_scope_proof(&forged_proof).unwrap();
        forged_proof.scope_proof[0] ^= 1;
        assert_eq!(
            kernel.verify(&forged_proof).expect_err("forged proof"),
            DenialCode::ScopeProofInvalid
        );

        let mut rebound_proof = request();
        rebound_proof.action_id = "action:rebound-proof".to_owned();
        rebound_proof.scope_proof = kernel.issue_scope_proof(&rebound_proof).unwrap();
        rebound_proof.path = "/api/other".to_owned();
        assert_eq!(
            kernel.verify(&rebound_proof).expect_err("rebound proof"),
            DenialCode::ScopeProofInvalid
        );

        let mut wrong_method = request();
        wrong_method.action_id = "action:method".to_owned();
        wrong_method.method = "DELETE".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&wrong_method),
            Err(DenialCode::ScopeTargetDenied)
        );
        let mut wrong_path = request();
        wrong_path.action_id = "action:path".to_owned();
        wrong_path.path = "/outside".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&wrong_path),
            Err(DenialCode::ScopeTargetDenied)
        );
        let mut wrong_port = request();
        wrong_port.action_id = "action:port".to_owned();
        wrong_port.target.set_port(9090);
        assert_eq!(
            kernel.issue_scope_proof(&wrong_port),
            Err(DenialCode::ScopeTargetDenied)
        );
        let mut wrong_protocol = request();
        wrong_protocol.action_id = "action:protocol".to_owned();
        wrong_protocol.protocol = "https".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&wrong_protocol),
            Err(DenialCode::ScopeTargetDenied)
        );
        let mut wrong_family = request();
        wrong_family.action_id = "action:family".to_owned();
        wrong_family.action_family = "http.raw".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&wrong_family),
            Err(DenialCode::ScopeActionDenied)
        );
        let mut wrong_pack = request();
        wrong_pack.action_id = "action:pack".to_owned();
        wrong_pack.pack_id = "llm".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&wrong_pack),
            Err(DenialCode::ScopeActionDenied)
        );
        let mut wrong_class = request();
        wrong_class.action_id = "action:class".to_owned();
        wrong_class.action_class = ActionClass::StateChange;
        wrong_class.canary_ref = Some("canary:1".to_owned());
        wrong_class.cleanup_plan_ref = Some("cleanup:1".to_owned());
        assert_eq!(
            kernel.issue_scope_proof(&wrong_class),
            Err(DenialCode::ScopeActionDenied)
        );
        let mut wrong_identity = request();
        wrong_identity.action_id = "action:identity".to_owned();
        wrong_identity.identity_id = "identity:outsider".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&wrong_identity),
            Err(DenialCode::ScopeIdentityDenied)
        );
        let mut wrong_tenant = request();
        wrong_tenant.action_id = "action:tenant".to_owned();
        wrong_tenant.tenant_id = Some("tenant:beta".to_owned());
        assert_eq!(
            kernel.issue_scope_proof(&wrong_tenant),
            Err(DenialCode::ScopeTenantDenied)
        );
    }

    #[test]
    fn overlapping_active_windows_extend_live_expiry_as_a_union() {
        let clock = FixedClock::new(1_000);
        let (envelope, verifier) = envelope(7, false);
        let mut overlapping_policy = policy();
        overlapping_policy.execution_windows = vec![
            TimeWindow {
                starts_at_millis: 800,
                ends_at_millis: 1_200,
            },
            TimeWindow {
                starts_at_millis: 900,
                ends_at_millis: 1_800,
            },
        ];
        let kernel = DeterministicScopeKernel::new(overlapping_policy, verifier, clock)
            .expect("overlapping-window policy");
        kernel.admit_epoch(&envelope).expect("current epoch");
        let mut dispatch = request();

        let approval = authorize(&kernel, &mut dispatch).expect("scope approval");

        assert_eq!(approval.valid_until_millis, 1_800);
    }

    #[test]
    fn inactive_disjoint_window_does_not_extend_live_expiry() {
        let clock = FixedClock::new(1_000);
        let (envelope, verifier) = envelope(7, false);
        let mut disjoint_policy = policy();
        disjoint_policy.execution_windows = vec![
            TimeWindow {
                starts_at_millis: 800,
                ends_at_millis: 1_200,
            },
            TimeWindow {
                starts_at_millis: 1_300,
                ends_at_millis: 1_800,
            },
        ];
        let kernel = DeterministicScopeKernel::new(disjoint_policy, verifier, clock)
            .expect("disjoint-window policy");
        kernel.admit_epoch(&envelope).expect("current epoch");
        let mut dispatch = request();

        let approval = authorize(&kernel, &mut dispatch).expect("scope approval");

        assert_eq!(approval.valid_until_millis, 1_200);
    }

    #[test]
    fn resource_registration_without_a_cancellation_sink_fails_closed() {
        let clock = FixedClock::new(1_000);
        let (signed, verifier) = envelope(7, false);
        let kernel =
            DeterministicScopeKernel::new(policy(), verifier, clock).expect("scope kernel");
        kernel.admit_epoch(&signed).expect("initial epoch");
        let mut root = request();
        authorize(&kernel, &mut root).expect("authorized root");
        assert_eq!(
            kernel.register_resource(ScopedResource {
                resource_id: "resource:uncoupled".to_owned(),
                owner_action_id: root.action_id,
                kind: ResourceKind::OpenConnection,
                scope_epoch: 7,
            }),
            Err(DenialCode::ScopeDenied)
        );
    }

    #[test]
    fn explicit_deny_wins_over_every_matching_allow() {
        let clock = FixedClock::new(1_000);
        let (envelope, verifier) = envelope(7, false);
        let kernel = make_kernel(verifier, clock);
        kernel.admit_epoch(&envelope).unwrap();
        let mut denied = request();
        denied.path = "/api/admin/users".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&denied),
            Err(DenialCode::ExplicitScopeDeny)
        );
    }

    #[test]
    fn hostname_only_scope_denies_special_addresses_after_ip_canonicalization() {
        let clock = FixedClock::new(1_000);
        let (envelope, verifier) = envelope(7, false);
        let mut hostname_only = policy();
        hostname_only.targets[0].networks.clear();
        let kernel = DeterministicScopeKernel::new(hostname_only, verifier, clock).unwrap();
        kernel.admit_epoch(&envelope).unwrap();

        for address in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            let mut denied = request();
            denied.target = std::net::SocketAddr::new(address.parse().unwrap(), 8080);
            assert_eq!(
                kernel.issue_scope_proof(&denied),
                Err(DenialCode::ScopeTargetDenied),
                "hostname-only scope admitted special address {address}"
            );
        }

        let mut global = request();
        global.target = "93.184.216.34:8080".parse().unwrap();
        assert!(kernel.issue_scope_proof(&global).is_ok());

        let mut mapped_global = request();
        mapped_global.target =
            std::net::SocketAddr::new("::ffff:93.184.216.34".parse().unwrap(), 8080);
        assert!(kernel.issue_scope_proof(&mapped_global).is_ok());
    }

    #[test]
    fn explicit_networks_match_mapped_ipv4_only_after_canonicalization() {
        let mapped_loopback = IpNetwork::new("::ffff:127.0.0.0".parse().unwrap(), 104).unwrap();
        assert!(mapped_loopback.contains("127.1.2.3".parse().unwrap()));
        assert!(mapped_loopback.contains("::ffff:127.1.2.3".parse().unwrap()));
        assert!(!mapped_loopback.contains("128.0.0.1".parse().unwrap()));
        assert_eq!(
            IpNetwork::new("::ffff:127.0.0.0".parse().unwrap(), 95),
            Err(ScopePolicyError::InvalidNetwork)
        );

        let clock = FixedClock::new(1_000);
        let (envelope, verifier) = envelope(7, false);
        let kernel = make_kernel(verifier, clock);
        kernel.admit_epoch(&envelope).unwrap();
        let mut explicitly_allowed = request();
        explicitly_allowed.target =
            std::net::SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), 8080);
        assert!(kernel.issue_scope_proof(&explicitly_allowed).is_ok());
    }

    #[test]
    fn dns_redirect_and_each_child_flow_are_re_evaluated() {
        let clock = FixedClock::new(1_000);
        let (envelope, verifier) = envelope(7, false);
        let kernel = make_kernel(verifier, clock);
        kernel.admit_epoch(&envelope).unwrap();
        let mut root = request();
        authorize(&kernel, &mut root).unwrap();

        let mut dns = request();
        dns.action_id = "action:dns".to_owned();
        dns.flow_kind = FlowKind::DnsResolution;
        dns.parent_action_id = Some(root.action_id.clone());
        authorize(&kernel, &mut dns).unwrap();

        let mut rebound = request();
        rebound.action_id = "action:rebound".to_owned();
        rebound.flow_kind = FlowKind::DnsResolution;
        rebound.parent_action_id = Some(root.action_id.clone());
        rebound.target = "169.254.169.254:8080".parse().unwrap();
        assert_eq!(
            kernel.issue_scope_proof(&rebound),
            Err(DenialCode::ScopeTargetDenied)
        );

        let mut redirect = request();
        redirect.action_id = "action:redirect".to_owned();
        redirect.flow_kind = FlowKind::Redirect;
        redirect.parent_action_id = Some(root.action_id.clone());
        redirect.hostname = "outside.example.test".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&redirect),
            Err(DenialCode::ScopeTargetDenied)
        );

        let mut cname = request();
        cname.action_id = "action:cname".to_owned();
        cname.flow_kind = FlowKind::DnsResolution;
        cname.parent_action_id = Some(root.action_id.clone());
        cname.hostname = "cname.outside.example.test".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&cname),
            Err(DenialCode::ScopeTargetDenied)
        );

        for (index, flow) in [
            FlowKind::BrowserSubresource,
            FlowKind::BrowserIframe,
            FlowKind::ServiceWorker,
            FlowKind::WebSocket,
            FlowKind::Download,
            FlowKind::ScannerChild,
            FlowKind::GraphQlChild,
            FlowKind::BatchChild,
            FlowKind::Callback,
            FlowKind::Polling,
            FlowKind::RawSchedule,
            FlowKind::PackAction,
        ]
        .into_iter()
        .enumerate()
        {
            let mut child = request();
            child.action_id = format!("action:child:{index}");
            child.flow_kind = flow;
            child.parent_action_id = Some(root.action_id.clone());
            authorize(&kernel, &mut child).unwrap();
        }

        let mut orphan = request();
        orphan.action_id = "action:orphan".to_owned();
        orphan.flow_kind = FlowKind::Polling;
        orphan.parent_action_id = Some("action:unknown".to_owned());
        assert_eq!(
            kernel.issue_scope_proof(&orphan),
            Err(DenialCode::InvalidChildFlow)
        );
    }

    #[test]
    fn epoch_admission_rejects_tamper_replay_rollback_and_invalid_receipts() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (signed_six, _) = envelope(6, false);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_six.digest(), 6, false),
            ],
        };
        let kernel = DeterministicScopeKernel::new(policy(), verifier, clock.clone()).unwrap();
        kernel.admit_epoch(&signed_seven).unwrap();
        assert_eq!(
            kernel.admit_epoch(&signed_seven),
            Err(EpochAdmissionError::Replay)
        );
        let tampered = SignedEpochEnvelope::new(b"tampered".to_vec()).unwrap();
        assert_eq!(
            kernel.admit_epoch(&tampered),
            Err(EpochAdmissionError::VerificationFailed)
        );
        assert_eq!(
            kernel.admit_epoch(&signed_six),
            Err(EpochAdmissionError::Rollback)
        );

        struct ForgedReceiptVerifier;
        impl super::epoch_verifier_private::Sealed for ForgedReceiptVerifier {}

        impl EpochVerifier for ForgedReceiptVerifier {
            fn verify(
                &self,
                envelope: &SignedEpochEnvelope,
                _now_millis: u64,
            ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
                Ok(VerifiedScopeEpoch::from_trusted_verifier(
                    VerifiedScopeEpochParts {
                        grant_id: "grant:owned".to_owned(),
                        epoch: 8,
                        issued_at_millis: 900,
                        expires_at_millis: 2_000,
                        revoked: false,
                        revocation_reason: None,
                        key_id: "authority-key:1".to_owned(),
                        signature_sequence: 9,
                        envelope_digest: envelope.digest(),
                        payload_digest: Digest::of(b"payload"),
                        verifier_receipt_digest: Digest::ZERO,
                        gateway_boot_id: "gateway-boot:fixture".to_owned(),
                        verification_nonce: [8; 16],
                    },
                ))
            }
        }
        let forged =
            DeterministicScopeKernel::new(policy(), ForgedReceiptVerifier, FixedClock::new(1_000))
                .unwrap();
        assert_eq!(
            forged.admit_epoch(&signed_seven),
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        );
    }

    #[test]
    fn epoch_and_nonce_commit_atomically_only_after_all_admission_checks() {
        let wrong_grant = SignedEpochEnvelope::new(b"wrong-grant".to_vec()).unwrap();
        let first = SignedEpochEnvelope::new(b"first".to_vec()).unwrap();
        let reused = SignedEpochEnvelope::new(b"reused".to_vec()).unwrap();
        let second = SignedEpochEnvelope::new(b"second".to_vec()).unwrap();
        let nonce_one = [0x31; 16];
        let nonce_two = [0x32; 16];
        let verifier = AtomicAdmissionVerifier {
            accepted: vec![
                (wrong_grant.digest(), "grant:other".to_owned(), 7, nonce_one),
                (first.digest(), "grant:owned".to_owned(), 7, nonce_one),
                (reused.digest(), "grant:owned".to_owned(), 8, nonce_one),
                (second.digest(), "grant:owned".to_owned(), 8, nonce_two),
            ],
        };
        let kernel =
            DeterministicScopeKernel::new(policy(), verifier, FixedClock::new(1_000)).unwrap();

        assert_eq!(
            kernel.admit_epoch(&wrong_grant),
            Err(EpochAdmissionError::GrantMismatch)
        );
        assert_eq!(kernel.admit_epoch(&first).unwrap().current_epoch, 7);
        assert_eq!(
            kernel.admit_epoch(&reused),
            Err(EpochAdmissionError::Replay)
        );
        assert_eq!(kernel.admit_epoch(&second).unwrap().current_epoch, 8);
    }

    #[test]
    fn authenticated_t13_receipt_enters_the_kernel_and_replays_fail_closed() {
        const NOW: u64 = 1_893_553_445_679;
        const AUTHORITY_KEY_ID: &str =
            "ed25519:sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c";
        let canonical = include_bytes!(
            "../../packages/protocol/tests/fixtures/scope_epoch_signed_envelope_v0_1.json"
        )
        .strip_suffix(b"\n")
        .unwrap()
        .to_vec();
        let receipt_hex = include_str!(
            "../../packages/protocol/tests/fixtures/scope_epoch_gateway_receipt_v0_1.hex"
        )
        .trim();
        let receipt = (0..receipt_hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&receipt_hex[index..index + 2], 16).unwrap())
            .collect();
        let envelope = SignedEpochEnvelope::with_verifier_receipt(canonical, receipt).unwrap();
        let trust_bytes = format!(
            "{{\"authority_keys\":[{{\"key_id\":\"{AUTHORITY_KEY_ID}\",\"public_key_base64url\":\"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg\",\"status\":\"active\"}}],\"controller_keys\":[{{\"key_id\":\"ed25519:sha256:39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f\",\"public_key_base64url\":\"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw\",\"status\":\"active\"}}],\"generation\":1,\"grant_pins\":[{{\"authority_key_ids\":[\"{AUTHORITY_KEY_ID}\"],\"controller_key_ids\":[\"ed25519:sha256:39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f\"],\"grant_id\":\"grant.golden\",\"minimum_version\":1}}],\"schema_version\":1}}"
        );
        let trust = crate::installed_trust::installed_trust_store_from_canonical_bytes_for_test(
            trust_bytes.as_bytes(),
        )
        .unwrap();
        let channel_key =
            std::array::from_fn(|index| u8::try_from(index).expect("epoch channel key byte"));
        let challenge = std::array::from_fn(|index| {
            0x80_u8.saturating_add(u8::try_from(index).expect("gateway challenge byte"))
        });
        let boot = GatewayBootBinding::new("gateway-boot:test-1".to_owned(), challenge).unwrap();
        let channel =
            ReceiptAuthenticationChannel::new("gateway-channel:test".to_owned(), channel_key, boot)
                .unwrap();
        let expected_grant = ExpectedScopeEpochGrant::new("grant.golden".to_owned(), 1).unwrap();
        let verifier = T13ReceiptEpochVerifier::new(T13EpochVerifierConfig::new(
            channel,
            Arc::new(trust),
            expected_grant,
        ));
        let mut golden_policy = policy();
        golden_policy.grant_id = "grant.golden".to_owned();
        golden_policy.execution_windows = vec![TimeWindow {
            starts_at_millis: NOW - 1_000,
            ends_at_millis: NOW + 60_000,
        }];
        let kernel =
            DeterministicScopeKernel::new(golden_policy, verifier, FixedClock::new(NOW)).unwrap();

        assert_eq!(kernel.admit_epoch(&envelope).unwrap().current_epoch, 7);
        assert_eq!(
            kernel.admit_epoch(&envelope),
            Err(EpochAdmissionError::Replay)
        );
    }

    #[test]
    fn revocation_cancels_every_registered_long_lived_resource_once() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (revoked, _) = envelope(8, true);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (revoked.digest(), 8, true),
            ],
        };
        let kernel = DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock,
            Arc::new(RecordingCancellationSink::default()),
        )
        .unwrap();
        kernel.admit_epoch(&signed_seven).unwrap();
        let mut root = request();
        authorize(&kernel, &mut root).unwrap();

        for (index, kind) in [
            ResourceKind::QueuedAction,
            ResourceKind::OpenConnection,
            ResourceKind::WebSocket,
            ResourceKind::CallbackLease,
            ResourceKind::Polling,
            ResourceKind::LongScannerJob,
        ]
        .into_iter()
        .enumerate()
        {
            kernel
                .register_resource(ScopedResource {
                    resource_id: format!("resource:{index}"),
                    owner_action_id: root.action_id.clone(),
                    kind,
                    scope_epoch: 7,
                })
                .unwrap();
        }
        assert_eq!(kernel.active_resource_count().unwrap(), 6);

        let transition = kernel.admit_epoch(&revoked).unwrap();
        assert!(transition.revoked);
        assert_eq!(transition.cancellations.len(), 6);
        assert_eq!(kernel.active_resource_count().unwrap(), 0);
        assert!(
            transition
                .cancellations
                .iter()
                .all(|item| item.cause == CancellationCause::ScopeRevoked)
        );
        assert_eq!(kernel.take_cancellations().unwrap().len(), 6);
        assert!(kernel.take_cancellations().unwrap().is_empty());

        let mut after_revoke = request();
        after_revoke.scope_epoch = 8;
        assert_eq!(
            kernel.issue_scope_proof(&after_revoke),
            Err(DenialCode::ScopeEpochRevoked)
        );
    }

    #[test]
    fn epoch_transitions_notify_the_cancellation_sink_once_with_exact_grant_scope() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (signed_eight, _) = envelope(8, false);
        let (revoked_nine, _) = envelope(9, true);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_eight.digest(), 8, false),
                (revoked_nine.digest(), 9, true),
            ],
        };
        let sink = Arc::new(RecordingCancellationSink::default());
        let kernel = DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock,
            Arc::clone(&sink) as Arc<dyn ScopeCancellationSink>,
        )
        .expect("scope kernel with cancellation sink");

        kernel.admit_epoch(&signed_seven).expect("initial epoch");
        assert!(sink.events.lock().expect("events").is_empty());
        kernel.admit_epoch(&signed_eight).expect("advance epoch");
        kernel.admit_epoch(&revoked_nine).expect("revoke scope");

        assert_eq!(
            *sink.events.lock().expect("events"),
            vec![
                ScopeCancellation {
                    grant_id: "grant:owned".to_owned(),
                    grant_version: 3,
                    invalidated_through_epoch: 7,
                    revoked_at_epoch: None,
                    cause: CancellationCause::EpochAdvanced,
                },
                ScopeCancellation {
                    grant_id: "grant:owned".to_owned(),
                    grant_version: 3,
                    invalidated_through_epoch: 9,
                    revoked_at_epoch: Some(9),
                    cause: CancellationCause::ScopeRevoked,
                },
            ]
        );
    }

    #[test]
    fn cancellation_sink_failure_cannot_commit_an_epoch_transition_or_expiry() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (signed_eight, _) = envelope(8, false);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_eight.digest(), 8, false),
            ],
        };
        let kernel = DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock.clone(),
            Arc::new(FailingCancellationSink),
        )
        .expect("scope kernel with failing sink");
        kernel.admit_epoch(&signed_seven).expect("initial epoch");
        let mut dispatch = request();
        authorize(&kernel, &mut dispatch).expect("authorized dispatch");
        kernel
            .register_resource(ScopedResource {
                resource_id: "resource:failed-cancellation".to_owned(),
                owner_action_id: dispatch.action_id,
                kind: ResourceKind::OpenConnection,
                scope_epoch: 7,
            })
            .expect("registered resource");

        assert_eq!(
            kernel.admit_epoch(&signed_eight),
            Err(EpochAdmissionError::StateUnavailable)
        );
        assert_eq!(kernel.active_resource_count(), Ok(1));
        assert!(
            kernel
                .take_cancellations()
                .expect("cancellations")
                .is_empty()
        );

        clock.set(2_000);
        assert_eq!(
            kernel.issue_scope_proof(&request()),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(kernel.active_resource_count(), Ok(1));
    }

    #[test]
    fn canceled_dispatch_resource_cannot_finish_as_success() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (signed_eight, _) = envelope(8, false);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_eight.digest(), 8, false),
            ],
        };
        let kernel = DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock,
            Arc::new(RecordingCancellationSink::default()),
        )
        .expect("scope kernel with cancellation sink");
        kernel.admit_epoch(&signed_seven).expect("initial epoch");
        let mut dispatch = request();
        authorize(&kernel, &mut dispatch).expect("authorized dispatch");
        let approval = LeaseApproval::fixture(&dispatch);
        ScopeVerifier::register_dispatch(&kernel, &dispatch, &approval)
            .expect("registered dispatch");

        kernel.admit_epoch(&signed_eight).expect("advance epoch");
        assert_eq!(
            ScopeVerifier::finish_dispatch(&kernel, &approval),
            Err(DenialCode::ScopeDenied)
        );
    }

    #[test]
    fn scope_finish_before_lease_finalize_is_counted_from_cancellation_report() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (signed_eight, _) = envelope(8, false);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_eight.digest(), 8, false),
            ],
        };
        let kernel = DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock,
            Arc::new(ReportingCancellationSink {
                interrupted_active: 1,
            }),
        )
        .expect("scope kernel with reporting cancellation sink");
        kernel.admit_epoch(&signed_seven).expect("initial epoch");
        let mut dispatch = request();
        authorize(&kernel, &mut dispatch).expect("authorized dispatch");
        let approval = LeaseApproval::fixture(&dispatch);
        ScopeVerifier::register_dispatch(&kernel, &dispatch, &approval)
            .expect("registered dispatch");
        ScopeVerifier::finish_dispatch(&kernel, &approval).expect("scope finish wins race");

        let transition = kernel
            .admit_epoch(&signed_eight)
            .expect("advance while lease remains active");

        assert!(transition.cancellations.is_empty());
        assert_eq!(transition.interrupted_active, 1);
        assert_eq!(transition.interrupted_resources(), 1);
    }

    #[test]
    fn epoch_expiry_notifies_the_cancellation_sink_once() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (signed_eight, _) = envelope(8, false);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_eight.digest(), 8, false),
            ],
        };
        let sink = Arc::new(RecordingCancellationSink::default());
        let kernel = DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock.clone(),
            Arc::clone(&sink) as Arc<dyn ScopeCancellationSink>,
        )
        .expect("scope kernel with cancellation sink");
        kernel.admit_epoch(&signed_seven).expect("initial epoch");

        clock.set(2_000);
        assert_eq!(
            kernel.issue_scope_proof(&request()),
            Err(DenialCode::ScopeEpochExpired)
        );
        assert_eq!(
            kernel.issue_scope_proof(&request()),
            Err(DenialCode::ScopeEpochExpired)
        );
        kernel
            .admit_epoch(&signed_eight)
            .expect("advance after expired epoch");
        assert_eq!(
            *sink.events.lock().expect("events"),
            vec![ScopeCancellation {
                grant_id: "grant:owned".to_owned(),
                grant_version: 3,
                invalidated_through_epoch: 7,
                revoked_at_epoch: None,
                cause: CancellationCause::EpochExpired,
            }]
        );
    }

    #[test]
    fn epoch_advance_physically_interrupts_gateway_transport_and_holds_the_exact_lease() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
        let target = listener.local_addr().expect("listener address");
        let (signed_seven, _) = envelope(7, false);
        let (signed_eight, _) = envelope(8, false);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_eight.digest(), 8, false),
            ],
        };
        let binding_seven = verified_epoch_binding(
            &verifier
                .verify(&signed_seven, 1_000)
                .expect("verified epoch seven"),
        );
        let binding_eight = verified_epoch_binding(
            &verifier
                .verify(&signed_eight, 1_000)
                .expect("verified epoch eight"),
        );
        let (authority, reconciler) = cancellation_authority();
        let mut coupled_policy = policy();
        coupled_policy.targets[0].ports = vec![target.port()];
        let clock = FixedClock::new(1_000);
        let scope = Arc::new(
            DeterministicScopeKernel::new_with_cancellation_sink(
                coupled_policy,
                verifier,
                clock.clone(),
                Arc::clone(&authority) as Arc<dyn ScopeCancellationSink>,
            )
            .expect("coupled scope kernel"),
        );
        scope.admit_epoch(&signed_seven).expect("initial epoch");

        let mut dispatch = request();
        dispatch.target = target;
        dispatch.bind_canonical_semantics();
        dispatch.scope_proof = scope
            .issue_scope_proof(&dispatch)
            .expect("epoch-seven scope proof");
        dispatch.lease_proof = authority
            .issue(cancellation_lease_spec(&dispatch, binding_seven))
            .expect("epoch-seven lease")
            .proof;
        let frame_digest = Digest::of(&encode_request(&dispatch).expect("canonical request"));
        let intent_digest = dispatch.intent_digest;
        let request_bytes = dispatch.payload.clone();
        let request_byte_count = request_bytes.len() as u64;
        let (request_read_tx, request_read_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("Gateway connection");
            let mut received = vec![0_u8; request_bytes.len()];
            stream.read_exact(&mut received).expect("request bytes");
            assert_eq!(received, request_bytes);
            request_read_tx.send(()).expect("request-read signal");
            release_rx.recv().expect("release target connection");
        });
        let gateway = Gateway::new(
            Arc::clone(&scope),
            Arc::clone(&authority),
            ExactCompiler,
            TcpTargetTransport::new(),
            clock,
        );
        let worker = thread::spawn(move || gateway.handle(dispatch, frame_digest));
        request_read_rx.recv().expect("target received request");

        let transition = scope.admit_epoch(&signed_eight).expect("advance epoch");
        assert_eq!(transition.cancellations.len(), 1);
        assert_eq!(
            transition.cancellations[0].cause,
            CancellationCause::EpochAdvanced
        );
        let response = worker.join().expect("Gateway worker");
        let GatewayResponse::Receipt { receipt, .. } = response else {
            panic!("interrupted dispatch must produce an authenticated receipt");
        };
        assert_eq!(receipt.outcome, DispatchOutcome::UnknownOutcome);
        assert!(receipt.reconciliation_required);
        let effect_digest = crate::policy::target_effect_digest(
            ActionKind::SemanticHttpV1,
            receipt.egress_plane,
            receipt.resolution_digest,
            receipt.request_digest,
        );
        assert_eq!(receipt.bytes_sent, request_byte_count);
        assert_eq!(
            authority
                .usage("grant:owned", 3)
                .expect("usage")
                .active_dispatches,
            0
        );
        release_tx.send(()).expect("release target");
        server.join().expect("target worker");

        let mut same_intent = request();
        same_intent.action_id = "action:epoch-eight-retry".to_owned();
        same_intent.correlation_id = "correlation:epoch-eight-retry".to_owned();
        same_intent.lease_id = "lease:epoch-eight-retry".to_owned();
        same_intent.scope_epoch = 8;
        same_intent.target = target;
        same_intent.decision_digest = Digest::of(b"epoch-eight retry decision");
        same_intent.dispatch_nonce = *b"epoch-eight-0001";
        same_intent.bind_canonical_semantics();
        same_intent.scope_proof = scope
            .issue_scope_proof(&same_intent)
            .expect("epoch-eight scope proof");
        assert_eq!(
            authority.issue(cancellation_lease_spec(&same_intent, binding_eight)),
            Err(DenialCode::LeaseReconciliationRequired)
        );

        let reconciliation = reconciler
            .issue_control_plane_hold(
                crate::lease::ControlPlaneReconciliationHold {
                    grant_id: "grant:owned".to_owned(),
                    grant_version: 3,
                    intent_digest,
                    effect_digest,
                    hold_binding_digest: receipt.hold_binding_digest,
                },
                crate::lease::ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"scope cancellation terminal evidence"),
                    nonce: *b"scope-cancel-001",
                    resolved_at_millis: 1_002,
                },
            )
            .expect("scope cancellation reconciliation");
        assert_eq!(
            authority.reconcile_control_plane_hold(&reconciliation),
            Ok(())
        );
        assert_eq!(
            authority.reconcile_control_plane_hold(&reconciliation),
            Err(DenialCode::LeaseReplay)
        );
    }

    #[test]
    fn scope_revoke_between_reservation_and_registration_opens_no_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let target = listener.local_addr().expect("listener address");
        let (signed_seven, _) = envelope(7, false);
        let (revoked_eight, _) = envelope(8, true);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (revoked_eight.digest(), 8, true),
            ],
        };
        let binding_seven = verified_epoch_binding(
            &verifier
                .verify(&signed_seven, 1_000)
                .expect("verified epoch seven"),
        );
        let (authority, _) = cancellation_authority();
        let mut coupled_policy = policy();
        coupled_policy.targets[0].ports = vec![target.port()];
        let clock = FixedClock::new(1_000);
        let scope = Arc::new(
            DeterministicScopeKernel::new_with_cancellation_sink(
                coupled_policy,
                verifier,
                clock.clone(),
                Arc::clone(&authority) as Arc<dyn ScopeCancellationSink>,
            )
            .expect("coupled scope kernel"),
        );
        scope.admit_epoch(&signed_seven).expect("initial epoch");
        let mut dispatch = request();
        dispatch.target = target;
        dispatch.bind_canonical_semantics();
        dispatch.scope_proof = scope.issue_scope_proof(&dispatch).expect("scope proof");
        dispatch.lease_proof = authority
            .issue(cancellation_lease_spec(&dispatch, binding_seven))
            .expect("lease")
            .proof;
        let frame_digest = Digest::of(&encode_request(&dispatch).expect("canonical request"));
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let gateway = Gateway::new(
            Arc::clone(&scope),
            Arc::clone(&authority),
            BlockingCompiler {
                entered: entered_tx,
                release: release_rx,
            },
            TcpTargetTransport::new(),
            clock,
        );
        let worker = thread::spawn(move || gateway.handle(dispatch, frame_digest));
        entered_rx.recv().expect("lease reserved before compiler");
        let transition = scope
            .admit_epoch(&revoked_eight)
            .expect("revoke while compiler is blocked");
        assert!(transition.revoked);
        assert!(transition.cancellations.is_empty());
        release_tx.send(()).expect("release compiler");
        assert!(matches!(
            worker.join().expect("Gateway worker"),
            GatewayResponse::Denied(_)
        ));
        assert_eq!(
            listener
                .accept()
                .expect_err("post-revoke dispatch cannot connect")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            authority
                .usage("grant:owned", 3)
                .expect("usage")
                .active_dispatches,
            0
        );
    }

    #[test]
    fn newer_non_revoked_epoch_invalidates_old_actions_and_resources() {
        let clock = FixedClock::new(1_000);
        let (signed_seven, _) = envelope(7, false);
        let (signed_eight, _) = envelope(8, false);
        let verifier = SequenceVerifier {
            accepted: vec![
                (signed_seven.digest(), 7, false),
                (signed_eight.digest(), 8, false),
            ],
        };
        let kernel = DeterministicScopeKernel::new_with_cancellation_sink(
            policy(),
            verifier,
            clock,
            Arc::new(RecordingCancellationSink::default()),
        )
        .unwrap();
        kernel.admit_epoch(&signed_seven).unwrap();
        let mut old = request();
        authorize(&kernel, &mut old).unwrap();
        kernel
            .register_resource(ScopedResource {
                resource_id: "resource:old-connection".to_owned(),
                owner_action_id: old.action_id.clone(),
                kind: ResourceKind::OpenConnection,
                scope_epoch: 7,
            })
            .unwrap();

        let transition = kernel.admit_epoch(&signed_eight).unwrap();
        assert_eq!(transition.previous_epoch, Some(7));
        assert_eq!(transition.current_epoch, 8);
        assert_eq!(transition.cancellations.len(), 1);
        assert_eq!(
            transition.cancellations[0].cause,
            CancellationCause::EpochAdvanced
        );
        assert_eq!(
            kernel.issue_scope_proof(&old),
            Err(DenialCode::ScopeEpochStale)
        );

        let mut current = request();
        current.action_id = "action:epoch-eight".to_owned();
        current.scope_epoch = 8;
        authorize(&kernel, &mut current).unwrap();
    }

    #[test]
    fn expiry_cancels_resources_and_time_windows_fail_closed() {
        let clock = FixedClock::new(1_000);
        let (signed, verifier) = envelope(7, false);
        let kernel = make_kernel(verifier, clock.clone());
        kernel.admit_epoch(&signed).unwrap();
        let mut root = request();
        authorize(&kernel, &mut root).unwrap();
        kernel
            .register_resource(ScopedResource {
                resource_id: "resource:poll".to_owned(),
                owner_action_id: root.action_id.clone(),
                kind: ResourceKind::Polling,
                scope_epoch: 7,
            })
            .unwrap();

        clock.set(1_900);
        let mut outside_window = request();
        outside_window.action_id = "action:outside-window".to_owned();
        assert_eq!(
            kernel.issue_scope_proof(&outside_window),
            Err(DenialCode::ScopeTimeDenied)
        );
        clock.set(2_000);
        assert_eq!(
            kernel.issue_scope_proof(&outside_window),
            Err(DenialCode::ScopeEpochExpired)
        );
        assert_eq!(kernel.active_resource_count().unwrap(), 0);
        let cancellations = kernel.take_cancellations().unwrap();
        assert_eq!(cancellations.len(), 1);
        assert_eq!(cancellations[0].cause, CancellationCause::EpochExpired);
    }

    #[test]
    fn production_epoch_verifier_is_deliberately_fail_closed() {
        let envelope = SignedEpochEnvelope::new(b"untrusted".to_vec()).unwrap();
        let kernel =
            DeterministicScopeKernel::new(policy(), UnavailableEpochVerifier, SystemScopeClock)
                .unwrap();
        assert_eq!(
            kernel.admit_epoch(&envelope),
            Err(EpochAdmissionError::VerifierUnavailable)
        );
    }

    #[test]
    fn poisoned_scope_state_never_reports_an_empty_or_successful_state() {
        let clock = FixedClock::new(1_000);
        let (signed, verifier) = envelope(7, false);
        let kernel = make_kernel(verifier, clock);
        kernel.admit_epoch(&signed).unwrap();
        let mut root = request();
        authorize(&kernel, &mut root).unwrap();
        kernel
            .register_resource(ScopedResource {
                resource_id: "resource:open".to_owned(),
                owner_action_id: root.action_id.clone(),
                kind: ResourceKind::OpenConnection,
                scope_epoch: 7,
            })
            .unwrap();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = kernel.state.lock().unwrap();
            panic!("poison fixture scope state");
        }));

        assert_eq!(
            kernel.issue_scope_proof(&request()),
            Err(DenialCode::ScopeDenied)
        );
        assert_eq!(kernel.active_resource_count(), Err(DenialCode::ScopeDenied));
        assert_eq!(kernel.take_cancellations(), Err(DenialCode::ScopeDenied));
        assert_eq!(
            kernel.finish_resource("resource:open"),
            Err(DenialCode::ScopeDenied)
        );
    }
}
