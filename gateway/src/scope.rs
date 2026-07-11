use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Digest;
use crate::ipc::{ActionClass, DenialCode, DispatchRequest, FlowKind, valid_identifier};
use crate::policy::{ScopeApproval, ScopeVerifier};

const MAX_SIGNED_EPOCH_BYTES: usize = 16_384;

mod epoch_verifier_private {
    pub trait Sealed {}
}

pub trait ScopeClock {
    fn now_millis(&self) -> u64;
}

pub struct SystemScopeClock;

impl ScopeClock for SystemScopeClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| value.as_millis().try_into().unwrap_or(u64::MAX))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEpochEnvelope {
    canonical_bytes: Vec<u8>,
}

impl SignedEpochEnvelope {
    pub fn new(canonical_bytes: Vec<u8>) -> Result<Self, EpochAdmissionError> {
        if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_SIGNED_EPOCH_BYTES {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        Ok(Self { canonical_bytes })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn digest(&self) -> Digest {
        Digest::of(&self.canonical_bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedScopeEpoch {
    grant_id: String,
    epoch: u64,
    issued_at_millis: u64,
    expires_at_millis: u64,
    revoked: bool,
    revocation_reason: Option<String>,
    key_id: String,
    signature_sequence: u64,
    envelope_digest: Digest,
    payload_digest: Digest,
    verifier_receipt_digest: Digest,
}

#[cfg(test)]
impl VerifiedScopeEpoch {
    #[allow(clippy::too_many_arguments)]
    fn from_trusted_verifier(
        grant_id: String,
        epoch: u64,
        issued_at_millis: u64,
        expires_at_millis: u64,
        revoked: bool,
        revocation_reason: Option<String>,
        key_id: String,
        signature_sequence: u64,
        envelope_digest: Digest,
        payload_digest: Digest,
        verifier_receipt_digest: Digest,
    ) -> Self {
        Self {
            grant_id,
            epoch,
            issued_at_millis,
            expires_at_millis,
            revoked,
            revocation_reason,
            key_id,
            signature_sequence,
            envelope_digest,
            payload_digest,
            verifier_receipt_digest,
        }
    }
}

pub trait EpochVerifier: epoch_verifier_private::Sealed {
    fn verify(
        &self,
        envelope: &SignedEpochEnvelope,
        now_millis: u64,
    ) -> Result<VerifiedScopeEpoch, EpochAdmissionError>;
}

pub struct UnavailableEpochVerifier;

impl epoch_verifier_private::Sealed for UnavailableEpochVerifier {}

impl EpochVerifier for UnavailableEpochVerifier {
    fn verify(
        &self,
        _envelope: &SignedEpochEnvelope,
        _now_millis: u64,
    ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
        Err(EpochAdmissionError::VerifierUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochAdmissionError {
    InvalidEnvelope,
    VerifierUnavailable,
    VerificationFailed,
    GrantMismatch,
    NotYetValid,
    Expired,
    InvalidValidity,
    InvalidVerificationReceipt,
    Rollback,
    Replay,
    StateUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, ScopePolicyError> {
        let (address, prefix) = canonical_network(address, prefix)?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(ScopePolicyError::InvalidNetwork);
        }
        Ok(Self {
            address: mask_ip(address, prefix),
            prefix,
        })
    }

    fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, canonical_ip(candidate)) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                mask_v4(candidate, self.prefix) == network
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                mask_v6(candidate, self.prefix) == network
            }
            _ => false,
        }
    }
}

fn canonical_network(address: IpAddr, prefix: u8) -> Result<(IpAddr, u8), ScopePolicyError> {
    match address {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) if prefix >= 96 => Ok((IpAddr::V4(mapped), prefix - 96)),
            Some(_) => Err(ScopePolicyError::InvalidNetwork),
            None => Ok((IpAddr::V6(address), prefix)),
        },
        IpAddr::V4(address) => Ok((IpAddr::V4(address), prefix)),
    }
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

fn mask_ip(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(mask_v4(address, prefix)),
        IpAddr::V6(address) => IpAddr::V6(mask_v6(address, prefix)),
    }
}

fn mask_v4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn mask_v6(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(address) & mask)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeWindow {
    pub starts_at_millis: u64,
    pub ends_at_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetRule {
    pub target_id: String,
    pub host_patterns: Vec<String>,
    pub networks: Vec<IpNetwork>,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub path_patterns: Vec<String>,
    pub methods: Vec<String>,
    pub supporting_read_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitDenyRule {
    pub deny_id: String,
    pub target_id: Option<String>,
    pub host_pattern: Option<String>,
    pub path_pattern: Option<String>,
    pub methods: Vec<String>,
    pub action_families: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopePolicy {
    pub grant_id: String,
    pub grant_version: u64,
    pub targets: Vec<TargetRule>,
    pub pack_ids: Vec<String>,
    pub allowed_classes: Vec<ActionClass>,
    pub allowed_families: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_path_patterns: Vec<String>,
    pub denied: Vec<ExplicitDenyRule>,
    pub identities: Vec<String>,
    pub tenants: Vec<String>,
    pub execution_windows: Vec<TimeWindow>,
    pub state_change_families: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopePolicyError {
    InvalidIdentifier,
    DuplicateIdentifier,
    InvalidHostPattern,
    InvalidNetwork,
    InvalidPort,
    InvalidProtocol,
    InvalidMethod,
    InvalidPathPattern,
    InvalidTimeWindow,
    EmptyRequiredAllowlist,
}

impl ScopePolicy {
    fn validate(&self) -> Result<(), ScopePolicyError> {
        if !valid_identifier(&self.grant_id) || self.grant_version == 0 {
            return Err(ScopePolicyError::InvalidIdentifier);
        }
        validate_identifiers(&self.pack_ids, true)?;
        validate_identifiers(&self.allowed_families, true)?;
        validate_identifiers(&self.identities, true)?;
        validate_identifiers(&self.tenants, false)?;
        validate_identifiers(&self.state_change_families, false)?;
        validate_methods(&self.allowed_methods, true)?;
        validate_paths(&self.allowed_path_patterns, true)?;
        if self.allowed_classes.is_empty() || self.execution_windows.is_empty() {
            return Err(ScopePolicyError::EmptyRequiredAllowlist);
        }
        let class_count = self
            .allowed_classes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len();
        if class_count != self.allowed_classes.len() {
            return Err(ScopePolicyError::DuplicateIdentifier);
        }
        for window in &self.execution_windows {
            if window.ends_at_millis <= window.starts_at_millis {
                return Err(ScopePolicyError::InvalidTimeWindow);
            }
        }
        let mut target_ids = BTreeSet::new();
        if self.targets.is_empty() {
            return Err(ScopePolicyError::EmptyRequiredAllowlist);
        }
        for target in &self.targets {
            if !valid_identifier(&target.target_id) || !target_ids.insert(&target.target_id) {
                return Err(if valid_identifier(&target.target_id) {
                    ScopePolicyError::DuplicateIdentifier
                } else {
                    ScopePolicyError::InvalidIdentifier
                });
            }
            if target.host_patterns.is_empty() && target.networks.is_empty() {
                return Err(ScopePolicyError::EmptyRequiredAllowlist);
            }
            validate_host_patterns(&target.host_patterns)?;
            validate_unique_ports(&target.ports)?;
            validate_protocols(&target.protocols, true)?;
            validate_methods(&target.methods, true)?;
            validate_paths(&target.path_patterns, true)?;
        }
        let mut deny_ids = BTreeSet::new();
        for deny in &self.denied {
            if !valid_identifier(&deny.deny_id) || !deny_ids.insert(&deny.deny_id) {
                return Err(if valid_identifier(&deny.deny_id) {
                    ScopePolicyError::DuplicateIdentifier
                } else {
                    ScopePolicyError::InvalidIdentifier
                });
            }
            if deny
                .target_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            {
                return Err(ScopePolicyError::InvalidIdentifier);
            }
            if let Some(pattern) = &deny.host_pattern {
                validate_host_pattern(pattern)?;
            }
            if let Some(pattern) = &deny.path_pattern {
                validate_path_pattern(pattern)?;
            }
            validate_methods(&deny.methods, false)?;
            validate_identifiers(&deny.action_families, false)?;
        }
        Ok(())
    }
}

fn validate_identifiers(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.iter().any(|value| !valid_identifier(value)) {
        return Err(ScopePolicyError::InvalidIdentifier);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_unique_ports(values: &[u16]) -> Result<(), ScopePolicyError> {
    if values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.contains(&0) {
        return Err(ScopePolicyError::InvalidPort);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_protocols(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.iter().any(|value| {
        value.is_empty()
            || value.len() > 16
            || value != &value.to_ascii_lowercase()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return Err(ScopePolicyError::InvalidProtocol);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_methods(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.iter().any(|value| {
        value.is_empty()
            || value.len() > 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(ScopePolicyError::InvalidMethod);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_paths(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    for value in values {
        validate_path_pattern(value)?;
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_path_pattern(value: &str) -> Result<(), ScopePolicyError> {
    let prefix = value.strip_suffix('*').unwrap_or(value);
    if value.is_empty()
        || value.len() > 4_096
        || !value.starts_with('/')
        || prefix.contains('*')
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte == b'#' || byte == b'?')
    {
        return Err(ScopePolicyError::InvalidPathPattern);
    }
    Ok(())
}

fn validate_host_patterns(values: &[String]) -> Result<(), ScopePolicyError> {
    for value in values {
        validate_host_pattern(value)?;
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_host_pattern(value: &str) -> Result<(), ScopePolicyError> {
    let host = value.strip_prefix("*.").unwrap_or(value);
    if host.is_empty()
        || host.len() > 253
        || host != host.to_ascii_lowercase()
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ScopePolicyError::InvalidHostPattern);
    }
    Ok(())
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationCause {
    EpochAdvanced,
    ScopeRevoked,
    EpochExpired,
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
}

#[derive(Clone, Debug)]
struct AdmittedEpoch {
    epoch: u64,
    issued_at_millis: u64,
    expires_at_millis: u64,
    revoked: bool,
    binding_digest: Digest,
}

#[derive(Default)]
struct ScopeState {
    current_epoch: Option<AdmittedEpoch>,
    approved_actions: BTreeMap<String, u64>,
    resources: BTreeMap<String, ScopedResource>,
    cancellation_log: Vec<CancellationRecord>,
}

pub struct DeterministicScopeKernel<V, C> {
    policy: ScopePolicy,
    verifier: V,
    clock: C,
    state: Mutex<ScopeState>,
}

impl<V, C> DeterministicScopeKernel<V, C>
where
    V: EpochVerifier,
    C: ScopeClock,
{
    pub fn new(policy: ScopePolicy, verifier: V, clock: C) -> Result<Self, ScopePolicyError> {
        policy.validate()?;
        Ok(Self {
            policy,
            verifier,
            clock,
            state: Mutex::new(ScopeState::default()),
        })
    }

    pub fn admit_epoch(
        &self,
        envelope: &SignedEpochEnvelope,
    ) -> Result<EpochTransition, EpochAdmissionError> {
        let now = self.clock.now_millis();
        let verified = self.verifier.verify(envelope, now)?;
        self.validate_verified_epoch(envelope, &verified, now)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EpochAdmissionError::StateUnavailable)?;
        let previous_epoch = state.current_epoch.as_ref().map(|epoch| epoch.epoch);
        if let Some(current) = &state.current_epoch {
            if verified.epoch < current.epoch {
                return Err(EpochAdmissionError::Rollback);
            }
            if verified.epoch == current.epoch {
                return Err(EpochAdmissionError::Replay);
            }
        }
        let cause = if verified.revoked {
            CancellationCause::ScopeRevoked
        } else {
            CancellationCause::EpochAdvanced
        };
        let cancellations = cancel_all(&mut state, verified.epoch, cause);
        let binding_digest = verified_epoch_binding(&verified);
        state.current_epoch = Some(AdmittedEpoch {
            epoch: verified.epoch,
            issued_at_millis: verified.issued_at_millis,
            expires_at_millis: verified.expires_at_millis,
            revoked: verified.revoked,
            binding_digest,
        });
        Ok(EpochTransition {
            previous_epoch,
            current_epoch: verified.epoch,
            revoked: verified.revoked,
            cancellations,
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
        let now = self.clock.now_millis();
        let mut state = self.state.lock().map_err(|_| DenialCode::ScopeDenied)?;
        reconcile_expiry(&mut state, now);
        let epoch = evaluate(&self.policy, &state, request, now)?;
        Ok(scope_proof(epoch.binding_digest, request)
            .as_bytes()
            .to_vec())
    }

    pub fn register_resource(&self, resource: ScopedResource) -> Result<(), DenialCode> {
        if !valid_identifier(&resource.resource_id) || !valid_identifier(&resource.owner_action_id)
        {
            return Err(DenialCode::InvalidRequest);
        }
        let now = self.clock.now_millis();
        let mut state = self.state.lock().map_err(|_| DenialCode::ScopeDenied)?;
        reconcile_expiry(&mut state, now);
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
}

impl<V, C> ScopeVerifier for DeterministicScopeKernel<V, C>
where
    V: EpochVerifier,
    C: ScopeClock,
{
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        let now = self.clock.now_millis();
        let mut state = self.state.lock().map_err(|_| DenialCode::ScopeDenied)?;
        reconcile_expiry(&mut state, now);
        let epoch = evaluate(&self.policy, &state, request, now)?;
        let expected_proof = scope_proof(epoch.binding_digest, request);
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
            scope_binding_digest: request.scope_binding_digest(),
            target: request.target,
            action_kind: request.action_kind,
            action_class: request.action_class,
            required_features: request.required_features.clone(),
        })
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

fn is_special_address(address: IpAddr) -> bool {
    match canonical_ip(address) {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            value >> 24 == 0
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || value >> 22 == u32::from(Ipv4Addr::new(100, 64, 0, 0)) >> 22
                || value >> 8 == u32::from(Ipv4Addr::new(192, 0, 0, 0)) >> 8
                || value >> 8 == u32::from(Ipv4Addr::new(192, 0, 2, 0)) >> 8
                || value >> 17 == u32::from(Ipv4Addr::new(198, 18, 0, 0)) >> 17
                || value >= u32::from(Ipv4Addr::new(240, 0, 0, 0))
                || value >> 8 == u32::from(Ipv4Addr::new(198, 51, 100, 0)) >> 8
                || value >> 8 == u32::from(Ipv4Addr::new(203, 0, 113, 0)) >> 8
        }
        IpAddr::V6(address) => {
            let value = u128::from(address);
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || value >> 32 == 0
                || value >> 64 == u128::from(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0)) >> 64
                || value >> 121 == u128::from(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)) >> 121
                || value >> 118 == u128::from(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)) >> 118
                || value >> 118 == u128::from(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0)) >> 118
                || value >> 80 == u128::from(Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0)) >> 80
                || value >> 96 == u128::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)) >> 96
        }
    }
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

fn verified_epoch_binding(epoch: &VerifiedScopeEpoch) -> Digest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(b"faultloom-verified-scope-epoch-v1\0");
    bytes.extend_from_slice(epoch.envelope_digest.as_bytes());
    bytes.extend_from_slice(epoch.payload_digest.as_bytes());
    bytes.extend_from_slice(epoch.verifier_receipt_digest.as_bytes());
    bytes.extend_from_slice(&(epoch.grant_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(epoch.grant_id.as_bytes());
    bytes.extend_from_slice(&epoch.epoch.to_be_bytes());
    bytes.extend_from_slice(&epoch.issued_at_millis.to_be_bytes());
    bytes.extend_from_slice(&epoch.expires_at_millis.to_be_bytes());
    bytes.push(u8::from(epoch.revoked));
    bytes.extend_from_slice(&(epoch.key_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(epoch.key_id.as_bytes());
    Digest::of(&bytes)
}

fn reconcile_expiry(state: &mut ScopeState, now: u64) {
    let Some(epoch) = &state.current_epoch else {
        return;
    };
    if now >= epoch.expires_at_millis {
        let epoch_number = epoch.epoch;
        cancel_all(state, epoch_number, CancellationCause::EpochExpired);
    }
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::ipc::{ActionKind, RequiredFeature};

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
                "grant:owned".to_owned(),
                self.epoch,
                900,
                2_000,
                self.revoked,
                self.revoked.then(|| "operator revoke".to_owned()),
                "authority-key:1".to_owned(),
                self.epoch,
                envelope.digest(),
                Digest::of(b"signed-payload"),
                Digest::of(b"t13-verification-receipt"),
            ))
        }
    }

    #[derive(Clone)]
    struct SequenceVerifier {
        accepted: Vec<(Digest, u64, bool)>,
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
                "grant:owned".to_owned(),
                *epoch,
                900,
                2_000,
                *revoked,
                revoked.then(|| "operator revoke".to_owned()),
                "authority-key:1".to_owned(),
                *epoch,
                digest,
                Digest::of(b"signed-payload"),
                Digest::of(b"t13-verification-receipt"),
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
        DispatchRequest {
            action_id: "action:root".to_owned(),
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
            flow_kind: FlowKind::TopLevel,
            parent_action_id: None,
            required_features: vec![RequiredFeature::GatewayDispatchV1],
            hostname: "lab.example.test".to_owned(),
            protocol: "http".to_owned(),
            method: "GET".to_owned(),
            path: "/api/item".to_owned(),
            target: "127.0.0.1:8080".parse().unwrap(),
            payload: b"GET /api/item HTTP/1.1\r\n\r\n".to_vec(),
            scope_proof: vec![1],
            lease_proof: b"lease-proof".to_vec(),
            compiler_proof: b"compiler-proof".to_vec(),
            canary_ref: None,
            cleanup_plan_ref: None,
        }
    }

    fn make_kernel(
        verifier: FixtureVerifier,
        clock: FixedClock,
    ) -> DeterministicScopeKernel<FixtureVerifier, FixedClock> {
        DeterministicScopeKernel::new(policy(), verifier, clock).unwrap()
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
                    "grant:owned".to_owned(),
                    8,
                    900,
                    2_000,
                    false,
                    None,
                    "authority-key:1".to_owned(),
                    9,
                    envelope.digest(),
                    Digest::of(b"payload"),
                    Digest::ZERO,
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
        let kernel = DeterministicScopeKernel::new(policy(), verifier, clock).unwrap();
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
        let kernel = DeterministicScopeKernel::new(policy(), verifier, clock).unwrap();
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
