use std::sync::Arc;
use std::time::Duration;

use crate::Digest;
use crate::authority::{
    AuthorityVerifier, AuthorizedRunPolicy, RequestedSelection, authorize_selection,
};
use crate::boot_binding::{
    BootBindingContext, VerifiedBootAuthorization, verify_boot_authorization,
};
use crate::channel::ChannelServer;
use crate::installed_trust::InstalledTrustStore;
use crate::ipc::DenialCode;
use crate::lease::{GrantBudget, LeaseAuthority};
use crate::scope::{
    DeterministicScopeKernel, ExpectedScopeEpochGrant, GatewayBootBinding,
    ReceiptAuthenticationChannel, SystemScopeClock, T13EpochVerifierConfig,
    T13ReceiptEpochVerifier,
};
use crate::semantic_http::SemanticHttpCompiler;
use crate::supervisor_assembly::SupervisorRuntime;
use crate::supervisor_bootstrap_v4::{SupervisorSecretsV4, UnverifiedSupervisorBootstrapV4};
use crate::supervisor_journal::{JournalClient, MAX_DURABLE_RESPONSE_SLOTS};

#[path = "installed_startup_binding.rs"]
mod binding;
#[path = "installed_startup_io.rs"]
mod io_boundary;

pub(crate) use io_boundary::authorize_installed_startup;
#[cfg(test)]
use io_boundary::measure_running_executable;

const AUTHORITY_GRANT_CLOCK_SKEW_MILLIS: u64 = 300_000;

pub(crate) type ProductionScope =
    DeterministicScopeKernel<T13ReceiptEpochVerifier, SystemScopeClock>;

struct StableStartupIdentity {
    authority_key_id: String,
    grant_payload_digest: Digest,
    grant_id: String,
    grant_version: u64,
    selection_digest: Digest,
}

#[must_use]
pub(crate) struct AuthorizedStartup {
    stable: StableStartupIdentity,
    secrets: SupervisorSecretsV4,
    channel: Arc<ChannelServer>,
    scope: Arc<ProductionScope>,
    lease: Arc<LeaseAuthority>,
    compiler: SemanticHttpCompiler,
    selection: RequestedSelection,
    grant_id: String,
    grant_version: u64,
    budget: GrantBudget,
    expected_journal_anchor: Digest,
    maximum_workers: usize,
    verified_boot_authorization: VerifiedBootAuthorization,
}

pub(crate) struct AuthorizedRuntimeParts {
    pub(crate) channel: Arc<ChannelServer>,
    pub(crate) scope: Arc<ProductionScope>,
    pub(crate) lease: Arc<LeaseAuthority>,
    pub(crate) compiler: SemanticHttpCompiler,
    pub(crate) selection: RequestedSelection,
    pub(crate) grant_id: String,
    pub(crate) grant_version: u64,
    pub(crate) budget: GrantBudget,
    pub(crate) expected_journal_anchor: Digest,
    pub(crate) maximum_workers: usize,
    pub(crate) boot_replay: (u64, [u8; 16]),
}

pub(crate) fn authorize_loaded_startup(
    trust: InstalledTrustStore,
    unverified: UnverifiedSupervisorBootstrapV4,
    executable_digest: Digest,
    now_millis: u64,
) -> Result<AuthorizedStartup, DenialCode> {
    let trust = Arc::new(trust);
    let grant = AuthorityVerifier::verify(
        &unverified.signed_authority_grant,
        trust.as_ref(),
        now_millis,
        AUTHORITY_GRANT_CLOCK_SKEW_MILLIS,
    )
    .map_err(|_| DenialCode::IpcAuthenticationFailed)?;
    let policy: AuthorizedRunPolicy = authorize_selection(&grant, unverified.selection.clone())
        .map_err(|_| DenialCode::ScopeDenied)?;
    super::supervisor_install::validate_response_capacity(policy.budget())?;
    if policy.selection().protocol() != "http"
        || now_millis < unverified.secrets.channel_issued_at_millis
        || now_millis >= unverified.secrets.channel_expires_at_millis
    {
        return Err(DenialCode::IpcAuthenticationFailed);
    }
    unverified.secrets.validate_separation()?;

    let channel = Arc::new(unverified.secrets.channel_server()?);
    let lease = Arc::new(LeaseAuthority::new_with_reconciliation_verifier(
        unverified.secrets.lease_key_id.clone(),
        unverified.secrets.lease_key,
        unverified.secrets.gateway_boot_id.clone(),
        Digest::of(&unverified.secrets.gateway_challenge),
        unverified.secrets.reconciliation_key_id.clone(),
        unverified.secrets.reconciliation_verification_key,
    )?);
    let epoch_channel = ReceiptAuthenticationChannel::new(
        unverified.secrets.epoch_channel_key_id.clone(),
        unverified.secrets.epoch_channel_key,
        GatewayBootBinding::new(
            unverified.secrets.gateway_boot_id.clone(),
            unverified.secrets.gateway_challenge,
        )
        .map_err(|_| DenialCode::ScopeVerifierUnavailable)?,
    )
    .map_err(|_| DenialCode::ScopeVerifierUnavailable)?;
    let expected_grant = ExpectedScopeEpochGrant::new(
        policy.scope_policy().grant_id.clone(),
        policy.scope_policy().grant_version,
    )
    .map_err(|_| DenialCode::ScopeVerifierUnavailable)?;
    let epoch_verifier = T13ReceiptEpochVerifier::new(T13EpochVerifierConfig::new(
        epoch_channel,
        Arc::clone(&trust),
        expected_grant,
    ));
    let scope = Arc::new(
        DeterministicScopeKernel::new_with_cancellation_sink(
            policy.scope_policy().clone(),
            epoch_verifier,
            SystemScopeClock,
            Arc::clone(&lease) as Arc<dyn crate::scope::ScopeCancellationSink>,
        )
        .map_err(|_| DenialCode::ScopeDenied)?,
    );
    let compiler = SemanticHttpCompiler::new(
        unverified.secrets.compiler_key_id.clone(),
        unverified.secrets.compiler_key,
    )?;
    let maximum_workers = usize::try_from(policy.budget().max_concurrency)
        .unwrap_or(MAX_DURABLE_RESPONSE_SLOTS)
        .clamp(1, 16);

    let context = BootBindingContext {
        trust_generation: policy.trust_generation(),
        grant_envelope_digest: policy.signed_grant_digest(),
        grant_payload_digest: policy.authority_payload_digest(),
        grant_id: &policy.scope_policy().grant_id,
        grant_version: policy.scope_policy().grant_version,
        selection: policy.selection(),
        selection_digest: policy.selection().binding_digest(),
        secrets: &unverified.secrets,
        expected_journal_anchor: unverified.expected_journal_anchor,
        executable_digest,
    };
    let verified_boot_authorization = verify_boot_authorization(
        trust.as_ref(),
        &context,
        &unverified.boot_authorization,
        now_millis,
    )?;
    Ok(AuthorizedStartup {
        stable: StableStartupIdentity {
            authority_key_id: policy.authority_key_id().to_owned(),
            grant_payload_digest: policy.authority_payload_digest(),
            grant_id: policy.scope_policy().grant_id.clone(),
            grant_version: policy.scope_policy().grant_version,
            selection_digest: policy.selection().binding_digest(),
        },
        secrets: unverified.secrets,
        channel,
        scope,
        lease,
        compiler,
        selection: unverified.selection,
        grant_id: policy.scope_policy().grant_id.clone(),
        grant_version: policy.scope_policy().grant_version,
        budget: policy.budget().clone(),
        expected_journal_anchor: unverified.expected_journal_anchor,
        maximum_workers,
        verified_boot_authorization,
    })
}

impl AuthorizedStartup {
    pub(crate) fn attach(self) -> std::io::Result<SupervisorRuntime> {
        let stable_binding = self
            .durability_binding()
            .map_err(|reason| startup_error("invalid durability binding", reason))?;
        let journal_key = self.secrets.journal_key;
        let gateway_boot_id = self.secrets.gateway_boot_id.clone();
        let (journal_writer, journal_reader) =
            super::supervisor_journal_io::open_inherited_journal_channels()?;
        let journal = JournalClient::new(
            journal_reader,
            journal_writer,
            journal_key,
            gateway_boot_id,
            stable_binding,
            Duration::from_secs(5),
        )?;
        SupervisorRuntime::attach(self, journal)
            .map_err(|reason| startup_error("invalid authorized startup", reason))
    }

    pub(crate) fn into_runtime_parts(self) -> AuthorizedRuntimeParts {
        AuthorizedRuntimeParts {
            channel: self.channel,
            scope: self.scope,
            lease: self.lease,
            compiler: self.compiler,
            selection: self.selection,
            grant_id: self.grant_id,
            grant_version: self.grant_version,
            budget: self.budget,
            expected_journal_anchor: self.expected_journal_anchor,
            maximum_workers: self.maximum_workers,
            boot_replay: (
                self.verified_boot_authorization.boot_sequence(),
                self.verified_boot_authorization.nonce(),
            ),
        }
    }
}

fn startup_error(message: &'static str, reason: DenialCode) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("{message}: {reason:?}"),
    )
}

#[cfg(test)]
#[path = "installed_startup_tests.rs"]
mod tests;
