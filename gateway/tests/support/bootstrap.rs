use std::net::SocketAddr;

use faultloom_gateway::Digest;
use faultloom_gateway::channel::{ChannelChallenge, ChannelClient};
use faultloom_gateway::ipc::{ActionClass, DenialCode};
use faultloom_gateway::lease::GrantBudget;
use faultloom_gateway::scope::TimeWindow;

#[path = "bootstrap/binding.rs"]
mod binding;
#[path = "bootstrap/grant.rs"]
mod grant;
#[path = "bootstrap/wire.rs"]
mod wire;

pub(crate) use grant::protocol_time;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct TestSecrets {
    pub(super) channel_key_id: String,
    pub(super) channel_key: [u8; 32],
    pub(super) channel_boot_id: String,
    pub(super) channel_nonce: [u8; 16],
    pub(super) channel_issued_at_millis: u64,
    pub(super) channel_expires_at_millis: u64,
    pub(super) epoch_channel_key_id: String,
    pub(super) epoch_channel_key: [u8; 32],
    pub(super) gateway_boot_id: String,
    pub(super) gateway_challenge: [u8; 32],
    pub(super) lease_key_id: String,
    pub(super) lease_key: [u8; 32],
    pub(super) compiler_key_id: String,
    pub(super) compiler_key: [u8; 32],
    pub(super) journal_key_id: String,
    pub(super) journal_key: [u8; 32],
    pub(super) reconciliation_key_id: String,
    pub(super) reconciliation_verification_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TestTarget {
    pub(super) target_id: String,
    pub(super) hostname: String,
    pub(super) socket: SocketAddr,
    pub(super) protocol: String,
    pub(super) pack_id: String,
    pub(super) action_family: String,
    pub(super) identity_id: String,
    pub(super) tenant_id: Option<String>,
    pub(super) methods: Vec<String>,
    pub(super) path_patterns: Vec<String>,
    pub(super) allowed_classes: Vec<ActionClass>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TestRoot {
    pub(super) seed: u8,
    pub(super) active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TestTrust {
    pub(super) generation: u64,
    pub(super) authority_roots: Vec<TestRoot>,
    pub(super) controller_roots: Vec<TestRoot>,
    pub(super) pinned_grant_id: String,
    pub(super) minimum_grant_version: u64,
    pub(super) pinned_authority_seeds: Vec<u8>,
    pub(super) pinned_controller_seeds: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TestBootAuthorization {
    pub(super) controller_seed: u8,
    pub(super) signing_seed: u8,
    pub(super) issued_at_millis: u64,
    pub(super) expires_at_millis: u64,
    pub(super) sequence: u64,
    pub(super) nonce: [u8; 16],
    pub(super) signed_executable_digest: Option<Digest>,
    pub(super) signed_anchor: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct TestBootstrap {
    pub(super) secrets: TestSecrets,
    pub(super) grant_id: String,
    pub(super) grant_version: u64,
    pub(super) grant_issued_at_millis: u64,
    pub(super) grant_signed_at_millis: u64,
    pub(super) authority_seed: u8,
    pub(super) granted_target: Option<TestTarget>,
    pub(super) target: TestTarget,
    pub(super) budget: GrantBudget,
    pub(super) execution_window: TimeWindow,
    pub(super) expected_journal_anchor: Digest,
    pub(super) trust: TestTrust,
    pub(super) boot: TestBootAuthorization,
}

impl TestBootstrap {
    pub(super) fn encode_for_fd3(&self, executable_digest: Digest) -> Result<Vec<u8>, DenialCode> {
        binding::encode_bootstrap(self, executable_digest)
    }

    pub(super) fn durability_binding(&self) -> Result<Digest, DenialCode> {
        binding::durability_binding(self)
    }

    pub(super) fn trust_document(&self) -> Vec<u8> {
        grant::trust_document(&self.trust)
    }

    pub(super) fn authority_signing_key(&self) -> [u8; 32] {
        grant::secret(self.authority_seed)
    }

    pub(super) fn channel_challenge(&self) -> Result<ChannelChallenge, DenialCode> {
        ChannelChallenge::new(
            self.secrets.channel_key_id.clone(),
            self.secrets.channel_boot_id.clone(),
            self.secrets.channel_nonce,
            self.secrets.channel_issued_at_millis,
            self.secrets.channel_expires_at_millis,
        )
    }

    pub(super) fn channel_client(&self) -> Result<ChannelClient, DenialCode> {
        let challenge = self.channel_challenge()?;
        let session_id = format!(
            "supervisor:channel:v1:{}",
            challenge.challenge_id().to_hex()
        );
        ChannelClient::new(self.secrets.channel_key, challenge, session_id)
    }
}

pub(super) fn test_key(seed: u8) -> [u8; 32] {
    grant::secret(seed)
}
