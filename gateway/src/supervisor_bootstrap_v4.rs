use crate::Digest;
use crate::authority::RequestedSelection;
use crate::channel::{ChannelChallenge, ChannelServer};
use crate::ipc::{DenialCode, valid_identifier};

pub(crate) const MAX_SIGNED_AUTHORITY_GRANT_BYTES: usize = 48 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SupervisorSecretsV4 {
    pub(crate) channel_key_id: String,
    pub(crate) channel_key: [u8; 32],
    pub(crate) channel_boot_id: String,
    pub(crate) channel_nonce: [u8; 16],
    pub(crate) channel_issued_at_millis: u64,
    pub(crate) channel_expires_at_millis: u64,
    pub(crate) epoch_channel_key_id: String,
    pub(crate) epoch_channel_key: [u8; 32],
    pub(crate) gateway_boot_id: String,
    pub(crate) gateway_challenge: [u8; 32],
    pub(crate) lease_key_id: String,
    pub(crate) lease_key: [u8; 32],
    pub(crate) compiler_key_id: String,
    pub(crate) compiler_key: [u8; 32],
    pub(crate) journal_key_id: String,
    pub(crate) journal_key: [u8; 32],
    pub(crate) reconciliation_key_id: String,
    pub(crate) reconciliation_verification_key: [u8; 32],
}

impl SupervisorSecretsV4 {
    pub(super) fn channel_challenge(&self) -> Result<ChannelChallenge, DenialCode> {
        ChannelChallenge::new(
            self.channel_key_id.clone(),
            self.channel_boot_id.clone(),
            self.channel_nonce,
            self.channel_issued_at_millis,
            self.channel_expires_at_millis,
        )
    }

    pub(crate) fn channel_server(&self) -> Result<ChannelServer, DenialCode> {
        let challenge = self.channel_challenge()?;
        let session_id = format!(
            "supervisor:channel:v1:{}",
            challenge.challenge_id().to_hex()
        );
        ChannelServer::new_pinned_session(self.channel_key, challenge, session_id)
    }

    pub(crate) fn validate_separation(&self) -> Result<(), DenialCode> {
        self.channel_challenge()?;
        if !valid_identifier(&self.gateway_boot_id) {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let keys = [
            self.channel_key,
            self.epoch_channel_key,
            self.lease_key,
            self.compiler_key,
            self.journal_key,
            self.reconciliation_verification_key,
            self.gateway_challenge,
        ];
        if keys
            .iter()
            .enumerate()
            .any(|(index, key)| !valid_secret(key) || keys[index + 1..].contains(key))
        {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let key_ids = [
            &self.channel_key_id,
            &self.epoch_channel_key_id,
            &self.lease_key_id,
            &self.compiler_key_id,
            &self.journal_key_id,
            &self.reconciliation_key_id,
        ];
        if key_ids.iter().enumerate().any(|(index, key_id)| {
            !valid_identifier(key_id) || key_ids[index + 1..].contains(key_id)
        }) {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct BootAuthorization {
    pub(crate) controller_key_id: String,
    pub(crate) issued_at_millis: u64,
    pub(crate) expires_at_millis: u64,
    pub(crate) boot_sequence: u64,
    pub(crate) nonce: [u8; 16],
    pub(crate) signature: [u8; 64],
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct UnverifiedSupervisorBootstrapV4 {
    pub(crate) signed_authority_grant: Vec<u8>,
    pub(crate) selection: RequestedSelection,
    pub(crate) secrets: SupervisorSecretsV4,
    pub(crate) expected_journal_anchor: Digest,
    pub(crate) boot_authorization: BootAuthorization,
}

impl UnverifiedSupervisorBootstrapV4 {
    pub(crate) fn from_bytes(encoded: &[u8]) -> Result<Self, DenialCode> {
        super::supervisor_bootstrap_v4_codec::decode(encoded)
    }

    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, DenialCode> {
        super::supervisor_bootstrap_v4_codec::encode(self)
    }
}

fn valid_secret(value: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

#[cfg(test)]
#[path = "supervisor_bootstrap_v4_codec_tests.rs"]
mod codec_tests;
