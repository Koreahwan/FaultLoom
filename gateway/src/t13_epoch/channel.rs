use crate::ipc::valid_identifier;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChannelTrustError {
    InvalidChannelKeyId,
    InvalidGatewayBootId,
    InvalidExpectedGrant,
    WeakChannelKey,
    WeakGatewayChallenge,
    ReusedBootMaterial,
}

pub(crate) struct GatewayBootBinding {
    id: String,
    challenge: [u8; 32],
}

impl GatewayBootBinding {
    pub(crate) fn new(id: String, challenge: [u8; 32]) -> Result<Self, ChannelTrustError> {
        if !valid_identifier(&id) {
            return Err(ChannelTrustError::InvalidGatewayBootId);
        }
        if !valid_secret(&challenge) {
            return Err(ChannelTrustError::WeakGatewayChallenge);
        }
        Ok(Self { id, challenge })
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
}

pub(crate) struct ReceiptAuthenticationChannel {
    key_id: String,
    key: [u8; 32],
    boot: GatewayBootBinding,
}

impl ReceiptAuthenticationChannel {
    pub(crate) fn new(
        key_id: String,
        key: [u8; 32],
        boot: GatewayBootBinding,
    ) -> Result<Self, ChannelTrustError> {
        if !valid_identifier(&key_id) {
            return Err(ChannelTrustError::InvalidChannelKeyId);
        }
        if !valid_secret(&key) {
            return Err(ChannelTrustError::WeakChannelKey);
        }
        if key == *boot.challenge() {
            return Err(ChannelTrustError::ReusedBootMaterial);
        }
        Ok(Self { key_id, key, boot })
    }

    pub(super) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(super) const fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub(super) const fn boot(&self) -> &GatewayBootBinding {
        &self.boot
    }
}

fn valid_secret(value: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(8).count() == 8
}
