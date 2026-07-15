use super::*;

impl ChannelChallenge {
    pub fn new(
        key_id: String,
        boot_id: String,
        nonce: [u8; 16],
        issued_at_millis: u64,
        expires_at_millis: u64,
    ) -> Result<Self, DenialCode> {
        if !valid_identifier(&key_id)
            || !valid_identifier(&boot_id)
            || !valid_nonce(&nonce)
            || issued_at_millis >= expires_at_millis
        {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let mut challenge = Self {
            key_id,
            boot_id,
            nonce,
            issued_at_millis,
            expires_at_millis,
            challenge_id: Digest::ZERO,
        };
        challenge.challenge_id = challenge.canonical_id();
        Ok(challenge)
    }

    pub fn challenge_id(&self) -> Digest {
        self.challenge_id
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }

    fn canonical_id(&self) -> Digest {
        let mut bytes = Vec::with_capacity(160);
        bytes.extend_from_slice(b"faultloom-gateway-channel-challenge-v1\0");
        push_string(&mut bytes, &self.key_id);
        push_string(&mut bytes, &self.boot_id);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.issued_at_millis.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_millis.to_be_bytes());
        Digest::of(&bytes)
    }

    pub(super) fn valid_at(&self, now_millis: u64) -> bool {
        self.challenge_id == self.canonical_id()
            && now_millis >= self.issued_at_millis
            && now_millis < self.expires_at_millis
    }
}
