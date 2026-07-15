use super::*;

impl ChannelServer {
    pub fn new(key: [u8; 32], challenge: ChannelChallenge) -> Result<Self, DenialCode> {
        if !valid_secret(&key) || challenge.challenge_id == Digest::of(&key) {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        Ok(Self {
            key,
            challenge,
            expected_session_id: None,
            replay: Mutex::new(ServerReplayState::default()),
        })
    }

    pub(crate) fn new_pinned_session(
        key: [u8; 32],
        challenge: ChannelChallenge,
        expected_session_id: String,
    ) -> Result<Self, DenialCode> {
        if !valid_identifier(&expected_session_id) {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let mut server = Self::new(key, challenge)?;
        server.expected_session_id = Some(expected_session_id);
        Ok(server)
    }

    pub fn challenge(&self) -> &ChannelChallenge {
        &self.challenge
    }

    pub fn verify_request(
        &self,
        request: AuthenticatedRequest,
        now_millis: u64,
    ) -> Result<VerifiedRequest, DenialCode> {
        if !self.challenge.valid_at(now_millis) || request.expires_at_millis <= now_millis {
            return Err(DenialCode::IpcSessionExpired);
        }
        if request.key_id != self.challenge.key_id
            || request.boot_id != self.challenge.boot_id
            || request.challenge_id != self.challenge.challenge_id
            || !valid_identifier(&request.session_id)
            || self
                .expected_session_id
                .as_ref()
                .is_some_and(|expected| expected != &request.session_id)
            || request.sequence == 0
            || !valid_nonce(&request.nonce)
            || request.issued_at_millis > now_millis
            || request.expires_at_millis > self.challenge.expires_at_millis
            || request.issued_at_millis >= request.expires_at_millis
            || request
                .expires_at_millis
                .saturating_sub(request.issued_at_millis)
                > MAX_CHANNEL_TTL_MILLIS
            || request.request_frame.is_empty()
            || request.request_frame_digest != Digest::of(&request.request_frame)
            || request.envelope_id != Digest::of(&request.encode_internal())
        {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let expected_tag = authenticate(
            &self.key,
            b"faultloom-channel-request-v1\0",
            &request.unsigned_bytes(),
        );
        if !constant_time_eq(
            expected_tag.as_bytes(),
            request.authentication_tag.as_bytes(),
        ) {
            return Err(DenialCode::IpcAuthenticationFailed);
        }

        let mut replay = self
            .replay
            .lock()
            .map_err(|_| DenialCode::IpcAuthenticationFailed)?;
        let expected_sequence = replay
            .last_sequence
            .get(&request.session_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(DenialCode::IpcReplay)?;
        if request.sequence != expected_sequence
            || replay.nonces.contains(&request.nonce)
            || replay.envelopes.contains(&request.envelope_id)
        {
            return Err(DenialCode::IpcReplay);
        }
        replay
            .last_sequence
            .insert(request.session_id.clone(), request.sequence);
        replay.nonces.insert(request.nonce);
        replay.envelopes.insert(request.envelope_id);
        Ok(VerifiedRequest { request })
    }

    pub fn seal_response(
        &self,
        request: &VerifiedRequest,
        response_frame: Vec<u8>,
        nonce: [u8; 16],
        issued_at_millis: u64,
        expires_at_millis: u64,
    ) -> Result<AuthenticatedResponse, DenialCode> {
        if response_frame.is_empty()
            || response_frame.len() > MAX_FRAME_BYTES
            || !valid_nonce(&nonce)
            || issued_at_millis >= expires_at_millis
            || issued_at_millis < self.challenge.issued_at_millis
            || expires_at_millis > self.challenge.expires_at_millis
            || expires_at_millis.saturating_sub(issued_at_millis) > MAX_CHANNEL_TTL_MILLIS
        {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let mut response = AuthenticatedResponse {
            key_id: self.challenge.key_id.clone(),
            boot_id: self.challenge.boot_id.clone(),
            challenge_id: self.challenge.challenge_id,
            session_id: request.request.session_id.clone(),
            sequence: request.request.sequence,
            request_envelope_id: request.request.envelope_id,
            request_frame_digest: request.request.request_frame_digest,
            nonce,
            issued_at_millis,
            expires_at_millis,
            response_frame_digest: Digest::of(&response_frame),
            response_frame,
            authentication_tag: Digest::ZERO,
            envelope_id: Digest::ZERO,
        };
        response.authentication_tag = authenticate(
            &self.key,
            b"faultloom-channel-response-v1\0",
            &response.unsigned_bytes(),
        );
        response.envelope_id = Digest::of(&response.encode_internal());
        Ok(response)
    }
}
