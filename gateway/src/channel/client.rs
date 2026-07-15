use super::*;

impl ChannelClient {
    pub fn new(
        key: [u8; 32],
        challenge: ChannelChallenge,
        session_id: String,
    ) -> Result<Self, DenialCode> {
        if !valid_secret(&key)
            || !valid_identifier(&session_id)
            || challenge.challenge_id == Digest::of(&key)
        {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        Ok(Self {
            key,
            challenge,
            session_id,
            state: Mutex::new(ClientState::default()),
        })
    }

    pub fn seal_request(
        &self,
        request_frame: Vec<u8>,
        nonce: [u8; 16],
        issued_at_millis: u64,
        expires_at_millis: u64,
    ) -> Result<AuthenticatedRequest, DenialCode> {
        if request_frame.is_empty()
            || request_frame.len() > MAX_FRAME_BYTES
            || !valid_nonce(&nonce)
            || issued_at_millis >= expires_at_millis
            || issued_at_millis < self.challenge.issued_at_millis
            || expires_at_millis > self.challenge.expires_at_millis
            || expires_at_millis.saturating_sub(issued_at_millis) > MAX_CHANNEL_TTL_MILLIS
        {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| DenialCode::IpcAuthenticationFailed)?;
        let sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or(DenialCode::IpcReplay)?;
        let mut request = AuthenticatedRequest {
            key_id: self.challenge.key_id.clone(),
            boot_id: self.challenge.boot_id.clone(),
            challenge_id: self.challenge.challenge_id,
            session_id: self.session_id.clone(),
            sequence,
            nonce,
            issued_at_millis,
            expires_at_millis,
            request_frame_digest: Digest::of(&request_frame),
            request_frame,
            authentication_tag: Digest::ZERO,
            envelope_id: Digest::ZERO,
        };
        request.authentication_tag = authenticate(
            &self.key,
            b"faultloom-channel-request-v1\0",
            &request.unsigned_bytes(),
        );
        request.envelope_id = Digest::of(&request.encode_internal());
        state.next_sequence = sequence;
        Ok(request)
    }

    pub fn verify_response(
        &self,
        request: &AuthenticatedRequest,
        response: AuthenticatedResponse,
        now_millis: u64,
    ) -> Result<Vec<u8>, DenialCode> {
        if !self.challenge.valid_at(now_millis) || response.expires_at_millis <= now_millis {
            return Err(DenialCode::IpcSessionExpired);
        }
        if response.key_id != self.challenge.key_id
            || response.boot_id != self.challenge.boot_id
            || response.challenge_id != self.challenge.challenge_id
            || response.session_id != self.session_id
            || response.sequence != request.sequence
            || response.request_envelope_id != request.envelope_id
            || response.request_frame_digest != request.request_frame_digest
            || !valid_nonce(&response.nonce)
            || response.issued_at_millis > now_millis
            || response.expires_at_millis > self.challenge.expires_at_millis
            || response.issued_at_millis >= response.expires_at_millis
            || response
                .expires_at_millis
                .saturating_sub(response.issued_at_millis)
                > MAX_CHANNEL_TTL_MILLIS
            || response.response_frame.is_empty()
            || response.response_frame_digest != Digest::of(&response.response_frame)
            || response.envelope_id != Digest::of(&response.encode_internal())
        {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let expected_tag = authenticate(
            &self.key,
            b"faultloom-channel-response-v1\0",
            &response.unsigned_bytes(),
        );
        if !constant_time_eq(
            expected_tag.as_bytes(),
            response.authentication_tag.as_bytes(),
        ) {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| DenialCode::IpcAuthenticationFailed)?;
        if !state.response_nonces.insert(response.nonce)
            || !state.response_envelopes.insert(response.envelope_id)
        {
            return Err(DenialCode::IpcReplay);
        }
        Ok(response.response_frame)
    }
}
