use super::*;

impl AuthenticatedRequest {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, DenialCode> {
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(DenialCode::MalformedFrame);
        }
        let mut decoder = Decoder::new(encoded, REQUEST)?;
        let request = Self {
            key_id: decoder.string()?,
            boot_id: decoder.string()?,
            challenge_id: decoder.digest()?,
            session_id: decoder.string()?,
            sequence: decoder.u64()?,
            nonce: decoder.nonce()?,
            issued_at_millis: decoder.u64()?,
            expires_at_millis: decoder.u64()?,
            request_frame_digest: decoder.digest()?,
            request_frame: decoder.bytes(MAX_FRAME_BYTES)?,
            authentication_tag: decoder.digest()?,
            envelope_id: Digest::ZERO,
        };
        decoder.finish()?;
        let canonical = request.encode_internal();
        if canonical != encoded {
            return Err(DenialCode::MalformedFrame);
        }
        let envelope_id = Digest::of(&canonical);
        Ok(Self {
            envelope_id,
            ..request
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.encode_internal()
    }

    pub fn envelope_id(&self) -> Digest {
        self.envelope_id
    }

    pub fn request_frame_digest(&self) -> Digest {
        self.request_frame_digest
    }

    pub(super) fn unsigned_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(REQUEST);
        encoder.string(&self.key_id);
        encoder.string(&self.boot_id);
        encoder.digest(self.challenge_id);
        encoder.string(&self.session_id);
        encoder.u64(self.sequence);
        encoder.nonce(self.nonce);
        encoder.u64(self.issued_at_millis);
        encoder.u64(self.expires_at_millis);
        encoder.digest(self.request_frame_digest);
        encoder.bytes(&self.request_frame);
        encoder.bytes
    }

    pub(super) fn encode_internal(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_bytes();
        bytes.extend_from_slice(self.authentication_tag.as_bytes());
        bytes
    }
}

impl AuthenticatedResponse {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, DenialCode> {
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(DenialCode::MalformedFrame);
        }
        let mut decoder = Decoder::new(encoded, RESPONSE)?;
        let response = Self {
            key_id: decoder.string()?,
            boot_id: decoder.string()?,
            challenge_id: decoder.digest()?,
            session_id: decoder.string()?,
            sequence: decoder.u64()?,
            request_envelope_id: decoder.digest()?,
            request_frame_digest: decoder.digest()?,
            nonce: decoder.nonce()?,
            issued_at_millis: decoder.u64()?,
            expires_at_millis: decoder.u64()?,
            response_frame_digest: decoder.digest()?,
            response_frame: decoder.bytes(MAX_FRAME_BYTES)?,
            authentication_tag: decoder.digest()?,
            envelope_id: Digest::ZERO,
        };
        decoder.finish()?;
        let canonical = response.encode_internal();
        if canonical != encoded {
            return Err(DenialCode::MalformedFrame);
        }
        let envelope_id = Digest::of(&canonical);
        Ok(Self {
            envelope_id,
            ..response
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.encode_internal()
    }

    pub fn envelope_id(&self) -> Digest {
        self.envelope_id
    }

    pub(super) fn unsigned_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(RESPONSE);
        encoder.string(&self.key_id);
        encoder.string(&self.boot_id);
        encoder.digest(self.challenge_id);
        encoder.string(&self.session_id);
        encoder.u64(self.sequence);
        encoder.digest(self.request_envelope_id);
        encoder.digest(self.request_frame_digest);
        encoder.nonce(self.nonce);
        encoder.u64(self.issued_at_millis);
        encoder.u64(self.expires_at_millis);
        encoder.digest(self.response_frame_digest);
        encoder.bytes(&self.response_frame);
        encoder.bytes
    }

    pub(super) fn encode_internal(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_bytes();
        bytes.extend_from_slice(self.authentication_tag.as_bytes());
        bytes
    }
}

impl VerifiedRequest {
    pub fn request_frame(&self) -> &[u8] {
        &self.request.request_frame
    }

    pub fn request_frame_digest(&self) -> Digest {
        self.request.request_frame_digest
    }

    pub fn envelope_id(&self) -> Digest {
        self.request.envelope_id
    }
}
