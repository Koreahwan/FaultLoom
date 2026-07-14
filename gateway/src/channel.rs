use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::Digest;
use crate::ipc::{DenialCode, MAX_FRAME_BYTES, valid_identifier};

const MAGIC: &[u8; 4] = b"FLAC";
const VERSION: u8 = 1;
const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;
const HMAC_BLOCK_BYTES: usize = 64;
const MAX_CHANNEL_TTL_MILLIS: u64 = 30_000;
const MAX_ENVELOPE_BYTES: usize = MAX_FRAME_BYTES + 2_048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelChallenge {
    key_id: String,
    boot_id: String,
    nonce: [u8; 16],
    issued_at_millis: u64,
    expires_at_millis: u64,
    challenge_id: Digest,
}

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

    fn valid_at(&self, now_millis: u64) -> bool {
        self.challenge_id == self.canonical_id()
            && now_millis >= self.issued_at_millis
            && now_millis < self.expires_at_millis
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRequest {
    key_id: String,
    boot_id: String,
    challenge_id: Digest,
    session_id: String,
    sequence: u64,
    nonce: [u8; 16],
    issued_at_millis: u64,
    expires_at_millis: u64,
    request_frame_digest: Digest,
    request_frame: Vec<u8>,
    authentication_tag: Digest,
    envelope_id: Digest,
}

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

    fn unsigned_bytes(&self) -> Vec<u8> {
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

    fn encode_internal(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_bytes();
        bytes.extend_from_slice(self.authentication_tag.as_bytes());
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedResponse {
    key_id: String,
    boot_id: String,
    challenge_id: Digest,
    session_id: String,
    sequence: u64,
    request_envelope_id: Digest,
    request_frame_digest: Digest,
    nonce: [u8; 16],
    issued_at_millis: u64,
    expires_at_millis: u64,
    response_frame_digest: Digest,
    response_frame: Vec<u8>,
    authentication_tag: Digest,
    envelope_id: Digest,
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

    fn unsigned_bytes(&self) -> Vec<u8> {
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

    fn encode_internal(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_bytes();
        bytes.extend_from_slice(self.authentication_tag.as_bytes());
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRequest {
    request: AuthenticatedRequest,
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

#[derive(Default)]
struct ServerReplayState {
    last_sequence: HashMap<String, u64>,
    nonces: HashSet<[u8; 16]>,
    envelopes: HashSet<Digest>,
}

pub struct ChannelServer {
    key: [u8; 32],
    challenge: ChannelChallenge,
    replay: Mutex<ServerReplayState>,
}

impl ChannelServer {
    pub fn new(key: [u8; 32], challenge: ChannelChallenge) -> Result<Self, DenialCode> {
        if !valid_secret(&key) || challenge.challenge_id == Digest::of(&key) {
            return Err(DenialCode::IpcAuthenticationFailed);
        }
        Ok(Self {
            key,
            challenge,
            replay: Mutex::new(ServerReplayState::default()),
        })
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

#[derive(Default)]
struct ClientState {
    next_sequence: u64,
    response_nonces: HashSet<[u8; 16]>,
    response_envelopes: HashSet<Digest>,
}

pub struct ChannelClient {
    key: [u8; 32],
    challenge: ChannelChallenge,
    session_id: String,
    state: Mutex<ClientState>,
}

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

pub fn response_nonce(request_id: Digest, response_digest: Digest) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(b"faultloom-channel-response-nonce-v1\0");
    bytes.extend_from_slice(request_id.as_bytes());
    bytes.extend_from_slice(response_digest.as_bytes());
    let digest = Digest::of(&bytes);
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&digest.as_bytes()[..16]);
    nonce
}

fn valid_secret(value: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

fn valid_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn authenticate(key: &[u8], domain: &[u8], message: &[u8]) -> Digest {
    let mut canonical = Vec::with_capacity(domain.len() + message.len());
    canonical.extend_from_slice(domain);
    canonical.extend_from_slice(message);
    hmac_sha256(key, &canonical)
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Digest {
    let mut key_block = [0_u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        key_block[..32].copy_from_slice(Digest::of(key).as_bytes());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in key_block.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(HMAC_BLOCK_BYTES + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = Digest::of(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_BYTES + 32);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(inner_digest.as_bytes());
    Digest::of(&outer)
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new(message_type: u8) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(message_type);
        Self { bytes }
    }

    fn string(&mut self, value: &str) {
        push_string(&mut self.bytes, value);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn digest(&mut self, value: Digest) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn nonce(&mut self, value: [u8; 16]) {
        self.bytes.extend_from_slice(&value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.bytes.extend_from_slice(value);
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], expected_type: u8) -> Result<Self, DenialCode> {
        if bytes.len() < 6
            || &bytes[..4] != MAGIC
            || bytes[4] != VERSION
            || bytes[5] != expected_type
        {
            return Err(DenialCode::MalformedFrame);
        }
        Ok(Self { bytes, offset: 6 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DenialCode> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DenialCode::MalformedFrame)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DenialCode::MalformedFrame)?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, DenialCode> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, DenialCode> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }

    fn string(&mut self) -> Result<String, DenialCode> {
        let length = self.u32()? as usize;
        if length == 0 || length > 256 {
            return Err(DenialCode::MalformedFrame);
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| DenialCode::MalformedFrame)
    }

    fn digest(&mut self) -> Result<Digest, DenialCode> {
        Ok(Digest::from_bytes(
            self.take(32)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }

    fn nonce(&mut self) -> Result<[u8; 16], DenialCode> {
        self.take(16)?
            .try_into()
            .map_err(|_| DenialCode::MalformedFrame)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, DenialCode> {
        let length = self.u32()? as usize;
        if length == 0 || length > maximum {
            return Err(DenialCode::MalformedFrame);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finish(self) -> Result<(), DenialCode> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DenialCode::MalformedFrame)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    const NOW: u64 = 10_000;

    fn key() -> [u8; 32] {
        std::array::from_fn(|index| u8::try_from(index + 1).expect("small key byte"))
    }

    fn challenge(boot: &str) -> ChannelChallenge {
        ChannelChallenge::new(
            "channel-key:1".to_owned(),
            boot.to_owned(),
            *b"0123456789abcdef",
            NOW - 1,
            NOW + 60_000,
        )
        .expect("challenge")
    }

    #[test]
    fn exact_authenticated_request_and_response_round_trip() {
        let challenge = challenge("gateway:boot:one");
        let client =
            ChannelClient::new(key(), challenge.clone(), "session:one".to_owned()).expect("client");
        let server = ChannelServer::new(key(), challenge).expect("server");
        let request = client
            .seal_request(
                b"canonical request frame".to_vec(),
                *b"request-nonce-01",
                NOW,
                NOW + 1_000,
            )
            .expect("seal request");
        let decoded =
            AuthenticatedRequest::from_bytes(&request.as_bytes()).expect("decode request");
        assert_eq!(decoded, request);
        let verified = server.verify_request(decoded, NOW).expect("verify request");
        let response_bytes = b"canonical response frame".to_vec();
        let response = server
            .seal_response(
                &verified,
                response_bytes.clone(),
                *b"response-nonce01",
                NOW,
                NOW + 1_000,
            )
            .expect("seal response");
        let decoded =
            AuthenticatedResponse::from_bytes(&response.as_bytes()).expect("decode response");
        assert_eq!(
            client.verify_response(&request, decoded, NOW),
            Ok(response_bytes)
        );
    }

    #[test]
    fn tamper_wrong_key_stale_boot_and_replay_fail_closed() {
        let current_challenge = challenge("gateway:boot:current");
        let client = ChannelClient::new(key(), current_challenge.clone(), "session:one".to_owned())
            .expect("client");
        let server = ChannelServer::new(key(), current_challenge.clone()).expect("server");
        let request = client
            .seal_request(b"request".to_vec(), *b"request-nonce-01", NOW, NOW + 1_000)
            .expect("request");

        let mut tampered = request.as_bytes();
        let payload_offset = tampered.len() - 32 - b"request".len();
        tampered[payload_offset] ^= 1;
        let tampered =
            AuthenticatedRequest::from_bytes(&tampered).expect("canonical altered frame");
        assert_eq!(
            server.verify_request(tampered, NOW),
            Err(DenialCode::IpcAuthenticationFailed)
        );
        assert!(server.verify_request(request.clone(), NOW).is_ok());
        assert_eq!(
            server.verify_request(request, NOW),
            Err(DenialCode::IpcReplay)
        );

        let wrong_server = ChannelServer::new(
            std::array::from_fn(|index| u8::try_from(index + 65).expect("small key byte")),
            current_challenge,
        )
        .expect("wrong-key server");
        let second = client
            .seal_request(b"second".to_vec(), *b"request-nonce-02", NOW, NOW + 1_000)
            .expect("second request");
        assert_eq!(
            wrong_server.verify_request(second, NOW),
            Err(DenialCode::IpcAuthenticationFailed)
        );

        let stale_server =
            ChannelServer::new(key(), challenge("gateway:boot:old")).expect("old server");
        let current_client = ChannelClient::new(
            key(),
            challenge("gateway:boot:new"),
            "session:new".to_owned(),
        )
        .expect("new client");
        let current = current_client
            .seal_request(b"current".to_vec(), *b"request-nonce-03", NOW, NOW + 1_000)
            .expect("current request");
        assert_eq!(
            stale_server.verify_request(current, NOW),
            Err(DenialCode::IpcAuthenticationFailed)
        );
    }

    #[test]
    fn sequence_and_nonce_commit_atomically_under_concurrency() {
        let challenge = challenge("gateway:boot:concurrency");
        let client =
            ChannelClient::new(key(), challenge.clone(), "session:one".to_owned()).expect("client");
        let server = Arc::new(ChannelServer::new(key(), challenge).expect("server"));
        let request = client
            .seal_request(b"request".to_vec(), *b"request-nonce-01", NOW, NOW + 1_000)
            .expect("request");
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let server = Arc::clone(&server);
            let request = request.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                server.verify_request(request, NOW)
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DenialCode::IpcReplay)))
                .count(),
            1
        );
    }

    #[test]
    fn expired_request_and_expired_boot_challenge_are_distinct_typed_denials() {
        let current = challenge("gateway:boot:expiry");
        let client = ChannelClient::new(key(), current.clone(), "session:expiry".to_owned())
            .expect("client");
        let server = ChannelServer::new(key(), current).expect("server");
        let request = client
            .seal_request(
                b"expiring request".to_vec(),
                *b"request-expiry01",
                NOW,
                NOW + 1,
            )
            .expect("expiring request");
        assert_eq!(
            server.verify_request(request, NOW + 1),
            Err(DenialCode::IpcSessionExpired)
        );

        let expired_challenge = ChannelChallenge::new(
            "channel-key:expired".to_owned(),
            "gateway:boot:expired".to_owned(),
            *b"fedcba9876543210",
            NOW - 10,
            NOW - 1,
        )
        .expect("historical challenge shape");
        let expired_client = ChannelClient::new(
            key(),
            expired_challenge.clone(),
            "session:expired".to_owned(),
        )
        .expect("expired client shape");
        assert_eq!(
            expired_client.seal_request(b"request".to_vec(), *b"request-expiry02", NOW, NOW + 1,),
            Err(DenialCode::IpcAuthenticationFailed)
        );
    }
}
