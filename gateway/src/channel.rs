use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::Digest;
use crate::ipc::{DenialCode, MAX_FRAME_BYTES, valid_identifier};
use codec::{Decoder, Encoder};
use crypto::{authenticate, constant_time_eq, push_string, valid_nonce, valid_secret};

#[path = "channel/codec.rs"]
mod codec;

#[path = "channel/crypto.rs"]
mod crypto;

#[path = "channel/challenge.rs"]
mod challenge;

#[path = "channel/envelope.rs"]
mod envelope;

#[path = "channel/server.rs"]
mod server;

#[path = "channel/client.rs"]
mod client;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRequest {
    request: AuthenticatedRequest,
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
    expected_session_id: Option<String>,
    replay: Mutex<ServerReplayState>,
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

#[cfg(test)]
#[path = "channel/tests/mod.rs"]
mod tests;
