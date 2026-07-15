mod auth;
mod messages;
mod snapshot;
mod wire;

use crate::Digest;
use crate::ipc::DenialCode;

use self::auth::{domain_digest, open, seal};
use self::messages::{decode_denial, unsigned_reply, unsigned_request};
use self::snapshot::{decode_snapshot, encode_snapshot};
use self::wire::{Decoder, Encoder};
use super::supervisor_journal::{
    JournalOperation, JournalReply, JournalRequest, JournalResult, JournalSnapshot,
};

const MAGIC: &[u8; 4] = b"FLJR";
const VERSION: u8 = 3;
const REQUEST: u8 = 1;
const REPLY: u8 = 2;
const OPEN: u8 = 1;
const COMMIT: u8 = 2;
const OPENED: u8 = 1;
const COMMITTED: u8 = 2;
const DENIED: u8 = 3;
const MAX_ITEMS: usize = 64;

pub(super) fn encode_request(
    request: &JournalRequest,
    key: &[u8; 32],
) -> Result<Vec<u8>, DenialCode> {
    seal(
        unsigned_request(request)?,
        key,
        b"faultloom-journal-request-mac-v1\0",
    )
}

pub(super) fn decode_request(encoded: &[u8], key: &[u8; 32]) -> Result<JournalRequest, DenialCode> {
    let unsigned = open(encoded, key, b"faultloom-journal-request-mac-v1\0")?;
    let mut decoder = Decoder::new(unsigned, REQUEST)?;
    let request = JournalRequest {
        session_id: decoder.string()?,
        stable_binding: decoder.digest()?,
        sequence: decoder.u64()?,
        nonce: decoder.nonce()?,
        operation: match decoder.byte()? {
            OPEN => JournalOperation::Open {
                expected_anchor: decoder.optional_digest()?,
            },
            COMMIT => JournalOperation::Commit {
                previous_anchor: decoder.optional_digest()?,
                snapshot: decode_snapshot(&mut decoder)?,
            },
            _ => return Err(DenialCode::MalformedFrame),
        },
    };
    decoder.finish()?;
    if unsigned_request(&request)?.as_slice() != unsigned {
        return Err(DenialCode::MalformedFrame);
    }
    Ok(request)
}

pub(super) fn request_id(request: &JournalRequest) -> Result<Digest, DenialCode> {
    let unsigned = unsigned_request(request)?;
    Ok(domain_digest(
        b"faultloom-journal-request-id-v1\0",
        &unsigned,
    ))
}

pub(super) fn encode_reply(reply: &JournalReply, key: &[u8; 32]) -> Result<Vec<u8>, DenialCode> {
    seal(
        unsigned_reply(reply)?,
        key,
        b"faultloom-journal-reply-mac-v1\0",
    )
}

pub(super) fn decode_reply(encoded: &[u8], key: &[u8; 32]) -> Result<JournalReply, DenialCode> {
    let unsigned = open(encoded, key, b"faultloom-journal-reply-mac-v1\0")?;
    let mut decoder = Decoder::new(unsigned, REPLY)?;
    let reply = JournalReply {
        session_id: decoder.string()?,
        stable_binding: decoder.digest()?,
        sequence: decoder.u64()?,
        request_id: decoder.digest()?,
        result: match decoder.byte()? {
            OPENED => JournalResult::Opened {
                current_anchor: decoder.optional_digest()?,
                snapshot: if decoder.bool()? {
                    Some(decode_snapshot(&mut decoder)?)
                } else {
                    None
                },
            },
            COMMITTED => JournalResult::Committed {
                previous_anchor: decoder.optional_digest()?,
                current_anchor: decoder.digest()?,
                snapshot_digest: decoder.digest()?,
            },
            DENIED => JournalResult::Denied(decode_denial(decoder.byte()?)?),
            _ => return Err(DenialCode::MalformedFrame),
        },
    };
    decoder.finish()?;
    if unsigned_reply(&reply)?.as_slice() != unsigned {
        return Err(DenialCode::MalformedFrame);
    }
    Ok(reply)
}

pub(super) fn snapshot_digest(snapshot: &JournalSnapshot) -> Result<Digest, DenialCode> {
    let mut encoder = Encoder::plain();
    encode_snapshot(&mut encoder, snapshot)?;
    Ok(domain_digest(
        b"faultloom-journal-snapshot-v2\0",
        &encoder.finish()?,
    ))
}
