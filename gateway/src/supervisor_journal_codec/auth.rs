use crate::Digest;
use crate::ipc::DenialCode;

use super::super::supervisor_journal::MAX_JOURNAL_FRAME_BYTES;

pub(super) fn seal(
    mut unsigned: Vec<u8>,
    key: &[u8; 32],
    domain: &[u8],
) -> Result<Vec<u8>, DenialCode> {
    if weak_key(key) {
        return Err(DenialCode::IpcAuthenticationFailed);
    }
    let tag = hmac(key, domain, &unsigned);
    unsigned.extend_from_slice(tag.as_bytes());
    if unsigned.len() > MAX_JOURNAL_FRAME_BYTES {
        Err(DenialCode::InvalidRequest)
    } else {
        Ok(unsigned)
    }
}

pub(super) fn open<'a>(
    encoded: &'a [u8],
    key: &[u8; 32],
    domain: &[u8],
) -> Result<&'a [u8], DenialCode> {
    if weak_key(key) || encoded.len() <= 38 || encoded.len() > MAX_JOURNAL_FRAME_BYTES {
        return Err(DenialCode::IpcAuthenticationFailed);
    }
    let (unsigned, supplied) = encoded.split_at(encoded.len() - 32);
    if !constant_time_eq(hmac(key, domain, unsigned).as_bytes(), supplied) {
        return Err(DenialCode::IpcAuthenticationFailed);
    }
    Ok(unsigned)
}

fn hmac(key: &[u8; 32], domain: &[u8], message: &[u8]) -> Digest {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..32 {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Vec::with_capacity(64 + domain.len() + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(domain);
    inner.extend_from_slice(message);
    let inner_digest = Digest::of(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(inner_digest.as_bytes());
    Digest::of(&outer)
}

pub(super) fn domain_digest(domain: &[u8], value: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(domain.len() + value.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(value);
    Digest::of(&bytes)
}

fn weak_key(key: &[u8; 32]) -> bool {
    key.iter().all(|byte| *byte == key[0])
}

fn constant_time_eq(expected: &[u8; 32], supplied: &[u8]) -> bool {
    supplied.len() == 32
        && expected
            .iter()
            .zip(supplied)
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
