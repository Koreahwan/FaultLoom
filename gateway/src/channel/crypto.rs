use super::*;

pub(super) fn valid_secret(value: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

pub(super) fn valid_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

pub(super) fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

pub(super) fn authenticate(key: &[u8], domain: &[u8], message: &[u8]) -> Digest {
    let mut canonical = Vec::with_capacity(domain.len() + message.len());
    canonical.extend_from_slice(domain);
    canonical.extend_from_slice(message);
    hmac_sha256(key, &canonical)
}

pub(super) fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
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
