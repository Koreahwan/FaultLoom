use std::sync::{Arc, Barrier};
use std::thread;

use super::*;

mod replay_and_expiry;
mod round_trip;
mod sessions;

pub(super) const NOW: u64 = 10_000;

pub(super) fn key() -> [u8; 32] {
    std::array::from_fn(|index| u8::try_from(index + 1).expect("small key byte"))
}

pub(super) fn challenge(boot: &str) -> ChannelChallenge {
    ChannelChallenge::new(
        "channel-key:1".to_owned(),
        boot.to_owned(),
        *b"0123456789abcdef",
        NOW - 1,
        NOW + 60_000,
    )
    .expect("challenge")
}
