use std::time::{SystemTime, UNIX_EPOCH};

pub trait ScopeClock {
    fn now_millis(&self) -> u64;
}

pub struct SystemScopeClock;

impl ScopeClock for SystemScopeClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| value.as_millis().try_into().unwrap_or(u64::MAX))
    }
}
