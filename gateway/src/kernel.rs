mod dispatch;
mod receipt;
#[cfg(test)]
mod tests;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::{
    ActionCompiler, LeaseVerifier, PreEgressBarrier, ScopeVerifier, UnavailablePreEgressBarrier,
};
use crate::transport::TargetTransport;

pub(crate) trait Clock {
    fn now_millis(&self) -> u64;
}

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

pub(crate) struct Gateway<S, L, C, T, K, B = UnavailablePreEgressBarrier> {
    scope: S,
    lease: L,
    compiler: C,
    transport: T,
    clock: K,
    barrier: B,
}

#[cfg(not(test))]
impl<S, L, C, T, K> Gateway<S, L, C, T, K, UnavailablePreEgressBarrier>
where
    S: ScopeVerifier,
    L: LeaseVerifier,
    C: ActionCompiler,
    T: TargetTransport,
    K: Clock,
{
    pub(crate) const fn new(scope: S, lease: L, compiler: C, transport: T, clock: K) -> Self {
        Self {
            scope,
            lease,
            compiler,
            transport,
            clock,
            barrier: UnavailablePreEgressBarrier,
        }
    }
}

#[cfg(test)]
impl<S, L, C, T, K> Gateway<S, L, C, T, K, crate::policy::TestPreEgressBarrier>
where
    S: ScopeVerifier,
    L: LeaseVerifier,
    C: ActionCompiler,
    T: TargetTransport,
    K: Clock,
{
    pub(crate) const fn new(scope: S, lease: L, compiler: C, transport: T, clock: K) -> Self {
        Self {
            scope,
            lease,
            compiler,
            transport,
            clock,
            barrier: crate::policy::TestPreEgressBarrier,
        }
    }
}

impl<S, L, C, T, K, B> Gateway<S, L, C, T, K, B>
where
    S: ScopeVerifier,
    L: LeaseVerifier,
    C: ActionCompiler,
    T: TargetTransport,
    K: Clock,
    B: PreEgressBarrier,
{
    pub(crate) const fn new_with_barrier(
        scope: S,
        lease: L,
        compiler: C,
        transport: T,
        clock: K,
        barrier: B,
    ) -> Self {
        Self {
            scope,
            lease,
            compiler,
            transport,
            clock,
            barrier,
        }
    }
}
