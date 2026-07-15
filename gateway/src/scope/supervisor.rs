use std::sync::Arc;

use crate::ipc::DenialCode;

use super::{DeterministicScopeKernel, EpochVerifier, ScopeClock, ScopePolicy, ScopePolicyError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationCause {
    EpochAdvanced,
    ScopeRevoked,
    EpochExpired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeCancellation {
    pub grant_id: String,
    pub grant_version: u64,
    pub invalidated_through_epoch: u64,
    pub revoked_at_epoch: Option<u64>,
    pub cause: CancellationCause,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScopeCancellationReport {
    pub interrupted_active: u64,
}

pub trait ScopeCancellationSink: Send + Sync {
    fn cancel_scope(&self, cancellation: &ScopeCancellation) -> Result<(), DenialCode>;

    fn cancel_scope_with_report(
        &self,
        cancellation: &ScopeCancellation,
    ) -> Result<ScopeCancellationReport, DenialCode> {
        self.cancel_scope(cancellation)?;
        Ok(ScopeCancellationReport::default())
    }
}

impl<V, C> DeterministicScopeKernel<V, C>
where
    V: EpochVerifier,
    C: ScopeClock,
{
    pub fn new_with_cancellation_sink(
        policy: ScopePolicy,
        verifier: V,
        clock: C,
        cancellation_sink: Arc<dyn ScopeCancellationSink>,
    ) -> Result<Self, ScopePolicyError> {
        Self::build(policy, verifier, clock, Some(cancellation_sink))
    }

    pub(super) fn notify_cancellation(
        &self,
        cancellation: &ScopeCancellation,
    ) -> Result<ScopeCancellationReport, DenialCode> {
        if let Some(sink) = self.cancellation_sink.as_ref() {
            sink.cancel_scope_with_report(cancellation)
        } else {
            Ok(ScopeCancellationReport::default())
        }
    }
}
