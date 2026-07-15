use std::sync::Arc;

use crate::Digest;
use crate::authority::RequestedSelection;
use crate::channel::ChannelServer;
use crate::ipc::DenialCode;
use crate::kernel::{Gateway, SystemClock};
use crate::lease::{GrantBudget, LeaseAuthority};
use crate::scope::SignedEpochEnvelope;
use crate::semantic_http::SemanticHttpCompiler;
use crate::supervisor_durable::{DurablePreEgressBarrier, DurableSupervisorState};
use crate::supervisor_journal::JournalClient;
use crate::transport::TcpTargetTransport;

use super::installed_startup::{AuthorizedStartup, ProductionScope};
use super::supervisor_protocol::{
    ControlEgressDisposition, SupervisorControlReceipt, SupervisorResponse,
};

#[path = "supervisor_dispatch.rs"]
mod dispatch;
#[path = "supervisor_runtime_journal.rs"]
mod journal;

type ProductionGateway = Gateway<
    Arc<ProductionScope>,
    Arc<LeaseAuthority>,
    SemanticHttpCompiler,
    TcpTargetTransport,
    SystemClock,
    DurablePreEgressBarrier,
>;

pub(crate) struct SupervisorRuntime {
    pub(crate) channel: Arc<ChannelServer>,
    scope: Arc<ProductionScope>,
    lease: Arc<LeaseAuthority>,
    gateway: Arc<ProductionGateway>,
    selection: RequestedSelection,
    grant_id: String,
    grant_version: u64,
    budget: GrantBudget,
    compiler: SemanticHttpCompiler,
    durable: Arc<DurableSupervisorState>,
    pub(crate) maximum_workers: usize,
    _boot_replay: (u64, [u8; 16]),
}

impl SupervisorRuntime {
    pub(crate) fn attach(
        startup: AuthorizedStartup,
        journal: JournalClient,
    ) -> Result<Self, DenialCode> {
        let parts = startup.into_runtime_parts();
        let expected_anchor = (parts.expected_journal_anchor != Digest::ZERO)
            .then_some(parts.expected_journal_anchor);
        let (journal_anchor, journal_snapshot) = journal
            .open(expected_anchor)
            .map_err(|_| DenialCode::DurabilityAnchorMismatch)?;
        match DurableSupervisorState::recovery_checkpoint(&journal_snapshot)? {
            Some(checkpoint) => {
                parts
                    .lease
                    .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())?;
            }
            None if expected_anchor.is_none() => {
                parts.lease.register_grant(
                    &parts.grant_id,
                    parts.grant_version,
                    parts.budget.clone(),
                )?;
            }
            None => return Err(DenialCode::DurabilityAnchorMismatch),
        }
        let durable = Arc::new(DurableSupervisorState::new(
            Arc::clone(&parts.lease),
            journal,
            journal_anchor,
            journal_snapshot,
        )?);
        let gateway = Arc::new(Gateway::new_with_barrier(
            Arc::clone(&parts.scope),
            Arc::clone(&parts.lease),
            parts.compiler.clone(),
            TcpTargetTransport::new(),
            SystemClock,
            DurablePreEgressBarrier::new(Arc::clone(&durable)),
        ));
        Ok(Self {
            channel: parts.channel,
            scope: parts.scope,
            lease: parts.lease,
            gateway,
            selection: parts.selection,
            grant_id: parts.grant_id,
            grant_version: parts.grant_version,
            budget: parts.budget,
            compiler: parts.compiler,
            durable,
            maximum_workers: parts.maximum_workers,
            _boot_replay: parts.boot_replay,
        })
    }

    pub(crate) fn admit_epoch(
        &self,
        canonical_envelope: Vec<u8>,
        verifier_receipt: Vec<u8>,
    ) -> Result<SupervisorResponse, DenialCode> {
        let envelope =
            SignedEpochEnvelope::with_verifier_receipt(canonical_envelope, verifier_receipt)
                .map_err(super::supervisor_policy::map_epoch_error)?;
        let transition = self
            .scope
            .admit_epoch(&envelope)
            .map_err(super::supervisor_policy::map_epoch_error)?;
        let interrupted_resources = transition.interrupted_resources();
        Ok(SupervisorResponse::Control(
            SupervisorControlReceipt::EpochAdmitted {
                previous_epoch: transition.previous_epoch,
                current_epoch: transition.current_epoch,
                revoked: transition.revoked,
                interrupted_resources,
                egress_disposition: control_disposition(interrupted_resources),
            },
        ))
    }

    pub(crate) fn reconcile_expiry(&self) -> Result<SupervisorResponse, DenialCode> {
        let interrupted_resources = self.scope.reconcile_expiry_now()?;
        Ok(SupervisorResponse::Control(
            SupervisorControlReceipt::ExpiryReconciled {
                interrupted_resources,
                egress_disposition: control_disposition(interrupted_resources),
            },
        ))
    }

    pub(crate) fn shutdown_active(&self) -> Result<(), DenialCode> {
        match self
            .lease
            .interrupt_grant(&self.grant_id, self.grant_version)
        {
            Ok(_) | Err(DenialCode::LeaseRevoked) => Ok(()),
            Err(reason) => Err(reason),
        }
    }
}

fn control_disposition(interrupted_resources: u64) -> ControlEgressDisposition {
    if interrupted_resources == 0 {
        ControlEgressDisposition::NoActiveEgress
    } else {
        ControlEgressDisposition::TargetOutcomeUnknown
    }
}
