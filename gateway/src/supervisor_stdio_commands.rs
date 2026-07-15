use std::io::{self, Write};
use std::sync::Arc;

use crate::Digest;
use crate::channel::VerifiedRequest;
use crate::supervisor_durable::{DurableReconciliationError, ReconciliationAdmission};
use crate::supervisor_protocol::SupervisorCommand;

use super::processing::RuntimeIo;
use super::response::{denied, seal_and_write, send_response};
use super::workers::{ReconciliationGuard, ScopedWorker, WorkerAdmission, join_all};
use super::{SupervisorStageError, terminate_process};

pub(super) fn handle_command<'scope, W>(
    state: &RuntimeIo<W>,
    scope: &'scope std::thread::Scope<'scope, '_>,
    workers: &mut Vec<ScopedWorker<'scope>>,
    request: VerifiedRequest,
    command_digest: Digest,
    command: SupervisorCommand,
) -> Result<(), SupervisorStageError>
where
    W: Write + Send + 'scope,
{
    match command {
        SupervisorCommand::Dispatch(dispatch) => {
            let action_id = dispatch.action_id.clone();
            let response_slot = state
                .runtime
                .reserve_response(request.envelope_id())
                .map_err(SupervisorStageError::Persist)?;
            let preflighted = match state.runtime.preflight_dispatch(*dispatch, response_slot) {
                Ok(preflighted) => preflighted,
                Err(rejection) => {
                    let (slot, reason) = rejection.into_parts();
                    send_response(
                        &state.output,
                        &state.runtime,
                        slot,
                        &request,
                        denied(&action_id, command_digest, reason),
                    )?;
                    return Ok(());
                }
            };
            let admission = WorkerAdmission::new(
                Arc::clone(&state.active_workers),
                &state.worker_coordination,
                state.runtime.maximum_workers,
            );
            let (preflighted, permit) = match admission.after_preflight(preflighted) {
                Ok(admitted) => admitted,
                Err((preflighted, reason)) => {
                    send_response(
                        &state.output,
                        &state.runtime,
                        preflighted.into_response_slot(),
                        &request,
                        denied(&action_id, command_digest, reason),
                    )?;
                    return Ok(());
                }
            };
            let runtime = Arc::clone(&state.runtime);
            let output = Arc::clone(&state.output);
            workers.push(scope.spawn(move || {
                let _permit = permit;
                let dispatched = match runtime.dispatch(preflighted, command_digest) {
                    Ok(dispatched) => dispatched,
                    Err(_) => terminate_process(),
                };
                let (slot, response) = dispatched.into_parts();
                if send_response(&output, &runtime, slot, &request, response).is_err() {
                    terminate_process();
                }
            }));
        }
        SupervisorCommand::AdmitEpoch {
            canonical_envelope,
            verifier_receipt,
        } => {
            let slot = state
                .runtime
                .reserve_response(request.envelope_id())
                .map_err(SupervisorStageError::Persist)?;
            let response = state
                .runtime
                .admit_epoch(canonical_envelope, verifier_receipt)
                .unwrap_or_else(|reason| denied("scope-control", command_digest, reason));
            send_response(&state.output, &state.runtime, slot, &request, response)?;
        }
        SupervisorCommand::ReconcileExpiry => {
            let slot = state
                .runtime
                .reserve_response(request.envelope_id())
                .map_err(SupervisorStageError::Persist)?;
            let response = state
                .runtime
                .reconcile_expiry()
                .unwrap_or_else(|reason| denied("expiry-control", command_digest, reason));
            send_response(&state.output, &state.runtime, slot, &request, response)?;
        }
        SupervisorCommand::ReconcileHold(reconciliation) => {
            let reconciliation_guard = ReconciliationGuard::lock(&state.worker_coordination)?;
            join_all(workers)?;
            if state
                .runtime
                .has_pending_responses()
                .map_err(SupervisorStageError::Persist)?
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "pending worker response must be acknowledged before reconciliation",
                )
                .into());
            }
            let admission = reconciliation_guard
                .run_when_quiescent(&state.active_workers, || {
                    state
                        .runtime
                        .admit_reconciliation(request.envelope_id(), reconciliation.as_ref())
                })?
                .map_err(SupervisorStageError::Persist)?;
            let slot = match admission {
                ReconciliationAdmission::Ready(slot) => slot,
                ReconciliationAdmission::Rejected {
                    response_slot,
                    reason,
                } => {
                    send_response(
                        &state.output,
                        &state.runtime,
                        response_slot,
                        &request,
                        denied("reconciliation-control", command_digest, reason),
                    )?;
                    return Ok(());
                }
            };
            match state.runtime.reconcile_hold(slot, reconciliation.as_ref()) {
                Ok(response_frame) => seal_and_write(
                    &state.output,
                    &state.runtime.channel,
                    &request,
                    response_frame,
                )
                .map_err(SupervisorStageError::Output)?,
                Err(DurableReconciliationError::Rejected {
                    response_slot,
                    reason,
                }) => send_response(
                    &state.output,
                    &state.runtime,
                    response_slot,
                    &request,
                    denied("reconciliation-control", command_digest, reason),
                )?,
                Err(DurableReconciliationError::Terminal(error)) => {
                    return Err(SupervisorStageError::Persist(error));
                }
            }
        }
        SupervisorCommand::RecoverPendingResponse { .. } => {
            return Err(
                io::Error::new(io::ErrorKind::NotFound, "pending response not found").into(),
            );
        }
        SupervisorCommand::AcknowledgePendingResponse {
            original_request_id,
            response_digest,
        } => state
            .runtime
            .acknowledge_response(original_request_id, response_digest)
            .map_err(SupervisorStageError::Persist)?,
    }
    Ok(())
}
