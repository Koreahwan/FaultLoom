use std::io::{self, Write};

use crate::channel::VerifiedRequest;
use crate::supervisor_protocol::SupervisorCommand;

use super::SupervisorStageError;
use super::processing::RuntimeIo;
use super::response::seal_and_write;

pub(super) fn handle_if_pending(
    state: &RuntimeIo<impl Write>,
    request: &VerifiedRequest,
    command: &SupervisorCommand,
) -> Result<bool, SupervisorStageError> {
    if !state
        .runtime
        .has_pending_responses()
        .map_err(SupervisorStageError::Persist)?
    {
        return Ok(false);
    }
    match command {
        SupervisorCommand::RecoverPendingResponse {
            original_request_id,
        } => {
            let pending = state
                .runtime
                .pending_response(*original_request_id)
                .map_err(SupervisorStageError::Persist)?
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "pending response not found")
                })?;
            seal_and_write(
                &state.output,
                &state.runtime.channel,
                request,
                pending.inner_response,
            )
            .map_err(SupervisorStageError::Output)?;
        }
        SupervisorCommand::AcknowledgePendingResponse {
            original_request_id,
            response_digest,
        } => state
            .runtime
            .acknowledge_response(*original_request_id, *response_digest)
            .map_err(SupervisorStageError::Persist)?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pending response must be acknowledged",
            )
            .into());
        }
    }
    Ok(true)
}
