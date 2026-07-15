use std::io::{self, Read, Write};

use crate::channel::AuthenticatedRequest;
use crate::ipc::read_frame;
use crate::supervisor_protocol::SupervisorCommand;

use super::commands::handle_command;
use super::pending::handle_if_pending;
use super::processing::RuntimeIo;
use super::response::{denied, send_response};
use super::workers::{ScopedWorker, join_finished};
use super::{SupervisorStageError, supervisor_error};

pub(super) fn process_frames<'scope, R, W>(
    input: &mut R,
    state: &RuntimeIo<W>,
    scope: &'scope std::thread::Scope<'scope, '_>,
    workers: &mut Vec<ScopedWorker<'scope>>,
) -> Result<(), SupervisorStageError>
where
    R: Read,
    W: Write + Send + 'scope,
{
    while let Some(frame) = read_frame(input)? {
        join_finished(workers)?;
        let authenticated = AuthenticatedRequest::from_bytes(&frame)
            .map_err(|reason| supervisor_error("invalid authenticated frame", reason))?;
        let now = crate::system_now_millis()?;
        let verified = state
            .runtime
            .channel
            .verify_request(authenticated, now)
            .map_err(|reason| supervisor_error("request authentication failed", reason))?;
        let command_digest = verified.request_frame_digest();
        let command = match SupervisorCommand::from_bytes(verified.request_frame()) {
            Ok(command) => command,
            Err(reason) => {
                if state
                    .runtime
                    .has_pending_responses()
                    .map_err(SupervisorStageError::Persist)?
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pending response must be acknowledged",
                    )
                    .into());
                }
                let slot = state
                    .runtime
                    .reserve_response(verified.envelope_id())
                    .map_err(SupervisorStageError::Persist)?;
                send_response(
                    &state.output,
                    &state.runtime,
                    slot,
                    &verified,
                    denied("supervisor-control", command_digest, reason),
                )?;
                continue;
            }
        };
        if handle_if_pending(state, &verified, &command)? {
            continue;
        }
        handle_command(state, scope, workers, verified, command_digest, command)?;
    }
    Ok(())
}
