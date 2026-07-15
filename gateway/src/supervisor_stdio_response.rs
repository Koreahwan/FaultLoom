use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use crate::Digest;
use crate::channel::{ChannelServer, VerifiedRequest, response_nonce};
use crate::ipc::{DenialCode, DeniedResponse, GatewayResponse, write_frame};
use crate::supervisor_assembly::SupervisorRuntime;
use crate::supervisor_durable::ReservedResponseSlot;
use crate::supervisor_protocol::SupervisorResponse;

use super::{SupervisorStageError, supervisor_error};

pub(super) fn denied(
    action_id: &str,
    request_digest: Digest,
    reason: DenialCode,
) -> SupervisorResponse {
    SupervisorResponse::Gateway(Box::new(GatewayResponse::Denied(DeniedResponse::bound(
        action_id.to_owned(),
        request_digest,
        reason,
    ))))
}

pub(super) fn send_response(
    output: &Arc<Mutex<impl Write>>,
    runtime: &SupervisorRuntime,
    response_slot: ReservedResponseSlot,
    request: &VerifiedRequest,
    response: SupervisorResponse,
) -> Result<(), SupervisorStageError> {
    let completed_receipt = match &response {
        SupervisorResponse::Gateway(gateway) => match gateway.as_ref() {
            GatewayResponse::Receipt { receipt, .. } => Some(receipt),
            GatewayResponse::Denied(_) => None,
        },
        SupervisorResponse::Control(_) => None,
    };
    let response_frame = response.to_bytes().map_err(|reason| {
        SupervisorStageError::General(supervisor_error(
            "cannot encode supervisor response",
            reason,
        ))
    })?;
    runtime
        .persist_response(response_slot, completed_receipt, response_frame.clone())
        .map_err(SupervisorStageError::Persist)?;
    seal_and_write(output, &runtime.channel, request, response_frame)
        .map_err(SupervisorStageError::Output)
}

pub(super) fn seal_and_write(
    output: &Arc<Mutex<impl Write>>,
    channel: &ChannelServer,
    request: &VerifiedRequest,
    response_frame: Vec<u8>,
) -> io::Result<()> {
    let response_digest = Digest::of(&response_frame);
    let issued_at_millis = crate::system_now_millis()?;
    let expires_at_millis = issued_at_millis
        .saturating_add(30_000)
        .min(channel.challenge().expires_at_millis());
    let sealed = channel
        .seal_response(
            request,
            response_frame,
            response_nonce(request.envelope_id(), response_digest),
            issued_at_millis,
            expires_at_millis,
        )
        .map_err(|reason| supervisor_error("cannot seal supervisor response", reason))?;
    let mut output = output
        .lock()
        .map_err(|_| io::Error::other("supervisor output lock poisoned"))?;
    write_frame(&mut *output, &sealed.as_bytes())
}
