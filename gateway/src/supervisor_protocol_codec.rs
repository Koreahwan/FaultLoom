mod command;
mod dispatch;
mod reconciliation;
mod response;

use crate::ipc::DenialCode;

use super::supervisor_protocol::{SupervisorCommand, SupervisorResponse};

const MAGIC: &[u8; 4] = b"FLSC";
const VERSION: u8 = 5;

pub(super) fn encode_command(command: &SupervisorCommand) -> Result<Vec<u8>, DenialCode> {
    command::encode_command(command)
}

pub(super) fn decode_command(encoded: &[u8]) -> Result<SupervisorCommand, DenialCode> {
    command::decode_command(encoded)
}

pub(super) fn encode_response(response: &SupervisorResponse) -> Result<Vec<u8>, DenialCode> {
    response::encode_response(response)
}

pub(super) fn decode_response(encoded: &[u8]) -> Result<SupervisorResponse, DenialCode> {
    response::decode_response(encoded)
}
