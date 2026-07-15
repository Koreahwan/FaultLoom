use faultloom_gateway::channel::{AuthenticatedRequest, AuthenticatedResponse};
use faultloom_gateway::ipc::DenialCode;
use faultloom_gateway::supervisor_protocol::SupervisorResponse;

use crate::process::ProcessHarness;

impl ProcessHarness {
    pub fn try_decode_for(
        &mut self,
        request: &AuthenticatedRequest,
        response: AuthenticatedResponse,
    ) -> Result<SupervisorResponse, DenialCode> {
        let (response, digest) = self.try_decode_for_without_ack(request, response)?;
        self.acknowledge_response(request.envelope_id(), digest);
        Ok(response)
    }
}
