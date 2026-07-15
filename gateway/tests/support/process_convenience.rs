use std::sync::Arc;

use faultloom_gateway::Digest;
use faultloom_gateway::channel::{AuthenticatedRequest, AuthenticatedResponse};
use faultloom_gateway::supervisor_protocol::SupervisorResponse;

use crate::bootstrap_fixture::TestBootstrap;
use crate::journal::FakeJournal;
use crate::process::ProcessHarness;

impl ProcessHarness {
    pub fn spawn(bootstrap: &TestBootstrap) -> Self {
        let journal = Arc::new(
            FakeJournal::new(
                bootstrap.secrets.journal_key,
                bootstrap.durability_binding().expect("durability binding"),
            )
            .expect("create fake journal"),
        );
        Self::spawn_with_journal(bootstrap, journal)
    }

    pub fn decode_for_without_ack(
        &mut self,
        request: &AuthenticatedRequest,
        response: AuthenticatedResponse,
    ) -> (SupervisorResponse, Digest) {
        self.try_decode_for_without_ack(request, response)
            .expect("verify supervisor response without ACK")
    }

    pub fn finish_expecting_failure(self) {
        let observation = self.observe_failure();
        assert!(
            !observation.status.success(),
            "supervised gateway unexpectedly succeeded"
        );
        assert!(
            observation.stdout.is_empty(),
            "failed supervisor returned stdout bytes"
        );
        assert!(
            observation.stderr.is_empty(),
            "failed supervisor returned stderr bytes"
        );
    }
}
