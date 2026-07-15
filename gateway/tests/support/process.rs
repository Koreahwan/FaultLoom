use std::io::Write;
use std::process::{Child, ChildStdin, ChildStdout, ExitStatus};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use faultloom_gateway::Digest;
use faultloom_gateway::channel::{AuthenticatedRequest, AuthenticatedResponse, ChannelClient};
use faultloom_gateway::ipc::{DenialCode, read_frame, write_frame};
use faultloom_gateway::supervisor_protocol::{SupervisorCommand, SupervisorResponse};

use crate::bootstrap_fixture::TestBootstrap;
use crate::journal::{FakeJournal, JournalGuards};

#[path = "process/fixture.rs"]
mod fixture;
#[path = "process/lifecycle.rs"]
mod lifecycle;
#[path = "process/sandbox.rs"]
mod sandbox;

pub use fixture::{bootstrap, nonce, now_millis};
pub use sandbox::LaunchOptions;

const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct FailureObservation {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub struct ProcessHarness {
    pub(super) child: Child,
    pub(super) input: Option<ChildStdin>,
    output: ChildStdout,
    client: ChannelClient,
    fixture_root: std::path::PathBuf,
    pub(crate) journal: Arc<FakeJournal>,
    pub(super) journal_guards: Option<JournalGuards>,
    pub(super) journal_worker: Option<JoinHandle<std::io::Result<()>>>,
}

impl ProcessHarness {
    pub fn spawn_with_journal(bootstrap: &TestBootstrap, journal: Arc<FakeJournal>) -> Self {
        Self::spawn_configured(bootstrap, journal, LaunchOptions::default())
    }

    pub fn spawn_configured(
        bootstrap: &TestBootstrap,
        journal: Arc<FakeJournal>,
        launch: LaunchOptions,
    ) -> Self {
        let executable = sandbox::exact_executable().expect("exact Cargo gateway binary");
        let executable_bytes = std::fs::read(&executable).expect("read exact gateway binary");
        let bootstrap_bytes = launch.bootstrap_bytes.clone().unwrap_or_else(|| {
            bootstrap
                .encode_for_fd3(Digest::of(&executable_bytes))
                .expect("encode signed FLBS v4 bootstrap")
        });
        let trust_bytes = launch
            .trust_bytes
            .clone()
            .unwrap_or_else(|| bootstrap.trust_document());
        let session = launch
            .journal_descriptors
            .then(|| journal.start_session().expect("start fake journal session"));
        let journal_paths = session
            .as_ref()
            .map(|(request, reply, _, _)| (request.clone(), reply.clone()));
        let sandbox = sandbox::spawn(sandbox::SandboxSpec {
            executable,
            bootstrap_bytes,
            trust_bytes,
            trust_permissions: launch.trust_permissions,
            journal_paths,
        });
        let (journal_guards, journal_worker) = match session {
            Some((_, _, guards, worker)) => (Some(guards), Some(worker)),
            None => (None, None),
        };
        let sandbox = match sandbox {
            Ok(process) => process,
            Err(error) => {
                drop(journal_guards);
                if let Some(worker) = journal_worker {
                    let _ = worker.join();
                }
                panic!("spawn isolated supervised gateway: {error}");
            }
        };
        let mut child = sandbox.child;
        let input = child.stdin.take().expect("gateway stdin");
        let output = child.stdout.take().expect("gateway stdout");
        Self {
            child,
            input: Some(input),
            output,
            client: bootstrap.channel_client().expect("channel client"),
            fixture_root: sandbox.fixture_root,
            journal,
            journal_guards,
            journal_worker,
        }
    }

    pub fn journal(&self) -> Arc<FakeJournal> {
        Arc::clone(&self.journal)
    }

    pub fn send(&mut self, command: SupervisorCommand, seed: u8) -> AuthenticatedRequest {
        let now = now_millis();
        let request = self
            .client
            .seal_request(
                command.to_bytes().expect("encode command"),
                nonce(seed),
                now,
                now + 20_000,
            )
            .expect("seal supervisor command");
        self.write_raw_request(&request);
        request
    }

    pub fn write_raw_request(&mut self, request: &AuthenticatedRequest) {
        let input = self.input.as_mut().expect("open gateway stdin");
        write_frame(&mut *input, &request.as_bytes()).expect("write supervisor command");
        input.flush().expect("flush supervisor command");
    }

    pub fn read_outer(&mut self) -> AuthenticatedResponse {
        let encoded = read_frame(&mut self.output)
            .expect("read supervisor response")
            .expect("supervisor response frame");
        AuthenticatedResponse::from_bytes(&encoded).expect("authenticated response envelope")
    }

    pub fn decode_for(
        &mut self,
        request: &AuthenticatedRequest,
        response: AuthenticatedResponse,
    ) -> SupervisorResponse {
        let (response, digest) = self
            .try_decode_for_without_ack(request, response)
            .expect("verify supervisor response");
        self.acknowledge_response(request.envelope_id(), digest);
        response
    }

    pub(crate) fn try_decode_for_without_ack(
        &mut self,
        request: &AuthenticatedRequest,
        response: AuthenticatedResponse,
    ) -> Result<(SupervisorResponse, Digest), DenialCode> {
        let inner = self
            .client
            .verify_response(request, response, now_millis())?;
        let digest = Digest::of(&inner);
        Ok((SupervisorResponse::from_bytes(&inner)?, digest))
    }

    pub fn round_trip(&mut self, command: SupervisorCommand, seed: u8) -> SupervisorResponse {
        let request = self.send(command, seed);
        let response = self.read_outer();
        self.decode_for(&request, response)
    }

    pub fn close_input(&mut self) {
        drop(self.input.take());
    }

    pub fn acknowledge_response(&mut self, request_id: Digest, response_digest: Digest) {
        if self.input.is_none() {
            return;
        }
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(b"faultloom-test-response-ack-nonce-v1\0");
        material.extend_from_slice(request_id.as_bytes());
        material.extend_from_slice(response_digest.as_bytes());
        let digest = Digest::of(&material);
        let mut ack_nonce = [0_u8; 16];
        ack_nonce.copy_from_slice(&digest.as_bytes()[..16]);
        self.send_authenticated(
            SupervisorCommand::AcknowledgePendingResponse {
                original_request_id: request_id,
                response_digest,
            },
            ack_nonce,
        );
    }

    fn send_authenticated(&mut self, command: SupervisorCommand, request_nonce: [u8; 16]) {
        let now = now_millis();
        let request = self
            .client
            .seal_request(
                command.to_bytes().expect("encode command"),
                request_nonce,
                now,
                now + 20_000,
            )
            .expect("seal supervisor command");
        self.write_raw_request(&request);
    }
}
