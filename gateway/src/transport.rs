use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ipc::{DenialCode, DispatchOutcome};
use crate::policy::CompiledAction;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_BYTES: usize = 65_536;

#[derive(Debug)]
pub(crate) struct TransportObservation {
    pub(crate) outcome: DispatchOutcome,
    pub(crate) bytes_sent: u64,
    pub(crate) response: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct DispatchCancellation {
    state: Arc<Mutex<CancellationState>>,
}

#[derive(Debug)]
struct CancellationState {
    cancelled: bool,
    stream: Option<TcpStream>,
}

impl DispatchCancellation {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CancellationState {
                cancelled: false,
                stream: None,
            })),
        }
    }

    pub(crate) fn cancel(&self) -> Result<bool, DenialCode> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cancelled = true;
        let Some(stream) = state.stream.as_ref() else {
            return Ok(false);
        };
        stream
            .shutdown(Shutdown::Both)
            .map_err(|_| DenialCode::LeaseAccountingUnavailable)?;
        state.stream = None;
        Ok(true)
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancelled
    }

    fn connect(&self, target: &std::net::SocketAddr) -> Result<TcpStream, ()> {
        // One lock makes connect/register atomic against completed cancellation.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.cancelled {
            return Err(());
        }
        let stream = TcpStream::connect_timeout(target, CONNECT_TIMEOUT).map_err(|_| ())?;
        if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(());
        }
        let cancellation_stream = stream.try_clone().map_err(|_| {
            let _ = stream.shutdown(Shutdown::Both);
        })?;
        state.stream = Some(cancellation_stream);
        Ok(stream)
    }

    fn detach(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stream = None;
    }
}

impl PartialEq for DispatchCancellation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

impl Eq for DispatchCancellation {}

pub(crate) trait TargetTransport {
    fn dispatch(&self, action: &CompiledAction) -> TransportObservation;

    fn dispatch_cancellable(
        &self,
        action: &CompiledAction,
        cancellation: &DispatchCancellation,
    ) -> TransportObservation {
        if cancellation.is_cancelled() {
            return failed(Vec::new(), 0);
        }
        let observation = self.dispatch(action);
        if cancellation.is_cancelled() {
            after_cancellation(observation.response, observation.bytes_sent)
        } else {
            observation
        }
    }
}

pub(crate) struct TcpTargetTransport;

impl TcpTargetTransport {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl TargetTransport for TcpTargetTransport {
    fn dispatch(&self, action: &CompiledAction) -> TransportObservation {
        self.dispatch_cancellable(action, &DispatchCancellation::new())
    }

    fn dispatch_cancellable(
        &self,
        action: &CompiledAction,
        cancellation: &DispatchCancellation,
    ) -> TransportObservation {
        let mut stream = match cancellation.connect(&action.target) {
            Ok(stream) => stream,
            Err(_) => return failed(Vec::new(), 0),
        };
        let observation = dispatch_stream(&mut stream, action, cancellation);
        cancellation.detach();
        if cancellation.is_cancelled() {
            after_cancellation(observation.response, observation.bytes_sent)
        } else {
            observation
        }
    }
}

fn dispatch_stream(
    stream: &mut TcpStream,
    action: &CompiledAction,
    cancellation: &DispatchCancellation,
) -> TransportObservation {
    let mut bytes_sent = 0usize;
    while bytes_sent < action.bytes.len() {
        if cancellation.is_cancelled() {
            return after_send_failure(Vec::new(), bytes_sent);
        }
        match stream.write(&action.bytes[bytes_sent..]) {
            Ok(0) => return after_send_failure(Vec::new(), bytes_sent),
            Ok(count) => bytes_sent += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return after_send_failure(Vec::new(), bytes_sent),
        }
    }
    if stream.shutdown(Shutdown::Write).is_err() {
        return after_send_failure(Vec::new(), bytes_sent);
    }

    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        if cancellation.is_cancelled() {
            return after_send_failure(response, bytes_sent);
        }
        match stream.read(&mut buffer) {
            Ok(0) => {
                return TransportObservation {
                    outcome: DispatchOutcome::Completed,
                    bytes_sent: bytes_sent as u64,
                    response,
                };
            }
            Ok(count) => {
                if response.len().saturating_add(count) > MAX_RESPONSE_BYTES {
                    return after_send_failure(response, bytes_sent);
                }
                response.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return after_send_failure(response, bytes_sent),
        }
    }
}

fn failed(response: Vec<u8>, bytes_sent: usize) -> TransportObservation {
    TransportObservation {
        outcome: DispatchOutcome::Failed,
        bytes_sent: bytes_sent as u64,
        response,
    }
}

fn after_send_failure(response: Vec<u8>, bytes_sent: usize) -> TransportObservation {
    if bytes_sent == 0 {
        failed(response, bytes_sent)
    } else {
        TransportObservation {
            outcome: DispatchOutcome::UnknownOutcome,
            bytes_sent: bytes_sent as u64,
            response,
        }
    }
}

fn after_cancellation(response: Vec<u8>, bytes_sent: u64) -> TransportObservation {
    TransportObservation {
        outcome: if bytes_sent == 0 {
            DispatchOutcome::Failed
        } else {
            DispatchOutcome::UnknownOutcome
        },
        bytes_sent,
        response,
    }
}

#[cfg(test)]
mod cancellation_tests {
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use super::*;
    use crate::Digest;
    use crate::ipc::{ActionKind, EgressPlane};

    fn action(target: std::net::SocketAddr) -> CompiledAction {
        CompiledAction {
            intent_digest: Digest::of(b"transport cancellation intent"),
            action_kind: ActionKind::SemanticHttpV1,
            target,
            egress_plane: EgressPlane::TargetGateway,
            semantic_action_digest: Digest::of(b"transport cancellation semantics"),
            resolution_digest: Digest::of(b"transport cancellation resolution"),
            request_binding_digest: Digest::of(b"transport cancellation binding"),
            bytes: b"PING".to_vec(),
        }
    }

    #[test]
    fn cancellation_before_dispatch_never_opens_a_target_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let cancellation = DispatchCancellation::new();
        assert_eq!(
            cancellation.cancel(),
            Ok(false),
            "no stream existed before cancellation"
        );

        let observation = TcpTargetTransport::new().dispatch_cancellable(
            &action(listener.local_addr().expect("listener address")),
            &cancellation,
        );
        assert_eq!(observation.outcome, DispatchOutcome::Failed);
        assert_eq!(observation.bytes_sent, 0);
        assert_eq!(
            listener
                .accept()
                .expect_err("cancelled dispatch cannot connect")
                .kind(),
            ErrorKind::WouldBlock
        );
    }

    #[test]
    fn cancellation_physically_interrupts_an_in_flight_stream_exactly_once() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
        let target = listener.local_addr().expect("listener address");
        let (request_read_tx, request_read_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("transport connection");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).expect("request bytes");
            assert_eq!(&request, b"PING");
            request_read_tx.send(()).expect("request-read signal");
            release_rx.recv().expect("release server connection");
            drop(stream);
        });

        let cancellation = DispatchCancellation::new();
        let worker_cancellation = cancellation.clone();
        let worker = thread::spawn(move || {
            TcpTargetTransport::new().dispatch_cancellable(&action(target), &worker_cancellation)
        });
        request_read_rx.recv().expect("target observed request");
        assert_eq!(
            cancellation.cancel(),
            Ok(true),
            "cancellation must shut down the registered live stream"
        );
        assert_eq!(
            cancellation.cancel(),
            Ok(false),
            "repeated cancellation cannot report a second physical interruption"
        );
        let observation = worker.join().expect("transport worker");
        assert_eq!(observation.outcome, DispatchOutcome::UnknownOutcome);
        assert_eq!(observation.bytes_sent, 4);
        release_tx.send(()).expect("release server");
        server.join().expect("server worker");
    }
}
