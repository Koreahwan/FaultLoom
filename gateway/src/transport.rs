use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use crate::ipc::DispatchOutcome;
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

pub(crate) trait TargetTransport {
    fn dispatch(&self, action: &CompiledAction) -> TransportObservation;
}

pub(crate) struct TcpTargetTransport;

impl TcpTargetTransport {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl TargetTransport for TcpTargetTransport {
    fn dispatch(&self, action: &CompiledAction) -> TransportObservation {
        let mut stream = match TcpStream::connect_timeout(&action.target, CONNECT_TIMEOUT) {
            Ok(stream) => stream,
            Err(_) => return failed(Vec::new(), 0),
        };
        if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            return failed(Vec::new(), 0);
        }

        let mut bytes_sent = 0usize;
        while bytes_sent < action.bytes.len() {
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
