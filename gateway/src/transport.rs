use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::policy::CompiledAction;
use crate::transport_outcome::{after_cancellation, after_send_failure, completed, failed};

mod cancellation;

use cancellation::ConnectFailure;
pub(crate) use cancellation::DispatchCancellation;

pub(crate) use crate::transport_outcome::{
    CancellationDisposition, DispatchLimits, TransportObservation,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_BYTES: usize = 65_536;

pub(crate) trait TargetTransport {
    fn dispatch_cancellable(
        &self,
        action: &CompiledAction,
        cancellation: &DispatchCancellation,
        limits: DispatchLimits,
    ) -> TransportObservation;
}

pub(crate) struct TcpTargetTransport;

impl TcpTargetTransport {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl TargetTransport for TcpTargetTransport {
    fn dispatch_cancellable(
        &self,
        action: &CompiledAction,
        cancellation: &DispatchCancellation,
        limits: DispatchLimits,
    ) -> TransportObservation {
        let Some(connect_timeout) = limits.deadline.checked_duration_since(Instant::now()) else {
            return failed(Vec::new(), 0);
        };
        if connect_timeout.is_zero() || limits.maximum_response_bytes == 0 {
            return failed(Vec::new(), 0);
        }
        let deadline = limits.deadline;
        let mut stream = match cancellation.connect(&action.target, connect_timeout) {
            Ok(stream) => stream,
            Err(ConnectFailure::Cancelled(disposition)) => {
                return after_cancellation(Vec::new(), 0, disposition);
            }
            Err(ConnectFailure::Failed) => return limit_reached(cancellation, Vec::new(), 0),
        };
        let observation = dispatch_stream(&mut stream, action, cancellation, deadline, limits);
        cancellation.detach();
        if let Some(disposition) = cancellation.disposition() {
            after_cancellation(observation.response, observation.bytes_sent, disposition)
        } else {
            observation
        }
    }
}

fn dispatch_stream(
    stream: &mut TcpStream,
    action: &CompiledAction,
    cancellation: &DispatchCancellation,
    deadline: Instant,
    limits: DispatchLimits,
) -> TransportObservation {
    let mut bytes_sent = 0usize;
    while bytes_sent < action.bytes.len() {
        if configure_timeout(stream, deadline, true).is_err() {
            return limit_reached(cancellation, Vec::new(), bytes_sent as u64);
        }
        let permit = match cancellation.begin_io() {
            Ok(permit) => permit,
            Err(disposition) => {
                return after_cancellation(Vec::new(), bytes_sent as u64, disposition);
            }
        };
        let write_result = stream.write(&action.bytes[bytes_sent..]);
        drop(permit);
        match write_result {
            Ok(0) => return after_send_failure(Vec::new(), bytes_sent),
            Ok(count) => bytes_sent += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if timeout_reached(&error, deadline) => {
                return limit_reached(cancellation, Vec::new(), bytes_sent as u64);
            }
            Err(_) => return after_send_failure(Vec::new(), bytes_sent),
        }
    }
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        if response.len() >= limits.maximum_response_bytes {
            return limit_reached(cancellation, response, bytes_sent as u64);
        }
        if configure_timeout(stream, deadline, false).is_err() {
            return limit_reached(cancellation, response, bytes_sent as u64);
        }
        let permit = match cancellation.begin_io() {
            Ok(permit) => permit,
            Err(disposition) => {
                return after_cancellation(response, bytes_sent as u64, disposition);
            }
        };
        let remaining_bytes = limits.maximum_response_bytes - response.len();
        let read_limit = buffer.len().min(remaining_bytes);
        let read_result = stream.read(&mut buffer[..read_limit]);
        drop(permit);
        match read_result {
            Ok(0) => return completed(response, bytes_sent),
            Ok(count) => {
                response.extend_from_slice(&buffer[..count]);
                if response.len() >= MAX_RESPONSE_BYTES {
                    return limit_reached(cancellation, response, bytes_sent as u64);
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if timeout_reached(&error, deadline) => {
                return limit_reached(cancellation, response, bytes_sent as u64);
            }
            Err(_) => return after_send_failure(response, bytes_sent),
        }
    }
}

fn configure_timeout(stream: &TcpStream, deadline: Instant, write: bool) -> Result<(), ()> {
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    if remaining.is_zero() {
        return Err(());
    }
    let timeout = remaining.min(IO_TIMEOUT);
    let result = if write {
        stream.set_write_timeout(Some(timeout))
    } else {
        stream.set_read_timeout(Some(timeout))
    };
    result.map_err(|_| ())
}

fn timeout_reached(error: &std::io::Error, deadline: Instant) -> bool {
    Instant::now() >= deadline
        || matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

fn limit_reached(
    cancellation: &DispatchCancellation,
    response: Vec<u8>,
    bytes_sent: u64,
) -> TransportObservation {
    let disposition = cancellation
        .cancel()
        .unwrap_or(CancellationDisposition::TargetOutcomeUnknown);
    after_cancellation(response, bytes_sent, disposition)
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod cancellation_tests;
