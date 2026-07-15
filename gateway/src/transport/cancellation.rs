use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::ipc::DenialCode;
use crate::transport_outcome::CancellationDisposition;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub(crate) struct DispatchCancellation {
    shared: Arc<CancellationShared>,
}

#[derive(Debug)]
struct CancellationState {
    disposition: Option<CancellationDisposition>,
    egress_started: bool,
    in_flight_io: u8,
    stream: Option<TcpStream>,
}

#[derive(Debug)]
struct CancellationShared {
    state: Mutex<CancellationState>,
    quiesced: Condvar,
}

pub(super) enum ConnectFailure {
    Cancelled(CancellationDisposition),
    Failed,
}

pub(super) struct IoPermit {
    shared: Arc<CancellationShared>,
}

impl Drop for IoPermit {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight_io = state.in_flight_io.saturating_sub(1);
        self.shared.quiesced.notify_all();
    }
}

impl DispatchCancellation {
    pub(crate) fn new() -> Self {
        Self {
            shared: Arc::new(CancellationShared {
                state: Mutex::new(CancellationState {
                    disposition: None,
                    egress_started: false,
                    in_flight_io: 0,
                    stream: None,
                }),
                quiesced: Condvar::new(),
            }),
        }
    }

    pub(crate) fn cancel(&self) -> Result<CancellationDisposition, DenialCode> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(disposition) = state.disposition {
            while state.in_flight_io != 0 {
                state = self
                    .shared
                    .quiesced
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            return Ok(disposition);
        }
        let disposition = if state.egress_started {
            CancellationDisposition::TargetOutcomeUnknown
        } else {
            CancellationDisposition::StableNoEgress
        };
        state.disposition = Some(disposition);
        if let Some(stream) = state.stream.as_ref()
            && stream.shutdown(Shutdown::Both).is_err()
        {
            state.disposition = Some(CancellationDisposition::TargetOutcomeUnknown);
        }
        state.stream = None;
        while state.in_flight_io != 0 {
            state = self
                .shared
                .quiesced
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        Ok(disposition)
    }

    pub(super) fn disposition(&self) -> Option<CancellationDisposition> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .disposition
    }

    pub(super) fn connect(
        &self,
        target: &std::net::SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, ConnectFailure> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(disposition) = state.disposition {
            return Err(ConnectFailure::Cancelled(disposition));
        }
        state.egress_started = true;
        let stream = TcpStream::connect_timeout(target, timeout.min(CONNECT_TIMEOUT))
            .map_err(|_| ConnectFailure::Failed)?;
        let cancellation_stream = stream.try_clone().map_err(|_| {
            let _ = stream.shutdown(Shutdown::Both);
            ConnectFailure::Failed
        })?;
        state.stream = Some(cancellation_stream);
        Ok(stream)
    }

    pub(super) fn begin_io(&self) -> Result<IoPermit, CancellationDisposition> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(disposition) = state.disposition {
            return Err(disposition);
        }
        state.in_flight_io = state.in_flight_io.saturating_add(1);
        Ok(IoPermit {
            shared: Arc::clone(&self.shared),
        })
    }

    pub(super) fn detach(&self) {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stream = None;
    }
}

impl PartialEq for DispatchCancellation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
}

impl Eq for DispatchCancellation {}
