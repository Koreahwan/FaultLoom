use crate::ipc::DispatchOutcome;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DispatchLimits {
    pub(crate) deadline: std::time::Instant,
    pub(crate) maximum_response_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct TransportObservation {
    pub(crate) outcome: DispatchOutcome,
    pub(crate) bytes_sent: u64,
    pub(crate) response: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancellationDisposition {
    StableNoEgress,
    TargetOutcomeUnknown,
}

pub(crate) fn completed(response: Vec<u8>, bytes_sent: usize) -> TransportObservation {
    TransportObservation {
        outcome: DispatchOutcome::Completed,
        bytes_sent: bytes_sent as u64,
        response,
    }
}

pub(crate) fn failed(response: Vec<u8>, bytes_sent: usize) -> TransportObservation {
    TransportObservation {
        outcome: DispatchOutcome::Failed,
        bytes_sent: bytes_sent as u64,
        response,
    }
}

pub(crate) fn after_send_failure(response: Vec<u8>, bytes_sent: usize) -> TransportObservation {
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

pub(crate) fn after_cancellation(
    response: Vec<u8>,
    bytes_sent: u64,
    disposition: CancellationDisposition,
) -> TransportObservation {
    TransportObservation {
        outcome: match disposition {
            CancellationDisposition::StableNoEgress => DispatchOutcome::Failed,
            CancellationDisposition::TargetOutcomeUnknown => DispatchOutcome::UnknownOutcome,
        },
        bytes_sent,
        response,
    }
}
