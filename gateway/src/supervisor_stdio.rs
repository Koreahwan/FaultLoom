use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::ipc::DenialCode;

use super::installed_startup::AuthorizedStartup;

#[path = "supervisor_stdio_commands.rs"]
mod commands;
#[path = "supervisor_stdio_loop.rs"]
mod event_loop;
#[path = "supervisor_stdio_pending.rs"]
mod pending;
#[path = "supervisor_stdio_processing.rs"]
mod processing;
#[path = "supervisor_stdio_response.rs"]
mod response;
#[path = "supervisor_stdio_workers.rs"]
mod workers;

#[derive(Debug)]
pub(super) enum SupervisorStageError {
    General(io::Error),
    Persist(io::Error),
    Output(io::Error),
}

impl SupervisorStageError {
    pub(super) fn into_io(self) -> io::Error {
        match self {
            Self::General(error) | Self::Persist(error) | Self::Output(error) => error,
        }
    }
}

impl From<io::Error> for SupervisorStageError {
    fn from(error: io::Error) -> Self {
        Self::General(error)
    }
}

pub(crate) fn run_supervised_stdio(
    input: impl Read,
    output: impl Write + Send,
    startup: AuthorizedStartup,
) -> io::Result<()> {
    let runtime = Arc::new(startup.attach()?);
    processing::run(input, output, runtime)
}

pub(super) fn finish_processing(
    processing: Result<(), SupervisorStageError>,
    cleanup: impl FnOnce() -> io::Result<()>,
    fail_stop: fn() -> !,
) -> io::Result<()> {
    match processing {
        Err(SupervisorStageError::Persist(_) | SupervisorStageError::Output(_)) => fail_stop(),
        Ok(()) => cleanup(),
        Err(SupervisorStageError::General(error)) => {
            let _ = cleanup();
            Err(error)
        }
    }
}

pub(super) fn terminate_process() -> ! {
    std::process::exit(1)
}

pub(super) fn supervisor_error(message: &'static str, reason: DenialCode) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{message}: {reason:?}"))
}

#[cfg(test)]
use workers::{ReconciliationGuard, WorkerAdmission, WorkerPermit};

#[cfg(test)]
#[path = "supervisor_stdio_stage_tests.rs"]
mod stage_tests;

#[cfg(test)]
#[path = "supervisor_stdio_tests.rs"]
mod tests;
