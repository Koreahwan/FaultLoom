use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use crate::supervisor_assembly::SupervisorRuntime;

use super::event_loop::process_frames;
use super::workers::{ScopedWorker, join_all};
use super::{SupervisorStageError, finish_processing, supervisor_error, terminate_process};

pub(super) struct RuntimeIo<W> {
    pub(super) runtime: Arc<SupervisorRuntime>,
    pub(super) output: Arc<Mutex<W>>,
    pub(super) active_workers: Arc<Mutex<usize>>,
    pub(super) worker_coordination: Arc<Mutex<()>>,
}

impl<W> RuntimeIo<W> {
    fn new(runtime: Arc<SupervisorRuntime>, output: W) -> Self {
        Self {
            runtime,
            output: Arc::new(Mutex::new(output)),
            active_workers: Arc::new(Mutex::new(0)),
            worker_coordination: Arc::new(Mutex::new(())),
        }
    }
}

pub(super) fn run(
    mut input: impl Read,
    output: impl Write + Send,
    runtime: Arc<SupervisorRuntime>,
) -> io::Result<()> {
    let state = RuntimeIo::new(runtime, output);
    std::thread::scope(|scope| -> io::Result<()> {
        let mut workers: Vec<ScopedWorker<'_>> = Vec::new();
        let processing = process_frames(&mut input, &state, scope, &mut workers);
        finish_processing(
            processing,
            || cleanup(&state.runtime, &mut workers),
            terminate_process,
        )
    })
}

fn cleanup(runtime: &SupervisorRuntime, workers: &mut Vec<ScopedWorker<'_>>) -> io::Result<()> {
    let shutdown = runtime
        .shutdown_active()
        .map_err(|reason| supervisor_error("cannot stop active dispatches", reason));
    let joined = join_all(workers).map_err(SupervisorStageError::into_io);
    let checkpoint = runtime.persist_shutdown_checkpoint();
    shutdown.and(joined).and(checkpoint)
}
