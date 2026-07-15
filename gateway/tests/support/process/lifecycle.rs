use std::fs;
use std::io::Read;

use super::{CHILD_EXIT_TIMEOUT, FailureObservation, ProcessHarness};

impl ProcessHarness {
    pub fn finish(mut self) {
        self.close_input();
        let status = self.wait_for_exit("clean supervisor shutdown");
        self.close_journal_guards();
        self.join_journal();
        if !status.success() {
            let stderr = self.read_stderr();
            panic!(
                "supervised gateway failed with {status}: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
    }

    pub fn observe_failure(mut self) -> FailureObservation {
        let status = self.wait_for_exit("expected supervisor failure");
        drop(self.input.take());
        let mut stdout = Vec::new();
        self.output
            .read_to_end(&mut stdout)
            .expect("read supervisor failure output");
        let stderr = self.read_stderr();
        self.close_journal_guards();
        self.join_journal();
        FailureObservation {
            status,
            stdout,
            stderr,
        }
    }

    pub(crate) fn wait_for_exit(&mut self, context: &str) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + CHILD_EXIT_TIMEOUT;
        loop {
            match self.child.try_wait().expect("poll supervised gateway") {
                Some(status) => return status,
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                None => {
                    let _ = self.child.kill();
                    let status = self
                        .child
                        .wait()
                        .expect("reap timed-out supervised gateway");
                    panic!("{context} exceeded {CHILD_EXIT_TIMEOUT:?}; killed child with {status}");
                }
            }
        }
    }

    pub(crate) fn close_journal_guards(&mut self) {
        drop(self.journal_guards.take());
    }

    pub(crate) fn join_journal(&mut self) {
        if let Some(worker) = self.journal_worker.take() {
            worker
                .join()
                .expect("join fake journal")
                .expect("serve fake journal");
        }
    }

    fn read_stderr(&mut self) -> Vec<u8> {
        let mut stderr = Vec::new();
        self.child
            .stderr
            .take()
            .expect("gateway stderr")
            .read_to_end(&mut stderr)
            .expect("read gateway stderr");
        stderr
    }
}

impl Drop for ProcessHarness {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.close_journal_guards();
        if let Some(worker) = self.journal_worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_dir_all(&self.fixture_root);
    }
}
