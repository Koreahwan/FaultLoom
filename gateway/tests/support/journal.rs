use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use faultloom_gateway::Digest;
use faultloom_gateway::supervisor_journal::JournalSnapshot;

#[path = "journal/session.rs"]
pub(crate) mod session;

// allow: SIZE_OK — this fake keeps one journal state machine and its deterministic ACK fault gate co-located.
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

pub struct FakeJournal {
    key: [u8; 32],
    root: PathBuf,
    next_session: AtomicU64,
    pub(super) state: Arc<Mutex<DurableState>>,
}

pub struct AckCommitPause {
    committed: Receiver<()>,
    release: Option<SyncSender<()>>,
}

pub(super) struct JournalGuards {
    _request: File,
    _reply: File,
}

struct AckGate {
    committed: SyncSender<()>,
    release: Receiver<()>,
}

pub(super) struct DurableState {
    stable_binding: Digest,
    pub(super) current_anchor: Option<Digest>,
    pub(super) snapshot: Option<JournalSnapshot>,
    pub(super) durable_sequence: u64,
    audit: File,
    pub(super) corrupt_next_ack: bool,
    next_ack_gate: Option<AckGate>,
    pub(super) received_frames: u64,
    pub(super) open_requests: u64,
    pub(super) commit_requests: u64,
}

impl FakeJournal {
    pub fn new(key: [u8; 32], stable_binding: Digest) -> io::Result<Self> {
        if key.iter().all(|byte| *byte == key[0]) || stable_binding == Digest::ZERO {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid binding"));
        }
        let root = fixture_root()?;
        let audit_path = root.join("durable-audit.bin");
        let audit = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(audit_path)?;
        audit.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            key,
            root,
            next_session: AtomicU64::new(0),
            state: Arc::new(Mutex::new(DurableState {
                stable_binding,
                current_anchor: None,
                snapshot: None,
                durable_sequence: 0,
                audit,
                corrupt_next_ack: false,
                next_ack_gate: None,
                received_frames: 0,
                open_requests: 0,
                commit_requests: 0,
            })),
        })
    }

    pub fn snapshot(&self) -> Option<JournalSnapshot> {
        self.state
            .lock()
            .expect("fake journal state")
            .snapshot
            .clone()
    }

    pub fn pause_next_ack_after_commit(&self) -> AckCommitPause {
        let (committed_tx, committed_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let previous = self
            .state
            .lock()
            .expect("fake journal ACK gate")
            .next_ack_gate
            .replace(AckGate {
                committed: committed_tx,
                release: release_rx,
            });
        assert!(previous.is_none(), "fake journal ACK gate already armed");
        AckCommitPause {
            committed: committed_rx,
            release: Some(release_tx),
        }
    }

    pub fn start_session(
        &self,
    ) -> io::Result<(PathBuf, PathBuf, JournalGuards, JoinHandle<io::Result<()>>)> {
        let sequence = self.next_session.fetch_add(1, Ordering::Relaxed);
        let request_fifo = self.root.join(format!("request-{sequence}.fifo"));
        let reply_fifo = self.root.join(format!("reply-{sequence}.fifo"));
        create_fifo(&request_fifo)?;
        if let Err(error) = create_fifo(&reply_fifo) {
            let _ = fs::remove_file(&request_fifo);
            return Err(error);
        }
        let request_guard = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&request_fifo)?;
        let reply_guard = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&reply_fifo)?;
        let worker_request = request_fifo.clone();
        let worker_reply = reply_fifo.clone();
        let key = self.key;
        let state = Arc::clone(&self.state);
        let worker = thread::Builder::new()
            .name(format!("fake-journal-{sequence}"))
            .spawn(move || {
                let result = session::serve_session(&worker_request, &worker_reply, key, state);
                let _ = fs::remove_file(&worker_request);
                let _ = fs::remove_file(&worker_reply);
                result
            })?;
        Ok((
            request_fifo,
            reply_fifo,
            JournalGuards {
                _request: request_guard,
                _reply: reply_guard,
            },
            worker,
        ))
    }
}

impl AckCommitPause {
    pub fn wait_until_commit_visible(&self) {
        self.committed
            .recv_timeout(Duration::from_secs(5))
            .expect("journal ACK commit did not become visible");
    }

    pub fn release(mut self) {
        self.release
            .take()
            .expect("journal ACK gate release")
            .send(())
            .expect("journal ACK gate worker");
    }
}

impl Drop for AckCommitPause {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for FakeJournal {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture_root() -> io::Result<PathBuf> {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "faultloom-fake-journal-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn create_fifo(path: &Path) -> io::Result<()> {
    let status = Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("mkfifo failed with {status}")))
    }
}
