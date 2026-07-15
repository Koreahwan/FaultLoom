use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct LaunchOptions {
    pub bootstrap_bytes: Option<Vec<u8>>,
    pub trust_bytes: Option<Vec<u8>>,
    pub trust_permissions: Option<u32>,
    pub journal_descriptors: bool,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            bootstrap_bytes: None,
            trust_bytes: None,
            trust_permissions: Some(0o644),
            journal_descriptors: true,
        }
    }
}

pub(super) struct SandboxSpec {
    pub executable: PathBuf,
    pub bootstrap_bytes: Vec<u8>,
    pub trust_bytes: Vec<u8>,
    pub trust_permissions: Option<u32>,
    pub journal_paths: Option<(PathBuf, PathBuf)>,
}

pub(super) struct SandboxProcess {
    pub child: Child,
    pub fixture_root: PathBuf,
}

pub(super) fn exact_executable() -> io::Result<PathBuf> {
    fs::canonicalize(env!("CARGO_BIN_EXE_faultloom-gateway"))
}

pub(super) fn spawn(spec: SandboxSpec) -> io::Result<SandboxProcess> {
    require_bwrap_0_9()?;
    let fixture_root = fixture_root()?;
    let bootstrap = fixture_root.join("bootstrap.flbs");
    let trust = fixture_root.join("gateway-trust-v1.json");
    fs::write(&bootstrap, &spec.bootstrap_bytes)?;
    fs::write(&trust, &spec.trust_bytes)?;
    fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&trust, fs::Permissions::from_mode(0o600))?;
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "exec 6<\"$1\"; shift; exec \"$@\"", "faultloom-bwrap"])
        .arg(&trust)
        .arg("/usr/bin/bwrap");
    sandbox_base(&mut command);
    command
        .args(["--ro-bind"])
        .arg(&spec.executable)
        .arg("/run/faultloom/faultloom-gateway")
        .args(["--ro-bind"])
        .arg(&bootstrap)
        .arg("/run/faultloom/bootstrap.flbs");
    if let Some(permissions) = spec.trust_permissions {
        command
            .args([
                "--perms",
                &format!("{permissions:04o}"),
                "--ro-bind-data",
                "6",
            ])
            .arg("/etc/faultloom/gateway-trust-v1.json");
    }
    let child_script = match spec.journal_paths {
        Some((request, reply)) => {
            command
                .args(["--bind"])
                .arg(request)
                .arg("/run/faultloom/journal-write.fifo")
                .args(["--bind"])
                .arg(reply)
                .arg("/run/faultloom/journal-read.fifo");
            "exec 3</run/faultloom/bootstrap.flbs; exec 4>/run/faultloom/journal-write.fifo; exec 5</run/faultloom/journal-read.fifo; exec /run/faultloom/faultloom-gateway --supervised-stdio --bootstrap-fd 3 --journal-write-fd 4 --journal-read-fd 5"
        }
        None => {
            "exec 3</run/faultloom/bootstrap.flbs; exec 4<&-; exec 5<&-; exec /run/faultloom/faultloom-gateway --supervised-stdio --bootstrap-fd 3 --journal-write-fd 4 --journal-read-fd 5"
        }
    };
    command
        .args(["--", "/bin/sh", "-c", child_script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match command.spawn() {
        Ok(child) => Ok(SandboxProcess {
            child,
            fixture_root,
        }),
        Err(error) => {
            let _ = fs::remove_dir_all(&fixture_root);
            Err(error)
        }
    }
}

fn sandbox_base(command: &mut Command) {
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--uid",
        "0",
        "--gid",
        "0",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--hostname",
        "faultloom-installed-test",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/",
        "--setenv",
        "LANG",
        "C",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/etc",
        "--dir",
        "/etc/faultloom",
        "--dir",
        "/run",
        "--dir",
        "/run/faultloom",
    ]);
}

fn require_bwrap_0_9() -> io::Result<()> {
    let output = Command::new("/usr/bin/bwrap")
        .arg("--version")
        .output()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("bwrap unavailable: {error}"),
            )
        })?;
    let version = String::from_utf8_lossy(&output.stdout);
    if output.status.success() && version.trim() == "bubblewrap 0.9.0" {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("requires bubblewrap 0.9.0, observed {version:?}"),
        ))
    }
}

fn fixture_root() -> io::Result<PathBuf> {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "faultloom-installed-process-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}
