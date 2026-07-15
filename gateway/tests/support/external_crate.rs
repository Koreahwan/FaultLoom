use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
static CARGO_CHECK_LOCK: Mutex<()> = Mutex::new(());

struct TempFixture(PathBuf);

impl TempFixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "faultloom-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("src")).expect("create external fixture");
        Self(path)
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn cargo_check(label: &str, package: &str, source: &str) -> Output {
    let _guard = cargo_check_guard();
    let fixture = TempFixture::new(label);
    let gateway = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::write(
        fixture.0.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{package}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             [dependencies]\nfaultloom-gateway = {{ path = \"{}\" }}\n",
            gateway.display().to_string().replace('\\', "\\\\")
        ),
    )
    .expect("write external manifest");
    fs::write(fixture.0.join("src/main.rs"), source).expect("write external source");

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    Command::new(cargo)
        .args(["check", "--offline", "--quiet"])
        .current_dir(&fixture.0)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_BUILD_JOBS", "1")
        .env("CARGO_TARGET_DIR", fixture.0.join("target"))
        .output()
        .expect("run external cargo check")
}

fn cargo_check_guard() -> MutexGuard<'static, ()> {
    CARGO_CHECK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
