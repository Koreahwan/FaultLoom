use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

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

fn toml_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "\\\\")
}

#[test]
fn external_crate_cannot_forge_a_verified_epoch_or_verifier() {
    let fixture = TempFixture::new("external-epoch-forgery");
    let gateway = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::write(
        fixture.0.join("Cargo.toml"),
        format!(
            "[package]\nname = \"epoch-forgery\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             [dependencies]\nfaultloom-gateway = {{ path = \"{}\" }}\n",
            toml_path(gateway)
        ),
    )
    .expect("write external manifest");
    fs::write(
        fixture.0.join("src/main.rs"),
        r#"
use faultloom_gateway::Digest;
use faultloom_gateway::scope::{
    EpochAdmissionError, EpochVerifier, SignedEpochEnvelope, VerifiedScopeEpoch,
};

struct ForgedVerifier;

impl EpochVerifier for ForgedVerifier {
    fn verify(
        &self,
        _envelope: &SignedEpochEnvelope,
        _now_millis: u64,
    ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
        panic!("a forged verifier must never compile")
    }
}

fn main() {
    let _ = VerifiedScopeEpoch::from_trusted_verifier(
        "grant:forged".to_owned(),
        1,
        1,
        2,
        false,
        None,
        "key:forged".to_owned(),
        1,
        Digest::ZERO,
        Digest::ZERO,
        Digest::ZERO,
    );
}
"#,
    )
    .expect("write external source");

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args(["check", "--offline", "--quiet"])
        .current_dir(&fixture.0)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", fixture.0.join("target"))
        .output()
        .expect("run external cargo check");
    assert!(
        !output.status.success(),
        "external epoch forgery unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Sealed") && stderr.contains("not implemented"),
        "external verifier was not rejected by the sealed boundary: {stderr}"
    );
    assert!(
        stderr.contains("from_trusted_verifier")
            && (stderr.contains("private") || stderr.contains("no function or associated item")),
        "opaque verified epoch constructor was not enforced: {stderr}"
    );
}
