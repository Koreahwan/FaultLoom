#[path = "support/external_crate.rs"]
mod external_crate;

#[test]
fn external_crate_can_name_the_opaque_bridge_and_controller_protocol() {
    let output = external_crate::cargo_check(
        "external-controller-surface",
        "controller-surface",
        r#"
use std::process::ExitCode;

use faultloom_gateway::channel::{ChannelChallenge, ChannelClient};
use faultloom_gateway::run_installed_cli;
use faultloom_gateway::supervisor_protocol::{SupervisorCommand, SupervisorResponse};

fn main() {
    let _: fn() -> ExitCode = run_installed_cli;
    let _ = std::mem::size_of::<Option<ChannelChallenge>>();
    let _ = std::mem::size_of::<Option<ChannelClient>>();
    let _ = std::mem::size_of::<Option<SupervisorCommand>>();
    let _ = std::mem::size_of::<Option<SupervisorResponse>>();
}
"#,
    );

    assert!(
        output.status.success(),
        "external controller surface did not compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn external_crate_cannot_forge_a_verified_epoch_or_verifier() {
    let output = external_crate::cargo_check(
        "external-epoch-forgery",
        "epoch-forgery",
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
    );
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

#[test]
fn external_crate_cannot_supply_a_lease_verifier_or_dispatch_transport() {
    let output = external_crate::cargo_check(
        "external-lease-forgery",
        "lease-forgery",
        r#"
use faultloom_gateway::kernel::Gateway;
use faultloom_gateway::lease::LeaseAuthority;
use faultloom_gateway::policy::LeaseVerifier;
use faultloom_gateway::transport::TargetTransport;

fn main() {
    let _ = LeaseAuthority::reserve;
    let _ = std::mem::size_of::<Gateway<(), (), (), (), ()>>();
    let _ = std::mem::size_of::<&dyn LeaseVerifier>();
    let _ = std::mem::size_of::<&dyn TargetTransport>();
}
"#,
    );
    assert!(
        !output.status.success(),
        "external lease/dispatch forgery unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for boundary in ["kernel", "policy", "transport"] {
        assert!(
            stderr.contains(boundary) && stderr.contains("private"),
            "external {boundary} boundary was not private: {stderr}"
        );
    }
    assert!(
        stderr.contains("reserve")
            && (stderr.contains("not found")
                || stderr.contains("no function or associated item")
                || stderr.contains("private")),
        "LeaseAuthority unexpectedly exposed reservation admission: {stderr}"
    );
}

#[test]
fn external_crate_cannot_access_privileged_supervisor_bootstrap_loader_or_runner() {
    let output = external_crate::cargo_check(
        "external-supervisor-authority",
        "supervisor-authority",
        r#"
use faultloom_gateway::supervisor_bootstrap::SupervisorBootstrap;
use faultloom_gateway::supervisor_bootstrap_io::load_inherited_supervisor_bootstrap;
use faultloom_gateway::supervisor_stdio::run_supervised_stdio;

fn main() {
    let _: Option<SupervisorBootstrap> = None;
    let _ = load_inherited_supervisor_bootstrap;
    let _ = run_supervised_stdio;
}
"#,
    );
    assert!(
        !output.status.success(),
        "external supervisor authority unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for (module, item) in [
        ("supervisor_bootstrap", "SupervisorBootstrap"),
        (
            "supervisor_bootstrap_io",
            "load_inherited_supervisor_bootstrap",
        ),
        ("supervisor_stdio", "run_supervised_stdio"),
    ] {
        assert!(
            stderr.contains(module) && stderr.contains(item) && stderr.contains("private"),
            "external supervisor boundary did not hide {module}::{item}: {stderr}"
        );
    }
}
