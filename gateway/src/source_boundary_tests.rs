#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    fn visit(directory: &Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).expect("read gateway source directory") {
            let entry = entry.expect("source entry");
            let path = entry.path();
            if entry.file_type().expect("source file type").is_dir() {
                if entry.file_name() != "tests" {
                    visit(&path, paths);
                }
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                paths.push(path);
            }
        }
    }

    let mut paths = Vec::new();
    visit(root, &mut paths);
    paths.sort();
    paths
}

#[test]
fn target_network_apis_exist_only_in_the_private_transport_module() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut matches = Vec::new();
    for path in rust_sources(&source) {
        let text = fs::read_to_string(&path).expect("read Rust source");
        let production = text.split("#[cfg(test)]").next().expect("source prefix");
        if production.contains("TcpStream")
            || production.contains("TcpListener")
            || production.contains("UdpSocket")
            || production.contains("ToSocketAddrs")
        {
            matches.push(
                path.strip_prefix(&source)
                    .expect("source-relative path")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    assert_eq!(matches, ["transport/cancellation.rs", "transport.rs"]);
}

#[test]
fn crate_has_exact_pinned_vendored_dependencies() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("read Cargo manifest");
    let dependency_section = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("dependency section")
        .split("\n[")
        .next()
        .expect("next manifest section");
    assert_eq!(
        dependency_section.trim(),
        concat!(
            "base64 = { version = \"=0.22.1\", default-features = false }\n",
            "ed25519-dalek = { version = \"=2.2.0\", default-features = false }\n",
            "serde = { version = \"=1.0.228\", default-features = false, ",
            "features = [\"derive\", \"std\"] }\n",
            "serde_json = { version = \"=1.0.150\", default-features = false, ",
            "features = [\"std\"] }",
        )
    );

    let workspace = manifest_dir.parent().expect("workspace directory");
    let cargo_config =
        fs::read_to_string(workspace.join(".cargo/config.toml")).expect("read Cargo config");
    assert_eq!(
        cargo_config,
        concat!(
            "[source.crates-io]\n",
            "replace-with = \"vendored-sources\"\n\n",
            "[source.vendored-sources]\n",
            "directory = \"vendor\"\n",
        )
    );
    for directory in [
        "base64-0.22.1",
        "ed25519-dalek-2.2.0",
        "serde-1.0.228",
        "serde_json-1.0.150",
    ] {
        assert!(workspace.join("vendor").join(directory).is_dir());
    }
}

#[test]
fn supervised_dispatch_cannot_name_a_network_destination_or_secret() {
    let protocol = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/supervisor_protocol.rs"),
    )
    .expect("read supervisor protocol");
    let dispatch = protocol
        .split("pub struct SupervisorDispatch {")
        .nth(1)
        .expect("dispatch declaration")
        .split("\n}")
        .next()
        .expect("dispatch fields");

    for forbidden in [
        "SocketAddr",
        "hostname",
        "url",
        "channel_key",
        "lease_key",
        "compiler_key",
        "verifier_receipt",
        "effect_digest",
        "compiled_request_digest",
        "request_digest",
        "deadline",
        "maximum_response_bytes",
        "duration_seconds",
    ] {
        assert!(
            !dispatch.contains(forbidden),
            "SupervisorDispatch exposes forbidden field or type: {forbidden}"
        );
    }
    assert!(dispatch.contains("target_id"));
}

#[test]
fn unsupported_action_classes_are_not_in_the_typed_api() {
    let ipc = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ipc/tags.rs"))
        .expect("read IPC action tags");
    let action_class = ipc
        .split("pub enum ActionClass")
        .nth(1)
        .expect("ActionClass enum")
        .split('}')
        .next()
        .expect("ActionClass body");
    assert!(!action_class.contains("HighLoad"));
    assert!(!action_class.contains("Destructive"));
}

#[test]
fn model_facing_dispatch_rpc_cannot_supply_boot_keys_or_epoch_receipts() {
    let ipc = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ipc.rs"))
        .expect("read IPC source");
    for forbidden in [
        "FLER",
        "channel_key",
        "gateway_challenge",
        "SignedEpochEnvelope",
        "verifier_receipt",
    ] {
        assert!(
            !ipc.contains(forbidden),
            "dispatch RPC unexpectedly exposes trusted epoch channel token {forbidden}"
        );
    }
}

#[test]
fn privileged_supervisor_runtime_has_one_opaque_public_bridge() -> std::io::Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let library = fs::read_to_string(manifest_dir.join("src/lib.rs"))?;
    let binary = fs::read_to_string(manifest_dir.join("src/main.rs"))?;
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml"))?;

    assert!(!library.contains("pub mod supervisor_bootstrap;"));
    assert!(!library.contains("pub use supervisor_bootstrap_io"));
    assert!(!library.contains("pub use supervisor_stdio"));
    assert_eq!(
        library
            .matches("pub use installed_cli::run_installed_cli;")
            .count(),
        1
    );
    assert!(library.contains("pub mod supervisor_protocol;"));
    assert!(!manifest.contains("test-fixtures"));

    assert_eq!(
        binary.trim(),
        "fn main() -> std::process::ExitCode {\n    faultloom_gateway::run_installed_cli()\n}"
    );
    Ok(())
}
