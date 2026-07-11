mod digest;
pub mod ipc;
mod kernel;
mod policy;
pub mod scope;
mod t13_epoch;
mod transport;

use std::io::{self, Read, Write};

pub use digest::Digest;

use ipc::{
    DeniedResponse, GatewayResponse, decode_request, encode_response, read_frame, write_frame,
};
use kernel::{Gateway, SystemClock};
use policy::{UnavailableActionCompiler, UnavailableLeaseVerifier, UnavailableScopeVerifier};
use transport::TcpTargetTransport;

pub fn run_fail_closed_stdio(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    let gateway = Gateway::new(
        UnavailableScopeVerifier,
        UnavailableLeaseVerifier,
        UnavailableActionCompiler,
        TcpTargetTransport::new(),
        SystemClock,
    );
    while let Some(frame) = read_frame(&mut input)? {
        let response = match decode_request(&frame) {
            Ok(request) => gateway.handle(request, Digest::of(&frame)),
            Err(error) => GatewayResponse::Denied(DeniedResponse {
                action_id: error.action_id.unwrap_or_else(|| "invalid".to_owned()),
                request_digest: Digest::of(&frame),
                reason: error.reason,
            }),
        };
        let encoded = encode_response(&response).map_err(|reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot encode fail-closed response: {reason:?}"),
            )
        })?;
        write_frame(&mut output, &encoded)?;
    }
    Ok(())
}

#[cfg(test)]
mod source_boundary_tests {
    use std::fs;
    use std::path::Path;

    #[test]
    fn target_network_apis_exist_only_in_the_private_transport_module() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut matches = Vec::new();
        for entry in fs::read_dir(&source).expect("read gateway source") {
            let path = entry.expect("source entry").path();
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("read Rust source");
            let production = text.split("#[cfg(test)]").next().expect("source prefix");
            if production.contains("TcpStream")
                || production.contains("TcpListener")
                || production.contains("UdpSocket")
                || production.contains("ToSocketAddrs")
            {
                matches.push(path.file_name().expect("file name").to_owned());
            }
        }
        assert_eq!(matches, ["transport.rs"]);
    }

    #[test]
    fn crate_has_no_external_dependencies() {
        let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read Cargo manifest");
        let dependency_section = manifest
            .split("[dependencies]")
            .nth(1)
            .expect("dependency section")
            .split("\n[")
            .next()
            .expect("next manifest section");
        assert!(dependency_section.trim().is_empty());
    }

    #[test]
    fn unsupported_action_classes_are_not_in_the_typed_api() {
        let ipc = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ipc.rs"))
            .expect("read IPC source");
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
}
