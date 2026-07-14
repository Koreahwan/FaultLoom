pub mod channel;
mod digest;
pub mod ipc;
mod kernel;
pub mod lease;
mod policy;
pub mod scope;
mod t13_epoch;
mod transport;

use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub use digest::Digest;

use ipc::{
    DeniedResponse, GatewayResponse, decode_request, encode_response, read_frame, write_frame,
};
use kernel::{Gateway, SystemClock};
use policy::{UnavailableActionCompiler, UnavailableLeaseVerifier, UnavailableScopeVerifier};
use transport::TcpTargetTransport;

use channel::{AuthenticatedRequest, ChannelServer, response_nonce};

pub fn run_fail_closed_stdio(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut input)? {
        let action_id = decode_request(&frame)
            .map(|request| request.action_id)
            .unwrap_or_else(|error| error.action_id.unwrap_or_else(|| "invalid".to_owned()));
        let response = GatewayResponse::Denied(DeniedResponse::bound(
            action_id,
            Digest::of(&frame),
            ipc::DenialCode::IpcAuthenticationRequired,
        ));
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

/// Authenticated reference process surface for a supervisor that provisions a
/// fresh boot challenge and an inherited channel key. Unauthenticated or
/// forged outer frames close the channel before request decoding or dispatch.
pub fn run_authenticated_fail_closed_stdio(
    mut input: impl Read,
    mut output: impl Write,
    channel: &ChannelServer,
) -> io::Result<()> {
    let gateway = Gateway::new(
        UnavailableScopeVerifier,
        UnavailableLeaseVerifier,
        UnavailableActionCompiler,
        TcpTargetTransport::new(),
        SystemClock,
    );
    while let Some(frame) = read_frame(&mut input)? {
        let authenticated = AuthenticatedRequest::from_bytes(&frame)
            .map_err(|reason| channel_error("invalid authenticated request frame", reason))?;
        let now = system_now_millis()?;
        let verified = channel
            .verify_request(authenticated, now)
            .map_err(|reason| channel_error("request authentication failed", reason))?;
        let request_frame = verified.request_frame();
        let response = match decode_request(request_frame) {
            Ok(request) => gateway.handle(request, verified.request_frame_digest()),
            Err(error) => GatewayResponse::Denied(DeniedResponse::bound(
                error.action_id.unwrap_or_else(|| "invalid".to_owned()),
                verified.request_frame_digest(),
                error.reason,
            )),
        };
        let response_frame = encode_response(&response).map_err(|reason| {
            channel_error("cannot encode authenticated fail-closed response", reason)
        })?;
        let response_digest = Digest::of(&response_frame);
        let issued_at_millis = system_now_millis()?.max(now);
        let expires_at_millis = issued_at_millis
            .saturating_add(30_000)
            .min(channel.challenge().expires_at_millis());
        let sealed = channel
            .seal_response(
                &verified,
                response_frame,
                response_nonce(verified.envelope_id(), response_digest),
                issued_at_millis,
                expires_at_millis,
            )
            .map_err(|reason| channel_error("cannot seal authenticated response", reason))?;
        write_frame(&mut output, &sealed.as_bytes())?;
    }
    Ok(())
}

fn system_now_millis() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "system clock precedes Unix epoch",
            )
        })?
        .as_millis()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "system clock overflow"))
}

fn channel_error(message: &'static str, reason: ipc::DenialCode) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{message}: {reason:?}"))
}

#[cfg(test)]
mod authenticated_stdio_tests {
    use std::io::Cursor;

    use super::*;
    use crate::channel::{AuthenticatedResponse, ChannelChallenge, ChannelClient};
    use crate::ipc::{DenialCode, decode_response};

    #[test]
    fn authenticated_stdio_binds_and_authenticates_the_exact_inner_frame() {
        let now = system_now_millis().expect("clock");
        let key =
            std::array::from_fn(|index| u8::try_from(index + 1).expect("small channel key byte"));
        let challenge = ChannelChallenge::new(
            "channel-key:stdio".to_owned(),
            "gateway:boot:stdio".to_owned(),
            *b"0123456789abcdef",
            now.saturating_sub(1),
            now + 60_000,
        )
        .expect("challenge");
        let client =
            ChannelClient::new(key, challenge.clone(), "session:stdio".to_owned()).expect("client");
        let server = ChannelServer::new(key, challenge).expect("server");
        let request = client
            .seal_request(
                b"intentionally malformed inner request".to_vec(),
                *b"request-nonce-01",
                now,
                now + 5_000,
            )
            .expect("seal request");
        let mut input = Vec::new();
        write_frame(&mut input, &request.as_bytes()).expect("outer request frame");
        let mut output = Vec::new();
        run_authenticated_fail_closed_stdio(Cursor::new(input), &mut output, &server)
            .expect("authenticated stdio");

        let mut output = Cursor::new(output);
        let outer = read_frame(&mut output)
            .expect("read outer response")
            .expect("outer response");
        assert!(read_frame(&mut output).expect("response EOF").is_none());
        let response = AuthenticatedResponse::from_bytes(&outer).expect("response envelope");
        let inner = client
            .verify_response(
                &request,
                response,
                system_now_millis().expect("verification clock"),
            )
            .expect("authenticated response");
        assert!(matches!(
            decode_response(&inner).expect("typed denial"),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::MalformedFrame,
                ..
            })
        ));
    }
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
