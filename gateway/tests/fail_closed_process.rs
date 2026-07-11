use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};

use faultloom_gateway::Digest;
use faultloom_gateway::ipc::{
    ActionClass, ActionKind, DenialCode, DeniedResponse, DispatchRequest, GatewayResponse,
    RequiredFeature, decode_response, encode_request, read_frame, write_frame,
};

fn request(target: std::net::SocketAddr) -> DispatchRequest {
    DispatchRequest {
        action_id: "action:process".to_owned(),
        target_id: "target:owned-loopback".to_owned(),
        intent_digest: Digest::of(b"intent"),
        decision_digest: Digest::of(b"decision"),
        lease_id: "lease:process".to_owned(),
        scope_epoch: 1,
        action_kind: ActionKind::SemanticHttpV1,
        action_class: ActionClass::Observe,
        required_features: vec![RequiredFeature::GatewayDispatchV1],
        target,
        payload: b"PING".to_vec(),
        scope_proof: b"untrusted-scope-proof".to_vec(),
        lease_proof: b"untrusted-lease-proof".to_vec(),
        compiler_proof: b"untrusted-compiler-proof".to_vec(),
        canary_ref: None,
        cleanup_plan_ref: None,
    }
}

#[test]
fn separate_process_denies_untrusted_proofs_without_target_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let encoded =
        encode_request(&request(listener.local_addr().expect("address"))).expect("encoded request");
    let mut process = Command::new(env!("CARGO_BIN_EXE_faultloom-gateway"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Gateway process");
    {
        let mut stdin = process.stdin.take().expect("Gateway stdin");
        write_frame(&mut stdin, &encoded).expect("write request frame");
    }
    let mut stdout = process.stdout.take().expect("Gateway stdout");
    let response_frame = read_frame(&mut stdout)
        .expect("read response")
        .expect("response frame");
    let mut trailing = Vec::new();
    stdout
        .read_to_end(&mut trailing)
        .expect("read trailing output");
    assert!(trailing.is_empty());
    let status = process.wait().expect("Gateway exit");
    assert!(status.success());
    assert!(matches!(
        decode_response(&response_frame),
        Ok(GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::ScopeVerifierUnavailable,
            ..
        }))
    ));
    assert_eq!(
        listener.accept().expect_err("no target egress").kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn process_returns_a_typed_denial_for_unknown_action_kind() {
    let target = "127.0.0.1:9".parse().expect("address");
    let mut encoded = encode_request(&request(target)).expect("encoded request");
    let action_id_length = u16::from_be_bytes([encoded[6], encoded[7]]) as usize;
    let target_length_offset = 8 + action_id_length;
    let target_id_length = u16::from_be_bytes([
        encoded[target_length_offset],
        encoded[target_length_offset + 1],
    ]) as usize;
    let action_kind_offset = target_length_offset + 2 + target_id_length + 32 + 32;
    let lease_length =
        u16::from_be_bytes([encoded[action_kind_offset], encoded[action_kind_offset + 1]]) as usize;
    let action_kind_offset = action_kind_offset + 2 + lease_length + 8;
    encoded[action_kind_offset] = 200;

    let mut process = Command::new(env!("CARGO_BIN_EXE_faultloom-gateway"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn Gateway process");
    {
        let mut stdin = process.stdin.take().expect("Gateway stdin");
        write_frame(&mut stdin, &encoded).expect("write request frame");
    }
    let response_frame = read_frame(&mut process.stdout.take().expect("Gateway stdout"))
        .expect("read response")
        .expect("response frame");
    assert!(process.wait().expect("Gateway exit").success());
    assert!(matches!(
        decode_response(&response_frame),
        Ok(GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::UnknownActionKind,
            ..
        }))
    ));
}
