use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use faultloom_gateway::Digest;
use faultloom_gateway::ipc::ActionClass;
use faultloom_gateway::supervisor_protocol::SupervisorDispatch;

use crate::bootstrap_fixture::TestBootstrap;
use crate::epoch::EpochReceiptIssuer;
use crate::process::{nonce, now_millis};

pub fn issuer(bootstrap: &TestBootstrap) -> EpochReceiptIssuer {
    EpochReceiptIssuer {
        channel_key_id: bootstrap.secrets.epoch_channel_key_id.clone(),
        channel_key: bootstrap.secrets.epoch_channel_key,
        gateway_boot_id: bootstrap.secrets.gateway_boot_id.clone(),
        gateway_challenge: bootstrap.secrets.gateway_challenge,
        authority_signing_key: bootstrap.authority_signing_key(),
        grant_id: bootstrap.grant_id.clone(),
    }
}

pub fn dispatch(label: &str, epoch: u64, target_id: &str, seed: u8) -> SupervisorDispatch {
    let now = now_millis();
    let intent_material: &[u8] = if matches!(label, "active" | "automatic-retry") {
        b"control-intent"
    } else {
        label.as_bytes()
    };
    let payload_label = if label == "automatic-retry" {
        "active"
    } else {
        label
    };
    SupervisorDispatch {
        action_id: format!("action:{label}"),
        correlation_id: format!("correlation:{label}"),
        lease_id: format!("lease:{label}"),
        target_id: target_id.to_owned(),
        scope_epoch: epoch,
        action_class: ActionClass::Observe,
        method: "POST".to_owned(),
        path: "/probe".to_owned(),
        intent_digest: Digest::of(intent_material),
        decision_digest: Digest::of(format!("decision:{label}").as_bytes()),
        dispatch_nonce: nonce(seed),
        issued_at_millis: now,
        expires_at_millis: now + 20_000,
        retry_of_intent_digest: None,
        payload: format!("probe-{payload_label}").into_bytes(),
        canary_ref: None,
        checkpoint_ref: None,
        cleanup_plan_ref: None,
    }
}

pub fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("target read timeout");
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1_024];
    let (header_end, content_length) = loop {
        let count = stream.read(&mut buffer).expect("owned request read");
        assert!(count > 0, "request ended before HTTP headers");
        request.extend_from_slice(&buffer[..count]);
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            let headers = std::str::from_utf8(&request[..header_end]).expect("ASCII request");
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .expect("content length")
                .parse::<usize>()
                .expect("numeric content length");
            break (header_end, content_length);
        }
    };
    while request.len() < header_end + content_length {
        let count = stream.read(&mut buffer).expect("owned request body");
        assert!(count > 0, "request ended before HTTP body");
        request.extend_from_slice(&buffer[..count]);
    }
    request
}
