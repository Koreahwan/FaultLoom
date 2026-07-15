use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::request::DispatchRequest;
use super::response::DecodeError;
use super::tags::{
    ActionClass, ActionKind, DenialCode, EgressPlane, FlowKind, MAX_FEATURES, MAX_FRAME_BYTES,
    REQUEST_MESSAGE, RequiredFeature,
};
use super::validation::valid_identifier;
use super::wire::Decoder;

fn request_decode_error(action_id: &str, reason: DenialCode) -> DecodeError {
    DecodeError {
        action_id: Some(action_id.to_owned()),
        reason,
    }
}

pub fn decode_request(bytes: &[u8]) -> Result<DispatchRequest, DecodeError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(DecodeError {
            action_id: None,
            reason: DenialCode::MalformedFrame,
        });
    }
    let mut input = Decoder::new(bytes, REQUEST_MESSAGE)?;
    let action_id = input.string()?;
    if !valid_identifier(&action_id) {
        return Err(request_decode_error(&action_id, DenialCode::InvalidRequest));
    }
    let correlation_id = input.string()?;
    let grant_id = input.string()?;
    let grant_version = input.u64()?;
    let target_id = input.string()?;
    let pack_id = input.string()?;
    let action_family = input.string()?;
    let identity_id = input.string()?;
    let tenant_id = input.optional_string()?;
    let intent_digest = input.digest()?;
    let decision_digest = input.digest()?;
    let lease_id = input.string()?;
    let scope_epoch = input.u64()?;
    let action_kind = match input.byte()? {
        1 => ActionKind::SemanticHttpV1,
        _ => {
            return Err(request_decode_error(
                &action_id,
                DenialCode::UnknownActionKind,
            ));
        }
    };
    let action_class = match input.byte()? {
        1 => ActionClass::Observe,
        2 => ActionClass::SafeProbe,
        3 => ActionClass::StateChange,
        4 | 5 => {
            return Err(request_decode_error(
                &action_id,
                DenialCode::UnsupportedActionClass,
            ));
        }
        _ => {
            return Err(request_decode_error(
                &action_id,
                DenialCode::UnsupportedActionClass,
            ));
        }
    };
    let egress_plane = match input.byte()? {
        1 => EgressPlane::TargetGateway,
        _ => {
            return Err(request_decode_error(
                &action_id,
                DenialCode::InvalidEgressPlane,
            ));
        }
    };
    let flow_kind = match input.byte()? {
        1 => FlowKind::TopLevel,
        2 => FlowKind::DnsResolution,
        3 => FlowKind::Redirect,
        4 => FlowKind::BrowserSubresource,
        5 => FlowKind::BrowserIframe,
        6 => FlowKind::ServiceWorker,
        7 => FlowKind::WebSocket,
        8 => FlowKind::Download,
        9 => FlowKind::ScannerChild,
        10 => FlowKind::GraphQlChild,
        11 => FlowKind::BatchChild,
        12 => FlowKind::Callback,
        13 => FlowKind::Polling,
        14 => FlowKind::RawSchedule,
        15 => FlowKind::PackAction,
        _ => {
            return Err(request_decode_error(
                &action_id,
                DenialCode::InvalidChildFlow,
            ));
        }
    };
    let parent_action_id = input.optional_string()?;
    let feature_count = input.byte()? as usize;
    if feature_count == 0 || feature_count > MAX_FEATURES {
        return Err(request_decode_error(
            &action_id,
            DenialCode::UnknownRequiredFeature,
        ));
    }
    let mut required_features = Vec::with_capacity(feature_count);
    for _ in 0..feature_count {
        match input.byte()? {
            1 => required_features.push(RequiredFeature::GatewayDispatchV1),
            _ => {
                return Err(request_decode_error(
                    &action_id,
                    DenialCode::UnknownRequiredFeature,
                ));
            }
        }
    }
    if required_features != [RequiredFeature::GatewayDispatchV1] {
        return Err(request_decode_error(
            &action_id,
            DenialCode::UnknownRequiredFeature,
        ));
    }
    let hostname = input.string()?;
    let protocol = input.string()?;
    let method = input.string()?;
    let path = input.string()?;
    let ip = match input.byte()? {
        4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(input.take(4)?).expect("four-byte IPv4 address"),
        )),
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(input.take(16)?).expect("16-byte IPv6 address"),
        )),
        _ => {
            return Err(request_decode_error(&action_id, DenialCode::InvalidRequest));
        }
    };
    let port = input.u16()?;
    let resolution_digest = input.digest()?;
    let semantic_action_digest = input.digest()?;
    let dispatch_nonce = input.nonce()?;
    let request_issued_at_millis = input.u64()?;
    let request_expires_at_millis = input.u64()?;
    let retry_of_intent_digest = input.optional_digest()?;
    let payload = input.long_bytes()?.to_vec();
    let scope_proof = input.short_bytes()?.to_vec();
    let lease_proof = input.short_bytes()?.to_vec();
    let compiler_proof = input.short_bytes()?.to_vec();
    let canary_ref = input.optional_string()?;
    let checkpoint_ref = input.optional_string()?;
    let cleanup_plan_ref = input.optional_string()?;
    input.finish()?;
    let request = DispatchRequest {
        action_id,
        correlation_id,
        grant_id,
        grant_version,
        target_id,
        pack_id,
        action_family,
        identity_id,
        tenant_id,
        intent_digest,
        decision_digest,
        lease_id,
        scope_epoch,
        action_kind,
        action_class,
        egress_plane,
        flow_kind,
        parent_action_id,
        required_features,
        hostname,
        protocol,
        method,
        path,
        target: SocketAddr::new(ip, port),
        resolution_digest,
        semantic_action_digest,
        dispatch_nonce,
        request_issued_at_millis,
        request_expires_at_millis,
        retry_of_intent_digest,
        payload,
        scope_proof,
        lease_proof,
        compiler_proof,
        canary_ref,
        checkpoint_ref,
        cleanup_plan_ref,
    };
    if let Err(reason) = request.validate() {
        return Err(request_decode_error(&request.action_id, reason));
    }
    Ok(request)
}
