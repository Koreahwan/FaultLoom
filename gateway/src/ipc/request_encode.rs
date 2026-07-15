use std::net::IpAddr;

use super::request::DispatchRequest;
use super::tags::{DenialCode, MAX_FRAME_BYTES, REQUEST_MESSAGE};
use super::wire::Encoder;

pub fn encode_request(request: &DispatchRequest) -> Result<Vec<u8>, DenialCode> {
    request.validate()?;
    let mut output = Encoder::new(REQUEST_MESSAGE);
    output.string(&request.action_id)?;
    output.string(&request.correlation_id)?;
    output.string(&request.grant_id)?;
    output.u64(request.grant_version);
    output.string(&request.target_id)?;
    output.string(&request.pack_id)?;
    output.string(&request.action_family)?;
    output.string(&request.identity_id)?;
    output.optional_string(request.tenant_id.as_deref())?;
    output.digest(request.intent_digest);
    output.digest(request.decision_digest);
    output.string(&request.lease_id)?;
    output.u64(request.scope_epoch);
    output.byte(request.action_kind as u8);
    output.byte(request.action_class as u8);
    output.byte(request.egress_plane as u8);
    output.byte(request.flow_kind as u8);
    output.optional_string(request.parent_action_id.as_deref())?;
    output.byte(
        u8::try_from(request.required_features.len())
            .map_err(|_| DenialCode::UnknownRequiredFeature)?,
    );
    for feature in &request.required_features {
        output.byte(*feature as u8);
    }
    output.string(&request.hostname)?;
    output.string(&request.protocol)?;
    output.string(&request.method)?;
    output.string(&request.path)?;
    match request.target.ip() {
        IpAddr::V4(address) => {
            output.byte(4);
            output.bytes.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            output.byte(6);
            output.bytes.extend_from_slice(&address.octets());
        }
    }
    output.u16(request.target.port());
    output.digest(request.resolution_digest);
    output.digest(request.semantic_action_digest);
    output.nonce(request.dispatch_nonce);
    output.u64(request.request_issued_at_millis);
    output.u64(request.request_expires_at_millis);
    output.optional_digest(request.retry_of_intent_digest);
    output.long_bytes(&request.payload)?;
    output.short_bytes(&request.scope_proof)?;
    output.short_bytes(&request.lease_proof)?;
    output.short_bytes(&request.compiler_proof)?;
    output.optional_string(request.canary_ref.as_deref())?;
    output.optional_string(request.checkpoint_ref.as_deref())?;
    output.optional_string(request.cleanup_plan_ref.as_deref())?;
    if output.bytes.len() > MAX_FRAME_BYTES {
        return Err(DenialCode::InvalidRequest);
    }
    Ok(output.bytes)
}
