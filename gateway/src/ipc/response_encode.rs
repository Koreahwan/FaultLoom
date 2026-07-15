use super::response::GatewayResponse;
use super::tags::{DenialCode, MAX_FRAME_BYTES, RESPONSE_MESSAGE};
use super::validation::valid_identifier;
use super::wire::Encoder;
use crate::semantic_http::validate_semantic_http_artifact;

pub fn encode_response(response: &GatewayResponse) -> Result<Vec<u8>, DenialCode> {
    let mut output = Encoder::new(RESPONSE_MESSAGE);
    match response {
        GatewayResponse::Denied(denied) => {
            if !denied.validate() {
                return Err(DenialCode::InvalidRequest);
            }
            output.byte(1);
            output.digest(denied.denial_id);
            output.string(&denied.action_id)?;
            output.digest(denied.request_digest);
            output.byte(denied.reason as u8);
        }
        GatewayResponse::Receipt {
            action_id,
            receipt,
            semantic_http,
        } => {
            if !valid_identifier(action_id)
                || action_id != &receipt.action_id
                || !receipt.validate()
                || semantic_http.as_ref().is_some_and(|artifact| {
                    !validate_semantic_http_artifact(artifact)
                        || Some(artifact.raw_response_digest) != receipt.response_digest
                        || artifact.raw_response_length != receipt.bytes_received
                })
            {
                return Err(DenialCode::InvalidRequest);
            }
            output.byte(2);
            output.string(action_id)?;
            output.digest(receipt.receipt_id);
            output.digest(receipt.receipt_authentication_tag);
            output.string(&receipt.action_id)?;
            output.string(&receipt.correlation_id)?;
            output.string(&receipt.lease_id)?;
            output.string(&receipt.grant_id)?;
            output.u64(receipt.grant_version);
            output.string(&receipt.authority_key_id)?;
            output.digest(receipt.scope_epoch_binding_digest);
            output.string(&receipt.lease_key_id)?;
            output.string(&receipt.gateway_boot_id)?;
            output.digest(receipt.boot_challenge_digest);
            output.digest(receipt.intent_digest);
            output.digest(receipt.decision_digest);
            output.u64(receipt.scope_epoch);
            output.digest(receipt.semantic_action_digest);
            output.digest(receipt.request_binding_digest);
            output.digest(receipt.request_frame_digest);
            output.digest(receipt.control_envelope_id);
            output.digest(receipt.hold_binding_digest);
            output.digest(receipt.resolution_digest);
            output.byte(receipt.action_kind as u8);
            output.byte(receipt.egress_plane as u8);
            output.digest(receipt.effect_digest);
            output.nonce(receipt.dispatch_nonce);
            output.u64(receipt.lease_issued_at_millis);
            output.u64(receipt.lease_expires_at_millis);
            output.optional_digest(receipt.retry_of_intent_digest);
            output.u64(receipt.reserved_action_count);
            output.u64(receipt.reserved_request_bytes);
            output.u64(receipt.reserved_response_bytes);
            output.u64(receipt.reserved_duration_seconds);
            output.digest(receipt.request_digest);
            match receipt.response_digest {
                Some(digest) => {
                    output.byte(1);
                    output.digest(digest);
                }
                None => output.byte(0),
            }
            output.byte(receipt.outcome as u8);
            output.u64(receipt.dispatched_at_millis);
            output.u64(receipt.completed_at_millis);
            output.u64(receipt.bytes_sent);
            output.u64(receipt.bytes_received);
            output.byte(u8::from(receipt.reconciliation_required));
            output.byte(u8::from(semantic_http.is_some()));
            if let Some(artifact) = semantic_http {
                output.u16(artifact.status_code);
                output.u16(
                    u16::try_from(artifact.headers.len())
                        .map_err(|_| DenialCode::InvalidRequest)?,
                );
                for header in &artifact.headers {
                    output.string(&header.name)?;
                    output.short_bytes(&header.value)?;
                }
                output.long_bytes(&artifact.body)?;
                output.digest(artifact.body_digest);
                output.digest(artifact.raw_response_digest);
                output.u64(artifact.raw_response_length);
            }
        }
    }
    if output.bytes.len() > MAX_FRAME_BYTES {
        return Err(DenialCode::InvalidRequest);
    }
    Ok(output.bytes)
}
