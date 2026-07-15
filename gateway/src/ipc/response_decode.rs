use super::denial_code::denial_code;
use super::receipt::DispatchReceipt;
use super::response::{DecodeError, DeniedResponse, GatewayResponse};
use super::tags::{ActionKind, DenialCode, DispatchOutcome, EgressPlane, RESPONSE_MESSAGE};
use super::validation::valid_identifier;
use super::wire::Decoder;
use crate::semantic_http::{
    SemanticHttpHeader, SemanticHttpResponseArtifact, validate_semantic_http_artifact,
};

pub fn decode_response(bytes: &[u8]) -> Result<GatewayResponse, DecodeError> {
    let mut input = Decoder::new(bytes, RESPONSE_MESSAGE)?;
    let response = match input.byte()? {
        1 => {
            let denial_id = input.digest()?;
            let action_id = input.string()?;
            let request_digest = input.digest()?;
            let reason = denial_code(input.byte()?)?;
            let denied = DeniedResponse {
                denial_id,
                action_id,
                request_digest,
                reason,
            };
            if !denied.validate() {
                return Err(DecodeError {
                    action_id: Some(denied.action_id),
                    reason: DenialCode::MalformedFrame,
                });
            }
            GatewayResponse::Denied(denied)
        }
        2 => {
            let action_id = input.string()?;
            let receipt_id = input.digest()?;
            let receipt_authentication_tag = input.digest()?;
            let receipt_action_id = input.string()?;
            let correlation_id = input.string()?;
            let lease_id = input.string()?;
            let grant_id = input.string()?;
            let grant_version = input.u64()?;
            let authority_key_id = input.string()?;
            let scope_epoch_binding_digest = input.digest()?;
            let lease_key_id = input.string()?;
            let gateway_boot_id = input.string()?;
            let boot_challenge_digest = input.digest()?;
            let intent_digest = input.digest()?;
            let decision_digest = input.digest()?;
            let scope_epoch = input.u64()?;
            let semantic_action_digest = input.digest()?;
            let request_binding_digest = input.digest()?;
            let request_frame_digest = input.digest()?;
            let control_envelope_id = input.digest()?;
            let hold_binding_digest = input.digest()?;
            let resolution_digest = input.digest()?;
            let action_kind = match input.byte()? {
                1 => ActionKind::SemanticHttpV1,
                _ => {
                    return Err(DecodeError {
                        action_id: Some(action_id),
                        reason: DenialCode::UnknownActionKind,
                    });
                }
            };
            let egress_plane = match input.byte()? {
                1 => EgressPlane::TargetGateway,
                _ => {
                    return Err(DecodeError {
                        action_id: Some(action_id),
                        reason: DenialCode::InvalidEgressPlane,
                    });
                }
            };
            let effect_digest = input.digest()?;
            let dispatch_nonce = input.nonce()?;
            let lease_issued_at_millis = input.u64()?;
            let lease_expires_at_millis = input.u64()?;
            let retry_of_intent_digest = input.optional_digest()?;
            let reserved_action_count = input.u64()?;
            let reserved_request_bytes = input.u64()?;
            let reserved_response_bytes = input.u64()?;
            let reserved_duration_seconds = input.u64()?;
            let request_digest = input.digest()?;
            let response_digest = match input.byte()? {
                0 => None,
                1 => Some(input.digest()?),
                _ => {
                    return Err(DecodeError {
                        action_id: Some(action_id),
                        reason: DenialCode::MalformedFrame,
                    });
                }
            };
            let outcome = match input.byte()? {
                1 => DispatchOutcome::Completed,
                2 => DispatchOutcome::Failed,
                3 => DispatchOutcome::UnknownOutcome,
                _ => {
                    return Err(DecodeError {
                        action_id: Some(action_id),
                        reason: DenialCode::MalformedFrame,
                    });
                }
            };
            let dispatched_at_millis = input.u64()?;
            let completed_at_millis = input.u64()?;
            let bytes_sent = input.u64()?;
            let bytes_received = input.u64()?;
            let reconciliation_required = match input.byte()? {
                0 => false,
                1 => true,
                _ => {
                    return Err(DecodeError {
                        action_id: Some(action_id),
                        reason: DenialCode::MalformedFrame,
                    });
                }
            };
            let semantic_http = match input.byte()? {
                0 => None,
                1 => {
                    let status_code = input.u16()?;
                    let header_count = input.u16()?;
                    let mut headers = Vec::with_capacity(usize::from(header_count));
                    for _ in 0..header_count {
                        headers.push(SemanticHttpHeader {
                            name: input.string()?,
                            value: input.short_bytes()?.to_vec(),
                        });
                    }
                    Some(SemanticHttpResponseArtifact {
                        status_code,
                        headers,
                        body: input.long_bytes()?.to_vec(),
                        body_digest: input.digest()?,
                        raw_response_digest: input.digest()?,
                        raw_response_length: input.u64()?,
                    })
                }
                _ => {
                    return Err(DecodeError {
                        action_id: Some(action_id),
                        reason: DenialCode::MalformedFrame,
                    });
                }
            };
            let receipt = DispatchReceipt {
                receipt_id,
                receipt_authentication_tag,
                action_id: receipt_action_id,
                correlation_id,
                lease_id,
                grant_id,
                grant_version,
                authority_key_id,
                scope_epoch_binding_digest,
                lease_key_id,
                gateway_boot_id,
                boot_challenge_digest,
                intent_digest,
                decision_digest,
                scope_epoch,
                semantic_action_digest,
                request_binding_digest,
                request_frame_digest,
                control_envelope_id,
                hold_binding_digest,
                resolution_digest,
                action_kind,
                egress_plane,
                effect_digest,
                dispatch_nonce,
                lease_issued_at_millis,
                lease_expires_at_millis,
                retry_of_intent_digest,
                reserved_action_count,
                reserved_request_bytes,
                reserved_response_bytes,
                reserved_duration_seconds,
                request_digest,
                response_digest,
                outcome,
                dispatched_at_millis,
                completed_at_millis,
                bytes_sent,
                bytes_received,
                reconciliation_required,
            };
            if !valid_identifier(&action_id)
                || action_id != receipt.action_id
                || !receipt.validate()
                || semantic_http.as_ref().is_some_and(|artifact| {
                    !validate_semantic_http_artifact(artifact)
                        || Some(artifact.raw_response_digest) != receipt.response_digest
                        || artifact.raw_response_length != receipt.bytes_received
                })
            {
                return Err(DecodeError {
                    action_id: Some(action_id),
                    reason: DenialCode::MalformedFrame,
                });
            }
            GatewayResponse::Receipt {
                action_id,
                receipt,
                semantic_http,
            }
        }
        _ => {
            return Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            });
        }
    };
    input.finish()?;
    Ok(response)
}
