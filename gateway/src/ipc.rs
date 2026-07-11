use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::Digest;

const MAGIC: &[u8; 4] = b"FLGW";
const VERSION: u8 = 1;
const REQUEST_MESSAGE: u8 = 1;
const RESPONSE_MESSAGE: u8 = 2;
pub const MAX_FRAME_BYTES: usize = 65_536;
const MAX_ID_BYTES: usize = 256;
const MAX_PROOF_BYTES: usize = 4_096;
const MAX_PAYLOAD_BYTES: usize = 32_768;
const MAX_FEATURES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionClass {
    Observe = 1,
    SafeProbe = 2,
    StateChange = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionKind {
    SemanticHttpV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RequiredFeature {
    GatewayDispatchV1 = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchRequest {
    pub action_id: String,
    pub target_id: String,
    pub intent_digest: Digest,
    pub decision_digest: Digest,
    pub lease_id: String,
    pub scope_epoch: u64,
    pub action_kind: ActionKind,
    pub action_class: ActionClass,
    pub required_features: Vec<RequiredFeature>,
    pub target: SocketAddr,
    pub payload: Vec<u8>,
    pub scope_proof: Vec<u8>,
    pub lease_proof: Vec<u8>,
    pub compiler_proof: Vec<u8>,
    pub canary_ref: Option<String>,
    pub cleanup_plan_ref: Option<String>,
}

impl DispatchRequest {
    pub(crate) fn validate(&self) -> Result<(), DenialCode> {
        if !valid_identifier(&self.action_id)
            || !valid_identifier(&self.target_id)
            || !valid_identifier(&self.lease_id)
            || self.scope_epoch == 0
            || self.target.port() == 0
            || self.payload.is_empty()
            || self.payload.len() > MAX_PAYLOAD_BYTES
            || self.scope_proof.is_empty()
            || self.scope_proof.len() > MAX_PROOF_BYTES
            || self.lease_proof.is_empty()
            || self.lease_proof.len() > MAX_PROOF_BYTES
            || self.compiler_proof.is_empty()
            || self.compiler_proof.len() > MAX_PROOF_BYTES
        {
            return Err(DenialCode::InvalidRequest);
        }
        if self.required_features != [RequiredFeature::GatewayDispatchV1] {
            return Err(DenialCode::UnknownRequiredFeature);
        }
        if self.action_class == ActionClass::StateChange
            && (self
                .canary_ref
                .as_deref()
                .is_none_or(|value| !valid_identifier(value))
                || self
                    .cleanup_plan_ref
                    .as_deref()
                    .is_none_or(|value| !valid_identifier(value)))
        {
            return Err(DenialCode::StateChangeContractMissing);
        }
        if self
            .canary_ref
            .as_deref()
            .is_some_and(|value| !valid_identifier(value))
            || self
                .cleanup_plan_ref
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
        {
            return Err(DenialCode::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DispatchOutcome {
    Completed = 1,
    Failed = 2,
    UnknownOutcome = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchReceipt {
    pub receipt_id: Digest,
    pub lease_id: String,
    pub intent_digest: Digest,
    pub decision_digest: Digest,
    pub scope_epoch: u64,
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub outcome: DispatchOutcome,
    pub dispatched_at_millis: u64,
    pub completed_at_millis: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub reconciliation_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DenialCode {
    MalformedFrame = 1,
    UnknownActionKind = 2,
    UnsupportedActionClass = 3,
    UnknownRequiredFeature = 4,
    InvalidRequest = 5,
    StateChangeContractMissing = 6,
    ScopeVerifierUnavailable = 7,
    ScopeDenied = 8,
    LeaseVerifierUnavailable = 9,
    LeaseDenied = 10,
    CompilerUnavailable = 11,
    CompilerDenied = 12,
    VerificationBindingMismatch = 13,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeniedResponse {
    pub action_id: String,
    pub request_digest: Digest,
    pub reason: DenialCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayResponse {
    Denied(DeniedResponse),
    Receipt {
        action_id: String,
        receipt: DispatchReceipt,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub action_id: Option<String>,
    pub reason: DenialCode,
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_ID_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn request_decode_error(action_id: &str, reason: DenialCode) -> DecodeError {
    DecodeError {
        action_id: Some(action_id.to_owned()),
        reason,
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new(message: u8) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(message);
        Self { bytes }
    }

    fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn digest(&mut self, value: Digest) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn short_bytes(&mut self, value: &[u8]) -> Result<(), DenialCode> {
        let length = u16::try_from(value.len()).map_err(|_| DenialCode::InvalidRequest)?;
        self.u16(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn long_bytes(&mut self, value: &[u8]) -> Result<(), DenialCode> {
        let length = u32::try_from(value.len()).map_err(|_| DenialCode::InvalidRequest)?;
        self.u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), DenialCode> {
        self.short_bytes(value.as_bytes())
    }

    fn optional_string(&mut self, value: Option<&str>) -> Result<(), DenialCode> {
        match value {
            Some(item) => {
                self.byte(1);
                self.string(item)?;
            }
            None => self.byte(0),
        }
        Ok(())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], message: u8) -> Result<Self, DecodeError> {
        if bytes.len() < 6 || &bytes[..4] != MAGIC || bytes[4] != VERSION || bytes[5] != message {
            return Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            });
        }
        Ok(Self { bytes, offset: 6 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.offset.checked_add(length).ok_or(DecodeError {
            action_id: None,
            reason: DenialCode::MalformedFrame,
        })?;
        let value = self.bytes.get(self.offset..end).ok_or(DecodeError {
            action_id: None,
            reason: DenialCode::MalformedFrame,
        })?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two-byte slice"),
        ))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four-byte slice"),
        ))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight-byte slice"),
        ))
    }

    fn digest(&mut self) -> Result<Digest, DecodeError> {
        Ok(Digest::from_bytes(
            self.take(32)?.try_into().expect("32-byte slice"),
        ))
    }

    fn short_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let length = self.u16()? as usize;
        self.take(length)
    }

    fn long_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let length = usize::try_from(self.u32()?).map_err(|_| DecodeError {
            action_id: None,
            reason: DenialCode::MalformedFrame,
        })?;
        self.take(length)
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let text = std::str::from_utf8(self.short_bytes()?).map_err(|_| DecodeError {
            action_id: None,
            reason: DenialCode::InvalidRequest,
        })?;
        Ok(text.to_owned())
    }

    fn optional_string(&mut self) -> Result<Option<String>, DecodeError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.string().map(Some),
            _ => Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            }),
        }
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            })
        }
    }
}

pub fn encode_request(request: &DispatchRequest) -> Result<Vec<u8>, DenialCode> {
    request.validate()?;
    let mut output = Encoder::new(REQUEST_MESSAGE);
    output.string(&request.action_id)?;
    output.string(&request.target_id)?;
    output.digest(request.intent_digest);
    output.digest(request.decision_digest);
    output.string(&request.lease_id)?;
    output.u64(request.scope_epoch);
    output.byte(request.action_kind as u8);
    output.byte(request.action_class as u8);
    output.byte(
        u8::try_from(request.required_features.len())
            .map_err(|_| DenialCode::UnknownRequiredFeature)?,
    );
    for feature in &request.required_features {
        output.byte(*feature as u8);
    }
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
    output.long_bytes(&request.payload)?;
    output.short_bytes(&request.scope_proof)?;
    output.short_bytes(&request.lease_proof)?;
    output.short_bytes(&request.compiler_proof)?;
    output.optional_string(request.canary_ref.as_deref())?;
    output.optional_string(request.cleanup_plan_ref.as_deref())?;
    if output.bytes.len() > MAX_FRAME_BYTES {
        return Err(DenialCode::InvalidRequest);
    }
    Ok(output.bytes)
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
    let target_id = input.string()?;
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
    let payload = input.long_bytes()?.to_vec();
    let scope_proof = input.short_bytes()?.to_vec();
    let lease_proof = input.short_bytes()?.to_vec();
    let compiler_proof = input.short_bytes()?.to_vec();
    let canary_ref = input.optional_string()?;
    let cleanup_plan_ref = input.optional_string()?;
    input.finish()?;
    let request = DispatchRequest {
        action_id,
        target_id,
        intent_digest,
        decision_digest,
        lease_id,
        scope_epoch,
        action_kind,
        action_class,
        required_features,
        target: SocketAddr::new(ip, port),
        payload,
        scope_proof,
        lease_proof,
        compiler_proof,
        canary_ref,
        cleanup_plan_ref,
    };
    if let Err(reason) = request.validate() {
        return Err(request_decode_error(&request.action_id, reason));
    }
    Ok(request)
}

pub fn encode_response(response: &GatewayResponse) -> Result<Vec<u8>, DenialCode> {
    let mut output = Encoder::new(RESPONSE_MESSAGE);
    match response {
        GatewayResponse::Denied(denied) => {
            output.byte(1);
            output.string(&denied.action_id)?;
            output.digest(denied.request_digest);
            output.byte(denied.reason as u8);
        }
        GatewayResponse::Receipt { action_id, receipt } => {
            output.byte(2);
            output.string(action_id)?;
            output.digest(receipt.receipt_id);
            output.string(&receipt.lease_id)?;
            output.digest(receipt.intent_digest);
            output.digest(receipt.decision_digest);
            output.u64(receipt.scope_epoch);
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
        }
    }
    if output.bytes.len() > MAX_FRAME_BYTES {
        return Err(DenialCode::InvalidRequest);
    }
    Ok(output.bytes)
}

pub fn decode_response(bytes: &[u8]) -> Result<GatewayResponse, DecodeError> {
    let mut input = Decoder::new(bytes, RESPONSE_MESSAGE)?;
    let response = match input.byte()? {
        1 => {
            let action_id = input.string()?;
            let request_digest = input.digest()?;
            let reason = denial_code(input.byte()?)?;
            GatewayResponse::Denied(DeniedResponse {
                action_id,
                request_digest,
                reason,
            })
        }
        2 => {
            let action_id = input.string()?;
            let receipt_id = input.digest()?;
            let lease_id = input.string()?;
            let intent_digest = input.digest()?;
            let decision_digest = input.digest()?;
            let scope_epoch = input.u64()?;
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
            if reconciliation_required != (outcome == DispatchOutcome::UnknownOutcome)
                || completed_at_millis < dispatched_at_millis
            {
                return Err(DecodeError {
                    action_id: Some(action_id),
                    reason: DenialCode::MalformedFrame,
                });
            }
            GatewayResponse::Receipt {
                action_id,
                receipt: DispatchReceipt {
                    receipt_id,
                    lease_id,
                    intent_digest,
                    decision_digest,
                    scope_epoch,
                    request_digest,
                    response_digest,
                    outcome,
                    dispatched_at_millis,
                    completed_at_millis,
                    bytes_sent,
                    bytes_received,
                    reconciliation_required,
                },
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

fn denial_code(value: u8) -> Result<DenialCode, DecodeError> {
    let reason = match value {
        1 => DenialCode::MalformedFrame,
        2 => DenialCode::UnknownActionKind,
        3 => DenialCode::UnsupportedActionClass,
        4 => DenialCode::UnknownRequiredFeature,
        5 => DenialCode::InvalidRequest,
        6 => DenialCode::StateChangeContractMissing,
        7 => DenialCode::ScopeVerifierUnavailable,
        8 => DenialCode::ScopeDenied,
        9 => DenialCode::LeaseVerifierUnavailable,
        10 => DenialCode::LeaseDenied,
        11 => DenialCode::CompilerUnavailable,
        12 => DenialCode::CompilerDenied,
        13 => DenialCode::VerificationBindingMismatch,
        _ => {
            return Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            });
        }
    };
    Ok(reason)
}

pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "frame exceeds limit",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "frame length overflow"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0u8; 4];
    match reader.read(&mut length_bytes[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!("one-byte read returned more than one byte"),
    }
    reader.read_exact(&mut length_bytes[1..])?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> DispatchRequest {
        DispatchRequest {
            action_id: "action:1".to_owned(),
            target_id: "target:loopback".to_owned(),
            intent_digest: Digest::of(b"intent"),
            decision_digest: Digest::of(b"decision"),
            lease_id: "lease:1".to_owned(),
            scope_epoch: 3,
            action_kind: ActionKind::SemanticHttpV1,
            action_class: ActionClass::SafeProbe,
            required_features: vec![RequiredFeature::GatewayDispatchV1],
            target: "127.0.0.1:8080".parse().expect("socket address"),
            payload: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            scope_proof: b"scope-proof".to_vec(),
            lease_proof: b"lease-proof".to_vec(),
            compiler_proof: b"compiler-proof".to_vec(),
            canary_ref: None,
            cleanup_plan_ref: None,
        }
    }

    fn tags_offset(frame: &[u8]) -> usize {
        let mut decoder = Decoder::new(frame, REQUEST_MESSAGE).expect("valid header");
        decoder.string().expect("action ID");
        decoder.string().expect("target ID");
        decoder.digest().expect("intent digest");
        decoder.digest().expect("decision digest");
        decoder.string().expect("lease ID");
        decoder.u64().expect("scope epoch");
        decoder.offset
    }

    #[test]
    fn request_round_trip_is_canonical() {
        let expected = request();
        let encoded = encode_request(&expected).expect("encode request");
        assert_eq!(decode_request(&encoded), Ok(expected));
    }

    #[test]
    fn raw_high_load_and_destructive_tags_are_denied() {
        let encoded = encode_request(&request()).expect("encode request");
        let class_offset = tags_offset(&encoded) + 1;
        for tag in [4, 5] {
            let mut mutated = encoded.clone();
            mutated[class_offset] = tag;
            assert_eq!(
                decode_request(&mutated)
                    .expect_err("unsupported class")
                    .reason,
                DenialCode::UnsupportedActionClass
            );
        }
    }

    #[test]
    fn unknown_action_and_feature_tags_are_denied() {
        let encoded = encode_request(&request()).expect("encode request");
        let action_offset = tags_offset(&encoded);
        let mut unknown_action = encoded.clone();
        unknown_action[action_offset] = 99;
        assert_eq!(
            decode_request(&unknown_action)
                .expect_err("unknown action")
                .reason,
            DenialCode::UnknownActionKind
        );

        let mut unknown_feature = encoded;
        unknown_feature[action_offset + 3] = 99;
        assert_eq!(
            decode_request(&unknown_feature)
                .expect_err("unknown feature")
                .reason,
            DenialCode::UnknownRequiredFeature
        );
    }

    #[test]
    fn state_change_requires_canary_and_cleanup_references() {
        let mut candidate = request();
        candidate.action_class = ActionClass::StateChange;
        assert_eq!(
            encode_request(&candidate),
            Err(DenialCode::StateChangeContractMissing)
        );
        candidate.canary_ref = Some("canary:1".to_owned());
        candidate.cleanup_plan_ref = Some("cleanup:1".to_owned());
        assert!(encode_request(&candidate).is_ok());
    }

    #[test]
    fn dispatch_receipt_response_round_trip_is_canonical() {
        let response = GatewayResponse::Receipt {
            action_id: "action:1".to_owned(),
            receipt: DispatchReceipt {
                receipt_id: Digest::of(b"receipt"),
                lease_id: "lease:1".to_owned(),
                intent_digest: Digest::of(b"intent"),
                decision_digest: Digest::of(b"decision"),
                scope_epoch: 3,
                request_digest: Digest::of(b"request"),
                response_digest: Some(Digest::of(b"response")),
                outcome: DispatchOutcome::Completed,
                dispatched_at_millis: 1_000,
                completed_at_millis: 1_001,
                bytes_sent: 7,
                bytes_received: 8,
                reconciliation_required: false,
            },
        };
        let encoded = encode_response(&response).expect("encode response");
        assert_eq!(decode_response(&encoded), Ok(response));
    }

    #[test]
    fn frame_reader_rejects_partial_and_oversized_frames() {
        let mut partial = &b"\x00\x00"[..];
        assert_eq!(
            read_frame(&mut partial).expect_err("partial length").kind(),
            ErrorKind::UnexpectedEof
        );
        let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame(&mut &oversized[..])
                .expect_err("oversized frame")
                .kind(),
            ErrorKind::InvalidData
        );
    }
}
