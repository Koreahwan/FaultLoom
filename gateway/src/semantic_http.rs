use crate::Digest;
use crate::ipc::{ActionKind, DenialCode, DispatchRequest, EgressPlane, valid_identifier};
use crate::policy::{ActionCompiler, CompiledAction, CompilerLeaseBinding, target_effect_digest};

const HMAC_BLOCK_BYTES: usize = 64;
pub(crate) const MAX_SEMANTIC_HTTP_RESPONSE_BYTES: usize = 32_768;
const MAX_SEMANTIC_HTTP_HEADERS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticHttpHeader {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticHttpResponseArtifact {
    pub status_code: u16,
    pub headers: Vec<SemanticHttpHeader>,
    pub body: Vec<u8>,
    pub body_digest: Digest,
    pub raw_response_digest: Digest,
    pub raw_response_length: u64,
}

pub(crate) fn parse_semantic_http_response(
    response: &[u8],
) -> Option<SemanticHttpResponseArtifact> {
    if response.is_empty() || response.len() > MAX_SEMANTIC_HTTP_RESPONSE_BYTES {
        return None;
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let head = &response[..header_end];
    let body = &response[header_end + 4..];
    let lines = head.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    let status_line = canonical_header_line(lines.first()?, lines.len() == 1)?;
    let status_code = parse_status_line(status_line)?;
    let mut headers = Vec::new();
    let mut content_length = None;
    for (index, raw_line) in lines.iter().enumerate().skip(1) {
        if headers.len() >= MAX_SEMANTIC_HTTP_HEADERS {
            return None;
        }
        let line = canonical_header_line(raw_line, index + 1 == lines.len())?;
        let separator = line.iter().position(|byte| *byte == b':')?;
        let (raw_name, raw_value) = line.split_at(separator);
        if raw_name.is_empty() || !raw_name.iter().copied().all(valid_header_name_byte) {
            return None;
        }
        let name = raw_name
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>();
        let name = String::from_utf8(name).ok()?;
        let value = trim_optional_whitespace(&raw_value[1..]);
        if !value
            .iter()
            .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
        {
            return None;
        }
        if name == "transfer-encoding" {
            return None;
        }
        if name == "content-length" {
            if content_length.is_some() || value.is_empty() {
                return None;
            }
            let text = std::str::from_utf8(value).ok()?;
            if !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            content_length = text.parse::<usize>().ok();
            if content_length.is_none() {
                return None;
            }
        }
        headers.push(SemanticHttpHeader {
            name,
            value: value.to_vec(),
        });
    }
    if content_length.is_some_and(|length| length != body.len()) {
        return None;
    }
    Some(SemanticHttpResponseArtifact {
        status_code,
        headers,
        body: body.to_vec(),
        body_digest: Digest::of(body),
        raw_response_digest: Digest::of(response),
        raw_response_length: u64::try_from(response.len()).ok()?,
    })
}

pub(crate) fn validate_semantic_http_artifact(artifact: &SemanticHttpResponseArtifact) -> bool {
    (100..=599).contains(&artifact.status_code)
        && artifact.headers.len() <= MAX_SEMANTIC_HTTP_HEADERS
        && artifact.headers.iter().all(|header| {
            !header.name.is_empty()
                && header.name == header.name.to_ascii_lowercase()
                && header.name.bytes().all(valid_header_name_byte)
                && header
                    .value
                    .iter()
                    .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
        })
        && artifact.body.len() <= MAX_SEMANTIC_HTTP_RESPONSE_BYTES
        && artifact.body_digest == Digest::of(&artifact.body)
        && artifact.raw_response_digest != Digest::ZERO
        && artifact.raw_response_length > 0
        && artifact.raw_response_length <= MAX_SEMANTIC_HTTP_RESPONSE_BYTES as u64
}

fn canonical_header_line(line: &[u8], is_last: bool) -> Option<&[u8]> {
    let line = if is_last {
        line
    } else {
        line.strip_suffix(b"\r")?
    };
    (!line.contains(&b'\r')).then_some(line)
}

fn parse_status_line(line: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.splitn(3, ' ');
    if parts.next()? != "HTTP/1.1" {
        return None;
    }
    let status = parts.next()?;
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let status = status.parse::<u16>().ok()?;
    (100..=599).contains(&status).then_some(status)
}

fn valid_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Clone)]
pub(crate) struct SemanticHttpCompiler {
    key_id: String,
    key: [u8; 32],
}

impl SemanticHttpCompiler {
    pub(crate) fn new(key_id: String, key: [u8; 32]) -> Result<Self, DenialCode> {
        if !valid_identifier(&key_id) || !valid_secret(&key) {
            return Err(DenialCode::CompilerUnavailable);
        }
        Ok(Self { key_id, key })
    }

    pub(crate) fn issue_proof(
        &self,
        request: &DispatchRequest,
    ) -> Result<CompilerLeaseBinding, DenialCode> {
        let bytes = compile_http(request)?;
        let compiled_length = u64::try_from(bytes.len()).map_err(|_| DenialCode::CompilerDenied)?;
        let compiled_request_digest = Digest::of(&bytes);
        let effect_digest = target_effect_digest(
            request.action_kind,
            request.egress_plane,
            request.resolution_digest,
            compiled_request_digest,
        );
        Ok(CompilerLeaseBinding {
            proof: self.proof(request, &bytes).as_bytes().to_vec(),
            compiled_length,
            compiled_request_digest,
            effect_digest,
        })
    }

    fn proof(&self, request: &DispatchRequest, bytes: &[u8]) -> Digest {
        let mut message = Vec::with_capacity(256);
        message.extend_from_slice(b"faultloom-semantic-http-compiler-v1\0");
        push_string(&mut message, &self.key_id);
        message.extend_from_slice(request.intent_digest.as_bytes());
        message.extend_from_slice(request.semantic_action_digest.as_bytes());
        message.extend_from_slice(request.resolution_digest.as_bytes());
        message.extend_from_slice(request.lease_binding_digest().as_bytes());
        message.extend_from_slice(Digest::of(bytes).as_bytes());
        hmac_sha256(&self.key, &message)
    }
}

impl ActionCompiler for SemanticHttpCompiler {
    fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
        let bytes = compile_http(request)?;
        let expected = self.proof(request, &bytes);
        if !constant_time_eq(expected.as_bytes(), &request.compiler_proof) {
            return Err(DenialCode::CompilerDenied);
        }
        let effect_digest = target_effect_digest(
            request.action_kind,
            request.egress_plane,
            request.resolution_digest,
            Digest::of(&bytes),
        );
        Ok(CompiledAction {
            intent_digest: request.intent_digest,
            action_kind: request.action_kind,
            target: request.target,
            egress_plane: request.egress_plane,
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            request_binding_digest: request.lease_binding_digest(),
            effect_digest,
            bytes,
        })
    }
}

fn compile_http(request: &DispatchRequest) -> Result<Vec<u8>, DenialCode> {
    if request.action_kind != ActionKind::SemanticHttpV1
        || request.egress_plane != EgressPlane::TargetGateway
        || request.protocol != "http"
        || request.method.is_empty()
        || !request
            .method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        || !request.path.starts_with('/')
        || !request
            .path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'?')
        || request.hostname.is_empty()
        || !request
            .hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        return Err(DenialCode::CompilerDenied);
    }
    let mut bytes = Vec::with_capacity(160 + request.path.len() + request.payload.len());
    bytes.extend_from_slice(request.method.as_bytes());
    bytes.push(b' ');
    bytes.extend_from_slice(request.path.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    bytes.extend_from_slice(request.hostname.as_bytes());
    bytes.extend_from_slice(b"\r\nConnection: close\r\nContent-Length: ");
    bytes.extend_from_slice(request.payload.len().to_string().as_bytes());
    bytes.extend_from_slice(b"\r\n\r\n");
    bytes.extend_from_slice(&request.payload);
    Ok(bytes)
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn valid_secret(value: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

fn constant_time_eq(expected: &[u8; 32], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Digest {
    let mut key_block = [0_u8; HMAC_BLOCK_BYTES];
    key_block[..key.len()].copy_from_slice(key);
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in key_block.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(HMAC_BLOCK_BYTES + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = Digest::of(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_BYTES + 32);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(inner_digest.as_bytes());
    Digest::of(&outer)
}
