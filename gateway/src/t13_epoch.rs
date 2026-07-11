use std::collections::BTreeMap;

use crate::Digest;
use crate::ipc::valid_identifier;
use crate::scope::{
    EpochAdmissionError, EpochVerifier, SignedEpochEnvelope, VerifiedScopeEpoch,
    epoch_verifier_private,
};

const RECEIPT_MAGIC: &[u8; 4] = b"FLER";
const RECEIPT_VERSION: u8 = 1;
const MAX_RECEIPT_CLOCK_SKEW_MILLIS: u64 = 1_000;
const MAX_RECEIPT_TTL_MILLIS: u64 = 5_000;
const MAX_AUTHORITY_KEYS: usize = 64;
const MAX_REASON_BYTES: usize = 16_384;
const MAX_INT64: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityKeyStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedAuthorityKey {
    key_id: String,
    status: AuthorityKeyStatus,
}

impl PinnedAuthorityKey {
    pub fn active(key_id: String) -> Result<Self, ChannelTrustError> {
        Self::new(key_id, AuthorityKeyStatus::Active)
    }

    pub fn revoked(key_id: String) -> Result<Self, ChannelTrustError> {
        Self::new(key_id, AuthorityKeyStatus::Revoked)
    }

    fn new(key_id: String, status: AuthorityKeyStatus) -> Result<Self, ChannelTrustError> {
        if !valid_ed25519_key_id(&key_id) {
            return Err(ChannelTrustError::InvalidAuthorityKeyId);
        }
        Ok(Self { key_id, status })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelTrustError {
    InvalidChannelKeyId,
    InvalidGatewayBootId,
    WeakChannelKey,
    WeakGatewayChallenge,
    ReusedBootMaterial,
    EmptyAuthorityTrustStore,
    TooManyAuthorityKeys,
    DuplicateAuthorityKeyId,
    InvalidAuthorityKeyId,
}

pub struct T13ReceiptEpochVerifier {
    channel_key_id: String,
    channel_key: [u8; 32],
    gateway_boot_id: String,
    gateway_challenge: [u8; 32],
    authority_keys: BTreeMap<String, AuthorityKeyStatus>,
}

impl T13ReceiptEpochVerifier {
    pub fn from_gateway_held_key(
        channel_key_id: String,
        channel_key: [u8; 32],
        gateway_boot_id: String,
        gateway_challenge: [u8; 32],
        authority_keys: Vec<PinnedAuthorityKey>,
    ) -> Result<Self, ChannelTrustError> {
        if !valid_identifier(&channel_key_id) {
            return Err(ChannelTrustError::InvalidChannelKeyId);
        }
        if !valid_boot_secret(&channel_key) {
            return Err(ChannelTrustError::WeakChannelKey);
        }
        if !valid_identifier(&gateway_boot_id) {
            return Err(ChannelTrustError::InvalidGatewayBootId);
        }
        if !valid_boot_secret(&gateway_challenge) {
            return Err(ChannelTrustError::WeakGatewayChallenge);
        }
        if channel_key == gateway_challenge {
            return Err(ChannelTrustError::ReusedBootMaterial);
        }
        if authority_keys.is_empty() {
            return Err(ChannelTrustError::EmptyAuthorityTrustStore);
        }
        if authority_keys.len() > MAX_AUTHORITY_KEYS {
            return Err(ChannelTrustError::TooManyAuthorityKeys);
        }
        let mut pinned = BTreeMap::new();
        for authority in authority_keys {
            if pinned.insert(authority.key_id, authority.status).is_some() {
                return Err(ChannelTrustError::DuplicateAuthorityKeyId);
            }
        }
        Ok(Self {
            channel_key_id,
            channel_key,
            gateway_boot_id,
            gateway_challenge,
            authority_keys: pinned,
        })
    }
}

impl epoch_verifier_private::Sealed for T13ReceiptEpochVerifier {}

impl EpochVerifier for T13ReceiptEpochVerifier {
    fn verify(
        &self,
        envelope: &SignedEpochEnvelope,
        now_millis: u64,
    ) -> Result<VerifiedScopeEpoch, EpochAdmissionError> {
        let parsed = ParsedScopeEpoch::parse(envelope.canonical_bytes())?;
        let receipt_bytes = envelope
            .verifier_receipt_bytes()
            .ok_or(EpochAdmissionError::InvalidVerificationReceipt)?;
        let receipt = ParsedReceipt::parse(receipt_bytes)?;
        if receipt.channel_key_id != self.channel_key_id {
            return Err(EpochAdmissionError::UnknownKey);
        }
        if receipt.gateway_boot_id != self.gateway_boot_id
            || receipt.gateway_challenge != self.gateway_challenge
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        match self.authority_keys.get(&parsed.key_id) {
            Some(AuthorityKeyStatus::Active) => {}
            Some(AuthorityKeyStatus::Revoked) => {
                return Err(EpochAdmissionError::TrustAnchorRevoked);
            }
            None => return Err(EpochAdmissionError::UnknownKey),
        }

        let issued_at = ProtocolTime::parse(&parsed.issued_at)?;
        let expires_at = ProtocolTime::parse(&parsed.expires_at)?;
        let signed_at = ProtocolTime::parse(&parsed.signed_at)?;
        let signature_expires_at = ProtocolTime::parse(&parsed.signature_expires_at)?;
        if expires_at.micros <= issued_at.micros
            || signature_expires_at != expires_at
            || signed_at.micros < issued_at.micros
            || parsed.sequence != parsed.epoch
        {
            return Err(EpochAdmissionError::InvalidValidity);
        }

        let payload = parsed.canonical_payload();
        let payload_digest = Digest::of(&payload);
        let envelope_digest = envelope.digest();
        if parsed.payload_digest != digest_text(payload_digest)
            || receipt.envelope_digest != envelope_digest
            || receipt.payload_digest != payload_digest
            || receipt.authority_key_id != parsed.key_id
            || receipt.protocol_version != "0.1.0"
            || receipt.schema_version != "0.1.0"
            || receipt.purpose != "scope_epoch"
            || receipt.canonical_envelope != envelope.canonical_bytes()
            || receipt.grant_id != parsed.grant_id
            || receipt.epoch != parsed.epoch
            || receipt.sequence != parsed.sequence
            || receipt.issued_at != parsed.issued_at
            || receipt.expires_at != parsed.expires_at
            || receipt.revoked != parsed.revoked
            || receipt.revocation_reason != parsed.revocation_reason
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        if receipt.expires_at_millis <= receipt.verified_at_millis
            || receipt.verified_at_millis < issued_at.ceil_millis
            || receipt.verified_at_millis > now_millis.saturating_add(MAX_RECEIPT_CLOCK_SKEW_MILLIS)
            || now_millis >= receipt.expires_at_millis
            || receipt.expires_at_millis > expires_at.floor_millis
            || receipt.expires_at_millis - receipt.verified_at_millis > MAX_RECEIPT_TTL_MILLIS
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }

        let expected_mac = hmac_sha256(&self.channel_key, receipt.authenticated_bytes);
        if !constant_time_equal(expected_mac.as_bytes(), &receipt.mac) {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        let receipt_digest = Digest::of(receipt_bytes);

        Ok(VerifiedScopeEpoch::from_trusted_verifier(
            parsed.grant_id,
            parsed.epoch,
            issued_at.ceil_millis,
            expires_at.floor_millis,
            parsed.revoked,
            parsed.revocation_reason,
            parsed.key_id,
            parsed.sequence,
            envelope_digest,
            payload_digest,
            receipt_digest,
            receipt.gateway_boot_id,
            receipt.nonce,
        ))
    }
}

fn valid_boot_secret(value: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(8).count() == 8
}

fn valid_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> Digest {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(inner_pad.len() + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = Digest::of(&inner);
    let mut outer = Vec::with_capacity(outer_pad.len() + 32);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(inner_digest.as_bytes());
    Digest::of(&outer)
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn valid_ed25519_key_id(value: &str) -> bool {
    value
        .strip_prefix("ed25519:sha256:")
        .is_some_and(valid_lower_hex_digest)
}

fn valid_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_text(digest: Digest) -> String {
    format!("sha256:{}", digest.to_hex())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtocolTime {
    micros: u64,
    floor_millis: u64,
    ceil_millis: u64,
}

impl ProtocolTime {
    fn parse(value: &str) -> Result<Self, EpochAdmissionError> {
        let bytes = value.as_bytes();
        if bytes.len() != 27
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'.'
            || bytes[26] != b'Z'
        {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        let year = decimal(&bytes[0..4])?;
        let month = decimal(&bytes[5..7])?;
        let day = decimal(&bytes[8..10])?;
        let hour = decimal(&bytes[11..13])?;
        let minute = decimal(&bytes[14..16])?;
        let second = decimal(&bytes[17..19])?;
        let fractional = decimal(&bytes[20..26])?;
        if !(1970..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        let days = days_before_year(year)
            .ok_or(EpochAdmissionError::InvalidEnvelope)?
            .checked_add(days_before_month(year, month))
            .and_then(|value| value.checked_add(day - 1))
            .ok_or(EpochAdmissionError::InvalidEnvelope)?;
        let seconds = days
            .checked_mul(86_400)
            .and_then(|value| value.checked_add(hour * 3_600))
            .and_then(|value| value.checked_add(minute * 60))
            .and_then(|value| value.checked_add(second))
            .ok_or(EpochAdmissionError::InvalidEnvelope)?;
        let micros = seconds
            .checked_mul(1_000_000)
            .and_then(|value| value.checked_add(fractional))
            .ok_or(EpochAdmissionError::InvalidEnvelope)?;
        let floor_millis = micros / 1_000;
        let ceil_millis = floor_millis + u64::from(micros % 1_000 != 0);
        Ok(Self {
            micros,
            floor_millis,
            ceil_millis,
        })
    }
}

fn decimal(bytes: &[u8]) -> Result<u64, EpochAdmissionError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(EpochAdmissionError::InvalidEnvelope);
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(EpochAdmissionError::InvalidEnvelope)
    })
}

fn leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_before_year(year: u64) -> Option<u64> {
    let previous = year.checked_sub(1)?;
    let through_previous = previous
        .checked_mul(365)?
        .checked_add(previous / 4)?
        .checked_sub(previous / 100)?
        .checked_add(previous / 400)?;
    let through_1969 = 1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400;
    through_previous.checked_sub(through_1969)
}

fn days_before_month(year: u64, month: u64) -> u64 {
    const CUMULATIVE: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    CUMULATIVE[(month - 1) as usize] + u64::from(month > 2 && leap_year(year))
}

#[derive(Clone, Debug)]
struct ParsedScopeEpoch {
    epoch: u64,
    expires_at: String,
    grant_id: String,
    issued_at: String,
    revocation_reason: Option<String>,
    revoked: bool,
    signature_expires_at: String,
    key_id: String,
    payload_digest: String,
    sequence: u64,
    signature: String,
    signed_at: String,
}

impl ParsedScopeEpoch {
    fn parse(bytes: &[u8]) -> Result<Self, EpochAdmissionError> {
        let mut cursor = JsonCursor::new(bytes)?;
        cursor.literal(b"{\"payload\":{\"epoch\":")?;
        let epoch = cursor.positive_int64()?;
        cursor.literal(b",\"expires_at\":")?;
        let expires_at = cursor.string(27)?;
        cursor.literal(b",\"grant_id\":")?;
        let grant_id = cursor.string(256)?;
        cursor.literal(b",\"issued_at\":")?;
        let issued_at = cursor.string(27)?;
        cursor.literal(b",\"revocation_reason\":")?;
        let revocation_reason = cursor.nullable_string(MAX_REASON_BYTES)?;
        cursor.literal(b",\"revoked\":")?;
        let revoked = cursor.boolean()?;
        cursor.literal(b",\"schema_version\":\"0.1.0\"},\"schema_version\":\"0.1.0\",\"signature\":{\"algorithm\":\"Ed25519\",\"expires_at\":")?;
        let signature_expires_at = cursor.string(27)?;
        cursor.literal(b",\"key_id\":")?;
        let key_id = cursor.string(79)?;
        cursor.literal(b",\"payload_digest\":")?;
        let payload_digest = cursor.string(71)?;
        cursor.literal(b",\"protocol_version\":\"0.1.0\",\"purpose\":\"scope_epoch\",\"schema_version\":\"0.1.0\",\"sequence\":")?;
        let sequence = cursor.positive_int64()?;
        cursor.literal(b",\"signature\":")?;
        let signature = cursor.string(86)?;
        cursor.literal(b",\"signed_at\":")?;
        let signed_at = cursor.string(27)?;
        cursor.literal(b"}}")?;
        cursor.finish()?;

        if !valid_identifier(&grant_id)
            || !valid_ed25519_key_id(&key_id)
            || !payload_digest
                .strip_prefix("sha256:")
                .is_some_and(valid_lower_hex_digest)
            || !valid_base64url_signature(&signature)
            || revoked != revocation_reason.is_some()
            || revocation_reason
                .as_ref()
                .is_some_and(|reason| reason.trim() != reason)
        {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        let parsed = Self {
            epoch,
            expires_at,
            grant_id,
            issued_at,
            revocation_reason,
            revoked,
            signature_expires_at,
            key_id,
            payload_digest,
            sequence,
            signature,
            signed_at,
        };
        if parsed.canonical_envelope() != bytes {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        Ok(parsed)
    }

    fn canonical_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(b"{\"epoch\":");
        bytes.extend_from_slice(self.epoch.to_string().as_bytes());
        bytes.extend_from_slice(b",\"expires_at\":");
        push_json_string(&mut bytes, &self.expires_at);
        bytes.extend_from_slice(b",\"grant_id\":");
        push_json_string(&mut bytes, &self.grant_id);
        bytes.extend_from_slice(b",\"issued_at\":");
        push_json_string(&mut bytes, &self.issued_at);
        bytes.extend_from_slice(b",\"revocation_reason\":");
        match &self.revocation_reason {
            Some(reason) => push_json_string(&mut bytes, reason),
            None => bytes.extend_from_slice(b"null"),
        }
        bytes.extend_from_slice(if self.revoked {
            b",\"revoked\":true,\"schema_version\":\"0.1.0\"}"
        } else {
            b",\"revoked\":false,\"schema_version\":\"0.1.0\"}"
        });
        bytes
    }

    fn canonical_envelope(&self) -> Vec<u8> {
        let payload = self.canonical_payload();
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(b"{\"payload\":");
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(b",\"schema_version\":\"0.1.0\",\"signature\":{\"algorithm\":\"Ed25519\",\"expires_at\":");
        push_json_string(&mut bytes, &self.signature_expires_at);
        bytes.extend_from_slice(b",\"key_id\":");
        push_json_string(&mut bytes, &self.key_id);
        bytes.extend_from_slice(b",\"payload_digest\":");
        push_json_string(&mut bytes, &self.payload_digest);
        bytes.extend_from_slice(b",\"protocol_version\":\"0.1.0\",\"purpose\":\"scope_epoch\",\"schema_version\":\"0.1.0\",\"sequence\":");
        bytes.extend_from_slice(self.sequence.to_string().as_bytes());
        bytes.extend_from_slice(b",\"signature\":");
        push_json_string(&mut bytes, &self.signature);
        bytes.extend_from_slice(b",\"signed_at\":");
        push_json_string(&mut bytes, &self.signed_at);
        bytes.extend_from_slice(b"}}");
        bytes
    }
}

fn valid_base64url_signature(value: &str) -> bool {
    value.len() == 86
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

struct JsonCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> JsonCursor<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, EpochAdmissionError> {
        std::str::from_utf8(bytes).map_err(|_| EpochAdmissionError::InvalidEnvelope)?;
        Ok(Self { bytes, offset: 0 })
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), EpochAdmissionError> {
        let end = self
            .offset
            .checked_add(expected.len())
            .ok_or(EpochAdmissionError::InvalidEnvelope)?;
        if self.bytes.get(self.offset..end) != Some(expected) {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        self.offset = end;
        Ok(())
    }

    fn positive_int64(&mut self) -> Result<u64, EpochAdmissionError> {
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset += 1;
        }
        let digits = self
            .bytes
            .get(start..self.offset)
            .ok_or(EpochAdmissionError::InvalidEnvelope)?;
        if digits.is_empty() || digits[0] == b'0' {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        let value = decimal(digits)?;
        if value == 0 || value > MAX_INT64 {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        Ok(value)
    }

    fn boolean(&mut self) -> Result<bool, EpochAdmissionError> {
        if self.bytes[self.offset..].starts_with(b"true") {
            self.offset += 4;
            Ok(true)
        } else if self.bytes[self.offset..].starts_with(b"false") {
            self.offset += 5;
            Ok(false)
        } else {
            Err(EpochAdmissionError::InvalidEnvelope)
        }
    }

    fn nullable_string(&mut self, maximum: usize) -> Result<Option<String>, EpochAdmissionError> {
        if self.bytes[self.offset..].starts_with(b"null") {
            self.offset += 4;
            return Ok(None);
        }
        self.string(maximum).map(Some)
    }

    fn string(&mut self, maximum: usize) -> Result<String, EpochAdmissionError> {
        self.literal(b"\"")?;
        let mut value = String::new();
        loop {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or(EpochAdmissionError::InvalidEnvelope)?;
            match byte {
                b'\"' => {
                    self.offset += 1;
                    break;
                }
                b'\\' => {
                    self.offset += 1;
                    let escaped = *self
                        .bytes
                        .get(self.offset)
                        .ok_or(EpochAdmissionError::InvalidEnvelope)?;
                    self.offset += 1;
                    match escaped {
                        b'\"' => value.push('\"'),
                        b'\\' => value.push('\\'),
                        b'/' => value.push('/'),
                        b'b' => value.push('\u{0008}'),
                        b'f' => value.push('\u{000c}'),
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        b'u' => {
                            let end = self
                                .offset
                                .checked_add(4)
                                .ok_or(EpochAdmissionError::InvalidEnvelope)?;
                            let digits = self
                                .bytes
                                .get(self.offset..end)
                                .ok_or(EpochAdmissionError::InvalidEnvelope)?;
                            let codepoint = hex_u16(digits)?;
                            self.offset = end;
                            value.push(
                                char::from_u32(u32::from(codepoint))
                                    .ok_or(EpochAdmissionError::InvalidEnvelope)?,
                            );
                        }
                        _ => return Err(EpochAdmissionError::InvalidEnvelope),
                    }
                }
                0x00..=0x1f => return Err(EpochAdmissionError::InvalidEnvelope),
                _ => {
                    let remainder = std::str::from_utf8(&self.bytes[self.offset..])
                        .map_err(|_| EpochAdmissionError::InvalidEnvelope)?;
                    let character = remainder
                        .chars()
                        .next()
                        .ok_or(EpochAdmissionError::InvalidEnvelope)?;
                    value.push(character);
                    self.offset += character.len_utf8();
                }
            }
            if value.len() > maximum {
                return Err(EpochAdmissionError::InvalidEnvelope);
            }
        }
        if value.is_empty() || value.len() > maximum {
            return Err(EpochAdmissionError::InvalidEnvelope);
        }
        Ok(value)
    }

    fn finish(self) -> Result<(), EpochAdmissionError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EpochAdmissionError::InvalidEnvelope)
        }
    }
}

fn hex_u16(bytes: &[u8]) -> Result<u16, EpochAdmissionError> {
    bytes.iter().try_fold(0_u16, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a') + 10,
            b'A'..=b'F' => u16::from(byte - b'A') + 10,
            _ => return Err(EpochAdmissionError::InvalidEnvelope),
        };
        Ok((value << 4) | digit)
    })
}

fn push_json_string(output: &mut Vec<u8>, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push(b'\"');
    for character in value.chars() {
        match character {
            '\"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{0008}' => output.extend_from_slice(b"\\b"),
            '\u{000c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            '\u{0000}'..='\u{001f}' => {
                let value = character as u8;
                output.extend_from_slice(b"\\u00");
                output.push(HEX[(value >> 4) as usize]);
                output.push(HEX[(value & 0x0f) as usize]);
            }
            _ => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'\"');
}

struct ParsedReceipt<'a> {
    channel_key_id: String,
    gateway_boot_id: String,
    gateway_challenge: [u8; 32],
    protocol_version: String,
    schema_version: String,
    purpose: String,
    canonical_envelope: &'a [u8],
    envelope_digest: Digest,
    payload_digest: Digest,
    authority_key_id: String,
    grant_id: String,
    epoch: u64,
    sequence: u64,
    issued_at: String,
    expires_at: String,
    revoked: bool,
    revocation_reason: Option<String>,
    verified_at_millis: u64,
    expires_at_millis: u64,
    nonce: [u8; 16],
    authenticated_bytes: &'a [u8],
    mac: [u8; 32],
}

impl<'a> ParsedReceipt<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, EpochAdmissionError> {
        let mut cursor = BinaryCursor::new(bytes);
        cursor.literal(RECEIPT_MAGIC)?;
        if cursor.u8()? != RECEIPT_VERSION {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        let channel_key_id = cursor.string(256)?;
        let gateway_boot_id = cursor.string(256)?;
        let gateway_challenge = cursor.array()?;
        let protocol_version = cursor.string(256)?;
        let schema_version = cursor.string(256)?;
        let purpose = cursor.string(256)?;
        let canonical_envelope = cursor.length_prefixed_bytes()?;
        let envelope_digest = Digest::from_bytes(cursor.array()?);
        let payload_digest = Digest::from_bytes(cursor.array()?);
        let authority_key_id = cursor.string(256)?;
        let grant_id = cursor.string(256)?;
        let epoch = cursor.u64()?;
        let sequence = cursor.u64()?;
        let issued_at = cursor.string(256)?;
        let expires_at = cursor.string(256)?;
        let revoked = match cursor.u8()? {
            0 => false,
            1 => true,
            _ => return Err(EpochAdmissionError::InvalidVerificationReceipt),
        };
        let revocation_reason = cursor.optional_string(MAX_REASON_BYTES)?;
        let verified_at_millis = cursor.u64()?;
        let expires_at_millis = cursor.u64()?;
        let nonce = cursor.array()?;
        let authenticated_length = cursor.offset;
        let mac = cursor.array()?;
        cursor.finish()?;
        if !valid_identifier(&channel_key_id)
            || !valid_identifier(&gateway_boot_id)
            || !valid_ed25519_key_id(&authority_key_id)
            || !valid_identifier(&grant_id)
            || epoch == 0
            || epoch > MAX_INT64
            || sequence == 0
            || sequence > MAX_INT64
            || revoked != revocation_reason.is_some()
            || !valid_nonce(&nonce)
        {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        Ok(Self {
            channel_key_id,
            gateway_boot_id,
            gateway_challenge,
            protocol_version,
            schema_version,
            purpose,
            canonical_envelope,
            envelope_digest,
            payload_digest,
            authority_key_id,
            grant_id,
            epoch,
            sequence,
            issued_at,
            expires_at,
            revoked,
            revocation_reason,
            verified_at_millis,
            expires_at_millis,
            nonce,
            authenticated_bytes: &bytes[..authenticated_length],
            mac,
        })
    }
}

struct BinaryCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], EpochAdmissionError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EpochAdmissionError::InvalidVerificationReceipt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EpochAdmissionError::InvalidVerificationReceipt)?;
        self.offset = end;
        Ok(value)
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), EpochAdmissionError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        }
    }

    fn u8(&mut self) -> Result<u8, EpochAdmissionError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, EpochAdmissionError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, EpochAdmissionError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], EpochAdmissionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| EpochAdmissionError::InvalidVerificationReceipt)
    }

    fn string(&mut self, maximum: usize) -> Result<String, EpochAdmissionError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length == 0 || length > maximum {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| EpochAdmissionError::InvalidVerificationReceipt)
    }

    fn optional_string(&mut self, maximum: usize) -> Result<Option<String>, EpochAdmissionError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.string(maximum).map(Some),
            _ => Err(EpochAdmissionError::InvalidVerificationReceipt),
        }
    }

    fn length_prefixed_bytes(&mut self) -> Result<&'a [u8], EpochAdmissionError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| EpochAdmissionError::InvalidVerificationReceipt)?;
        if length == 0 || length > 16_384 {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), EpochAdmissionError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHORITY_KEY_ID: &str =
        "ed25519:sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c";
    const CHANNEL_KEY_ID: &str = "gateway-channel:test";
    const GATEWAY_BOOT_ID: &str = "gateway-boot:test-1";
    const CHANNEL_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const GATEWAY_CHALLENGE: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const RECEIPT_NONCE: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];

    fn golden_envelope_bytes() -> Vec<u8> {
        include_bytes!(
            "../../packages/protocol/tests/fixtures/scope_epoch_signed_envelope_v0_1.json"
        )
        .strip_suffix(b"\n")
        .unwrap()
        .to_vec()
    }

    fn golden_now() -> u64 {
        ProtocolTime::parse("2030-01-02T03:04:05.678901Z")
            .unwrap()
            .ceil_millis
    }

    fn receipt(envelope: &[u8], key: &[u8; 32], authority_key_id: &str, sequence: u64) -> Vec<u8> {
        let parsed = ParsedScopeEpoch::parse(envelope).unwrap();
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(RECEIPT_MAGIC);
        bytes.push(RECEIPT_VERSION);
        push_binary_string(&mut bytes, CHANNEL_KEY_ID);
        push_binary_string(&mut bytes, GATEWAY_BOOT_ID);
        bytes.extend_from_slice(&GATEWAY_CHALLENGE);
        push_binary_string(&mut bytes, "0.1.0");
        push_binary_string(&mut bytes, "0.1.0");
        push_binary_string(&mut bytes, "scope_epoch");
        bytes.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        bytes.extend_from_slice(envelope);
        bytes.extend_from_slice(Digest::of(envelope).as_bytes());
        bytes.extend_from_slice(Digest::of(&parsed.canonical_payload()).as_bytes());
        push_binary_string(&mut bytes, authority_key_id);
        push_binary_string(&mut bytes, &parsed.grant_id);
        bytes.extend_from_slice(&parsed.epoch.to_be_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());
        push_binary_string(&mut bytes, &parsed.issued_at);
        push_binary_string(&mut bytes, &parsed.expires_at);
        bytes.push(u8::from(parsed.revoked));
        match &parsed.revocation_reason {
            Some(reason) => {
                bytes.push(1);
                push_binary_string(&mut bytes, reason);
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&golden_now().to_be_bytes());
        bytes.extend_from_slice(&(golden_now() + 4_000).to_be_bytes());
        bytes.extend_from_slice(&RECEIPT_NONCE);
        let mac = hmac_sha256(key, &bytes);
        bytes.extend_from_slice(mac.as_bytes());
        bytes
    }

    fn synthetic_revocation_envelope(reason: String) -> Vec<u8> {
        let mut parsed = ParsedScopeEpoch {
            epoch: 8,
            expires_at: "2030-01-02T03:14:05.678901Z".to_owned(),
            grant_id: "grant.golden".to_owned(),
            issued_at: "2030-01-02T03:04:05.678000Z".to_owned(),
            revocation_reason: Some(reason),
            revoked: true,
            signature_expires_at: "2030-01-02T03:14:05.678901Z".to_owned(),
            key_id: AUTHORITY_KEY_ID.to_owned(),
            payload_digest: String::new(),
            sequence: 8,
            signature: "A".repeat(86),
            signed_at: "2030-01-02T03:04:05.678901Z".to_owned(),
        };
        parsed.payload_digest = digest_text(Digest::of(&parsed.canonical_payload()));
        parsed.canonical_envelope()
    }

    fn push_binary_string(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }

    fn replace_receipt_times_and_resign(
        mut receipt: Vec<u8>,
        verified_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let authenticated_length = receipt.len() - 32;
        let verified_offset = authenticated_length - 32;
        receipt[verified_offset..verified_offset + 8].copy_from_slice(&verified_at.to_be_bytes());
        receipt[verified_offset + 8..verified_offset + 16]
            .copy_from_slice(&expires_at.to_be_bytes());
        let mac = hmac_sha256(&CHANNEL_KEY, &receipt[..authenticated_length]);
        receipt[authenticated_length..].copy_from_slice(mac.as_bytes());
        receipt
    }

    fn verifier(status: AuthorityKeyStatus) -> T13ReceiptEpochVerifier {
        let authority = match status {
            AuthorityKeyStatus::Active => PinnedAuthorityKey::active(AUTHORITY_KEY_ID.to_owned()),
            AuthorityKeyStatus::Revoked => PinnedAuthorityKey::revoked(AUTHORITY_KEY_ID.to_owned()),
        }
        .unwrap();
        T13ReceiptEpochVerifier::from_gateway_held_key(
            CHANNEL_KEY_ID.to_owned(),
            CHANNEL_KEY,
            GATEWAY_BOOT_ID.to_owned(),
            GATEWAY_CHALLENGE,
            vec![authority],
        )
        .unwrap()
    }

    fn golden() -> SignedEpochEnvelope {
        let envelope = golden_envelope_bytes();
        let receipt = decode_hex(include_str!(
            "../../packages/protocol/tests/fixtures/scope_epoch_gateway_receipt_v0_1.hex"
        ));
        SignedEpochEnvelope::with_verifier_receipt(envelope, receipt).unwrap()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let value = value.trim();
        assert!(value.len().is_multiple_of(2));
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn authenticated_t13_receipt_verifies_exact_protocol_fixture() {
        let verifier = verifier(AuthorityKeyStatus::Active);
        let verified = verifier.verify(&golden(), golden_now()).unwrap();
        assert_eq!(verified.epoch(), 7);
        assert_eq!(verified.grant_id(), "grant.golden");
        assert!(verifier.verify(&golden(), golden_now()).is_ok());
    }

    #[test]
    fn envelope_and_every_receipt_binding_fail_closed_on_tamper() {
        let original = golden();
        for offset in [0, 6, 40, original.canonical_bytes().len() - 2] {
            let mut bytes = original.canonical_bytes().to_vec();
            bytes[offset] ^= 1;
            let tampered = SignedEpochEnvelope::with_verifier_receipt(
                bytes,
                original.verifier_receipt_bytes().unwrap().to_vec(),
            )
            .unwrap();
            assert!(
                verifier(AuthorityKeyStatus::Active)
                    .verify(&tampered, golden_now())
                    .is_err()
            );
        }

        let receipt_bytes = original.verifier_receipt_bytes().unwrap();
        for offset in [0, 5, 30, receipt_bytes.len() - 1] {
            let mut bytes = receipt_bytes.to_vec();
            bytes[offset] ^= 1;
            let tampered = SignedEpochEnvelope::with_verifier_receipt(
                original.canonical_bytes().to_vec(),
                bytes,
            )
            .unwrap();
            assert!(
                verifier(AuthorityKeyStatus::Active)
                    .verify(&tampered, golden_now())
                    .is_err()
            );
        }
    }

    #[test]
    fn wrong_channel_and_unknown_or_revoked_authority_keys_are_rejected() {
        let envelope = golden_envelope_bytes();
        let wrong_receipt = receipt(&envelope, &[0x33; 32], AUTHORITY_KEY_ID, 7);
        let wrong = SignedEpochEnvelope::with_verifier_receipt(envelope, wrong_receipt).unwrap();
        assert_eq!(
            verifier(AuthorityKeyStatus::Active).verify(&wrong, golden_now()),
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        );

        let unknown = PinnedAuthorityKey::active(
            "ed25519:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        )
        .unwrap();
        let unknown_verifier = T13ReceiptEpochVerifier::from_gateway_held_key(
            CHANNEL_KEY_ID.to_owned(),
            CHANNEL_KEY,
            GATEWAY_BOOT_ID.to_owned(),
            GATEWAY_CHALLENGE,
            vec![unknown],
        )
        .unwrap();
        assert_eq!(
            unknown_verifier.verify(&golden(), golden_now()),
            Err(EpochAdmissionError::UnknownKey)
        );
        assert_eq!(
            verifier(AuthorityKeyStatus::Revoked).verify(&golden(), golden_now()),
            Err(EpochAdmissionError::TrustAnchorRevoked)
        );
    }

    #[test]
    fn trust_configuration_and_noncanonical_envelopes_are_rejected() {
        assert_eq!(
            T13ReceiptEpochVerifier::from_gateway_held_key(
                CHANNEL_KEY_ID.to_owned(),
                [0; 32],
                GATEWAY_BOOT_ID.to_owned(),
                GATEWAY_CHALLENGE,
                vec![PinnedAuthorityKey::active(AUTHORITY_KEY_ID.to_owned()).unwrap()],
            )
            .err(),
            Some(ChannelTrustError::WeakChannelKey)
        );
        assert_eq!(
            T13ReceiptEpochVerifier::from_gateway_held_key(
                CHANNEL_KEY_ID.to_owned(),
                CHANNEL_KEY,
                GATEWAY_BOOT_ID.to_owned(),
                [0; 32],
                vec![PinnedAuthorityKey::active(AUTHORITY_KEY_ID.to_owned()).unwrap()],
            )
            .err(),
            Some(ChannelTrustError::WeakGatewayChallenge)
        );
        assert_eq!(
            T13ReceiptEpochVerifier::from_gateway_held_key(
                CHANNEL_KEY_ID.to_owned(),
                CHANNEL_KEY,
                GATEWAY_BOOT_ID.to_owned(),
                CHANNEL_KEY,
                vec![PinnedAuthorityKey::active(AUTHORITY_KEY_ID.to_owned()).unwrap()],
            )
            .err(),
            Some(ChannelTrustError::ReusedBootMaterial)
        );
        let authority = PinnedAuthorityKey::active(AUTHORITY_KEY_ID.to_owned()).unwrap();
        assert_eq!(
            T13ReceiptEpochVerifier::from_gateway_held_key(
                CHANNEL_KEY_ID.to_owned(),
                CHANNEL_KEY,
                GATEWAY_BOOT_ID.to_owned(),
                GATEWAY_CHALLENGE,
                vec![authority.clone(), authority],
            )
            .err(),
            Some(ChannelTrustError::DuplicateAuthorityKeyId)
        );

        let original = golden();
        let mut whitespace = original.canonical_bytes().to_vec();
        whitespace.insert(1, b' ');
        let noncanonical = SignedEpochEnvelope::with_verifier_receipt(
            whitespace,
            original.verifier_receipt_bytes().unwrap().to_vec(),
        )
        .unwrap();
        assert_eq!(
            verifier(AuthorityKeyStatus::Active).verify(&noncanonical, golden_now()),
            Err(EpochAdmissionError::InvalidEnvelope)
        );
    }

    #[test]
    fn receipt_from_a_previous_gateway_boot_is_rejected() {
        let authority = PinnedAuthorityKey::active(AUTHORITY_KEY_ID.to_owned()).unwrap();
        let restarted = T13ReceiptEpochVerifier::from_gateway_held_key(
            CHANNEL_KEY_ID.to_owned(),
            CHANNEL_KEY,
            "gateway-boot:test-2".to_owned(),
            GATEWAY_CHALLENGE,
            vec![authority.clone()],
        )
        .unwrap();
        assert_eq!(
            restarted.verify(&golden(), golden_now()),
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        );

        let mut next_challenge = GATEWAY_CHALLENGE;
        next_challenge.rotate_left(1);
        let rechallenged = T13ReceiptEpochVerifier::from_gateway_held_key(
            CHANNEL_KEY_ID.to_owned(),
            CHANNEL_KEY,
            GATEWAY_BOOT_ID.to_owned(),
            next_challenge,
            vec![authority],
        )
        .unwrap();
        assert_eq!(
            rechallenged.verify(&golden(), golden_now()),
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        );
    }

    #[test]
    fn trusted_channel_accepts_protocol_bounded_unicode_revocation_reason() {
        let envelope = synthetic_revocation_envelope("철회".repeat(1_000));
        assert!(envelope.len() < 16_384);
        let receipt = receipt(&envelope, &CHANNEL_KEY, AUTHORITY_KEY_ID, 8);
        assert!(receipt.len() < 36_864);
        let signed = SignedEpochEnvelope::with_verifier_receipt(envelope, receipt).unwrap();
        assert!(
            verifier(AuthorityKeyStatus::Active)
                .verify(&signed, golden_now())
                .is_ok()
        );
    }

    #[test]
    fn stale_future_oversized_ttl_and_weak_nonce_receipts_are_rejected() {
        let original = golden();
        let canonical = original.canonical_bytes().to_vec();
        let receipt = original.verifier_receipt_bytes().unwrap().to_vec();
        for invalid in [
            replace_receipt_times_and_resign(receipt.clone(), golden_now() - 1_000, golden_now()),
            replace_receipt_times_and_resign(
                receipt.clone(),
                golden_now() + MAX_RECEIPT_CLOCK_SKEW_MILLIS + 1,
                golden_now() + MAX_RECEIPT_CLOCK_SKEW_MILLIS + 2,
            ),
            replace_receipt_times_and_resign(
                receipt.clone(),
                golden_now(),
                golden_now() + MAX_RECEIPT_TTL_MILLIS + 1,
            ),
        ] {
            let envelope =
                SignedEpochEnvelope::with_verifier_receipt(canonical.clone(), invalid).unwrap();
            assert_eq!(
                verifier(AuthorityKeyStatus::Active).verify(&envelope, golden_now()),
                Err(EpochAdmissionError::InvalidVerificationReceipt)
            );
        }

        let mut weak_nonce = receipt;
        let authenticated_length = weak_nonce.len() - 32;
        weak_nonce[authenticated_length - 16..authenticated_length].fill(0);
        let mac = hmac_sha256(&CHANNEL_KEY, &weak_nonce[..authenticated_length]);
        weak_nonce[authenticated_length..].copy_from_slice(mac.as_bytes());
        let envelope = SignedEpochEnvelope::with_verifier_receipt(canonical, weak_nonce).unwrap();
        assert_eq!(
            verifier(AuthorityKeyStatus::Active).verify(&envelope, golden_now()),
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        );
    }

    #[test]
    fn timestamp_calendar_and_submillisecond_rounding_are_fail_closed() {
        let leap = ProtocolTime::parse("2024-02-29T00:00:00.000001Z").unwrap();
        assert_eq!(leap.ceil_millis, leap.floor_millis + 1);
        assert_eq!(
            ProtocolTime::parse("2023-02-29T00:00:00.000000Z"),
            Err(EpochAdmissionError::InvalidEnvelope)
        );
        assert_eq!(
            ProtocolTime::parse("2030-01-02T03:04:60.000000Z"),
            Err(EpochAdmissionError::InvalidEnvelope)
        );
    }

    #[test]
    fn hmac_matches_independent_python_vector_for_a_32_byte_key() {
        let digest = hmac_sha256(&[0x0b; 32], b"Hi There");
        assert_eq!(
            digest.to_hex(),
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
        );
    }
}
