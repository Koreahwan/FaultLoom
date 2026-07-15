use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use faultloom_gateway::Digest;

use crate::bootstrap_fixture::protocol_time;

pub struct EpochReceiptIssuer {
    pub channel_key_id: String,
    pub channel_key: [u8; 32],
    pub gateway_boot_id: String,
    pub gateway_challenge: [u8; 32],
    pub authority_signing_key: [u8; 32],
    pub grant_id: String,
}

struct IssuedEpoch {
    envelope: Vec<u8>,
    payload: Vec<u8>,
    authority_key_id: String,
    epoch: u64,
    issued_at: String,
    expires_at: String,
    reason: Option<&'static str>,
    verified_at_millis: u64,
    epoch_expires_at_millis: u64,
}

impl EpochReceiptIssuer {
    pub fn issue(
        &self,
        epoch: u64,
        revoked: bool,
        now_millis: u64,
        expires_at_millis: u64,
        nonce_seed: u8,
    ) -> (Vec<u8>, Vec<u8>) {
        let issued_at_millis = now_millis.saturating_sub(1_000);
        let issued_at = protocol_time(issued_at_millis);
        let signed_at = protocol_time(now_millis);
        let expires_at = protocol_time(expires_at_millis);
        let reason = revoked.then_some("operator-revoked");
        let payload = format!(
            "{{\"epoch\":{epoch},\"expires_at\":\"{expires_at}\",\"grant_id\":\"{}\",\"issued_at\":\"{issued_at}\",\"revocation_reason\":{},\"revoked\":{},\"schema_version\":\"0.1.0\"}}",
            self.grant_id,
            reason.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\"")),
            if revoked { "true" } else { "false" },
        );
        let payload_digest = format!("sha256:{}", Digest::of(payload.as_bytes()).to_hex());
        let signing_key = SigningKey::from_bytes(&self.authority_signing_key);
        let authority_key_id = format!(
            "ed25519:sha256:{}",
            Digest::of(signing_key.verifying_key().as_bytes()).to_hex()
        );
        let signing_document = format!(
            "{{\"algorithm\":\"Ed25519\",\"expires_at\":\"{expires_at}\",\"key_id\":\"{authority_key_id}\",\"payload\":{payload},\"payload_digest\":\"{payload_digest}\",\"protocol_version\":\"0.1.0\",\"purpose\":\"scope_epoch\",\"sequence\":{epoch},\"signed_at\":\"{signed_at}\"}}"
        );
        let signature =
            signature_base64url(&signing_key.sign(signing_document.as_bytes()).to_bytes());
        let envelope = format!(
            "{{\"payload\":{payload},\"schema_version\":\"0.1.0\",\"signature\":{{\"algorithm\":\"Ed25519\",\"expires_at\":\"{expires_at}\",\"key_id\":\"{authority_key_id}\",\"payload_digest\":\"{payload_digest}\",\"protocol_version\":\"0.1.0\",\"purpose\":\"scope_epoch\",\"schema_version\":\"0.1.0\",\"sequence\":{epoch},\"signature\":\"{signature}\",\"signed_at\":\"{signed_at}\"}}}}",
        )
        .into_bytes();
        let issued = IssuedEpoch {
            envelope,
            payload: payload.into_bytes(),
            authority_key_id,
            epoch,
            issued_at,
            expires_at,
            reason,
            verified_at_millis: now_millis,
            epoch_expires_at_millis: expires_at_millis,
        };
        let receipt = self.receipt(&issued, nonce_seed);
        (issued.envelope, receipt)
    }

    fn receipt(&self, issued: &IssuedEpoch, nonce_seed: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1_024);
        bytes.extend_from_slice(b"FLER");
        bytes.push(1);
        push_string(&mut bytes, &self.channel_key_id);
        push_string(&mut bytes, &self.gateway_boot_id);
        bytes.extend_from_slice(&self.gateway_challenge);
        push_string(&mut bytes, "0.1.0");
        push_string(&mut bytes, "0.1.0");
        push_string(&mut bytes, "scope_epoch");
        bytes.extend_from_slice(
            &u32::try_from(issued.envelope.len())
                .expect("fixture envelope length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&issued.envelope);
        bytes.extend_from_slice(Digest::of(&issued.envelope).as_bytes());
        bytes.extend_from_slice(Digest::of(&issued.payload).as_bytes());
        push_string(&mut bytes, &issued.authority_key_id);
        push_string(&mut bytes, &self.grant_id);
        bytes.extend_from_slice(&issued.epoch.to_be_bytes());
        bytes.extend_from_slice(&issued.epoch.to_be_bytes());
        push_string(&mut bytes, &issued.issued_at);
        push_string(&mut bytes, &issued.expires_at);
        bytes.push(u8::from(issued.reason.is_some()));
        match issued.reason {
            Some(reason) => {
                bytes.push(1);
                push_string(&mut bytes, reason);
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&issued.verified_at_millis.to_be_bytes());
        bytes.extend_from_slice(
            &issued
                .verified_at_millis
                .saturating_add(4_000)
                .min(issued.epoch_expires_at_millis)
                .to_be_bytes(),
        );
        let nonce: [u8; 16] = std::array::from_fn(|index| {
            nonce_seed.wrapping_add(u8::try_from(index).expect("receipt nonce index"))
        });
        bytes.extend_from_slice(&nonce);
        let mac = hmac_sha256(&self.channel_key, &bytes);
        bytes.extend_from_slice(mac.as_bytes());
        bytes
    }
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("fixture receipt string length")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> Digest {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = Digest::of(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(inner_digest.as_bytes());
    Digest::of(&outer)
}

fn signature_base64url(raw: &[u8; 64]) -> String {
    let mut encoded = [0_u8; 86];
    let length = URL_SAFE_NO_PAD
        .encode_slice(raw, &mut encoded)
        .expect("fixture signature base64url");
    std::str::from_utf8(&encoded[..length])
        .expect("base64url UTF-8")
        .to_owned()
}
