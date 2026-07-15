use std::net::{IpAddr, SocketAddr};

use faultloom_gateway::Digest;
use faultloom_gateway::ipc::DenialCode;

const MAX_FRAME_BYTES: usize = 65_536;
const MAX_TEXT_BYTES: usize = 4_096;

pub(super) struct Wire(Vec<u8>);

impl Wire {
    pub(super) fn new(magic: &[u8; 4], version: u8, kind: u8) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&[version, kind]);
        Self(bytes)
    }

    pub(super) fn byte(&mut self, value: u8) {
        self.0.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn key(&mut self, value: [u8; 32]) {
        self.0.extend_from_slice(&value);
    }

    pub(super) fn nonce(&mut self, value: [u8; 16]) {
        self.0.extend_from_slice(&value);
    }

    pub(super) fn digest(&mut self, value: Digest) {
        self.0.extend_from_slice(value.as_bytes());
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), DenialCode> {
        self.u32(u32::try_from(value.len()).map_err(|_| DenialCode::InvalidRequest)?);
        self.0.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn string(&mut self, value: &str) -> Result<(), DenialCode> {
        if value.len() > MAX_TEXT_BYTES {
            return Err(DenialCode::InvalidRequest);
        }
        self.bytes(value.as_bytes())
    }

    pub(super) fn optional_string(&mut self, value: Option<&str>) -> Result<(), DenialCode> {
        self.byte(u8::from(value.is_some()));
        value.map_or(Ok(()), |text| self.string(text))
    }

    pub(super) fn socket(&mut self, value: SocketAddr) {
        match value.ip() {
            IpAddr::V4(address) => {
                self.byte(4);
                self.0.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                self.byte(6);
                self.0.extend_from_slice(&address.octets());
            }
        }
        self.u16(value.port());
    }

    pub(super) fn finish(self) -> Result<Vec<u8>, DenialCode> {
        (self.0.len() <= MAX_FRAME_BYTES)
            .then_some(self.0)
            .ok_or(DenialCode::InvalidRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_limit_matches_the_installed_decoder_boundary() {
        let mut admitted = Wire::new(b"TEST", 1, 1);
        let mut rejected = Wire::new(b"TEST", 1, 1);

        assert_eq!(admitted.string(&"x".repeat(MAX_TEXT_BYTES)), Ok(()));
        assert_eq!(
            rejected.string(&"x".repeat(MAX_TEXT_BYTES + 1)),
            Err(DenialCode::InvalidRequest)
        );
    }
}
