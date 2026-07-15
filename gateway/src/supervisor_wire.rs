use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::Digest;
use crate::ipc::DenialCode;

pub(crate) const MAX_SUPERVISOR_FRAME_BYTES: usize = 65_536;
const MAX_TEXT_BYTES: usize = 4_096;

pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(magic: &[u8; 4], version: u8, kind: u8) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(magic);
        bytes.push(version);
        bytes.push(kind);
        Self { bytes }
    }

    pub(crate) fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn digest(&mut self, value: Digest) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn nonce(&mut self, value: [u8; 16]) {
        self.bytes.extend_from_slice(&value);
    }

    pub(crate) fn key(&mut self, value: [u8; 32]) {
        self.bytes.extend_from_slice(&value);
    }

    pub(crate) fn string(&mut self, value: &str) -> Result<(), DenialCode> {
        if value.len() > MAX_TEXT_BYTES {
            return Err(DenialCode::InvalidRequest);
        }
        self.bytes(value.as_bytes())
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), DenialCode> {
        let length = u32::try_from(value.len()).map_err(|_| DenialCode::InvalidRequest)?;
        self.u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn optional_string(&mut self, value: Option<&str>) -> Result<(), DenialCode> {
        self.bool(value.is_some());
        if let Some(value) = value {
            self.string(value)?;
        }
        Ok(())
    }

    pub(crate) fn optional_digest(&mut self, value: Option<Digest>) {
        self.bool(value.is_some());
        if let Some(value) = value {
            self.digest(value);
        }
    }

    pub(crate) fn socket(&mut self, value: SocketAddr) {
        match value.ip() {
            IpAddr::V4(address) => {
                self.byte(4);
                self.bytes.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                self.byte(6);
                self.bytes.extend_from_slice(&address.octets());
            }
        }
        self.u16(value.port());
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, DenialCode> {
        if self.bytes.len() > MAX_SUPERVISOR_FRAME_BYTES {
            Err(DenialCode::InvalidRequest)
        } else {
            Ok(self.bytes)
        }
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], magic: &[u8; 4], version: u8) -> Result<Self, DenialCode> {
        if bytes.len() < 6
            || bytes.len() > MAX_SUPERVISOR_FRAME_BYTES
            || &bytes[..4] != magic
            || bytes[4] != version
        {
            return Err(DenialCode::MalformedFrame);
        }
        Ok(Self { bytes, offset: 5 })
    }

    pub(crate) fn byte(&mut self) -> Result<u8, DenialCode> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(DenialCode::MalformedFrame)?;
        self.offset += 1;
        Ok(value)
    }

    pub(crate) fn bool(&mut self) -> Result<bool, DenialCode> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DenialCode::MalformedFrame),
        }
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DenialCode> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DenialCode> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DenialCode> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }

    pub(crate) fn digest(&mut self) -> Result<Digest, DenialCode> {
        Ok(Digest::from_bytes(
            self.take(32)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }

    pub(crate) fn nonce(&mut self) -> Result<[u8; 16], DenialCode> {
        self.take(16)?
            .try_into()
            .map_err(|_| DenialCode::MalformedFrame)
    }

    pub(crate) fn key(&mut self) -> Result<[u8; 32], DenialCode> {
        self.take(32)?
            .try_into()
            .map_err(|_| DenialCode::MalformedFrame)
    }

    pub(crate) fn string(&mut self) -> Result<String, DenialCode> {
        let bytes = self.bytes(MAX_TEXT_BYTES)?;
        String::from_utf8(bytes).map_err(|_| DenialCode::MalformedFrame)
    }

    pub(crate) fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, DenialCode> {
        let length = usize::try_from(self.u32()?).map_err(|_| DenialCode::MalformedFrame)?;
        if length > maximum {
            return Err(DenialCode::MalformedFrame);
        }
        Ok(self.take(length)?.to_vec())
    }

    pub(crate) fn optional_string(&mut self) -> Result<Option<String>, DenialCode> {
        self.bool().and_then(|present| {
            if present {
                self.string().map(Some)
            } else {
                Ok(None)
            }
        })
    }

    pub(crate) fn optional_digest(&mut self) -> Result<Option<Digest>, DenialCode> {
        self.bool().and_then(|present| {
            if present {
                self.digest().map(Some)
            } else {
                Ok(None)
            }
        })
    }

    pub(crate) fn socket(&mut self) -> Result<SocketAddr, DenialCode> {
        let address = match self.byte()? {
            4 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(self.take(4)?).map_err(|_| DenialCode::MalformedFrame)?,
            )),
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(self.take(16)?).map_err(|_| DenialCode::MalformedFrame)?,
            )),
            _ => return Err(DenialCode::MalformedFrame),
        };
        Ok(SocketAddr::new(address, self.u16()?))
    }

    pub(crate) fn finish(self) -> Result<(), DenialCode> {
        (self.offset == self.bytes.len())
            .then_some(())
            .ok_or(DenialCode::MalformedFrame)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DenialCode> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DenialCode::MalformedFrame)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DenialCode::MalformedFrame)?;
        self.offset = end;
        Ok(value)
    }
}
