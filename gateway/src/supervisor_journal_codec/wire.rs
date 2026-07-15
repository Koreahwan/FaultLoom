use crate::Digest;
use crate::ipc::DenialCode;

use super::super::supervisor_journal::MAX_JOURNAL_FRAME_BYTES;
use super::{MAGIC, MAX_ITEMS, VERSION};

const MAX_TEXT_BYTES: usize = 4_096;

pub(super) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(super) fn new(kind: u8) -> Self {
        let mut value = Self::plain();
        value.bytes.extend_from_slice(MAGIC);
        value.byte(VERSION);
        value.byte(kind);
        value
    }
    pub(super) fn plain() -> Self {
        Self {
            bytes: Vec::with_capacity(512),
        }
    }
    pub(super) fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }
    pub(super) fn bool(&mut self, value: bool) {
        self.byte(u8::from(value));
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub(super) fn digest(&mut self, value: Digest) {
        self.bytes.extend_from_slice(value.as_bytes());
    }
    pub(super) fn nonce(&mut self, value: [u8; 16]) {
        self.bytes.extend_from_slice(&value);
    }
    pub(super) fn string(&mut self, value: &str) -> Result<(), DenialCode> {
        self.bytes(value.as_bytes(), MAX_TEXT_BYTES)
    }
    pub(super) fn bytes(&mut self, value: &[u8], maximum: usize) -> Result<(), DenialCode> {
        if value.len() > maximum {
            return Err(DenialCode::InvalidRequest);
        }
        self.u32(u32::try_from(value.len()).map_err(|_| DenialCode::InvalidRequest)?);
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub(super) fn count(&mut self, value: usize) -> Result<(), DenialCode> {
        if value > MAX_ITEMS {
            return Err(DenialCode::InvalidRequest);
        }
        self.u16(value as u16);
        Ok(())
    }
    pub(super) fn optional_digest(&mut self, value: Option<Digest>) -> Result<(), DenialCode> {
        if value == Some(Digest::ZERO) {
            return Err(DenialCode::InvalidRequest);
        }
        self.bool(value.is_some());
        if let Some(value) = value {
            self.digest(value);
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<Vec<u8>, DenialCode> {
        if self.bytes.len() > MAX_JOURNAL_FRAME_BYTES {
            Err(DenialCode::InvalidRequest)
        } else {
            Ok(self.bytes)
        }
    }
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8], kind: u8) -> Result<Self, DenialCode> {
        if bytes.len() < 6 || &bytes[..4] != MAGIC || bytes[4] != VERSION || bytes[5] != kind {
            Err(DenialCode::MalformedFrame)
        } else {
            Ok(Self { bytes, offset: 6 })
        }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], DenialCode> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(DenialCode::MalformedFrame)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DenialCode::MalformedFrame)?;
        self.offset = end;
        Ok(value)
    }
    pub(super) fn byte(&mut self) -> Result<u8, DenialCode> {
        Ok(self.take(1)?[0])
    }
    pub(super) fn bool(&mut self) -> Result<bool, DenialCode> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DenialCode::MalformedFrame),
        }
    }
    fn u16(&mut self) -> Result<u16, DenialCode> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, DenialCode> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }
    pub(super) fn u64(&mut self) -> Result<u64, DenialCode> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }
    pub(super) fn digest(&mut self) -> Result<Digest, DenialCode> {
        Ok(Digest::from_bytes(
            self.take(32)?
                .try_into()
                .map_err(|_| DenialCode::MalformedFrame)?,
        ))
    }
    pub(super) fn nonce(&mut self) -> Result<[u8; 16], DenialCode> {
        self.take(16)?
            .try_into()
            .map_err(|_| DenialCode::MalformedFrame)
    }
    pub(super) fn string(&mut self) -> Result<String, DenialCode> {
        String::from_utf8(self.bytes(MAX_TEXT_BYTES)?).map_err(|_| DenialCode::MalformedFrame)
    }
    pub(super) fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, DenialCode> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(DenialCode::MalformedFrame);
        }
        Ok(self.take(length)?.to_vec())
    }
    pub(super) fn count(&mut self) -> Result<usize, DenialCode> {
        let value = self.u16()? as usize;
        if value > MAX_ITEMS {
            Err(DenialCode::MalformedFrame)
        } else {
            Ok(value)
        }
    }
    pub(super) fn optional_digest(&mut self) -> Result<Option<Digest>, DenialCode> {
        if self.bool()? {
            let value = self.digest()?;
            if value == Digest::ZERO {
                Err(DenialCode::MalformedFrame)
            } else {
                Ok(Some(value))
            }
        } else {
            Ok(None)
        }
    }
    pub(super) fn finish(self) -> Result<(), DenialCode> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DenialCode::MalformedFrame)
        }
    }
}
