use crate::Digest;

use super::response::DecodeError;
use super::tags::{DenialCode, MAGIC, VERSION};

pub(super) struct Encoder {
    pub(super) bytes: Vec<u8>,
}

impl Encoder {
    pub(super) fn new(message: u8) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(message);
        Self { bytes }
    }

    pub(super) fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
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

    pub(super) fn short_bytes(&mut self, value: &[u8]) -> Result<(), DenialCode> {
        let length = u16::try_from(value.len()).map_err(|_| DenialCode::InvalidRequest)?;
        self.u16(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn long_bytes(&mut self, value: &[u8]) -> Result<(), DenialCode> {
        let length = u32::try_from(value.len()).map_err(|_| DenialCode::InvalidRequest)?;
        self.u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn string(&mut self, value: &str) -> Result<(), DenialCode> {
        self.short_bytes(value.as_bytes())
    }

    pub(super) fn optional_string(&mut self, value: Option<&str>) -> Result<(), DenialCode> {
        match value {
            Some(item) => {
                self.byte(1);
                self.string(item)?;
            }
            None => self.byte(0),
        }
        Ok(())
    }

    pub(super) fn optional_digest(&mut self, value: Option<Digest>) {
        match value {
            Some(item) => {
                self.byte(1);
                self.digest(item);
            }
            None => self.byte(0),
        }
    }
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8], message: u8) -> Result<Self, DecodeError> {
        if bytes.len() < 6 || &bytes[..4] != MAGIC || bytes[4] != VERSION || bytes[5] != message {
            return Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            });
        }
        Ok(Self { bytes, offset: 6 })
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
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

    pub(super) fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two-byte slice"),
        ))
    }

    pub(super) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four-byte slice"),
        ))
    }

    pub(super) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight-byte slice"),
        ))
    }

    pub(super) fn digest(&mut self) -> Result<Digest, DecodeError> {
        Ok(Digest::from_bytes(
            self.take(32)?.try_into().expect("32-byte slice"),
        ))
    }

    pub(super) fn nonce(&mut self) -> Result<[u8; 16], DecodeError> {
        Ok(self.take(16)?.try_into().expect("16-byte nonce"))
    }

    pub(super) fn short_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let length = self.u16()? as usize;
        self.take(length)
    }

    pub(super) fn long_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let length = usize::try_from(self.u32()?).map_err(|_| DecodeError {
            action_id: None,
            reason: DenialCode::MalformedFrame,
        })?;
        self.take(length)
    }

    pub(super) fn string(&mut self) -> Result<String, DecodeError> {
        let text = std::str::from_utf8(self.short_bytes()?).map_err(|_| DecodeError {
            action_id: None,
            reason: DenialCode::InvalidRequest,
        })?;
        Ok(text.to_owned())
    }

    pub(super) fn optional_string(&mut self) -> Result<Option<String>, DecodeError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.string().map(Some),
            _ => Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            }),
        }
    }

    pub(super) fn optional_digest(&mut self) -> Result<Option<Digest>, DecodeError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.digest().map(Some),
            _ => Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            }),
        }
    }

    pub(super) fn finish(self) -> Result<(), DecodeError> {
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
