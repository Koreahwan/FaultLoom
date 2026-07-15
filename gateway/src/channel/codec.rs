use super::*;

pub(super) struct Encoder {
    pub(super) bytes: Vec<u8>,
}

impl Encoder {
    pub(super) fn new(message_type: u8) -> Self {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(message_type);
        Self { bytes }
    }

    pub(super) fn string(&mut self, value: &str) {
        push_string(&mut self.bytes, value);
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

    pub(super) fn bytes(&mut self, value: &[u8]) {
        self.bytes
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.bytes.extend_from_slice(value);
    }
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8], expected_type: u8) -> Result<Self, DenialCode> {
        if bytes.len() < 6
            || &bytes[..4] != MAGIC
            || bytes[4] != VERSION
            || bytes[5] != expected_type
        {
            return Err(DenialCode::MalformedFrame);
        }
        Ok(Self { bytes, offset: 6 })
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

    pub(super) fn string(&mut self) -> Result<String, DenialCode> {
        let length = self.u32()? as usize;
        if length == 0 || length > 256 {
            return Err(DenialCode::MalformedFrame);
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| DenialCode::MalformedFrame)
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

    pub(super) fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, DenialCode> {
        let length = self.u32()? as usize;
        if length == 0 || length > maximum {
            return Err(DenialCode::MalformedFrame);
        }
        Ok(self.take(length)?.to_vec())
    }

    pub(super) fn finish(self) -> Result<(), DenialCode> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DenialCode::MalformedFrame)
        }
    }
}
