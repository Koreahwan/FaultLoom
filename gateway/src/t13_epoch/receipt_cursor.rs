use crate::scope::EpochAdmissionError;

const MAXIMUM_CANONICAL_ENVELOPE_BYTES: usize = 16_384;

pub(super) struct ReceiptCursor<'a> {
    bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> ReceiptCursor<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], EpochAdmissionError> {
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

    pub(super) fn literal(&mut self, expected: &[u8]) -> Result<(), EpochAdmissionError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        }
    }

    pub(super) fn byte(&mut self) -> Result<u8, EpochAdmissionError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(EpochAdmissionError::InvalidVerificationReceipt)
    }

    pub(super) fn u64(&mut self) -> Result<u64, EpochAdmissionError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], EpochAdmissionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| EpochAdmissionError::InvalidVerificationReceipt)
    }

    pub(super) fn string(&mut self, maximum: usize) -> Result<String, EpochAdmissionError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length == 0 || length > maximum {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        core::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| EpochAdmissionError::InvalidVerificationReceipt)
    }

    pub(super) fn optional_string(
        &mut self,
        maximum: usize,
    ) -> Result<Option<String>, EpochAdmissionError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.string(maximum).map(Some),
            _ => Err(EpochAdmissionError::InvalidVerificationReceipt),
        }
    }

    pub(super) fn envelope_bytes(&mut self) -> Result<&'a [u8], EpochAdmissionError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| EpochAdmissionError::InvalidVerificationReceipt)?;
        if length == 0 || length > MAXIMUM_CANONICAL_ENVELOPE_BYTES {
            return Err(EpochAdmissionError::InvalidVerificationReceipt);
        }
        self.take(length)
    }

    pub(super) fn finish(self) -> Result<(), EpochAdmissionError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EpochAdmissionError::InvalidVerificationReceipt)
        }
    }
}
