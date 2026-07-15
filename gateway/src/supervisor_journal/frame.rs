use std::io::{self, Read, Write};

use super::MAX_JOURNAL_FRAME_BYTES;

pub fn write_journal_frame(output: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_JOURNAL_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid journal frame length",
        ));
    }
    output.write_all(
        &u32::try_from(frame.len())
            .map_err(|_| io::Error::other("journal frame overflow"))?
            .to_be_bytes(),
    )?;
    output.write_all(frame)?;
    output.flush()
}

pub fn read_journal_frame(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_JOURNAL_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid journal frame length",
        ));
    }
    let mut frame = vec![0_u8; length];
    input.read_exact(&mut frame)?;
    Ok(frame)
}
