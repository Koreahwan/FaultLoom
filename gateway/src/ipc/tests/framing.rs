use std::io::ErrorKind;

use super::super::{MAX_FRAME_BYTES, read_frame};

#[test]
fn frame_reader_rejects_partial_and_oversized_frames() {
    let mut partial = &b"\x00\x00"[..];
    assert_eq!(
        read_frame(&mut partial).expect_err("partial length").kind(),
        ErrorKind::UnexpectedEof
    );
    let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
    assert_eq!(
        read_frame(&mut &oversized[..])
            .expect_err("oversized frame")
            .kind(),
        ErrorKind::InvalidData
    );
}
