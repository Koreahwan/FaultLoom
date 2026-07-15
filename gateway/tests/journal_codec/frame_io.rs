use std::io::{self, Cursor, ErrorKind};

use faultloom_gateway::supervisor_journal::{
    MAX_JOURNAL_FRAME_BYTES, read_journal_frame, write_journal_frame,
};

#[test]
fn frame_io_rejects_empty_oversized_and_truncated_frames() {
    // Given / When / Then
    let mut output = Vec::new();
    assert_io_error(
        write_journal_frame(&mut output, &[]),
        ErrorKind::InvalidInput,
    );
    assert_io_error(
        write_journal_frame(&mut output, &vec![0; MAX_JOURNAL_FRAME_BYTES + 1]),
        ErrorKind::InvalidInput,
    );

    let oversized_length = u32::try_from(MAX_JOURNAL_FRAME_BYTES + 1)
        .expect("journal maximum fits in u32")
        .to_be_bytes();
    assert_io_error(
        read_journal_frame(&mut Cursor::new(0_u32.to_be_bytes())),
        ErrorKind::InvalidData,
    );
    assert_io_error(
        read_journal_frame(&mut Cursor::new(oversized_length)),
        ErrorKind::InvalidData,
    );
    let truncated = [0, 0, 0, 4, 1, 2];
    assert_io_error(
        read_journal_frame(&mut Cursor::new(truncated)),
        ErrorKind::UnexpectedEof,
    );
}

fn assert_io_error<T>(result: io::Result<T>, expected: ErrorKind) {
    assert_eq!(result.err().map(|error| error.kind()), Some(expected));
}
