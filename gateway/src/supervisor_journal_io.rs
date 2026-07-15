use std::fs::{File, OpenOptions};
use std::io;

use super::supervisor_install::{SUPERVISOR_JOURNAL_READ_FD, SUPERVISOR_JOURNAL_WRITE_FD};

pub(crate) fn open_inherited_journal_channels() -> io::Result<(File, File)> {
    let writer = open_fd(SUPERVISOR_JOURNAL_WRITE_FD, false)?;
    let reader = open_fd(SUPERVISOR_JOURNAL_READ_FD, true)?;
    if !private_fifo(&writer.metadata()?) || !private_fifo(&reader.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal descriptors must be private inherited FIFOs",
        ));
    }
    Ok((writer, reader))
}

fn open_fd(fd: &str, read: bool) -> io::Result<File> {
    let proc_fd = format!("/proc/self/fd/{fd}");
    let dev_fd = format!("/dev/fd/{fd}");
    let open = |path: &str| OpenOptions::new().read(read).write(!read).open(path);
    open(&proc_fd).or_else(|_| open(&dev_fd))
}

#[cfg(unix)]
fn private_fifo(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    metadata.file_type().is_fifo() && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_fifo(_metadata: &std::fs::Metadata) -> bool {
    false
}
