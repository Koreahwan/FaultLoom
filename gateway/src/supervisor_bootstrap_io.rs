use std::fs::File;
use std::io::{self, Read};

use super::supervisor_bootstrap_v4::UnverifiedSupervisorBootstrapV4;
use super::supervisor_install::{MAX_SUPERVISOR_BOOTSTRAP_BYTES_U64, SUPERVISOR_BOOTSTRAP_FD};

pub(crate) fn load_inherited_supervisor_bootstrap_v4() -> io::Result<UnverifiedSupervisorBootstrapV4>
{
    let proc_fd = format!("/proc/self/fd/{SUPERVISOR_BOOTSTRAP_FD}");
    let dev_fd = format!("/dev/fd/{SUPERVISOR_BOOTSTRAP_FD}");
    let mut file = File::open(proc_fd).or_else(|_| File::open(dev_fd))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SUPERVISOR_BOOTSTRAP_BYTES_U64
        || !private_permissions(&metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "supervisor bootstrap must be a bounded private regular file on inherited fd 3",
        ));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "supervisor bootstrap is too large",
        )
    })?;
    let mut encoded = Vec::with_capacity(length);
    file.by_ref()
        .take(MAX_SUPERVISOR_BOOTSTRAP_BYTES_U64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "supervisor bootstrap changed while being read",
        ));
    }
    UnverifiedSupervisorBootstrapV4::from_bytes(&encoded).map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid supervisor bootstrap: {reason:?}"),
        )
    })
}

#[cfg(unix)]
fn private_permissions(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_permissions(_metadata: &std::fs::Metadata) -> bool {
    false
}
