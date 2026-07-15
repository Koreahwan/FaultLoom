use std::fs::File;
use std::io::{self, Read};

use crate::Digest;
use crate::installed_trust::load_installed_trust_store;

use super::{AuthorizedStartup, authorize_loaded_startup};

const EXECUTABLE_PATH: &str = "/proc/self/exe";
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn authorize_installed_startup() -> io::Result<AuthorizedStartup> {
    let trust = load_installed_trust_store().map_err(|reason| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("installed trust rejected: {reason}"),
        )
    })?;
    let unverified = crate::supervisor_bootstrap_io::load_inherited_supervisor_bootstrap_v4()?;
    let executable_digest = measure_running_executable()?;
    let now_millis = crate::system_now_millis()?;
    authorize_loaded_startup(trust, unverified, executable_digest, now_millis).map_err(|reason| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("installed startup rejected: {reason:?}"),
        )
    })
}

pub(super) fn measure_running_executable() -> io::Result<Digest> {
    let mut executable = File::open(EXECUTABLE_PATH)?;
    let metadata = executable.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "running executable is not a bounded regular file",
        ));
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "executable size overflow"))?;
    let mut bytes = Vec::with_capacity(length);
    executable
        .by_ref()
        .take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "running executable changed while being measured",
        ));
    }
    Ok(Digest::of(&bytes))
}
