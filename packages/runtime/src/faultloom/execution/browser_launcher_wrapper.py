from __future__ import annotations

from pathlib import Path

from .browser_runtime_snapshot import ChromiumRuntimeMount

_BWRAP_PREFIX = (
    "--die-with-parent", "--new-session", "--unshare-user", "--uid", "0",
    "--gid", "0", "--unshare-net", "--unshare-pid", "--unshare-ipc",
    "--unshare-uts", "--cap-drop", "ALL", "--clearenv", "--setenv", "HOME",
    "/tmp/home", "--setenv", "XDG_CONFIG_HOME", "/tmp/home/config", "--setenv",
    "XDG_CACHE_HOME", "/tmp/home/cache", "--setenv", "LANG", "C.UTF-8",
    "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink",
    "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--ro-bind",
    "/etc/fonts", "/etc/fonts", "--dir", "/opt", "--dir",
    "/opt/faultloom-chromium",
)
_BWRAP_SUFFIX = (
    "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir",
    "/tmp/home", "--dir", "/tmp/home/config", "--dir", "/tmp/home/cache",
    "--", "/opt/faultloom-chromium/chrome",
)


def create_wrapper_bytes(
    bwrap: Path,
    mounts: tuple[ChromiumRuntimeMount, ...],
    pid_file: Path,
    socket_path: Path,
    token: bytes,
) -> bytes:
    destinations = tuple(
        f"/opt/faultloom-chromium/{mount.asset.name.value}" for mount in mounts
    )
    constants = (
        "#!/usr/bin/python3 -I\n"
        "from __future__ import annotations\n"
        "import array\nimport os\nimport socket\nimport sys\n\n"
        f"BWRAP = {str(bwrap)!r}\n"
        f"PID_FILE = {str(pid_file)!r}\n"
        f"SOCKET_PATH = {str(socket_path)!r}\n"
        f"TOKEN = {token!r}\n"
        f"DESTINATIONS = {destinations!r}\n"
        f"BWRAP_PREFIX = {_BWRAP_PREFIX!r}\n"
        f"BWRAP_SUFFIX = {_BWRAP_SUFFIX!r}\n\n"
    )
    return (constants + _WRAPPER_BODY).encode()


_WRAPPER_BODY = "\n".join(
    (
        "def receive_descriptors() -> list[int]:",
        '    item_size = array.array("i").itemsize',
        "    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:",
        "        connection.connect(SOCKET_PATH)",
        "        connection.sendall(TOKEN)",
        "        payload, controls, flags, _ = connection.recvmsg(",
        "            1,",
        "            socket.CMSG_SPACE(len(DESTINATIONS) * item_size),",
        "        )",
        '    descriptors = array.array("i")',
        "    for level, kind, data in controls:",
        "        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:",
        "            usable = len(data) - (len(data) % item_size)",
        "            descriptors.frombytes(data[:usable])",
        '    if payload != b"\\x01" or flags & socket.MSG_CTRUNC:',
        '        raise RuntimeError("Chromium descriptor response is invalid")',
        "    if len(descriptors) != len(DESTINATIONS):",
        '        raise RuntimeError("Chromium descriptor count differs from manifest")',
        "    for descriptor in descriptors:",
        "        os.set_inheritable(descriptor, True)",
        "    return descriptors.tolist()",
        "",
        "",
        "def write_pid() -> None:",
        "    descriptor = os.open(",
        "        PID_FILE,",
        "        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,",
        "        0o600,",
        "    )",
        "    try:",
        '        os.write(descriptor, (str(os.getpid()) + "\\n").encode("ascii"))',
        "    finally:",
        "        os.close(descriptor)",
        "",
        "",
        "def main() -> None:",
        "    descriptors = receive_descriptors()",
        "    arguments = [BWRAP, *BWRAP_PREFIX]",
        "    for descriptor, destination in zip(descriptors, DESTINATIONS, strict=True):",
        '        arguments.extend(("--ro-bind-fd", str(descriptor), destination))',
        "    arguments.extend((*BWRAP_SUFFIX, *sys.argv[1:]))",
        "    write_pid()",
        "    os.execv(BWRAP, arguments)",
        "",
        "",
        'if __name__ == "__main__":',
        "    main()",
        "",
    )
)
