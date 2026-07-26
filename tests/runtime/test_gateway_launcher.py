from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from faultloom.execution import (
    GatewayLaunchBundle,
    GatewayLaunchError,
    GatewayLauncher,
)


pytestmark = pytest.mark.skipif(
    os.name != "posix" or shutil.which("cc") is None,
    reason="verified-descriptor Gateway launch requires POSIX and a native test compiler",
)


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _compile_gateway(path: Path, marker: str) -> None:
    compiler = shutil.which("cc")
    assert compiler is not None
    source = path.with_suffix(".c")
    source.write_text(
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "#include <sys/stat.h>\n"
        "#include <unistd.h>\n"
        "int main(int argc, char **argv) {\n"
        "  struct stat bootstrap, journal_write, journal_read;\n"
        "  char bytes[64] = {0};\n"
        "  if (argc != 8 || strcmp(argv[1], \"--supervised-stdio\") != 0 ||\n"
        "      strcmp(argv[2], \"--bootstrap-fd\") != 0 || strcmp(argv[3], \"3\") != 0 ||\n"
        "      strcmp(argv[4], \"--journal-write-fd\") != 0 || strcmp(argv[5], \"4\") != 0 ||\n"
        "      strcmp(argv[6], \"--journal-read-fd\") != 0 || strcmp(argv[7], \"5\") != 0 ||\n"
        "      fstat(3, &bootstrap) != 0 || !S_ISREG(bootstrap.st_mode) ||\n"
        "      fstat(4, &journal_write) != 0 || !S_ISFIFO(journal_write.st_mode) ||\n"
        "      fstat(5, &journal_read) != 0 || !S_ISFIFO(journal_read.st_mode) ||\n"
        "      read(3, bytes, sizeof(bytes)) != 27 ||\n"
        "      memcmp(bytes, \"controller-signed-bootstrap\", 27) != 0) return 91;\n"
        f"  if (write(4, \"{marker}\", {len(marker)}) != {len(marker)}) return 92;\n"
        "  while (read(0, bytes, sizeof(bytes)) > 0) {}\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(
        (compiler, "-std=c11", "-O0", "-o", str(path), str(source)),
        check=True,
        capture_output=True,
        text=True,
    )
    path.chmod(0o700)


def _provisioned_bundle(tmp_path: Path) -> tuple[Path, tuple[int, int, int, int]]:
    executable = tmp_path / "owned-gateway"
    _compile_gateway(executable, "VERIFIED")
    bootstrap = tmp_path / "bootstrap.flbs"
    bootstrap.write_bytes(b"controller-signed-bootstrap")
    bootstrap.chmod(0o600)
    journal_read, journal_write = os.pipe()
    reply_read, reply_write = os.pipe()
    now = int(time.time() * 1000)
    document = {
        "schema": "faultloom.gateway-launch-bundle.v1",
        "executable": str(executable),
        "executable_digest": _digest(executable),
        "bootstrap": str(bootstrap),
        "bootstrap_digest": _digest(bootstrap),
        "journal_write_fd": journal_write,
        "journal_read_fd": reply_read,
        "channel": {
            "key_id": "channel-key.1",
            "key_hex": bytes(range(1, 33)).hex(),
            "boot_id": "gateway-boot.1",
            "nonce_hex": bytes(range(16)).hex(),
            "issued_at_millis": now - 1_000,
            "expires_at_millis": now + 60_000,
        },
    }
    bundle = tmp_path / "gateway-bundle.json"
    bundle.write_text(json.dumps(document), encoding="utf-8")
    bundle.chmod(0o600)
    return bundle, (journal_read, journal_write, reply_read, reply_write)


def _await_marker(read_fd: int, child: subprocess.Popen[bytes]) -> bytes:
    os.set_blocking(read_fd, False)
    for _ in range(100):
        try:
            marker = os.read(read_fd, 64)
        except BlockingIOError:
            marker = b""
        if marker:
            return marker
        if child.poll() is not None:
            break
        time.sleep(0.01)
    return b""


def test_real_launcher_uses_exact_installed_arguments_and_reaps_child(tmp_path: Path) -> None:
    bundle_path, descriptors = _provisioned_bundle(tmp_path)
    child = None
    try:
        launcher = GatewayLauncher(GatewayLaunchBundle.load(bundle_path))
        launcher.start()
        child = launcher.process
        assert child is not None
        assert child.args[1:] == (
            "--supervised-stdio",
            "--bootstrap-fd",
            "3",
            "--journal-write-fd",
            "4",
            "--journal-read-fd",
            "5",
        )
        assert str(child.args[0]).startswith("/proc/self/fd/")
        assert _await_marker(descriptors[0], child) == b"VERIFIED"
        assert child.poll() is None

        launcher.close()

        assert child.poll() is not None
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=1)


def test_executable_path_swap_runs_only_the_opened_verified_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.execution.gateway_launcher as launcher_module

    bundle_path, descriptors = _provisioned_bundle(tmp_path)
    bundle = GatewayLaunchBundle.load(bundle_path)
    verified_digest = bundle.executable_digest
    replacement = tmp_path / "replacement-gateway"
    _compile_gateway(replacement, "REPLACED")
    replacement_digest = _digest(replacement)
    original_install = launcher_module._install_fixed_gateway_fds
    swapped = False
    child = None

    def swap_after_verification(sources: list[int]) -> list[tuple[int, int | None, bool]]:
        nonlocal swapped
        os.replace(replacement, bundle.executable)
        swapped = True
        return original_install(sources)

    monkeypatch.setattr(launcher_module, "_install_fixed_gateway_fds", swap_after_verification)
    try:
        launcher = GatewayLauncher(bundle)
        launcher.start()
        child = launcher.process
        assert swapped is True
        assert child is not None
        assert _await_marker(descriptors[0], child) == b"VERIFIED"
        assert _digest(bundle.executable) == replacement_digest
        assert replacement_digest != verified_digest
        launcher.close()
        assert child.poll() is not None
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=1)


def test_launch_reserves_verified_executable_above_initially_absent_fixed_fds(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "owned-gateway"
    _compile_gateway(executable, "VERIFIED")
    bootstrap = tmp_path / "bootstrap.flbs"
    bootstrap.write_bytes(b"controller-signed-bootstrap")
    bootstrap.chmod(0o600)
    bundle_path = tmp_path / "isolated-bundle.json"
    root = Path(__file__).resolve().parents[2]
    helper = textwrap.dedent(
        """
        import fcntl
        import hashlib
        import json
        import os
        import select
        import sys
        import time
        from pathlib import Path

        root, executable_text, bootstrap_text, bundle_text = sys.argv[1:]
        sys.path[:0] = [
            root,
            str(Path(root) / "packages/protocol/src"),
            str(Path(root) / "packages/sdk/src"),
            str(Path(root) / "packages/runtime/src"),
        ]
        from faultloom.execution import GatewayLaunchBundle, GatewayLauncher

        for descriptor in (3, 4, 5):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raw = (*os.pipe(), *os.pipe())
        high = tuple(
            fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 64)
            for descriptor in raw
        )
        for descriptor in raw:
            os.close(descriptor)
        journal_read, journal_write, reply_read, reply_write = high
        executable = Path(executable_text)
        bootstrap = Path(bootstrap_text)
        now = int(time.time() * 1000)
        bundle = Path(bundle_text)
        bundle.write_text(json.dumps({
            "schema": "faultloom.gateway-launch-bundle.v1",
            "executable": str(executable),
            "executable_digest": "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest(),
            "bootstrap": str(bootstrap),
            "bootstrap_digest": "sha256:" + hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
            "journal_write_fd": journal_write,
            "journal_read_fd": reply_read,
            "channel": {
                "key_id": "channel-key.1",
                "key_hex": bytes(range(1, 33)).hex(),
                "boot_id": "gateway-boot.1",
                "nonce_hex": bytes(range(16)).hex(),
                "issued_at_millis": now - 1000,
                "expires_at_millis": now + 60000,
            },
        }), encoding="utf-8")
        bundle.chmod(0o600)
        child = None
        try:
            launcher = GatewayLauncher(GatewayLaunchBundle.load(bundle))
            launcher.start()
            child = launcher.process
            readable, _, _ = select.select((journal_read,), (), (), 2)
            marker = os.read(journal_read, 64) if readable else b""
            process_arg = str(child.args[0]) if child is not None else ""
            live_before_close = child is not None and child.poll() is None
            launcher.close()
            print(json.dumps({
                "fixed_fds_were_absent": True,
                "live_before_close": live_before_close,
                "marker": marker.decode("ascii"),
                "process_arg": process_arg,
                "reaped": child is not None and child.poll() is not None,
            }))
        finally:
            for descriptor in high:
                os.close(descriptor)
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=1)
        """
    )

    result = subprocess.run(
        (
            sys.executable,
            "-c",
            helper,
            str(root),
            str(executable),
            str(bootstrap),
            str(bundle_path),
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    observation = json.loads(result.stdout)
    assert set(observation) == {
        "fixed_fds_were_absent",
        "live_before_close",
        "marker",
        "process_arg",
        "reaped",
    }
    assert observation["fixed_fds_were_absent"] is True
    assert observation["live_before_close"] is True
    assert observation["marker"] == "VERIFIED"
    assert observation["reaped"] is True
    executable_fd = int(observation["process_arg"].removeprefix("/proc/self/fd/"))
    assert executable_fd >= 64


def test_launcher_rejects_bootstrap_digest_tamper_before_child_start(tmp_path: Path) -> None:
    bundle_path, descriptors = _provisioned_bundle(tmp_path)
    try:
        bundle = GatewayLaunchBundle.load(bundle_path)
        bundle.bootstrap.write_bytes(b"tampered")
        bundle.bootstrap.chmod(stat.S_IRUSR | stat.S_IWUSR)

        launcher = GatewayLauncher(bundle)
        with pytest.raises(GatewayLaunchError, match="digest differs"):
            launcher.start()
        assert launcher.process is None
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_launcher_fails_closed_when_another_controller_thread_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_path, descriptors = _provisioned_bundle(tmp_path)
    try:
        monkeypatch.setattr("threading.active_count", lambda: 2)
        launcher = GatewayLauncher(GatewayLaunchBundle.load(bundle_path))
        with pytest.raises(GatewayLaunchError, match="single-threaded"):
            launcher.start()
        assert launcher.process is None
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_bundle_requires_private_single_link_file(tmp_path: Path) -> None:
    bundle_path, descriptors = _provisioned_bundle(tmp_path)
    try:
        bundle_path.chmod(0o644)
        with pytest.raises(GatewayLaunchError, match="group or other"):
            GatewayLaunchBundle.load(bundle_path)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
