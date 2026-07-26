from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import signal
import stat
import subprocess
import tempfile
from pathlib import Path

from playwright.sync_api import Browser, Error as PlaywrightError, Playwright, sync_playwright

from faultloom_protocol.base import Sha256Digest

from .browser_contracts import BrowserContractError
from .browser_descriptor_broker import ChromiumDescriptorBroker
from .browser_runtime_manifest import (
    ChromiumRuntimeAsset,
    PINNED_CHROMIUM_RUNTIME_ASSETS,
)
from .browser_launcher_wrapper import create_wrapper_bytes
from .browser_runtime_snapshot import ChromiumRuntimeSnapshot
from .contracts import ExecutionModel


class ChromiumLaunchConfig(ExecutionModel):
    executable: Path
    executable_digest: Sha256Digest
    runtime_assets: tuple[ChromiumRuntimeAsset, ...] = PINNED_CHROMIUM_RUNTIME_ASSETS
    bwrap_executable: Path = Path("/usr/bin/bwrap")


class ChromiumLauncher:
    def __init__(self, config: ChromiumLaunchConfig) -> None:
        self._config = config
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._wrapper_root: tempfile.TemporaryDirectory[str] | None = None
        self._browser_pid_file: Path | None = None
        self._browser_pidfd: int | None = None
        self._descriptor_broker: ChromiumDescriptorBroker | None = None
        self._snapshot: ChromiumRuntimeSnapshot | None = ChromiumRuntimeSnapshot.stage(
            config.executable,
            config.executable_digest,
            config.runtime_assets,
        )

    def browser(self) -> Browser:
        if self._browser is not None:
            return self._browser
        snapshot = self._snapshot
        if snapshot is None:
            raise BrowserContractError("Chromium runtime snapshot is unavailable")
        try:
            wrapper, broker = self._create_verified_wrapper(snapshot)
        except BrowserContractError:
            self._cleanup_wrapper()
            self._close_snapshot()
            raise
        try:
            playwright = sync_playwright().start()
        except PlaywrightError:
            self._cleanup_wrapper()
            self._close_snapshot()
            raise
        try:
            snapshot.assert_launchable()
        except BrowserContractError:
            playwright.stop()
            self._cleanup_wrapper()
            self._close_snapshot()
            raise
        try:
            broker.start()
        except BrowserContractError:
            playwright.stop()
            self._cleanup_wrapper()
            self._close_snapshot()
            raise
        try:
            browser = playwright.chromium.launch(
                executable_path=str(wrapper),
                headless=True,
                chromium_sandbox=False,
                args=(
                    "--no-sandbox",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-dev-shm-usage",
                    "--disable-sync",
                    "--metrics-recording-only",
                    "--no-first-run",
                ),
            )
        except PlaywrightError as exc:
            playwright.stop()
            self._cleanup_wrapper()
            self._close_snapshot()
            raise BrowserContractError("digest-pinned isolated Chromium launch failed") from exc
        try:
            broker.finish()
            self._capture_browser_pidfd()
        except BrowserContractError:
            browser.close()
            playwright.stop()
            self._cleanup_wrapper()
            self._close_snapshot()
            raise
        self._playwright = playwright
        self._browser = browser
        return browser

    def close(self) -> None:
        browser = self._browser
        playwright = self._playwright
        self._browser = None
        self._playwright = None
        close_failed = False
        if browser is not None:
            try:
                browser.close()
            except PlaywrightError:
                close_failed = True
        if playwright is not None:
            playwright.stop()
        self._close_pidfd()
        self._cleanup_wrapper()
        try:
            self._close_snapshot()
        except BrowserContractError:
            close_failed = True
        if close_failed:
            raise BrowserContractError("isolated Chromium process cleanup failed")

    def interrupt(self) -> None:
        pidfd = self._browser_pidfd
        if pidfd is None:
            raise BrowserContractError("isolated Chromium process is unavailable for interrupt")
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError as exc:
            raise BrowserContractError("isolated Chromium process interrupt failed") from exc

    def _create_verified_wrapper(
        self,
        snapshot: ChromiumRuntimeSnapshot,
    ) -> tuple[Path, ChromiumDescriptorBroker]:
        bwrap = self._verify_bwrap()
        root = tempfile.TemporaryDirectory(prefix="faultloom-chromium-")
        root_path = Path(root.name)
        wrapper = root_path / "chromium-isolated"
        pid_file = root_path / "browser.pid"
        socket_path = root_path / "runtime-fds.sock"
        token = secrets.token_bytes(32)
        content = create_wrapper_bytes(
            bwrap,
            snapshot.mounts,
            pid_file,
            socket_path,
            token,
        )
        try:
            wrapper.write_bytes(content)
            wrapper.chmod(0o500)
            observed = wrapper.read_bytes()
            mode = stat.S_IMODE(wrapper.stat().st_mode)
        except OSError as exc:
            root.cleanup()
            raise BrowserContractError("isolated Chromium wrapper cannot be created") from exc
        expected_digest = hashlib.sha256(content).digest()
        observed_digest = hashlib.sha256(observed).digest()
        if not hmac.compare_digest(expected_digest, observed_digest):
            root.cleanup()
            raise BrowserContractError("isolated Chromium wrapper verification failed")
        if mode != 0o500 or wrapper.parent != root_path:
            root.cleanup()
            raise BrowserContractError("isolated Chromium wrapper permissions are unsafe")
        self._wrapper_root = root
        self._browser_pid_file = pid_file
        broker = ChromiumDescriptorBroker(
            socket_path,
            token,
            snapshot.descriptors,
        )
        self._descriptor_broker = broker
        return wrapper, broker

    def _capture_browser_pidfd(self) -> None:
        pid_file = self._browser_pid_file
        if pid_file is None:
            raise BrowserContractError("isolated Chromium PID boundary is unavailable")
        try:
            pid = int(pid_file.read_text(encoding="ascii"))
            pidfd = os.pidfd_open(pid)
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
            command = Path(f"/proc/{pid}/cmdline").read_bytes()
        except (OSError, ValueError) as exc:
            raise BrowserContractError("isolated Chromium PID boundary is invalid") from exc
        if executable != Path("/usr/bin/bwrap") or b"--unshare-net" not in command:
            os.close(pidfd)
            raise BrowserContractError("isolated Chromium PID does not identify bubblewrap")
        self._browser_pidfd = pidfd

    def _verify_bwrap(self) -> Path:
        try:
            bwrap = self._config.bwrap_executable.resolve(strict=True)
        except OSError as exc:
            raise BrowserContractError("bubblewrap executable is unavailable") from exc
        if bwrap != Path("/usr/bin/bwrap") or not os.access(bwrap, os.X_OK):
            raise BrowserContractError("bubblewrap executable is not the pinned system path")
        try:
            probe = subprocess.run(
                (str(bwrap), "--version"),
                check=False,
                capture_output=True,
                timeout=5,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BrowserContractError("bubblewrap version probe failed") from exc
        if probe.returncode != 0 or probe.stdout.strip() != b"bubblewrap 0.9.0":
            raise BrowserContractError("bubblewrap version differs from 0.9.0")
        return bwrap

    def _cleanup_wrapper(self) -> None:
        broker = self._descriptor_broker
        self._descriptor_broker = None
        if broker is not None:
            broker.close()
        root = self._wrapper_root
        self._wrapper_root = None
        self._browser_pid_file = None
        if root is not None:
            root.cleanup()

    def _close_pidfd(self) -> None:
        pidfd = self._browser_pidfd
        self._browser_pidfd = None
        if pidfd is not None:
            os.close(pidfd)

    def _close_snapshot(self) -> None:
        snapshot = self._snapshot
        self._snapshot = None
        if snapshot is not None:
            snapshot.close()
