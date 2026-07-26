from __future__ import annotations

import array
import hmac
import os
import socket
import struct
from contextlib import suppress
from pathlib import Path
from threading import Event, Thread

from .browser_contracts import BrowserContractError

_BROKER_TIMEOUT_SECONDS = 10.0


class ChromiumDescriptorBroker:
    def __init__(
        self,
        socket_path: Path,
        token: bytes,
        descriptors: tuple[int, ...],
    ) -> None:
        self._socket_path = socket_path
        self._token = token
        self._descriptors = descriptors
        self._cancelled = Event()
        self._done = Event()
        self._listener: socket.socket | None = None
        self._thread: Thread | None = None
        self._error: OSError | ValueError | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise BrowserContractError("Chromium descriptor broker already started")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self._socket_path))
            os.chmod(self._socket_path, 0o600)
            listener.listen(1)
            listener.settimeout(_BROKER_TIMEOUT_SECONDS)
        except OSError as exc:
            listener.close()
            raise BrowserContractError("Chromium descriptor broker cannot start") from exc
        self._listener = listener
        thread = Thread(
            target=self._serve,
            name="faultloom-chromium-descriptor-broker",
            daemon=False,
        )
        self._thread = thread
        thread.start()

    def finish(self) -> None:
        if not self._done.wait(timeout=_BROKER_TIMEOUT_SECONDS):
            self.close()
            raise BrowserContractError("Chromium descriptor transfer timed out")
        thread = self._thread
        if thread is not None:
            thread.join(timeout=1)
        if self._error is not None:
            raise BrowserContractError("Chromium descriptor transfer failed") from self._error

    def close(self) -> None:
        self._cancelled.set()
        if not self._done.is_set():
            with suppress(OSError):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wake:
                    wake.connect(str(self._socket_path))
        thread = self._thread
        if thread is not None:
            thread.join(timeout=1)
        listener = self._listener
        self._listener = None
        if listener is not None:
            listener.close()
        with suppress(FileNotFoundError):
            self._socket_path.unlink()

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            self._error = ValueError("descriptor broker listener is absent")
            self._done.set()
            return
        try:
            connection, _ = listener.accept()
            with connection:
                if self._cancelled.is_set():
                    return
                self._verify_peer(connection)
                token = _receive_exact(connection, len(self._token))
                if not hmac.compare_digest(token, self._token):
                    raise ValueError("descriptor broker token mismatch")
                payload = array.array("i", self._descriptors)
                sent = connection.sendmsg(
                    [b"\x01"],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, payload)],
                )
                if sent != 1:
                    raise OSError("descriptor broker response was truncated")
        except (OSError, ValueError) as exc:
            if not self._cancelled.is_set():
                self._error = exc
        finally:
            listener.close()
            self._listener = None
            with suppress(FileNotFoundError):
                self._socket_path.unlink()
            self._done.set()

    @staticmethod
    def _verify_peer(connection: socket.socket) -> None:
        credentials = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _, user_id, _ = struct.unpack("3i", credentials)
        if user_id != os.getuid():
            raise ValueError("descriptor broker peer has the wrong user")


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise OSError("descriptor broker request ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
