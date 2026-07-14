from __future__ import annotations

import multiprocessing
import os
import select
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from multiprocessing.process import BaseProcess
from types import TracebackType
from typing import Self, cast

LOOPBACK_BODY = b"gateway-only-loopback"


class _LoopbackServer(HTTPServer):
    def __init__(self, server_address: tuple[str, int], result_fd: int) -> None:
        self.result_fd = result_fd
        super().__init__(server_address, _LoopbackHandler)


class _LoopbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = cast(_LoopbackServer, self.server)
        payload = self.path.encode()
        os.write(server.result_fd, len(payload).to_bytes(2, "big") + payload)
        self.send_response(200)
        self.send_header("content-length", str(len(LOOPBACK_BODY)))
        self.end_headers()
        self.wfile.write(LOOPBACK_BODY)

    def log_message(self, format: str, *args: str | int) -> None:
        return


@dataclass(slots=True)
class LoopbackTarget:
    port: int
    result_fd: int
    process: BaseProcess

    def read_path(self, timeout: float = 1.0) -> str | None:
        readable, _, _ = select.select((self.result_fd,), (), (), timeout)
        if not readable:
            return None
        length = int.from_bytes(_read_exact(self.result_fd, 2), "big")
        return _read_exact(self.result_fd, length).decode()

    def close(self) -> None:
        if self.process.is_alive():
            self.process.terminate()
        self.process.join(timeout=5)
        os.close(self.result_fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def start_loopback_target() -> LoopbackTarget:
    port_read, port_write = os.pipe()
    result_read, result_write = os.pipe()
    context = multiprocessing.get_context("fork")
    process = context.Process(
        target=_target_process,
        args=(port_write, result_write, port_read, result_read),
        daemon=True,
    )
    process.start()
    os.close(port_write)
    os.close(result_write)
    port = int.from_bytes(_read_exact(port_read, 2), "big")
    os.close(port_read)
    return LoopbackTarget(port=port, result_fd=result_read, process=process)


def _target_process(
    port_write: int,
    result_write: int,
    port_read: int,
    result_read: int,
) -> None:
    os.close(port_read)
    os.close(result_read)
    server = _LoopbackServer(("127.0.0.1", 0), result_write)
    os.write(port_write, server.server_port.to_bytes(2, "big"))
    os.close(port_write)
    try:
        server.handle_request()
    finally:
        server.server_close()
        os.close(result_write)


def _read_exact(fd: int, length: int) -> bytes:
    payload = bytearray()
    while len(payload) < length:
        chunk = os.read(fd, length - len(payload))
        if not chunk:
            raise RuntimeError("loopback target pipe closed mid-frame")
        payload.extend(chunk)
    return bytes(payload)
