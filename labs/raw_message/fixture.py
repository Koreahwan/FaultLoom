"""A loopback-only source of fixed raw HTTP/1.1 message transcripts."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Literal, final
from urllib.parse import urlparse
from urllib.request import urlopen

CaseId = Literal["ambiguous", "malformed", "negative"]


@dataclass(frozen=True)
class RawMessageFixtureResponse:
    url: str
    body: bytes


@final
class LoopbackRawMessageFixture:
    """Expose static transcripts over loopback GET; it never accepts a raw request."""

    def __init__(self) -> None:
        self._requests: list[tuple[str, str]] = []
        self._request_lock = Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    def __enter__(self) -> "LoopbackRawMessageFixture":
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler hook
                fixture._record("GET", self.path)
                body = fixture._routes().get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                _ = self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler hook
                fixture._record("POST", self.path)
                self.send_error(405)

            def log_message(self, format: str, *args: object) -> None:
                _ = (format, args)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("raw-message fixture is not running")
        host, port = self._server.server_address[:2]
        if host != "127.0.0.1":
            raise RuntimeError("raw-message fixture must bind loopback only")
        return f"http://{host}:{port}"

    @property
    def requests(self) -> tuple[tuple[str, str], ...]:
        with self._request_lock:
            return tuple(self._requests)

    def read(self, case_id: CaseId) -> RawMessageFixtureResponse:
        url = f"{self.base_url}/{case_id}"
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise ValueError("raw-message fixture permits only loopback HTTP")
        with urlopen(url, timeout=2) as response:  # noqa: S310 - fixed owned fixture
            return RawMessageFixtureResponse(url=url, body=response.read())

    def assert_read_only_loopback(self) -> None:
        if not self.base_url.startswith("http://127.0.0.1:"):
            raise AssertionError("fixture did not use a loopback endpoint")
        if any(method != "GET" for method, _path in self.requests):
            raise AssertionError("fixture received a non-read-only request")

    def _record(self, method: str, path: str) -> None:
        with self._request_lock:
            self._requests.append((method, path))

    @staticmethod
    def _routes() -> dict[str, bytes]:
        return {
            "/ambiguous": (
                b"POST /probe HTTP/1.1\r\n"
                b"Host: raw-message.fixture\r\n"
                b"Content-Length: 4\r\n"
                b"Content-Length: 8\r\n\r\n"
                b"PINGPONG"
            ),
            "/malformed": (
                b"POST /probe HTTP/1.1\r\n"
                b"Host raw-message.fixture\r\n"
                b"Content-Length: 4\r\n\r\n"
                b"PING"
            ),
            "/negative": (
                b"POST /probe HTTP/1.1\r\n"
                b"Host: raw-message.fixture\r\n"
                b"Content-Length: 4\r\n"
                b"Content-Length: 4\r\n\r\n"
                b"PING"
            ),
        }
