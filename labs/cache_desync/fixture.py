"""A read-only local HTTP fixture with matched cache/desync controls."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Literal, final
from urllib.parse import urlparse
from urllib.request import urlopen


CaseId = Literal["positive", "negative"]


@dataclass(frozen=True)
class FixtureResponse:
    url: str
    body: bytes
    headers: tuple[tuple[str, str], ...]

    def header(self, name: str) -> str:
        for actual, value in self.headers:
            if actual.casefold() == name.casefold():
                return value
        raise ValueError(f"missing required fixture header: {name}")


@final
class LoopbackCacheDesyncFixture:
    """Serve fixed evidence only on 127.0.0.1; every supported route is a GET."""

    def __init__(self) -> None:
        self._requests: list[tuple[str, str]] = []
        self._request_lock = Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    def __enter__(self) -> "LoopbackCacheDesyncFixture":
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler hook
                fixture._record("GET", self.path)
                response = fixture._routes().get(self.path)
                if response is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                for name, value in response.headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(response.body)))
                self.end_headers()
                _ = self.wfile.write(response.body)

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler hook
                fixture._record("POST", self.path)
                self.send_error(405)

            def log_message(self, format: str, *args: object) -> None:
                _ = (format, args)
                return

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
            raise RuntimeError("loopback fixture is not running")
        host, port = self._server.server_address[:2]
        if host != "127.0.0.1":
            raise RuntimeError("cache/desync fixture must bind loopback only")
        return f"http://{host}:{port}"

    @property
    def requests(self) -> tuple[tuple[str, str], ...]:
        with self._request_lock:
            return tuple(self._requests)

    def url(self, case_id: CaseId, evidence: Literal["stale", "fresh", "final-effect"]) -> str:
        return f"{self.base_url}/{case_id}/{evidence}"

    def read(
        self,
        case_id: CaseId,
        evidence: Literal["stale", "fresh", "final-effect"],
    ) -> FixtureResponse:
        url = self.url(case_id, evidence)
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise ValueError("cache/desync fixture permits only loopback HTTP")
        with urlopen(url, timeout=2) as response:  # noqa: S310 - fixed owned fixture
            return FixtureResponse(
                url=url,
                body=response.read(),
                headers=tuple(response.headers.items()),
            )

    def assert_read_only_loopback(self) -> None:
        if not self.base_url.startswith("http://127.0.0.1:"):
            raise AssertionError("fixture did not use a loopback endpoint")
        if any(method != "GET" for method, _path in self.requests):
            raise AssertionError("fixture received a non-read-only request")

    def _record(self, method: str, path: str) -> None:
        with self._request_lock:
            self._requests.append((method, path))

    @staticmethod
    def _routes() -> dict[str, FixtureResponse]:
        positive_stale = b'{"canary":"inert-cache-desync","revision":"epoch-41"}'
        positive_fresh = b'{"canary":"inert-cache-desync","revision":"epoch-42"}'
        negative_fresh = b'{"canary":"inert-cache-desync","revision":"epoch-42"}'
        return {
            "/positive/stale": FixtureResponse(
                "/positive/stale",
                positive_stale,
                (
                    ("Age", "120"),
                    ("X-Cache", "HIT"),
                    ("X-Fixture-Epoch", "41"),
                ),
            ),
            "/positive/fresh": FixtureResponse(
                "/positive/fresh",
                positive_fresh,
                (
                    ("Age", "0"),
                    ("X-Cache", "MISS"),
                    ("X-Fixture-Epoch", "42"),
                ),
            ),
            "/positive/final-effect": FixtureResponse(
                "/positive/final-effect",
                b'{"effect":"inert-cache-desync-canary","observed_epoch":42}',
                (("X-Final-Effect", "inert-cache-desync-canary"),),
            ),
            "/negative/stale": FixtureResponse(
                "/negative/stale",
                negative_fresh,
                (
                    ("Age", "120"),
                    ("X-Cache", "HIT"),
                    ("X-Fixture-Epoch", "42"),
                ),
            ),
            "/negative/fresh": FixtureResponse(
                "/negative/fresh",
                negative_fresh,
                (
                    ("Age", "0"),
                    ("X-Cache", "MISS"),
                    ("X-Fixture-Epoch", "42"),
                ),
            ),
            "/negative/final-effect": FixtureResponse(
                "/negative/final-effect",
                b'{"effect":"absent","observed_epoch":42}',
                (("X-Final-Effect", "absent"),),
            ),
        }
