"""Loopback-only, static Cloud/IAM/OAuth observation fixture."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import BinaryIO, Literal, cast, final, override
from urllib.parse import urlparse
from urllib.request import urlopen

CaseId = Literal[
    "iam-trust-mismatch",
    "oauth-redirect-mismatch",
    "iam-matched-negative",
    "oauth-matched-negative",
]


@dataclass(frozen=True)
class CloudTrustFixtureResponse:
    url: str
    body: bytes


@final
class LoopbackCloudTrustFixture:
    """Expose fixed, credential-free projections over owned loopback GET routes."""

    def __init__(self) -> None:
        self._requests: list[tuple[str, str]] = []
        self._request_lock = Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    def __enter__(self) -> "LoopbackCloudTrustFixture":
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler hook
                fixture._record("GET", self.path)
                body = fixture._routes().get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                _ = self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler hook
                fixture._record("POST", self.path)
                self.send_error(405)

            @override
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
            raise RuntimeError("cloud trust fixture is not running")
        host, port = self._server.server_address[:2]
        if host != "127.0.0.1":
            raise RuntimeError("cloud trust fixture must bind loopback only")
        return f"http://{host}:{port}"

    @property
    def requests(self) -> tuple[tuple[str, str], ...]:
        with self._request_lock:
            return tuple(self._requests)

    def read(self, case_id: CaseId) -> CloudTrustFixtureResponse:
        url = f"{self.base_url}/{case_id}"
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise ValueError("cloud trust fixture permits only loopback HTTP")
        response_context = cast(
            AbstractContextManager[BinaryIO],
            urlopen(url, timeout=2),  # noqa: S310 - fixed owned fixture
        )
        with response_context as response:
            body = response.read()
        return CloudTrustFixtureResponse(url=url, body=body)

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
        projections = {
            "/iam-trust-mismatch": {
                "surface": "iam",
                "token_material_present": False,
                "issuer_matches": True,
                "subject_matches": False,
                "audience_matches": True,
                "redirect_uri_matches": True,
                "privilege_path": [
                    "principal:build-workload",
                    "permission:iam.serviceAccounts.getAccessToken",
                    "role:project-admin",
                ],
            },
            "/oauth-redirect-mismatch": {
                "surface": "oauth",
                "token_material_present": False,
                "issuer_matches": True,
                "subject_matches": True,
                "audience_matches": True,
                "redirect_uri_matches": False,
                "privilege_path": [
                    "client:console",
                    "scope:directory.readwrite",
                    "role:tenant-admin",
                ],
            },
            "/iam-matched-negative": {
                "surface": "iam",
                "token_material_present": False,
                "issuer_matches": True,
                "subject_matches": True,
                "audience_matches": True,
                "redirect_uri_matches": True,
                "privilege_path": [
                    "principal:readonly-workload",
                    "role:storage-viewer",
                ],
            },
            "/oauth-matched-negative": {
                "surface": "oauth",
                "token_material_present": False,
                "issuer_matches": True,
                "subject_matches": True,
                "audience_matches": True,
                "redirect_uri_matches": True,
                "privilege_path": [
                    "client:reports",
                    "scope:reports.read",
                ],
            },
        }
        return {
            path: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            for path, value in projections.items()
        }
