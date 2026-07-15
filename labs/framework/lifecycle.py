"""Owned-loopback lifecycle for the minimal semantic HTTP fixture."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Final, Iterator, assert_never
from urllib.parse import urlsplit

from .contracts import LabManifest, SemanticFixtureMode

HEALTH_PATH: Final = "/healthz"
RESOURCE_PATH: Final = "/v1/tenants/tenant.beta/resources/canary"
CANARY_PATH: Final = "/v1/canary"
CANARY_TOUCH_PATH: Final = "/v1/canary/touch"
LOOPBACK_HOST: Final = "127.0.0.1"
OWNER_TENANT: Final = "tenant.alpha"
_JSON_CONTENT_TYPE: Final = "application/json"
_HEALTH_BODY: Final = b'{"ready":true}'
_RESOURCE_BODY: Final = (
    b'{"owner_tenant":"tenant.alpha","resource_id":"resource.canary"}'
)
_DENIED_BODY: Final = b'{"error":"denied"}'
_NOT_FOUND_BODY: Final = b'{"error":"not_found"}'


@dataclass(frozen=True, slots=True)
class CanarySnapshot:
    snapshot_id: str
    state_id: str
    marker: str
    generation: int


@dataclass(frozen=True, slots=True)
class LabEndpoint:
    host: str
    port: int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class LabReadiness:
    instance_id: str
    ready: bool
    endpoint: LabEndpoint | None


@dataclass(frozen=True, slots=True)
class LabLifecycleError(RuntimeError):
    detail: str

    def __str__(self) -> str:
        return self.detail


class _CanaryStore:
    """Mutable state exists only to exercise deterministic reset and cleanup."""

    def __init__(self, state_id: str) -> None:
        self._state_id = state_id
        self._lock = Lock()
        self._snapshot = self._clean_snapshot()

    def snapshot(self) -> CanarySnapshot:
        with self._lock:
            return self._snapshot

    def touch(self) -> CanarySnapshot:
        with self._lock:
            self._snapshot = CanarySnapshot(
                snapshot_id=f"{self._state_id}.generation.1",
                state_id=self._state_id,
                marker="touched",
                generation=1,
            )
            return self._snapshot

    def reset(self) -> CanarySnapshot:
        with self._lock:
            self._snapshot = self._clean_snapshot()
            return self._snapshot

    def _clean_snapshot(self) -> CanarySnapshot:
        return CanarySnapshot(
            snapshot_id=f"{self._state_id}.generation.0",
            state_id=self._state_id,
            marker="clean",
            generation=0,
        )


class _LabHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        state: _CanaryStore,
        mode: SemanticFixtureMode,
    ) -> None:
        self.lab_state = state
        self.fixture_mode = mode
        super().__init__(address, _SemanticLabHandler)


class _SemanticLabHandler(BaseHTTPRequestHandler):
    server: _LabHttpServer

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == HEALTH_PATH:
            self._respond(200, _HEALTH_BODY)
            return
        if path == RESOURCE_PATH:
            match self.server.fixture_mode:
                case SemanticFixtureMode.VULNERABLE:
                    allowed = True
                case SemanticFixtureMode.DENIED:
                    allowed = False
                case unreachable:
                    assert_never(unreachable)
            self._respond(200, _RESOURCE_BODY) if allowed else self._respond(
                403, _DENIED_BODY
            )
            return
        if path == CANARY_PATH:
            self._respond(200, _canary_body(self.server.lab_state.snapshot()))
            return
        self._respond(404, _NOT_FOUND_BODY)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != CANARY_TOUCH_PATH:
            self._respond(404, _NOT_FOUND_BODY)
            return
        if self.headers.get("X-Lab-Tenant", "") != OWNER_TENANT:
            self._respond(403, _DENIED_BODY)
            return
        self._respond(200, _canary_body(self.server.lab_state.touch()))

    def log_message(self, format: str, *args: str) -> None:
        return

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", _JSON_CONTENT_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _canary_body(snapshot: CanarySnapshot) -> bytes:
    return (
        f'{{"generation":{snapshot.generation},"marker":"{snapshot.marker}",'
        f'"state_id":"{snapshot.state_id}"}}'
    ).encode()


class SemanticHttpLab:
    """Mutable owner of one loopback server and its deterministic canary state."""

    def __init__(self, manifest: LabManifest, mode: SemanticFixtureMode) -> None:
        self.manifest = manifest
        self.mode = mode
        self.instance_id = f"{manifest.lab_id}:{mode.value}"
        self._state = _CanaryStore(manifest.state_id)
        self._server: _LabHttpServer | None = None
        self._thread: Thread | None = None
        self._endpoint: LabEndpoint | None = None

    def start(self) -> LabEndpoint:
        if self._server is not None:
            raise LabLifecycleError("loopback lab is already started")
        server = _LabHttpServer((LOOPBACK_HOST, 0), self._state, self.mode)
        thread = Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name=f"faultloom-lab-{self.mode.value}",
            daemon=True,
        )
        thread.start()
        if not thread.is_alive():
            server.server_close()
            raise LabLifecycleError("loopback lab did not become ready")
        endpoint = LabEndpoint(host=LOOPBACK_HOST, port=server.server_port)
        self._server = server
        self._thread = thread
        self._endpoint = endpoint
        return endpoint

    def readiness(self) -> LabReadiness:
        thread = self._thread
        return LabReadiness(
            instance_id=self.instance_id,
            ready=thread is not None and thread.is_alive(),
            endpoint=self._endpoint,
        )

    def snapshot(self) -> CanarySnapshot:
        return self._state.snapshot()

    def reset(self) -> CanarySnapshot:
        return self._state.reset()

    def cleanup(self) -> CanarySnapshot:
        return self._state.reset()

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        if server is None or thread is None:
            return
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise LabLifecycleError("loopback lab thread did not stop")
        self._server = None
        self._thread = None
        self._endpoint = None


@contextmanager
def running_lab(
    manifest: LabManifest,
    mode: SemanticFixtureMode,
) -> Iterator[SemanticHttpLab]:
    """Start an owned lab and guarantee canary cleanup and shutdown."""

    lab = SemanticHttpLab(manifest, mode)
    lab.start()
    try:
        yield lab
    finally:
        lab.cleanup()
        lab.stop()


@contextmanager
def clean_replay(lab: SemanticHttpLab) -> Iterator[SemanticHttpLab]:
    """Run one replay from clean canary state and clean it again on exit."""

    lab.reset()
    try:
        yield lab
    finally:
        lab.cleanup()
