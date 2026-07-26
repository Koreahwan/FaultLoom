"""A loopback-only source of fixed app-link/API binding observations."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Literal, final
from urllib.parse import urlparse
from urllib.request import urlopen

from faultloom_mobile import (
    G46_PINNED_MANIFEST,
    G46AdmissionToken,
    G46PreparedGatewayCommand,
    G46SyntheticIdentities,
    G46VerifierReceipt,
    MobileApiBindingRun,
    assert_g46_no_secrets,
    observe_mobile_api_binding,
    prepare_g46_gateway_command,
    verify_g46_fixture,
)

CaseId = Literal["mismatch", "negative"]
EvidenceKind = Literal["app-link", "api-binding"]


@dataclass(frozen=True)
class MobileApiBindingFixtureResponse:
    url: str
    body: bytes


@dataclass(frozen=True, slots=True)
class G46FixtureState:
    phase: Literal["ready", "completed"] = "ready"
    runs: int = 0
    simulated_io_count: Literal[0] = 0


@dataclass(frozen=True, slots=True)
class G46FixtureRun:
    observation: MobileApiBindingRun
    command: G46PreparedGatewayCommand | None
    receipt: G46VerifierReceipt


@final
class OwnedG46MobileApiFixture:
    """Fully simulated G46 source with a signed, bounded, inert command seam."""

    endpoint = "fixture://owned-g46-mobile-api"
    initial_state = G46FixtureState()

    def __init__(
        self,
        admission_token: G46AdmissionToken,
        authority_public_key: bytes,
        now_epoch_seconds: int,
    ) -> None:
        if type(admission_token) is not G46AdmissionToken:
            raise TypeError("G46 fixture requires a G46 admission envelope")
        self.admission_token = admission_token
        self.authority_public_key = bytes(authority_public_key)
        self.now_epoch_seconds = now_epoch_seconds
        self.identities = G46SyntheticIdentities(
            device_id=admission_token.device_id,
            application_id=admission_token.application_id,
            api_id=admission_token.api_id,
        )
        self.admission_token.assert_verified(
            G46_PINNED_MANIFEST,
            self.identities,
            self.authority_public_key,
            now_epoch_seconds,
        )
        self.state = self.initial_state

    def __enter__(self) -> "OwnedG46MobileApiFixture":
        if self.state != self.initial_state:
            raise RuntimeError("G46 fixture must start from its declared initial state")
        return self

    def __exit__(self, *_args: object) -> None:
        self.cleanup()

    def run(self, case_id: CaseId) -> G46FixtureRun:
        if self.state != self.initial_state:
            raise RuntimeError("reset or cleanup is required before another G46 fixture run")
        observation = observe_mobile_api_binding(_G46SuppliedJsonSource(), case_id)
        command = (
            prepare_g46_gateway_command(
                observation,
                G46_PINNED_MANIFEST,
                self.admission_token,
                self.authority_public_key,
                self.now_epoch_seconds,
            )
            if observation.evidence.classification == "diagnostic_candidate"
            else None
        )
        receipt = verify_g46_fixture(
            observation,
            G46_PINNED_MANIFEST,
            self.admission_token,
            command,
            self.authority_public_key,
            self.now_epoch_seconds,
        )
        self.state = replace(self.state, phase="completed", runs=1)
        self.assert_no_secrets()
        return G46FixtureRun(observation=observation, command=command, receipt=receipt)

    def reset(self) -> None:
        self.state = self.initial_state

    def cleanup(self) -> None:
        self.reset()

    def assert_no_secrets(self) -> None:
        assert_g46_no_secrets(
            (
                G46_PINNED_MANIFEST,
                self.admission_token,
                self.identities,
                _G46_ROUTES,
            )
        )

    def assert_fully_simulated(self) -> None:
        if self.endpoint != "fixture://owned-g46-mobile-api":
            raise AssertionError("G46 fixture must not identify an external API endpoint")
        if self.state.simulated_io_count != 0:
            raise AssertionError("G46 fixture must not perform device or API I/O")


@final
class _G46SuppliedJsonSource:
    """Return pre-supplied JSON only; this type performs no I/O."""

    def read(
        self, case_id: CaseId, evidence: EvidenceKind
    ) -> MobileApiBindingFixtureResponse:
        try:
            body = _G46_ROUTES[(case_id, evidence)]
        except KeyError as exc:
            raise ValueError("G46 supplied JSON case is not declared") from exc
        return MobileApiBindingFixtureResponse(
            url=f"fixture://owned-g46-mobile-api/{case_id}/{evidence}", body=body
        )


_G46_ROUTES = {
    ("mismatch", "app-link"): json.dumps(
        {
            "application_id": "synthetic.g46.application.mobile",
            "deep_link": "fixture://owned-g46-mobile-api/callback",
            "api_audience": "synthetic.g46.audience.public",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode(),
    ("mismatch", "api-binding"): json.dumps(
        {
            "api_id": "synthetic.g46.api.binding",
            "binding_id": "synthetic.g46.binding.mismatch",
            "bound_deep_link": "fixture://owned-g46-mobile-api/callback",
            "api_audience": "audience-b",
            "token_material_present": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode(),
    ("negative", "app-link"): json.dumps(
        {
            "application_id": "synthetic.g46.application.mobile",
            "deep_link": "fixture://owned-g46-mobile-api/callback",
            "api_audience": "synthetic.g46.audience.public",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode(),
    ("negative", "api-binding"): json.dumps(
        {
            "api_id": "synthetic.g46.api.binding",
            "binding_id": "synthetic.g46.binding.negative",
            "bound_deep_link": "fixture://owned-g46-mobile-api/callback",
            "api_audience": "synthetic.g46.audience.public",
            "token_material_present": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode(),
}


@final
class LoopbackMobileApiBindingFixture:
    """Serve static evidence over loopback GET and never control a device."""

    def __init__(self) -> None:
        self._requests: list[tuple[str, str]] = []
        self._request_lock = Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    def __enter__(self) -> "LoopbackMobileApiBindingFixture":
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
            raise RuntimeError("mobile/API fixture is not running")
        host, port = self._server.server_address[:2]
        if host != "127.0.0.1":
            raise RuntimeError("mobile/API fixture must bind loopback only")
        return f"http://{host}:{port}"

    @property
    def requests(self) -> tuple[tuple[str, str], ...]:
        with self._request_lock:
            return tuple(self._requests)

    def read(
        self, case_id: CaseId, evidence: EvidenceKind
    ) -> MobileApiBindingFixtureResponse:
        url = f"{self.base_url}/{case_id}/{evidence}"
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise ValueError("mobile/API fixture permits only loopback HTTP")
        with urlopen(url, timeout=2) as response:  # noqa: S310 - fixed owned fixture
            return MobileApiBindingFixtureResponse(url=url, body=response.read())

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
            "/mismatch/app-link": (
                b'{"application_id":"com.fixture.mobile",'
                b'"deep_link":"fixture://authorized/callback",'
                b'"api_audience":"mobile.client.public"}'
            ),
            "/mismatch/api-binding": (
                b'{"binding_id":"fixture-binding-42",'
                b'"api_id":"fixture.api.binding",'
                b'"bound_deep_link":"fixture://authorized/callback",'
                b'"api_audience":"mobile.client.private"}'
            ),
            "/negative/app-link": (
                b'{"application_id":"com.fixture.mobile",'
                b'"deep_link":"fixture://authorized/callback",'
                b'"api_audience":"mobile.client.public"}'
            ),
            "/negative/api-binding": (
                b'{"binding_id":"fixture-binding-43",'
                b'"api_id":"fixture.api.binding",'
                b'"bound_deep_link":"fixture://authorized/callback",'
                b'"api_audience":"mobile.client.public"}'
            ),
        }
