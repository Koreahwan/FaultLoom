from __future__ import annotations

from dataclasses import dataclass

from .browser_contracts import BrowserContractError
from .contracts import SemanticHttpObservation

_UNSAFE_RESPONSE_HEADERS = frozenset(
    {
        "connection",
        "content-disposition",
        "content-length",
        "keep-alive",
        "location",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass(frozen=True, slots=True)
class BrowserRouteArtifact:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def browser_route_artifact(observation: SemanticHttpObservation) -> BrowserRouteArtifact:
    if observation.status_code is None or observation.body is None:
        raise BrowserContractError("Gateway response has no browser-renderable bytes")
    if 300 <= observation.status_code < 400:
        raise BrowserContractError("browser redirects require a separately admitted route")
    headers: dict[str, str] = {}
    for header in observation.headers:
        name = header.name.casefold()
        if name in _UNSAFE_RESPONSE_HEADERS or name in headers:
            raise BrowserContractError("Gateway response header is unsafe for browser fulfillment")
        headers[name] = header.value.decode("latin-1")
    return BrowserRouteArtifact(
        status=observation.status_code,
        headers=tuple(headers.items()),
        body=observation.body,
    )
