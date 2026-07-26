from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from playwright.sync_api import Request, Route
from pydantic import ValidationError

from faultloom_protocol import SCHEMA_VERSION

from .browser_artifact import BrowserRouteArtifact, browser_route_artifact
from .browser_contracts import BrowserContractError
from .contracts import (
    BrowserChildCandidate,
    BrowserChildKind,
    EndpointScheme,
    SemanticEndpoint,
    SemanticHttpObservation,
    SemanticHttpRequest,
)

_SUBRESOURCE_TYPES = frozenset(
    {
        "eventsource",
        "fetch",
        "font",
        "image",
        "manifest",
        "media",
        "script",
        "stylesheet",
        "texttrack",
        "xhr",
    }
)
@dataclass(frozen=True, slots=True)
class FulfillIntercept:
    artifact: BrowserRouteArtifact


@dataclass(frozen=True, slots=True)
class PauseIntercept:
    candidate: BrowserChildCandidate


@dataclass(frozen=True, slots=True)
class AbortIntercept:
    reason: str


type InterceptDecision = FulfillIntercept | PauseIntercept | AbortIntercept


@dataclass(frozen=True, slots=True)
class _ArmedNavigation:
    url: str
    route_key: tuple[str, str, int, str]
    method: str
    artifact: BrowserRouteArtifact


@dataclass(frozen=True, slots=True)
class _PendingRoute:
    candidate: BrowserChildCandidate
    route: Route


class BrowserRouteRegistry:
    def __init__(self) -> None:
        self._armed: dict[str, _ArmedNavigation] = {}
        self._origins: dict[str, tuple[str, str, int]] = {}
        self._pending: dict[str, _PendingRoute] = {}
        self._discovered: dict[str, list[BrowserChildCandidate]] = {}
        self._consumed: set[str] = set()
        self._closed: set[str] = set()
        self._sequence = 0

    def arm_navigation(
        self,
        context_id: str,
        request: SemanticHttpRequest,
        observation: SemanticHttpObservation,
    ) -> str:
        if context_id in self._closed or context_id in self._armed:
            raise BrowserContractError("browser navigation route is unavailable")
        url = semantic_request_url(request)
        route_key = _route_key(url)
        self._armed[context_id] = _ArmedNavigation(
            url=url,
            route_key=route_key,
            method=request.method,
            artifact=browser_route_artifact(observation),
        )
        self._origins[context_id] = route_key[:3]
        return url

    def intercept(
        self,
        context_id: str,
        parent_action_id: str,
        route: Route,
        request: Request,
    ) -> InterceptDecision:
        if context_id in self._closed:
            return AbortIntercept("browser context is closed")
        armed = self._armed.get(context_id)
        if (
            armed is not None
            and _route_key(request.url) == armed.route_key
            and request.method == armed.method
        ):
            del self._armed[context_id]
            return FulfillIntercept(armed.artifact)
        parsed = urlsplit(request.url)
        kind = _child_kind(request)
        if kind is None:
            return AbortIntercept("browser transport is unsupported")
        if armed is not None or not _is_supported_child(
            parsed, request.method, self._origins.get(context_id)
        ):
            return AbortIntercept("browser route is outside the admitted HTTP subset")
        try:
            candidate = self._candidate(context_id, parent_action_id, kind, parsed)
        except ValidationError:
            return AbortIntercept("browser route is not canonical")
        pending = _PendingRoute(candidate=candidate, route=route)
        if candidate.candidate_id in self._pending or candidate.candidate_id in self._consumed:
            return AbortIntercept("browser route ID was reused")
        self._pending[candidate.candidate_id] = pending
        self._discovered.setdefault(context_id, []).append(candidate)
        return PauseIntercept(candidate)

    def take(self, candidate: BrowserChildCandidate) -> Route:
        if candidate.browser_context_id in self._closed:
            raise BrowserContractError("browser route expired with its context")
        pending = self._pending.pop(candidate.candidate_id, None)
        if pending is None:
            if candidate.candidate_id in self._consumed:
                raise BrowserContractError("browser route was already consumed")
            raise BrowserContractError("browser route was not intercepted")
        if pending.candidate != candidate:
            self._consumed.add(candidate.candidate_id)
            raise BrowserContractError("browser route differs from the admitted candidate")
        self._consumed.add(candidate.candidate_id)
        return pending.route

    def abort(self, candidate_id: str) -> Route:
        pending = self._pending.pop(candidate_id, None)
        if pending is None:
            raise BrowserContractError("browser route is unavailable for abort")
        self._consumed.add(candidate_id)
        return pending.route

    def drain_discovered(self, context_id: str) -> tuple[BrowserChildCandidate, ...]:
        return tuple(self._discovered.pop(context_id, ()))

    def close_context(self, context_id: str) -> tuple[Route, ...]:
        self._closed.add(context_id)
        self._armed.pop(context_id, None)
        self._origins.pop(context_id, None)
        self._discovered.pop(context_id, None)
        owned = tuple(
            candidate_id
            for candidate_id, pending in self._pending.items()
            if pending.candidate.browser_context_id == context_id
        )
        routes = tuple(self._pending.pop(candidate_id).route for candidate_id in owned)
        self._consumed.update(owned)
        return routes

    def _candidate(
        self,
        context_id: str,
        parent_action_id: str,
        kind: BrowserChildKind,
        parsed: SplitResult,
    ) -> BrowserChildCandidate:
        self._sequence += 1
        port = parsed.port or 80
        endpoint = SemanticEndpoint(
            schema_version=SCHEMA_VERSION,
            scheme=EndpointScheme.HTTP,
            hostname=parsed.hostname or "",
            port=port,
            path=parsed.path or "/",
        )
        semantic = SemanticHttpRequest(
            schema_version=SCHEMA_VERSION,
            endpoint=endpoint,
            method="GET",
        )
        material = (
            f"{context_id}\0{parent_action_id}\0{self._sequence}\0"
            f"{semantic_request_url(semantic)}\0{kind.value}"
        ).encode()
        digest = f"sha256:{hashlib.sha256(material).hexdigest()}"
        return BrowserChildCandidate(
            schema_version=SCHEMA_VERSION,
            candidate_id=f"child.{digest.removeprefix('sha256:')}",
            parent_action_id=parent_action_id,
            browser_context_id=context_id,
            kind=kind,
            endpoint=endpoint,
            request=semantic,
            discovery_digest=digest,
        )


def semantic_request_url(request: SemanticHttpRequest) -> str:
    endpoint = request.endpoint
    if endpoint.scheme is not EndpointScheme.HTTP or endpoint.query:
        raise BrowserContractError("live Chromium supports canonical plain HTTP without query")
    return f"http://{endpoint.hostname}:{endpoint.port}{endpoint.path}"


def _child_kind(request: Request) -> BrowserChildKind | None:
    if request.resource_type == "document" and request.frame.parent_frame is not None:
        return BrowserChildKind.IFRAME
    if request.resource_type in _SUBRESOURCE_TYPES:
        return BrowserChildKind.SUBRESOURCE
    return None


def _is_supported_child(
    parsed: SplitResult,
    method: str,
    origin: tuple[str, str, int] | None,
) -> bool:
    return (
        origin == (parsed.scheme, parsed.hostname, parsed.port or 80)
        and parsed.scheme == "http"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and method == "GET"
    )


def _route_key(url: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(url)
    return (
        parsed.scheme,
        parsed.hostname or "",
        parsed.port or 80,
        parsed.path or "/",
    )
