"""Typed, secret-safe contracts for Gateway-mediated semantic execution.

These models describe requests to the local Gateway.  They deliberately do not
contain target transport methods: resolving DNS, opening sockets, compiling
wire bytes, and resolving secret references remain Gateway responsibilities.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Annotated, Self

from pydantic import AfterValidator, ConfigDict, Field, model_validator

from faultloom_protocol import (
    ActionIntent,
    ActionLease,
    DecisionOutcome,
    DispatchReceipt,
    ObservationRef,
    PolicyDecision,
    ProtocolModel,
    SecretRef,
    sha256_digest,
)
from faultloom_protocol.base import Identifier, NonEmptyStr, Sha256Digest, ShortStr

SEMANTIC_HTTP_ACTION_KIND = "http.semantic"

_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Z]+$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SENSITIVE_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "cookie",
        "credential",
        "id_token",
        "password",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "session",
        "session_id",
        "token",
        "x_api_key",
    }
)
_SENSITIVE_COMPACT_NAMES = frozenset(name.replace("_", "") for name in _SENSITIVE_NAMES)
_SENSITIVE_NAME_PARTS = frozenset(
    {
        "auth",
        "authorization",
        "cookie",
        "credential",
        "key",
        "password",
        "secret",
        "session",
        "token",
    }
)
_COMPILER_OWNED_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


def _canonical_method(value: str) -> str:
    if value != value.upper() or not _HTTP_TOKEN.fullmatch(value):
        raise ValueError("HTTP method must be one canonical uppercase token")
    return value


HttpMethod = Annotated[str, Field(min_length=1, max_length=32), AfterValidator(_canonical_method)]


def _canonical_hostname(value: str) -> str:
    if value != value.strip() or value != value.casefold() or value.endswith("."):
        raise ValueError("hostname must be lowercase canonical text without a trailing dot")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("hostname must already be canonical ASCII/IDNA text") from exc
        if len(encoded) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in value.split(".")):
            raise ValueError("hostname is not a canonical DNS name")
    else:
        if address.compressed != value:
            raise ValueError("IP address must use its canonical compressed form")
    return value


Hostname = Annotated[str, Field(min_length=1, max_length=253), AfterValidator(_canonical_hostname)]


def _safe_component(value: str) -> str:
    if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("semantic values cannot contain control separators")
    return value


SafeValue = Annotated[NonEmptyStr, AfterValidator(_safe_component)]


def _looks_sensitive_name(value: str) -> bool:
    normalized = value.casefold().replace("-", "_")
    parts = frozenset(part for part in normalized.split("_") if part)
    compact = normalized.replace("_", "")
    return (
        normalized in _SENSITIVE_NAMES
        or bool(parts.intersection(_SENSITIVE_NAME_PARTS))
        or compact in _SENSITIVE_COMPACT_NAMES
    )


class EndpointScheme(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    WS = "ws"
    WSS = "wss"


class ExecutionModel(ProtocolModel):
    """Protocol strictness without silent whitespace rewriting."""

    model_config = ConfigDict(
        **{**ProtocolModel.model_config, "str_strip_whitespace": False}
    )


class SemanticValue(ExecutionModel):
    """One non-secret literal or an opaque vault reference, never both."""

    literal: SafeValue | None = None
    secret_ref: SecretRef | None = None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> Self:
        if (self.literal is None) == (self.secret_ref is None):
            raise ValueError("semantic value requires exactly one literal or secret_ref")
        return self


class SemanticHeader(ExecutionModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    value: SemanticValue

    @model_validator(mode="after")
    def _safe_header(self) -> Self:
        if self.name != self.name.casefold() or not _HEADER_NAME.fullmatch(self.name):
            raise ValueError("header name must be one canonical lowercase token")
        if self.name in _COMPILER_OWNED_HEADERS:
            raise ValueError("hop-by-hop and framing headers are owned by the Gateway compiler")
        if _looks_sensitive_name(self.name) and self.value.secret_ref is None:
            raise ValueError("sensitive request headers require a secret_ref")
        return self


class SemanticQueryParameter(ExecutionModel):
    name: Annotated[str, Field(min_length=1, max_length=256)]
    value: SemanticValue

    @model_validator(mode="after")
    def _safe_query_parameter(self) -> Self:
        if self.name != self.name.strip() or any(char in self.name for char in "&=#\r\n\x00"):
            raise ValueError("query parameter name must be unambiguous semantic text")
        if _looks_sensitive_name(self.name) and self.value.secret_ref is None:
            raise ValueError("sensitive query parameters require a secret_ref")
        return self


class SemanticEndpoint(ExecutionModel):
    scheme: EndpointScheme
    hostname: Hostname
    port: Annotated[int, Field(ge=1, le=65535)]
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    query: tuple[SemanticQueryParameter, ...] = ()

    @model_validator(mode="after")
    def _canonical_path(self) -> Self:
        if not self.path.startswith("/") or any(char in self.path for char in "?#\r\n\x00"):
            raise ValueError("path must be an absolute semantic path without query or fragment")
        try:
            encoded = self.path.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("path must already use ASCII percent encoding") from exc
        if any(byte <= 32 or byte == 127 for byte in encoded):
            raise ValueError("path must already use ASCII percent encoding")
        index = 0
        while index < len(self.path):
            if self.path[index] == "%":
                triplet = self.path[index + 1 : index + 3]
                if len(triplet) != 2 or any(char not in "0123456789ABCDEF" for char in triplet):
                    raise ValueError("percent escapes must use canonical uppercase hex")
                index += 3
            else:
                index += 1
        return self


class SemanticBodyRef(ExecutionModel):
    cas_digest: Sha256Digest
    byte_length: Annotated[int, Field(ge=0, le=2**63 - 1)]
    media_type: ShortStr


class SemanticHttpRequest(ExecutionModel):
    """A compiler input; it is not a serialized raw HTTP request."""

    endpoint: SemanticEndpoint
    method: HttpMethod
    headers: tuple[SemanticHeader, ...] = ()
    body_ref: SemanticBodyRef | None = None

    @model_validator(mode="after")
    def _http_only_and_unambiguous(self) -> Self:
        if self.endpoint.scheme not in {EndpointScheme.HTTP, EndpointScheme.HTTPS}:
            raise ValueError("SemanticHttpRequest only supports http and https")
        names = [header.name for header in self.headers]
        if len(names) != len(set(names)):
            raise ValueError("duplicate semantic header names are forbidden")
        return self


class ExecutionIdentity(ExecutionModel):
    """An isolated session handle; raw credentials and cookies never appear here."""

    context_id: Identifier
    identity_id: Identifier | None = None
    tenant_id: Identifier | None = None
    session_ref: SecretRef | None = None

    @model_validator(mode="after")
    def _session_belongs_to_an_identity(self) -> Self:
        if self.session_ref is not None and self.identity_id is None:
            raise ValueError("an authenticated session requires an identity_id")
        return self


class GatewayDispatchCommand(ExecutionModel):
    """One approved action handed to the only target-egress process."""

    intent: ActionIntent
    decision: PolicyDecision
    lease: ActionLease
    request: SemanticHttpRequest
    identity: ExecutionIdentity

    @model_validator(mode="after")
    def _bindings_are_exact(self) -> Self:
        intent_digest = sha256_digest(self.intent)
        payload_digest = semantic_payload_digest(self.request, self.identity)
        if self.intent.action_kind != SEMANTIC_HTTP_ACTION_KIND:
            raise ValueError("action kind is not the admitted semantic HTTP family")
        if self.intent.payload_digest != payload_digest:
            raise ValueError(
                "intent payload_digest is not bound to the request and session context"
            )
        if self.intent.protocol != self.request.endpoint.scheme.value:
            raise ValueError("intent protocol differs from the semantic endpoint")
        if (
            self.intent.method != self.request.method
            or self.intent.path != self.request.endpoint.path
        ):
            raise ValueError("intent method/path differs from the semantic request")
        if self.intent.resource.target_id != self.intent.target_id:
            raise ValueError("intent resource target differs from target_id")
        if self.intent.subject.identity_id != self.identity.identity_id:
            raise ValueError("execution identity differs from the action subject")
        if self.intent.subject.tenant_id != self.identity.tenant_id:
            raise ValueError("execution tenant differs from the action subject")
        if self.decision.outcome is not DecisionOutcome.ALLOW:
            raise ValueError("only an allow decision can be dispatched")
        if (
            self.decision.intent_digest != intent_digest
            or self.lease.intent_digest != intent_digest
        ):
            raise ValueError("decision/lease is not bound to the intent")
        if self.decision.lease_id != self.lease.lease_id:
            raise ValueError("decision is not bound to the supplied lease")
        decision_scope = (
            self.decision.grant_id,
            self.decision.grant_version,
            self.decision.scope_epoch,
        )
        lease_scope = (self.lease.grant_id, self.lease.grant_version, self.lease.scope_epoch)
        if decision_scope != lease_scope:
            raise ValueError("decision and lease scope bindings differ")
        if not (
            self.intent.requested_at
            <= self.decision.evaluated_at
            <= self.lease.issued_at
        ):
            raise ValueError("intent, decision, and lease timestamps are not causally ordered")
        return self

    @property
    def intent_digest(self) -> str:
        return sha256_digest(self.intent)

    @property
    def decision_digest(self) -> str:
        return sha256_digest(self.decision)


def semantic_payload_digest(request: SemanticHttpRequest, identity: ExecutionIdentity) -> str:
    """Bind compiler input and the opaque session handle into one intent digest."""

    return sha256_digest({"identity": identity, "request": request})


class BrowserChildKind(str, Enum):
    REDIRECT = "redirect"
    IFRAME = "iframe"
    SUBRESOURCE = "subresource"
    SERVICE_WORKER = "service_worker"
    WEBSOCKET = "websocket"
    DOWNLOAD = "download"


class BrowserChildCandidate(ExecutionModel):
    """A discovered child request, not an authorization to send it."""

    candidate_id: Identifier
    parent_action_id: Identifier
    browser_context_id: Identifier
    kind: BrowserChildKind
    endpoint: SemanticEndpoint
    request: SemanticHttpRequest | None = None
    discovery_digest: Sha256Digest

    @model_validator(mode="after")
    def _transport_matches_kind(self) -> Self:
        if self.kind is BrowserChildKind.WEBSOCKET:
            if self.endpoint.scheme not in {EndpointScheme.WS, EndpointScheme.WSS}:
                raise ValueError("WebSocket candidates require ws or wss")
            if self.request is not None:
                raise ValueError("WebSocket execution belongs to its separately admitted engine")
        else:
            if self.request is None or self.request.endpoint != self.endpoint:
                raise ValueError("HTTP browser children require an exact semantic request")
        return self


class SemanticHttpObservation(ExecutionModel):
    response_ref: ObservationRef
    child_candidates: tuple[BrowserChildCandidate, ...] = ()

    @model_validator(mode="after")
    def _candidate_ids_are_unique(self) -> Self:
        ids = [candidate.candidate_id for candidate in self.child_candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("browser child candidate IDs must be unique")
        return self


class GatewayDispatchResult(ExecutionModel):
    receipt: DispatchReceipt
    observation: SemanticHttpObservation | None = None


class GatewayDeniedResult(ExecutionModel):
    action_id: Identifier
    request_digest: Sha256Digest
    reason_code: Identifier


GatewayResult = GatewayDispatchResult | GatewayDeniedResult
