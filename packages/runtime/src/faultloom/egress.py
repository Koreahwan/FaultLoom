"""Fail-closed control plane for non-target egress.

The target Gateway, model-provider proxy, and knowledge fetcher are separate
egress planes.  This module owns only the deterministic policy boundary for
the latter two planes.  Concrete transports are injected and receive an
immutable, policy-compiled request; callers cannot supply a destination URL.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from faultloom_protocol import (
    AuthorityGrant,
    ProtocolModel,
    SCHEMA_VERSION,
    SecretRef,
    sha256_digest,
)
from faultloom_protocol.base import (
    AwareDatetime,
    Identifier,
    NonEmptyStr,
    Sha256Digest,
    ShortStr,
)

NonNegativeInt = Annotated[int, Field(ge=0, le=2**63 - 1)]
PositiveInt = Annotated[int, Field(ge=1, le=2**63 - 1)]

_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")


class EgressPlane(str, Enum):
    TARGET = "target"
    MODEL_PROVIDER = "model_provider"
    KNOWLEDGE = "knowledge"


class ProviderToolKind(str, Enum):
    LOCAL = "local"
    PROVIDER_WEB = "provider_web"
    PROVIDER_COMPUTER = "provider_computer"


class TransportOutcome(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"


class EgressOutcome(str, Enum):
    DENIED = "denied"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"


class DenialCode(str, Enum):
    AUTHORITY_BINDING_MISMATCH = "authority_binding_mismatch"
    AUTHORITY_NOT_CURRENT = "authority_not_current"
    DATA_POLICY_DENIED = "data_policy_denied"
    DESTINATION_OVERLAPS_TARGET = "destination_overlaps_target"
    ENDPOINT_DENIED = "endpoint_denied"
    KNOWLEDGE_METHOD_DENIED = "knowledge_method_denied"
    KNOWLEDGE_PATH_DENIED = "knowledge_path_denied"
    MODEL_SNAPSHOT_DENIED = "model_snapshot_denied"
    PROVIDER_DENIED = "provider_denied"
    PROVIDER_TOOL_DENIED = "provider_tool_denied"
    PROVIDER_TOOL_LIVE_DENIED = "provider_tool_live_denied"
    REQUEST_BUDGET_EXCEEDED = "request_budget_exceeded"
    REQUEST_TIME_INVALID = "request_time_invalid"
    SECRET_REFERENCE_DENIED = "secret_reference_denied"
    SCOPE_EPOCH_MISMATCH = "scope_epoch_mismatch"
    SOURCE_DENIED = "source_denied"
    TRANSPORT_PLANE_MISMATCH = "transport_plane_mismatch"


def _origin_host(origin: str) -> str:
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
    ):
        raise ValueError("origin must be an HTTPS origin without path, credentials, or query")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("origin contains an invalid port") from exc
    host = parsed.hostname
    if not host.isascii() or host != host.casefold() or host.endswith("."):
        raise ValueError("origin hostname must be canonical lowercase ASCII")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or labels[-1].isdecimal() or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
            for label in labels
        ):
            raise ValueError("origin hostname is invalid")
        authority = host
    else:
        authority = f"[{address.compressed}]" if address.version == 6 else address.compressed
    if port is not None and port != 443:
        authority += f":{port}"
    if origin != f"https://{authority}":
        raise ValueError("origin must use its canonical form")
    return host


def _validate_path(path: str) -> None:
    if (
        _SAFE_PATH.fullmatch(path) is None
        or "//" in path
        or "%" in path
        or "\\" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise ValueError("knowledge path must be a canonical absolute path without traversal")


def _path_is_below(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    base = prefix.rstrip("/")
    return path == base or path.startswith(base + "/")


class ProviderTool(ProtocolModel):
    tool_id: Identifier
    kind: ProviderToolKind


class ProviderEndpoint(ProtocolModel):
    endpoint_id: Identifier
    provider_id: Identifier
    origin: ShortStr
    tools: tuple[ProviderTool, ...] = ()

    @model_validator(mode="after")
    def _valid_endpoint(self) -> "ProviderEndpoint":
        _origin_host(self.origin)
        tool_ids = tuple(tool.tool_id for tool in self.tools)
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("provider endpoint tool IDs must be unique")
        return self


class KnowledgeSource(ProtocolModel):
    source_id: Identifier
    origin: ShortStr
    allowed_path_prefixes: tuple[NonEmptyStr, ...]
    allowed_methods: tuple[Literal["GET", "HEAD"], ...] = ("GET",)
    allowed_data_policy_ids: tuple[Identifier, ...]
    maximum_response_bytes: PositiveInt

    @model_validator(mode="after")
    def _valid_source(self) -> "KnowledgeSource":
        _origin_host(self.origin)
        if not self.allowed_path_prefixes:
            raise ValueError("knowledge source requires at least one allowed path prefix")
        if not self.allowed_methods or not self.allowed_data_policy_ids:
            raise ValueError("knowledge source requires methods and data policies")
        for prefix in self.allowed_path_prefixes:
            _validate_path(prefix)
        for name, values in (
            ("path prefixes", self.allowed_path_prefixes),
            ("methods", self.allowed_methods),
            ("data policies", self.allowed_data_policy_ids),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"knowledge source {name} must be unique")
        return self


class ProviderRequest(ProtocolModel):
    request_id: Identifier
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    endpoint_id: Identifier
    provider_id: Identifier
    model_snapshot: ShortStr
    data_policy_id: Identifier
    credential_ref: SecretRef
    payload_digest: Sha256Digest
    payload_bytes: NonNegativeInt
    tool_ids: tuple[Identifier, ...] = ()
    requested_at: AwareDatetime
    live: bool

    @model_validator(mode="after")
    def _unique_tools(self) -> "ProviderRequest":
        if len(self.tool_ids) != len(set(self.tool_ids)):
            raise ValueError("provider request tool IDs must be unique")
        return self


class KnowledgeFetchIntent(ProtocolModel):
    request_id: Identifier
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    source_id: Identifier
    method: Literal["GET", "HEAD"]
    path: NonEmptyStr
    data_policy_id: Identifier
    requested_at: AwareDatetime

    @model_validator(mode="after")
    def _canonical_path(self) -> "KnowledgeFetchIntent":
        _validate_path(self.path)
        return self


class CompiledProviderRequest(ProtocolModel):
    plane: Literal[EgressPlane.MODEL_PROVIDER] = EgressPlane.MODEL_PROVIDER
    request_id: Identifier
    endpoint_id: Identifier
    provider_id: Identifier
    origin: ShortStr
    model_snapshot: ShortStr
    data_policy_id: Identifier
    credential_ref: SecretRef
    payload_digest: Sha256Digest
    payload_bytes: NonNegativeInt
    tool_ids: tuple[Identifier, ...]
    maximum_request_bytes: PositiveInt
    maximum_response_bytes: PositiveInt
    follow_redirects: Literal[False] = False


class CompiledKnowledgeRequest(ProtocolModel):
    plane: Literal[EgressPlane.KNOWLEDGE] = EgressPlane.KNOWLEDGE
    request_id: Identifier
    source_id: Identifier
    origin: ShortStr
    method: Literal["GET", "HEAD"]
    path: NonEmptyStr
    data_policy_id: Identifier
    maximum_response_bytes: PositiveInt
    follow_redirects: Literal[False] = False


class EgressTransportResult(ProtocolModel):
    plane: EgressPlane
    outcome: TransportOutcome
    response_digest: Sha256Digest | None = None
    response_status: NonNegativeInt | None = None
    bytes_sent: NonNegativeInt
    bytes_received: NonNegativeInt


class EgressReceipt(ProtocolModel):
    receipt_digest: Sha256Digest
    plane: EgressPlane
    request_id: Identifier
    request_digest: Sha256Digest
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    policy_digest: Sha256Digest
    destination_digest: Sha256Digest | None
    outcome: EgressOutcome
    denial_code: DenialCode | None
    response_digest: Sha256Digest | None
    response_status: NonNegativeInt | None
    bytes_sent: NonNegativeInt
    bytes_received: NonNegativeInt
    evaluated_at: AwareDatetime
    reconciliation_required: bool = False

    @model_validator(mode="after")
    def _outcome_contract(self) -> "EgressReceipt":
        if (self.outcome is EgressOutcome.DENIED) != (self.denial_code is not None):
            raise ValueError("only denied receipts carry a denial code")
        if (self.outcome is EgressOutcome.UNKNOWN_OUTCOME) != self.reconciliation_required:
            raise ValueError("only unknown outcomes require reconciliation")
        if self.outcome is EgressOutcome.DENIED and (self.bytes_sent or self.bytes_received):
            raise ValueError("denied receipts cannot report transport bytes")
        return self


class ProviderTransport(Protocol):
    plane: EgressPlane

    def dispatch(self, request: CompiledProviderRequest) -> EgressTransportResult: ...


class KnowledgeTransport(Protocol):
    plane: EgressPlane

    def dispatch(self, request: CompiledKnowledgeRequest) -> EgressTransportResult: ...


Clock = Callable[[], datetime]


def _system_clock() -> datetime:
    return datetime.now(timezone.utc)


def _trusted_now(clock: Clock) -> datetime:
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise RuntimeError("egress clock must return a timezone-aware datetime")
    return now


def _authority_is_current(grant: AuthorityGrant, now: datetime) -> bool:
    return (
        grant.not_before <= now < grant.expires_at
        and any(window.starts_at <= now < window.ends_at for window in grant.execution_windows)
    )


def _hostname_matches_target(host: str, target_hostname: str) -> bool:
    candidate = target_hostname.casefold().rstrip(".")
    if candidate.startswith("*."):
        suffix = candidate[2:]
        if not _valid_target_hostname(suffix):
            return True
        return host.endswith("." + suffix)
    if not _valid_target_hostname(candidate):
        return True
    return host == candidate or host.endswith("." + candidate)


def _valid_target_hostname(host: str) -> bool:
    if not host or not host.isascii():
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is not None
            for label in host.split(".")
        )
    return True


def _destination_overlaps_targets(origin: str, grant: AuthorityGrant) -> bool:
    host = _origin_host(origin)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for target in grant.targets:
        if any(_hostname_matches_target(host, name) for name in target.hostnames):
            return True
        for raw_network in target.cidrs:
            try:
                network = ipaddress.ip_network(raw_network, strict=False)
            except ValueError:
                return True
            if address is not None and address in network:
                return True
    return False


def _registry(values: Iterable[ProtocolModel], attribute: str) -> dict[str, ProtocolModel]:
    result: dict[str, ProtocolModel] = {}
    for value in values:
        key = getattr(value, attribute)
        if key in result:
            raise ValueError(f"duplicate egress policy ID: {key}")
        result[key] = value
    return result


def _receipt(
    *,
    plane: EgressPlane,
    request_id: str,
    request_digest: str,
    authority_digest: str,
    scope_epoch: int,
    policy_digest: str,
    destination_digest: str | None,
    outcome: EgressOutcome,
    denial_code: DenialCode | None,
    result: EgressTransportResult | None,
    evaluated_at: datetime,
) -> EgressReceipt:
    response_digest = None if result is None else result.response_digest
    response_status = None if result is None else result.response_status
    bytes_sent = 0 if result is None else result.bytes_sent
    bytes_received = 0 if result is None else result.bytes_received
    reconciliation_required = outcome is EgressOutcome.UNKNOWN_OUTCOME
    payload = {
        "schema_version": SCHEMA_VERSION,
        "plane": plane,
        "request_id": request_id,
        "request_digest": request_digest,
        "authority_digest": authority_digest,
        "scope_epoch": scope_epoch,
        "policy_digest": policy_digest,
        "destination_digest": destination_digest,
        "outcome": outcome,
        "denial_code": denial_code,
        "response_digest": response_digest,
        "response_status": response_status,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "evaluated_at": evaluated_at,
        "reconciliation_required": reconciliation_required,
    }
    return EgressReceipt(
        receipt_digest=sha256_digest(payload),
        **payload,
    )


def _transport_outcome(result: EgressTransportResult) -> EgressOutcome:
    return EgressOutcome(result.outcome.value)


class ProviderProxy:
    """Compile model calls onto one immutable provider egress plane."""

    def __init__(
        self,
        *,
        endpoints: Iterable[ProviderEndpoint],
        transport: ProviderTransport,
        live: bool,
        scope_epoch: int,
        clock: Clock = _system_clock,
    ) -> None:
        if transport.plane is not EgressPlane.MODEL_PROVIDER:
            raise ValueError("provider proxy requires a model-provider transport")
        if type(live) is not bool:
            raise ValueError("provider proxy live mode must be a boolean")
        self._endpoints = _registry(endpoints, "endpoint_id")
        self._transport = transport
        self._live = live
        if type(scope_epoch) is not int or scope_epoch < 1:
            raise ValueError("provider proxy scope epoch must be a positive integer")
        self._scope_epoch = scope_epoch
        self._clock = clock

    def dispatch(self, request: ProviderRequest, grant: AuthorityGrant) -> EgressReceipt:
        now = _trusted_now(self._clock)
        request_digest = sha256_digest(request)
        grant_digest = sha256_digest(grant)
        endpoint = self._endpoints.get(request.endpoint_id)
        policy_digest = sha256_digest(
            {
                "schema_version": SCHEMA_VERSION,
                "plane": EgressPlane.MODEL_PROVIDER,
                "provider_policy": grant.provider_policy,
                "endpoint": endpoint,
                "live": self._live,
            }
        )

        denial = self._provider_denial(request, grant, grant_digest, endpoint, now)
        if denial is not None:
            return _receipt(
                plane=EgressPlane.MODEL_PROVIDER,
                request_id=request.request_id,
                request_digest=request_digest,
                authority_digest=grant_digest,
                scope_epoch=self._scope_epoch,
                policy_digest=policy_digest,
                destination_digest=None,
                outcome=EgressOutcome.DENIED,
                denial_code=denial,
                result=None,
                evaluated_at=now,
            )
        assert isinstance(endpoint, ProviderEndpoint)
        compiled = CompiledProviderRequest(
            schema_version=SCHEMA_VERSION,
            request_id=request.request_id,
            endpoint_id=endpoint.endpoint_id,
            provider_id=request.provider_id,
            origin=endpoint.origin,
            model_snapshot=request.model_snapshot,
            data_policy_id=request.data_policy_id,
            credential_ref=request.credential_ref,
            payload_digest=request.payload_digest,
            payload_bytes=request.payload_bytes,
            tool_ids=request.tool_ids,
            maximum_request_bytes=grant.budget.max_request_bytes,
            maximum_response_bytes=grant.budget.max_response_bytes,
        )
        return self._dispatch_compiled(
            request=request,
            compiled=compiled,
            grant_digest=grant_digest,
            policy_digest=policy_digest,
            now=now,
        )

    def _provider_denial(
        self,
        request: ProviderRequest,
        grant: AuthorityGrant,
        grant_digest: str,
        endpoint: ProtocolModel | None,
        now: datetime,
    ) -> DenialCode | None:
        if request.authority_digest != grant_digest:
            return DenialCode.AUTHORITY_BINDING_MISMATCH
        if request.scope_epoch != self._scope_epoch:
            return DenialCode.SCOPE_EPOCH_MISMATCH
        if request.live != self._live:
            return DenialCode.AUTHORITY_BINDING_MISMATCH
        if request.requested_at > now:
            return DenialCode.REQUEST_TIME_INVALID
        if not _authority_is_current(grant, now):
            return DenialCode.AUTHORITY_NOT_CURRENT
        if endpoint is None or not isinstance(endpoint, ProviderEndpoint):
            return DenialCode.ENDPOINT_DENIED
        if endpoint.provider_id != request.provider_id:
            return DenialCode.ENDPOINT_DENIED
        policy = grant.provider_policy
        if request.provider_id not in policy.allowed_providers:
            return DenialCode.PROVIDER_DENIED
        if request.model_snapshot not in policy.allowed_model_snapshots:
            return DenialCode.MODEL_SNAPSHOT_DENIED
        if request.data_policy_id != policy.data_policy_id:
            return DenialCode.DATA_POLICY_DENIED
        if request.payload_bytes > grant.budget.max_request_bytes:
            return DenialCode.REQUEST_BUDGET_EXCEEDED
        if request.credential_ref.purpose != f"model-provider:{request.provider_id}":
            return DenialCode.SECRET_REFERENCE_DENIED
        tools = {tool.tool_id: tool for tool in endpoint.tools}
        for tool_id in request.tool_ids:
            tool = tools.get(tool_id)
            if tool is None:
                return DenialCode.PROVIDER_TOOL_DENIED
            if self._live and tool.kind in {
                ProviderToolKind.PROVIDER_WEB,
                ProviderToolKind.PROVIDER_COMPUTER,
            }:
                return DenialCode.PROVIDER_TOOL_LIVE_DENIED
        if _destination_overlaps_targets(endpoint.origin, grant):
            return DenialCode.DESTINATION_OVERLAPS_TARGET
        if self._transport.plane is not EgressPlane.MODEL_PROVIDER:
            return DenialCode.TRANSPORT_PLANE_MISMATCH
        return None

    def _dispatch_compiled(
        self,
        *,
        request: ProviderRequest,
        compiled: CompiledProviderRequest,
        grant_digest: str,
        policy_digest: str,
        now: datetime,
    ) -> EgressReceipt:
        destination_digest = sha256_digest(
            {
                "plane": compiled.plane,
                "endpoint_id": compiled.endpoint_id,
                "origin": compiled.origin,
            }
        )
        try:
            result = self._transport.dispatch(compiled)
        except Exception:
            return _receipt(
                plane=EgressPlane.MODEL_PROVIDER,
                request_id=request.request_id,
                request_digest=sha256_digest(request),
                authority_digest=grant_digest,
                scope_epoch=self._scope_epoch,
                policy_digest=policy_digest,
                destination_digest=destination_digest,
                outcome=EgressOutcome.UNKNOWN_OUTCOME,
                denial_code=None,
                result=None,
                evaluated_at=now,
            )
        if result.plane is not EgressPlane.MODEL_PROVIDER:
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        elif (
            result.bytes_sent > compiled.maximum_request_bytes
            or result.bytes_received > compiled.maximum_response_bytes
        ):
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        else:
            outcome = _transport_outcome(result)
        return _receipt(
            plane=EgressPlane.MODEL_PROVIDER,
            request_id=request.request_id,
            request_digest=sha256_digest(request),
            authority_digest=grant_digest,
            scope_epoch=self._scope_epoch,
            policy_digest=policy_digest,
            destination_digest=destination_digest,
            outcome=outcome,
            denial_code=None,
            result=result,
            evaluated_at=now,
        )


class KnowledgeFetcher:
    """Compile allowlisted public-knowledge fetches without arbitrary URLs."""

    def __init__(
        self,
        *,
        sources: Iterable[KnowledgeSource],
        transport: KnowledgeTransport,
        scope_epoch: int,
        clock: Clock = _system_clock,
    ) -> None:
        if transport.plane is not EgressPlane.KNOWLEDGE:
            raise ValueError("knowledge fetcher requires a knowledge transport")
        self._sources = _registry(sources, "source_id")
        self._transport = transport
        if type(scope_epoch) is not int or scope_epoch < 1:
            raise ValueError("knowledge fetcher scope epoch must be a positive integer")
        self._scope_epoch = scope_epoch
        self._clock = clock

    def dispatch(self, request: KnowledgeFetchIntent, grant: AuthorityGrant) -> EgressReceipt:
        now = _trusted_now(self._clock)
        request_digest = sha256_digest(request)
        grant_digest = sha256_digest(grant)
        source = self._sources.get(request.source_id)
        policy_digest = sha256_digest(
            {
                "schema_version": SCHEMA_VERSION,
                "plane": EgressPlane.KNOWLEDGE,
                "source": source,
                "data_policy_id": grant.provider_policy.data_policy_id,
            }
        )
        denial = self._knowledge_denial(request, grant, grant_digest, source, now)
        if denial is not None:
            return _receipt(
                plane=EgressPlane.KNOWLEDGE,
                request_id=request.request_id,
                request_digest=request_digest,
                authority_digest=grant_digest,
                scope_epoch=self._scope_epoch,
                policy_digest=policy_digest,
                destination_digest=None,
                outcome=EgressOutcome.DENIED,
                denial_code=denial,
                result=None,
                evaluated_at=now,
            )
        assert isinstance(source, KnowledgeSource)
        compiled = CompiledKnowledgeRequest(
            schema_version=SCHEMA_VERSION,
            request_id=request.request_id,
            source_id=source.source_id,
            origin=source.origin,
            method=request.method,
            path=request.path,
            data_policy_id=request.data_policy_id,
            maximum_response_bytes=min(
                source.maximum_response_bytes, grant.budget.max_response_bytes
            ),
        )
        destination_digest = sha256_digest(
            {
                "plane": compiled.plane,
                "source_id": compiled.source_id,
                "origin": compiled.origin,
                "path": compiled.path,
            }
        )
        try:
            result = self._transport.dispatch(compiled)
        except Exception:
            return _receipt(
                plane=EgressPlane.KNOWLEDGE,
                request_id=request.request_id,
                request_digest=request_digest,
                authority_digest=grant_digest,
                scope_epoch=self._scope_epoch,
                policy_digest=policy_digest,
                destination_digest=destination_digest,
                outcome=EgressOutcome.UNKNOWN_OUTCOME,
                denial_code=None,
                result=None,
                evaluated_at=now,
            )
        if result.plane is not EgressPlane.KNOWLEDGE:
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        elif result.bytes_received > compiled.maximum_response_bytes:
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        else:
            outcome = _transport_outcome(result)
        return _receipt(
            plane=EgressPlane.KNOWLEDGE,
            request_id=request.request_id,
            request_digest=request_digest,
            authority_digest=grant_digest,
            scope_epoch=self._scope_epoch,
            policy_digest=policy_digest,
            destination_digest=destination_digest,
            outcome=outcome,
            denial_code=None,
            result=result,
            evaluated_at=now,
        )

    def _knowledge_denial(
        self,
        request: KnowledgeFetchIntent,
        grant: AuthorityGrant,
        grant_digest: str,
        source: ProtocolModel | None,
        now: datetime,
    ) -> DenialCode | None:
        if request.authority_digest != grant_digest:
            return DenialCode.AUTHORITY_BINDING_MISMATCH
        if request.scope_epoch != self._scope_epoch:
            return DenialCode.SCOPE_EPOCH_MISMATCH
        if request.requested_at > now:
            return DenialCode.REQUEST_TIME_INVALID
        if not _authority_is_current(grant, now):
            return DenialCode.AUTHORITY_NOT_CURRENT
        if source is None or not isinstance(source, KnowledgeSource):
            return DenialCode.SOURCE_DENIED
        if request.method not in source.allowed_methods:
            return DenialCode.KNOWLEDGE_METHOD_DENIED
        if not any(
            _path_is_below(request.path, prefix) for prefix in source.allowed_path_prefixes
        ):
            return DenialCode.KNOWLEDGE_PATH_DENIED
        if (
            request.data_policy_id != grant.provider_policy.data_policy_id
            or request.data_policy_id not in source.allowed_data_policy_ids
        ):
            return DenialCode.DATA_POLICY_DENIED
        if _destination_overlaps_targets(source.origin, grant):
            return DenialCode.DESTINATION_OVERLAPS_TARGET
        if self._transport.plane is not EgressPlane.KNOWLEDGE:
            return DenialCode.TRANSPORT_PLANE_MISMATCH
        return None


__all__ = [
    "CompiledKnowledgeRequest",
    "CompiledProviderRequest",
    "DenialCode",
    "EgressOutcome",
    "EgressPlane",
    "EgressReceipt",
    "EgressTransportResult",
    "KnowledgeFetchIntent",
    "KnowledgeFetcher",
    "KnowledgeSource",
    "KnowledgeTransport",
    "ProviderEndpoint",
    "ProviderProxy",
    "ProviderRequest",
    "ProviderTool",
    "ProviderToolKind",
    "ProviderTransport",
    "TransportOutcome",
]
