"""Fail-closed control plane for non-target egress.

The target Gateway, model-provider proxy, and knowledge fetcher are separate
egress planes.  This module owns only the deterministic policy boundary for
the latter two planes.  Concrete transports are injected and receive an
immutable, policy-compiled request; callers cannot supply a destination URL.
Signed authority and epoch state is reverified for every dispatch, while an
externally anchored authenticated SQLite hold prevents implicit replay.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import re
import sqlite3
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Annotated, Literal, Protocol
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from pydantic import Field, model_validator

from faultloom_protocol import (
    AuthorityGrant,
    AuthoritySigner,
    AuthorityRevokedError,
    Ed25519PublicKeyRecord,
    ProtocolModel,
    SCHEMA_VERSION,
    ScopeEpoch,
    SecretRef,
    SignatureExpiredError,
    SignatureNotYetValidError,
    SignatureVerificationError,
    SignedAuthorityGrant,
    SignedScopeEpoch,
    canonical_json_bytes,
    load_public_key,
    sha256_digest,
    verify_authority_grant,
    verify_scope_epoch,
)
from faultloom.egress_state import (
    EgressStateCheckpoint,
    EgressStateIntegrityError,
    SqliteEgressStateStore,
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
    AUTHORITY_VERIFICATION_FAILED = "authority_verification_failed"
    DATA_POLICY_DENIED = "data_policy_denied"
    DESTINATION_OVERLAPS_TARGET = "destination_overlaps_target"
    DESTINATION_RESOLUTION_DENIED = "destination_resolution_denied"
    DESTINATION_SPECIAL_USE = "destination_special_use"
    ENDPOINT_DENIED = "endpoint_denied"
    KNOWLEDGE_METHOD_DENIED = "knowledge_method_denied"
    KNOWLEDGE_PATH_DENIED = "knowledge_path_denied"
    MODEL_SNAPSHOT_DENIED = "model_snapshot_denied"
    PROVIDER_DENIED = "provider_denied"
    PROVIDER_TOOL_DENIED = "provider_tool_denied"
    PROVIDER_TOOL_LIVE_DENIED = "provider_tool_live_denied"
    REQUEST_BUDGET_EXCEEDED = "request_budget_exceeded"
    REQUEST_REPLAY_DENIED = "request_replay_denied"
    REQUEST_TIME_INVALID = "request_time_invalid"
    SECRET_REFERENCE_DENIED = "secret_reference_denied"
    SCOPE_EPOCH_MISMATCH = "scope_epoch_mismatch"
    SOURCE_DENIED = "source_denied"
    STATE_STORE_UNAVAILABLE = "state_store_unavailable"
    TRANSPORT_PLANE_MISMATCH = "transport_plane_mismatch"


class ReconciliationDisposition(str, Enum):
    """Explicit operator/control-plane resolution of an uncertain dispatch."""

    RETRY_AUTHORIZED = "retry_authorized"
    EFFECT_CONFIRMED = "effect_confirmed"


class ReconciliationAuthorization(ProtocolModel):
    """Exact one-use authority to resolve one uncertain semantic action."""

    capability_id: Identifier
    sequence: PositiveInt
    plane: Literal[EgressPlane.MODEL_PROVIDER, EgressPlane.KNOWLEDGE]
    action_digest: Sha256Digest
    request_digest: Sha256Digest
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    disposition: ReconciliationDisposition
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def _valid_window(self) -> "ReconciliationAuthorization":
        if self.expires_at <= self.issued_at:
            raise ValueError("reconciliation authorization expiry must follow issuance")
        return self


class SignedReconciliationAuthorization(ProtocolModel):
    payload: ReconciliationAuthorization
    key_id: NonEmptyStr
    payload_digest: Sha256Digest
    signature: NonEmptyStr


def _reconciliation_signing_bytes(
    payload: ReconciliationAuthorization, *, key_id: str, payload_digest: str
) -> bytes:
    return canonical_json_bytes(
        {
            "domain": "faultloom-egress-reconciliation-v1",
            "key_id": key_id,
            "payload": payload,
            "payload_digest": payload_digest,
            "schema_version": SCHEMA_VERSION,
        }
    )


def sign_reconciliation_authorization(
    payload: ReconciliationAuthorization, signer: AuthoritySigner
) -> SignedReconciliationAuthorization:
    """Sign an operator/control-plane reconciliation decision."""

    candidate = ReconciliationAuthorization.model_validate(
        payload.model_dump(mode="python")
    )
    payload_digest = sha256_digest(candidate)
    signature = signer.sign(
        _reconciliation_signing_bytes(
            candidate, key_id=signer.key_id, payload_digest=payload_digest
        )
    )
    return SignedReconciliationAuthorization(
        schema_version=SCHEMA_VERSION,
        payload=candidate,
        key_id=signer.key_id,
        payload_digest=payload_digest,
        signature=signature,
    )


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
    if "%" in host:
        raise ValueError("scoped IPv6 origins are forbidden")
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


def _canonical_hostname(host: str) -> str:
    if not host.isascii() or host != host.casefold() or host.endswith("."):
        raise ValueError("resolved hostname must be canonical lowercase ASCII")
    labels = host.split(".")
    if len(labels) < 2 or labels[-1].isdecimal() or any(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError("resolved hostname is invalid")
    return host


def _normalized_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if "%" in value:
        raise ValueError("scoped IPv6 addresses are forbidden")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _address_is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
    )


def _hostname_is_special_use(host: str) -> bool:
    normalized = host.casefold().rstrip(".")
    return (
        normalized == "localhost"
        or normalized.endswith(".localhost")
        or normalized.endswith(".local")
        or normalized.endswith(".internal")
    )


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


class DestinationResolution(ProtocolModel):
    """Resolver result pinned into the transport request for one dispatch."""

    plane: Literal[EgressPlane.MODEL_PROVIDER, EgressPlane.KNOWLEDGE]
    origin: ShortStr
    cname_chain: tuple[ShortStr, ...] = ()
    addresses: tuple[ShortStr, ...]

    @model_validator(mode="after")
    def _valid_resolution(self) -> "DestinationResolution":
        _origin_host(self.origin)
        if not self.addresses:
            raise ValueError("destination resolution requires at least one address")
        for hostname in self.cname_chain:
            _canonical_hostname(hostname)
        normalized = tuple(_normalized_address(value).compressed for value in self.addresses)
        if len(normalized) != len(set(normalized)):
            raise ValueError("resolved addresses must be unique after normalization")
        if len(self.cname_chain) != len(set(self.cname_chain)):
            raise ValueError("CNAME chain entries must be unique")
        return self


class DestinationResolver(Protocol):
    plane: EgressPlane
    resolver_id: Identifier

    def resolve(self, origin: str) -> DestinationResolution: ...


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
    resolved_addresses: tuple[ShortStr, ...]
    resolution_digest: Sha256Digest
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
    resolved_addresses: tuple[ShortStr, ...]
    resolution_digest: Sha256Digest
    maximum_request_bytes: PositiveInt
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
    execution_component_digest: Sha256Digest | None
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
        payload = self.model_dump(mode="python", exclude={"receipt_digest"})
        if not hmac.compare_digest(self.receipt_digest, sha256_digest(payload)):
            raise ValueError("egress receipt digest does not match its fields")
        return self


class ProviderTransport(Protocol):
    """Transport that must pin resolved_addresses and keep redirects disabled."""

    plane: EgressPlane
    transport_id: Identifier

    def dispatch(self, request: CompiledProviderRequest) -> EgressTransportResult: ...


class KnowledgeTransport(Protocol):
    """Transport that must pin resolved_addresses and keep redirects disabled."""

    plane: EgressPlane
    transport_id: Identifier

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


def _normalized_network(
    value: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if isinstance(network, ipaddress.IPv6Network):
        first = network.network_address.ipv4_mapped
        last = network.broadcast_address.ipv4_mapped
        if first is not None and last is not None and network.prefixlen >= 96:
            return ipaddress.ip_network(f"{first}/{network.prefixlen - 96}", strict=False)
    return network


def _hostname_overlaps_targets(host: str, grant: AuthorityGrant) -> bool:
    for target in grant.targets:
        if any(_hostname_matches_target(host, name) for name in target.hostnames):
            return True
    return False


def _address_overlaps_targets(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, grant: AuthorityGrant
) -> bool:
    normalized = _normalized_address(address.compressed)
    for target in grant.targets:
        for raw_network in target.cidrs:
            network = _normalized_network(raw_network)
            if network is None:
                return True
            if normalized.version == network.version and normalized in network:
                return True
    return False


def _destination_overlaps_targets(origin: str, grant: AuthorityGrant) -> bool:
    host = _origin_host(origin)
    if _hostname_overlaps_targets(host, grant):
        return True
    try:
        address = _normalized_address(host)
    except ValueError:
        return False
    return _address_overlaps_targets(address, grant)


def _destination_denial(
    origin: str, resolution: DestinationResolution, grant: AuthorityGrant
) -> DenialCode | None:
    if resolution.origin != origin:
        return DenialCode.DESTINATION_RESOLUTION_DENIED
    host = _origin_host(origin)
    if _hostname_is_special_use(host):
        return DenialCode.DESTINATION_SPECIAL_USE
    if _destination_overlaps_targets(origin, grant):
        return DenialCode.DESTINATION_OVERLAPS_TARGET
    try:
        literal_address = _normalized_address(host)
    except ValueError:
        literal_address = None
    resolved_addresses = {
        _normalized_address(raw_address) for raw_address in resolution.addresses
    }
    if literal_address is not None and not _address_is_public(literal_address):
        return DenialCode.DESTINATION_SPECIAL_USE
    if literal_address is not None and resolved_addresses != {literal_address}:
        return DenialCode.DESTINATION_RESOLUTION_DENIED
    for hostname in resolution.cname_chain:
        if _hostname_is_special_use(hostname):
            return DenialCode.DESTINATION_SPECIAL_USE
        if _hostname_overlaps_targets(hostname, grant):
            return DenialCode.DESTINATION_OVERLAPS_TARGET
    for address in resolved_addresses:
        if not _address_is_public(address):
            return DenialCode.DESTINATION_SPECIAL_USE
        if _address_overlaps_targets(address, grant):
            return DenialCode.DESTINATION_OVERLAPS_TARGET
    return None


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
    execution_component_digest: str | None = None,
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
        "execution_component_digest": execution_component_digest,
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


class _ReservationResult(str, Enum):
    RESERVED = "reserved"
    REPLAY = "replay"
    CONFLICT = "conflict"


class TrustedAuthorityState:
    """Pinned trust material plus a signed grant and current signed scope epoch."""

    def __init__(
        self,
        *,
        trust_domain: str,
        trusted_key: Ed25519PublicKeyRecord,
        trusted_reconciliation_key: Ed25519PublicKeyRecord,
        authority: SignedAuthorityGrant,
        scope_epoch: SignedScopeEpoch,
        state_store: SqliteEgressStateStore,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", trust_domain):
            raise ValueError("trust domain must be an identifier")
        self._trust_domain = trust_domain
        self._trusted_key = Ed25519PublicKeyRecord.model_validate(
            trusted_key.model_dump(mode="python")
        )
        load_public_key(self._trusted_key)
        self._trusted_reconciliation_key = Ed25519PublicKeyRecord.model_validate(
            trusted_reconciliation_key.model_dump(mode="python")
        )
        load_public_key(self._trusted_reconciliation_key)
        if self._trusted_reconciliation_key.key_id == self._trusted_key.key_id:
            raise ValueError("reconciliation requires a separate trusted signing key")
        self._authority = SignedAuthorityGrant.model_validate(
            authority.model_dump(mode="python")
        )
        self._scope_epoch = SignedScopeEpoch.model_validate(
            scope_epoch.model_dump(mode="python")
        )
        if not isinstance(state_store, SqliteEgressStateStore):
            raise TypeError("trusted authority requires a durable SQLite egress state store")
        self._state_store = state_store
        self._lock = RLock()

    @property
    def authority_digest(self) -> str:
        return sha256_digest(self._authority)

    @property
    def scope_epoch_number(self) -> int:
        return self._scope_epoch.payload.epoch

    @property
    def state_store(self) -> SqliteEgressStateStore:
        return self._state_store

    @property
    def trust_domain(self) -> str:
        return self._trust_domain

    @property
    def reconciliation_key_id(self) -> str:
        return self._trusted_reconciliation_key.key_id

    @property
    def reconciliation_key_digest(self) -> str:
        return sha256_digest(self._trusted_reconciliation_key)

    def verify(self, now: datetime) -> tuple[AuthorityGrant, ScopeEpoch]:
        with self._lock:
            grant = verify_authority_grant(
                self._authority,
                self._trusted_key,
                now=now,
                minimum_version=1,
                expected_grant_id=self._authority.payload.grant_id,
            )
            try:
                epoch = verify_scope_epoch(
                    self._scope_epoch,
                    self._trusted_key,
                    now=now,
                    minimum_epoch=1,
                    expected_grant_id=grant.grant_id,
                )
            except AuthorityRevokedError:
                self._observe(grant, self._scope_epoch.payload, now, revoked=True)
                raise
            self._observe(grant, epoch, now, revoked=False)
            return grant, epoch

    def install_scope_epoch(self, scope_epoch: SignedScopeEpoch, *, now: datetime) -> None:
        candidate = SignedScopeEpoch.model_validate(scope_epoch.model_dump(mode="python"))
        with self._lock:
            previous = self._scope_epoch
            if candidate.payload.epoch <= previous.payload.epoch:
                raise ValueError("scope epoch update must advance monotonically")
            self._scope_epoch = candidate
            try:
                self.verify(now)
            except AuthorityRevokedError:
                raise
            except (SignatureVerificationError, ValueError, sqlite3.Error, OSError, RuntimeError):
                self._scope_epoch = previous
                raise

    def _observe(
        self, grant: AuthorityGrant, epoch: ScopeEpoch, now: datetime, *, revoked: bool
    ) -> None:
        self._state_store.observe_authority(
            trust_domain=self._trust_domain,
            trusted_key_digest=sha256_digest(self._trusted_key),
            key_id=self._trusted_key.key_id,
            grant_id=grant.grant_id,
            grant_version=grant.grant_version,
            authority_digest=sha256_digest(self._authority),
            scope_epoch=epoch.epoch,
            epoch_digest=sha256_digest(self._scope_epoch),
            revoked=revoked,
            observed_at=now,
        )

    def verify_reconciliation(
        self,
        authorization: SignedReconciliationAuthorization,
        *,
        now: datetime,
        plane: EgressPlane,
        action_digest: str,
        request_digest: str,
    ) -> ReconciliationAuthorization:
        candidate = SignedReconciliationAuthorization.model_validate(
            authorization.model_dump(mode="python")
        )
        payload = candidate.payload
        if candidate.key_id != self._trusted_reconciliation_key.key_id:
            raise SignatureVerificationError("untrusted reconciliation key")
        if candidate.payload_digest != sha256_digest(payload):
            raise SignatureVerificationError("reconciliation payload digest mismatch")
        if not payload.issued_at <= now < payload.expires_at:
            raise SignatureVerificationError("reconciliation authorization is not current")
        if (
            payload.plane is not plane
            or payload.action_digest != action_digest
            or payload.request_digest != request_digest
            or payload.authority_digest != self.authority_digest
            or payload.scope_epoch != self.scope_epoch_number
        ):
            raise SignatureVerificationError("reconciliation authorization binding mismatch")
        padding = "=" * (-len(candidate.signature) % 4)
        try:
            raw_signature = base64.b64decode(
                candidate.signature + padding, altchars=b"-_", validate=True
            )
        except (TypeError, ValueError) as exc:
            raise SignatureVerificationError("invalid reconciliation signature encoding") from exc
        if base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode("ascii") != candidate.signature:
            raise SignatureVerificationError("non-canonical reconciliation signature")
        try:
            load_public_key(self._trusted_reconciliation_key).verify(
                raw_signature,
                _reconciliation_signing_bytes(
                    payload,
                    key_id=candidate.key_id,
                    payload_digest=candidate.payload_digest,
                ),
            )
        except InvalidSignature as exc:
            raise SignatureVerificationError("reconciliation signature verification failed") from exc
        return payload


def _validated_resolution(
    resolver: DestinationResolver, origin: str, *, expected_plane: EgressPlane
) -> DestinationResolution:
    if getattr(resolver, "plane", None) is not expected_plane:
        raise ValueError("destination resolver belongs to another egress plane")
    value = resolver.resolve(origin)
    if getattr(resolver, "plane", None) is not expected_plane:
        raise ValueError("destination resolver plane changed during resolution")
    if not isinstance(value, DestinationResolution):
        raise TypeError("destination resolver must return DestinationResolution")
    resolution = DestinationResolution.model_validate(value.model_dump(mode="python"))
    if resolution.origin != origin or resolution.plane is not expected_plane:
        raise ValueError("destination resolution is bound to another origin")
    return resolution


def _compiled_addresses(resolution: DestinationResolution) -> tuple[str, ...]:
    addresses = {_normalized_address(value) for value in resolution.addresses}
    return tuple(
        address.compressed
        for address in sorted(addresses, key=lambda item: (item.version, int(item)))
    )


def _validated_transport_result(value: object) -> EgressTransportResult:
    if not isinstance(value, EgressTransportResult):
        raise TypeError("egress transport must return EgressTransportResult")
    return EgressTransportResult.model_validate(value.model_dump(mode="python"))


def _component_id(value: object, *, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value
    ) is None:
        raise ValueError(f"{field} must be a stable identifier")
    return value


def _execution_component_digest(
    plane: EgressPlane, resolver: DestinationResolver, transport: object
) -> str:
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "plane": plane,
            "resolver_id": _component_id(
                getattr(resolver, "resolver_id", None), field="resolver_id"
            ),
            "transport_id": _component_id(
                getattr(transport, "transport_id", None), field="transport_id"
            ),
        }
    )


def provider_action_digest(request: ProviderRequest) -> str:
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "plane": EgressPlane.MODEL_PROVIDER,
            "authority_digest": request.authority_digest,
            "scope_epoch": request.scope_epoch,
            "endpoint_id": request.endpoint_id,
            "provider_id": request.provider_id,
            "model_snapshot": request.model_snapshot,
            "data_policy_id": request.data_policy_id,
            "credential_ref": request.credential_ref,
            "payload_digest": request.payload_digest,
            "payload_bytes": request.payload_bytes,
            "tool_ids": request.tool_ids,
            "live": request.live,
        }
    )


def knowledge_action_digest(request: KnowledgeFetchIntent) -> str:
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "plane": EgressPlane.KNOWLEDGE,
            "authority_digest": request.authority_digest,
            "scope_epoch": request.scope_epoch,
            "source_id": request.source_id,
            "method": request.method,
            "path": request.path,
            "data_policy_id": request.data_policy_id,
        }
    )


def _correlation_digest(plane: EgressPlane, *, run_id: str, request_id: str) -> str:
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "plane": plane,
            "run_id": run_id,
            "request_id": request_id,
        }
    )


class ProviderProxy:
    """Compile model calls onto one immutable provider egress plane."""

    def __init__(
        self,
        *,
        endpoints: Iterable[ProviderEndpoint],
        transport: ProviderTransport,
        resolver: DestinationResolver,
        authority_state: TrustedAuthorityState,
        live: bool,
        clock: Clock = _system_clock,
    ) -> None:
        if transport.plane is not EgressPlane.MODEL_PROVIDER:
            raise ValueError("provider proxy requires a model-provider transport")
        if type(live) is not bool:
            raise ValueError("provider proxy live mode must be a boolean")
        if not isinstance(authority_state, TrustedAuthorityState):
            raise TypeError("provider proxy requires pinned signed authority state")
        if not callable(getattr(resolver, "resolve", None)):
            raise TypeError("provider proxy requires a destination resolver")
        if getattr(resolver, "plane", None) is not EgressPlane.MODEL_PROVIDER:
            raise ValueError("provider proxy requires a model-provider resolver")
        self._endpoints = _registry(endpoints, "endpoint_id")
        self._transport = transport
        self._resolver = resolver
        self._authority = authority_state
        self._state_store = authority_state.state_store
        self._live = live
        self._clock = clock
        self._component_digest = _execution_component_digest(
            EgressPlane.MODEL_PROVIDER, resolver, transport
        )

    def dispatch(self, request: ProviderRequest) -> EgressReceipt:
        now = _trusted_now(self._clock)
        request_digest = sha256_digest(request)
        action_digest = provider_action_digest(request)
        authority_digest = self._authority.authority_digest
        scope_epoch = self._authority.scope_epoch_number
        endpoint = self._endpoints.get(request.endpoint_id)
        unverified_policy_digest = sha256_digest(
            {
                "schema_version": SCHEMA_VERSION,
                "plane": EgressPlane.MODEL_PROVIDER,
                "authority_digest": authority_digest,
                "scope_epoch": scope_epoch,
                "endpoint": endpoint,
                "live": self._live,
            }
        )
        try:
            grant, epoch = self._authority.verify(now)
        except (AuthorityRevokedError, SignatureExpiredError, SignatureNotYetValidError):
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=scope_epoch,
                policy_digest=unverified_policy_digest,
                denial=DenialCode.AUTHORITY_NOT_CURRENT,
                now=now,
            )
        except (SignatureVerificationError, ValueError, sqlite3.Error, OSError, RuntimeError):
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=scope_epoch,
                policy_digest=unverified_policy_digest,
                denial=DenialCode.AUTHORITY_VERIFICATION_FAILED,
                now=now,
            )
        policy_digest = sha256_digest(
            {
                "schema_version": SCHEMA_VERSION,
                "plane": EgressPlane.MODEL_PROVIDER,
                "authority_digest": authority_digest,
                "scope_epoch": epoch.epoch,
                "provider_policy": grant.provider_policy,
                "endpoint": endpoint,
                "live": self._live,
            }
        )

        denial = self._provider_denial(
            request, grant, epoch, authority_digest, endpoint, now
        )
        if denial is not None:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=denial,
                now=now,
        )
        assert isinstance(endpoint, ProviderEndpoint)
        prior_state = self._prior_dispatch_state(action_digest)
        if prior_state is not None:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=prior_state,
                now=now,
            )
        try:
            resolution = _validated_resolution(
                self._resolver,
                endpoint.origin,
                expected_plane=EgressPlane.MODEL_PROVIDER,
            )
            destination_denial = _destination_denial(endpoint.origin, resolution, grant)
        except (TypeError, ValueError, OSError):
            resolution = None
            destination_denial = DenialCode.DESTINATION_RESOLUTION_DENIED
        if destination_denial is not None or resolution is None:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=destination_denial or DenialCode.DESTINATION_RESOLUTION_DENIED,
                now=now,
            )
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
            resolved_addresses=_compiled_addresses(resolution),
            resolution_digest=sha256_digest(resolution),
            maximum_request_bytes=grant.budget.max_request_bytes,
            maximum_response_bytes=grant.budget.max_response_bytes,
        )
        try:
            reservation = self._state_store.reserve_dispatch(
                plane=EgressPlane.MODEL_PROVIDER.value,
                action_digest=action_digest,
                correlation_digest=_correlation_digest(
                    EgressPlane.MODEL_PROVIDER,
                    run_id=request.run_id,
                    request_id=request.request_id,
                ),
                request_digest=request_digest,
                reserved_at=now,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=DenialCode.STATE_STORE_UNAVAILABLE,
                now=now,
            )
        if reservation != _ReservationResult.RESERVED.value:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=DenialCode.REQUEST_REPLAY_DENIED,
                now=now,
            )
        return self._dispatch_compiled(
            request=request,
            compiled=compiled,
            action_digest=action_digest,
            request_digest=request_digest,
            authority_digest=authority_digest,
            scope_epoch=epoch.epoch,
            policy_digest=policy_digest,
            now=now,
        )

    def reconcile(
        self,
        request: ProviderRequest,
        authorization: SignedReconciliationAuthorization,
    ) -> bool:
        if not isinstance(authorization, SignedReconciliationAuthorization):
            return False
        now = _trusted_now(self._clock)
        request_digest = sha256_digest(request)
        action_digest = provider_action_digest(request)
        try:
            payload = self._authority.verify_reconciliation(
                authorization,
                now=now,
                plane=EgressPlane.MODEL_PROVIDER,
                action_digest=action_digest,
                request_digest=request_digest,
            )
            return self._state_store.reconcile(
                trust_domain=self._authority.trust_domain,
                trusted_key_digest=self._authority.reconciliation_key_digest,
                key_id=self._authority.reconciliation_key_id,
                capability_id=payload.capability_id,
                sequence=payload.sequence,
                plane=EgressPlane.MODEL_PROVIDER.value,
                action_digest=action_digest,
                request_digest=request_digest,
                disposition=payload.disposition.value,
                reconciled_at=now,
            )
        except (SignatureVerificationError, ValueError, sqlite3.Error, OSError, RuntimeError):
            return False

    def _denied(
        self,
        *,
        request: ProviderRequest,
        request_digest: str,
        authority_digest: str,
        scope_epoch: int,
        policy_digest: str,
        denial: DenialCode,
        now: datetime,
    ) -> EgressReceipt:
        return _receipt(
            plane=EgressPlane.MODEL_PROVIDER,
            request_id=request.request_id,
            request_digest=request_digest,
            authority_digest=authority_digest,
            scope_epoch=scope_epoch,
            policy_digest=policy_digest,
            destination_digest=None,
            outcome=EgressOutcome.DENIED,
            denial_code=denial,
            result=None,
            evaluated_at=now,
        )

    def _prior_dispatch_state(self, action_digest: str) -> DenialCode | None:
        try:
            state = self._state_store.dispatch_state(
                plane=EgressPlane.MODEL_PROVIDER.value,
                action_digest=action_digest,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            return DenialCode.STATE_STORE_UNAVAILABLE
        if state is None or state == ReconciliationDisposition.RETRY_AUTHORIZED.value:
            return None
        return DenialCode.REQUEST_REPLAY_DENIED

    def _provider_denial(
        self,
        request: ProviderRequest,
        grant: AuthorityGrant,
        epoch: ScopeEpoch,
        authority_digest: str,
        endpoint: ProtocolModel | None,
        now: datetime,
    ) -> DenialCode | None:
        if request.authority_digest != authority_digest:
            return DenialCode.AUTHORITY_BINDING_MISMATCH
        if request.scope_epoch != epoch.epoch:
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
        if self._transport.plane is not EgressPlane.MODEL_PROVIDER:
            return DenialCode.TRANSPORT_PLANE_MISMATCH
        return None

    def _dispatch_compiled(
        self,
        *,
        request: ProviderRequest,
        compiled: CompiledProviderRequest,
        action_digest: str,
        request_digest: str,
        authority_digest: str,
        scope_epoch: int,
        policy_digest: str,
        now: datetime,
    ) -> EgressReceipt:
        destination_digest = sha256_digest(
            {
                "plane": compiled.plane,
                "endpoint_id": compiled.endpoint_id,
                "origin": compiled.origin,
                "resolution_digest": compiled.resolution_digest,
            }
        )
        try:
            current_component_digest = _execution_component_digest(
                EgressPlane.MODEL_PROVIDER, self._resolver, self._transport
            )
        except ValueError:
            current_component_digest = None
        if current_component_digest != self._component_digest:
            self._state_store.finish_dispatch(
                plane=EgressPlane.MODEL_PROVIDER.value,
                action_digest=action_digest,
                request_digest=request_digest,
                outcome=EgressOutcome.FAILED.value,
                finished_at=now,
            )
            return _receipt(
                plane=EgressPlane.MODEL_PROVIDER,
                request_id=request.request_id,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=scope_epoch,
                policy_digest=policy_digest,
                destination_digest=destination_digest,
                execution_component_digest=self._component_digest,
                outcome=EgressOutcome.FAILED,
                denial_code=None,
                result=None,
                evaluated_at=now,
            )
        try:
            result = _validated_transport_result(self._transport.dispatch(compiled))
        except Exception:
            self._finish_or_hold_unknown(
                action_digest, request_digest, now, plane=EgressPlane.MODEL_PROVIDER
            )
            return _receipt(
                plane=EgressPlane.MODEL_PROVIDER,
                request_id=request.request_id,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=scope_epoch,
                policy_digest=policy_digest,
                destination_digest=destination_digest,
                execution_component_digest=self._component_digest,
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
        try:
            self._state_store.finish_dispatch(
                plane=EgressPlane.MODEL_PROVIDER.value,
                action_digest=action_digest,
                request_digest=request_digest,
                outcome=outcome.value,
                finished_at=now,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        return _receipt(
            plane=EgressPlane.MODEL_PROVIDER,
            request_id=request.request_id,
            request_digest=request_digest,
            authority_digest=authority_digest,
            scope_epoch=scope_epoch,
            policy_digest=policy_digest,
            destination_digest=destination_digest,
            execution_component_digest=self._component_digest,
            outcome=outcome,
            denial_code=None,
            result=result,
            evaluated_at=now,
        )

    def _finish_or_hold_unknown(
        self,
        action_digest: str,
        request_digest: str,
        now: datetime,
        *,
        plane: EgressPlane,
    ) -> None:
        try:
            self._state_store.finish_dispatch(
                plane=plane.value,
                action_digest=action_digest,
                request_digest=request_digest,
                outcome=EgressOutcome.UNKNOWN_OUTCOME.value,
                finished_at=now,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            # The durable row remains pending and therefore still blocks replay.
            return


class KnowledgeFetcher:
    """Compile allowlisted public-knowledge fetches without arbitrary URLs."""

    def __init__(
        self,
        *,
        sources: Iterable[KnowledgeSource],
        transport: KnowledgeTransport,
        resolver: DestinationResolver,
        authority_state: TrustedAuthorityState,
        clock: Clock = _system_clock,
    ) -> None:
        if transport.plane is not EgressPlane.KNOWLEDGE:
            raise ValueError("knowledge fetcher requires a knowledge transport")
        if not isinstance(authority_state, TrustedAuthorityState):
            raise TypeError("knowledge fetcher requires pinned signed authority state")
        if not callable(getattr(resolver, "resolve", None)):
            raise TypeError("knowledge fetcher requires a destination resolver")
        if getattr(resolver, "plane", None) is not EgressPlane.KNOWLEDGE:
            raise ValueError("knowledge fetcher requires a knowledge resolver")
        self._sources = _registry(sources, "source_id")
        self._transport = transport
        self._resolver = resolver
        self._authority = authority_state
        self._state_store = authority_state.state_store
        self._clock = clock
        self._component_digest = _execution_component_digest(
            EgressPlane.KNOWLEDGE, resolver, transport
        )

    def dispatch(self, request: KnowledgeFetchIntent) -> EgressReceipt:
        now = _trusted_now(self._clock)
        request_digest = sha256_digest(request)
        action_digest = knowledge_action_digest(request)
        authority_digest = self._authority.authority_digest
        scope_epoch = self._authority.scope_epoch_number
        source = self._sources.get(request.source_id)
        unverified_policy_digest = sha256_digest(
            {
                "schema_version": SCHEMA_VERSION,
                "plane": EgressPlane.KNOWLEDGE,
                "authority_digest": authority_digest,
                "scope_epoch": scope_epoch,
                "source": source,
            }
        )
        try:
            grant, epoch = self._authority.verify(now)
        except (AuthorityRevokedError, SignatureExpiredError, SignatureNotYetValidError):
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=scope_epoch,
                policy_digest=unverified_policy_digest,
                denial=DenialCode.AUTHORITY_NOT_CURRENT,
                now=now,
            )
        except (SignatureVerificationError, ValueError, sqlite3.Error, OSError, RuntimeError):
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=scope_epoch,
                policy_digest=unverified_policy_digest,
                denial=DenialCode.AUTHORITY_VERIFICATION_FAILED,
                now=now,
            )
        policy_digest = sha256_digest(
            {
                "schema_version": SCHEMA_VERSION,
                "plane": EgressPlane.KNOWLEDGE,
                "authority_digest": authority_digest,
                "scope_epoch": epoch.epoch,
                "source": source,
                "data_policy_id": grant.provider_policy.data_policy_id,
            }
        )
        denial = self._knowledge_denial(
            request, grant, epoch, authority_digest, source, now
        )
        if denial is not None:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=denial,
                now=now,
            )
        assert isinstance(source, KnowledgeSource)
        prior_state = self._prior_dispatch_state(action_digest)
        if prior_state is not None:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=prior_state,
                now=now,
            )
        try:
            resolution = _validated_resolution(
                self._resolver,
                source.origin,
                expected_plane=EgressPlane.KNOWLEDGE,
            )
            destination_denial = _destination_denial(source.origin, resolution, grant)
        except (TypeError, ValueError, OSError):
            resolution = None
            destination_denial = DenialCode.DESTINATION_RESOLUTION_DENIED
        if destination_denial is not None or resolution is None:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=destination_denial or DenialCode.DESTINATION_RESOLUTION_DENIED,
                now=now,
            )
        compiled = CompiledKnowledgeRequest(
            schema_version=SCHEMA_VERSION,
            request_id=request.request_id,
            source_id=source.source_id,
            origin=source.origin,
            method=request.method,
            path=request.path,
            data_policy_id=request.data_policy_id,
            resolved_addresses=_compiled_addresses(resolution),
            resolution_digest=sha256_digest(resolution),
            maximum_request_bytes=grant.budget.max_request_bytes,
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
                "resolution_digest": compiled.resolution_digest,
            }
        )
        try:
            reservation = self._state_store.reserve_dispatch(
                plane=EgressPlane.KNOWLEDGE.value,
                action_digest=action_digest,
                correlation_digest=_correlation_digest(
                    EgressPlane.KNOWLEDGE,
                    run_id=request.run_id,
                    request_id=request.request_id,
                ),
                request_digest=request_digest,
                reserved_at=now,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=DenialCode.STATE_STORE_UNAVAILABLE,
                now=now,
            )
        if reservation != _ReservationResult.RESERVED.value:
            return self._denied(
                request=request,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                denial=DenialCode.REQUEST_REPLAY_DENIED,
                now=now,
            )
        try:
            current_component_digest = _execution_component_digest(
                EgressPlane.KNOWLEDGE, self._resolver, self._transport
            )
        except ValueError:
            current_component_digest = None
        if current_component_digest != self._component_digest:
            self._state_store.finish_dispatch(
                plane=EgressPlane.KNOWLEDGE.value,
                action_digest=action_digest,
                request_digest=request_digest,
                outcome=EgressOutcome.FAILED.value,
                finished_at=now,
            )
            return _receipt(
                plane=EgressPlane.KNOWLEDGE,
                request_id=request.request_id,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                destination_digest=destination_digest,
                execution_component_digest=self._component_digest,
                outcome=EgressOutcome.FAILED,
                denial_code=None,
                result=None,
                evaluated_at=now,
            )
        try:
            result = _validated_transport_result(self._transport.dispatch(compiled))
        except Exception:
            self._finish_or_hold_unknown(action_digest, request_digest, now)
            return _receipt(
                plane=EgressPlane.KNOWLEDGE,
                request_id=request.request_id,
                request_digest=request_digest,
                authority_digest=authority_digest,
                scope_epoch=epoch.epoch,
                policy_digest=policy_digest,
                destination_digest=destination_digest,
                execution_component_digest=self._component_digest,
                outcome=EgressOutcome.UNKNOWN_OUTCOME,
                denial_code=None,
                result=None,
                evaluated_at=now,
            )
        if result.plane is not EgressPlane.KNOWLEDGE:
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        elif (
            result.bytes_sent > compiled.maximum_request_bytes
            or result.bytes_received > compiled.maximum_response_bytes
        ):
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        else:
            outcome = _transport_outcome(result)
        try:
            self._state_store.finish_dispatch(
                plane=EgressPlane.KNOWLEDGE.value,
                action_digest=action_digest,
                request_digest=request_digest,
                outcome=outcome.value,
                finished_at=now,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            outcome = EgressOutcome.UNKNOWN_OUTCOME
        return _receipt(
            plane=EgressPlane.KNOWLEDGE,
            request_id=request.request_id,
            request_digest=request_digest,
            authority_digest=authority_digest,
            scope_epoch=epoch.epoch,
            policy_digest=policy_digest,
            destination_digest=destination_digest,
            execution_component_digest=self._component_digest,
            outcome=outcome,
            denial_code=None,
            result=result,
            evaluated_at=now,
        )

    def reconcile(
        self,
        request: KnowledgeFetchIntent,
        authorization: SignedReconciliationAuthorization,
    ) -> bool:
        if not isinstance(authorization, SignedReconciliationAuthorization):
            return False
        now = _trusted_now(self._clock)
        request_digest = sha256_digest(request)
        action_digest = knowledge_action_digest(request)
        try:
            payload = self._authority.verify_reconciliation(
                authorization,
                now=now,
                plane=EgressPlane.KNOWLEDGE,
                action_digest=action_digest,
                request_digest=request_digest,
            )
            return self._state_store.reconcile(
                trust_domain=self._authority.trust_domain,
                trusted_key_digest=self._authority.reconciliation_key_digest,
                key_id=self._authority.reconciliation_key_id,
                capability_id=payload.capability_id,
                sequence=payload.sequence,
                plane=EgressPlane.KNOWLEDGE.value,
                action_digest=action_digest,
                request_digest=request_digest,
                disposition=payload.disposition.value,
                reconciled_at=now,
            )
        except (SignatureVerificationError, ValueError, sqlite3.Error, OSError, RuntimeError):
            return False

    def _denied(
        self,
        *,
        request: KnowledgeFetchIntent,
        request_digest: str,
        authority_digest: str,
        scope_epoch: int,
        policy_digest: str,
        denial: DenialCode,
        now: datetime,
    ) -> EgressReceipt:
        return _receipt(
            plane=EgressPlane.KNOWLEDGE,
            request_id=request.request_id,
            request_digest=request_digest,
            authority_digest=authority_digest,
            scope_epoch=scope_epoch,
            policy_digest=policy_digest,
            destination_digest=None,
            outcome=EgressOutcome.DENIED,
            denial_code=denial,
            result=None,
            evaluated_at=now,
        )

    def _prior_dispatch_state(self, action_digest: str) -> DenialCode | None:
        try:
            state = self._state_store.dispatch_state(
                plane=EgressPlane.KNOWLEDGE.value,
                action_digest=action_digest,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            return DenialCode.STATE_STORE_UNAVAILABLE
        if state is None or state == ReconciliationDisposition.RETRY_AUTHORIZED.value:
            return None
        return DenialCode.REQUEST_REPLAY_DENIED

    def _finish_or_hold_unknown(
        self, action_digest: str, request_digest: str, now: datetime
    ) -> None:
        try:
            self._state_store.finish_dispatch(
                plane=EgressPlane.KNOWLEDGE.value,
                action_digest=action_digest,
                request_digest=request_digest,
                outcome=EgressOutcome.UNKNOWN_OUTCOME.value,
                finished_at=now,
            )
        except (sqlite3.Error, OSError, RuntimeError):
            return

    def _knowledge_denial(
        self,
        request: KnowledgeFetchIntent,
        grant: AuthorityGrant,
        epoch: ScopeEpoch,
        authority_digest: str,
        source: ProtocolModel | None,
        now: datetime,
    ) -> DenialCode | None:
        if request.authority_digest != authority_digest:
            return DenialCode.AUTHORITY_BINDING_MISMATCH
        if request.scope_epoch != epoch.epoch:
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
        if self._transport.plane is not EgressPlane.KNOWLEDGE:
            return DenialCode.TRANSPORT_PLANE_MISMATCH
        return None


__all__ = [
    "CompiledKnowledgeRequest",
    "CompiledProviderRequest",
    "DenialCode",
    "DestinationResolution",
    "DestinationResolver",
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
    "ReconciliationDisposition",
    "SqliteEgressStateStore",
    "TransportOutcome",
    "TrustedAuthorityState",
]
