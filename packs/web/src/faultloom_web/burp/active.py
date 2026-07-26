"""Prepare an explicitly selected Burp request for the Gateway-only live path.

This module never opens a target connection and never sends a request.  It only
checks that a user-selected Burp item still exactly describes an already
approved semantic Gateway command.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Literal, Protocol, final

from pydantic import Field, model_validator

from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    SignedAuthorityGrant,
    SignedScopeEpoch,
    verify_authority_grant,
    verify_scope_epoch,
)
from faultloom_protocol.base import Sha256Digest
from faultloom_protocol.models import AuthorityGrant, DispatchOutcome, EgressPlane
from faultloom_protocol.signing import SignatureVerificationError

from .models import BurpHeader, BurpModel, BurpScope
from .policy import BurpPolicyError

if TYPE_CHECKING:
    from faultloom.execution import GatewayDispatchCommand, GatewayResult


class GatewayDispatcher(Protocol):
    """The existing Gateway dispatch surface; this pack owns no transport."""

    def dispatch(self, command: GatewayDispatchCommand) -> GatewayResult: ...


class BurpSelectedBudget(BurpModel):
    request_bytes: int = Field(ge=1)
    response_bytes: int = Field(ge=0)
    duration_seconds: int = Field(ge=1)


class BurpSelectedIdentity(BurpModel):
    context_id: str = Field(min_length=1, max_length=256)
    identity_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)


class BurpSelectedRequest(BurpModel):
    """A metadata-only record of one item the operator selected in Burp."""

    selection_source: Literal["burp.user_selected"]
    selection_id: str = Field(min_length=1, max_length=256)
    scheme: Literal["http", "https"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    method: str = Field(min_length=1, max_length=32)
    path: str = Field(min_length=1, max_length=4096)
    body_digest: Sha256Digest | None = None
    body_length: int = Field(default=0, ge=0)
    headers: tuple[BurpHeader, ...] = ()
    identity: BurpSelectedIdentity
    budget: BurpSelectedBudget

    @model_validator(mode="after")
    def _canonical_metadata(self) -> "BurpSelectedRequest":
        if self.host != self.host.casefold():
            raise ValueError("selected Burp host must be lower-case")
        if self.method != self.method.upper():
            raise ValueError("selected Burp method must be canonical upper-case")
        if not self.path.startswith("/") or any(char in self.path for char in "?#\r\n\x00"):
            raise ValueError("selected Burp path must be an absolute semantic path")
        if self.body_digest is None and self.body_length != 0:
            raise ValueError("selected Burp body length requires a body digest")
        return self


class BurpGatewayPreview(BurpModel):
    selection_id: str
    scheme: Literal["http", "https"]
    host: str
    port: int
    method: str
    path: str
    body_digest: Sha256Digest | None
    body_length: int
    headers: tuple[BurpHeader, ...]
    context_id: str
    identity_id: str
    tenant_id: str
    action_id: str
    lease_id: str
    dispatch_performed: Literal[False] = False
    gateway_only: Literal[True] = True


class BurpGatewayCandidateReceipt(BurpModel):
    """A completed Gateway action remains a candidate until independent verification."""

    selection_id: str
    gateway_receipt_id: str
    target_id: str
    action_id: str
    lease_id: str
    candidate_only: Literal[True] = True
    gateway_dispatched: Literal[True] = True
    verification_evidence: Literal[False] = False
    verification_status: Literal["unverified"] = "unverified"


@dataclass(frozen=True, slots=True)
class PreparedBurpGatewayDispatch:
    """The exact approved command, ready for the existing Gateway live path."""

    command: GatewayDispatchCommand
    preview: BurpGatewayPreview
    command_digest: Sha256Digest

    def gateway_command(self) -> GatewayDispatchCommand:
        return self.command


@dataclass(frozen=True, slots=True)
class ActiveBurpDispatchAuthority:
    """Separately signed authority and scope material for one active handoff."""

    authority: SignedAuthorityGrant
    authority_public_key: Ed25519PublicKeyRecord
    scope_epoch: SignedScopeEpoch
    scope_public_key: Ed25519PublicKeyRecord
    verified_at: datetime


@final
class ActiveBurpRequestPreparer:
    """Fail-closed adapter from a selected Burp item to a pre-approved command."""

    def __init__(self, scope: BurpScope) -> None:
        self._scope = scope

    def prepare(
        self,
        selection: BurpSelectedRequest,
        command: GatewayDispatchCommand,
    ) -> PreparedBurpGatewayDispatch:
        from faultloom.execution import GatewayDispatchCommand

        if type(command) is not GatewayDispatchCommand:
            raise BurpPolicyError("command_invalid", "Gateway command must have the exact type")
        endpoint = command.request.endpoint
        if not self._scope.contains(selection.host, selection.path):
            raise BurpPolicyError("out_of_scope", "selected Burp item is outside the approved scope")
        if (
            selection.scheme != endpoint.scheme.value
            or selection.host != endpoint.hostname
            or selection.port != endpoint.port
        ):
            raise BurpPolicyError(
                "endpoint_mismatch",
                "selected Burp endpoint differs from the approved Gateway command",
            )
        if selection.method != command.request.method:
            raise BurpPolicyError(
                "method_mismatch",
                "selected Burp method differs from the approved Gateway command",
            )
        if selection.path != endpoint.path:
            raise BurpPolicyError(
                "path_mismatch",
                "selected Burp path differs from the approved Gateway command",
            )
        self._require_body_match(selection, command)
        self._require_budget_match(selection, command)
        self._require_identity_match(selection, command)
        return PreparedBurpGatewayDispatch(
            command=command,
            preview=BurpGatewayPreview(
                selection_id=selection.selection_id,
                scheme=selection.scheme,
                host=selection.host,
                port=selection.port,
                method=selection.method,
                path=selection.path,
                body_digest=selection.body_digest,
                body_length=selection.body_length,
                headers=tuple(_redact_header(header) for header in selection.headers),
                context_id=selection.identity.context_id,
                identity_id=selection.identity.identity_id,
                tenant_id=selection.identity.tenant_id,
                action_id=command.intent.action_id,
                lease_id=command.lease.lease_id,
            ),
            command_digest=_command_digest(command),
        )

    @staticmethod
    def _require_body_match(
        selection: BurpSelectedRequest,
        command: GatewayDispatchCommand,
    ) -> None:
        body_ref = command.request.body_ref
        if body_ref is None:
            matches = selection.body_digest is None and selection.body_length == 0
        else:
            matches = (
                selection.body_digest == body_ref.cas_digest
                and selection.body_length == body_ref.byte_length
            )
        if not matches:
            raise BurpPolicyError(
                "body_mismatch",
                "selected Burp body differs from the approved Gateway command",
            )

    @staticmethod
    def _require_budget_match(
        selection: BurpSelectedRequest,
        command: GatewayDispatchCommand,
    ) -> None:
        reservation = command.lease.reservation
        if (
            selection.budget.request_bytes != reservation.request_bytes
            or selection.budget.response_bytes != reservation.response_bytes
            or selection.budget.duration_seconds != reservation.duration_seconds
        ):
            raise BurpPolicyError(
                "budget_mismatch",
                "selected Burp budget differs from the approved Gateway command",
            )

    @staticmethod
    def _require_identity_match(
        selection: BurpSelectedRequest,
        command: GatewayDispatchCommand,
    ) -> None:
        identity = command.identity
        if (
            selection.identity.context_id != identity.context_id
            or selection.identity.identity_id != identity.identity_id
            or selection.identity.tenant_id != identity.tenant_id
        ):
            raise BurpPolicyError(
                "identity_mismatch",
                "selected Burp identity differs from the approved Gateway command",
            )


@final
class ActiveBurpGatewayHandoff:
    """Dispatch one unchanged prepared item through the preapproved Gateway only."""

    def __init__(self, authority: ActiveBurpDispatchAuthority) -> None:
        if type(authority) is not ActiveBurpDispatchAuthority:
            raise BurpPolicyError("authority_invalid", "active Burp authority must have the exact type")
        self._authority = authority

    def execute(
        self,
        prepared: PreparedBurpGatewayDispatch,
        gateway: GatewayDispatcher,
    ) -> BurpGatewayCandidateReceipt:
        from faultloom.execution import GatewayDeniedResult, GatewayDispatchCommand, GatewayDispatchResult

        if type(prepared) is not PreparedBurpGatewayDispatch:
            raise BurpPolicyError("command_invalid", "prepared Burp handoff must have the exact type")
        command = prepared.command
        if type(command) is not GatewayDispatchCommand:
            raise BurpPolicyError("command_invalid", "Gateway command must have the exact type")
        try:
            command_digest = _command_digest(command)
        except Exception as exc:
            raise BurpPolicyError(
                "command_changed", "Gateway command is not a canonical prepared command"
            ) from exc
        if command_digest != prepared.command_digest:
            raise BurpPolicyError("command_changed", "Gateway command changed after Burp preparation")
        grant = self._verified_grant(command)
        self._require_authorized_command(command, grant)
        try:
            result = gateway.dispatch(command)
        except AttributeError as exc:
            raise BurpPolicyError("gateway_invalid", "Gateway dispatcher has no dispatch surface") from exc
        if type(result) is GatewayDeniedResult:
            raise BurpPolicyError("gateway_denied", "Gateway denied the prepared active Burp action")
        if type(result) is not GatewayDispatchResult:
            raise BurpPolicyError("gateway_result_invalid", "Gateway returned an invalid dispatch result")
        self._require_receipt_binding(command, result)
        return BurpGatewayCandidateReceipt(
            selection_id=prepared.preview.selection_id,
            gateway_receipt_id=result.receipt.receipt_id,
            target_id=command.intent.target_id,
            action_id=command.intent.action_id,
            lease_id=command.lease.lease_id,
        )

    def _verified_grant(self, command: GatewayDispatchCommand) -> AuthorityGrant:
        authority = self._authority
        if (
            type(authority.authority) is not SignedAuthorityGrant
            or type(authority.authority_public_key) is not Ed25519PublicKeyRecord
            or type(authority.scope_epoch) is not SignedScopeEpoch
            or type(authority.scope_public_key) is not Ed25519PublicKeyRecord
            or type(authority.verified_at) is not datetime
            or authority.verified_at.tzinfo is None
            or authority.verified_at.utcoffset() is None
        ):
            raise BurpPolicyError("authority_invalid", "signed active Burp authority is malformed")
        try:
            grant = verify_authority_grant(
                authority.authority,
                authority.authority_public_key,
                now=authority.verified_at,
                minimum_version=command.lease.grant_version,
                expected_grant_id=command.lease.grant_id,
            )
            epoch = verify_scope_epoch(
                authority.scope_epoch,
                authority.scope_public_key,
                now=authority.verified_at,
                minimum_epoch=command.lease.scope_epoch,
                expected_grant_id=grant.grant_id,
            )
        except (SignatureVerificationError, ValueError) as exc:
            raise BurpPolicyError(
                "authority_invalid", "signed active Burp authority or scope was rejected"
            ) from exc
        if (
            authority.authority_public_key.key_id != command.lease.authority_key_id
            or authority.scope_public_key.key_id != command.lease.authority_key_id
            or grant.grant_version != command.lease.grant_version
            or epoch.epoch != command.lease.scope_epoch
        ):
            raise BurpPolicyError("authority_mismatch", "signed authority is not bound to the lease")
        return grant

    def _require_authorized_command(
        self,
        command: GatewayDispatchCommand,
        grant: AuthorityGrant,
    ) -> None:
        now = self._authority.verified_at
        endpoint = command.request.endpoint
        if endpoint.hostname != "127.0.0.1":
            raise BurpPolicyError(
                "target_not_owned_loopback", "active Burp candidate handoff permits owned loopback only"
            )
        target = next(
            (item for item in grant.targets if item.target_id == command.intent.target_id),
            None,
        )
        if target is None:
            raise BurpPolicyError("target_not_authorized", "Gateway target is absent from signed authority")
        if (
            endpoint.hostname not in target.hostnames
            or endpoint.port not in target.ports
            or endpoint.scheme.value not in target.protocols
            or not _matches_any(endpoint.path, target.paths)
            or command.request.method not in target.methods
        ):
            raise BurpPolicyError("target_not_authorized", "Gateway endpoint is outside signed authority")
        policy = grant.action_policy
        if (
            command.intent.pack_id not in grant.pack_ids
            or command.intent.action_class not in policy.allowed_classes
            or command.intent.action_kind not in policy.allowed_families
            or command.request.method not in policy.allowed_methods
            or not _matches_any(endpoint.path, policy.allowed_path_patterns)
            or command.identity.identity_id not in grant.identities
            or command.identity.tenant_id not in grant.tenants
            or command.lease.egress_plane is not EgressPlane.TARGET_GATEWAY
        ):
            raise BurpPolicyError("authority_mismatch", "Gateway command is outside signed authority")
        if not any(window.starts_at <= now < window.ends_at for window in grant.execution_windows):
            raise BurpPolicyError("authority_expired", "signed authority is outside its execution window")
        lease = command.lease
        if not lease.issued_at <= now < lease.expires_at:
            raise BurpPolicyError("authority_expired", "Gateway lease is not active")
        budget = grant.budget
        reservation = lease.reservation
        if (
            reservation.request_bytes > budget.max_request_bytes
            or reservation.response_bytes > budget.max_response_bytes
            or reservation.duration_seconds > budget.max_duration_seconds
        ):
            raise BurpPolicyError("budget_not_authorized", "Gateway reservation exceeds signed budget")

    @staticmethod
    def _require_receipt_binding(
        command: GatewayDispatchCommand,
        result: object,
    ) -> None:
        from faultloom.execution import GatewayDispatchResult
        if type(result) is not GatewayDispatchResult:
            raise BurpPolicyError("gateway_result_invalid", "Gateway returned an invalid dispatch result")
        receipt = result.receipt
        if (
            receipt.outcome is not DispatchOutcome.COMPLETED
            or receipt.action_id != command.intent.action_id
            or receipt.lease_id != command.lease.lease_id
            or receipt.grant_id != command.lease.grant_id
            or receipt.grant_version != command.lease.grant_version
            or receipt.authority_key_id != command.lease.authority_key_id
            or receipt.scope_epoch != command.lease.scope_epoch
            or receipt.target_id != command.intent.target_id
            or receipt.identity_id != command.identity.identity_id
            or receipt.tenant_id != command.identity.tenant_id
            or receipt.reservation != command.lease.reservation
            or receipt.egress_plane is not EgressPlane.TARGET_GATEWAY
        ):
            raise BurpPolicyError(
                "gateway_receipt_mismatch", "Gateway receipt is not bound to the approved command"
            )


def _redact_header(header: BurpHeader) -> BurpHeader:
    """Retain only header names: arbitrary Burp values are never preview-safe."""

    return BurpHeader(name=header.name, value="<redacted>")


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _command_digest(command: GatewayDispatchCommand) -> str:
    from faultloom.execution.wire import execution_sha256_digest

    return execution_sha256_digest(command)
