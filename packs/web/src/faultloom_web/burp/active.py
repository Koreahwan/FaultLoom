"""Prepare an explicitly selected Burp request for the Gateway-only live path.

This module never opens a target connection and never sends a request.  It only
checks that a user-selected Burp item still exactly describes an already
approved semantic Gateway command.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, final

from pydantic import Field, model_validator

from faultloom_protocol.base import Sha256Digest

from .models import BurpHeader, BurpModel, BurpScope
from .policy import BurpPolicyError

if TYPE_CHECKING:
    from faultloom.execution import GatewayDispatchCommand


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


@dataclass(frozen=True, slots=True)
class PreparedBurpGatewayDispatch:
    """The exact approved command, ready for the existing Gateway live path."""

    command: GatewayDispatchCommand
    preview: BurpGatewayPreview

    def gateway_command(self) -> GatewayDispatchCommand:
        return self.command


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


def _redact_header(header: BurpHeader) -> BurpHeader:
    """Retain only header names: arbitrary Burp values are never preview-safe."""

    return BurpHeader(name=header.name, value="<redacted>")
