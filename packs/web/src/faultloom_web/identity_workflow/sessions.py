"""Identity vault references and isolated session ownership."""

from __future__ import annotations

from enum import StrEnum
from typing import Self, assert_never

from pydantic import model_validator

from faultloom_protocol import AuthSession, IdentityContext, IdentityProfile
from faultloom_protocol.base import Identifier

from ._base import IdentityWorkflowModel
from .errors import IdentityWorkflowError


class SessionChannel(StrEnum):
    BROWSER = "browser"
    API = "api"


class SessionRegistration(IdentityWorkflowModel):
    channel: SessionChannel
    profile: IdentityProfile
    session: AuthSession
    context: IdentityContext

    @model_validator(mode="after")
    def _is_consistent(self) -> Self:
        match self.profile.status:
            case "active":
                pass
            case "disabled" | "revoked":
                raise IdentityWorkflowError(
                    code="identity.profile_inactive",
                    detail="disabled and revoked identities cannot own active contexts",
                )
            case unreachable:
                assert_never(unreachable)
        if self.session.revoked_at is not None:
            raise IdentityWorkflowError(
                code="identity.session_revoked",
                detail="revoked sessions cannot be registered",
            )
        identity_ids = {
            self.profile.identity_id,
            self.session.identity_id,
            self.context.identity_id,
        }
        if len(identity_ids) != 1:
            raise IdentityWorkflowError(
                code="identity.binding_mismatch",
                detail="profile, session, and context identify different actors",
            )
        if self.session.tenant_id != self.context.tenant_id:
            raise IdentityWorkflowError(
                code="identity.tenant_mismatch",
                detail="session and context identify different tenants",
            )
        if self.context.tenant_id not in self.profile.tenant_ids:
            raise IdentityWorkflowError(
                code="identity.tenant_unprovisioned",
                detail="context tenant is absent from the provisioned profile",
            )
        if not set(self.context.role_ids).issubset(self.profile.role_ids):
            raise IdentityWorkflowError(
                code="identity.role_unprovisioned",
                detail="context contains a role absent from the provisioned profile",
            )
        if self.context.auth_session_id != self.session.auth_session_id:
            raise IdentityWorkflowError(
                code="identity.session_mismatch",
                detail="context is not bound to the supplied authentication session",
            )
        match self.channel:
            case SessionChannel.BROWSER:
                valid_channel = (
                    self.context.browser_context_ref is not None
                    and self.context.api_session_ref is None
                )
            case SessionChannel.API:
                valid_channel = (
                    self.context.api_session_ref is not None
                    and self.context.browser_context_ref is None
                )
            case unreachable:
                assert_never(unreachable)
        if not valid_channel:
            raise IdentityWorkflowError(
                code="identity.channel_alias",
                detail="each context must own exactly one browser or API session reference",
            )
        return self

    @property
    def channel_ref_uri(self) -> str:
        match self.channel:
            case SessionChannel.BROWSER:
                reference = self.context.browser_context_ref
            case SessionChannel.API:
                reference = self.context.api_session_ref
            case unreachable:
                assert_never(unreachable)
        if reference is None:
            raise IdentityWorkflowError(
                code="identity.channel_reference_missing",
                detail="validated session channel lost its opaque reference",
            )
        return reference.uri


class IdentitySessionVault:
    """Mutable ownership registry; secret bytes never enter this process."""

    def __init__(self) -> None:
        self._registrations: dict[str, SessionRegistration] = {}
        self._auth_session_owners: dict[str, str] = {}
        self._secret_owners: dict[str, str] = {}

    def register(self, registration: SessionRegistration) -> None:
        context_id = registration.context.identity_context_id
        if context_id in self._registrations:
            raise IdentityWorkflowError(
                code="identity.context_reused",
                detail="identity context IDs must be fresh",
            )
        session_id = registration.session.auth_session_id
        if session_id in self._auth_session_owners:
            raise IdentityWorkflowError(
                code="identity.auth_session_shared",
                detail="authentication sessions cannot cross identity contexts",
            )
        secret_uris = (
            registration.session.session_handle_ref.uri,
            registration.channel_ref_uri,
        )
        if registration.profile.credential_ref.uri in secret_uris:
            raise IdentityWorkflowError(
                code="identity.credential_session_alias",
                detail="credential references cannot double as session handles",
            )
        if any(uri in self._secret_owners for uri in secret_uris):
            raise IdentityWorkflowError(
                code="identity.session_reference_shared",
                detail="browser and API session references cannot be shared",
            )
        self._registrations[context_id] = registration
        self._auth_session_owners[session_id] = context_id
        self._secret_owners.update((uri, context_id) for uri in secret_uris)

    def registration(self, context_id: Identifier) -> SessionRegistration:
        registration = self._registrations.get(context_id)
        if registration is None:
            raise IdentityWorkflowError(
                code="identity.context_unknown",
                detail=f"identity context is not registered: {context_id}",
            )
        return registration

    def context_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._registrations))
