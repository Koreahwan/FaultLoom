from __future__ import annotations

from typing import Self, assert_never

from pydantic import model_validator

from faultloom_protocol.base import Identifier

from .contracts import BrowserChildKind, ExecutionIdentity, ExecutionModel
from .gateway import ExecutionFlowKind
from .http_validation import ExecutionContractError


class BrowserContractError(ExecutionContractError):
    """A browser context or discovered child violated an isolation contract."""


class UnsupportedBrowserTransport(BrowserContractError):
    """The child requires a separately admitted non-HTTP executor."""


class BrowserIdentityContext(ExecutionModel):
    browser_context_id: Identifier
    storage_partition_id: Identifier
    identity: ExecutionIdentity

    @model_validator(mode="after")
    def _authenticated_and_consistent(self) -> Self:
        if self.identity.context_id != self.browser_context_id:
            raise ValueError("browser and execution context IDs differ")
        if self.identity.identity_id is None or self.identity.session_ref is None:
            raise ValueError("browser contexts require an operator-provisioned session handle")
        return self

    @property
    def session_uri(self) -> str:
        session_ref = self.identity.session_ref
        if session_ref is None:
            raise BrowserContractError("browser context session handle is absent")
        return session_ref.uri


def browser_flow_kind(kind: BrowserChildKind) -> ExecutionFlowKind:
    match kind:
        case BrowserChildKind.REDIRECT:
            return ExecutionFlowKind.REDIRECT
        case BrowserChildKind.IFRAME:
            return ExecutionFlowKind.IFRAME
        case BrowserChildKind.SUBRESOURCE:
            return ExecutionFlowKind.SUBRESOURCE
        case BrowserChildKind.SERVICE_WORKER:
            return ExecutionFlowKind.SERVICE_WORKER
        case BrowserChildKind.DOWNLOAD:
            return ExecutionFlowKind.DOWNLOAD
        case BrowserChildKind.WEBSOCKET:
            raise UnsupportedBrowserTransport(
                "WebSocket candidate requires the separately admitted semantic WebSocket engine"
            )
        case unreachable:
            assert_never(unreachable)
