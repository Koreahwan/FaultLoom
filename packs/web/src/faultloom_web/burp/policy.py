from __future__ import annotations

from dataclasses import dataclass

from faultloom_protocol import SecretRef

from .manifest import expected_server_snapshot
from .models import (
    BurpHeader,
    BurpHistoryItem,
    BurpScope,
    BurpServerSnapshot,
    BurpTool,
    BurpToolRequest,
    CandidateReceipt,
    HistoryTransport,
    LoopbackEndpoint,
    ScrubbedHistoryItem,
    ScrubbedSecret,
    SecretRegistrar,
)

_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "set-cookie"})
_HISTORY_TOOLS = {
    BurpTool.READ_HTTP_HISTORY: HistoryTransport.HTTP,
    BurpTool.READ_WEBSOCKET_HISTORY: HistoryTransport.WEBSOCKET,
}


@dataclass(frozen=True, slots=True)
class BurpPolicyError(ValueError):
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


class PassiveBurpPolicyAdapter:
    def __init__(self, endpoint: LoopbackEndpoint, scope: BurpScope) -> None:
        self._endpoint = endpoint
        self._scope = scope
        self._disabled_reason: str | None = None

    @property
    def enabled(self) -> bool:
        return self._disabled_reason is None

    def check_server(self, observed: BurpServerSnapshot) -> None:
        self._require_enabled()
        if observed != expected_server_snapshot():
            self._disabled_reason = "server version, tool inventory, or schema digest drift"
            raise BurpPolicyError("adapter_disabled", self._disabled_reason)

    def authorize(
        self,
        request: BurpToolRequest,
        *,
        observed_server: BurpServerSnapshot,
    ) -> CandidateReceipt:
        self.check_server(observed_server)
        try:
            tool = BurpTool(request.tool_name)
        except ValueError as exc:
            raise BurpPolicyError("tool_denied", "tool is not in the passive allowlist") from exc
        if request.host is None or request.path is None:
            raise BurpPolicyError("scope_missing", "tool request requires an explicit target")
        self._require_in_scope(request.host, request.path)
        if tool is BurpTool.CREATE_REPEATER_TAB and request.http_version is None:
            raise BurpPolicyError("invalid_request", "Repeater tab requires HTTP/1.1 or HTTP/2")
        if tool is not BurpTool.CREATE_REPEATER_TAB and request.http_version is not None:
            raise BurpPolicyError("invalid_request", "HTTP version is valid only for Repeater tabs")
        return CandidateReceipt(tool=tool)

    def scrub_history(
        self,
        request: BurpToolRequest,
        items: tuple[BurpHistoryItem, ...],
        *,
        observed_server: BurpServerSnapshot,
        secrets: SecretRegistrar,
    ) -> tuple[ScrubbedHistoryItem, ...]:
        receipt = self.authorize(request, observed_server=observed_server)
        expected_transport = _HISTORY_TOOLS.get(receipt.tool)
        if expected_transport is None:
            raise BurpPolicyError("invalid_request", "tool does not return proxy history")
        scrubbed: list[ScrubbedHistoryItem] = []
        for item in items:
            if item.transport is not expected_transport:
                raise BurpPolicyError("history_mismatch", "history transport does not match tool")
            self._require_in_scope(item.host, item.path)
            scrubbed.append(self._scrub_item(item, secrets))
        return tuple(scrubbed)

    def _scrub_item(
        self,
        item: BurpHistoryItem,
        secrets: SecretRegistrar,
    ) -> ScrubbedHistoryItem:
        headers: list[BurpHeader] = []
        credentials: list[ScrubbedSecret] = []
        refs: list[SecretRef] = []
        for header in item.headers:
            if header.name.casefold() not in _SENSITIVE_HEADERS:
                headers.append(header)
                continue
            ref = self._register_secret(secrets, purpose=f"burp.header.{header.name}", value=header.value)
            headers.append(BurpHeader(name=header.name, value="<secret-ref>"))
            refs.append(ref)
        for credential in item.credentials:
            ref = self._register_secret(
                secrets,
                purpose=f"burp.credential.{credential.name}",
                value=credential.value,
            )
            credentials.append(ScrubbedSecret(name=credential.name, secret_ref=ref))
            refs.append(ref)
        return ScrubbedHistoryItem(
            item_id=item.item_id,
            transport=item.transport,
            host=item.host,
            path=item.path,
            headers=tuple(headers),
            credentials=tuple(credentials),
            secret_refs=tuple(refs),
        )

    @staticmethod
    def _register_secret(secrets: SecretRegistrar, *, purpose: str, value: str) -> SecretRef:
        try:
            ref = secrets.register(purpose=purpose, value=value)
        except Exception as exc:
            raise BurpPolicyError("secret_scrub_failed", "secret registration failed closed") from exc
        if type(ref) is not SecretRef or value in ref.uri or value in ref.purpose:
            raise BurpPolicyError("secret_scrub_failed", "registrar returned an unsafe reference")
        return ref

    def _require_enabled(self) -> None:
        if self._disabled_reason is not None:
            raise BurpPolicyError("adapter_disabled", self._disabled_reason)

    def _require_in_scope(self, host: str, path: str) -> None:
        if not self._scope.contains(host, path):
            raise BurpPolicyError("out_of_scope", "Burp item is outside the approved scope")
