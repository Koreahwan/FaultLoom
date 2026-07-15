from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import SecretRef
from faultloom_protocol.base import Sha256Digest


class BurpModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class BurpTool(StrEnum):
    READ_SCANNER_ISSUES = "scanner_issues.read"
    READ_HTTP_HISTORY = "proxy.http_history.read"
    READ_WEBSOCKET_HISTORY = "proxy.websocket_history.read"
    READ_ORGANIZER_ITEMS = "organizer.items.read"
    CREATE_REPEATER_TAB = "repeater.tab.create"


class HistoryTransport(StrEnum):
    HTTP = "http"
    WEBSOCKET = "websocket"


class HttpVersion(StrEnum):
    HTTP_1_1 = "HTTP/1.1"
    HTTP_2 = "HTTP/2"


class ToolDescriptor(BurpModel):
    name: str = Field(min_length=1, max_length=128)
    input_schema_digest: Sha256Digest


class BurpServerSnapshot(BurpModel):
    server_version: str = Field(min_length=1, max_length=128)
    tools: tuple[ToolDescriptor, ...]

    @model_validator(mode="after")
    def _unique_tools(self) -> Self:
        names = tuple(tool.name for tool in self.tools)
        if len(names) != len(set(names)):
            raise ValueError("server tool inventory contains duplicate names")
        return self


class LoopbackEndpoint(BurpModel):
    url: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def _loopback_only(self) -> Self:
        parsed = urlsplit(self.url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("Burp policy endpoint must be HTTP loopback")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Burp policy endpoint cannot contain user information")
        if parsed.query or parsed.fragment or parsed.path not in {"", "/", "/mcp"}:
            raise ValueError("Burp policy endpoint has unsupported URL components")
        return self


class BurpScope(BurpModel):
    hosts: tuple[str, ...]
    path_prefixes: tuple[str, ...] = ("/",)

    @model_validator(mode="after")
    def _canonical_scope(self) -> Self:
        if not self.hosts or any(host != host.casefold() or "*" in host for host in self.hosts):
            raise ValueError("scope hosts must be explicit lower-case names")
        if len(self.hosts) != len(set(self.hosts)):
            raise ValueError("scope hosts must be unique")
        if not self.path_prefixes or any(not path.startswith("/") for path in self.path_prefixes):
            raise ValueError("scope path prefixes must be absolute")
        return self

    def contains(self, host: str, path: str) -> bool:
        def path_matches(prefix: str) -> bool:
            normalized = prefix.rstrip("/") or "/"
            return normalized == "/" or path == normalized or path.startswith(f"{normalized}/")

        return host.casefold() in self.hosts and any(path_matches(p) for p in self.path_prefixes)


class BurpToolRequest(BurpModel):
    tool_name: str = Field(min_length=1, max_length=128)
    host: str | None = Field(default=None, min_length=1, max_length=253)
    path: str | None = Field(default=None, min_length=1, max_length=4096)
    http_version: HttpVersion | None = None


class BurpHeader(BurpModel):
    name: str = Field(min_length=1, max_length=256)
    value: str = Field(max_length=65_536)


class CredentialField(BurpModel):
    name: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=1, max_length=65_536)


class BurpHistoryItem(BurpModel):
    item_id: str = Field(min_length=1, max_length=256)
    transport: HistoryTransport
    host: str = Field(min_length=1, max_length=253)
    path: str = Field(min_length=1, max_length=4096)
    headers: tuple[BurpHeader, ...] = ()
    credentials: tuple[CredentialField, ...] = ()


class ScrubbedSecret(BurpModel):
    name: str
    value: Literal["<secret-ref>"] = "<secret-ref>"
    secret_ref: SecretRef


class ScrubbedHistoryItem(BurpModel):
    item_id: str
    transport: HistoryTransport
    host: str
    path: str
    headers: tuple[BurpHeader, ...]
    credentials: tuple[ScrubbedSecret, ...]
    secret_refs: tuple[SecretRef, ...]


class CandidateReceipt(BurpModel):
    tool: BurpTool
    candidate_only: Literal[True] = True
    execution_performed: Literal[False] = False
    verification_evidence: Literal[False] = False


class SecretRegistrar(Protocol):
    def register(self, *, purpose: str, value: str) -> SecretRef: ...
