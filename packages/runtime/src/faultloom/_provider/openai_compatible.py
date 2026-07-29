"""OpenAI Chat Completions translation on the existing provider-egress plane."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import ssl
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Literal, Protocol, Self
from types import MappingProxyType
from urllib.parse import urlsplit

from faultloom.egress import (
    CompiledProviderRequest,
    EgressOutcome,
    EgressPlane,
    EgressReceipt,
    EgressTransportResult,
    ProviderProxy as EgressProviderProxy,
    ProviderRequest,
    TransportOutcome,
)
from faultloom_protocol import AuthoritySigner, SecretRef
from faultloom_protocol.base import Identifier, NonEmptyStr, ShortStr
from pydantic import model_validator

from .common import (
    ProviderPlane,
    ProxyEffectDisposition,
    ProxyOutcome,
    _RuntimeModel,
    provider_canonical_json_bytes,
    provider_sha256_digest as sha256_digest,
)
from .intent import GenerationConfig
from .metadata import ProviderObservedMetadata
from .proxy import (
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderUsage,
    provider_proxy_result_attestation_bytes,
)


class OpenAICompatiblePreset(str, Enum):
    KIMI = "kimi"
    GLM = "glm"
    GROK = "grok"


_PRESETS: dict[OpenAICompatiblePreset, tuple[str, str, str]] = {
    OpenAICompatiblePreset.KIMI: (
        "moonshot",
        "https://api.moonshot.ai/v1",
        "/chat/completions",
    ),
    OpenAICompatiblePreset.GLM: (
        "bigmodel",
        "https://open.bigmodel.cn/api/paas/v4",
        "/chat/completions",
    ),
    OpenAICompatiblePreset.GROK: (
        "xai",
        "https://api.x.ai/v1",
        "/chat/completions",
    ),
}
_ENVIRONMENT_VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class OpenAICompatibleEndpointConfig(_RuntimeModel):
    """Pinned endpoint facts; credentials remain outside serialized config."""

    endpoint_id: Identifier
    provider_id: Identifier
    base_url: NonEmptyStr
    model: ShortStr
    credential_ref: SecretRef
    metadata: ProviderObservedMetadata
    chat_completions_path: NonEmptyStr = "/chat/completions"

    @model_validator(mode="after")
    def _valid_endpoint(self) -> Self:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "base URL must be an HTTPS URL without credentials, query, or fragment"
            )
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("base URL port must be valid") from exc
        if _SAFE_PATH.fullmatch(parsed.path or "/") is None or "//" in parsed.path:
            raise ValueError("base URL path must be canonical")
        if (
            _SAFE_PATH.fullmatch(self.chat_completions_path) is None
            or "//" in self.chat_completions_path
            or any(
                part in {".", ".."}
                for part in self.chat_completions_path.split("/")
            )
        ):
            raise ValueError("chat completions path must be a canonical absolute relative path")
        if (
            self.metadata.provider_id != self.provider_id
            or self.metadata.actual_snapshot != self.model
        ):
            raise ValueError("endpoint metadata must independently bind provider and exact model")
        return self

    @property
    def origin(self) -> str:
        parsed = urlsplit(self.base_url)
        return f"https://{parsed.netloc}"

    @property
    def api_path(self) -> str:
        prefix = urlsplit(self.base_url).path.rstrip("/")
        return (prefix or "") + self.chat_completions_path


class OpenAICompatibleMessage(_RuntimeModel):
    role: Literal["system", "user", "assistant"]
    content: NonEmptyStr

    def as_wire(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


class OpenAICompatibleChatPayload(_RuntimeModel):
    messages: tuple[OpenAICompatibleMessage, ...]
    generation: GenerationConfig

    @model_validator(mode="after")
    def _requires_message(self) -> Self:
        if not self.messages:
            raise ValueError("OpenAI-compatible chat payload requires one or more messages")
        return self

    def prompt_material(self) -> dict[str, tuple[dict[str, str], ...]]:
        return {"messages": tuple(message.as_wire() for message in self.messages)}

    def prompt_digest(self) -> str:
        return sha256_digest(self.prompt_material())

    def prompt_bytes(self) -> int:
        return len(provider_canonical_json_bytes(self.prompt_material()))


PromptResolver = Callable[[ProviderProxyRequest], OpenAICompatibleChatPayload]


@dataclass(frozen=True, slots=True)
class OpenAICompatibleCredentialBinding:
    credential_ref: SecretRef
    endpoint_id: str
    provider_id: str
    origin: str
    resolution_digest: str
    destination_digest: str
    environment_variable: str

    def __post_init__(self) -> None:
        if _ENVIRONMENT_VARIABLE.fullmatch(self.environment_variable) is None:
            raise ValueError(
                "credential environment variable must be an uppercase identifier"
            )
        if not (
            _SHA256_DIGEST.fullmatch(self.resolution_digest)
            and _SHA256_DIGEST.fullmatch(self.destination_digest)
        ):
            raise ValueError(
                "credential binding requires pinned resolution and destination digests"
            )


class ProviderCredentialResolver(Protocol):
    identity: str

    def resolve(self, request: CompiledProviderRequest) -> str: ...


class BoundEnvironmentCredentialResolver:
    """Explicit environment injection, bound to a compiled egress destination."""

    __slots__ = ("_bindings", "_environment", "_identity", "_sealed")

    def __init__(
        self,
        *,
        bindings: Iterable[OpenAICompatibleCredentialBinding],
        environment: Mapping[str, str],
    ) -> None:
        records = tuple(bindings)
        if len({(item.endpoint_id, item.credential_ref.uri) for item in records}) != len(
            records
        ):
            raise ValueError("credential bindings must be unique")
        self._bindings = records
        self._environment = MappingProxyType(dict(environment))
        self._identity = "credential-resolver.bound-environment.v2:" + hashlib.sha256(
            json.dumps(
                [
                    {
                        "credential_ref": item.credential_ref.model_dump(mode="json"),
                        "destination_digest": item.destination_digest,
                        "endpoint_id": item.endpoint_id,
                        "environment_variable": item.environment_variable,
                        "origin": item.origin,
                        "provider_id": item.provider_id,
                        "resolution_digest": item.resolution_digest,
                    }
                    for item in sorted(records, key=lambda item: item.endpoint_id)
                ],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self._sealed = True

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("credential resolver is immutable after construction")
        object.__setattr__(self, name, value)

    @property
    def identity(self) -> str:
        return self._identity

    def resolve(self, request: CompiledProviderRequest) -> str:
        for binding in self._bindings:
            if (
                binding.credential_ref == request.credential_ref
                and binding.endpoint_id == request.endpoint_id
                and binding.provider_id == request.provider_id
                and binding.origin == request.origin
                and binding.resolution_digest == request.resolution_digest
                and binding.destination_digest == request.destination_digest
            ):
                value = self._environment.get(binding.environment_variable)
                if isinstance(value, str) and value:
                    return value
                break
        raise ValueError(
            "no bound credential is available for compiled provider request"
        )


@dataclass(frozen=True, slots=True)
class OpenAICompatibleHttpResponse:
    status: int
    body: bytes


class OpenAICompatibleHttpPort(Protocol):
    """Trusted T17/Gateway HTTP boundary; it must honor compiled destination pins."""

    identity: str

    def dispatch(
        self,
        request: CompiledProviderRequest,
        *,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        maximum_response_bytes: int,
    ) -> OpenAICompatibleHttpResponse: ...


class PinnedHttpsGatewayPort:
    """Concrete no-proxy HTTPS port for a pre-resolved egress destination."""

    __slots__ = ("_timeout_seconds", "_identity", "_sealed")

    def __init__(self, *, timeout_seconds: int = 30) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
            raise ValueError("pinned HTTPS timeout must be 1 through 300 seconds")
        self._timeout_seconds = timeout_seconds
        self._identity = f"gateway.https-pinned-tls.v2:timeout={timeout_seconds}"
        self._sealed = True

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("pinned HTTPS port is immutable after construction")
        object.__setattr__(self, name, value)

    @property
    def identity(self) -> str:
        return self._identity

    def dispatch(
        self,
        request: CompiledProviderRequest,
        *,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        maximum_response_bytes: int,
    ) -> OpenAICompatibleHttpResponse:
        origin = urlsplit(request.origin)
        host = origin.hostname
        if origin.scheme != "https" or host is None or not request.resolved_addresses:
            raise ValueError("compiled provider request is not a pinned HTTPS destination")
        try:
            port = origin.port or 443
        except ValueError as exc:
            raise ValueError("compiled provider origin has an invalid port") from exc
        host_header = origin.netloc
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise ValueError("provider request path is not safe for HTTP")
        if any(
            not isinstance(name, str)
            or not isinstance(value, str)
            or "\r" in name
            or "\n" in name
            or "\r" in value
            or "\n" in value
            for name, value in headers.items()
        ):
            raise ValueError("provider request headers are not safe for HTTP")
        message = (
            f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
            + "".join(f"{name}: {value}\r\n" for name, value in headers.items())
            + "\r\n"
        ).encode("ascii") + body
        last_error: OSError | None = None
        for address in request.resolved_addresses:
            try:
                with socket.create_connection((address, port), self._timeout_seconds) as raw:
                    context = ssl.create_default_context()
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        tls.sendall(message)
                        return self._read_response(tls, maximum_response_bytes)
            except OSError as exc:
                last_error = exc
        raise OSError("all compiled provider addresses failed") from last_error

    @staticmethod
    def _read_response(
        tls: ssl.SSLSocket, maximum_response_bytes: int
    ) -> OpenAICompatibleHttpResponse:
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            if len(head) >= 8192:
                raise ValueError("provider response headers exceed their bounded size")
            chunk = tls.recv(1)
            if not chunk:
                raise ValueError("provider response ended before its headers")
            head.extend(chunk)
        status, headers = PinnedHttpsGatewayPort._parse_response_head(bytes(head[:-4]))
        if 100 <= status < 200:
            raise ValueError("interim provider responses are not supported")
        transfer_encoding = headers.get("transfer-encoding")
        content_length = headers.get("content-length")
        if transfer_encoding is not None and content_length is not None:
            raise ValueError("provider response has ambiguous HTTP framing")
        if transfer_encoding is not None:
            if transfer_encoding.lower() != b"chunked":
                raise ValueError("provider response uses unsupported transfer encoding")
            body = PinnedHttpsGatewayPort._read_chunked_body(
                tls, maximum_response_bytes
            )
        elif content_length is not None:
            if not content_length.isdigit():
                raise ValueError("provider response has an invalid content length")
            length = int(content_length)
            if length > maximum_response_bytes:
                raise ValueError("provider response exceeds its bounded body")
            body = PinnedHttpsGatewayPort._read_exact(tls, length)
        else:
            raise ValueError("provider response has no supported HTTP framing")
        return OpenAICompatibleHttpResponse(status=status, body=body)

    @staticmethod
    def _parse_response_head(head: bytes) -> tuple[int, dict[str, bytes]]:
        lines = head.split(b"\r\n")
        status_line = lines[0].split()
        if (
            len(status_line) != 3
            or status_line[0] != b"HTTP/1.1"
            or len(status_line[1]) != 3
            or not status_line[1].isdigit()
        ):
            raise ValueError("provider response has no valid HTTP status")
        headers: dict[str, bytes] = {}
        for line in lines[1:]:
            if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
                raise ValueError("provider response has malformed headers")
            raw_name, value = line.split(b":", 1)
            if not raw_name.isascii() or not all(
                character.isalnum() or character in "-" for character in raw_name.decode()
            ):
                raise ValueError("provider response has malformed header names")
            name = raw_name.decode("ascii").lower()
            if name in headers:
                raise ValueError("provider response has duplicate headers")
            headers[name] = value.strip()
        return int(status_line[1]), headers

    @staticmethod
    def _read_exact(tls: ssl.SSLSocket, length: int) -> bytes:
        body = bytearray()
        while len(body) < length:
            chunk = tls.recv(length - len(body))
            if not chunk:
                raise ValueError("provider response ended before its framed body")
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _read_line(tls: ssl.SSLSocket, maximum_bytes: int) -> bytes:
        line = bytearray()
        while not line.endswith(b"\r\n"):
            if len(line) >= maximum_bytes:
                raise ValueError("provider response framing line exceeds its bound")
            chunk = tls.recv(1)
            if not chunk:
                raise ValueError("provider response ended in its framed body")
            line.extend(chunk)
        return bytes(line[:-2])

    @staticmethod
    def _read_chunked_body(
        tls: ssl.SSLSocket, maximum_response_bytes: int
    ) -> bytes:
        body = bytearray()
        while True:
            raw_size = PinnedHttpsGatewayPort._read_line(tls, 8192)
            size_text = raw_size.split(b";", 1)[0]
            if not size_text or not all(
                character in b"0123456789abcdefABCDEF" for character in size_text
            ):
                raise ValueError("provider response has an invalid chunk size")
            size = int(size_text, 16)
            if size > maximum_response_bytes - len(body):
                raise ValueError("provider response exceeds its bounded body")
            if size == 0:
                if PinnedHttpsGatewayPort._read_line(tls, 8192):
                    raise ValueError("provider response trailers are not supported")
                return bytes(body)
            body.extend(PinnedHttpsGatewayPort._read_exact(tls, size))
            if PinnedHttpsGatewayPort._read_exact(tls, 2) != b"\r\n":
                raise ValueError("provider response chunk has no terminating CRLF")


@dataclass(frozen=True, slots=True)
class _PayloadRecord:
    payload: OpenAICompatibleChatPayload
    request_binding_digest: str


@dataclass(frozen=True, slots=True)
class _TransportArtifact:
    response: OpenAICompatibleHttpResponse | None
    not_dispatched: bool


class OpenAICompatiblePayloadStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[str, _PayloadRecord] = {}

    def publish(
        self,
        request: ProviderProxyRequest,
        payload: OpenAICompatibleChatPayload,
    ) -> None:
        with self._lock:
            if request.request_id in self._records:
                raise ValueError("OpenAI-compatible payload request ID is already pending")
            self._records[request.request_id] = _PayloadRecord(
                payload=payload,
                request_binding_digest=_payload_request_binding(request),
            )

    def consume(
        self, request: CompiledProviderRequest
    ) -> OpenAICompatibleChatPayload | None:
        with self._lock:
            record = self._records.pop(request.request_id, None)
        if (
            record is None
            or request.payload_digest != record.payload.prompt_digest()
            or record.request_binding_digest != _compiled_payload_request_binding(request)
        ):
            return None
        return record.payload

    def discard(self, request_id: str) -> None:
        with self._lock:
            self._records.pop(request_id, None)


def _payload_request_binding(request: ProviderProxyRequest) -> str:
    return sha256_digest(
        {
            "credential_ref": request.credential_ref,
            "data_policy_id": request.data_policy_id,
            "endpoint_id": request.endpoint_id,
            "model_snapshot": request.model_snapshot,
            "payload_bytes": request.payload_bytes,
            "payload_digest": request.payload_digest,
            "provider_id": request.provider_id,
            "request_id": request.request_id,
            "tool_ids": request.tool_ids,
        }
    )


def _compiled_payload_request_binding(request: CompiledProviderRequest) -> str:
    return sha256_digest(
        {
            "credential_ref": request.credential_ref,
            "data_policy_id": request.data_policy_id,
            "endpoint_id": request.endpoint_id,
            "model_snapshot": request.model_snapshot,
            "payload_bytes": request.payload_bytes,
            "payload_digest": request.payload_digest,
            "provider_id": request.provider_id,
            "request_id": request.request_id,
            "tool_ids": request.tool_ids,
        }
    )


class OpenAICompatibleEgressTransport:
    """ProviderTransport implementation invoked only after egress authorization."""

    plane = EgressPlane.MODEL_PROVIDER
    transport_id = "transport.openai-compatible.v2"

    def __init__(
        self,
        *,
        endpoints: Iterable[OpenAICompatibleEndpointConfig],
        payload_store: OpenAICompatiblePayloadStore,
        credential_resolver: ProviderCredentialResolver,
    ) -> None:
        self._initialize(
            endpoints=endpoints,
            payload_store=payload_store,
            credential_resolver=credential_resolver,
            http_port=PinnedHttpsGatewayPort(),
            test_only=False,
        )

    @classmethod
    def for_testing(
        cls,
        *,
        endpoints: Iterable[OpenAICompatibleEndpointConfig],
        payload_store: OpenAICompatiblePayloadStore,
        credential_resolver: ProviderCredentialResolver,
        http_port: OpenAICompatibleHttpPort,
    ) -> Self:
        instance = cls.__new__(cls)
        instance._initialize(
            endpoints=endpoints,
            payload_store=payload_store,
            credential_resolver=credential_resolver,
            http_port=http_port,
            test_only=True,
        )
        return instance

    def _initialize(
        self,
        *,
        endpoints: Iterable[OpenAICompatibleEndpointConfig],
        payload_store: OpenAICompatiblePayloadStore,
        credential_resolver: ProviderCredentialResolver,
        http_port: OpenAICompatibleHttpPort,
        test_only: bool,
    ) -> None:
        configs = tuple(endpoints)
        if not configs or len({item.endpoint_id for item in configs}) != len(configs):
            raise ValueError(
                "OpenAI-compatible endpoint IDs must be non-empty and unique"
            )
        if (
            not callable(getattr(credential_resolver, "resolve", None))
            or not isinstance(getattr(credential_resolver, "identity", None), str)
            or not credential_resolver.identity
            or not callable(getattr(http_port, "dispatch", None))
            or not isinstance(getattr(http_port, "identity", None), str)
            or not http_port.identity
        ):
            raise TypeError(
                "OpenAI-compatible transport requires bound credential and HTTP ports"
            )
        if not test_only and (
            type(credential_resolver) is not BoundEnvironmentCredentialResolver
            or type(http_port) is not PinnedHttpsGatewayPort
        ):
            raise TypeError("live transport requires immutable bound TLS components")
        self._endpoints = {item.endpoint_id: item for item in configs}
        self._payload_store = payload_store
        self._credential_resolver = credential_resolver
        self._http_port = http_port
        self._test_only = test_only
        self._component_descriptor = self._describe_components()
        self.transport_id = "transport.openai-compatible.v3:" + self._component_descriptor
        self._lock = RLock()
        self._artifacts: dict[str, _TransportArtifact] = {}

    @property
    def test_only(self) -> bool:
        return self._test_only

    def _describe_components(self) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "credential_resolver": self._credential_resolver.identity,
                    "endpoints": [
                        item.model_dump(mode="json")
                        for item in sorted(
                            self._endpoints.values(), key=lambda item: item.endpoint_id
                        )
                    ],
                    "http_port": self._http_port.identity,
                    "test_only": self._test_only,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def _components_are_current(self) -> bool:
        try:
            current = self._describe_components()
        except Exception:
            return False
        return hmac.compare_digest(current, self._component_descriptor)

    def dispatch(self, request: CompiledProviderRequest) -> EgressTransportResult:
        if not self._components_are_current():
            return self._not_dispatched(request)
        payload = self._payload_store.consume(request)
        endpoint = self._endpoints.get(request.endpoint_id)
        if (
            payload is None
            or endpoint is None
            or endpoint.provider_id != request.provider_id
            or endpoint.origin != request.origin
            or endpoint.model != request.model_snapshot
            or endpoint.credential_ref != request.credential_ref
            or request.tool_ids
        ):
            return self._not_dispatched(request)
        body = _request_body(endpoint.model, payload)
        raw_body = json.dumps(
            body, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(raw_body) > request.maximum_request_bytes:
            return self._not_dispatched(request)
        try:
            credential = self._credential_resolver.resolve(request)
        except Exception:
            return self._not_dispatched(request)
        try:
            response = self._http_port.dispatch(
                request,
                path=endpoint.api_path,
                headers={
                    "Authorization": f"Bearer {credential}",
                    "Content-Type": "application/json",
                    "X-FaultLoom-Request-ID": request.request_id,
                },
                body=raw_body,
                maximum_response_bytes=request.maximum_response_bytes,
            )
            if (
                not isinstance(response, OpenAICompatibleHttpResponse)
                or type(response.status) is not int
                or not isinstance(response.body, bytes)
                or len(response.body) > request.maximum_response_bytes
            ):
                raise ValueError(
                    "HTTP boundary returned an invalid or oversized response"
                )
        except Exception:
            return EgressTransportResult(
                schema_version="0.1.0",
                plane=EgressPlane.MODEL_PROVIDER,
                outcome=TransportOutcome.UNKNOWN_OUTCOME,
                bytes_sent=len(raw_body),
                bytes_received=0,
            )
        with self._lock:
            self._artifacts[request.request_id] = _TransportArtifact(response, False)
        return EgressTransportResult(
            schema_version="0.1.0",
            plane=EgressPlane.MODEL_PROVIDER,
            outcome=(
                TransportOutcome.COMPLETED
                if 200 <= response.status < 300
                else TransportOutcome.FAILED
            ),
            response_digest="sha256:" + hashlib.sha256(response.body).hexdigest(),
            response_status=response.status,
            bytes_sent=len(raw_body),
            bytes_received=len(response.body),
        )

    def take_artifact(self, request_id: str) -> _TransportArtifact | None:
        with self._lock:
            return self._artifacts.pop(request_id, None)

    def _not_dispatched(self, request: CompiledProviderRequest) -> EgressTransportResult:
        with self._lock:
            self._artifacts[request.request_id] = _TransportArtifact(None, True)
        return EgressTransportResult(
            schema_version="0.1.0",
            plane=EgressPlane.MODEL_PROVIDER,
            outcome=TransportOutcome.FAILED,
            bytes_sent=0,
            bytes_received=0,
        )


def openai_compatible_preset(
    preset: OpenAICompatiblePreset,
    *,
    endpoint_id: str,
    model: str,
    credential_ref: SecretRef,
    metadata: ProviderObservedMetadata,
    chat_completions_path: str = "/chat/completions",
) -> OpenAICompatibleEndpointConfig:
    provider_id, base_url, _ = _PRESETS[OpenAICompatiblePreset(preset)]
    return OpenAICompatibleEndpointConfig(
        endpoint_id=endpoint_id,
        provider_id=provider_id,
        base_url=base_url,
        model=model,
        credential_ref=credential_ref,
        metadata=metadata,
        chat_completions_path=chat_completions_path,
    )


class OpenAICompatibleProviderProxy:
    """Signed ProviderProxyPort adapter layered above the immutable egress plane."""

    plane = ProviderPlane.MODEL_PROVIDER

    def __init__(
        self,
        *,
        proxy_id: str,
        endpoints: Iterable[OpenAICompatibleEndpointConfig],
        prompt_resolver: PromptResolver,
        payload_store: OpenAICompatiblePayloadStore,
        egress_proxy: EgressProviderProxy,
        transport: OpenAICompatibleEgressTransport,
        attestation_signer: AuthoritySigner,
    ) -> None:
        configs = tuple(endpoints)
        if not isinstance(proxy_id, str) or not proxy_id or not callable(prompt_resolver):
            raise ValueError(
                "OpenAI-compatible proxy requires an identifier and prompt resolver"
            )
        if not callable(getattr(egress_proxy, "dispatch", None)):
            raise TypeError(
                "OpenAI-compatible proxy requires the existing provider egress proxy"
            )
        if transport.test_only and bool(getattr(egress_proxy, "_live", False)):
            raise ValueError("test-only transport cannot be attached to live egress")
        self._proxy_id = proxy_id
        self._endpoints = {item.endpoint_id: item for item in configs}
        self._resolver = prompt_resolver
        self._payload_store = payload_store
        self._egress_proxy = egress_proxy
        self._transport = transport
        self._signer = attestation_signer
        self.contract_digest = sha256_digest(
            {
                "purpose": "faultloom.openai_compatible_provider_proxy.v2",
                "endpoints": tuple(item.model_dump(mode="json") for item in configs),
            }
        )
        self.attestation_public_key = attestation_signer.public_key_record

    @property
    def proxy_id(self) -> str:
        return self._proxy_id

    def dispatch(self, request: ProviderProxyRequest) -> ProviderProxyResult:
        request = ProviderProxyRequest.model_validate(request.model_dump(mode="python"))
        if request.live and self._transport.test_only:
            return self._result(request, outcome=ProxyOutcome.DENIED)
        endpoint = self._endpoints.get(request.endpoint_id)
        if not self._request_matches_endpoint(request, endpoint):
            return self._result(request, outcome=ProxyOutcome.DENIED)
        try:
            payload = OpenAICompatibleChatPayload.model_validate(
                self._resolver(request).model_dump(mode="python")
            )
        except Exception:
            return self._result(request, outcome=ProxyOutcome.PRE_SEND_FAILED)
        if (
            payload.prompt_digest() != request.payload_digest
            or payload.prompt_bytes() != request.payload_bytes
            or sha256_digest(payload.generation) != request.config_digest
        ):
            return self._result(request, outcome=ProxyOutcome.DENIED)
        try:
            self._payload_store.publish(request, payload)
            receipt = self._egress_proxy.dispatch(
                ProviderRequest(
                    schema_version="0.1.0",
                    request_id=request.request_id,
                    run_id=request.run_id,
                    authority_digest=request.authority_digest,
                    scope_epoch=request.scope_epoch,
                    endpoint_id=request.endpoint_id,
                    provider_id=request.provider_id,
                    model_snapshot=request.model_snapshot,
                    data_policy_id=request.data_policy_id,
                    credential_ref=request.credential_ref,
                    payload_digest=request.payload_digest,
                    payload_bytes=request.payload_bytes,
                    tool_ids=request.tool_ids,
                    requested_at=request.requested_at,
                    live=request.live,
                )
            )
        except Exception:
            self._payload_store.discard(request.request_id)
            return self._result(
                request,
                outcome=ProxyOutcome.UNKNOWN_OUTCOME,
                effect=ProxyEffectDisposition.POSSIBLE,
                reconciliation_required=True,
            )
        finally:
            self._payload_store.discard(request.request_id)
        artifact = self._transport.take_artifact(request.request_id)
        if receipt.outcome is EgressOutcome.DENIED:
            return self._result(request, outcome=ProxyOutcome.DENIED)
        if artifact is not None and artifact.not_dispatched:
            return self._result(request, outcome=ProxyOutcome.PRE_SEND_FAILED)
        if receipt.outcome is EgressOutcome.UNKNOWN_OUTCOME:
            return self._result(
                request,
                outcome=ProxyOutcome.UNKNOWN_OUTCOME,
                effect=ProxyEffectDisposition.POSSIBLE,
                bytes_sent=receipt.bytes_sent,
                bytes_received=receipt.bytes_received,
                reconciliation_required=True,
            )
        if receipt.outcome is EgressOutcome.FAILED:
            effect = (
                ProxyEffectDisposition.OBSERVED
                if receipt.bytes_received
                else ProxyEffectDisposition.POSSIBLE
            )
            return self._result(
                request,
                outcome=ProxyOutcome.FAILED,
                effect=effect,
                status=receipt.response_status,
                bytes_sent=receipt.bytes_sent,
                bytes_received=receipt.bytes_received,
            )
        if (
            artifact is None
            or artifact.response is None
            or receipt.response_digest
            != "sha256:" + hashlib.sha256(artifact.response.body).hexdigest()
        ):
            return self._result(
                request,
                outcome=ProxyOutcome.UNKNOWN_OUTCOME,
                effect=ProxyEffectDisposition.POSSIBLE,
                bytes_sent=receipt.bytes_sent,
                bytes_received=receipt.bytes_received,
                reconciliation_required=True,
            )
        return self._completed_or_failed(request, endpoint, artifact.response, receipt)

    @staticmethod
    def _request_matches_endpoint(
        request: ProviderProxyRequest,
        endpoint: OpenAICompatibleEndpointConfig | None,
    ) -> bool:
        if (
            endpoint is None
            or request.tool_ids
            or endpoint.provider_id != request.provider_id
            or endpoint.model != request.model_snapshot
            or endpoint.credential_ref != request.credential_ref
        ):
            return False
        metadata = endpoint.metadata
        if request.live and not (
            metadata.snapshot_exact
            and metadata.runtime_exact
            and metadata.tokenizer_exact
            and metadata.context_window_exact
            and metadata.provenance.exact
        ):
            return False
        return (
            request.runtime_version == metadata.runtime_version
            and request.tokenizer_id == metadata.tokenizer_id
            and request.tokenizer_version == metadata.tokenizer_version
            and request.context_window == metadata.context_window
        )

    def _completed_or_failed(
        self,
        request: ProviderProxyRequest,
        endpoint: OpenAICompatibleEndpointConfig,
        response: OpenAICompatibleHttpResponse,
        receipt: EgressReceipt,
    ) -> ProviderProxyResult:
        try:
            decoded = json.loads(response.body)
            usage = decoded["usage"]
            if (
                not isinstance(decoded, dict)
                or decoded.get("model") != endpoint.model
                or type(decoded.get("choices")) is not list
                or not decoded["choices"]
                or type(usage) is not dict
                or type(usage.get("prompt_tokens")) is not int
                or type(usage.get("completion_tokens")) is not int
                or usage["prompt_tokens"] < 0
                or usage["completion_tokens"] < 0
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return self._result(
                request,
                outcome=ProxyOutcome.FAILED,
                effect=ProxyEffectDisposition.OBSERVED,
                status=receipt.response_status,
                bytes_sent=receipt.bytes_sent,
                bytes_received=receipt.bytes_received,
            )
        return self._result(
            request,
            outcome=ProxyOutcome.COMPLETED,
            effect=ProxyEffectDisposition.OBSERVED,
            status=receipt.response_status,
            bytes_sent=receipt.bytes_sent,
            bytes_received=receipt.bytes_received,
            response_digest=receipt.response_digest,
            metadata=endpoint.metadata,
            usage=ProviderUsage(
                input_tokens=usage["prompt_tokens"],
                output_tokens=usage["completion_tokens"],
            ),
        )

    def _result(
        self,
        request: ProviderProxyRequest,
        *,
        outcome: ProxyOutcome,
        effect: ProxyEffectDisposition = ProxyEffectDisposition.NOT_DISPATCHED,
        status: int | None = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        reconciliation_required: bool = False,
        response_digest: str | None = None,
        metadata: ProviderObservedMetadata | None = None,
        usage: ProviderUsage | None = None,
    ) -> ProviderProxyResult:
        completed = outcome is ProxyOutcome.COMPLETED
        payload: dict[str, object] = {
            "plane": ProviderPlane.MODEL_PROVIDER,
            "request_id": request.request_id,
            "proxy_request_digest": sha256_digest(request),
            "attested_proxy_id": self.proxy_id,
            "attested_proxy_contract_digest": self.contract_digest,
            "attestation_key_id": self.attestation_public_key.key_id,
            "proxy_receipt_digest": "sha256:" + "0" * 64,
            "attestation_signature": "unsigned",
            "outcome": outcome,
            "effect_disposition": effect,
            "response_digest": response_digest,
            "response_status": status,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "reconciliation_required": reconciliation_required,
            "observed_metadata": metadata,
            "usage": usage,
            "accepted_prompt_digest": request.prompt_digest if completed else None,
            "accepted_compiled_context_digest": (
                request.compiled_context_digest if completed else None
            ),
            "accepted_tool_schema_digest": request.tool_schema_digest if completed else None,
            "accepted_output_schema_digest": (
                request.output_schema_digest if completed else None
            ),
            "accepted_config_digest": request.config_digest if completed else None,
            "accepted_policy_ref": request.policy_ref if completed else None,
            "accepted_data_policy_id": request.data_policy_id if completed else None,
            "accepted_data_consent_ref": (
                request.data_consent_ref if completed else None
            ),
            "accepted_proxy_id": self.proxy_id if completed else None,
            "accepted_proxy_contract_digest": self.contract_digest if completed else None,
        }
        draft = ProviderProxyResult.model_construct(**payload)
        payload["proxy_receipt_digest"] = sha256_digest(
            draft.model_dump(
                mode="python",
                exclude={"proxy_receipt_digest", "attestation_signature"},
                warnings=False,
            )
        )
        unsigned = ProviderProxyResult.model_validate(payload)
        payload["attestation_signature"] = self._signer.sign(
            provider_proxy_result_attestation_bytes(unsigned)
        )
        return ProviderProxyResult.model_validate(payload)


def _request_body(model: str, payload: OpenAICompatibleChatPayload) -> dict[str, object]:
    generation = payload.generation
    body: dict[str, object] = {
        "model": model,
        "messages": [item.as_wire() for item in payload.messages],
        "max_tokens": generation.max_output_tokens,
        "temperature": generation.temperature_milli / 1000,
        "top_p": generation.top_p_milli / 1000,
    }
    if generation.seed is not None:
        body["seed"] = generation.seed
    if generation.response_format == "json":
        body["response_format"] = {"type": "json_object"}
    return body
