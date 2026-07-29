"""Signed OpenAI Chat Completions proxy for configured provider endpoints.

The provider contract deliberately carries prompt and tool-schema digests, not
their raw bytes.  A caller therefore supplies a local prompt resolver and this
proxy refuses to send unless its canonical message material matches the
attested request digest.  Tool schemas are not available at this boundary, so
tool calls are fail-closed rather than silently converted to an API payload.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from enum import Enum
from typing import Literal, Self
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from faultloom_protocol import AuthoritySigner, SecretRef
from faultloom_protocol.base import Identifier, NonEmptyStr, ShortStr
from pydantic import model_validator

from .common import (
    MetadataSourceKind,
    ProviderPlane,
    ProxyEffectDisposition,
    ProxyOutcome,
    _RuntimeModel,
    provider_canonical_json_bytes,
    provider_sha256_digest as sha256_digest,
)
from .intent import GenerationConfig
from .metadata import MetadataProvenance, ProviderObservedMetadata
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
        "MOONSHOT_API_KEY",
    ),
    OpenAICompatiblePreset.GLM: (
        "bigmodel",
        "https://open.bigmodel.cn/api/paas/v4",
        "BIGMODEL_API_KEY",
    ),
    OpenAICompatiblePreset.GROK: (
        "xai",
        "https://api.x.ai/v1",
        "XAI_API_KEY",
    ),
}
_ENVIRONMENT_VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class OpenAICompatibleEndpointConfig(_RuntimeModel):
    """One model endpoint and an indirection to its non-serialized credential."""

    endpoint_id: Identifier
    provider_id: Identifier
    base_url: NonEmptyStr
    model: ShortStr
    credential_ref: SecretRef
    credential_env_var: NonEmptyStr
    metadata_provenance: MetadataProvenance

    @model_validator(mode="after")
    def _safe_endpoint(self) -> Self:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "base URL must be an absolute URL without credentials, query, or fragment"
            )
        if parsed.scheme == "http" and parsed.hostname.casefold() not in _LOOPBACK_HOSTS:
            raise ValueError("unencrypted OpenAI-compatible endpoints must be loopback-only")
        if _ENVIRONMENT_VARIABLE.fullmatch(self.credential_env_var) is None:
            raise ValueError("credential environment variable must be an uppercase identifier")
        if (
            not self.metadata_provenance.exact
            or self.metadata_provenance.source_kind
            is MetadataSourceKind.CONSERVATIVE_LAB
        ):
            raise ValueError("endpoint metadata provenance must be an exact pinned source")
        return self


class OpenAICompatibleMessage(_RuntimeModel):
    role: Literal["system", "user", "assistant"]
    content: NonEmptyStr

    def as_wire(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


class OpenAICompatibleChatPayload(_RuntimeModel):
    """Prompt material that must be bound to a ``ProviderProxyRequest``."""

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
HttpOpener = Callable[..., object]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _open_pinned_endpoint(request: Request, *, timeout: int) -> object:
    """Do not let an endpoint redirect a bearer credential to another host."""

    return build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=timeout)


def openai_compatible_preset(
    preset: OpenAICompatiblePreset,
    *,
    endpoint_id: str,
    model: str,
    credential_ref: SecretRef,
    metadata_provenance: MetadataProvenance,
) -> OpenAICompatibleEndpointConfig:
    """Build a thin named preset while requiring an explicit exact model ID."""

    provider_id, base_url, credential_env_var = _PRESETS[OpenAICompatiblePreset(preset)]
    return OpenAICompatibleEndpointConfig(
        endpoint_id=endpoint_id,
        provider_id=provider_id,
        base_url=base_url,
        model=model,
        credential_ref=credential_ref,
        credential_env_var=credential_env_var,
        metadata_provenance=metadata_provenance,
    )


class OpenAICompatibleProviderProxy:
    """A stdlib HTTP implementation of the existing signed provider-proxy port."""

    plane = ProviderPlane.MODEL_PROVIDER

    def __init__(
        self,
        *,
        proxy_id: str,
        endpoints: Iterable[OpenAICompatibleEndpointConfig],
        prompt_resolver: PromptResolver,
        attestation_signer: AuthoritySigner,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: int = 30,
        opener: HttpOpener = _open_pinned_endpoint,
    ) -> None:
        if not isinstance(proxy_id, str) or not proxy_id:
            raise ValueError("OpenAI-compatible proxy requires an identifier")
        if not callable(prompt_resolver) or not callable(opener):
            raise TypeError("OpenAI-compatible proxy requires callable resolver and opener")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
            raise ValueError("OpenAI-compatible timeout must be 1 through 300 seconds")
        configs = tuple(
            OpenAICompatibleEndpointConfig.model_validate(item.model_dump(mode="python"))
            for item in endpoints
        )
        if not configs or len({config.endpoint_id for config in configs}) != len(configs):
            raise ValueError("OpenAI-compatible endpoint IDs must be non-empty and unique")
        self._proxy_id = proxy_id
        self._endpoints = {config.endpoint_id: config for config in configs}
        self._resolver = prompt_resolver
        self._signer = attestation_signer
        self._environment = os.environ if environment is None else environment
        self._timeout_seconds = timeout_seconds
        self._opener = opener
        self.contract_digest = sha256_digest(
            {
                "purpose": "faultloom.openai_compatible_provider_proxy.v1",
                "endpoints": tuple(config.model_dump(mode="json") for config in configs),
            }
        )
        self.attestation_public_key = attestation_signer.public_key_record

    @property
    def proxy_id(self) -> str:
        return self._proxy_id

    def dispatch(self, request: ProviderProxyRequest) -> ProviderProxyResult:
        request = ProviderProxyRequest.model_validate(request.model_dump(mode="python"))
        endpoint = self._endpoints.get(request.endpoint_id)
        if (
            endpoint is None
            or endpoint.provider_id != request.provider_id
            or endpoint.model != request.model_snapshot
            or endpoint.credential_ref != request.credential_ref
        ):
            return self._result(request, outcome=ProxyOutcome.DENIED)
        if request.tool_ids:
            # The existing port attests only tool IDs and a schema digest.  It
            # never receives the schema bytes required by Chat Completions.
            return self._result(request, outcome=ProxyOutcome.DENIED)
        credential = self._environment.get(endpoint.credential_env_var)
        if not isinstance(credential, str) or not credential:
            return self._result(request, outcome=ProxyOutcome.PRE_SEND_FAILED)
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
        body = self._request_body(endpoint.model, payload)
        raw_body = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        outbound = Request(
            endpoint.base_url.rstrip("/") + "/chat/completions",
            data=raw_body,
            headers={
                "Authorization": f"Bearer {credential}",
                "Content-Type": "application/json",
                "X-FaultLoom-Request-ID": request.request_id,
            },
            method="POST",
        )
        try:
            with self._opener(outbound, timeout=self._timeout_seconds) as response:
                raw_response = response.read()
                status = response.getcode()
        except HTTPError as exc:
            raw_response = exc.read()
            return self._result(
                request,
                outcome=ProxyOutcome.FAILED,
                effect=ProxyEffectDisposition.OBSERVED,
                status=exc.code,
                bytes_sent=len(raw_body),
                bytes_received=len(raw_response),
            )
        except (URLError, OSError, TimeoutError):
            return self._result(
                request,
                outcome=ProxyOutcome.UNKNOWN_OUTCOME,
                effect=ProxyEffectDisposition.POSSIBLE,
                bytes_sent=len(raw_body),
                reconciliation_required=True,
            )
        except Exception:
            return self._result(
                request,
                outcome=ProxyOutcome.UNKNOWN_OUTCOME,
                effect=ProxyEffectDisposition.POSSIBLE,
                bytes_sent=len(raw_body),
                reconciliation_required=True,
            )
        return self._completed_or_failed(
            request,
            endpoint,
            raw_response,
            status,
            bytes_sent=len(raw_body),
        )

    @staticmethod
    def _request_body(model: str, payload: OpenAICompatibleChatPayload) -> dict[str, object]:
        generation = payload.generation
        body: dict[str, object] = {
            "model": model,
            "messages": [message.as_wire() for message in payload.messages],
            "max_tokens": generation.max_output_tokens,
            "temperature": generation.temperature_milli / 1000,
            "top_p": generation.top_p_milli / 1000,
        }
        if generation.seed is not None:
            body["seed"] = generation.seed
        if generation.response_format == "json":
            body["response_format"] = {"type": "json_object"}
        return body

    def _completed_or_failed(
        self,
        request: ProviderProxyRequest,
        endpoint: OpenAICompatibleEndpointConfig,
        raw_response: bytes,
        status: int,
        *,
        bytes_sent: int,
    ) -> ProviderProxyResult:
        try:
            decoded = json.loads(raw_response)
            usage = decoded["usage"]
            response_model = decoded["model"]
            if (
                not isinstance(decoded, dict)
                or "error" in decoded
                or type(response_model) is not str
                or response_model != request.model_snapshot
                or type(decoded.get("choices")) is not list
                or not decoded["choices"]
                or type(usage) is not dict
                or type(usage.get("prompt_tokens")) is not int
                or type(usage.get("completion_tokens")) is not int
                or usage["prompt_tokens"] < 0
                or usage["completion_tokens"] < 0
            ):
                raise ValueError(
                    "provider response does not satisfy the configured Chat Completions contract"
                )
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return self._result(
                request,
                outcome=ProxyOutcome.FAILED,
                effect=ProxyEffectDisposition.OBSERVED,
                status=status,
                bytes_sent=bytes_sent,
                bytes_received=len(raw_response),
            )
        metadata = ProviderObservedMetadata(
            provider_id=endpoint.provider_id,
            actual_snapshot=response_model,
            runtime_version=request.runtime_version,
            tokenizer_id=request.tokenizer_id,
            tokenizer_version=request.tokenizer_version,
            context_window=request.context_window,
            snapshot_exact=True,
            runtime_exact=True,
            tokenizer_exact=True,
            context_window_exact=True,
            provenance=endpoint.metadata_provenance,
        )
        return self._result(
            request,
            outcome=ProxyOutcome.COMPLETED,
            effect=ProxyEffectDisposition.OBSERVED,
            status=status,
            bytes_sent=bytes_sent,
            bytes_received=len(raw_response),
            response_digest="sha256:" + hashlib.sha256(raw_response).hexdigest(),
            metadata=metadata,
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
            "accepted_output_schema_digest": request.output_schema_digest if completed else None,
            "accepted_config_digest": request.config_digest if completed else None,
            "accepted_policy_ref": request.policy_ref if completed else None,
            "accepted_data_policy_id": request.data_policy_id if completed else None,
            "accepted_data_consent_ref": request.data_consent_ref if completed else None,
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
