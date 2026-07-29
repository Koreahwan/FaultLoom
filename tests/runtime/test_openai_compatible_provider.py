from __future__ import annotations

import base64
import hashlib
import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Iterator

from faultloom.provider import (
    GenerationConfig,
    OpenAICompatibleChatPayload,
    OpenAICompatibleEndpointConfig,
    OpenAICompatibleMessage,
    OpenAICompatiblePreset,
    OpenAICompatibleProviderProxy,
    ProviderAdapter,
    ProviderCallOutcome,
    ProviderProxyRequest,
    ProxyEffectDisposition,
    ProxyOutcome,
    openai_compatible_preset,
    provider_proxy_result_attestation_bytes,
    provider_sha256_digest,
)
from faultloom_protocol import SecretRef, load_public_key

from tests.runtime.provider_test_models import (
    PROXY_SIGNER,
    call_intent,
    digest,
    profile,
    provenance,
)
from tests.runtime.provider_test_runtime import StepClock, StepMonotonic
from faultloom.provider import MemoryProviderReceiptJournal


class _RecordingServer(ThreadingHTTPServer):
    response_status: int = 200
    response_body: bytes = b"{}"
    received: list[tuple[str, dict[str, str], bytes]]

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _RecordingHandler)
        self.received = []


class _RecordingHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.received.append(  # type: ignore[attr-defined]
            (self.path, dict(self.headers), body)
        )
        self.send_response(self.server.response_status)  # type: ignore[attr-defined]
        self.send_header("Content-Type", "application/json")
        self.send_header(  # type: ignore[attr-defined]
            "Content-Length", str(len(self.server.response_body))
        )
        self.end_headers()
        self.wfile.write(self.server.response_body)  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def _server(status: int, response: dict[str, object]) -> Iterator[_RecordingServer]:
    server = _RecordingServer()
    server.response_status = status
    server.response_body = json.dumps(response, separators=(",", ":")).encode()
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def _credential_ref() -> SecretRef:
    return SecretRef(
        schema_version="0.1.0",
        uri="secret://engagement/openai-compatible-key",
        purpose="provider.credential",
    )


def _payload() -> OpenAICompatibleChatPayload:
    return OpenAICompatibleChatPayload(
        messages=(OpenAICompatibleMessage(role="user", content="summarize fixture"),),
        generation=GenerationConfig(
            max_output_tokens=50,
            temperature_milli=0,
            top_p_milli=1000,
            seed=42,
            response_format="json",
        ),
    )


def _proxy(
    server: _RecordingServer,
    payload: OpenAICompatibleChatPayload,
    *,
    environment: dict[str, str] | None = None,
) -> OpenAICompatibleProviderProxy:
    config = OpenAICompatibleEndpointConfig(
        endpoint_id="endpoint-primary",
        provider_id="local-provider",
        base_url=f"http://127.0.0.1:{server.server_port}/v1",
        model="exact-local-model",
        credential_ref=_credential_ref(),
        credential_env_var="OPENAI_COMPATIBLE_TEST_KEY",
        metadata_provenance=provenance(),
    )
    return OpenAICompatibleProviderProxy(
        proxy_id="openai-compatible-proxy",
        endpoints=(config,),
        prompt_resolver=lambda request: payload,
        attestation_signer=PROXY_SIGNER,
        environment=(
            {"OPENAI_COMPATIBLE_TEST_KEY": "test-secret-only"}
            if environment is None
            else environment
        ),
    )


def _request(
    proxy: OpenAICompatibleProviderProxy,
    payload: OpenAICompatibleChatPayload,
) -> ProviderProxyRequest:
    return ProviderProxyRequest(
        proxy_id=proxy.proxy_id,
        proxy_contract_digest=proxy.contract_digest,
        proxy_attestation_key_id=proxy.attestation_public_key.key_id,
        dispatch_reservation_digest=digest("reservation"),
        request_id="attempt-1",
        run_id="run-1",
        authority_digest=digest("authority"),
        scope_epoch=1,
        endpoint_id="endpoint-primary",
        provider_id="local-provider",
        requested_alias="local",
        model_snapshot="exact-local-model",
        runtime_version="runtime-1",
        tokenizer_id="tokenizer-1",
        tokenizer_version="v1",
        context_window=8192,
        prompt_digest=payload.prompt_digest(),
        compiled_context_digest=digest("context"),
        tool_schema_digest=digest("tools"),
        output_schema_digest=digest("output"),
        config_digest=provider_sha256_digest(payload.generation),
        policy_ref="policy-1",
        data_policy_id="data-1",
        data_consent_ref="consent-1",
        credential_ref=_credential_ref(),
        payload_digest=payload.prompt_digest(),
        payload_bytes=payload.prompt_bytes(),
        requested_at=call_intent().requested_at,
        live=False,
    )


def test_loopback_chat_completion_binds_authorization_usage_and_raw_tool_reasoning_response(
) -> None:
    payload = _payload()
    response = {
        "id": "chatcmpl-local",
        "model": "exact-local-model",
        "choices": [
            {
                "message": {
                    "tool_calls": [{"id": "tool-1"}],
                    "reasoning_content": "internal",
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    with _server(200, response) as server:
        proxy = _proxy(server, payload)
        result = proxy.dispatch(_request(proxy, payload))

    assert result.outcome is ProxyOutcome.COMPLETED
    assert result.effect_disposition is ProxyEffectDisposition.OBSERVED
    assert result.usage is not None
    assert result.usage.input_tokens == 10
    assert result.usage.output_tokens == 5
    assert result.response_digest == "sha256:" + hashlib.sha256(server.response_body).hexdigest()
    load_public_key(PROXY_SIGNER.public_key_record).verify(
        base64.urlsafe_b64decode(result.attestation_signature + "=="),
        provider_proxy_result_attestation_bytes(result),
    )
    path, headers, raw_body = server.received[0]
    assert path == "/v1/chat/completions"
    assert headers["Authorization"] == "Bearer test-secret-only"
    assert headers["X-Faultloom-Request-Id"] == "attempt-1"
    assert json.loads(raw_body) == {
        "model": "exact-local-model",
        "messages": [{"role": "user", "content": "summarize fixture"}],
        "max_tokens": 50,
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 42,
        "response_format": {"type": "json_object"},
    }


def test_http_provider_error_is_attested_as_observed_failed_dispatch() -> None:
    payload = _payload()
    with _server(429, {"error": {"message": "rate limited"}}) as server:
        proxy = _proxy(server, payload)
        result = proxy.dispatch(_request(proxy, payload))

    assert result.outcome is ProxyOutcome.FAILED
    assert result.effect_disposition is ProxyEffectDisposition.OBSERVED
    assert result.response_status == 429
    assert result.bytes_sent > 0
    assert result.bytes_received == len(server.response_body)


def test_missing_environment_credential_fails_before_any_loopback_request() -> None:
    payload = _payload()
    response = {
        "model": "exact-local-model",
        "choices": [{"message": {"content": "unused"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    with _server(200, response) as server:
        proxy = _proxy(server, payload, environment={})
        result = proxy.dispatch(_request(proxy, payload))

    assert result.outcome is ProxyOutcome.PRE_SEND_FAILED
    assert result.effect_disposition is ProxyEffectDisposition.NOT_DISPATCHED
    assert server.received == []


def test_tool_ids_are_denied_without_attested_tool_schema_bytes() -> None:
    payload = _payload()
    response = {
        "model": "exact-local-model",
        "choices": [{"message": {"content": "unused"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    with _server(200, response) as server:
        proxy = _proxy(server, payload)
        request = _request(proxy, payload).model_copy(update={"tool_ids": ("tool-1",)})
        result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.DENIED
    assert result.effect_disposition is ProxyEffectDisposition.NOT_DISPATCHED
    assert server.received == []


def test_model_substitution_is_denied_before_dispatch() -> None:
    payload = _payload()
    response = {
        "model": "exact-local-model",
        "choices": [{"message": {"content": "unused"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    with _server(200, response) as server:
        proxy = _proxy(server, payload)
        request = _request(proxy, payload).model_copy(
            update={"model_snapshot": "unapproved-model-swap"}
        )
        result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.DENIED
    assert result.effect_disposition is ProxyEffectDisposition.NOT_DISPATCHED
    assert server.received == []


def test_adapter_accepts_a_completed_local_openai_compatible_result() -> None:
    payload = _payload()
    response = {
        "model": "exact-local-model",
        "choices": [{"message": {"content": "fixture"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    with _server(200, response) as server:
        proxy = _proxy(server, payload)
        model = profile(
            provider_id="local-provider",
            snapshot="exact-local-model",
            alias="local",
        )
        intent = call_intent(
            input_tokens=10,
            prompt_bytes=payload.prompt_bytes(),
            max_output_tokens=50,
        ).model_copy(
            update={
                "prompt_digest": payload.prompt_digest(),
                "credential_ref": _credential_ref(),
            }
        )
        adapter = ProviderAdapter(
            profiles=(model,),
            proxy=proxy,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=MemoryProviderReceiptJournal(),
            live=False,
            clock=StepClock(),
            monotonic_clock=StepMonotonic(),
        )
        receipt = adapter.call(intent)

    assert receipt.outcome is ProviderCallOutcome.COMPLETED
    assert receipt.response_digest == "sha256:" + hashlib.sha256(server.response_body).hexdigest()


def test_presets_are_endpoint_only_and_never_select_a_model_or_secret() -> None:
    for preset, base_url, environment_name in (
        (OpenAICompatiblePreset.KIMI, "https://api.moonshot.ai/v1", "MOONSHOT_API_KEY"),
        (OpenAICompatiblePreset.GLM, "https://open.bigmodel.cn/api/paas/v4", "BIGMODEL_API_KEY"),
        (OpenAICompatiblePreset.GROK, "https://api.x.ai/v1", "XAI_API_KEY"),
    ):
        config = openai_compatible_preset(
            preset,
            endpoint_id=f"endpoint-{preset.value}",
            model="operator-pinned-model-id",
            credential_ref=_credential_ref(),
            metadata_provenance=provenance(),
        )
        serialized = config.model_dump(mode="json")
        assert config.base_url == base_url
        assert config.credential_env_var == environment_name
        assert config.model == "operator-pinned-model-id"
        assert "test-secret-only" not in json.dumps(serialized)


def test_unknown_future_provider_uses_generic_config_without_a_preset_or_source_change() -> None:
    payload = _payload()
    response = {
        "model": "future-model-42",
        "choices": [{"message": {"content": "fixture"}}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
    }
    with _server(200, response) as server:
        config = OpenAICompatibleEndpointConfig(
            endpoint_id="future-endpoint",
            provider_id="future-provider",
            base_url=f"http://127.0.0.1:{server.server_port}/api/openai/v99",
            model="future-model-42",
            credential_ref=_credential_ref(),
            credential_env_var="FUTURE_PROVIDER_TOKEN",
            metadata_provenance=provenance(),
        )
        proxy = OpenAICompatibleProviderProxy(
            proxy_id="future-provider-proxy",
            endpoints=(config,),
            prompt_resolver=lambda request: payload,
            attestation_signer=PROXY_SIGNER,
            environment={"FUTURE_PROVIDER_TOKEN": "future-secret-only"},
        )
        request = _request(proxy, payload).model_copy(
            update={
                "endpoint_id": "future-endpoint",
                "provider_id": "future-provider",
                "model_snapshot": "future-model-42",
            }
        )
        result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.COMPLETED
    assert server.received[0][0] == "/api/openai/v99/chat/completions"
    assert json.loads(server.received[0][2])["model"] == "future-model-42"
