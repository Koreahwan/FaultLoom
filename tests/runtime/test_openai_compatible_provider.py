from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from faultloom.egress import EgressPlane, ProviderProxy as EgressProviderProxy
from faultloom.provider import (
    BoundEnvironmentCredentialResolver,
    GenerationConfig,
    MetadataProvenance,
    MetadataSourceKind,
    OpenAICompatibleChatPayload,
    OpenAICompatibleCredentialBinding,
    OpenAICompatibleEgressTransport,
    OpenAICompatibleEndpointConfig,
    OpenAICompatibleHttpResponse,
    OpenAICompatibleMessage,
    OpenAICompatiblePayloadStore,
    OpenAICompatiblePreset,
    OpenAICompatibleProviderProxy,
    ProviderObservedMetadata,
    ProxyEffectDisposition,
    ProxyOutcome,
    openai_compatible_preset,
    provider_sha256_digest,
)
from faultloom_protocol import SecretRef

from tests.runtime.provider_test_models import PROXY_SIGNER, digest
from tests.runtime.test_egress import (
    DISPATCH_TIME,
    StaticResolver,
    authority_state,
    grant,
    provider_endpoint,
)


@dataclass
class FakePinnedHttpPort:
    response: OpenAICompatibleHttpResponse
    calls: list[tuple[object, str, dict[str, str], bytes, int]] = field(default_factory=list)

    def dispatch(
        self,
        request: object,
        *,
        path: str,
        headers: dict[str, str],
        body: bytes,
        maximum_response_bytes: int,
    ) -> OpenAICompatibleHttpResponse:
        self.calls.append((request, path, headers, body, maximum_response_bytes))
        return self.response


def _credential() -> SecretRef:
    return SecretRef(
        schema_version="0.1.0",
        uri="secret://engagement/provider-test",
        purpose="model-provider:provider.test",
    )


def _metadata(
    provider_id: str = "provider.test",
    model: str = "frontier-2030-01-01",
) -> ProviderObservedMetadata:
    return ProviderObservedMetadata(
        schema_version="0.1.0",
        provider_id=provider_id,
        actual_snapshot=model,
        runtime_version="runtime-1",
        tokenizer_id="tokenizer-1",
        tokenizer_version="v1",
        context_window=8192,
        snapshot_exact=True,
        runtime_exact=True,
        tokenizer_exact=True,
        context_window_exact=True,
        provenance=MetadataProvenance(
            schema_version="0.1.0",
            source_kind=MetadataSourceKind.PINNED_REGISTRY,
            source_id="provider-metadata-registry",
            evidence_digest=digest("provider-metadata"),
            observed_at=DISPATCH_TIME,
            exact=True,
        ),
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


def _stack(
    tmp_path: Path,
    http_port: FakePinnedHttpPort,
    *,
    environment: dict[str, str] | None = None,
):
    config = OpenAICompatibleEndpointConfig(
        endpoint_id="endpoint.frontier",
        provider_id="provider.test",
        base_url="https://provider.example.invalid/v1",
        model="frontier-2030-01-01",
        credential_ref=_credential(),
        metadata=_metadata(),
    )
    payload_store = OpenAICompatiblePayloadStore()
    transport = OpenAICompatibleEgressTransport(
        endpoints=(config,),
        payload_store=payload_store,
        credential_resolver=BoundEnvironmentCredentialResolver(
            bindings=(
                OpenAICompatibleCredentialBinding(
                    credential_ref=_credential(),
                    endpoint_id=config.endpoint_id,
                    provider_id=config.provider_id,
                    origin=config.origin,
                    environment_variable="BOUND_PROVIDER_KEY",
                ),
            ),
            environment=(
                environment
                if environment is not None
                else {"BOUND_PROVIDER_KEY": "bound-secret"}
            ),
        ),
        http_port=http_port,
    )
    state = authority_state(grant(), tmp_path / "egress.sqlite3")
    egress = EgressProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=transport,
        resolver=StaticResolver(plane=EgressPlane.MODEL_PROVIDER),
        authority_state=state,
        live=True,
        clock=lambda: DISPATCH_TIME,
    )
    proxy = OpenAICompatibleProviderProxy(
        proxy_id="openai-compatible-proxy",
        endpoints=(config,),
        prompt_resolver=lambda request: _payload(),
        payload_store=payload_store,
        egress_proxy=egress,
        transport=transport,
        attestation_signer=PROXY_SIGNER,
    )
    return proxy, state


def _request(proxy: OpenAICompatibleProviderProxy, authority_digest: str):
    payload = _payload()
    from faultloom.provider import ProviderProxyRequest

    return ProviderProxyRequest(
        proxy_id=proxy.proxy_id,
        proxy_contract_digest=proxy.contract_digest,
        proxy_attestation_key_id=proxy.attestation_public_key.key_id,
        dispatch_reservation_digest=digest("reservation"),
        request_id="provider-request.1",
        run_id="run.1",
        authority_digest=authority_digest,
        scope_epoch=7,
        endpoint_id="endpoint.frontier",
        provider_id="provider.test",
        requested_alias="frontier",
        model_snapshot="frontier-2030-01-01",
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
        data_policy_id="policy.no-training",
        data_consent_ref="consent-1",
        credential_ref=_credential(),
        payload_digest=payload.prompt_digest(),
        payload_bytes=payload.prompt_bytes(),
        requested_at=DISPATCH_TIME,
        live=True,
    )


def _response() -> OpenAICompatibleHttpResponse:
    return OpenAICompatibleHttpResponse(
        status=200,
        body=json.dumps(
            {
                "model": "frontier-2030-01-01",
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
        ).encode(),
    )


def test_routes_only_through_egress_compiled_transport_and_preserves_raw_response_digest(
    tmp_path: Path,
) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state = _stack(tmp_path, http)
    result = proxy.dispatch(_request(proxy, state.authority_digest))

    assert result.outcome is ProxyOutcome.COMPLETED
    assert result.effect_disposition is ProxyEffectDisposition.OBSERVED
    assert result.response_digest == (
        "sha256:" + __import__("hashlib").sha256(_response().body).hexdigest()
    )
    compiled, path, headers, body, maximum_response_bytes = http.calls[0]
    assert compiled.origin == "https://provider.example.invalid"
    assert compiled.resolved_addresses == ("8.8.8.8",)
    assert compiled.follow_redirects is False
    assert path == "/v1/chat/completions"
    assert headers["Authorization"] == "Bearer bound-secret"
    assert json.loads(body)["model"] == "frontier-2030-01-01"
    assert maximum_response_bytes > len(_response().body)


def test_unrelated_environment_values_cannot_supply_a_credential(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state = _stack(
        tmp_path,
        http,
        environment={"UNRELATED_PROVIDER_KEY": "not-usable"},
    )
    result = proxy.dispatch(_request(proxy, state.authority_digest))

    assert result.outcome is ProxyOutcome.PRE_SEND_FAILED
    assert result.effect_disposition is ProxyEffectDisposition.NOT_DISPATCHED
    assert http.calls == []


def test_request_metadata_cannot_be_promoted_over_independent_endpoint_metadata(
    tmp_path: Path,
) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state = _stack(tmp_path, http)
    request = _request(proxy, state.authority_digest).model_copy(
        update={"runtime_version": "forged"}
    )
    result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.DENIED
    assert http.calls == []


def test_oversized_http_response_is_not_retained_or_accepted(tmp_path: Path) -> None:
    oversized = OpenAICompatibleHttpResponse(status=200, body=b"x" * 100_000)
    http = FakePinnedHttpPort(oversized)
    proxy, state = _stack(tmp_path, http)
    result = proxy.dispatch(_request(proxy, state.authority_digest))

    assert result.outcome is ProxyOutcome.UNKNOWN_OUTCOME
    assert result.reconciliation_required is True
    assert http.calls[0][4] < len(oversized.body)


def test_presets_and_unknown_provider_config_remain_thin_and_path_configurable() -> None:
    for preset, provider_id, base_url in (
        (OpenAICompatiblePreset.KIMI, "moonshot", "https://api.moonshot.ai/v1"),
        (OpenAICompatiblePreset.GLM, "bigmodel", "https://open.bigmodel.cn/api/paas/v4"),
        (OpenAICompatiblePreset.GROK, "xai", "https://api.x.ai/v1"),
    ):
        config = openai_compatible_preset(
            preset,
            endpoint_id=f"endpoint-{preset.value}",
            model="operator-pinned-model",
            credential_ref=_credential(),
            metadata=_metadata(provider_id, "operator-pinned-model"),
        )
        assert config.provider_id == provider_id
        assert config.base_url == base_url
    future = OpenAICompatibleEndpointConfig(
        endpoint_id="future-endpoint",
        provider_id="future-provider",
        base_url="https://future.example.invalid/api/v99",
        model="future-model",
        credential_ref=_credential(),
        metadata=_metadata("future-provider", "future-model"),
        chat_completions_path="/custom/chat",
    )
    assert future.api_path == "/api/v99/custom/chat"
