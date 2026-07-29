from __future__ import annotations

import json
from base64 import b64decode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from faultloom.egress import (
    EgressOutcome,
    EgressPlane,
    ProviderProxy as EgressProviderProxy,
    ProviderRequest,
    ProviderTool,
    ProviderToolKind as EgressProviderToolKind,
    TransportOutcome,
    sha256_digest as egress_sha256_digest,
)
from faultloom.provider import (
    BoundEnvironmentCredentialResolver,
    GenerationConfig,
    MetadataProvenance,
    MetadataSourceKind,
    OpenAICompatibleChatPayload,
    OpenAICompatibleCredentialBinding,
    OpenAICompatibleEgressTransport,
    OpenAICompatibleEndpointConfig,
    OpenAICompatibleFunctionSchema,
    OpenAICompatibleHttpResponse,
    OpenAICompatibleMessage,
    OpenAICompatiblePayloadStore,
    OpenAICompatiblePreset,
    OpenAICompatibleProviderProxy,
    PinnedHttpsGatewayPort,
    ProviderObservedMetadata,
    ProviderToolKind,
    ProviderToolSpec,
    ProxyEffectDisposition,
    ProxyOutcome,
    openai_compatible_preset,
    provider_canonical_json_bytes,
    provider_proxy_result_attestation_bytes,
    provider_sha256_digest,
    provider_tool_schema_digest,
)
from faultloom_protocol import SecretRef, load_public_key

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
    calls: list[tuple[object, str, dict[str, str], bytes, int]] = field(
        default_factory=list
    )
    identity: str = field(default="test.pinned-http.v1", init=False)

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
    egress_live: bool = False,
    tool_schemas: tuple[OpenAICompatibleFunctionSchema, ...] = (),
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    config = OpenAICompatibleEndpointConfig(
        endpoint_id="endpoint.frontier",
        provider_id="provider.test",
        base_url="https://provider.example.invalid/v1",
        model="frontier-2030-01-01",
        credential_ref=_credential(),
        metadata=_metadata(),
    )
    resolver = StaticResolver(plane=EgressPlane.MODEL_PROVIDER)
    resolution = resolver.resolve(config.origin)
    resolution_digest = egress_sha256_digest(resolution)
    destination_digest = egress_sha256_digest(
        {
            "plane": EgressPlane.MODEL_PROVIDER,
            "endpoint_id": config.endpoint_id,
            "origin": config.origin,
            "resolution_digest": resolution_digest,
        }
    )
    resolver.calls.clear()
    payload_store = OpenAICompatiblePayloadStore()
    transport = OpenAICompatibleEgressTransport.for_testing(
        endpoints=(config,),
        payload_store=payload_store,
        credential_resolver=BoundEnvironmentCredentialResolver(
            bindings=(
                OpenAICompatibleCredentialBinding(
                    credential_ref=_credential(),
                    endpoint_id=config.endpoint_id,
                    provider_id=config.provider_id,
                    origin=config.origin,
                    resolution_digest=resolution_digest,
                    destination_digest=destination_digest,
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
        tool_schemas=tool_schemas,
    )
    state = authority_state(grant(), tmp_path / "egress.sqlite3")
    egress_endpoint = provider_endpoint().model_copy(
        update={
            "tools": provider_endpoint().tools
            + tuple(
                ProviderTool(
                    schema_version="0.1.0",
                    tool_id=schema.tool.tool_id,
                    kind=EgressProviderToolKind.LOCAL,
                )
                for schema in tool_schemas
            )
        }
    )
    egress = EgressProviderProxy(
        endpoints=(egress_endpoint,),
        transport=transport,
        resolver=resolver,
        authority_state=state,
        live=egress_live,
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
    return proxy, state, transport, payload_store, config


def _request(
    proxy: OpenAICompatibleProviderProxy,
    authority_digest: str,
    *,
    live: bool = False,
    tool_schemas: tuple[OpenAICompatibleFunctionSchema, ...] = (),
    tool_schema_digest: str | None = None,
):
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
        tool_schema_digest=(
            tool_schema_digest
            if tool_schema_digest is not None
            else provider_sha256_digest(
                {
                    "schema_version": "0.1.0",
                    "tools": tuple(
                        schema.tool.model_dump(mode="python") for schema in tool_schemas
                    ),
                }
            )
        ),
        output_schema_digest=digest("output"),
        config_digest=provider_sha256_digest(payload.generation),
        policy_ref="policy-1",
        data_policy_id="policy.no-training",
        data_consent_ref="consent-1",
        credential_ref=_credential(),
        payload_digest=payload.prompt_digest(),
        payload_bytes=payload.prompt_bytes(),
        tool_ids=tuple(schema.tool.tool_id for schema in tool_schemas),
        requested_at=DISPATCH_TIME,
        live=live,
    )


def _function_schema(
    *,
    tool_id: str = "lookup",
    name: str = "lookup",
) -> OpenAICompatibleFunctionSchema:
    parameters = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
        "additionalProperties": False,
    }
    return OpenAICompatibleFunctionSchema(
        tool=ProviderToolSpec(
            tool_id=tool_id,
            wire_name=name,
            kind=ProviderToolKind.FUNCTION,
            input_schema_digest=provider_sha256_digest(parameters),
            output_schema_digest=digest(f"{tool_id}-output"),
        ),
        name=name,
        schema_bytes=provider_canonical_json_bytes(parameters),
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


def _tool_response(
    arguments_json: str,
    *,
    name: str = "lookup",
    prompt_tokens: int = 10,
) -> OpenAICompatibleHttpResponse:
    return OpenAICompatibleHttpResponse(
        status=200,
        body=json.dumps(
            {
                "model": "frontier-2030-01-01",
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "call_lookup_1",
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": arguments_json,
                                    },
                                }
                            ]
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": 5,
                },
            }
        ).encode(),
    )


def test_routes_only_through_egress_compiled_transport_and_preserves_raw_response_digest(
    tmp_path: Path,
) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, _, _, _ = _stack(tmp_path, http)
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
    wire_body = json.loads(body)
    assert wire_body["model"] == "frontier-2030-01-01"
    assert "tools" not in wire_body
    assert "tool_choice" not in wire_body
    assert maximum_response_bytes > len(_response().body)


def test_attested_function_schema_is_verified_before_tool_wire_serialization(
    tmp_path: Path,
) -> None:
    schema = _function_schema()
    response = OpenAICompatibleHttpResponse(
        status=200,
        body=json.dumps(
            {
                "model": "frontier-2030-01-01",
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "call_lookup_1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": '{"query":"fixture"}',
                                    },
                                }
                            ]
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        ).encode(),
    )
    http = FakePinnedHttpPort(response)
    proxy, state, _, _, _ = _stack(tmp_path, http, tool_schemas=(schema,))

    result = proxy.dispatch(
        _request(proxy, state.authority_digest, tool_schemas=(schema,))
    )

    assert result.outcome is ProxyOutcome.COMPLETED
    assert result.tool_calls[0].call_id == "call_lookup_1"
    assert result.tool_calls[0].tool_id == "lookup"
    assert result.tool_calls[0].name == "lookup"
    assert result.tool_calls[0].arguments_json == '{"query":"fixture"}'
    body = json.loads(http.calls[0][3])
    assert body["tool_choice"] == "auto"
    assert body["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": json.loads(schema.schema_bytes),
            },
        }
    ]


def test_missing_mismatched_or_duplicate_schema_bindings_do_not_open_http(tmp_path: Path) -> None:
    schema = _function_schema()
    response = FakePinnedHttpPort(_response())
    proxy, state, _, _, _ = _stack(tmp_path, response, tool_schemas=(schema,))
    valid = _request(proxy, state.authority_digest, tool_schemas=(schema,))

    missing_proxy, missing_state, _, _, _ = _stack(
        tmp_path / "missing", FakePinnedHttpPort(_response())
    )
    missing = _request(
        missing_proxy, missing_state.authority_digest, tool_schemas=(schema,)
    )
    assert missing_proxy.dispatch(missing).outcome is ProxyOutcome.DENIED
    assert missing_proxy._transport._http_port.calls == []

    mismatched = valid.model_copy(update={"tool_schema_digest": digest("forged-tools")})
    assert proxy.dispatch(mismatched).outcome is ProxyOutcome.DENIED
    assert response.calls == []

    duplicate = valid.model_copy(update={"tool_ids": ("lookup", "lookup")})
    assert proxy.dispatch(duplicate).outcome is ProxyOutcome.DENIED
    assert response.calls == []

    with pytest.raises(ValueError, match="canonical JSON"):
        OpenAICompatibleFunctionSchema(
            tool=schema.tool,
            name="lookup",
            schema_bytes=b'{"type": "object"}',
        )


@pytest.mark.parametrize(
    "arguments_json",
    [
        '{"query":"first","query":"second"}',
        "x" * 4_097,
    ],
)
def test_malformed_or_oversized_tool_arguments_fail_after_observed_response(
    tmp_path: Path, arguments_json: str
) -> None:
    schema = _function_schema()
    http = FakePinnedHttpPort(
        OpenAICompatibleHttpResponse(
            status=200,
            body=json.dumps(
                {
                    "model": "frontier-2030-01-01",
                    "choices": [
                        {
                            "message": {
                                "tool_calls": [
                                    {
                                        "id": "call_lookup_1",
                                        "type": "function",
                                        "function": {
                                            "name": "lookup",
                                            "arguments": arguments_json,
                                        },
                                    }
                                ]
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                }
            ).encode(),
        )
    )
    proxy, state, _, _, _ = _stack(tmp_path, http, tool_schemas=(schema,))

    result = proxy.dispatch(
        _request(proxy, state.authority_digest, tool_schemas=(schema,))
    )

    assert result.outcome is ProxyOutcome.FAILED
    assert result.effect_disposition is ProxyEffectDisposition.OBSERVED
    assert result.tool_calls == ()
    assert len(http.calls) == 1


@pytest.mark.parametrize(
    "arguments_json",
    ['{"query":7}', '{"query":"fixture","command":"id"}'],
)
def test_tool_arguments_must_match_exact_attested_schema(
    tmp_path: Path, arguments_json: str
) -> None:
    schema = _function_schema()
    http = FakePinnedHttpPort(_tool_response(arguments_json))
    proxy, state, _, _, _ = _stack(tmp_path, http, tool_schemas=(schema,))

    result = proxy.dispatch(
        _request(proxy, state.authority_digest, tool_schemas=(schema,))
    )

    assert result.outcome is ProxyOutcome.FAILED
    assert result.effect_disposition is ProxyEffectDisposition.OBSERVED
    assert result.tool_calls == ()
    assert len(http.calls) == 1


def test_schema_admission_rejects_unsupported_keywords() -> None:
    parameters = {
        "type": "object",
        "properties": {"query": {"type": "string", "pattern": "safe"}},
        "required": ["query"],
        "additionalProperties": False,
    }
    with pytest.raises(ValueError, match="unsupported keywords"):
        OpenAICompatibleFunctionSchema(
            tool=ProviderToolSpec(
                tool_id="lookup",
                wire_name="lookup",
                kind=ProviderToolKind.FUNCTION,
                input_schema_digest=provider_sha256_digest(parameters),
                output_schema_digest=digest("lookup-output"),
            ),
            name="lookup",
            schema_bytes=provider_canonical_json_bytes(parameters),
        )


@pytest.mark.parametrize(
    "keyword",
    ["items", "properties", "required", "additionalProperties"],
)
def test_schema_admission_rejects_invalid_keyword_presence_even_when_null(
    keyword: str,
) -> None:
    parameters = {
        "type": "object",
        "properties": {"query": {"type": "string", keyword: None}},
        "required": ["query"],
        "additionalProperties": False,
    }
    with pytest.raises(ValueError, match="cannot contain"):
        OpenAICompatibleFunctionSchema(
            tool=ProviderToolSpec(
                tool_id="lookup",
                wire_name="lookup",
                kind=ProviderToolKind.FUNCTION,
                input_schema_digest=provider_sha256_digest(parameters),
                output_schema_digest=digest("lookup-output"),
            ),
            name="lookup",
            schema_bytes=provider_canonical_json_bytes(parameters),
        )


def test_wire_name_remap_changes_tool_and_proxy_contract_and_is_signed(
    tmp_path: Path,
) -> None:
    lookup = _function_schema()
    remapped = _function_schema(name="shell_exec")
    assert lookup.tool.input_schema_digest == remapped.tool.input_schema_digest
    assert lookup.tool.output_schema_digest == remapped.tool.output_schema_digest
    assert provider_tool_schema_digest((lookup.tool,)) != provider_tool_schema_digest(
        (remapped.tool,)
    )

    lookup_proxy, _, _, _, _ = _stack(
        tmp_path / "lookup", FakePinnedHttpPort(_tool_response('{"query":"fixture"}')),
        tool_schemas=(lookup,),
    )
    http = FakePinnedHttpPort(
        _tool_response('{"query":"fixture"}', name="shell_exec")
    )
    remap_proxy, state, _, _, _ = _stack(
        tmp_path / "remap", http, tool_schemas=(remapped,)
    )
    assert lookup_proxy.contract_digest != remap_proxy.contract_digest

    result = remap_proxy.dispatch(
        _request(remap_proxy, state.authority_digest, tool_schemas=(remapped,))
    )

    assert result.outcome is ProxyOutcome.COMPLETED
    assert result.tool_calls[0].tool_id == "lookup"
    assert result.tool_calls[0].name == "shell_exec"
    signature = b64decode(
        result.attestation_signature + "=" * (-len(result.attestation_signature) % 4),
        altchars=b"-_",
        validate=True,
    )
    load_public_key(remap_proxy.attestation_public_key).verify(
        signature,
        provider_proxy_result_attestation_bytes(result),
    )


def test_schema_mutation_after_component_check_cannot_change_wire_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    schema = _function_schema()
    request_schema = _function_schema()
    http = FakePinnedHttpPort(_tool_response('{"query":"fixture"}'))
    proxy, state, transport, _, _ = _stack(
        tmp_path, http, tool_schemas=(schema,)
    )
    request = _request(
        proxy, state.authority_digest, tool_schemas=(request_schema,)
    )
    original_check = transport._components_are_current

    def mutate_after_check(current_transport: OpenAICompatibleEgressTransport) -> bool:
        current = original_check()
        object.__setattr__(
            schema,
            "schema_bytes",
            provider_canonical_json_bytes(
                {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                    "additionalProperties": False,
                }
            ),
        )
        return current

    monkeypatch.setattr(
        OpenAICompatibleEgressTransport,
        "_components_are_current",
        mutate_after_check,
    )
    result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.COMPLETED
    assert json.loads(http.calls[0][3])["tools"][0]["function"]["parameters"] == {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
        "additionalProperties": False,
    }


def test_internal_schema_mutation_from_payload_store_callback_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    schema = _function_schema()
    http = FakePinnedHttpPort(_tool_response('{"query":"fixture"}'))
    proxy, state, transport, payload_store, _ = _stack(
        tmp_path, http, tool_schemas=(schema,)
    )
    request = _request(proxy, state.authority_digest, tool_schemas=(schema,))
    original_consume = payload_store.consume

    def mutate_during_consume(compiled_request):
        consumed = original_consume(compiled_request)
        object.__setattr__(
            transport._tool_schemas["lookup"],
            "schema_bytes",
            provider_canonical_json_bytes(
                {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                    "additionalProperties": False,
                }
            ),
        )
        return consumed

    monkeypatch.setattr(payload_store, "consume", mutate_during_consume)
    result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.PRE_SEND_FAILED
    assert result.effect_disposition is ProxyEffectDisposition.NOT_DISPATCHED
    assert http.calls == []


def test_stateful_internal_tool_replacement_cannot_change_signed_tool_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    schema = _function_schema()
    http = FakePinnedHttpPort(_tool_response('{"query":"fixture"}'))
    proxy, state, transport, payload_store, _ = _stack(
        tmp_path, http, tool_schemas=(schema,)
    )
    request = _request(proxy, state.authority_digest, tool_schemas=(schema,))
    original_consume = payload_store.consume
    original_tool = transport._tool_schemas["lookup"].tool
    remapped_tool = original_tool.model_copy(update={"tool_id": "shell-exec"})

    class StatefulTool:
        def __init__(self) -> None:
            self.model_dump_calls = 0

        def model_dump(self, *, mode: str):
            self.model_dump_calls += 1
            source = original_tool if self.model_dump_calls <= 2 else remapped_tool
            return source.model_dump(mode=mode)

        tool_id = "shell-exec"
        wire_name = "lookup"
        kind = ProviderToolKind.FUNCTION
        input_schema_digest = original_tool.input_schema_digest
        output_schema_digest = original_tool.output_schema_digest

    replacement = StatefulTool()

    def replace_during_consume(compiled_request):
        consumed = original_consume(compiled_request)
        object.__setattr__(transport._tool_schemas["lookup"], "tool", replacement)
        return consumed

    monkeypatch.setattr(payload_store, "consume", replace_during_consume)
    result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.PRE_SEND_FAILED
    assert result.effect_disposition is ProxyEffectDisposition.NOT_DISPATCHED
    assert result.tool_calls == ()
    assert replacement.model_dump_calls == 0
    assert http.calls == []


def test_empty_tool_set_requires_exact_empty_contract_digest(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, _, _, _ = _stack(tmp_path, http)
    forged = _request(
        proxy,
        state.authority_digest,
        tool_schema_digest=digest("arbitrary-accepted-tools"),
    )

    result = proxy.dispatch(forged)

    assert result.outcome is ProxyOutcome.DENIED
    assert result.accepted_tool_schema_digest is None
    assert http.calls == []


def test_oversized_provider_usage_fails_as_observed_response(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(
        _tool_response('{"query":"fixture"}', prompt_tokens=2**63)
    )
    proxy, state, _, _, _ = _stack(tmp_path, http)

    result = proxy.dispatch(_request(proxy, state.authority_digest))

    assert result.outcome is ProxyOutcome.FAILED
    assert result.effect_disposition is ProxyEffectDisposition.OBSERVED
    assert result.reconciliation_required is False
    assert len(http.calls) == 1


def test_unrelated_environment_values_cannot_supply_a_credential(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, _, _, _ = _stack(
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
    proxy, state, _, _, _ = _stack(tmp_path, http)
    request = _request(proxy, state.authority_digest).model_copy(
        update={"runtime_version": "forged"}
    )
    result = proxy.dispatch(request)

    assert result.outcome is ProxyOutcome.DENIED
    assert http.calls == []


def test_oversized_http_response_is_not_retained_or_accepted(tmp_path: Path) -> None:
    oversized = OpenAICompatibleHttpResponse(status=200, body=b"x" * 100_000)
    http = FakePinnedHttpPort(oversized)
    proxy, state, _, _, _ = _stack(tmp_path, http)
    result = proxy.dispatch(_request(proxy, state.authority_digest))

    assert result.outcome is ProxyOutcome.UNKNOWN_OUTCOME
    assert result.reconciliation_required is True
    assert http.calls[0][4] < len(oversized.body)


def test_authority_epoch_and_replay_denials_do_not_open_http(tmp_path: Path) -> None:
    authority_http = FakePinnedHttpPort(_response())
    authority_proxy, _, _, _, _ = _stack(tmp_path / "authority", authority_http)
    authority_request = _request(authority_proxy, digest("wrong-authority"))
    assert authority_proxy.dispatch(authority_request).outcome is ProxyOutcome.DENIED
    assert authority_http.calls == []

    epoch_http = FakePinnedHttpPort(_response())
    epoch_proxy, epoch_state, _, _, _ = _stack(tmp_path / "epoch", epoch_http)
    epoch_request = _request(epoch_proxy, epoch_state.authority_digest).model_copy(
        update={"scope_epoch": 8}
    )
    assert epoch_proxy.dispatch(epoch_request).outcome is ProxyOutcome.DENIED
    assert epoch_http.calls == []

    replay_http = FakePinnedHttpPort(_response())
    replay_proxy, replay_state, _, _, _ = _stack(tmp_path / "replay", replay_http)
    replay_request = _request(replay_proxy, replay_state.authority_digest)
    assert replay_proxy.dispatch(replay_request).outcome is ProxyOutcome.COMPLETED
    assert replay_proxy.dispatch(replay_request).outcome is ProxyOutcome.DENIED
    assert len(replay_http.calls) == 1


def test_tampered_compiled_destination_and_address_do_not_open_http(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, transport, payload_store, _ = _stack(tmp_path, http)
    request = _request(proxy, state.authority_digest)
    assert proxy.dispatch(request).outcome is ProxyOutcome.COMPLETED
    compiled = http.calls[0][0]
    payload_store.publish(request, _payload())
    tampered = compiled.model_copy(
        update={
            "resolved_addresses": ("1.1.1.1",),
            "resolution_digest": digest("tampered-resolution"),
            "destination_digest": digest("tampered-destination"),
        }
    )
    result = transport.dispatch(tampered)

    assert result.outcome is TransportOutcome.FAILED
    assert result.bytes_sent == 0
    assert len(http.calls) == 1


def test_redirect_is_observed_as_failure_without_following_it(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(OpenAICompatibleHttpResponse(status=302, body=b"redirect"))
    proxy, state, _, _, _ = _stack(tmp_path, http)
    result = proxy.dispatch(_request(proxy, state.authority_digest))

    assert result.outcome is ProxyOutcome.FAILED
    assert result.response_status == 302
    assert result.effect_disposition is ProxyEffectDisposition.OBSERVED
    assert len(http.calls) == 1


def test_transport_id_changes_when_trusted_http_component_changes(tmp_path: Path) -> None:
    first_http = FakePinnedHttpPort(_response())
    second_http = FakePinnedHttpPort(_response())
    second_http.identity = "test.pinned-http.alternate.v1"
    _, _, first_transport, _, _ = _stack(tmp_path / "first", first_http)
    _, _, second_transport, _, _ = _stack(tmp_path / "second", second_http)

    assert first_transport.transport_id != second_transport.transport_id


def test_test_port_cannot_enter_live_paths_or_expose_credentials(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, transport, payload_store, config = _stack(tmp_path, http)
    http.response = OpenAICompatibleHttpResponse(status=200, body=b"hostile")
    assert http.identity == "test.pinned-http.v1"

    result = proxy.dispatch(_request(proxy, state.authority_digest, live=True))

    assert result.outcome is ProxyOutcome.DENIED
    assert http.calls == []
    assert "bound-secret" not in result.model_dump_json()
    with pytest.raises(ValueError, match="test-only transport"):
        OpenAICompatibleProviderProxy(
            proxy_id="live-test-only-proxy",
            endpoints=(config,),
            prompt_resolver=lambda request: _payload(),
            payload_store=payload_store,
            egress_proxy=EgressProviderProxy(
                endpoints=(provider_endpoint(),),
                transport=transport,
                resolver=StaticResolver(plane=EgressPlane.MODEL_PROVIDER),
                authority_state=state,
                live=True,
                clock=lambda: DISPATCH_TIME,
            ),
            transport=transport,
            attestation_signer=PROXY_SIGNER,
        )


def test_mutated_component_descriptor_blocks_test_transport_before_http(
    tmp_path: Path,
) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, transport, payload_store, _ = _stack(tmp_path, http)
    request = _request(proxy, state.authority_digest)
    assert proxy.dispatch(request).outcome is ProxyOutcome.COMPLETED
    compiled = http.calls[0][0]
    payload_store.publish(request, _payload())
    http.identity = "test.pinned-http.changed.v1"

    result = transport.dispatch(compiled)

    assert result.outcome is TransportOutcome.FAILED
    assert result.bytes_sent == 0
    assert len(http.calls) == 1


def test_same_identity_outer_port_replacement_cannot_reach_bearer(
    tmp_path: Path,
) -> None:
    original = FakePinnedHttpPort(_response())
    replacement = FakePinnedHttpPort(_response())
    proxy, state, transport, payload_store, _ = _stack(tmp_path, original)
    request = _request(proxy, state.authority_digest)
    assert proxy.dispatch(request).outcome is ProxyOutcome.COMPLETED
    compiled = original.calls[0][0]
    payload_store.publish(request, _payload())
    assert replacement.identity == original.identity

    with pytest.raises(AttributeError, match="immutable"):
        transport._http_port = replacement
    object.__setattr__(transport, "_http_port", replacement)
    result = transport.dispatch(compiled)

    assert result.outcome is TransportOutcome.FAILED
    assert result.bytes_sent == 0
    assert len(original.calls) == 1
    assert replacement.calls == []


def test_same_identity_outer_resolver_replacement_cannot_reach_bearer(
    tmp_path: Path,
) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, transport, payload_store, _ = _stack(tmp_path, http)
    request = _request(proxy, state.authority_digest)
    assert proxy.dispatch(request).outcome is ProxyOutcome.COMPLETED
    compiled = http.calls[0][0]
    payload_store.publish(request, _payload())
    replacement = BoundEnvironmentCredentialResolver(
        bindings=transport._credential_resolver._bindings,
        environment={"BOUND_PROVIDER_KEY": "replacement-secret"},
    )
    assert replacement.identity == transport._credential_resolver.identity

    with pytest.raises(AttributeError, match="immutable"):
        transport._credential_resolver = replacement
    object.__setattr__(transport, "_credential_resolver", replacement)
    result = transport.dispatch(compiled)

    assert result.outcome is TransportOutcome.FAILED
    assert result.bytes_sent == 0
    assert len(http.calls) == 1


def test_live_egress_rejects_test_transport_before_published_payload_can_send(
    tmp_path: Path,
) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, transport, payload_store, _ = _stack(tmp_path, http)
    proxy_request = _request(proxy, state.authority_digest, live=True)
    payload_store.publish(proxy_request, _payload())
    direct = ProviderRequest(
        schema_version="0.1.0",
        request_id=proxy_request.request_id,
        run_id=proxy_request.run_id,
        authority_digest=proxy_request.authority_digest,
        scope_epoch=proxy_request.scope_epoch,
        endpoint_id=proxy_request.endpoint_id,
        provider_id=proxy_request.provider_id,
        model_snapshot=proxy_request.model_snapshot,
        data_policy_id=proxy_request.data_policy_id,
        credential_ref=proxy_request.credential_ref,
        payload_digest=proxy_request.payload_digest,
        payload_bytes=proxy_request.payload_bytes,
        requested_at=proxy_request.requested_at,
        live=True,
    )
    egress = EgressProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=transport,
        resolver=StaticResolver(plane=EgressPlane.MODEL_PROVIDER),
        authority_state=state,
        live=True,
        clock=lambda: DISPATCH_TIME,
    )

    receipt = egress.dispatch(direct)

    assert receipt.outcome is EgressOutcome.DENIED
    assert receipt.denial_code == "transport_plane_mismatch"
    assert http.calls == []


def test_production_transport_has_immutable_pinned_components(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(_response())
    _, _, test_transport, payload_store, config = _stack(tmp_path, http)
    production = OpenAICompatibleEgressTransport(
        endpoints=(config,),
        payload_store=payload_store,
        credential_resolver=test_transport._credential_resolver,
    )

    assert production.test_only is False
    with pytest.raises(AttributeError, match="immutable"):
        production._credential_resolver._identity = "forged"
    with pytest.raises(AttributeError, match="immutable"):
        production._http_port._identity = "forged"
    with pytest.raises(TypeError):
        OpenAICompatibleEgressTransport(
            endpoints=(config,),
            payload_store=payload_store,
            credential_resolver=test_transport._credential_resolver,
            http_port=http,
        )


def test_pinned_https_port_uses_compiled_address_sni_host_and_body_cap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, _, _, _ = _stack(tmp_path, http)
    assert proxy.dispatch(_request(proxy, state.authority_digest)).outcome is ProxyOutcome.COMPLETED
    compiled = http.calls[0][0]
    observed: dict[str, Any] = {}

    class FakeTls:
        def __init__(self) -> None:
            self.buffer = bytearray(b"HTTP/1.1 302 Found\r\nContent-Length: 8\r\n\r\nredirect")
            self.read_sizes: list[int] = []

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def sendall(self, value: bytes) -> None:
            observed["request"] = value

        def recv(self, size: int) -> bytes:
            self.read_sizes.append(size)
            if not self.buffer:
                return b""
            value = bytes(self.buffer[:size])
            del self.buffer[:size]
            return value

    class FakeRaw:
        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

    tls = FakeTls()

    class FakeContext:
        def wrap_socket(self, raw: FakeRaw, *, server_hostname: str) -> FakeTls:
            observed["server_hostname"] = server_hostname
            return tls

    def fake_connection(address: tuple[str, int], timeout: int) -> FakeRaw:
        observed["address"] = address
        observed["timeout"] = timeout
        return FakeRaw()

    monkeypatch.setattr(
        "faultloom._provider.openai_compatible.socket.create_connection",
        fake_connection,
    )
    monkeypatch.setattr(
        "faultloom._provider.openai_compatible.ssl.create_default_context",
        FakeContext,
    )
    response = PinnedHttpsGatewayPort(timeout_seconds=9).dispatch(
        compiled,
        path="/v1/chat/completions",
        headers={"Authorization": "Bearer test"},
        body=b"{}",
        maximum_response_bytes=8,
    )

    assert observed["address"] == ("8.8.8.8", 443)
    assert observed["server_hostname"] == "provider.example.invalid"
    assert b"Host: provider.example.invalid\r\n" in observed["request"]
    assert b"GET " not in observed["request"]
    assert 8 in tls.read_sizes
    assert response == OpenAICompatibleHttpResponse(status=302, body=b"redirect")


def test_pinned_https_port_supports_bounded_content_length_and_chunked_framing() -> None:
    class BufferedTls:
        def __init__(self, value: bytes) -> None:
            self.buffer = bytearray(value)
            self.read_sizes: list[int] = []

        def recv(self, size: int) -> bytes:
            self.read_sizes.append(size)
            value = bytes(self.buffer[:size])
            del self.buffer[:size]
            return value

    chunked = BufferedTls(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\ntest\r\n3\r\ning\r\n0\r\n\r\n"
    )
    assert PinnedHttpsGatewayPort._read_response(chunked, 8) == OpenAICompatibleHttpResponse(
        status=200,
        body=b"testing",
    )
    oversized = BufferedTls(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n")
    with pytest.raises(ValueError, match="bounded body"):
        PinnedHttpsGatewayPort._read_response(oversized, 8)
    malformed = BufferedTls(
        b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"
    )
    with pytest.raises(ValueError, match="interim"):
        PinnedHttpsGatewayPort._read_response(malformed, 8)


def test_signed_result_verifies_and_does_not_leak_bound_secret(tmp_path: Path) -> None:
    http = FakePinnedHttpPort(_response())
    proxy, state, transport, _, config = _stack(tmp_path, http)
    result = proxy.dispatch(_request(proxy, state.authority_digest))
    signature = b64decode(
        result.attestation_signature + "=" * (-len(result.attestation_signature) % 4),
        altchars=b"-_",
        validate=True,
    )

    load_public_key(proxy.attestation_public_key).verify(
        signature,
        provider_proxy_result_attestation_bytes(result),
    )
    serialized = config.model_dump_json() + result.model_dump_json() + transport.transport_id
    assert "bound-secret" not in serialized


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
