from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from faultloom.egress_wire import WireValue
from faultloom.automation.models import ModelTurn
from faultloom.automation.provider_contract import (
    MODEL_TURN_TOOL_ID,
    MODEL_TURN_WIRE_NAME,
    model_turn_function_schema,
    model_turn_function_schema_bytes,
    model_turn_openai_function_schema,
    model_turn_provider_output_schema,
    model_turn_provider_tool_spec,
)
from faultloom.provider import (
    OpenAICompatibleHttpResponse,
    ProxyOutcome,
    provider_canonical_json_bytes,
    provider_sha256_digest,
)
from tests.runtime.test_openai_compatible_provider import (
    FakePinnedHttpPort,
    _request,
    _stack,
)


def _model_turn_document(*, extra_property: bool = False) -> dict[str, object]:
    document: dict[str, object] = {
        "hypotheses": [
            {
                "proposal_id": "hypothesis.1",
                "statement": "A bounded candidate needs replay.",
                "provenance": ["behavior"],
                "supporting_evidence_ids": ["evidence.1"],
                "contradicting_evidence_ids": [],
                "prerequisite_ids": [],
            }
        ],
        "negative_results": [],
        "actions": [],
        "stop_reason": "Await independent verification.",
    }
    if extra_property:
        document["unexpected"] = True
    return document


def _tool_response(arguments: str) -> OpenAICompatibleHttpResponse:
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
                                    "id": "call_model_turn_1",
                                    "type": "function",
                                    "function": {
                                        "name": MODEL_TURN_WIRE_NAME,
                                        "arguments": arguments,
                                    },
                                }
                            ]
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        ).encode("utf-8"),
    )


def _schema_node_count(node: dict[str, WireValue]) -> int:
    if node["type"] == "object":
        assert node["additionalProperties"] is False
        assert type(node["properties"]) is dict
        assert type(node["required"]) is list
        return 1 + sum(
            _schema_node_count(child)
            for child in cast(dict[str, WireValue], node["properties"]).values()
            if type(child) is dict
        )
    if node["type"] == "array":
        assert type(node["items"]) is dict
        return 1 + _schema_node_count(cast(dict[str, WireValue], node["items"]))
    return 1


def test_model_turn_function_contract_is_canonical_and_admitted() -> None:
    schema = model_turn_function_schema()
    schema_bytes = model_turn_function_schema_bytes()
    tool = model_turn_provider_tool_spec()
    admitted = model_turn_openai_function_schema()

    assert schema_bytes == provider_canonical_json_bytes(schema)
    assert schema_bytes == model_turn_function_schema_bytes()
    assert len(schema_bytes) < 16_384
    assert _schema_node_count(schema) <= 256
    assert tool.input_schema_digest == (
        "sha256:b8856f6a4e8edfb1153a0aaaa167ff1415fc917fd0f87f0bcaf5aa3b4af174cd"
    )
    assert tool.output_schema_digest == (
        "sha256:d746974fa9afd5e951f76f9af38954b0ad7f436f2120dc974da65e5ee39f856f"
    )
    assert tool.tool_id == MODEL_TURN_TOOL_ID
    assert tool.wire_name == MODEL_TURN_WIRE_NAME
    assert tool.input_schema_digest == provider_sha256_digest(schema)
    assert tool.output_schema_digest == provider_sha256_digest(
        model_turn_provider_output_schema()
    )
    assert admitted.tool == tool
    assert admitted.name == MODEL_TURN_WIRE_NAME
    assert admitted.schema_bytes == schema_bytes


def test_test_provider_proxy_accepts_valid_model_turn_without_optional_fields(
    tmp_path: Path,
) -> None:
    arguments = json.dumps(_model_turn_document(), separators=(",", ":"))
    assert ModelTurn.model_validate_json(arguments).poc is None
    assert ModelTurn.model_validate_json(arguments).finding_draft is None
    schema = model_turn_openai_function_schema()
    http = FakePinnedHttpPort(_tool_response(arguments))
    proxy, state, _, _, _ = _stack(tmp_path, http, tool_schemas=(schema,))

    result = proxy.dispatch(
        _request(proxy, state.authority_digest, tool_schemas=(schema,))
    )

    assert result.outcome is ProxyOutcome.COMPLETED
    assert result.tool_calls[0].tool_id == MODEL_TURN_TOOL_ID
    assert result.tool_calls[0].name == MODEL_TURN_WIRE_NAME
    assert result.tool_calls[0].arguments_json == arguments
    assert len(http.calls) == 1


def test_test_provider_proxy_rejects_additional_model_turn_argument_property(
    tmp_path: Path,
) -> None:
    arguments = json.dumps(
        _model_turn_document(extra_property=True), separators=(",", ":")
    )
    schema = model_turn_openai_function_schema()
    http = FakePinnedHttpPort(_tool_response(arguments))
    proxy, state, _, _, _ = _stack(tmp_path, http, tool_schemas=(schema,))

    result = proxy.dispatch(
        _request(proxy, state.authority_digest, tool_schemas=(schema,))
    )

    assert result.outcome is ProxyOutcome.FAILED
    assert result.tool_calls == ()
    assert len(http.calls) == 1
