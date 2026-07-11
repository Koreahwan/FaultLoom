from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom.execution import (
    EndpointScheme,
    SemanticEndpoint,
    SemanticHeader,
    SemanticHttpRequest,
    SemanticQueryParameter,
    SemanticValue,
    semantic_payload_digest,
)
from faultloom_protocol import SCHEMA_VERSION, SecretRef, canonical_json

from .execution_helpers import command, execution_identity, semantic_request


def literal(value: str) -> SemanticValue:
    return SemanticValue(schema_version=SCHEMA_VERSION, literal=value)


def secret(name: str) -> SemanticValue:
    return SemanticValue(
        schema_version=SCHEMA_VERSION,
        secret_ref=SecretRef(
            schema_version=SCHEMA_VERSION,
            uri=f"secret://run/{name}",
            purpose=name,
        ),
    )


@pytest.mark.parametrize(
    "name", ["authorization", "cookie", "x-api-key", "x-auth-token", "x-session-key"]
)
def test_sensitive_headers_require_opaque_secret_references(name: str) -> None:
    with pytest.raises(ValidationError, match="secret_ref"):
        SemanticHeader(schema_version=SCHEMA_VERSION, name=name, value=literal("raw"))
    header = SemanticHeader(schema_version=SCHEMA_VERSION, name=name, value=secret(name))
    assert "raw" not in canonical_json(header)
    assert "secret://" in canonical_json(header)


@pytest.mark.parametrize(
    "name", ["host", "content-length", "transfer-encoding", "connection", "upgrade"]
)
def test_gateway_compiler_owns_framing_and_hop_by_hop_headers(name: str) -> None:
    with pytest.raises(ValidationError, match="Gateway compiler"):
        SemanticHeader(schema_version=SCHEMA_VERSION, name=name, value=literal("x"))


def test_semantic_contract_rejects_crlf_ambiguous_paths_and_raw_query_tokens() -> None:
    with pytest.raises(ValidationError, match="control separators"):
        literal("safe\r\nInjected: yes")
    with pytest.raises(ValidationError, match="absolute semantic path"):
        SemanticEndpoint(
            schema_version=SCHEMA_VERSION,
            scheme=EndpointScheme.HTTPS,
            hostname="loopback.test",
            port=443,
            path="/api?unbound=yes",
        )
    with pytest.raises(ValidationError, match="secret_ref"):
        SemanticQueryParameter(
            schema_version=SCHEMA_VERSION,
            name="access_token",
            value=literal("raw-token"),
        )
    with pytest.raises(ValidationError, match="ASCII percent encoding"):
        semantic_request(path="/api/owned tenant")
    with pytest.raises(ValidationError, match="uppercase hex"):
        semantic_request(path="/api/%2fadmin")
    assert semantic_request(path="/api/%2Fadmin").endpoint.path == "/api/%2Fadmin"


def test_semantic_request_is_canonical_and_intent_payload_is_exactly_bound() -> None:
    request = semantic_request()
    approved = command(request=request)
    assert approved.intent.payload_digest == semantic_payload_digest(request, approved.identity)

    changed_request = semantic_request(path="/api/other")
    values = approved.model_dump(mode="python")
    values["request"] = changed_request
    with pytest.raises(ValidationError, match="payload_digest"):
        type(approved).model_validate(values)

    swapped_identity = execution_identity(session_uri="secret://run/swapped-session")
    values = approved.model_dump(mode="python")
    values["identity"] = swapped_identity
    with pytest.raises(ValidationError, match="payload_digest"):
        type(approved).model_validate(values)


def test_semantic_http_refuses_websocket_schemes() -> None:
    endpoint = SemanticEndpoint(
        schema_version=SCHEMA_VERSION,
        scheme=EndpointScheme.WSS,
        hostname="loopback.test",
        port=443,
        path="/socket",
    )
    with pytest.raises(ValidationError, match="only supports http and https"):
        SemanticHttpRequest(
            schema_version=SCHEMA_VERSION,
            endpoint=endpoint,
            method="GET",
        )
