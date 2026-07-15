from __future__ import annotations

import hashlib
from contextlib import closing
from dataclasses import dataclass
from http.client import HTTPConnection

import pytest
from pydantic import ValidationError

from labs.framework import (
    GatewayEvidenceBindingError,
    GatewayEvidenceRequest,
    LabDiagnostic,
    LabEndpoint,
    SemanticFixtureMode,
    bind_gateway_evidence,
    clean_replay,
    load_semantic_http_manifest,
    running_lab,
)
from tests.runtime.execution_helpers import (
    command,
    completed_result,
    execution_identity,
    semantic_request,
)


@dataclass(frozen=True, slots=True)
class _DiagnosticRequest:
    method: str
    path: str
    tenant: str


def _diagnose(endpoint: LabEndpoint, request: _DiagnosticRequest) -> tuple[int, bytes]:
    with closing(HTTPConnection(endpoint.host, endpoint.port, timeout=2)) as connection:
        connection.request(
            request.method,
            request.path,
            headers={"X-Lab-Tenant": request.tenant},
        )
        response = connection.getresponse()
        return response.status, response.read()


def test_manifest_provides_versioned_positive_and_negative_oracles() -> None:
    manifest = load_semantic_http_manifest()

    modes = {variant.mode for variant in manifest.variants}

    assert manifest.schema_version == "0.1.0"
    assert manifest.descriptor.namespace == "faultloom.lab.web.semantic_http"
    assert modes == {SemanticFixtureMode.VULNERABLE, SemanticFixtureMode.DENIED}


def test_manifest_rejects_a_non_loopback_bind_host() -> None:
    manifest = load_semantic_http_manifest()
    document = manifest.model_dump_json().replace("127.0.0.1", "0.0.0.0")

    with pytest.raises(ValidationError):
        type(manifest).model_validate_json(document)


def test_vulnerable_fixture_exposes_only_the_owned_canary_on_loopback() -> None:
    manifest = load_semantic_http_manifest()
    request = _DiagnosticRequest(
        method="GET",
        path="/v1/tenants/tenant.beta/resources/canary",
        tenant="tenant.beta",
    )

    with running_lab(manifest, SemanticFixtureMode.VULNERABLE) as lab:
        readiness = lab.readiness()
        assert readiness.ready is True
        assert readiness.endpoint is not None
        assert readiness.endpoint.host == "127.0.0.1"
        status, body = _diagnose(readiness.endpoint, request)

    assert status == 200
    assert body == b'{"owner_tenant":"tenant.alpha","resource_id":"resource.canary"}'
    assert lab.readiness().ready is False


def test_denied_fixture_is_the_negative_control() -> None:
    manifest = load_semantic_http_manifest()
    request = _DiagnosticRequest(
        method="GET",
        path="/v1/tenants/tenant.beta/resources/canary",
        tenant="tenant.beta",
    )

    with running_lab(manifest, SemanticFixtureMode.DENIED) as lab:
        endpoint = lab.readiness().endpoint
        assert endpoint is not None
        status, body = _diagnose(endpoint, request)

    assert status == 403
    assert body == b'{"error":"denied"}'


def test_clean_replay_resets_and_cleans_canary_state() -> None:
    manifest = load_semantic_http_manifest()
    touch = _DiagnosticRequest(
        method="POST",
        path="/v1/canary/touch",
        tenant="tenant.alpha",
    )

    with running_lab(manifest, SemanticFixtureMode.VULNERABLE) as lab:
        endpoint = lab.readiness().endpoint
        assert endpoint is not None
        with clean_replay(lab):
            assert lab.snapshot().marker == "clean"
            status, _ = _diagnose(endpoint, touch)
            assert status == 200
            assert lab.snapshot().marker == "touched"
        cleaned = lab.snapshot()

    assert cleaned.marker == "clean"
    assert cleaned.generation == 0
    assert cleaned.snapshot_id == "state.semantic-http.canary.generation.0"


def test_direct_diagnostic_is_ineligible_but_gateway_receipt_can_bind_the_run() -> None:
    manifest = load_semantic_http_manifest()
    variant = manifest.variant("variant.semantic-http.vulnerable")
    dispatch_command = command(
        request=semantic_request(path=variant.request_path),
        identity=execution_identity(
            context_id="browser.outsider",
            identity_id="identity.outsider",
            tenant_id="tenant.beta",
            session_uri="secret://run/identity-outsider",
        ),
    )
    result = completed_result(dispatch_command)
    diagnostic = LabDiagnostic(
        fixture_id=manifest.fixture_id,
        variant_id=variant.variant_id,
        status_code=200,
        body_digest=f"sha256:{hashlib.sha256(b'diagnostic-only').hexdigest()}",
    )

    binding = bind_gateway_evidence(
        GatewayEvidenceRequest(
            manifest=manifest,
            variant_id=variant.variant_id,
            intent=dispatch_command.intent,
            receipt=result.receipt,
        )
    )

    assert diagnostic.evidence_eligible is False
    assert binding.evidence_eligible is True
    assert binding.run_id == dispatch_command.intent.run_id
    assert binding.target_id == manifest.target_id
    assert binding.receipt_id == result.receipt.receipt_id


def test_gateway_binding_rejects_a_receipt_for_another_target() -> None:
    manifest = load_semantic_http_manifest()
    variant = manifest.variant("variant.semantic-http.vulnerable")
    dispatch_command = command(
        request=semantic_request(path=variant.request_path),
        identity=execution_identity(
            context_id="browser.outsider",
            identity_id="identity.outsider",
            tenant_id="tenant.beta",
            session_uri="secret://run/identity-outsider",
        ),
    )
    result = completed_result(dispatch_command)
    other_target_receipt = result.receipt.model_copy(
        update={"target_id": "target.other"}
    )

    with pytest.raises(GatewayEvidenceBindingError):
        bind_gateway_evidence(
            GatewayEvidenceRequest(
                manifest=manifest,
                variant_id=variant.variant_id,
                intent=dispatch_command.intent,
                receipt=other_target_receipt,
            )
        )


def test_gateway_binding_rejects_the_wrong_oracle_actor() -> None:
    manifest = load_semantic_http_manifest()
    variant = manifest.variant("variant.semantic-http.vulnerable")
    owner_command = command(
        request=semantic_request(path=variant.request_path),
    )
    owner_result = completed_result(owner_command)

    with pytest.raises(GatewayEvidenceBindingError):
        bind_gateway_evidence(
            GatewayEvidenceRequest(
                manifest=manifest,
                variant_id=variant.variant_id,
                intent=owner_command.intent,
                receipt=owner_result.receipt,
            )
        )
