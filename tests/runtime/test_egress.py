from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from faultloom.egress import (
    CompiledKnowledgeRequest,
    CompiledProviderRequest,
    DenialCode,
    EgressOutcome,
    EgressPlane,
    EgressTransportResult,
    KnowledgeFetchIntent,
    KnowledgeFetcher,
    KnowledgeSource,
    ProviderEndpoint,
    ProviderProxy,
    ProviderRequest,
    ProviderTool,
    ProviderToolKind,
    TransportOutcome,
)
from faultloom_protocol import AuthorityGrant, SCHEMA_VERSION, SecretRef, sha256_digest
from tests.protocol.factories import D1, NOW, sample_models

DISPATCH_TIME = NOW + timedelta(minutes=10)


def grant() -> AuthorityGrant:
    return sample_models()["AuthorityGrant"]  # type: ignore[return-value]


def grant_with_network_identity(
    *, hostnames: tuple[str, ...] = (), cidrs: tuple[str, ...] = ()
) -> AuthorityGrant:
    document = grant().model_dump(mode="python")
    target = document["targets"][0]
    target["hostnames"] = hostnames
    target["cidrs"] = cidrs
    return AuthorityGrant.model_validate(document)


def provider_endpoint(*, origin: str = "https://provider.example.invalid") -> ProviderEndpoint:
    return ProviderEndpoint(
        schema_version=SCHEMA_VERSION,
        endpoint_id="endpoint.frontier",
        provider_id="provider.test",
        origin=origin,
        tools=(
            ProviderTool(
                schema_version=SCHEMA_VERSION,
                tool_id="tool.local",
                kind=ProviderToolKind.LOCAL,
            ),
            ProviderTool(
                schema_version=SCHEMA_VERSION,
                tool_id="tool.provider-web",
                kind=ProviderToolKind.PROVIDER_WEB,
            ),
            ProviderTool(
                schema_version=SCHEMA_VERSION,
                tool_id="tool.provider-computer",
                kind=ProviderToolKind.PROVIDER_COMPUTER,
            ),
        ),
    )


def provider_request(
    authority: AuthorityGrant,
    *,
    live: bool = True,
    tool_ids: tuple[str, ...] = ("tool.local",),
    **changes: object,
) -> ProviderRequest:
    values: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "request_id": "provider-request.1",
        "run_id": "run.1",
        "authority_digest": sha256_digest(authority),
        "scope_epoch": 7,
        "endpoint_id": "endpoint.frontier",
        "provider_id": "provider.test",
        "model_snapshot": "frontier-2030-01-01",
        "data_policy_id": "policy.no-training",
        "credential_ref": SecretRef(
            schema_version=SCHEMA_VERSION,
            uri="secret://engagement/provider-test",
            purpose="model-provider:provider.test",
        ),
        "payload_digest": D1,
        "payload_bytes": 64,
        "tool_ids": tool_ids,
        "requested_at": DISPATCH_TIME,
        "live": live,
    }
    values.update(changes)
    return ProviderRequest(**values)


def knowledge_source(*, origin: str = "https://docs.example.invalid") -> KnowledgeSource:
    return KnowledgeSource(
        schema_version=SCHEMA_VERSION,
        source_id="source.security-docs",
        origin=origin,
        allowed_path_prefixes=("/security",),
        allowed_methods=("GET",),
        allowed_data_policy_ids=("policy.no-training",),
        maximum_response_bytes=4096,
    )


def knowledge_request(authority: AuthorityGrant, **changes: object) -> KnowledgeFetchIntent:
    values: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "request_id": "knowledge-request.1",
        "run_id": "run.1",
        "authority_digest": sha256_digest(authority),
        "scope_epoch": 7,
        "source_id": "source.security-docs",
        "method": "GET",
        "path": "/security/advisory",
        "data_policy_id": "policy.no-training",
        "requested_at": DISPATCH_TIME,
    }
    values.update(changes)
    return KnowledgeFetchIntent(**values)


def result(plane: EgressPlane) -> EgressTransportResult:
    return EgressTransportResult(
        schema_version=SCHEMA_VERSION,
        plane=plane,
        outcome=TransportOutcome.COMPLETED,
        response_digest=D1,
        response_status=200,
        bytes_sent=32,
        bytes_received=128,
    )


@dataclass
class MemoryProviderTransport:
    plane: EgressPlane = EgressPlane.MODEL_PROVIDER
    response: EgressTransportResult = field(
        default_factory=lambda: result(EgressPlane.MODEL_PROVIDER)
    )
    requests: list[CompiledProviderRequest] = field(default_factory=list)
    fail: bool = False

    def dispatch(self, request: CompiledProviderRequest) -> EgressTransportResult:
        self.requests.append(request)
        if self.fail:
            raise OSError("simulated response loss")
        return self.response


@dataclass
class MemoryKnowledgeTransport:
    plane: EgressPlane = EgressPlane.KNOWLEDGE
    response: EgressTransportResult = field(
        default_factory=lambda: result(EgressPlane.KNOWLEDGE)
    )
    requests: list[CompiledKnowledgeRequest] = field(default_factory=list)
    fail: bool = False

    def dispatch(self, request: CompiledKnowledgeRequest) -> EgressTransportResult:
        self.requests.append(request)
        if self.fail:
            raise OSError("simulated response loss")
        return self.response


def clock() -> datetime:
    return DISPATCH_TIME


def test_provider_proxy_compiles_only_configured_destination_and_secret_reference() -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=transport,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority), authority)

    assert receipt.outcome is EgressOutcome.COMPLETED
    assert receipt.plane is EgressPlane.MODEL_PROVIDER
    assert receipt.reconciliation_required is False
    assert len(transport.requests) == 1
    compiled = transport.requests[0]
    assert compiled.origin == "https://provider.example.invalid"
    assert compiled.follow_redirects is False
    assert compiled.credential_ref.uri == "secret://engagement/provider-test"
    serialized = receipt.model_dump_json()
    assert "secret://" not in serialized
    assert "provider.example.invalid" not in serialized


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"authority_digest": "sha256:" + "00" * 32}, DenialCode.AUTHORITY_BINDING_MISMATCH),
        ({"scope_epoch": 8}, DenialCode.SCOPE_EPOCH_MISMATCH),
        ({"provider_id": "provider.other"}, DenialCode.ENDPOINT_DENIED),
        ({"model_snapshot": "frontier-unapproved"}, DenialCode.MODEL_SNAPSHOT_DENIED),
        ({"data_policy_id": "policy.training"}, DenialCode.DATA_POLICY_DENIED),
        ({"payload_bytes": 4097}, DenialCode.REQUEST_BUDGET_EXCEEDED),
        (
            {
                "credential_ref": SecretRef(
                    schema_version=SCHEMA_VERSION,
                    uri="secret://engagement/provider-test",
                    purpose="wrong-purpose",
                )
            },
            DenialCode.SECRET_REFERENCE_DENIED,
        ),
        ({"requested_at": DISPATCH_TIME + timedelta(seconds=1)}, DenialCode.REQUEST_TIME_INVALID),
    ],
)
def test_provider_policy_denials_never_reach_transport(
    changes: dict[str, object], expected: DenialCode
) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=transport,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority, **changes), authority)

    assert receipt.outcome is EgressOutcome.DENIED
    assert receipt.denial_code is expected
    assert receipt.bytes_sent == 0
    assert transport.requests == []


@pytest.mark.parametrize("tool_id", ["tool.provider-web", "tool.provider-computer"])
def test_live_proxy_blocks_provider_managed_network_tools(tool_id: str) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=transport,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority, tool_ids=(tool_id,)), authority)

    assert receipt.denial_code is DenialCode.PROVIDER_TOOL_LIVE_DENIED
    assert transport.requests == []


def test_explicit_lab_provider_tool_does_not_weaken_live_binding() -> None:
    authority = grant()
    lab_transport = MemoryProviderTransport()
    lab_proxy = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=lab_transport,
        live=False,
        scope_epoch=7,
        clock=clock,
    )
    allowed = lab_proxy.dispatch(
        provider_request(authority, live=False, tool_ids=("tool.provider-web",)), authority
    )
    mismatched = lab_proxy.dispatch(provider_request(authority, live=True), authority)

    assert allowed.outcome is EgressOutcome.COMPLETED
    assert mismatched.denial_code is DenialCode.AUTHORITY_BINDING_MISMATCH
    assert len(lab_transport.requests) == 1


def test_unknown_provider_tool_is_fail_closed() -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=transport,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority, tool_ids=("tool.unknown",)), authority)
    assert receipt.denial_code is DenialCode.PROVIDER_TOOL_DENIED
    assert transport.requests == []


def test_model_request_accepts_secret_refs_not_raw_credentials_or_urls() -> None:
    authority = grant()
    document = provider_request(authority).model_dump(mode="python")
    document["api_key"] = "raw-secret"
    with pytest.raises(ValidationError):
        ProviderRequest.model_validate(document)
    document.pop("api_key")
    document["url"] = "https://loopback.test/target"
    with pytest.raises(ValidationError):
        ProviderRequest.model_validate(document)
    document.pop("url")
    document["credential_ref"] = "raw-secret"
    with pytest.raises(ValidationError):
        ProviderRequest.model_validate(document)


def test_provider_destination_cannot_overlap_authorized_target() -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = ProviderProxy(
        endpoints=(provider_endpoint(origin="https://loopback.test"),),
        transport=transport,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority), authority)
    assert receipt.denial_code is DenialCode.DESTINATION_OVERLAPS_TARGET
    assert transport.requests == []


@pytest.mark.parametrize(
    ("authority", "origin"),
    [
        (grant_with_network_identity(hostnames=("loopback.test",)), "https://child.loopback.test"),
        (grant_with_network_identity(cidrs=("192.0.2.0/24",)), "https://192.0.2.8"),
        (grant_with_network_identity(hostnames=("not a hostname",)), "https://provider.invalid"),
        (grant_with_network_identity(cidrs=("not-a-cidr",)), "https://provider.invalid"),
    ],
)
def test_ambiguous_or_indirect_target_overlap_is_denied(
    authority: AuthorityGrant, origin: str
) -> None:
    transport = MemoryProviderTransport()
    receipt = ProviderProxy(
        endpoints=(provider_endpoint(origin=origin),),
        transport=transport,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority), authority)
    assert receipt.denial_code is DenialCode.DESTINATION_OVERLAPS_TARGET
    assert transport.requests == []


def test_knowledge_fetcher_compiles_allowlisted_path_without_redirects() -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    receipt = KnowledgeFetcher(
        sources=(knowledge_source(),), transport=transport, scope_epoch=7, clock=clock
    ).dispatch(knowledge_request(authority), authority)

    assert receipt.outcome is EgressOutcome.COMPLETED
    assert receipt.plane is EgressPlane.KNOWLEDGE
    assert len(transport.requests) == 1
    compiled = transport.requests[0]
    assert compiled.origin == "https://docs.example.invalid"
    assert compiled.path == "/security/advisory"
    assert compiled.follow_redirects is False
    assert compiled.maximum_response_bytes == 4096


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"source_id": "source.unknown"}, DenialCode.SOURCE_DENIED),
        ({"method": "HEAD"}, DenialCode.KNOWLEDGE_METHOD_DENIED),
        ({"path": "/public/advisory"}, DenialCode.KNOWLEDGE_PATH_DENIED),
        ({"path": "/security-bypass/advisory"}, DenialCode.KNOWLEDGE_PATH_DENIED),
        ({"data_policy_id": "policy.training"}, DenialCode.DATA_POLICY_DENIED),
        ({"authority_digest": "sha256:" + "00" * 32}, DenialCode.AUTHORITY_BINDING_MISMATCH),
        ({"scope_epoch": 8}, DenialCode.SCOPE_EPOCH_MISMATCH),
    ],
)
def test_knowledge_allowlist_denials_never_reach_transport(
    changes: dict[str, object], expected: DenialCode
) -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    receipt = KnowledgeFetcher(
        sources=(knowledge_source(),), transport=transport, scope_epoch=7, clock=clock
    ).dispatch(knowledge_request(authority, **changes), authority)

    assert receipt.outcome is EgressOutcome.DENIED
    assert receipt.denial_code is expected
    assert transport.requests == []


@pytest.mark.parametrize(
    "path",
    [
        "https://docs.example.invalid/security",
        "/security/../private",
        "/security/%2e%2e/private",
        "/security//advisory",
        "/security\\advisory",
        "/security/advisory;admin=true",
    ],
)
def test_knowledge_intent_rejects_noncanonical_or_arbitrary_urls(path: str) -> None:
    with pytest.raises(ValidationError):
        knowledge_request(grant(), path=path)


def test_knowledge_destination_cannot_be_target_egress() -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    receipt = KnowledgeFetcher(
        sources=(knowledge_source(origin="https://loopback.test"),),
        transport=transport,
        scope_epoch=7,
        clock=clock,
    ).dispatch(knowledge_request(authority), authority)
    assert receipt.denial_code is DenialCode.DESTINATION_OVERLAPS_TARGET
    assert transport.requests == []


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ProviderProxy(
            endpoints=(provider_endpoint(),),
            transport=MemoryProviderTransport(plane=EgressPlane.TARGET),
            live=True,
            scope_epoch=7,
            clock=clock,
        ),
        lambda: KnowledgeFetcher(
            sources=(knowledge_source(),),
            transport=MemoryKnowledgeTransport(plane=EgressPlane.TARGET),
            scope_epoch=7,
            clock=clock,
        ),
    ],
)
def test_target_plane_transport_cannot_be_injected(factory) -> None:
    with pytest.raises(ValueError, match="transport"):
        factory()


def test_plane_drift_before_dispatch_fails_closed() -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    proxy = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=transport,
        live=True,
        scope_epoch=7,
        clock=clock,
    )
    transport.plane = EgressPlane.TARGET
    receipt = proxy.dispatch(provider_request(authority), authority)

    assert receipt.denial_code is DenialCode.TRANSPORT_PLANE_MISMATCH
    assert transport.requests == []


def test_wrong_result_plane_and_transport_loss_require_reconciliation() -> None:
    authority = grant()
    wrong_plane = MemoryProviderTransport(response=result(EgressPlane.TARGET))
    uncertain = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=wrong_plane,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority), authority)
    failing = MemoryProviderTransport(fail=True)
    lost = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=failing,
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(provider_request(authority), authority)

    assert uncertain.outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert uncertain.reconciliation_required is True
    assert lost.outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert lost.reconciliation_required is True


def test_receipts_are_deterministic_with_fixed_policy_clock_and_transport() -> None:
    authority = grant()
    request = provider_request(authority)
    first = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=MemoryProviderTransport(),
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(request, authority)
    second = ProviderProxy(
        endpoints=(provider_endpoint(),),
        transport=MemoryProviderTransport(),
        live=True,
        scope_epoch=7,
        clock=clock,
    ).dispatch(request, authority)

    assert first == second
    assert first.receipt_digest == sha256_digest(
        first.model_dump(mode="python", exclude={"receipt_digest"})
    )


def test_expired_authority_is_checked_against_trusted_clock() -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    fetcher = KnowledgeFetcher(
        sources=(knowledge_source(),),
        transport=transport,
        scope_epoch=7,
        clock=lambda: authority.expires_at,
    )
    receipt = fetcher.dispatch(knowledge_request(authority), authority)
    assert receipt.denial_code is DenialCode.AUTHORITY_NOT_CURRENT
    assert transport.requests == []


@pytest.mark.parametrize(
    "origin",
    [
        "http://docs.example.invalid",
        "https://user@docs.example.invalid",
        "https://docs.example.invalid/path",
        "https://DOCS.example.invalid",
        "https://docs.example.invalid/",
        "https://docs.example.invalid:443",
        "https://bad_host.example.invalid",
        "https://127.1",
        "https://2130706433",
        "https://localhost",
    ],
)
def test_egress_origins_require_canonical_https_origin(origin: str) -> None:
    with pytest.raises(ValidationError):
        knowledge_source(origin=origin)
