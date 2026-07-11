from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from faultloom.egress import (
    CompiledKnowledgeRequest,
    CompiledProviderRequest,
    DenialCode,
    DestinationResolution,
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
    ReconciliationDisposition,
    SqliteEgressStateStore,
    TransportOutcome,
    TrustedAuthorityState,
)
from faultloom_protocol import (
    AuthorityGrant,
    AuthorityRevokedError,
    AuthoritySigner,
    SCHEMA_VERSION,
    ScopeEpoch,
    SecretRef,
    SignedAuthorityGrant,
    SignedScopeEpoch,
    sha256_digest,
    sign_authority_grant,
    sign_scope_epoch,
)
from tests.protocol.factories import D1, NOW, sample_models

DISPATCH_TIME = NOW + timedelta(minutes=10)
AUTHORITY_SIGNER = AuthoritySigner.from_private_bytes(bytes(range(32)))


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


@dataclass
class StaticResolver:
    addresses: tuple[str, ...] = ("8.8.8.8",)
    cname_chain: tuple[str, ...] = ()
    calls: list[str] = field(default_factory=list)

    def resolve(self, origin: str) -> DestinationResolution:
        self.calls.append(origin)
        return DestinationResolution(
            schema_version=SCHEMA_VERSION,
            origin=origin,
            cname_chain=self.cname_chain,
            addresses=self.addresses,
        )


def signed_authority(
    authority: AuthorityGrant,
    *,
    scope_epoch: int = 7,
    signer: AuthoritySigner = AUTHORITY_SIGNER,
    revoked: bool = False,
) -> tuple[SignedAuthorityGrant, SignedScopeEpoch]:
    signed_grant = sign_authority_grant(authority, signer, signed_at=NOW)
    epoch = ScopeEpoch(
        schema_version=SCHEMA_VERSION,
        grant_id=authority.grant_id,
        epoch=scope_epoch,
        issued_at=NOW,
        expires_at=authority.expires_at,
        revoked=revoked,
        revocation_reason="operator revoked authority" if revoked else None,
    )
    return signed_grant, sign_scope_epoch(epoch, signer, signed_at=NOW)


def authority_state(
    authority: AuthorityGrant,
    path: Path,
    *,
    scope_epoch: int = 7,
    signer: AuthoritySigner = AUTHORITY_SIGNER,
    signed: tuple[SignedAuthorityGrant, SignedScopeEpoch] | None = None,
) -> TrustedAuthorityState:
    signed_grant, signed_epoch = signed or signed_authority(
        authority, scope_epoch=scope_epoch, signer=signer
    )
    return TrustedAuthorityState(
        trust_domain="authority.primary",
        trusted_key=AUTHORITY_SIGNER.public_key_record,
        authority=signed_grant,
        scope_epoch=signed_epoch,
        state_store=SqliteEgressStateStore(path),
    )


def provider_proxy(
    authority: AuthorityGrant,
    path: Path,
    *,
    transport: "MemoryProviderTransport",
    endpoint: ProviderEndpoint | None = None,
    resolver: StaticResolver | None = None,
    live: bool = True,
    state: TrustedAuthorityState | None = None,
    proxy_clock= None,
) -> ProviderProxy:
    return ProviderProxy(
        endpoints=(endpoint or provider_endpoint(),),
        transport=transport,
        resolver=resolver or StaticResolver(),
        authority_state=state or authority_state(authority, path),
        live=live,
        clock=proxy_clock or clock,
    )


def knowledge_fetcher(
    authority: AuthorityGrant,
    path: Path,
    *,
    transport: "MemoryKnowledgeTransport",
    source: KnowledgeSource | None = None,
    resolver: StaticResolver | None = None,
    state: TrustedAuthorityState | None = None,
    fetch_clock=None,
) -> KnowledgeFetcher:
    return KnowledgeFetcher(
        sources=(source or knowledge_source(),),
        transport=transport,
        resolver=resolver or StaticResolver(),
        authority_state=state or authority_state(authority, path),
        clock=fetch_clock or clock,
    )


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
        "authority_digest": sha256_digest(signed_authority(authority)[0]),
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
        "authority_digest": sha256_digest(signed_authority(authority)[0]),
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


def test_provider_proxy_compiles_only_configured_destination_and_secret_reference(
    tmp_path: Path,
) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
    ).dispatch(provider_request(authority))

    assert receipt.outcome is EgressOutcome.COMPLETED
    assert receipt.plane is EgressPlane.MODEL_PROVIDER
    assert receipt.reconciliation_required is False
    assert len(transport.requests) == 1
    compiled = transport.requests[0]
    assert compiled.origin == "https://provider.example.invalid"
    assert compiled.follow_redirects is False
    assert compiled.resolved_addresses == ("8.8.8.8",)
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
    changes: dict[str, object], expected: DenialCode, tmp_path: Path
) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
    ).dispatch(provider_request(authority, **changes))

    assert receipt.outcome is EgressOutcome.DENIED
    assert receipt.denial_code is expected
    assert receipt.bytes_sent == 0
    assert transport.requests == []


@pytest.mark.parametrize("tool_id", ["tool.provider-web", "tool.provider-computer"])
def test_live_proxy_blocks_provider_managed_network_tools(
    tool_id: str, tmp_path: Path
) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
    ).dispatch(provider_request(authority, tool_ids=(tool_id,)))

    assert receipt.denial_code is DenialCode.PROVIDER_TOOL_LIVE_DENIED
    assert transport.requests == []


def test_explicit_lab_provider_tool_does_not_weaken_live_binding(tmp_path: Path) -> None:
    authority = grant()
    lab_transport = MemoryProviderTransport()
    lab_proxy = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=lab_transport,
        live=False,
    )
    allowed = lab_proxy.dispatch(
        provider_request(authority, live=False, tool_ids=("tool.provider-web",))
    )
    mismatched = lab_proxy.dispatch(provider_request(authority, live=True))

    assert allowed.outcome is EgressOutcome.COMPLETED
    assert mismatched.denial_code is DenialCode.AUTHORITY_BINDING_MISMATCH
    assert len(lab_transport.requests) == 1


def test_unknown_provider_tool_is_fail_closed(tmp_path: Path) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
    ).dispatch(provider_request(authority, tool_ids=("tool.unknown",)))
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


def test_provider_destination_cannot_overlap_authorized_target(tmp_path: Path) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    receipt = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
        endpoint=provider_endpoint(origin="https://loopback.test"),
    ).dispatch(provider_request(authority))
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
    authority: AuthorityGrant, origin: str, tmp_path: Path
) -> None:
    transport = MemoryProviderTransport()
    receipt = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
        endpoint=provider_endpoint(origin=origin),
    ).dispatch(provider_request(authority))
    assert receipt.denial_code is DenialCode.DESTINATION_OVERLAPS_TARGET
    assert transport.requests == []


def test_knowledge_fetcher_compiles_allowlisted_path_without_redirects(tmp_path: Path) -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    receipt = knowledge_fetcher(
        authority, tmp_path / "state.sqlite3", transport=transport
    ).dispatch(knowledge_request(authority))

    assert receipt.outcome is EgressOutcome.COMPLETED
    assert receipt.plane is EgressPlane.KNOWLEDGE
    assert len(transport.requests) == 1
    compiled = transport.requests[0]
    assert compiled.origin == "https://docs.example.invalid"
    assert compiled.path == "/security/advisory"
    assert compiled.follow_redirects is False
    assert compiled.resolved_addresses == ("8.8.8.8",)
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
    changes: dict[str, object], expected: DenialCode, tmp_path: Path
) -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    receipt = knowledge_fetcher(
        authority, tmp_path / "state.sqlite3", transport=transport
    ).dispatch(knowledge_request(authority, **changes))

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


def test_knowledge_destination_cannot_be_target_egress(tmp_path: Path) -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    receipt = knowledge_fetcher(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
        source=knowledge_source(origin="https://loopback.test"),
    ).dispatch(knowledge_request(authority))
    assert receipt.denial_code is DenialCode.DESTINATION_OVERLAPS_TARGET
    assert transport.requests == []


@pytest.mark.parametrize(
    "kind",
    ["provider", "knowledge"],
)
def test_target_plane_transport_cannot_be_injected(kind: str, tmp_path: Path) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    with pytest.raises(ValueError, match="transport"):
        if kind == "provider":
            ProviderProxy(
                endpoints=(provider_endpoint(),),
                transport=MemoryProviderTransport(plane=EgressPlane.TARGET),
                resolver=StaticResolver(),
                authority_state=state,
                live=True,
                clock=clock,
            )
        else:
            KnowledgeFetcher(
                sources=(knowledge_source(),),
                transport=MemoryKnowledgeTransport(plane=EgressPlane.TARGET),
                resolver=StaticResolver(),
                authority_state=state,
                clock=clock,
            )


def test_plane_drift_before_dispatch_fails_closed(tmp_path: Path) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    proxy = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
    )
    transport.plane = EgressPlane.TARGET
    receipt = proxy.dispatch(provider_request(authority))

    assert receipt.denial_code is DenialCode.TRANSPORT_PLANE_MISMATCH
    assert transport.requests == []


def test_wrong_result_plane_and_transport_loss_require_reconciliation(tmp_path: Path) -> None:
    authority = grant()
    wrong_plane = MemoryProviderTransport(response=result(EgressPlane.TARGET))
    uncertain = provider_proxy(
        authority,
        tmp_path / "uncertain.sqlite3",
        transport=wrong_plane,
    ).dispatch(provider_request(authority))
    failing = MemoryProviderTransport(fail=True)
    lost = provider_proxy(
        authority,
        tmp_path / "lost.sqlite3",
        transport=failing,
    ).dispatch(provider_request(authority))

    assert uncertain.outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert uncertain.reconciliation_required is True
    assert lost.outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert lost.reconciliation_required is True


def test_receipts_are_deterministic_with_fixed_policy_clock_and_transport(
    tmp_path: Path,
) -> None:
    authority = grant()
    request = provider_request(authority)
    first = provider_proxy(
        authority,
        tmp_path / "first.sqlite3",
        transport=MemoryProviderTransport(),
    ).dispatch(request)
    second = provider_proxy(
        authority,
        tmp_path / "second.sqlite3",
        transport=MemoryProviderTransport(),
    ).dispatch(request)

    assert first == second
    assert first.receipt_digest == sha256_digest(
        first.model_dump(mode="python", exclude={"receipt_digest"})
    )


def test_expired_authority_is_checked_against_trusted_clock(tmp_path: Path) -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    fetcher = knowledge_fetcher(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
        fetch_clock=lambda: authority.expires_at,
    )
    receipt = fetcher.dispatch(knowledge_request(authority))
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


@pytest.mark.parametrize("plane", [EgressPlane.MODEL_PROVIDER, EgressPlane.KNOWLEDGE])
@pytest.mark.parametrize(
    "origin",
    [
        "https://127.0.0.1",
        "https://0.0.0.0",
        "https://169.254.169.254",
        "https://10.0.0.1",
        "https://[::1]",
        "https://[::]",
        "https://[fe80::1]",
        "https://[fd00:ec2::254]",
        "https://[ff02::1]",
        "https://metadata.google.internal",
        "https://api.localhost",
    ],
)
def test_static_special_use_destinations_are_denied_before_transport(
    plane: EgressPlane, origin: str, tmp_path: Path
) -> None:
    authority = grant()
    if plane is EgressPlane.MODEL_PROVIDER:
        transport = MemoryProviderTransport()
        receipt = provider_proxy(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
            endpoint=provider_endpoint(origin=origin),
        ).dispatch(provider_request(authority))
    else:
        transport = MemoryKnowledgeTransport()
        receipt = knowledge_fetcher(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
            source=knowledge_source(origin=origin),
        ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is DenialCode.DESTINATION_SPECIAL_USE
    assert transport.requests == []


@pytest.mark.parametrize("factory", [provider_endpoint, knowledge_source])
def test_scoped_ipv6_origins_are_rejected_at_policy_load(factory) -> None:
    with pytest.raises(ValidationError, match="scoped IPv6"):
        factory(origin="https://[fe80::1%25eth0]")


@pytest.mark.parametrize("plane", [EgressPlane.MODEL_PROVIDER, EgressPlane.KNOWLEDGE])
@pytest.mark.parametrize(
    "resolved_address",
    ["127.0.0.1", "0.0.0.0", "169.254.169.254", "::1", "fe80::1", "::ffff:7f00:1"],
)
def test_dns_resolution_to_special_use_address_is_denied(
    plane: EgressPlane, resolved_address: str, tmp_path: Path
) -> None:
    authority = grant()
    resolver = StaticResolver(addresses=(resolved_address,))
    if plane is EgressPlane.MODEL_PROVIDER:
        transport = MemoryProviderTransport()
        receipt = provider_proxy(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
            resolver=resolver,
        ).dispatch(provider_request(authority))
    else:
        transport = MemoryKnowledgeTransport()
        receipt = knowledge_fetcher(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
            resolver=resolver,
        ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is DenialCode.DESTINATION_SPECIAL_USE
    assert transport.requests == []


@pytest.mark.parametrize("plane", [EgressPlane.MODEL_PROVIDER, EgressPlane.KNOWLEDGE])
def test_ipv4_mapped_ipv6_is_normalized_for_target_overlap(
    plane: EgressPlane, tmp_path: Path
) -> None:
    authority = grant_with_network_identity(cidrs=("127.0.0.0/8",))
    origin = "https://[::ffff:7f00:1]"
    resolver = StaticResolver(addresses=("::ffff:7f00:1",))
    if plane is EgressPlane.MODEL_PROVIDER:
        transport = MemoryProviderTransport()
        receipt = provider_proxy(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
            endpoint=provider_endpoint(origin=origin),
            resolver=resolver,
        ).dispatch(provider_request(authority))
    else:
        transport = MemoryKnowledgeTransport()
        receipt = knowledge_fetcher(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
            source=knowledge_source(origin=origin),
            resolver=resolver,
        ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is DenialCode.DESTINATION_OVERLAPS_TARGET
    assert transport.requests == []


@pytest.mark.parametrize(
    ("cname", "expected"),
    [
        ("loopback.test", DenialCode.DESTINATION_OVERLAPS_TARGET),
        ("metadata.google.internal", DenialCode.DESTINATION_SPECIAL_USE),
    ],
)
def test_cname_chain_is_rechecked_at_dispatch(
    cname: str, expected: DenialCode, tmp_path: Path
) -> None:
    authority = grant()
    transport = MemoryKnowledgeTransport()
    receipt = knowledge_fetcher(
        authority,
        tmp_path / "state.sqlite3",
        transport=transport,
        resolver=StaticResolver(cname_chain=(cname,)),
    ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is expected
    assert transport.requests == []


def test_forged_authority_signed_by_untrusted_key_is_denied(tmp_path: Path) -> None:
    document = grant().model_dump(mode="python")
    document["provider_policy"]["allowed_providers"] = ("provider.attacker",)
    document["provider_policy"]["allowed_model_snapshots"] = ("attacker-model",)
    forged_grant = AuthorityGrant.model_validate(document)
    attacker = AuthoritySigner.from_private_bytes(bytes([9]) * 32)
    forged = signed_authority(forged_grant, signer=attacker)
    state = authority_state(
        forged_grant,
        tmp_path / "state.sqlite3",
        signer=attacker,
        signed=forged,
    )
    transport = MemoryProviderTransport()
    endpoint = ProviderEndpoint(
        schema_version=SCHEMA_VERSION,
        endpoint_id="endpoint.frontier",
        provider_id="provider.attacker",
        origin="https://attacker.example.invalid",
        tools=(),
    )
    request = provider_request(
        forged_grant,
        authority_digest=sha256_digest(forged[0]),
        provider_id="provider.attacker",
        model_snapshot="attacker-model",
        tool_ids=(),
    )
    receipt = provider_proxy(
        forged_grant,
        tmp_path / "unused.sqlite3",
        transport=transport,
        endpoint=endpoint,
        state=state,
    ).dispatch(request)

    assert receipt.denial_code is DenialCode.AUTHORITY_VERIFICATION_FAILED
    assert transport.requests == []


def test_dispatch_api_rejects_caller_supplied_unsigned_grant(tmp_path: Path) -> None:
    authority = grant()
    transport = MemoryProviderTransport()
    proxy = provider_proxy(authority, tmp_path / "state.sqlite3", transport=transport)

    with pytest.raises(TypeError):
        proxy.dispatch(provider_request(authority), authority)  # type: ignore[call-arg]
    assert transport.requests == []


def test_forged_signed_scope_epoch_is_denied(tmp_path: Path) -> None:
    authority = grant()
    signed_grant, _ = signed_authority(authority)
    attacker = AuthoritySigner.from_private_bytes(bytes([9]) * 32)
    _, forged_epoch = signed_authority(authority, signer=attacker)
    state = authority_state(
        authority,
        tmp_path / "state.sqlite3",
        signed=(signed_grant, forged_epoch),
    )
    transport = MemoryKnowledgeTransport()
    receipt = knowledge_fetcher(
        authority,
        tmp_path / "unused.sqlite3",
        transport=transport,
        state=state,
    ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is DenialCode.AUTHORITY_VERIFICATION_FAILED
    assert transport.requests == []


def test_scope_epoch_watermark_survives_state_store_restart(tmp_path: Path) -> None:
    authority = grant()
    database = tmp_path / "state.sqlite3"
    first_transport = MemoryProviderTransport()
    first = provider_proxy(
        authority,
        database,
        transport=first_transport,
        state=authority_state(authority, database, scope_epoch=7),
    ).dispatch(provider_request(authority))
    assert first.outcome is EgressOutcome.COMPLETED

    stale_signed = signed_authority(authority, scope_epoch=6)
    stale_state = authority_state(
        authority,
        database,
        scope_epoch=6,
        signed=stale_signed,
    )
    stale_transport = MemoryProviderTransport()
    stale = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=stale_transport,
        state=stale_state,
    ).dispatch(
        provider_request(
            authority,
            request_id="provider-request.stale",
            scope_epoch=6,
        )
    )

    assert stale.denial_code is DenialCode.AUTHORITY_VERIFICATION_FAILED
    assert stale_transport.requests == []


def test_signed_revocation_is_sticky_across_restart(tmp_path: Path) -> None:
    authority = grant()
    database = tmp_path / "state.sqlite3"
    state = authority_state(authority, database)
    _, revoked_epoch = signed_authority(authority, scope_epoch=8, revoked=True)
    with pytest.raises(AuthorityRevokedError):
        state.install_scope_epoch(revoked_epoch, now=DISPATCH_TIME)

    revoked_transport = MemoryProviderTransport()
    revoked = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=revoked_transport,
        state=state,
    ).dispatch(
        provider_request(
            authority,
            request_id="provider-request.revoked",
            scope_epoch=8,
        )
    )
    assert revoked.denial_code is DenialCode.AUTHORITY_NOT_CURRENT
    assert revoked_transport.requests == []

    stale_state = authority_state(authority, database, scope_epoch=7)
    stale_transport = MemoryProviderTransport()
    stale = provider_proxy(
        authority,
        tmp_path / "unused-2.sqlite3",
        transport=stale_transport,
        state=stale_state,
    ).dispatch(
        provider_request(authority, request_id="provider-request.after-revocation")
    )
    assert stale.denial_code is DenialCode.AUTHORITY_VERIFICATION_FAILED
    assert stale_transport.requests == []


def test_provider_unknown_outcome_hold_blocks_replay_across_restart(
    tmp_path: Path,
) -> None:
    authority = grant()
    database = tmp_path / "state.sqlite3"
    request = provider_request(authority)
    first_transport = MemoryProviderTransport(fail=True)
    first_resolver = StaticResolver()
    first_proxy = provider_proxy(
        authority, database, transport=first_transport, resolver=first_resolver
    )

    first = first_proxy.dispatch(request)
    repeated = first_proxy.dispatch(request)
    restarted_transport = MemoryProviderTransport()
    restarted_resolver = StaticResolver()
    restarted = provider_proxy(
        authority,
        database,
        transport=restarted_transport,
        resolver=restarted_resolver,
    ).dispatch(request)

    assert first.outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert repeated.denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert restarted.denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert len(first_transport.requests) == 1
    assert restarted_transport.requests == []
    assert first_resolver.calls == ["https://provider.example.invalid"]
    assert restarted_resolver.calls == []


def test_explicit_provider_reconciliation_is_required_before_retry(
    tmp_path: Path,
) -> None:
    authority = grant()
    database = tmp_path / "state.sqlite3"
    request = provider_request(authority)
    transport = MemoryProviderTransport(fail=True)
    proxy = provider_proxy(authority, database, transport=transport)

    assert proxy.dispatch(request).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert proxy.reconcile(request, ReconciliationDisposition.RETRY_AUTHORIZED) is True
    transport.fail = False
    retried = proxy.dispatch(request)

    assert retried.outcome is EgressOutcome.COMPLETED
    assert len(transport.requests) == 2


def test_effect_confirmed_reconciliation_does_not_authorize_retry(tmp_path: Path) -> None:
    authority = grant()
    request = provider_request(authority)
    transport = MemoryProviderTransport(fail=True)
    proxy = provider_proxy(authority, tmp_path / "state.sqlite3", transport=transport)

    assert proxy.dispatch(request).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert proxy.reconcile(request, ReconciliationDisposition.EFFECT_CONFIRMED) is True
    assert proxy.dispatch(request).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert len(transport.requests) == 1


def test_knowledge_unknown_outcome_hold_blocks_replay_until_reconciled(
    tmp_path: Path,
) -> None:
    authority = grant()
    request = knowledge_request(authority)
    database = tmp_path / "state.sqlite3"
    transport = MemoryKnowledgeTransport(fail=True)
    fetcher = knowledge_fetcher(authority, database, transport=transport)

    assert fetcher.dispatch(request).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert fetcher.dispatch(request).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    restarted_transport = MemoryKnowledgeTransport()
    restarted = knowledge_fetcher(
        authority, database, transport=restarted_transport
    )
    assert restarted.dispatch(request).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert restarted.reconcile(
        request, ReconciliationDisposition.RETRY_AUTHORIZED
    ) is True
    assert restarted.dispatch(request).outcome is EgressOutcome.COMPLETED
    assert len(transport.requests) == 1
    assert len(restarted_transport.requests) == 1


def test_same_request_id_with_changed_body_cannot_bypass_unknown_hold(
    tmp_path: Path,
) -> None:
    authority = grant()
    transport = MemoryProviderTransport(fail=True)
    proxy = provider_proxy(authority, tmp_path / "state.sqlite3", transport=transport)
    original = provider_request(authority)
    changed = provider_request(authority, payload_bytes=65)

    assert proxy.dispatch(original).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert proxy.dispatch(changed).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert len(transport.requests) == 1


def test_egress_state_store_rejects_non_durable_memory_database() -> None:
    with pytest.raises(ValueError, match="durable"):
        SqliteEgressStateStore(":memory:")
