from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
from threading import Thread

import pytest
from pydantic import ValidationError

from faultloom.egress import (
    CompiledKnowledgeRequest,
    CompiledProviderRequest,
    DenialCode,
    DestinationResolution,
    EgressOutcome,
    EgressPlane,
    EgressReceipt,
    EgressStateCheckpoint,
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
    ReconciliationAuthorization,
    SignedReconciliationAuthorization,
    SqliteEgressStateStore,
    TransportOutcome,
    TrustedAuthorityState,
    knowledge_action_digest,
    provider_action_digest,
    sign_reconciliation_authorization,
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
RECONCILIATION_SIGNER = AuthoritySigner.from_private_bytes(bytes(range(32, 64)))
STATE_AUTHENTICATION_KEY = bytes([73]) * 32


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
    plane: EgressPlane = EgressPlane.MODEL_PROVIDER
    resolver_id: str = "resolver.static"
    addresses: tuple[str, ...] = ("8.8.8.8",)
    cname_chain: tuple[str, ...] = ()
    calls: list[str] = field(default_factory=list)

    def resolve(self, origin: str) -> DestinationResolution:
        self.calls.append(origin)
        return DestinationResolution(
            schema_version=SCHEMA_VERSION,
            plane=self.plane,
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
    minimum_anchor: EgressStateCheckpoint | None = None,
) -> TrustedAuthorityState:
    signed_grant, signed_epoch = signed or signed_authority(
        authority, scope_epoch=scope_epoch, signer=signer
    )
    state_root = path.parent / f".{path.name}.state"
    anchor_root = path.parent / f".{path.name}.anchor"
    state_root.mkdir(mode=0o700, exist_ok=True)
    anchor_root.mkdir(mode=0o700, exist_ok=True)
    return TrustedAuthorityState(
        trust_domain="authority.primary",
        trusted_key=AUTHORITY_SIGNER.public_key_record,
        trusted_reconciliation_key=RECONCILIATION_SIGNER.public_key_record,
        authority=signed_grant,
        scope_epoch=signed_epoch,
        state_store=SqliteEgressStateStore(
            state_root / path.name,
            anchor_path=anchor_root / "state.anchor",
            authentication_key=STATE_AUTHENTICATION_KEY,
            minimum_anchor=minimum_anchor or EgressStateCheckpoint.empty(),
        ),
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
        resolver=resolver or StaticResolver(plane=EgressPlane.MODEL_PROVIDER),
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
        resolver=resolver or StaticResolver(plane=EgressPlane.KNOWLEDGE),
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


def reconciliation_authorization(
    request: ProviderRequest | KnowledgeFetchIntent,
    disposition: ReconciliationDisposition,
    *,
    sequence: int = 1,
    capability_id: str | None = None,
    signer: AuthoritySigner = RECONCILIATION_SIGNER,
) -> SignedReconciliationAuthorization:
    if isinstance(request, ProviderRequest):
        plane = EgressPlane.MODEL_PROVIDER
        action_digest = provider_action_digest(request)
    else:
        plane = EgressPlane.KNOWLEDGE
        action_digest = knowledge_action_digest(request)
    payload = ReconciliationAuthorization(
        schema_version=SCHEMA_VERSION,
        capability_id=capability_id or f"reconciliation.{sequence}",
        sequence=sequence,
        plane=plane,
        action_digest=action_digest,
        request_digest=sha256_digest(request),
        authority_digest=request.authority_digest,
        scope_epoch=request.scope_epoch,
        disposition=disposition,
        issued_at=DISPATCH_TIME - timedelta(minutes=1),
        expires_at=DISPATCH_TIME + timedelta(minutes=5),
    )
    return sign_reconciliation_authorization(payload, signer)


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
    transport_id: str = "transport.memory-provider"
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
    transport_id: str = "transport.memory-knowledge"
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
    resolver = StaticResolver(plane=plane, addresses=(resolved_address,))
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
    resolver = StaticResolver(plane=plane, addresses=("::ffff:7f00:1",))
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
        resolver=StaticResolver(
            plane=EgressPlane.KNOWLEDGE, cname_chain=(cname,)
        ),
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
    initial_state = authority_state(authority, database, scope_epoch=7)
    first = provider_proxy(
        authority,
        database,
        transport=first_transport,
        state=initial_state,
    ).dispatch(provider_request(authority))
    assert first.outcome is EgressOutcome.COMPLETED
    minimum_anchor = initial_state.state_store.checkpoint()

    stale_signed = signed_authority(authority, scope_epoch=6)
    stale_state = authority_state(
        authority,
        database,
        scope_epoch=6,
        signed=stale_signed,
        minimum_anchor=minimum_anchor,
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
    minimum_anchor = state.state_store.checkpoint()

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

    stale_state = authority_state(
        authority,
        database,
        scope_epoch=7,
        minimum_anchor=minimum_anchor,
    )
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
    initial_state = authority_state(authority, database)
    first_proxy = provider_proxy(
        authority,
        database,
        transport=first_transport,
        resolver=first_resolver,
        state=initial_state,
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
        state=authority_state(
            authority,
            database,
            minimum_anchor=initial_state.state_store.checkpoint(),
        ),
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
    assert proxy.reconcile(
        request,
        reconciliation_authorization(
            request, ReconciliationDisposition.RETRY_AUTHORIZED
        ),
    ) is True
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
    assert proxy.reconcile(
        request,
        reconciliation_authorization(
            request, ReconciliationDisposition.EFFECT_CONFIRMED
        ),
    ) is True
    assert proxy.dispatch(request).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert len(transport.requests) == 1


def test_knowledge_unknown_outcome_hold_blocks_replay_until_reconciled(
    tmp_path: Path,
) -> None:
    authority = grant()
    request = knowledge_request(authority)
    database = tmp_path / "state.sqlite3"
    transport = MemoryKnowledgeTransport(fail=True)
    initial_state = authority_state(authority, database)
    fetcher = knowledge_fetcher(
        authority, database, transport=transport, state=initial_state
    )

    assert fetcher.dispatch(request).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert fetcher.dispatch(request).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    restarted_transport = MemoryKnowledgeTransport()
    restarted = knowledge_fetcher(
        authority,
        database,
        transport=restarted_transport,
        state=authority_state(
            authority,
            database,
            minimum_anchor=initial_state.state_store.checkpoint(),
        ),
    )
    assert restarted.dispatch(request).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert restarted.reconcile(
        request,
        reconciliation_authorization(
            request, ReconciliationDisposition.RETRY_AUTHORIZED
        ),
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
    with pytest.raises(ValueError, match="absolute"):
        SqliteEgressStateStore(
            ":memory:",
            anchor_path="/tmp/unused-egress.anchor",
            authentication_key=STATE_AUTHENTICATION_KEY,
            minimum_anchor=EgressStateCheckpoint.empty(),
        )


def test_authenticated_state_rejects_direct_row_tampering(tmp_path: Path) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    transport = MemoryProviderTransport(fail=True)
    proxy = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=transport,
        state=state,
    )
    request = provider_request(authority)
    assert proxy.dispatch(request).outcome is EgressOutcome.UNKNOWN_OUTCOME

    with sqlite3.connect(state.state_store.path) as connection:
        connection.execute(
            "UPDATE dispatch_hold SET state = 'retry_authorized'"
        )
        connection.commit()

    transport.fail = False
    denied = proxy.dispatch(request)
    assert denied.denial_code is DenialCode.AUTHORITY_VERIFICATION_FAILED
    assert len(transport.requests) == 1


def test_authenticated_state_rejects_authority_watermark_rollback(
    tmp_path: Path,
) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    transport = MemoryProviderTransport()
    proxy = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=transport,
        state=state,
    )
    assert proxy.dispatch(provider_request(authority)).outcome is EgressOutcome.COMPLETED
    with sqlite3.connect(state.state_store.path) as connection:
        connection.execute("UPDATE authority_watermark SET scope_epoch = 1")
        connection.commit()
    receipt = proxy.dispatch(
        provider_request(authority, request_id="provider-request.after-tamper")
    )
    assert receipt.denial_code is DenialCode.AUTHORITY_VERIFICATION_FAILED
    assert len(transport.requests) == 1


def test_database_deletion_cannot_silently_create_empty_replay_state(
    tmp_path: Path,
) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    transport = MemoryProviderTransport(fail=True)
    proxy = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=transport,
        state=state,
    )
    request = provider_request(authority)
    assert proxy.dispatch(request).outcome is EgressOutcome.UNKNOWN_OUTCOME
    floor = state.state_store.checkpoint()
    database = state.state_store.path
    anchor = state.state_store.anchor_path
    state.state_store.close()
    database.unlink()
    with pytest.raises(RuntimeError, match="presence disagree"):
        SqliteEgressStateStore(
            database,
            anchor_path=anchor,
            authentication_key=STATE_AUTHENTICATION_KEY,
            minimum_anchor=floor,
        )


def test_external_floor_rejects_deleted_and_recreated_state(tmp_path: Path) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    proxy = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=MemoryProviderTransport(),
        state=state,
    )
    assert proxy.dispatch(provider_request(authority)).outcome is EgressOutcome.COMPLETED
    store = state.state_store
    floor = store.checkpoint()
    database = store.path
    anchor = store.anchor_path
    store.close()
    database.unlink()
    anchor.unlink()

    with pytest.raises(RuntimeError, match="minimum anchor"):
        SqliteEgressStateStore(
            database,
            anchor_path=anchor,
            authentication_key=STATE_AUTHENTICATION_KEY,
            minimum_anchor=floor,
        )


def test_state_store_rejects_drvfs_permissions_when_not_realized() -> None:
    drvfs_root = Path.cwd()
    if not str(drvfs_root).startswith("/mnt/") or not drvfs_root.is_dir():
        pytest.skip("DrvFS deployment surface is unavailable")
    owned = Path(tempfile.mkdtemp(prefix=".t17-permissions-", dir=drvfs_root))
    try:
        state_root = owned / "state"
        anchor_root = owned / "anchor"
        state_root.mkdir(mode=0o700)
        anchor_root.mkdir(mode=0o700)
        effective = stat.S_IMODE(state_root.stat().st_mode)
        if effective == 0o700:
            pytest.skip("filesystem realizes private POSIX permissions")
        with pytest.raises(RuntimeError, match="0700"):
            SqliteEgressStateStore(
                state_root / "state.sqlite3",
                anchor_path=anchor_root / "state.anchor",
                authentication_key=STATE_AUTHENTICATION_KEY,
                minimum_anchor=EgressStateCheckpoint.empty(),
            )
    finally:
        shutil.rmtree(owned, ignore_errors=True)


def test_reconciliation_requires_signed_one_use_scoped_authorization(
    tmp_path: Path,
) -> None:
    authority = grant()
    request = provider_request(authority)
    transport = MemoryProviderTransport(fail=True)
    proxy = provider_proxy(authority, tmp_path / "state.sqlite3", transport=transport)
    assert proxy.dispatch(request).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert proxy.reconcile(  # type: ignore[arg-type]
        request, ReconciliationDisposition.RETRY_AUTHORIZED
    ) is False
    attacker = AuthoritySigner.from_private_bytes(bytes([99]) * 32)
    forged = reconciliation_authorization(
        request, ReconciliationDisposition.RETRY_AUTHORIZED, signer=attacker
    )
    assert proxy.reconcile(request, forged) is False

    authorization = reconciliation_authorization(
        request, ReconciliationDisposition.RETRY_AUTHORIZED
    )
    assert proxy.reconcile(request, authorization) is True
    assert proxy.reconcile(request, authorization) is False
    transport.fail = False
    assert proxy.dispatch(request).outcome is EgressOutcome.COMPLETED
    assert len(transport.requests) == 2


def test_pending_crash_hold_can_be_explicitly_effect_confirmed(tmp_path: Path) -> None:
    authority = grant()
    request = provider_request(authority)
    state = authority_state(authority, tmp_path / "state.sqlite3")
    action_digest = provider_action_digest(request)
    assert state.state_store.reserve_dispatch(
        plane=EgressPlane.MODEL_PROVIDER.value,
        action_digest=action_digest,
        correlation_digest=D1,
        request_digest=sha256_digest(request),
        dispatch_authorization_digest=D1,
        reserved_at=DISPATCH_TIME,
    ) == "reserved"
    transport = MemoryProviderTransport()
    proxy = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=transport,
        state=state,
    )
    authorization = reconciliation_authorization(
        request, ReconciliationDisposition.EFFECT_CONFIRMED
    )
    assert proxy.reconcile(request, authorization) is True
    assert proxy.dispatch(request).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert transport.requests == []


@pytest.mark.parametrize("alias", ["request_id", "run_id"])
def test_semantic_action_alias_cannot_bypass_unknown_hold(
    alias: str, tmp_path: Path
) -> None:
    authority = grant()
    transport = MemoryProviderTransport(fail=True)
    proxy = provider_proxy(authority, tmp_path / "state.sqlite3", transport=transport)
    original = provider_request(authority)
    assert proxy.dispatch(original).outcome is EgressOutcome.UNKNOWN_OUTCOME
    changed = provider_request(authority, **{alias: f"{alias}.fresh"})
    assert proxy.dispatch(changed).denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert len(transport.requests) == 1


def test_knowledge_actual_request_bytes_are_bounded(tmp_path: Path) -> None:
    authority = grant()
    maximum = authority.budget.max_request_bytes
    transport = MemoryKnowledgeTransport(
        response=EgressTransportResult(
            schema_version=SCHEMA_VERSION,
            plane=EgressPlane.KNOWLEDGE,
            outcome=TransportOutcome.COMPLETED,
            response_digest=D1,
            response_status=200,
            bytes_sent=maximum + 1,
            bytes_received=1,
        )
    )
    receipt = knowledge_fetcher(
        authority, tmp_path / "state.sqlite3", transport=transport
    ).dispatch(knowledge_request(authority))
    assert receipt.outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert transport.requests[0].maximum_request_bytes == maximum


def test_receipt_digest_is_revalidated_on_wire_load(tmp_path: Path) -> None:
    authority = grant()
    receipt = provider_proxy(
        authority,
        tmp_path / "state.sqlite3",
        transport=MemoryProviderTransport(),
    ).dispatch(provider_request(authority))
    changed = receipt.model_dump(mode="python")
    changed["response_status"] = 299
    with pytest.raises(ValidationError, match="receipt digest"):
        EgressReceipt.model_validate(changed)


def test_same_version_signed_authority_fork_is_rejected(tmp_path: Path) -> None:
    authority = grant()
    database = tmp_path / "state.sqlite3"
    original_state = authority_state(authority, database)
    original = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=MemoryProviderTransport(),
        state=original_state,
    )
    assert original.dispatch(provider_request(authority)).outcome is EgressOutcome.COMPLETED
    floor = original_state.state_store.checkpoint()

    document = authority.model_dump(mode="python")
    document["provider_policy"]["allowed_model_snapshots"] = (
        *authority.provider_policy.allowed_model_snapshots,
        "frontier-fork",
    )
    fork = AuthorityGrant.model_validate(document)
    fork_state = authority_state(
        fork,
        database,
        signed=signed_authority(fork),
        minimum_anchor=floor,
    )
    transport = MemoryProviderTransport()
    receipt = provider_proxy(
        fork,
        tmp_path / "unused-2.sqlite3",
        transport=transport,
        state=fork_state,
    ).dispatch(provider_request(fork, model_snapshot="frontier-fork"))
    assert receipt.denial_code is DenialCode.AUTHORITY_VERIFICATION_FAILED
    assert transport.requests == []


@pytest.mark.parametrize("kind", ["provider", "knowledge"])
def test_target_plane_resolver_cannot_be_injected(kind: str, tmp_path: Path) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    resolver = StaticResolver(plane=EgressPlane.TARGET)
    with pytest.raises(ValueError, match="resolver"):
        if kind == "provider":
            ProviderProxy(
                endpoints=(provider_endpoint(),),
                transport=MemoryProviderTransport(),
                resolver=resolver,
                authority_state=state,
                live=True,
                clock=clock,
            )
        else:
            KnowledgeFetcher(
                sources=(knowledge_source(),),
                transport=MemoryKnowledgeTransport(),
                resolver=resolver,
                authority_state=state,
                clock=clock,
            )


@pytest.mark.parametrize("kind", ["provider", "knowledge"])
def test_scope_revocation_during_resolution_prevents_dispatch(
    kind: str, tmp_path: Path
) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    revoked_epoch = signed_authority(authority, scope_epoch=8, revoked=True)[1]

    class RevokingResolver:
        plane = (
            EgressPlane.MODEL_PROVIDER if kind == "provider" else EgressPlane.KNOWLEDGE
        )
        resolver_id = f"resolver.revoking-{kind}"

        def resolve(self, origin: str) -> DestinationResolution:
            try:
                state.install_scope_epoch(revoked_epoch, now=DISPATCH_TIME)
            except AuthorityRevokedError:
                pass
            return DestinationResolution(
                schema_version=SCHEMA_VERSION,
                plane=self.plane,
                origin=origin,
                addresses=("8.8.8.8",),
            )

    if kind == "provider":
        transport = MemoryProviderTransport()
        receipt = ProviderProxy(
            endpoints=(provider_endpoint(),),
            transport=transport,
            resolver=RevokingResolver(),
            authority_state=state,
            live=True,
            clock=clock,
        ).dispatch(provider_request(authority))
    else:
        transport = MemoryKnowledgeTransport()
        receipt = KnowledgeFetcher(
            sources=(knowledge_source(),),
            transport=transport,
            resolver=RevokingResolver(),
            authority_state=state,
            clock=clock,
        ).dispatch(knowledge_request(authority))

    assert state.scope_epoch_number == 8
    assert receipt.denial_code is DenialCode.AUTHORITY_NOT_CURRENT
    assert transport.requests == []


@pytest.mark.parametrize("kind", ["provider", "knowledge"])
def test_concurrent_revocation_after_reservation_prevents_dispatch(
    kind: str, tmp_path: Path
) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    revoked_epoch = signed_authority(authority, scope_epoch=8, revoked=True)[1]
    reserve = state.state_store.reserve_dispatch

    def reserve_then_revoke(**kwargs: object) -> str:
        reservation = reserve(**kwargs)

        def revoke() -> None:
            try:
                state.install_scope_epoch(revoked_epoch, now=DISPATCH_TIME)
            except AuthorityRevokedError:
                pass

        thread = Thread(target=revoke)
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive()
        return reservation

    state.state_store.reserve_dispatch = reserve_then_revoke  # type: ignore[method-assign]
    if kind == "provider":
        transport = MemoryProviderTransport()
        receipt = provider_proxy(
            authority,
            tmp_path / "unused.sqlite3",
            transport=transport,
            state=state,
        ).dispatch(provider_request(authority))
    else:
        transport = MemoryKnowledgeTransport()
        receipt = knowledge_fetcher(
            authority,
            tmp_path / "unused.sqlite3",
            transport=transport,
            state=state,
        ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is DenialCode.AUTHORITY_NOT_CURRENT
    assert transport.requests == []


@pytest.mark.parametrize("kind", ["provider", "knowledge"])
def test_resolver_cannot_switch_transport_to_target_plane(
    kind: str, tmp_path: Path
) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    if kind == "provider":
        transport = MemoryProviderTransport()
        expected_plane = EgressPlane.MODEL_PROVIDER
    else:
        transport = MemoryKnowledgeTransport()
        expected_plane = EgressPlane.KNOWLEDGE

    class MutatingResolver:
        plane = expected_plane
        resolver_id = f"resolver.mutating-{kind}-transport"

        def resolve(self, origin: str) -> DestinationResolution:
            transport.plane = EgressPlane.TARGET
            return DestinationResolution(
                schema_version=SCHEMA_VERSION,
                plane=self.plane,
                origin=origin,
                addresses=("8.8.8.8",),
            )

    if kind == "provider":
        receipt = ProviderProxy(
            endpoints=(provider_endpoint(),),
            transport=transport,
            resolver=MutatingResolver(),
            authority_state=state,
            live=True,
            clock=clock,
        ).dispatch(provider_request(authority))
    else:
        receipt = KnowledgeFetcher(
            sources=(knowledge_source(),),
            transport=transport,
            resolver=MutatingResolver(),
            authority_state=state,
            clock=clock,
        ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is DenialCode.TRANSPORT_PLANE_MISMATCH
    assert transport.requests == []


@pytest.mark.parametrize("kind", ["provider", "knowledge"])
def test_transport_plane_is_rechecked_after_reservation(
    kind: str, tmp_path: Path
) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    transport = (
        MemoryProviderTransport() if kind == "provider" else MemoryKnowledgeTransport()
    )
    reserve = state.state_store.reserve_dispatch

    def reserve_then_switch_plane(**kwargs: object) -> str:
        reservation = reserve(**kwargs)
        transport.plane = EgressPlane.TARGET
        return reservation

    state.state_store.reserve_dispatch = reserve_then_switch_plane  # type: ignore[method-assign]
    if kind == "provider":
        receipt = provider_proxy(
            authority,
            tmp_path / "unused.sqlite3",
            transport=transport,
            state=state,
        ).dispatch(provider_request(authority))
    else:
        receipt = knowledge_fetcher(
            authority,
            tmp_path / "unused.sqlite3",
            transport=transport,
            state=state,
        ).dispatch(knowledge_request(authority))

    assert receipt.denial_code is DenialCode.DISPATCH_BINDING_MISMATCH
    assert transport.requests == []


def test_retry_alias_correlation_cannot_be_reused_by_another_action(
    tmp_path: Path,
) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    transport = MemoryProviderTransport(
        response=EgressTransportResult(
            schema_version=SCHEMA_VERSION,
            plane=EgressPlane.MODEL_PROVIDER,
            outcome=TransportOutcome.UNKNOWN_OUTCOME,
            response_digest=D1,
            response_status=200,
            bytes_sent=32,
            bytes_received=128,
        )
    )
    proxy = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=transport,
        state=state,
    )
    first = provider_request(authority)
    assert proxy.dispatch(first).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert proxy.reconcile(
        first,
        reconciliation_authorization(
            first, ReconciliationDisposition.RETRY_AUTHORIZED
        ),
    )

    transport.response = result(EgressPlane.MODEL_PROVIDER)
    retry_alias = provider_request(
        authority,
        request_id="provider-request.retry",
        run_id="run.retry",
    )
    assert proxy.dispatch(retry_alias).outcome is EgressOutcome.COMPLETED
    changed = provider_request(
        authority,
        request_id="provider-request.retry",
        run_id="run.retry",
        payload_digest=sha256_digest({"different": "semantic-action"}),
    )
    denied = proxy.dispatch(changed)

    assert denied.denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert len(transport.requests) == 2
    with sqlite3.connect(state.state_store.path) as connection:
        rows = connection.execute(
            "SELECT action_digest FROM dispatch_correlation ORDER BY correlation_digest"
        ).fetchall()
    assert rows == [(provider_action_digest(first),), (provider_action_digest(first),)]


def test_retry_alias_correlation_survives_crash_before_transport(tmp_path: Path) -> None:
    authority = grant()
    state = authority_state(authority, tmp_path / "state.sqlite3")
    transport = MemoryProviderTransport(
        response=EgressTransportResult(
            schema_version=SCHEMA_VERSION,
            plane=EgressPlane.MODEL_PROVIDER,
            outcome=TransportOutcome.UNKNOWN_OUTCOME,
            response_digest=D1,
            response_status=200,
            bytes_sent=32,
            bytes_received=128,
        )
    )
    proxy = provider_proxy(
        authority,
        tmp_path / "unused.sqlite3",
        transport=transport,
        state=state,
    )
    first = provider_request(authority)
    assert proxy.dispatch(first).outcome is EgressOutcome.UNKNOWN_OUTCOME
    assert proxy.reconcile(
        first,
        reconciliation_authorization(
            first, ReconciliationDisposition.RETRY_AUTHORIZED
        ),
    )
    retry_alias = provider_request(
        authority,
        request_id="provider-request.crash-retry",
        run_id="run.crash-retry",
    )
    correlation_digest = sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "plane": EgressPlane.MODEL_PROVIDER,
            "run_id": retry_alias.run_id,
            "request_id": retry_alias.request_id,
        }
    )
    assert state.state_store.reserve_dispatch(
        plane=EgressPlane.MODEL_PROVIDER.value,
        action_digest=provider_action_digest(retry_alias),
        correlation_digest=correlation_digest,
        request_digest=sha256_digest(retry_alias),
        dispatch_authorization_digest=D1,
        reserved_at=DISPATCH_TIME,
    ) == "reserved"
    checkpoint = state.state_store.checkpoint()
    state.state_store.close()
    reopened_state = authority_state(
        authority,
        tmp_path / "state.sqlite3",
        minimum_anchor=checkpoint,
    )
    proxy = provider_proxy(
        authority,
        tmp_path / "unused-after-crash.sqlite3",
        transport=transport,
        state=reopened_state,
    )

    changed = provider_request(
        authority,
        request_id=retry_alias.request_id,
        run_id=retry_alias.run_id,
        payload_digest=sha256_digest({"different": "post-crash-action"}),
    )
    denied = proxy.dispatch(changed)
    assert denied.denial_code is DenialCode.REQUEST_REPLAY_DENIED
    assert len(transport.requests) == 1


def test_state_and_anchor_physical_parent_alias_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    shared = real / "shared"
    real.mkdir(mode=0o700)
    shared.mkdir(mode=0o700)
    (tmp_path / "alias-a").symlink_to(real, target_is_directory=True)
    (tmp_path / "alias-b").symlink_to(real, target_is_directory=True)
    state_parent = tmp_path / "alias-a" / "shared"
    anchor_parent = tmp_path / "alias-b" / "shared"
    assert (state_parent.stat().st_dev, state_parent.stat().st_ino) == (
        anchor_parent.stat().st_dev,
        anchor_parent.stat().st_ino,
    )

    with pytest.raises(RuntimeError, match="physical directory"):
        SqliteEgressStateStore(
            state_parent / "state.sqlite3",
            anchor_path=anchor_parent / "state.anchor",
            authentication_key=STATE_AUTHENTICATION_KEY,
            minimum_anchor=EgressStateCheckpoint.empty(),
        )


@pytest.mark.parametrize("kind", ["provider", "knowledge"])
def test_compiled_request_and_receipt_bind_dispatch_authorization(
    kind: str, tmp_path: Path
) -> None:
    authority = grant()
    if kind == "provider":
        transport = MemoryProviderTransport()
        receipt = provider_proxy(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
        ).dispatch(provider_request(authority))
    else:
        transport = MemoryKnowledgeTransport()
        receipt = knowledge_fetcher(
            authority,
            tmp_path / "state.sqlite3",
            transport=transport,
        ).dispatch(knowledge_request(authority))

    compiled = transport.requests[0]
    assert compiled.destination_digest == receipt.destination_digest
    assert compiled.execution_component_digest == receipt.execution_component_digest
    assert (
        compiled.dispatch_authorization_digest
        == receipt.dispatch_authorization_digest
    )
    changed = receipt.model_dump(mode="python")
    changed["dispatch_authorization_digest"] = D1
    with pytest.raises(ValidationError, match="receipt digest"):
        EgressReceipt.model_validate(changed)
