from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_protocol import EvidenceCapability, LicenseClass, SecretRef, sha256_digest
from faultloom_sdk import (
    AdapterAdmissionError,
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdmissionGate,
    AdmissionOutcome,
    ManifestRegistry,
)
from faultloom_web.burp import (
    BurpHeader,
    BurpHistoryItem,
    BurpPolicyError,
    BurpScope,
    BurpTool,
    BurpToolRequest,
    CredentialField,
    HistoryTransport,
    HttpVersion,
    LoopbackEndpoint,
    PassiveBurpPolicyAdapter,
    expected_server_snapshot,
    passive_burp_adapter_manifest,
)


class _SecretSink:
    def __init__(self) -> None:
        self.count = 0
        self.registrations: list[tuple[str, str]] = []

    def register(self, *, purpose: str, value: str) -> SecretRef:
        self.count += 1
        self.registrations.append((purpose, value))
        return SecretRef(
            schema_version="0.1.0",
            uri=f"secret://burp/item-{self.count}",
            purpose=purpose,
        )


class _BrokenSecretSink:
    def register(self, *, purpose: str, value: str) -> SecretRef:
        raise RuntimeError("vault unavailable")


def _adapter() -> PassiveBurpPolicyAdapter:
    return PassiveBurpPolicyAdapter(
        LoopbackEndpoint(url="http://127.0.0.1:9876/mcp"),
        BurpScope(hosts=("lab.test",), path_prefixes=("/approved",)),
    )


def _request(tool: BurpTool) -> BurpToolRequest:
    return BurpToolRequest(
        tool_name=tool.value,
        host="lab.test",
        path="/approved/object",
        http_version=HttpVersion.HTTP_2 if tool is BurpTool.CREATE_REPEATER_TAB else None,
    )


def test_manifest_and_passive_allowlist_are_exact_and_candidate_only() -> None:
    manifest = passive_burp_adapter_manifest()
    assert manifest.license_class is LicenseClass.EXTERNAL_USER_MANAGED
    assert manifest.evidence_capability is EvidenceCapability.CANDIDATE_ONLY
    assert manifest.network_mode == "loopback_policy_proxy"
    assert {tool.name for tool in expected_server_snapshot().tools} == {
        item.value for item in BurpTool
    }

    adapter = _adapter()
    for tool in BurpTool:
        receipt = adapter.authorize(_request(tool), observed_server=expected_server_snapshot())
        assert receipt.tool is tool
        assert receipt.candidate_only
        assert not receipt.execution_performed
        assert not receipt.verification_evidence


@pytest.mark.parametrize(
    "tool_name",
    (
        "http.send",
        "intruder.attack",
        "collaborator.poll",
        "config.update",
        "task.create",
        "intercept.toggle",
        "editor.replace",
        "future.unknown",
    ),
)
def test_direct_active_mutating_and_unknown_tools_are_denied(tool_name: str) -> None:
    with pytest.raises(BurpPolicyError, match="tool_denied"):
        _adapter().authorize(
            BurpToolRequest(tool_name=tool_name, host="lab.test", path="/approved"),
            observed_server=expected_server_snapshot(),
        )


def test_contract_drift_disables_the_whole_adapter_and_non_loopback_fails() -> None:
    adapter = _adapter()
    drifted = expected_server_snapshot().model_copy(update={"server_version": "1.0.1"})
    with pytest.raises(BurpPolicyError, match="adapter_disabled"):
        adapter.authorize(_request(BurpTool.READ_SCANNER_ISSUES), observed_server=drifted)
    assert not adapter.enabled
    with pytest.raises(BurpPolicyError, match="adapter_disabled"):
        adapter.authorize(
            _request(BurpTool.READ_SCANNER_ISSUES),
            observed_server=expected_server_snapshot(),
        )
    with pytest.raises(ValidationError, match="loopback"):
        LoopbackEndpoint(url="http://burp.example/mcp")


def test_history_is_scope_filtered_and_secrets_are_replaced_with_refs() -> None:
    raw_values = ("Bearer top-secret", "sid=private", "hunter2")
    item = BurpHistoryItem(
        item_id="history-1",
        transport=HistoryTransport.HTTP,
        host="lab.test",
        path="/approved/object",
        headers=(
            BurpHeader(name="Authorization", value=raw_values[0]),
            BurpHeader(name="Cookie", value=raw_values[1]),
            BurpHeader(name="Content-Type", value="application/json"),
        ),
        credentials=(CredentialField(name="password", value=raw_values[2]),),
    )
    sink = _SecretSink()
    result = _adapter().scrub_history(
        _request(BurpTool.READ_HTTP_HISTORY),
        (item,),
        observed_server=expected_server_snapshot(),
        secrets=sink,
    )
    serialized = result[0].model_dump_json()
    assert sink.count == 3
    assert serialized.count("<secret-ref>") == 3
    assert all(value not in serialized for value in raw_values)

    oos = item.model_copy(update={"host": "other.test"})
    with pytest.raises(BurpPolicyError, match="out_of_scope"):
        _adapter().scrub_history(
            _request(BurpTool.READ_HTTP_HISTORY),
            (oos,),
            observed_server=expected_server_snapshot(),
            secrets=sink,
        )
    prefix_confusion = item.model_copy(update={"path": "/approved-evil"})
    with pytest.raises(BurpPolicyError, match="out_of_scope"):
        _adapter().scrub_history(
            _request(BurpTool.READ_HTTP_HISTORY),
            (prefix_confusion,),
            observed_server=expected_server_snapshot(),
            secrets=sink,
        )
    with pytest.raises(BurpPolicyError, match="secret_scrub_failed"):
        _adapter().scrub_history(
            _request(BurpTool.READ_HTTP_HISTORY),
            (item,),
            observed_server=expected_server_snapshot(),
            secrets=_BrokenSecretSink(),
        )


@pytest.mark.parametrize(
    "header_name", ("X-API-Key", "x_auth_token", "Proxy-Authorization", "X-Session-Key")
)
def test_sensitive_header_aliases_are_scrubbed_without_overmatching(header_name: str) -> None:
    raw_value = f"secret-for-{header_name}"
    item = BurpHistoryItem(
        item_id="history-header-alias",
        transport=HistoryTransport.HTTP,
        host="lab.test",
        path="/approved/object",
        headers=(
            BurpHeader(name=header_name, value=raw_value),
            BurpHeader(name="X-Monkey-ID", value="useful-nonsecret"),
        ),
    )
    sink = _SecretSink()

    result = _adapter().scrub_history(
        _request(BurpTool.READ_HTTP_HISTORY),
        (item,),
        observed_server=expected_server_snapshot(),
        secrets=sink,
    )[0]

    assert result.headers == (
        BurpHeader(name=header_name, value="<secret-ref>"),
        BurpHeader(name="X-Monkey-ID", value="useful-nonsecret"),
    )
    assert type(result.secret_refs[0]) is SecretRef
    assert sink.registrations == [(f"burp.header.{header_name}", raw_value)]
    assert raw_value not in result.model_dump_json()


@pytest.mark.parametrize(
    ("wire_name", "canonical_name"),
    (("api_key", "api_key"), ("API%5FKEY", "api_key"), ("X%2DAPI%2DKEY", "x_api_key")),
)
def test_query_credentials_are_scrubbed_without_rewriting_nonsecret_query(
    wire_name: str,
    canonical_name: str,
) -> None:
    wire_secret = "S3cr%65t%2BToken"
    decoded_secret = "S3cret+Token"
    useful_prefix = "/approved/object?view=Full%2FDetail+Mode&"
    useful_suffix = "&cursor=a%2Fb+z&monkey=banana"
    item = BurpHistoryItem(
        item_id="history-query-secret",
        transport=HistoryTransport.HTTP,
        host="lab.test",
        path=f"{useful_prefix}{wire_name}={wire_secret}{useful_suffix}",
    )
    sink = _SecretSink()

    result = _adapter().scrub_history(
        _request(BurpTool.READ_HTTP_HISTORY),
        (item,),
        observed_server=expected_server_snapshot(),
        secrets=sink,
    )[0]

    assert result.path == f"{useful_prefix}{wire_name}=<secret-ref>{useful_suffix}"
    assert type(result.secret_refs[0]) is SecretRef
    assert sink.registrations == [(f"burp.query.{canonical_name}", decoded_secret)]
    serialized = result.model_dump_json()
    assert wire_secret not in serialized
    assert decoded_secret not in serialized


def test_history_scrub_fails_closed_before_secret_processing_on_schema_drift() -> None:
    expected = expected_server_snapshot()
    drifted_tool = expected.tools[0].model_copy(update={"input_schema_digest": "0" * 64})
    drifted = expected.model_copy(update={"tools": (drifted_tool, *expected.tools[1:])})
    item = BurpHistoryItem(
        item_id="history-schema-drift",
        transport=HistoryTransport.HTTP,
        host="lab.test",
        path="/approved/object?api_key=must-not-be-processed",
    )
    sink = _SecretSink()

    with pytest.raises(BurpPolicyError, match="adapter_disabled"):
        _adapter().scrub_history(
            _request(BurpTool.READ_HTTP_HISTORY),
            (item,),
            observed_server=drifted,
            secrets=sink,
        )

    assert sink.registrations == []


def test_candidate_only_adapter_cannot_be_promoted_by_caller_declared_metrics() -> None:
    manifest = passive_burp_adapter_manifest()
    registry = ManifestRegistry(known_adapter_capabilities=manifest.capabilities)
    registry.install_adapter(manifest)
    admission = AdapterAdmissionRegistry(registry)
    digest = sha256_digest(manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        admission.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
            )
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        AdapterAdmissionReceipt.model_validate(
            {
                "adapter_id": manifest.adapter_id,
                "manifest_digest": digest,
                "gate": AdmissionGate.MODEL_UTILITY,
                "outcome": AdmissionOutcome.PASSED,
                "artifact_digest": manifest.output_schema_digest,
                "unique_verified_positives": 2,
            }
        )
    with pytest.raises(AdapterAdmissionError, match="every admission gate"):
        admission.require_evidence_source(
            manifest.adapter_id,
            independent_non_tool_evidence=True,
        )
