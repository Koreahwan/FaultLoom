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

    def register(self, *, purpose: str, value: str) -> SecretRef:
        self.count += 1
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


def test_candidate_only_adapter_cannot_be_promoted_to_verification_evidence() -> None:
    manifest = passive_burp_adapter_manifest()
    registry = ManifestRegistry(known_adapter_capabilities=manifest.capabilities)
    registry.install_adapter(manifest)
    admission = AdapterAdmissionRegistry(registry)
    digest = sha256_digest(manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY, AdmissionGate.MODEL_UTILITY):
        admission.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
                unique_verified_positives=2 if gate is AdmissionGate.MODEL_UTILITY else 0,
            )
        )
    with pytest.raises(AdapterAdmissionError, match="candidate-only"):
        admission.require_evidence_source(
            manifest.adapter_id,
            independent_non_tool_evidence=True,
        )
