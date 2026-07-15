from __future__ import annotations

import hashlib
import json

from faultloom_protocol import (
    ActionClass,
    AdapterBudget,
    AdapterManifest,
    EvidenceCapability,
    LicenseClass,
    TelemetryPolicy,
)

from .models import BurpServerSnapshot, BurpTool, ToolDescriptor

EXPECTED_SERVER_VERSION = "1.0.0"
CAPABILITIES = (
    "burp.passive_scanner_issues",
    "burp.scope_filtered_history",
    "burp.organizer_read",
    "burp.repeater_tab_create",
)


def _digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


_TOOL_INPUTS: dict[BurpTool, dict[str, object]] = {
    BurpTool.READ_SCANNER_ISSUES: {"type": "object", "required": ["host", "path"]},
    BurpTool.READ_HTTP_HISTORY: {"type": "object", "required": ["host", "path"]},
    BurpTool.READ_WEBSOCKET_HISTORY: {"type": "object", "required": ["host", "path"]},
    BurpTool.READ_ORGANIZER_ITEMS: {"type": "object", "required": ["host", "path"]},
    BurpTool.CREATE_REPEATER_TAB: {
        "type": "object",
        "required": ["host", "path", "http_version"],
        "http_versions": ["HTTP/1.1", "HTTP/2"],
    },
}


def expected_server_snapshot() -> BurpServerSnapshot:
    return BurpServerSnapshot(
        server_version=EXPECTED_SERVER_VERSION,
        tools=tuple(
            ToolDescriptor(name=tool.value, input_schema_digest=_digest(_TOOL_INPUTS[tool]))
            for tool in BurpTool
        ),
    )


def passive_burp_adapter_manifest() -> AdapterManifest:
    snapshot = expected_server_snapshot()
    contract_digest = _digest(snapshot.model_dump(mode="json"))
    output_digest = _digest(
        {
            "candidate_only": True,
            "execution_performed": False,
            "verification_evidence": False,
            "secrets": "<secret-ref>",
        }
    )
    return AdapterManifest(
        schema_version="0.1.0",
        adapter_id="adapter.burp.passive",
        adapter_version="0.1.0",
        upstream_version=EXPECTED_SERVER_VERSION,
        image_digest=contract_digest,
        license_class=LicenseClass.EXTERNAL_USER_MANAGED,
        capabilities=CAPABILITIES,
        action_classes=(ActionClass.OBSERVE,),
        network_mode="loopback_policy_proxy",
        input_schema_digest=contract_digest,
        output_schema_digest=output_digest,
        budget=AdapterBudget(
            schema_version="0.1.0",
            rate_per_minute=60,
            timeout_seconds=10,
            max_bytes=4_194_304,
            max_concurrency=1,
        ),
        telemetry_policy=TelemetryPolicy.DISABLED,
        evidence_capability=EvidenceCapability.CANDIDATE_ONLY,
    )
