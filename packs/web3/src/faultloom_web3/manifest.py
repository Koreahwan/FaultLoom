"""Public manifests for the owned G44 Web/LLM/Web3 fixture slice."""

from __future__ import annotations

import re
from dataclasses import dataclass

from faultloom_protocol import SCHEMA_VERSION
from faultloom_protocol.models import PackManifest

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class WebLlmWeb3FixtureManifest:
    core_artifact_digest: str
    g42_artifact_digest: str
    pack_adapter_digest: str
    pack_id: str
    adapter_id: str
    semantic_depth: int
    expected_semantic_signatures: tuple[str, ...]
    boundary_crossings: tuple[str, ...]
    initial_state: tuple[tuple[str, object], ...]
    final_state: tuple[tuple[str, object], ...]
    final_inert_canary_effect: str
    action_budget: int
    time_budget_seconds: int
    cost_budget: int
    impact_budget: int
    negative_controls: tuple[str, ...]
    cleanup_contract: str

    def document(self) -> dict[str, object]:
        return {
            "action_budget": self.action_budget,
            "adapter_id": self.adapter_id,
            "boundary_crossings": list(self.boundary_crossings),
            "cleanup_contract": self.cleanup_contract,
            "core_artifact_digest": self.core_artifact_digest,
            "cost_budget": self.cost_budget,
            "expected_semantic_signatures": list(self.expected_semantic_signatures),
            "final_inert_canary_effect": self.final_inert_canary_effect,
            "final_state": dict(self.final_state),
            "g42_artifact_digest": self.g42_artifact_digest,
            "impact_budget": self.impact_budget,
            "initial_state": dict(self.initial_state),
            "negative_controls": list(self.negative_controls),
            "pack_adapter_digest": self.pack_adapter_digest,
            "pack_id": self.pack_id,
            "semantic_depth": self.semantic_depth,
            "time_budget_seconds": self.time_budget_seconds,
        }


def web3_pack_manifest() -> PackManifest:
    """Expose only simulation capabilities; the pack has no external RPC adapter."""

    return PackManifest(
        schema_version=SCHEMA_VERSION,
        pack_id="pack.web3.future-fixture",
        pack_version="0.3.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.web3.v1",
        capability_descriptors=("web3.read_only_analysis",),
        action_compilers=("web3.simulate",),
        observation_normalizers=("web3.simulation_receipt",),
        hypothesis_providers=("web3.invariant_hypothesis",),
        verifier_descriptors=("web3.deterministic_replay",),
        evaluation_descriptors=("web3.invariant_fixture",),
        required_gateway_features=("web3.simulation",),
        required_adapter_capabilities=("web3.read_only_rpc",),
    )


def web_llm_web3_fixture_manifest(
    *,
    core_artifact_digest: str,
    g42_artifact_digest: str,
    pack_adapter_digest: str,
    expected_semantic_signatures: tuple[str, ...],
) -> WebLlmWeb3FixtureManifest:
    """Bind the fixture to digests provisioned by its operator/controller."""

    _require_digest("core_artifact_digest", core_artifact_digest)
    _require_digest("g42_artifact_digest", g42_artifact_digest)
    _require_digest("pack_adapter_digest", pack_adapter_digest)
    if len(expected_semantic_signatures) != 8 or len(set(expected_semantic_signatures)) != 8:
        raise ValueError("G44 requires exactly eight distinct pinned semantic signatures")
    for signature in expected_semantic_signatures:
        _require_digest("expected_semantic_signature", signature)
    return WebLlmWeb3FixtureManifest(
        core_artifact_digest=core_artifact_digest,
        g42_artifact_digest=g42_artifact_digest,
        pack_adapter_digest=pack_adapter_digest,
        pack_id="pack.web3.future-fixture",
        adapter_id="adapter.web3.zero-value-simulator",
        semantic_depth=8,
        expected_semantic_signatures=expected_semantic_signatures,
        boundary_crossings=("web_api_to_llm_mcp", "llm_mcp_to_web3"),
        initial_state=(
            ("api_request_received", False),
            ("synthetic_document_approved", False),
            ("web_to_llm_bridge_authorized", False),
            ("llm_candidate", False),
            ("mcp_candidate", False),
            ("llm_to_web3_bridge_authorized", False),
            ("zero_value_simulated", False),
            ("web3_zero_value_balance", 0),
            ("final_canary", None),
        ),
        final_state=(
            ("api_request_received", True),
            ("synthetic_document_approved", True),
            ("web_to_llm_bridge_authorized", True),
            ("llm_candidate", True),
            ("mcp_candidate", True),
            ("llm_to_web3_bridge_authorized", True),
            ("zero_value_simulated", True),
            ("web3_zero_value_balance", 0),
            ("final_canary", "g44-inert-zero-value-canary"),
        ),
        final_inert_canary_effect="effect.web3.g44-inert-zero-value-canary",
        action_budget=8,
        time_budget_seconds=10,
        cost_budget=0,
        impact_budget=0,
        negative_controls=(
            "remove_web_api_to_llm_mcp_bridge",
            "remove_llm_mcp_to_web3_bridge",
        ),
        cleanup_contract="restore_declared_initial_state",
    )


def _require_digest(field: str, value: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase sha256 digest supplied by the operator")
