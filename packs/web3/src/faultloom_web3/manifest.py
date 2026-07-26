"""Public manifests for the owned G44 Web/LLM/Web3 fixture slice."""

from __future__ import annotations

import re
from dataclasses import dataclass

from faultloom_protocol import SCHEMA_VERSION
from faultloom_protocol.models import PackManifest

from .fixture import (
    G44_EXPECTED_BRIDGES,
    G44_EXPECTED_SEMANTIC_SIGNATURES,
    G44_FINAL_STATE_ID,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class WebLlmWeb3FixtureManifest:
    core_g42_digest: str
    pack_adapter_digest: str
    pack_id: str
    adapter_id: str
    semantic_depth: int
    expected_semantic_signatures: tuple[str, ...]
    boundary_crossings: tuple[str, ...]
    initial_state: tuple[tuple[str, object], ...]
    final_state: tuple[tuple[str, object], ...]
    final_state_id: str
    final_inert_canary_effect: str
    action_budget: int
    time_budget_seconds: int
    cost_budget: int
    impact_budget: int
    negative_controls: tuple[str, ...]
    cleanup_contract: str


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
    *, core_g42_digest: str, pack_adapter_digest: str
) -> WebLlmWeb3FixtureManifest:
    """Bind the fixture to digests provisioned by its operator/controller."""

    _require_digest("core_g42_digest", core_g42_digest)
    _require_digest("pack_adapter_digest", pack_adapter_digest)
    return WebLlmWeb3FixtureManifest(
        core_g42_digest=core_g42_digest,
        pack_adapter_digest=pack_adapter_digest,
        pack_id="pack.web3.future-fixture",
        adapter_id="adapter.web3.zero-value-simulator",
        semantic_depth=8,
        expected_semantic_signatures=G44_EXPECTED_SEMANTIC_SIGNATURES,
        boundary_crossings=tuple(
            bridge for bridge in G44_EXPECTED_BRIDGES if bridge != "within_surface"
        ),
        initial_state=(
            ("api_nonce", 0),
            ("llm_candidate", False),
            ("mcp_candidate", False),
            ("web3_zero_value_balance", 0),
            ("final_canary", None),
        ),
        final_state=(
            ("api_nonce", 1),
            ("llm_candidate", True),
            ("mcp_candidate", True),
            ("web3_zero_value_balance", 0),
            ("final_canary", "g44-inert-zero-value-canary"),
        ),
        final_state_id=G44_FINAL_STATE_ID,
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
