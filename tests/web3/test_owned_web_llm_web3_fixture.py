from __future__ import annotations

import pytest

from faultloom_web3 import CandidateEdge, candidate_evidence, web_llm_web3_fixture_manifest
from faultloom_web3.fixture import Bridge, Surface
from labs.web_llm_web3 import (
    BridgeConfiguration,
    FixtureState,
    OwnedWebLlmWeb3Fixture,
    SyntheticIdentities,
)


CORE_G42_DIGEST = "sha256:" + "42" * 32
PACK_ADAPTER_DIGEST = "sha256:" + "44" * 32


def identities() -> SyntheticIdentities:
    return SyntheticIdentities(
        web_identity_id="synthetic.operator.web",
        model_identity_id="synthetic.operator.model",
        mcp_identity_id="synthetic.operator.mcp",
        web3_identity_id="synthetic.operator.web3",
    )


def test_positive_candidate_has_eight_causal_edges_and_unique_leases() -> None:
    manifest = web_llm_web3_fixture_manifest(
        core_g42_digest=CORE_G42_DIGEST,
        pack_adapter_digest=PACK_ADAPTER_DIGEST,
    )
    fixture = OwnedWebLlmWeb3Fixture(identities())

    with fixture:
        evidence = fixture.run()
        final_state = fixture.state

    assert evidence.classification == "candidate_only"
    assert evidence.final_canary_reached
    assert evidence.final_effect_id == manifest.final_inert_canary_effect
    assert evidence.final_state_id == manifest.final_state_id
    assert len(evidence.edge_ids) == manifest.semantic_depth == 8
    assert evidence.semantic_signatures == manifest.expected_semantic_signatures
    assert len(set(evidence.lease_ids)) == 8
    assert evidence.lost_ids == 0
    assert evidence.duplicate_effects == 0
    assert final_state == FixtureState(
        api_nonce=1,
        llm_candidate=True,
        mcp_candidate=True,
        web3_zero_value_balance=0,
        final_canary="g44-inert-zero-value-canary",
    )
    assert fixture.state == fixture.initial_state


@pytest.mark.parametrize(
    "bridges,expected_depth",
    (
        (BridgeConfiguration(web_api_to_llm_mcp=False), 2),
        (BridgeConfiguration(llm_mcp_to_web3=False), 5),
    ),
)
def test_removing_either_bridge_makes_final_canary_unreachable(
    bridges: BridgeConfiguration, expected_depth: int
) -> None:
    fixture = OwnedWebLlmWeb3Fixture(identities())

    with fixture:
        evidence = fixture.run(bridges)

    assert len(evidence.edge_ids) == expected_depth
    assert not evidence.final_canary_reached
    assert evidence.final_effect_id is None
    assert evidence.final_state_id is None
    assert fixture.state == fixture.initial_state


def test_manifest_rejects_unpinned_or_malformed_digests() -> None:
    with pytest.raises(ValueError, match="core_g42_digest"):
        _ = web_llm_web3_fixture_manifest(
            core_g42_digest="latest",
            pack_adapter_digest=PACK_ADAPTER_DIGEST,
        )
    with pytest.raises(ValueError, match="pack_adapter_digest"):
        _ = web_llm_web3_fixture_manifest(
            core_g42_digest=CORE_G42_DIGEST,
            pack_adapter_digest="sha256:NOT-PINNED",
        )


def test_mixed_chain_with_right_count_and_final_suffix_cannot_claim_canary() -> None:
    signatures = (
        "web_api.request_received",
        "web_api.synthetic_document_selected",
        "bridge.web_api_to_llm_mcp",
        "unrelated.injected-candidate",
        "mcp.zero_value_tool_candidate",
        "bridge.llm_mcp_to_web3",
        "web3.zero_value_simulation",
        "web3.inert_canary_observed",
    )
    surfaces: tuple[tuple[Surface, Surface, Bridge], ...] = (
        ("web_api", "web_api", "within_surface"),
        ("web_api", "web_api", "within_surface"),
        ("web_api", "llm_mcp", "web_api_to_llm_mcp"),
        ("web_api", "llm_mcp", "within_surface"),
        ("llm_mcp", "llm_mcp", "within_surface"),
        ("llm_mcp", "web3_simulator", "llm_mcp_to_web3"),
        ("web3_simulator", "web3_simulator", "within_surface"),
        ("web3_simulator", "web3_simulator", "within_surface"),
    )
    effects = (
        "effect.g44.web-request",
        "effect.g44.document",
        "effect.g44.llm-input",
        "effect.unrelated.injected-candidate",
        "effect.g44.mcp-candidate",
        "effect.g44.web3-input",
        "effect.g44.zero-value",
        "effect.web3.g44-inert-zero-value-canary",
    )
    mixed = tuple(
        CandidateEdge(
            edge_id=f"edge.mixed.{index}",
            source_surface=surfaces[index][0],
            target_surface=surfaces[index][1],
            bridge=surfaces[index][2],
            lease_id=f"lease.mixed.{index}",
            semantic_signature=signatures[index],
            effect_id=effects[index],
        )
        for index in range(8)
    )

    evidence = candidate_evidence(mixed, expected_depth=8)

    assert not evidence.final_canary_reached
    assert evidence.final_effect_id is None
    assert evidence.final_state_id is None


def test_real_or_reused_identity_is_rejected_before_run() -> None:
    with pytest.raises(ValueError, match="only operator-provisioned synthetic"):
        _ = OwnedWebLlmWeb3Fixture(
            SyntheticIdentities(
                web_identity_id="production.wallet",
                model_identity_id="synthetic.operator.model",
                mcp_identity_id="synthetic.operator.mcp",
                web3_identity_id="synthetic.operator.web3",
            )
        )
