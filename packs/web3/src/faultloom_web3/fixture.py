"""Candidate-evidence contracts for the inert G44 fixture."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Surface = Literal["web_api", "llm_mcp", "web3_simulator"]
Bridge = Literal["within_surface", "web_api_to_llm_mcp", "llm_mcp_to_web3"]
G44_EXPECTED_SEMANTIC_SIGNATURES = (
    "web_api.request_received",
    "web_api.synthetic_document_selected",
    "bridge.web_api_to_llm_mcp",
    "llm.synthetic_instruction_observed",
    "mcp.zero_value_tool_candidate",
    "bridge.llm_mcp_to_web3",
    "web3.zero_value_simulation",
    "web3.inert_canary_observed",
)
G44_EXPECTED_SURFACE_TRANSITIONS: tuple[tuple[Surface, Surface], ...] = (
    ("web_api", "web_api"),
    ("web_api", "web_api"),
    ("web_api", "llm_mcp"),
    ("llm_mcp", "llm_mcp"),
    ("llm_mcp", "llm_mcp"),
    ("llm_mcp", "web3_simulator"),
    ("web3_simulator", "web3_simulator"),
    ("web3_simulator", "web3_simulator"),
)
G44_EXPECTED_BRIDGES: tuple[Bridge, ...] = (
    "within_surface",
    "within_surface",
    "web_api_to_llm_mcp",
    "within_surface",
    "within_surface",
    "llm_mcp_to_web3",
    "within_surface",
    "within_surface",
)
G44_EXPECTED_EFFECTS = (
    "effect.g44.web-request",
    "effect.g44.document",
    "effect.g44.llm-input",
    "effect.g44.llm-candidate",
    "effect.g44.mcp-candidate",
    "effect.g44.web3-input",
    "effect.g44.zero-value",
    "effect.web3.g44-inert-zero-value-canary",
)
G44_FINAL_STATE_ID = "state.g44.final-inert-canary"


@dataclass(frozen=True, slots=True)
class CandidateEdge:
    edge_id: str
    source_surface: Surface
    target_surface: Surface
    bridge: Bridge
    lease_id: str
    semantic_signature: str
    effect_id: str


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    classification: Literal["candidate_only"]
    edge_ids: tuple[str, ...]
    lease_ids: tuple[str, ...]
    semantic_signatures: tuple[str, ...]
    final_canary_reached: bool
    final_effect_id: str | None
    final_state_id: str | None
    lost_ids: int
    duplicate_effects: int


def candidate_evidence(
    executed: tuple[CandidateEdge, ...], *, expected_depth: int
) -> CandidateEvidence:
    """Record deterministic candidate evidence without claiming verification."""

    edge_ids = tuple(edge.edge_id for edge in executed)
    lease_ids = tuple(edge.lease_id for edge in executed)
    effects = tuple(edge.effect_id for edge in executed)
    if len(set(edge_ids)) != len(edge_ids) or len(set(lease_ids)) != len(lease_ids):
        raise ValueError("every candidate edge and lease must be unique")
    signatures = tuple(edge.semantic_signature for edge in executed)
    transitions = tuple(
        (edge.source_surface, edge.target_surface) for edge in executed
    )
    bridges = tuple(edge.bridge for edge in executed)
    surface_continuity = all(
        left.target_surface == right.source_surface
        for left, right in zip(executed, executed[1:], strict=False)
    )
    duplicate_effects = len(effects) - len(set(effects))
    final_reached = (
        expected_depth == len(G44_EXPECTED_SEMANTIC_SIGNATURES)
        and signatures == G44_EXPECTED_SEMANTIC_SIGNATURES
        and transitions == G44_EXPECTED_SURFACE_TRANSITIONS
        and bridges == G44_EXPECTED_BRIDGES
        and effects == G44_EXPECTED_EFFECTS
        and surface_continuity
    )
    return CandidateEvidence(
        classification="candidate_only",
        edge_ids=edge_ids,
        lease_ids=lease_ids,
        semantic_signatures=signatures,
        final_canary_reached=final_reached,
        final_effect_id=effects[-1] if final_reached else None,
        final_state_id=G44_FINAL_STATE_ID if final_reached else None,
        lost_ids=0,
        duplicate_effects=duplicate_effects,
    )
