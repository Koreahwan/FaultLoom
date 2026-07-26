"""Data contracts for the inert G44 fixture.

This module constructs canonical records.  Verification is deliberately kept in
``verifier.py`` so a verifier can consume JSON without importing or running the lab.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal


Surface = Literal["web_api", "llm_mcp", "web3_simulator"]
Boundary = Literal["within_surface", "web_api_to_llm_mcp", "llm_mcp_to_web3"]
PolicyKind = Literal["lease", "no_dispatch"]


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CandidateEdge:
    source_surface: Surface
    target_surface: Surface
    boundary: Boundary
    prerequisites: tuple[str, ...]
    effect: str
    pre_state: tuple[tuple[str, object], ...]
    post_state: tuple[tuple[str, object], ...]
    primitive: str
    policy_kind: PolicyKind
    identity_id: str
    budget: tuple[int, int, int, int]

    @property
    def semantic_signature(self) -> str:
        return canonical_sha256(self.semantic_document())

    @property
    def edge_id(self) -> str:
        return "edge." + canonical_sha256(
            {
                "boundary": self.boundary,
                "semantic_signature": self.semantic_signature,
                "source_surface": self.source_surface,
                "target_surface": self.target_surface,
            }
        ).removeprefix("sha256:")

    def semantic_document(self) -> dict[str, object]:
        return {
            "effect": self.effect,
            "post_state": dict(self.post_state),
            "pre_state": dict(self.pre_state),
            "prerequisites": list(self.prerequisites),
            "primitive": self.primitive,
        }

    def document(
        self,
        *,
        run_id: str,
        order: int,
        fixture_tick: int,
        pack_id: str,
        adapter_id: str,
    ) -> dict[str, object]:
        policy = self._policy_document(
            run_id=run_id,
            fixture_tick=fixture_tick,
            pack_id=pack_id,
            adapter_id=adapter_id,
        )
        return {
            "boundary": self.boundary,
            "budget": list(self.budget),
            "edge_id": self.edge_id,
            "effect": self.effect,
            "identity_id": self.identity_id,
            "order": order,
            "policy": policy,
            "post_state": dict(self.post_state),
            "pre_state": dict(self.pre_state),
            "prerequisites": list(self.prerequisites),
            "primitive": self.primitive,
            "semantic_signature": self.semantic_signature,
            "source_surface": self.source_surface,
            "target_surface": self.target_surface,
        }

    def _policy_document(
        self,
        *,
        run_id: str,
        fixture_tick: int,
        pack_id: str,
        adapter_id: str,
    ) -> dict[str, object]:
        common: dict[str, object] = {
            "edge_id": self.edge_id,
            "semantic_signature": self.semantic_signature,
        }
        if self.policy_kind == "no_dispatch":
            body = {
                **common,
                "dispatch": False,
                "kind": "no_dispatch",
                "reason": "structural_verification_only",
            }
        else:
            body = {
                **common,
                "adapter_id": adapter_id,
                "authority_epoch": "epoch.g44.owned-fixture.1",
                "budget_reservation": list(self.budget),
                "cleanup_obligation": "restore_declared_initial_state",
                "compiled_action": f"inert-local:{self.primitive}",
                "engagement_id": "engagement.g44.owned-simulation",
                "expires_at_tick": fixture_tick + 10,
                "identity_id": self.identity_id,
                "intent": "owned_inert_fixture_transition",
                "issued_at_tick": fixture_tick,
                "kind": "lease",
                "pack_id": pack_id,
                "reversible": True,
                "run_id": run_id,
                "scope_decision": "allow_owned_inert_simulation_only",
            }
        return {**body, "receipt_id": "receipt." + canonical_sha256(body).removeprefix("sha256:")}


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    classification: Literal["candidate_only"]
    edge_ids: tuple[str, ...]
    semantic_signatures: tuple[str, ...]
    final_canary_reached: bool
    final_effect_id: str | None
    lost_ids: int
    duplicate_effects: int


def candidate_evidence(
    executed: tuple[CandidateEdge, ...], *, expected_depth: int
) -> CandidateEvidence:
    """Retain the small candidate summary; it is not an independent verdict."""

    edge_ids = tuple(edge.edge_id for edge in executed)
    signatures = tuple(edge.semantic_signature for edge in executed)
    effects = tuple(edge.effect for edge in executed)
    unique = len(edge_ids) == len(set(edge_ids)) == expected_depth
    final_reached = unique and effects[-1:] == ("effect.web3.g44-inert-zero-value-canary",)
    return CandidateEvidence(
        classification="candidate_only",
        edge_ids=edge_ids,
        semantic_signatures=signatures,
        final_canary_reached=final_reached,
        final_effect_id=effects[-1] if final_reached else None,
        lost_ids=0,
        duplicate_effects=len(effects) - len(set(effects)),
    )
