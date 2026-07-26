"""Deterministic in-memory Web/API -> LLM/MCP -> Web3 fixture."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import final

from faultloom_web3 import CandidateEdge, CandidateEvidence, candidate_evidence


@dataclass(frozen=True, slots=True)
class SyntheticIdentities:
    web_identity_id: str
    model_identity_id: str
    mcp_identity_id: str
    web3_identity_id: str

    def validate(self) -> None:
        values = (
            self.web_identity_id,
            self.model_identity_id,
            self.mcp_identity_id,
            self.web3_identity_id,
        )
        if any(not value.startswith("synthetic.") for value in values):
            raise ValueError("G44 accepts only operator-provisioned synthetic identities")
        if len(set(values)) != len(values):
            raise ValueError("each G44 surface requires a distinct synthetic identity")


@dataclass(frozen=True, slots=True)
class FixtureState:
    api_nonce: int = 0
    llm_candidate: bool = False
    mcp_candidate: bool = False
    web3_zero_value_balance: int = 0
    final_canary: str | None = None


@dataclass(frozen=True, slots=True)
class BridgeConfiguration:
    web_api_to_llm_mcp: bool = True
    llm_mcp_to_web3: bool = True


@final
class OwnedWebLlmWeb3Fixture:
    """Run eight inert causal edges without network, wallet, credential, or asset I/O."""

    endpoint = "http://127.0.0.1/owned-g44-fixture"
    expected_depth = 8
    initial_state = FixtureState()

    def __init__(self, identities: SyntheticIdentities) -> None:
        identities.validate()
        self.identities = identities
        self.state = self.initial_state

    def __enter__(self) -> "OwnedWebLlmWeb3Fixture":
        if self.state != self.initial_state:
            raise RuntimeError("G44 fixture must start from its declared initial state")
        return self

    def __exit__(self, *_args: object) -> None:
        self.cleanup()

    def run(self, bridges: BridgeConfiguration | None = None) -> CandidateEvidence:
        if self.state != self.initial_state:
            raise RuntimeError("cleanup is required before another G44 fixture run")
        active_bridges = bridges or BridgeConfiguration()
        executed: list[CandidateEdge] = []
        for edge in _EDGES:
            if (
                edge.bridge == "web_api_to_llm_mcp"
                and not active_bridges.web_api_to_llm_mcp
            ):
                break
            if (
                edge.bridge == "llm_mcp_to_web3"
                and not active_bridges.llm_mcp_to_web3
            ):
                break
            executed.append(edge)
            self._apply(edge)
        return candidate_evidence(tuple(executed), expected_depth=self.expected_depth)

    def cleanup(self) -> None:
        self.state = self.initial_state

    def _apply(self, edge: CandidateEdge) -> None:
        if edge.edge_id == "edge.01.web-request":
            self.state = replace(self.state, api_nonce=1)
        elif edge.edge_id == "edge.04.llm-candidate":
            self.state = replace(self.state, llm_candidate=True)
        elif edge.edge_id == "edge.05.mcp-candidate":
            self.state = replace(self.state, mcp_candidate=True)
        elif edge.edge_id == "edge.08.final-canary":
            self.state = replace(self.state, final_canary="g44-inert-zero-value-canary")


_EDGES = (
    CandidateEdge(
        "edge.01.web-request", "web_api", "web_api", "within_surface",
        "lease.g44.01", "web_api.request_received", "effect.g44.web-request",
    ),
    CandidateEdge(
        "edge.02.document", "web_api", "web_api", "within_surface",
        "lease.g44.02", "web_api.synthetic_document_selected", "effect.g44.document",
    ),
    CandidateEdge(
        "edge.03.web-to-llm", "web_api", "llm_mcp", "web_api_to_llm_mcp",
        "lease.g44.03", "bridge.web_api_to_llm_mcp", "effect.g44.llm-input",
    ),
    CandidateEdge(
        "edge.04.llm-candidate", "llm_mcp", "llm_mcp", "within_surface",
        "lease.g44.04", "llm.synthetic_instruction_observed", "effect.g44.llm-candidate",
    ),
    CandidateEdge(
        "edge.05.mcp-candidate", "llm_mcp", "llm_mcp", "within_surface",
        "lease.g44.05", "mcp.zero_value_tool_candidate", "effect.g44.mcp-candidate",
    ),
    CandidateEdge(
        "edge.06.llm-to-web3", "llm_mcp", "web3_simulator", "llm_mcp_to_web3",
        "lease.g44.06", "bridge.llm_mcp_to_web3", "effect.g44.web3-input",
    ),
    CandidateEdge(
        "edge.07.zero-value", "web3_simulator", "web3_simulator", "within_surface",
        "lease.g44.07", "web3.zero_value_simulation", "effect.g44.zero-value",
    ),
    CandidateEdge(
        "edge.08.final-canary", "web3_simulator", "web3_simulator", "within_surface",
        "lease.g44.08", "web3.inert_canary_observed",
        "effect.web3.g44-inert-zero-value-canary",
    ),
)
