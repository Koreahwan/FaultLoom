"""Deterministic, in-memory Web/API -> LLM/MCP -> Web3 G44 fixture."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, cast, final

from faultloom_web3 import CandidateEdge, CandidateEvidence, candidate_evidence
from faultloom_web3.fixture import Boundary, PolicyKind, Surface, canonical_sha256
from faultloom_web3.manifest import WebLlmWeb3FixtureManifest


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
    api_request_received: bool = False
    synthetic_document_approved: bool = False
    web_to_llm_bridge_authorized: bool = False
    llm_candidate: bool = False
    mcp_candidate: bool = False
    llm_to_web3_bridge_authorized: bool = False
    zero_value_simulated: bool = False
    web3_zero_value_balance: int = 0
    final_canary: str | None = None


@dataclass(frozen=True, slots=True)
class BridgeConfiguration:
    web_api_to_llm_mcp: bool = True
    llm_mcp_to_web3: bool = True


def _items(state: FixtureState) -> tuple[tuple[str, object], ...]:
    return tuple(asdict(state).items())


def _transition(
    state: FixtureState, field: str, value: object
) -> tuple[tuple[str, object], tuple[tuple[str, object], ...], FixtureState]:
    updated = replace(state, **{field: value})
    return (field, value), _items(updated), updated


def _build_edges(identities: SyntheticIdentities) -> tuple[CandidateEdge, ...]:
    state = FixtureState()
    definitions = (
        ("web_api", "web_api", "within_surface", (), "api_request_received", True,
         "web_api_owned_request_admission", "lease", identities.web_identity_id, (1, 1, 0, 0)),
        ("web_api", "web_api", "within_surface", ("effect.g44.web-request",),
         "synthetic_document_approved", True, "synthetic_document_policy_selection",
         "no_dispatch", identities.web_identity_id, (0, 0, 0, 0)),
        ("web_api", "llm_mcp", "web_api_to_llm_mcp", ("effect.g44.document",),
         "web_to_llm_bridge_authorized", True, "web_api_to_llm_mcp_boundary",
         "no_dispatch", identities.model_identity_id, (0, 0, 0, 0)),
        ("llm_mcp", "llm_mcp", "within_surface", ("effect.g44.llm-input",),
         "llm_candidate", True, "pinned_loopback_model_observation", "lease",
         identities.model_identity_id, (1, 1, 0, 0)),
        ("llm_mcp", "llm_mcp", "within_surface", ("effect.g44.llm-candidate",),
         "mcp_candidate", True, "pinned_local_mcp_candidate", "lease",
         identities.mcp_identity_id, (1, 1, 0, 0)),
        ("llm_mcp", "web3_simulator", "llm_mcp_to_web3", ("effect.g44.mcp-candidate",),
         "llm_to_web3_bridge_authorized", True, "llm_mcp_to_web3_boundary",
         "no_dispatch", identities.web3_identity_id, (0, 0, 0, 0)),
        ("web3_simulator", "web3_simulator", "within_surface", ("effect.g44.web3-input",),
         "zero_value_simulated", True, "local_zero_value_state_transition", "lease",
         identities.web3_identity_id, (1, 1, 0, 0)),
        ("web3_simulator", "web3_simulator", "within_surface", ("effect.g44.zero-value",),
         "final_canary", "g44-inert-zero-value-canary", "inert_canary_verification",
         "no_dispatch", identities.web3_identity_id, (0, 0, 0, 0)),
    )
    effects = (
        "effect.g44.web-request",
        "effect.g44.document",
        "effect.g44.llm-input",
        "effect.g44.llm-candidate",
        "effect.g44.mcp-candidate",
        "effect.g44.web3-input",
        "effect.g44.zero-value",
        "effect.web3.g44-inert-zero-value-canary",
    )
    edges: list[CandidateEdge] = []
    for definition, effect in zip(definitions, effects, strict=True):
        (
            source, target, boundary, prerequisites, field, value, primitive,
            policy_kind, identity_id, budget,
        ) = definition
        pre_state = _items(state)
        _, post_state, state = _transition(state, field, value)
        edges.append(
            CandidateEdge(
                source_surface=cast(Surface, source),
                target_surface=cast(Surface, target),
                boundary=cast(Boundary, boundary),
                prerequisites=prerequisites,
                effect=effect,
                pre_state=pre_state,
                post_state=post_state,
                primitive=primitive,
                policy_kind=cast(PolicyKind, policy_kind),
                identity_id=identity_id,
                budget=budget,
            )
        )
    return tuple(edges)


@final
class OwnedWebLlmWeb3Fixture:
    """Run eight inert causal edges without RPC, wallet, credential, or asset I/O."""

    endpoint = "in-memory://owned-g44-fixture"
    expected_depth = 8
    initial_state = FixtureState()

    def __init__(self, identities: SyntheticIdentities) -> None:
        identities.validate()
        self.identities = identities
        self.state = self.initial_state
        self.edges = _build_edges(identities)

    def __enter__(self) -> "OwnedWebLlmWeb3Fixture":
        if self.state != self.initial_state:
            raise RuntimeError("G44 fixture must start from its declared initial state")
        return self

    def __exit__(self, *_args: object) -> None:
        self.cleanup()

    def run(self, bridges: BridgeConfiguration | None = None) -> CandidateEvidence:
        if self.state != self.initial_state:
            raise RuntimeError("cleanup is required before another G44 fixture run")
        active = bridges or BridgeConfiguration()
        executed: list[CandidateEdge] = []
        for edge in self.edges:
            if edge.boundary == "web_api_to_llm_mcp" and not active.web_api_to_llm_mcp:
                break
            if edge.boundary == "llm_mcp_to_web3" and not active.llm_mcp_to_web3:
                break
            executed.append(edge)
            self.state = FixtureState(**cast(Any, dict(edge.post_state)))
        return candidate_evidence(tuple(executed), expected_depth=self.expected_depth)

    def cleanup(self) -> None:
        self.state = self.initial_state

    def evidence_bundle(
        self,
        manifest: WebLlmWeb3FixtureManifest,
        *,
        artifact_provenance: dict[str, object],
    ) -> dict[str, object]:
        """Materialize data for a separate verifier; this method makes no verdict."""

        if tuple(edge.semantic_signature for edge in self.edges) != (
            manifest.expected_semantic_signatures
        ):
            raise ValueError("manifest semantic signatures do not match the owned fixture")
        primary_evidence = self.run()
        primary_final_state = asdict(self.state)
        primary = self._run_document(
            "run.g44.primary", manifest, primary_evidence.edge_ids, primary_final_state
        )
        cleanup_before = asdict(self.state)
        self.cleanup()
        cleanup_after = asdict(self.state)

        replay_fixture = OwnedWebLlmWeb3Fixture(self.identities)
        replay_evidence = replay_fixture.run()
        replay = replay_fixture._run_document(
            "run.g44.clean-replay", manifest, replay_evidence.edge_ids,
            asdict(replay_fixture.state),
        )
        replay_fixture.cleanup()
        primary_edges = primary["edges"]
        if not isinstance(primary_edges, list):
            raise TypeError("primary edges must be a list")
        lease_receipts = [
            edge["policy"]["receipt_id"]
            for edge in primary_edges
            if edge["policy"]["kind"] == "lease"
        ]
        no_dispatch_receipts = [
            edge["policy"]["receipt_id"]
            for edge in primary_edges
            if edge["policy"]["kind"] == "no_dispatch"
        ]
        effects = [edge.effect for edge in self.edges]
        state_ids = sorted({
            "state." + canonical_sha256(edge["pre_state"]).removeprefix("sha256:")
            for edge in primary_edges
        } | {
            "state." + canonical_sha256(edge["post_state"]).removeprefix("sha256:")
            for edge in primary_edges
        })
        ids_by_class = {
            "action": ["action." + edge["edge_id"].removeprefix("edge.")
                       for edge in primary_edges if edge["policy"]["kind"] == "lease"],
            "budget_reservation": [f"budget.{receipt.removeprefix('receipt.')}"
                                   for receipt in lease_receipts],
            "chain": ["chain.g44.owned"],
            "edge": [edge.edge_id for edge in self.edges],
            "effect": effects,
            "engagement": ["engagement.g44.owned-simulation"],
            "evidence": lease_receipts + no_dispatch_receipts,
            "hypothesis": ["hypothesis." + canonical_sha256(edge.primitive).removeprefix("sha256:")
                           for edge in self.edges],
            "identity": sorted(asdict(self.identities).values()),
            "lease": lease_receipts,
            "no_dispatch_receipt": no_dispatch_receipts,
            "node": state_ids,
            "pending_action": [],
            "run": ["run.g44.primary"],
            "state": state_ids,
        }
        persistent_ids = sorted({item for values in ids_by_class.values() for item in values})
        controls: list[dict[str, object]] = []
        replay_controls: list[dict[str, object]] = []
        for control_id, boundary in zip(
            manifest.negative_controls, manifest.boundary_crossings, strict=True
        ):
            configuration = (
                BridgeConfiguration(web_api_to_llm_mcp=False)
                if boundary == "web_api_to_llm_mcp"
                else BridgeConfiguration(llm_mcp_to_web3=False)
            )
            control_fixture = OwnedWebLlmWeb3Fixture(self.identities)
            observed = control_fixture.run(configuration)
            observed_state = asdict(control_fixture.state)
            control_fixture.cleanup()
            controls.append(self._control_document(
                control_id, boundary, primary["edges"], observed.edge_ids, observed_state
            ))
            replay_controls.append(self._control_document(
                control_id, boundary, replay["edges"], observed.edge_ids, observed_state
            ))
        return {
            "artifact_provenance": artifact_provenance,
            "classification": "g44_owned_simulated_fixture_evidence",
            "cleanup": {"after": cleanup_after, "before": cleanup_before},
            "manifest": manifest.document(),
            "negative_controls": controls,
            "primary_run": primary,
            "reset": {
                "after_effect_ids": list(effects),
                "after_ids_by_class": {key: list(value) for key, value in ids_by_class.items()},
                "after_persistent_ids": list(persistent_ids),
                "before_effect_ids": list(effects),
                "before_ids_by_class": {key: list(value) for key, value in ids_by_class.items()},
                "before_persistent_ids": list(persistent_ids),
            },
            "schema_version": "faultloom.g44.fixture-evidence.v1",
            "clean_replay": {
                **replay,
                "model_context": [],
                "negative_controls": replay_controls,
                "preseeded_evidence": [],
                "pristine": True,
                "snapshot_digest": canonical_sha256(
                    {"initial_state": dict(manifest.initial_state), "warm_frontier": []}
                ),
                "warm_frontier": [],
            },
        }

    def _run_document(
        self,
        run_id: str,
        manifest: WebLlmWeb3FixtureManifest,
        observed_edge_ids: tuple[str, ...],
        observed_final_state: dict[str, object],
    ) -> dict[str, object]:
        fixture_tick = 100
        edges = [
            edge.document(
                run_id=run_id,
                order=index,
                fixture_tick=fixture_tick,
                pack_id=manifest.pack_id,
                adapter_id=manifest.adapter_id,
            )
            for index, edge in enumerate(self.edges, start=1)
        ]
        return {
            "claimed_minimal_edge_ids": [edge.edge_id for edge in self.edges],
            "edges": edges,
            "final_effect": manifest.final_inert_canary_effect,
            "fixture_tick": fixture_tick,
            "initial_effects": [],
            "initial_state": dict(manifest.initial_state),
            "observed_edge_ids": list(observed_edge_ids),
            "observed_final_state": observed_final_state,
            "run_id": run_id,
        }

    @staticmethod
    def _control_document(
        control_id: str,
        boundary: str,
        run_edges: object,
        observed_edge_ids: tuple[str, ...],
        observed_final_state: dict[str, object],
    ) -> dict[str, object]:
        if not isinstance(run_edges, list):
            raise TypeError("run edges must be a list")
        return {
            "control_id": control_id,
            "edges": [edge for edge in run_edges if edge["boundary"] != boundary],
            "observed_edge_ids": list(observed_edge_ids),
            "observed_final_state": observed_final_state,
            "removed_boundary": boundary,
        }
