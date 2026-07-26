"""Externally admitted inert fixtures for G42 semantic-depth gates.

The helpers never dispatch an action and do not issue authority or Gateway
leases.  Every retained edge instead requires a caller-supplied Ed25519-signed
admission token from a pinned external verifier before budget accounting.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    canonical_json_bytes,
    load_public_key,
)

from .semantic_depth import (
    ZERO_BUDGET,
    BudgetVector,
    RunClass,
    SearchCheckpoint,
    SearchConfig,
    SemanticDepthEngine,
    SemanticEdge,
    SemanticGraph,
    SemanticWitness,
)


BudgetOperation = Literal["reserve", "consume", "release"]


class ExternalInertAdmissionError(ValueError):
    """An external inert-edge admission is absent, invalid, or already used."""


def _content_id(prefix: str, value: object) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"{prefix}.{hashlib.sha256(canonical).hexdigest()}"


def _require_text(value: str, name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{name} must be non-empty canonical text")


def _parse_expiry(value: str) -> datetime:
    _require_text(value, "expires_at")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError("expires_at must be canonical UTC seconds") from exc
    if (
        parsed.tzinfo != timezone.utc
        or parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value
    ):
        raise ValueError("expires_at must be canonical UTC seconds")
    return parsed


def _decode_signature(value: str) -> bytes:
    _require_text(value, "signature")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError) as exc:
        raise ExternalInertAdmissionError("admission signature is invalid") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value or len(decoded) != 64:
        raise ExternalInertAdmissionError("admission signature is invalid")
    return decoded


@dataclass(frozen=True, slots=True)
class InertDepthFixture:
    """A generated, deterministic graph and its matched negative control."""

    depth: int
    graph: SemanticGraph
    negative_graph: SemanticGraph
    config: SearchConfig
    provenance: Literal["fully_simulated"] = "fully_simulated"


@dataclass(frozen=True, slots=True)
class InertEdgeAdmission:
    authority_id: str
    edge_id: str
    edge_fingerprint: str
    run_id: str
    run_class: RunClass | None
    expires_at: str
    remaining_budget: BudgetVector
    lease_id: str
    lease_epoch: str
    verifier_key_id: str

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "edge_id",
            "edge_fingerprint",
            "run_id",
            "lease_id",
            "lease_epoch",
            "verifier_key_id",
        ):
            _require_text(getattr(self, name), name)
        if self.run_class not in (
            None,
            "generated_structural_conformance",
            "exploratory_research_run",
        ):
            raise ValueError("admission run_class is invalid")
        _parse_expiry(self.expires_at)

    def document(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "edge_fingerprint": self.edge_fingerprint,
            "edge_id": self.edge_id,
            "expires_at": self.expires_at,
            "lease_epoch": self.lease_epoch,
            "lease_id": self.lease_id,
            "remaining_budget": self.remaining_budget.document(),
            "run_class": self.run_class,
            "run_id": self.run_id,
            "verifier_key_id": self.verifier_key_id,
        }


def inert_edge_admission_bytes(admission: InertEdgeAdmission) -> bytes:
    if type(admission) is not InertEdgeAdmission:
        raise TypeError("admission must be an exact InertEdgeAdmission")
    return canonical_json_bytes(
        {"admission": admission.document(), "purpose": "faultloom.g42.inert_edge.v1"}
    )


@dataclass(frozen=True, slots=True)
class SignedInertEdgeAdmission:
    admission: InertEdgeAdmission
    signature: str

    @property
    def token_id(self) -> str:
        return _content_id(
            "inert-admission-token",
            {"admission": self.admission.document(), "signature": self.signature},
        )


@dataclass(frozen=True, slots=True)
class ExternallyAdmittedInertEdgeReceipt:
    admission_token_id: str
    authority_id: str
    edge_id: str
    edge_fingerprint: str
    run_id: str
    run_class: RunClass | None
    expires_at: str
    external_lease_id: str
    lease_epoch: str
    verifier_key_id: str
    disposition: Literal["externally_admitted_inert_edge"]
    gateway_lease: Literal[False]

    def document(self) -> dict[str, object]:
        return {
            "admission_token_id": self.admission_token_id,
            "authority_id": self.authority_id,
            "disposition": self.disposition,
            "edge_fingerprint": self.edge_fingerprint,
            "edge_id": self.edge_id,
            "expires_at": self.expires_at,
            "external_lease_id": self.external_lease_id,
            "gateway_lease": self.gateway_lease,
            "lease_epoch": self.lease_epoch,
            "run_class": self.run_class,
            "run_id": self.run_id,
            "verifier_key_id": self.verifier_key_id,
        }


@dataclass(frozen=True, slots=True)
class BudgetReceipt:
    admission_token_id: str
    reservation_id: str
    edge_id: str
    operation: BudgetOperation
    amount: BudgetVector
    remaining: BudgetVector

    def document(self) -> dict[str, object]:
        return {
            "admission_token_id": self.admission_token_id,
            "amount": self.amount.document(),
            "edge_id": self.edge_id,
            "operation": self.operation,
            "remaining": self.remaining.document(),
            "reservation_id": self.reservation_id,
        }


@dataclass(frozen=True, slots=True)
class InertGateReceipt:
    run_id: str
    clean_replay_run_id: str
    run_class: RunClass | None
    expected_depth: int
    witness: SemanticWitness
    clean_replay_witness: SemanticWitness
    negative_terminal_reason: str
    checkpoint_json: str
    edge_admission_receipts: tuple[ExternallyAdmittedInertEdgeReceipt, ...]
    clean_replay_edge_admission_receipts: tuple[
        ExternallyAdmittedInertEdgeReceipt, ...
    ]
    budget_receipts: tuple[BudgetReceipt, ...]
    clean_replay_budget_receipts: tuple[BudgetReceipt, ...]
    lost_ids: int
    duplicate_effects: int
    cleanup_result: Literal["initial_state_restored"]

    def document(self) -> dict[str, object]:
        return {
            "budget_receipts": [item.document() for item in self.budget_receipts],
            "clean_replay_budget_receipts": [
                item.document() for item in self.clean_replay_budget_receipts
            ],
            "checkpoint_json": self.checkpoint_json,
            "clean_replay_run_id": self.clean_replay_run_id,
            "clean_replay_edge_admission_receipts": [
                item.document() for item in self.clean_replay_edge_admission_receipts
            ],
            "clean_replay_witness": _witness_document(self.clean_replay_witness),
            "cleanup_result": self.cleanup_result,
            "duplicate_effects": self.duplicate_effects,
            "edge_admission_receipts": [
                item.document() for item in self.edge_admission_receipts
            ],
            "expected_depth": self.expected_depth,
            "lost_ids": self.lost_ids,
            "negative_terminal_reason": self.negative_terminal_reason,
            "run_class": self.run_class,
            "run_id": self.run_id,
            "witness": _witness_document(self.witness),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )


def _witness_document(witness: SemanticWitness) -> dict[str, object]:
    return {
        "consumed": witness.consumed.document(),
        "edge_ids": list(witness.edge_ids),
        "final_effect": witness.final_effect,
        "semantic_depth": witness.semantic_depth,
        "semantic_edge_ids": list(witness.semantic_edge_ids),
    }


def build_inert_depth_fixture(depth: int) -> InertDepthFixture:
    """Build one positive chain and a matched broken-chain negative control."""

    if depth < 1:
        raise ValueError("fixture depth must be positive")
    edges = tuple(
        SemanticEdge(
            source=f"node.{index - 1}",
            target=f"node.{index}",
            prerequisites=("seed" if index == 1 else f"effect.{index - 1}",),
            effect=f"effect.{index}",
            pre_state=f"state.{index - 1}",
            post_state=f"state.{index}",
            primitive=f"primitive.{index}",
            budget=BudgetVector(actions=1, time=2, cost=3, impact=1),
        )
        for index in range(1, depth + 1)
    )
    graph = SemanticGraph.build(
        initial_node="node.0",
        initial_state="state.0",
        initial_effects=("seed",),
        final_effect=f"effect.{depth}",
        edges=edges,
    )
    missing_id = edges[depth // 2].edge_id
    negative_graph = SemanticGraph.build(
        initial_node=graph.initial_node,
        initial_state=graph.initial_state,
        initial_effects=graph.initial_effects,
        final_effect=graph.final_effect,
        edges=tuple(edge for edge in edges if edge.edge_id != missing_id),
    )
    run_class: RunClass | None = (
        "generated_structural_conformance" if depth > 10 else None
    )
    config = SearchConfig(
        research_bound=depth,
        budget=BudgetVector(depth, depth * 2, depth * 3, depth),
        identity_id="identity.g42.inert",
        tenant_id="tenant.g42.inert",
        authority_epoch="epoch.g42.inert.1",
        pending_effect_disposition="none",
        run_class=run_class,
    )
    return InertDepthFixture(depth, graph, negative_graph, config)


def inert_fixture_run_id(
    fixture: InertDepthFixture, *, clean_replay: bool = False
) -> str:
    purpose = "clean_replay" if clean_replay else "primary"
    return _content_id(
        "semantic-run",
        {
            "config_id": fixture.config.config_id,
            "graph_id": fixture.graph.graph_id,
            "purpose": purpose,
        },
    )


def inert_edge_fingerprint(edge: SemanticEdge) -> str:
    if type(edge) is not SemanticEdge:
        raise TypeError("edge must be an exact SemanticEdge")
    return _content_id("inert-edge-fingerprint", edge.document())


class ExternalInertAdmissionVerifier:
    """Verify externally issued inert admissions and consume each exactly once."""

    __slots__ = (
        "_authority_id",
        "_consumed_edges",
        "_consumed_lease_ids",
        "_consumed_tokens",
        "_lease_epoch",
        "_public_key",
        "_run_class",
        "_run_id",
        "_verification_time",
        "_verifier_key_id",
    )

    def __init__(
        self,
        *,
        trusted_verifier_key: Ed25519PublicKeyRecord,
        verification_time: datetime,
        authority_id: str,
        run_id: str,
        run_class: RunClass | None,
        lease_epoch: str,
    ) -> None:
        if type(trusted_verifier_key) is not Ed25519PublicKeyRecord:
            raise ExternalInertAdmissionError(
                "inert admission requires an exact pinned verifier key"
            )
        if verification_time.tzinfo != timezone.utc:
            raise ExternalInertAdmissionError("verification_time must be UTC")
        for value, name in (
            (authority_id, "authority_id"),
            (run_id, "run_id"),
            (lease_epoch, "lease_epoch"),
        ):
            _require_text(value, name)
        try:
            public_key = load_public_key(trusted_verifier_key)
        except ValueError as exc:
            raise ExternalInertAdmissionError("pinned verifier key is invalid") from exc
        if not isinstance(public_key, Ed25519PublicKey):
            raise ExternalInertAdmissionError("pinned verifier key is invalid")
        self._authority_id = authority_id
        self._consumed_edges: set[str] = set()
        self._consumed_lease_ids: set[str] = set()
        self._consumed_tokens: set[str] = set()
        self._lease_epoch = lease_epoch
        self._public_key = public_key
        self._run_class = run_class
        self._run_id = run_id
        self._verification_time = verification_time
        self._verifier_key_id = trusted_verifier_key.key_id

    def admit(
        self,
        token: SignedInertEdgeAdmission,
        *,
        edge: SemanticEdge,
        expected_remaining: BudgetVector,
    ) -> ExternallyAdmittedInertEdgeReceipt:
        if type(token) is not SignedInertEdgeAdmission:
            raise ExternalInertAdmissionError(
                "edge requires an exact signed external admission token"
            )
        admission = token.admission
        if type(admission) is not InertEdgeAdmission:
            raise ExternalInertAdmissionError("admission payload type is invalid")
        try:
            self._public_key.verify(
                _decode_signature(token.signature),
                inert_edge_admission_bytes(admission),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ExternalInertAdmissionError("admission signature is invalid") from exc
        token_id = token.token_id
        if (
            token_id in self._consumed_tokens
            or admission.lease_id in self._consumed_lease_ids
            or edge.edge_id in self._consumed_edges
        ):
            raise ExternalInertAdmissionError(
                "admission token, external lease, or edge was already consumed"
            )
        if admission.verifier_key_id != self._verifier_key_id:
            raise ExternalInertAdmissionError("admission verifier key is not pinned")
        if admission.authority_id != self._authority_id:
            raise ExternalInertAdmissionError("admission authority does not match")
        if admission.run_id != self._run_id or admission.run_class != self._run_class:
            raise ExternalInertAdmissionError("admission run binding does not match")
        if admission.lease_epoch != self._lease_epoch:
            raise ExternalInertAdmissionError("admission lease epoch does not match")
        if admission.edge_id != edge.edge_id:
            raise ExternalInertAdmissionError("admission is bound to another edge")
        if admission.edge_fingerprint != inert_edge_fingerprint(edge):
            raise ExternalInertAdmissionError("admission edge fingerprint does not match")
        if not edge.budget.fits(admission.remaining_budget):
            raise ExternalInertAdmissionError("admission budget is exceeded")
        if admission.remaining_budget != expected_remaining:
            raise ExternalInertAdmissionError("admission remaining budget does not match")
        if self._verification_time >= _parse_expiry(admission.expires_at):
            raise ExternalInertAdmissionError("admission token is expired")
        self._consumed_tokens.add(token_id)
        self._consumed_lease_ids.add(admission.lease_id)
        self._consumed_edges.add(edge.edge_id)
        return ExternallyAdmittedInertEdgeReceipt(
            admission_token_id=token_id,
            authority_id=admission.authority_id,
            edge_id=admission.edge_id,
            edge_fingerprint=admission.edge_fingerprint,
            run_id=admission.run_id,
            run_class=admission.run_class,
            expires_at=admission.expires_at,
            external_lease_id=admission.lease_id,
            lease_epoch=admission.lease_epoch,
            verifier_key_id=admission.verifier_key_id,
            disposition="externally_admitted_inert_edge",
            gateway_lease=False,
        )


def execute_inert_gate(
    fixture: InertDepthFixture,
    *,
    admission_tokens: tuple[SignedInertEdgeAdmission, ...],
    clean_replay_admission_tokens: tuple[SignedInertEdgeAdmission, ...],
    admission_verifier: ExternalInertAdmissionVerifier,
    clean_replay_admission_verifier: ExternalInertAdmissionVerifier,
) -> InertGateReceipt:
    """Checkpoint, resume, clean-replay, and negatively control one fixture."""

    engine = SemanticDepthEngine(fixture.graph)
    interrupted = engine.search(fixture.config, max_expansions=fixture.depth)
    if interrupted.terminal_reason != "checkpointed":
        raise ValueError("fixture did not produce the required interrupted checkpoint")
    checkpoint_json = interrupted.checkpoint.to_json()
    restored = SearchCheckpoint.from_json(checkpoint_json)
    resumed = SemanticDepthEngine(restored.graph).search(
        restored.config,
        checkpoint=restored,
    )
    if resumed.witness is None or resumed.terminal_reason != "verified":
        raise ValueError("fixture did not produce a verified resumed witness")

    pristine_graph = SemanticGraph.from_document(fixture.graph.document())
    pristine_config = SearchConfig.from_document(fixture.config.document())
    clean_replay = SemanticDepthEngine(pristine_graph).search(pristine_config)
    if clean_replay.witness is None or clean_replay.terminal_reason != "verified":
        raise ValueError("fixture did not produce a verified clean replay")
    if clean_replay.witness != resumed.witness:
        raise ValueError("clean replay did not reproduce the resumed witness")

    negative = SemanticDepthEngine(fixture.negative_graph).search(fixture.config)
    if negative.witness is not None:
        raise ValueError("matched negative control unexpectedly reached the final effect")

    edge_by_id = {edge.edge_id: edge for edge in fixture.graph.edges}
    run_id = inert_fixture_run_id(fixture)
    clean_replay_run_id = inert_fixture_run_id(fixture, clean_replay=True)
    if (
        type(admission_verifier) is not ExternalInertAdmissionVerifier
        or type(clean_replay_admission_verifier) is not ExternalInertAdmissionVerifier
    ):
        raise ExternalInertAdmissionError(
            "inert execution requires exact external admission verifiers"
        )
    edge_admissions, budget_receipts = _admit_and_account(
        resumed.witness,
        edge_by_id,
        fixture.config.budget,
        admission_tokens,
        admission_verifier,
    )
    clean_edge_admissions, clean_budget_receipts = _admit_and_account(
        clean_replay.witness,
        edge_by_id,
        fixture.config.budget,
        clean_replay_admission_tokens,
        clean_replay_admission_verifier,
    )
    persistent_ids = {edge.edge_id for edge in fixture.graph.edges}
    restored_ids = {edge.edge_id for edge in restored.graph.edges}
    effects = tuple(edge_by_id[edge_id].effect for edge_id in resumed.witness.edge_ids)
    duplicate_effects = len(effects) - len(set(effects))

    return InertGateReceipt(
        run_id=run_id,
        clean_replay_run_id=clean_replay_run_id,
        run_class=restored.config.run_class,
        expected_depth=fixture.depth,
        witness=resumed.witness,
        clean_replay_witness=clean_replay.witness,
        negative_terminal_reason=negative.terminal_reason,
        checkpoint_json=checkpoint_json,
        edge_admission_receipts=edge_admissions,
        clean_replay_edge_admission_receipts=clean_edge_admissions,
        budget_receipts=budget_receipts,
        clean_replay_budget_receipts=clean_budget_receipts,
        lost_ids=len(persistent_ids - restored_ids),
        duplicate_effects=duplicate_effects,
        cleanup_result="initial_state_restored",
    )


def _admit_and_account(
    witness: SemanticWitness,
    edge_by_id: dict[str, SemanticEdge],
    limit: BudgetVector,
    tokens: tuple[SignedInertEdgeAdmission, ...],
    verifier: ExternalInertAdmissionVerifier,
) -> tuple[
    tuple[ExternallyAdmittedInertEdgeReceipt, ...], tuple[BudgetReceipt, ...]
]:
    if type(tokens) is not tuple or len(tokens) != len(witness.edge_ids):
        raise ExternalInertAdmissionError(
            "every retained edge requires exactly one external admission token"
        )
    remaining = limit
    admissions: list[ExternallyAdmittedInertEdgeReceipt] = []
    receipts: list[BudgetReceipt] = []
    for edge_id, token in zip(witness.edge_ids, tokens):
        amount = edge_by_id[edge_id].budget
        admission = verifier.admit(
            token,
            edge=edge_by_id[edge_id],
            expected_remaining=remaining,
        )
        admissions.append(admission)
        reservation_id = _content_id(
            "budget-reservation",
            {
                "admission_token_id": admission.admission_token_id,
                "amount": amount.document(),
                "edge_id": edge_id,
                "remaining_before": remaining.document(),
            },
        )
        consumed = BudgetVector(
            *(left - right for left, right in zip(remaining.as_tuple(), amount.as_tuple()))
        )
        receipts.extend(
            (
                BudgetReceipt(
                    admission.admission_token_id,
                    reservation_id,
                    edge_id,
                    "reserve",
                    amount,
                    consumed,
                ),
                BudgetReceipt(
                    admission.admission_token_id,
                    reservation_id,
                    edge_id,
                    "consume",
                    amount,
                    consumed,
                ),
                BudgetReceipt(
                    admission.admission_token_id,
                    reservation_id,
                    edge_id,
                    "release",
                    ZERO_BUDGET,
                    consumed,
                ),
            )
        )
        remaining = consumed
    return tuple(admissions), tuple(receipts)
