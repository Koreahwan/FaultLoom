"""Independent, data-only verifier for the owned G44 fixture evidence."""

from __future__ import annotations

import hashlib
import json
import re
import base64
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_BOUNDARIES = ("web_api_to_llm_mcp", "llm_mcp_to_web3")
_ARTIFACT_PATHS = (
    ("core", "packages/protocol/src/faultloom_protocol/models.py"),
    ("g42", "packages/runtime/src/faultloom/semantic_depth.py"),
    ("web3", "packs/web3/src/faultloom_web3/fixture.py"),
)
_GOAL_IDS = ("G42-v0.2-depth-and-advanced-web", "G44-v0.3-web3")


class G44VerificationError(ValueError):
    """Evidence is malformed or fails a normative G44 fixture condition."""


@dataclass(frozen=True, slots=True)
class G44VerificationReport:
    passed: bool
    semantic_depth: int
    minimized_edge_ids: tuple[str, ...]
    minimized_semantic_signatures: tuple[str, ...]
    boundary_crossings: tuple[str, ...]
    lost_ids: int
    duplicate_effects: int
    negative_controls_passed: tuple[str, ...]
    clean_replay_passed: bool
    cleanup_passed: bool
    manifest_digest: str
    provenance_key_id: str
    provenance_manifest_digest: str

    def document(self) -> dict[str, object]:
        return {
            "boundary_crossings": list(self.boundary_crossings),
            "clean_replay_passed": self.clean_replay_passed,
            "cleanup_passed": self.cleanup_passed,
            "duplicate_effects": self.duplicate_effects,
            "lost_ids": self.lost_ids,
            "manifest_digest": self.manifest_digest,
            "minimized_edge_ids": list(self.minimized_edge_ids),
            "minimized_semantic_signatures": list(self.minimized_semantic_signatures),
            "negative_controls_passed": list(self.negative_controls_passed),
            "passed": self.passed,
            "provenance_key_id": self.provenance_key_id,
            "provenance_manifest_digest": self.provenance_manifest_digest,
            "semantic_depth": self.semantic_depth,
        }


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _decode_base64url(value: object, label: str) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise G44VerificationError(f"{label} must be unpadded URL-safe base64")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise G44VerificationError(f"{label} is invalid") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    _require(canonical == value, f"{label} is not canonical")
    return decoded


def _parse_time(value: object, label: str) -> datetime:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise G44VerificationError(f"{label} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise G44VerificationError(f"{label} is invalid") from exc


def _verify_artifact_provenance(
    value: object,
    *,
    manifest: dict[str, Any],
    trusted_public_key_bytes: bytes,
    verification_time: datetime,
) -> tuple[str, str]:
    provenance = _mapping(value, "artifact provenance")
    _require(set(provenance) == {"manifest", "signature"},
             "artifact provenance must be signed and contain no private/test key material")
    artifact_manifest = _mapping(provenance["manifest"], "artifact provenance manifest")
    _require(set(artifact_manifest) == {
        "artifacts", "created_at", "expires_at", "goal_ids", "run_id", "schema_version",
        "versions",
    }, "artifact provenance manifest shape is not canonical")
    _require(artifact_manifest["schema_version"] == "faultloom.g44.artifact-provenance.v1",
             "artifact provenance schema is invalid")
    artifacts = _list(artifact_manifest["artifacts"], "provenance artifacts")
    _require(len(artifacts) == 3, "provenance must bind exactly Core, G42, and Web3 artifacts")
    expected_digests = (
        manifest["core_artifact_digest"], manifest["g42_artifact_digest"],
        manifest["pack_adapter_digest"],
    )
    for item_value, (expected_role, expected_path), expected_digest in zip(
        artifacts, _ARTIFACT_PATHS, expected_digests, strict=True
    ):
        item = _mapping(item_value, "provenance artifact")
        _require(set(item) == {"path", "role", "sha256"},
                 "provenance artifact shape is invalid")
        _require(item == {"role": expected_role, "path": expected_path,
                          "sha256": expected_digest},
                 "provenance artifact path, role, or digest mismatch")
    _require(artifact_manifest["goal_ids"] == list(_GOAL_IDS),
             "provenance goal IDs are not the pinned G42/G44 goals")
    versions = _mapping(artifact_manifest["versions"], "provenance versions")
    _require(versions == {
        "core": "0.1.0-candidate", "g42": "0.2.0-candidate", "web3": "0.3.0-candidate"
    }, "provenance versions are not pinned")
    _require(artifact_manifest["run_id"] == "run.g44.primary",
             "provenance run ID does not bind the primary fixture run")
    created_at = _parse_time(artifact_manifest["created_at"], "provenance created_at")
    expires_at = _parse_time(artifact_manifest["expires_at"], "provenance expires_at")
    if verification_time.tzinfo is None or verification_time.utcoffset() is None:
        raise G44VerificationError("verification time must be timezone-aware")
    verification_time = verification_time.astimezone(timezone.utc)
    _require(created_at <= verification_time < expires_at,
             "artifact provenance is not currently valid or has expired")

    if type(trusted_public_key_bytes) is not bytes or len(trusted_public_key_bytes) != 32:
        raise G44VerificationError("externally pinned Ed25519 public key must be exactly 32 bytes")
    key_id = "ed25519:sha256:" + hashlib.sha256(trusted_public_key_bytes).hexdigest()
    signature = _mapping(provenance["signature"], "artifact provenance signature")
    _require(set(signature) == {"algorithm", "key_id", "signature"} and
             signature["algorithm"] == "Ed25519" and signature["key_id"] == key_id,
             "artifact provenance is unsigned or uses the wrong externally pinned key")
    signature_bytes = _decode_base64url(signature["signature"], "artifact provenance signature")
    _require(len(signature_bytes) == 64, "artifact provenance signature must be 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key_bytes).verify(
            signature_bytes, _canonical_bytes(artifact_manifest)
        )
    except (InvalidSignature, ValueError) as exc:
        raise G44VerificationError("artifact provenance signature verification failed") from exc
    return key_id, _canonical_sha256(artifact_manifest)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise G44VerificationError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise G44VerificationError(f"{label} must be an array")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise G44VerificationError(message)


def _state_key(state: object) -> str:
    return json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _validate_manifest(value: object) -> dict[str, Any]:
    manifest = _mapping(value, "manifest")
    required = {
        "action_budget", "adapter_id", "boundary_crossings", "cleanup_contract",
        "core_artifact_digest", "cost_budget", "expected_semantic_signatures",
        "final_inert_canary_effect", "final_state", "g42_artifact_digest",
        "impact_budget", "initial_state", "negative_controls", "pack_adapter_digest",
        "pack_id", "semantic_depth", "time_budget_seconds",
    }
    _require(set(manifest) == required, "manifest shape is not canonical")
    for name in ("core_artifact_digest", "g42_artifact_digest", "pack_adapter_digest"):
        _require(type(manifest[name]) is str and bool(_DIGEST.fullmatch(manifest[name])),
                 f"{name} is not a pinned SHA-256 digest")
    depth = manifest["semantic_depth"]
    _require(type(depth) is int and 7 <= depth <= 10, "semantic depth is outside 7 through 10")
    _require(manifest["boundary_crossings"] == list(_BOUNDARIES),
             "boundary crossing order is not pinned Web/API -> LLM/MCP -> Web3")
    signatures = _list(manifest["expected_semantic_signatures"], "semantic signatures")
    _require(len(signatures) == depth and len(set(signatures)) == depth,
             "manifest signatures do not pin one distinct signature per edge")
    _require(all(type(item) is str and _DIGEST.fullmatch(item) for item in signatures),
             "manifest contains a noncanonical semantic signature")
    budgets = tuple(manifest[name] for name in (
        "action_budget", "time_budget_seconds", "cost_budget", "impact_budget"
    ))
    _require(all(type(item) is int and item >= 0 for item in budgets),
             "manifest budgets must be four nonnegative integers")
    _require(manifest["negative_controls"] == [
        "remove_web_api_to_llm_mcp_bridge", "remove_llm_mcp_to_web3_bridge"
    ], "both pinned bridge-removal controls are required")
    _require(manifest["cleanup_contract"] == "restore_declared_initial_state",
             "cleanup contract is not pinned")
    return manifest


def _validate_edge(
    value: object,
    *,
    order: int,
    run_id: str,
    fixture_tick: int,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    edge = _mapping(value, f"edge {order}")
    required = {
        "boundary", "budget", "edge_id", "effect", "identity_id", "order", "policy",
        "post_state", "pre_state", "prerequisites", "primitive", "semantic_signature",
        "source_surface", "target_surface",
    }
    _require(set(edge) == required and edge["order"] == order, "edge order or shape is invalid")
    prerequisites = _list(edge["prerequisites"], "edge prerequisites")
    _require(all(type(item) is str for item in prerequisites), "edge prerequisites must be text")
    semantic_document = {
        "effect": edge["effect"],
        "post_state": edge["post_state"],
        "pre_state": edge["pre_state"],
        "prerequisites": prerequisites,
        "primitive": edge["primitive"],
    }
    signature = _canonical_sha256(semantic_document)
    _require(edge["semantic_signature"] == signature, "edge semantic signature mismatch")
    edge_digest = _canonical_sha256({
        "boundary": edge["boundary"],
        "semantic_signature": signature,
        "source_surface": edge["source_surface"],
        "target_surface": edge["target_surface"],
    }).removeprefix("sha256:")
    _require(edge["edge_id"] == f"edge.{edge_digest}", "edge ID is not content-derived")
    budget = _list(edge["budget"], "edge budget")
    _require(len(budget) == 4 and all(type(item) is int and item >= 0 for item in budget),
             "edge budget vector is invalid")

    policy = _mapping(edge["policy"], "edge policy")
    receipt_id = policy.get("receipt_id")
    body = {key: item for key, item in policy.items() if key != "receipt_id"}
    _require(receipt_id == "receipt." + _canonical_sha256(body).removeprefix("sha256:"),
             "policy receipt is not content-derived")
    _require(policy.get("edge_id") == edge["edge_id"] and
             policy.get("semantic_signature") == signature,
             "policy receipt is not bound to the exact edge and semantics")
    if policy.get("kind") == "lease":
        required_lease = {
            "adapter_id", "authority_epoch", "budget_reservation", "cleanup_obligation",
            "compiled_action", "edge_id", "engagement_id", "expires_at_tick", "identity_id",
            "intent", "issued_at_tick", "kind", "pack_id", "receipt_id", "reversible",
            "run_id", "scope_decision", "semantic_signature",
        }
        _require(set(policy) == required_lease, "lease receipt shape is invalid")
        _require(policy["run_id"] == run_id and policy["identity_id"] == edge["identity_id"],
                 "lease is not bound to this run and identity")
        _require(policy["pack_id"] == manifest["pack_id"] and
                 policy["adapter_id"] == manifest["adapter_id"],
                 "lease pack or adapter binding mismatch")
        _require(policy["budget_reservation"] == budget, "lease budget reservation mismatch")
        _require(policy["issued_at_tick"] == fixture_tick and
                 type(policy["expires_at_tick"]) is int and policy["expires_at_tick"] > fixture_tick,
                 "lease is expired or not fresh")
        _require(policy["reversible"] is True and
                 policy["cleanup_obligation"] == "restore_declared_initial_state",
                 "lease lacks reversibility or cleanup binding")
        _require(policy["scope_decision"] == "allow_owned_inert_simulation_only",
                 "lease scope is broader than the owned simulation")
    elif policy.get("kind") == "no_dispatch":
        _require(set(policy) == {
            "dispatch", "edge_id", "kind", "reason", "receipt_id", "semantic_signature"
        }, "no-dispatch receipt shape is invalid")
        _require(policy["dispatch"] is False and
                 policy["reason"] == "structural_verification_only" and budget == [0, 0, 0, 0],
                 "structural edge lacks an explicit zero-budget no-dispatch receipt")
    else:
        raise G44VerificationError("edge has neither a lease nor a no-dispatch receipt")
    return edge


def _validate_run(value: object, manifest: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    run = _mapping(value, "run")
    run_id = run.get("run_id")
    fixture_tick = run.get("fixture_tick")
    if type(run_id) is not str or not run_id.startswith("run.g44."):
        raise G44VerificationError("run ID is invalid")
    if type(fixture_tick) is not int or fixture_tick < 0:
        raise G44VerificationError("fixture tick is invalid")
    _require(run.get("initial_state") == manifest["initial_state"], "run initial state drifted")
    _require(run.get("initial_effects") == [], "run must not contain pre-seeded effects")
    _require(run.get("final_effect") == manifest["final_inert_canary_effect"],
             "run final effect does not match the manifest")
    raw_edges = _list(run.get("edges"), "run edges")
    edges = tuple(
        _validate_edge(
            edge, order=index, run_id=run_id, fixture_tick=fixture_tick, manifest=manifest
        )
        for index, edge in enumerate(raw_edges, start=1)
    )
    return edges


def _minimize(
    edges: tuple[dict[str, Any], ...], *, initial_state: object, final_effect: str
) -> tuple[dict[str, Any], ...] | None:
    queue: deque[
        tuple[object, frozenset[str], tuple[dict[str, Any], ...], frozenset[str]]
    ] = deque([(initial_state, frozenset(), tuple(), frozenset())])
    visited: dict[tuple[str, frozenset[str]], int] = {}
    winners: list[tuple[dict[str, Any], ...]] = []
    winner_depth: int | None = None
    while queue:
        state, effects, path, used = queue.popleft()
        if winner_depth is not None and len(path) > winner_depth:
            break
        if final_effect in effects:
            winner_depth = len(path)
            winners.append(path)
            continue
        key = (_state_key(state), effects)
        if visited.get(key, len(edges) + 1) < len(path):
            continue
        visited[key] = len(path)
        eligible = sorted(
            (
                edge for edge in edges
                if edge["edge_id"] not in used
                and edge["pre_state"] == state
                and set(edge["prerequisites"]).issubset(effects)
            ),
            key=lambda edge: edge["edge_id"],
        )
        for edge in eligible:
            queue.append((
                edge["post_state"], effects | {edge["effect"]}, path + (edge,),
                used | {edge["edge_id"]},
            ))
    if not winners:
        return None
    return min(winners, key=lambda path: tuple(edge["edge_id"] for edge in path))


def _normalized_edge(edge: dict[str, Any]) -> dict[str, Any]:
    policy = _mapping(edge["policy"], "policy")
    normalized_policy = {
        key: value for key, value in policy.items() if key not in {"receipt_id", "run_id"}
    }
    return {**edge, "policy": normalized_policy}


def _validate_controls(
    value: object,
    *,
    edges: tuple[dict[str, Any], ...],
    manifest: dict[str, Any],
) -> tuple[str, ...]:
    controls = _list(value, "negative controls")
    _require(len(controls) == 2, "exactly two bridge-removal controls are required")
    passed: list[str] = []
    for expected_id, expected_boundary, control_value in zip(
        manifest["negative_controls"], _BOUNDARIES, controls, strict=True
    ):
        control = _mapping(control_value, "negative control")
        _require(set(control) == {
            "control_id", "edges", "observed_edge_ids", "observed_final_state",
            "removed_boundary",
        }, "negative control shape is invalid")
        _require(control["control_id"] == expected_id and
                 control["removed_boundary"] == expected_boundary,
                 "negative control identity or boundary mismatch")
        control_edges = tuple(_mapping(edge, "control edge") for edge in _list(
            control["edges"], "control edges"
        ))
        expected_edges = tuple(edge for edge in edges if edge["boundary"] != expected_boundary)
        _require(control_edges == expected_edges, "negative control is not an exact bridge removal")
        _require(_minimize(control_edges, initial_state=manifest["initial_state"],
                          final_effect=manifest["final_inert_canary_effect"]) is None,
                 "bridge-removal control still reaches the final effect")
        removed_index = next(
            index for index, edge in enumerate(edges) if edge["boundary"] == expected_boundary
        )
        expected_prefix = edges[:removed_index]
        _require(control["observed_edge_ids"] == [edge["edge_id"] for edge in expected_prefix],
                 "negative control observation is not the reachable prefix")
        expected_state = (
            expected_prefix[-1]["post_state"] if expected_prefix else manifest["initial_state"]
        )
        _require(control["observed_final_state"] == expected_state,
                 "negative control observed state mismatch")
        passed.append(expected_id)
    return tuple(passed)


def verify_g44_evidence(
    value: object,
    *,
    trusted_provenance_public_key: bytes,
    verification_time: datetime,
) -> G44VerificationReport:
    """Verify a JSON-compatible evidence object without invoking the fixture."""

    bundle = _mapping(value, "G44 evidence")
    _require(set(bundle) == {
        "artifact_provenance", "classification", "cleanup", "clean_replay", "manifest",
        "negative_controls", "primary_run", "reset", "schema_version",
    }, "G44 evidence shape is not canonical")
    _require(bundle["classification"] == "g44_owned_simulated_fixture_evidence" and
             bundle["schema_version"] == "faultloom.g44.fixture-evidence.v1",
             "G44 evidence classification or schema is invalid")
    manifest = _validate_manifest(bundle["manifest"])
    provenance_key_id, provenance_manifest_digest = _verify_artifact_provenance(
        bundle["artifact_provenance"],
        manifest=manifest,
        trusted_public_key_bytes=trusted_provenance_public_key,
        verification_time=verification_time,
    )
    primary_run = _mapping(bundle["primary_run"], "primary run")
    primary_edges = _validate_run(primary_run, manifest)
    witness = _minimize(
        primary_edges,
        initial_state=manifest["initial_state"],
        final_effect=manifest["final_inert_canary_effect"],
    )
    _require(witness is not None, "final inert canary is unreachable")
    assert witness is not None
    witness_ids = tuple(edge["edge_id"] for edge in witness)
    signatures = tuple(edge["semantic_signature"] for edge in witness)
    _require(len(witness) == manifest["semantic_depth"], "independently minimized depth mismatch")
    _require(list(signatures) == manifest["expected_semantic_signatures"],
             "minimized semantic signatures do not match the manifest")
    _require(primary_run.get("claimed_minimal_edge_ids") == list(witness_ids),
             "claimed minimal witness differs from independent minimization")
    _require(primary_run.get("observed_edge_ids") == list(witness_ids) and
             primary_run.get("observed_final_state") == manifest["final_state"],
             "primary runtime observations do not match the minimized witness")
    boundary_crossings = tuple(
        edge["boundary"] for edge in witness if edge["boundary"] != "within_surface"
    )
    _require(boundary_crossings == _BOUNDARIES, "minimized boundary order mismatch")
    _require(witness[-1]["post_state"] == manifest["final_state"], "final state mismatch")

    for removed in witness:
        reduced = tuple(edge for edge in primary_edges if edge["edge_id"] != removed["edge_id"])
        _require(_minimize(reduced, initial_state=manifest["initial_state"],
                          final_effect=manifest["final_inert_canary_effect"]) is None,
                 "minimized witness contains a removable semantic edge")

    consumed = tuple(sum(edge["budget"][index] for edge in witness) for index in range(4))
    limits = tuple(manifest[name] for name in (
        "action_budget", "time_budget_seconds", "cost_budget", "impact_budget"
    ))
    _require(all(used <= limit for used, limit in zip(consumed, limits, strict=True)),
             "minimized witness exceeds a pinned budget")

    passed_controls = _validate_controls(
        bundle["negative_controls"], edges=primary_edges, manifest=manifest
    )

    reset = _mapping(bundle["reset"], "reset receipt")
    _require(set(reset) == {
        "after_effect_ids", "after_ids_by_class", "after_persistent_ids",
        "before_effect_ids", "before_ids_by_class", "before_persistent_ids",
    }, "reset receipt shape is invalid")
    before_classes = _mapping(reset["before_ids_by_class"], "pre-reset ID classes")
    after_classes = _mapping(reset["after_ids_by_class"], "post-reset ID classes")
    expected_classes = {
        "action", "budget_reservation", "chain", "edge", "effect", "engagement",
        "evidence", "hypothesis", "identity", "lease", "no_dispatch_receipt", "node",
        "pending_action", "run", "state",
    }
    _require(set(before_classes) == expected_classes and before_classes == after_classes,
             "reset did not preserve every persistent ID class byte-for-byte")
    _require(all(type(items) is list and len(items) == len(set(items))
                 for items in before_classes.values()),
             "reset ID classes contain malformed or duplicate IDs")
    lease_receipts = [edge["policy"]["receipt_id"] for edge in primary_edges
                      if edge["policy"]["kind"] == "lease"]
    no_dispatch_receipts = [edge["policy"]["receipt_id"] for edge in primary_edges
                            if edge["policy"]["kind"] == "no_dispatch"]
    state_ids = sorted({
        "state." + _canonical_sha256(edge[state_name]).removeprefix("sha256:")
        for edge in primary_edges for state_name in ("pre_state", "post_state")
    })
    expected_id_inventory = {
        "action": ["action." + edge["edge_id"].removeprefix("edge.")
                   for edge in primary_edges if edge["policy"]["kind"] == "lease"],
        "budget_reservation": [f"budget.{receipt.removeprefix('receipt.')}"
                               for receipt in lease_receipts],
        "chain": ["chain.g44.owned"],
        "edge": [edge["edge_id"] for edge in primary_edges],
        "effect": [edge["effect"] for edge in primary_edges],
        "engagement": ["engagement.g44.owned-simulation"],
        "evidence": lease_receipts + no_dispatch_receipts,
        "hypothesis": ["hypothesis." + _canonical_sha256(edge["primitive"]).removeprefix("sha256:")
                       for edge in primary_edges],
        "identity": sorted({edge["identity_id"] for edge in primary_edges}),
        "lease": lease_receipts,
        "no_dispatch_receipt": no_dispatch_receipts,
        "node": state_ids,
        "pending_action": [],
        "run": [primary_run["run_id"]],
        "state": state_ids,
    }
    _require(before_classes == expected_id_inventory,
             "reset ID inventory does not match independently derived persistent objects")
    before_ids = _list(reset.get("before_persistent_ids"), "pre-reset IDs")
    after_ids = _list(reset.get("after_persistent_ids"), "post-reset IDs")
    flattened = sorted({item for items in before_classes.values() for item in items})
    _require(before_ids == flattened, "flat reset ID inventory omits a persistent ID class")
    lost_ids = len(set(before_ids) - set(after_ids))
    _require(before_ids == after_ids and lost_ids == 0, "reset did not preserve IDs byte-for-byte")
    before_effects = _list(reset.get("before_effect_ids"), "pre-reset effects")
    after_effects = _list(reset.get("after_effect_ids"), "post-reset effects")
    _require(before_effects == after_effects, "reset re-executed or changed effects")

    primary_effects = [edge["effect"] for edge in primary_edges]
    duplicate_effects = len(primary_effects) - len(set(primary_effects))
    _require(duplicate_effects == 0, "primary run contains duplicate effects")

    replay = _mapping(bundle["clean_replay"], "clean replay")
    _require(replay.get("pristine") is True and replay.get("warm_frontier") == [] and
             replay.get("model_context") == [] and replay.get("preseeded_evidence") == [],
             "clean replay is not pristine")
    expected_snapshot = _canonical_sha256({
        "initial_state": manifest["initial_state"], "warm_frontier": []
    })
    _require(replay.get("snapshot_digest") == expected_snapshot,
             "clean replay snapshot digest mismatch")
    _require(replay.get("run_id") != primary_run.get("run_id"),
             "clean replay must use a separate run")
    replay_edges = _validate_run(replay, manifest)
    replay_witness = _minimize(
        replay_edges, initial_state=manifest["initial_state"],
        final_effect=manifest["final_inert_canary_effect"]
    )
    _require(replay_witness is not None, "clean replay final effect is unreachable")
    assert replay_witness is not None
    _require(tuple(_normalized_edge(edge) for edge in replay_witness) ==
             tuple(_normalized_edge(edge) for edge in witness),
             "clean replay did not reproduce the normalized minimal witness")
    _require(replay.get("observed_edge_ids") == [edge["edge_id"] for edge in replay_witness] and
             replay.get("observed_final_state") == manifest["final_state"],
             "clean replay runtime observations mismatch")
    replay_controls = _validate_controls(
        replay.get("negative_controls"), edges=replay_edges, manifest=manifest
    )
    _require(replay_controls == passed_controls,
             "clean replay did not reproduce both negative controls")
    replay_effects = [edge["effect"] for edge in replay_edges]
    _require(len(replay_effects) == len(set(replay_effects)),
             "clean replay contains duplicate effects")

    cleanup = _mapping(bundle["cleanup"], "cleanup receipt")
    _require(cleanup == {"before": manifest["final_state"], "after": manifest["initial_state"]},
             "cleanup did not restore the declared initial state")
    return G44VerificationReport(
        passed=True,
        semantic_depth=len(witness),
        minimized_edge_ids=witness_ids,
        minimized_semantic_signatures=signatures,
        boundary_crossings=boundary_crossings,
        lost_ids=lost_ids,
        duplicate_effects=duplicate_effects,
        negative_controls_passed=passed_controls,
        clean_replay_passed=True,
        cleanup_passed=True,
        manifest_digest=_canonical_sha256(manifest),
        provenance_key_id=provenance_key_id,
        provenance_manifest_digest=provenance_manifest_digest,
    )
