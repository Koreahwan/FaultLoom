from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from faultloom.t40_arm_runtime import T40ArmRequest, canonical_json_bytes
from faultloom.t40_faultloom_arm import T40FaultLoomError, _parse_private
from faultloom.t40_owned_private_input import (
    _digest,
    _policy,
    generate_all_owned_private_inputs,
    generate_owned_private_input,
)


def _request(private_input: bytes, slot: int) -> T40ArmRequest:
    policy = _policy()
    return T40ArmRequest(
        request_id=f"formal.owned-private-input.test.{slot}",
        arm_id="faultloom",
        run_key="control",
        arm_runtime_digest=_digest(b"test arm runtime"),
        case_digest=_digest(f"case-{slot}".encode()),
        private_input_digest=_digest(private_input),
        policy_digest=policy.policy_digest,
        model_snapshot_digest=policy.model_snapshot_digest,
        model_runtime_digest=policy.model_runtime_digest,
        tool_schema_digest=policy.tool_schema_digest,
        gateway_policy_digest=policy.gateway_policy_digest,
        safety_policy_digest=policy.safety_policy_digest,
        generation_config_digest=policy.generation_config_digest,
        budget_digest=policy.budget_digest,
        requested_tools=(),
        private_input=private_input.decode("ascii"),
        session_id=f"formal.owned-private-input.test-session.{slot}",
        evaluator_challenge=hashlib.sha256(f"test-{slot}".encode()).hexdigest(),
        allocation_id=f"formal-owned-input-test-{slot}",
        trusted_minimum_sequence=0,
        core_wheel_digest=_digest(b"test core wheel"),
    )


def _strings(value: object):
    if isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def test_six_owned_documents_are_distinct_deterministic_and_actually_parse() -> None:
    first = generate_all_owned_private_inputs()
    second = generate_all_owned_private_inputs()

    assert first == second
    assert len(first) == len(set(first)) == 6
    for slot, encoded in enumerate(first, 1):
        assert encoded == canonical_json_bytes(json.loads(encoded))
        parsed = _parse_private(_request(encoded, slot))
        assert parsed.context.live is False
        assert parsed.context.state.engagement_id == f"engagement.owned.{slot}"
        assert parsed.context.state.checkpoint.identity_graph_id == f"identity-graph.owned.{slot}"
        assert parsed.context.state.checkpoint.workflow_graph_id == f"workflow-graph.owned.{slot}"
        assert parsed.context.state.checkpoint.surface_graph_id == f"surface-graph.owned.{slot}"
        assert parsed.context.state.checkpoint.chain_graph_id == f"chain-graph.owned.{slot}"
        assert parsed.context.verification_time.second == 5 + slot


def test_owned_documents_remain_offline_and_inside_reserved_namespaces() -> None:
    for encoded in generate_all_owned_private_inputs():
        document = json.loads(encoded)
        values = tuple(_strings(document))
        assert document["context"]["live"] is False
        assert not any("http://" in value or "https://" in value for value in values)
        domains = document["web"]["surface"]["binding"]["owned_callback_domains"]
        assert domains
        assert all(domain.endswith(".invalid") for domain in domains)
        assert document["planner"]["grant"]["state_change_policy"]["allowed_families"] == []
        assert all(
            action["intent"]["action_class"] in {"observe", "safe_probe"}
            for action in document["web"]["actions"]
        )


def test_runtime_module_has_no_test_or_lab_imports() -> None:
    source_path = (
        Path(__file__).parents[2]
        / "packages/runtime/src/faultloom/t40_owned_private_input.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imports.append(node.module)
    assert not any(name == "tests" or name.startswith("tests.") for name in imports)
    assert not any(name == "labs" or name.startswith("labs.") for name in imports)


@pytest.mark.parametrize("slot", (0, 7, True, 1.0, "1"))
def test_invalid_slots_are_rejected(slot: object) -> None:
    with pytest.raises(ValueError, match="slot must be an integer"):
        generate_owned_private_input(slot)  # type: ignore[arg-type]


def test_schema_and_canonical_mutations_are_rejected_by_actual_parser() -> None:
    encoded = generate_owned_private_input(1)
    document = json.loads(encoded)
    document["unexpected"] = True
    extra_field = canonical_json_bytes(document)
    with pytest.raises(T40FaultLoomError, match="malformed"):
        _parse_private(_request(extra_field, 1))

    noncanonical = b" " + encoded
    with pytest.raises(T40FaultLoomError, match="not canonical"):
        _parse_private(_request(noncanonical, 1))
