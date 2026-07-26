from __future__ import annotations

import hashlib
import inspect
import json
import os
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom import t40_arm_worker as arm_worker
from faultloom.t40_arm_runtime import (
    T40ArmPolicy,
    T40ArmRequest,
    T40ResourceBudget,
    verify_arm_response,
)
from faultloom.t40_arm_worker import T40ArmWorkerTimeout, run_isolated_worker


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _policy(timeout_seconds: int = 3) -> T40ArmPolicy:
    return T40ArmPolicy(
        model_snapshot_digest=_digest("1"),
        model_runtime_digest=_digest("2"),
        tool_schema_digest=_digest("3"),
        gateway_policy_digest=_digest("4"),
        safety_policy_digest=_digest("5"),
        generation_config_digest=_digest("6"),
        allowed_tools=("lab.browser.inspect", "lab.http.get"),
        budget=T40ResourceBudget(
            maximum_input_tokens=256,
            maximum_output_tokens=128,
            maximum_model_calls=1,
            maximum_tool_dispatches=2,
            timeout_seconds=timeout_seconds,
            cpu_seconds=2,
            maximum_address_space_bytes=1_073_741_824,
            maximum_response_bytes=65_536,
        ),
    )


def _request(policy: T40ArmPolicy) -> T40ArmRequest:
    private_input = "fixed kernel probe"
    return T40ArmRequest(
        request_id="request.kernel-probe",
        arm_id="faultloom",
        arm_runtime_digest=_digest("7"),
        case_digest=_digest("8"),
        private_input_digest=f"sha256:{hashlib.sha256(private_input.encode()).hexdigest()}",
        policy_digest=policy.policy_digest,
        model_snapshot_digest=policy.model_snapshot_digest,
        model_runtime_digest=policy.model_runtime_digest,
        tool_schema_digest=policy.tool_schema_digest,
        gateway_policy_digest=policy.gateway_policy_digest,
        safety_policy_digest=policy.safety_policy_digest,
        generation_config_digest=policy.generation_config_digest,
        budget_digest=policy.budget_digest,
        requested_tools=(),
        private_input=private_input,
    )


def _assert_pid_gone(pid: int) -> None:
    deadline = time.monotonic() + 2.0
    while os.path.exists(f"/proc/{pid}") and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not os.path.exists(f"/proc/{pid}")


def test_fixed_entrypoint_round_trip_is_signed_networkless_and_non_formal() -> None:
    policy = _policy()
    request = _request(policy)
    private_key = Ed25519PrivateKey.generate()
    parent_network_namespace = os.readlink("/proc/self/ns/net")
    encoded = run_isolated_worker(
        request=request,
        policy=policy,
        signing_key=private_key.private_bytes_raw(),
    )
    response = verify_arm_response(
        encoded=encoded,
        request=request,
        policy=policy,
        public_key=private_key.public_key(),
    )
    observation = json.loads(response.observation)
    assert observation["network_namespace"] != parent_network_namespace
    _assert_pid_gone(observation["descendant_pid"])
    assert response.provenance_kind == "kernel_probe"
    assert response.model_snapshot_loads == response.model_calls == 0


def test_timeout_reaps_descendants_and_network_is_unavailable() -> None:
    policy = _policy(timeout_seconds=1)
    parent_network_namespace = os.readlink("/proc/self/ns/net")
    with pytest.raises(T40ArmWorkerTimeout) as caught:
        run_isolated_worker(
            request=_request(policy),
            policy=policy,
            signing_key=Ed25519PrivateKey.generate().private_bytes_raw(),
        )
    diagnostic = json.loads(caught.value.partial_response)
    assert diagnostic["network_namespace"] != parent_network_namespace
    _assert_pid_gone(diagnostic["descendant_pid"])


def test_launcher_has_no_runtime_command_module_handler_or_path_selection() -> None:
    parameters = inspect.signature(run_isolated_worker).parameters
    assert tuple(parameters) == ("request", "policy", "signing_key")
    assert not {
        "worker_argv",
        "module",
        "handler",
        "private_input_path",
        "environment",
    }.intersection(parameters)
    sandbox_argv = arm_worker._sandbox_argv((10, 11, 12, 13))
    assert "--unshare-net" in sandbox_argv
    command_separator = sandbox_argv.index("--")
    assert sandbox_argv[command_separator + 1 : command_separator + 6] == (
        "/usr/bin/python3",
        "-S",
        "-B",
        "-m",
        "faultloom.t40_arm_worker",
    )
    worker_source = Path(arm_worker.__file__).read_text(encoding="utf-8")
    assert "import socket" not in worker_source
    assert "socket." not in worker_source
