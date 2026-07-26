from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import cast

import pytest

from faultloom.execution import (
    AuthenticatedGatewayClient,
    EndpointScheme,
    ExecutionContractError,
    ExecutionFlowKind,
    GatewayChannelConfig,
    GatewayDispatchFrame,
    SemanticEndpoint,
    SemanticHttpRequest,
    gateway_dispatch_frame,
)
from faultloom.execution.gateway_client import _Decoder, _encode_dispatch_command
from faultloom_protocol import SCHEMA_VERSION

from .execution_helpers import command


def test_channel_config_derives_a_boot_bound_session() -> None:
    config = GatewayChannelConfig(
        key_id="channel-key.1",
        key=bytes(range(1, 33)),
        boot_id="gateway-boot.1",
        nonce=bytes(range(16)),
        issued_at_millis=1_000,
        expires_at_millis=31_000,
    )

    assert len(config.challenge_id) == 32
    assert config.session_id == f"supervisor:channel:v1:{config.challenge_id.hex()}"


def test_production_client_requires_a_pinned_supervised_process() -> None:
    config = GatewayChannelConfig(
        key_id="channel-key.1",
        key=bytes(range(1, 33)),
        boot_id="gateway-boot.1",
        nonce=bytes(range(16)),
        issued_at_millis=1_000,
        expires_at_millis=31_000,
    )

    with pytest.raises(ExecutionContractError, match="private stdin/stdout"):
        AuthenticatedGatewayClient(
            cast(subprocess.Popen[bytes], object()),
            config,
            expected_binary_digest="sha256:" + "11" * 32,
        )


def test_production_client_interrupt_terminates_its_exact_gateway_process() -> None:
    executable = "/usr/bin/python3"
    process = subprocess.Popen(
        (
            executable,
            "-c",
            "import sys; sys.stdin.buffer.read()",
            "--supervised-stdio",
        ),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    config = GatewayChannelConfig(
        key_id="channel-key.1",
        key=bytes(range(1, 33)),
        boot_id="gateway-boot.1",
        nonce=bytes(range(16)),
        issued_at_millis=1_000,
        expires_at_millis=31_000,
    )
    client = AuthenticatedGatewayClient(
        process,
        config,
        expected_binary_digest=(
            "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()
        ),
    )
    try:
        client.interrupt()
        assert process.poll() is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        client.close()


def test_dispatch_codec_preserves_child_flow_and_parent_binding() -> None:
    approved = command(parent_action_ids=("action.parent",))
    frame = GatewayDispatchFrame(
        schema_version=SCHEMA_VERSION,
        command=approved,
        context_generation=1,
        flow_kind=ExecutionFlowKind.REDIRECT,
        parent_action_id="action.parent",
    )

    decoder = _Decoder(_encode_dispatch_command(frame), b"FLSC", 5, 1)
    assert decoder.byte() == 2
    assert decoder.string() == approved.intent.action_id
    assert decoder.string() == approved.lease.correlation_id
    assert decoder.string() == approved.lease.lease_id
    assert decoder.string() == approved.intent.target_id
    assert decoder.u64() == approved.lease.scope_epoch
    assert decoder.byte() == 2
    assert decoder.byte() == 3
    assert decoder.boolean()
    assert decoder.string() == "action.parent"


def test_t19_codec_rejects_https_before_supervisor_dispatch() -> None:
    request = SemanticHttpRequest(
        schema_version=SCHEMA_VERSION,
        endpoint=SemanticEndpoint(
            schema_version=SCHEMA_VERSION,
            scheme=EndpointScheme.HTTPS,
            hostname="loopback.test",
            port=443,
            path="/api/canary",
        ),
        method="GET",
    )
    approved = command(request=request)

    with pytest.raises(ExecutionContractError, match="plain HTTP"):
        _encode_dispatch_command(gateway_dispatch_frame(approved))
