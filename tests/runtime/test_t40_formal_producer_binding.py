from __future__ import annotations

import json
import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from faultloom import model_utility_sandbox
from faultloom.model_utility_attestation_state import MonotonicAttestationState
from faultloom.model_utility_attestor import TransientModelUtilityAttestor
from faultloom.model_utility_process import BoundedProcessLaunch, BoundedProcessResult
from faultloom.model_utility_proxy import DigestPinnedLocalProcessProxy
from faultloom.model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
    FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelProcessRequest,
    LocalModelRuntimeProfile,
)
from faultloom.t40_formal_producer_binding import (
    FORMAL_PRODUCER_BINDING_SCHEMA,
    FormalProducerBinding,
    main,
    materialize_formal_producer_binding,
    parse_formal_producer_binding,
)
from faultloom_protocol import AuthoritySigner, canonical_json_bytes
from faultloom_sdk import ModelUtilityArm, UtilityDecision


def _digest(value: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


@contextmanager
def _held_launch(
    config: LocalModelProcessConfig,
    stdin: bytes = b"",
) -> Generator[BoundedProcessLaunch, None, None]:
    descriptors = (
        os.open(os.devnull, os.O_RDONLY),
        os.open(os.devnull, os.O_RDONLY),
        os.open(os.devnull, os.O_RDONLY),
        os.open(os.devnull, os.O_RDONLY),
    )
    try:
        yield model_utility_sandbox._launch(config, stdin, descriptors)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _binding() -> FormalProducerBinding:
    return materialize_formal_producer_binding(
        core_wheel_digest=_digest(b"core-wheel"),
        timeout_seconds=30,
        maximum_request_bytes=65_536,
        maximum_response_bytes=4096,
    )


def test_binding_matches_actual_transient_attestor_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binding = _binding()
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=30,
        maximum_request_bytes=65_536,
        maximum_response_bytes=4096,
    )
    request = LocalModelProcessRequest(
        request_id="formal-binding-case",
        case_id="formal-binding-case",
        case_digest=_digest(b"case"),
        arm=ModelUtilityArm.BASELINE,
        model_snapshot_digest=config.model_snapshot_digest,
        runtime_artifact_digest=config.runtime_executable_digest,
        prompt_digest=_digest(b"prompt"),
        tool_schema_digest=_digest(b"tools"),
        budget_digest=_digest(b"budget"),
        generation_config_digest=_digest(b"generation"),
        seed=42,
        payload="owned fixture",
    )
    output = "inconclusive"
    response = canonical_json_bytes(
        {
            "request_id": request.request_id,
            "model_snapshot_digest": request.model_snapshot_digest,
            "runtime_artifact_digest": request.runtime_artifact_digest,
            "decision": UtilityDecision.INCONCLUSIVE.value,
            "output": output,
            "output_digest": _digest(output.encode()),
            "raw_llama_stdout_digest": _digest(b"raw-llama-stdout"),
            "input_tokens": 4,
            "output_tokens": 1,
        }
    ) + b"\n"

    @contextmanager
    def held(config_value: LocalModelProcessConfig, encoded: bytes):
        with _held_launch(config_value, encoded) as launch:
            yield launch

    monkeypatch.setattr("faultloom.model_utility_attestor.pinned_process_launch", held)
    monkeypatch.setattr(
        "faultloom.model_utility_attestor.run_bounded_process",
        lambda _launch: BoundedProcessResult(returncode=0, stdout=response),
    )
    with MonotonicAttestationState(tmp_path / "state.sqlite3") as state:
        exchange = TransientModelUtilityAttestor(
            proxy=DigestPinnedLocalProcessProxy(config),
            signer=AuthoritySigner.from_private_bytes(bytes(range(32))),
            sequence_state=state,
            core_wheel_digest=binding.core_wheel_digest,
        ).exchange(
            request,
            session_id="formal-binding-session",
            evaluator_challenge="0123456789abcdef" * 4,
            allocation_id="formal-binding-allocation",
        )
    payload = exchange.producer_receipt.payload
    assert binding.schema_id == FORMAL_PRODUCER_BINDING_SCHEMA
    assert payload.core_wheel_digest == binding.core_wheel_digest
    assert payload.model_digest == binding.producer_model_digest
    assert payload.runtime_wrapper_digest == binding.producer_runtime_wrapper_digest
    assert payload.runtime_bundle_digest == binding.producer_runtime_bundle_digest
    assert payload.bwrap_digest == binding.producer_sandbox_digest
    assert payload.fixed_argv_digest == binding.producer_fixed_argv_digest
    assert payload.profile_digest == binding.producer_profile_digest


def test_template_digest_matches_an_actual_held_launch() -> None:
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=30,
        maximum_request_bytes=65_536,
        maximum_response_bytes=4096,
    )
    expected = "sha256:3683c53906741d42404f1b9916302003c7ae828dbd9a04bbdbb212cad755d67b"
    assert (
        model_utility_sandbox.canonical_model_utility_launch_template_digest()
        == expected
    )
    with _held_launch(config) as launch:
        assert (
            model_utility_sandbox.canonical_model_utility_launch_digest(launch)
            == expected
        )


def test_binding_materialization_does_not_open_installed_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_opened(_spec: object) -> int:
        raise AssertionError(
            "pre-install binding materialization opened a runtime artifact"
        )

    monkeypatch.setattr(model_utility_sandbox, "_open_source", fail_if_opened)
    assert _binding().producer_fixed_argv_digest.startswith("sha256:")


def test_parse_rejects_noncanonical_and_mutated_bindings() -> None:
    binding = _binding()
    raw = canonical_json_bytes(binding.model_dump(mode="json", by_alias=True))
    assert parse_formal_producer_binding(raw) == binding

    noncanonical = json.dumps(
        binding.model_dump(mode="json", by_alias=True), indent=2
    ).encode()
    with pytest.raises(LocalModelProcessError, match="not canonical"):
        parse_formal_producer_binding(noncanonical)

    document = binding.model_dump(mode="json", by_alias=True)
    document["producer_runtime_wrapper_digest"] = _digest(b"mutated")
    with pytest.raises(LocalModelProcessError, match="schema is invalid"):
        parse_formal_producer_binding(canonical_json_bytes(document))

    document = binding.model_dump(mode="json", by_alias=True)
    document["producer_fixed_argv_digest"] = _digest(b"mutated")
    with pytest.raises(LocalModelProcessError, match="schema is invalid"):
        parse_formal_producer_binding(canonical_json_bytes(document))

    with pytest.raises(ValueError, match="fixed profile"):
        FormalProducerBinding(**document)


def test_cli_stdout_is_exactly_parseable_without_trailing_bytes(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    exit_code = main(
        [
            "--core-wheel-digest",
            _digest(b"core-wheel"),
            "--timeout-seconds",
            "30",
            "--maximum-request-bytes",
            "65536",
            "--maximum-response-bytes",
            "4096",
        ]
    )
    output = capsysbinary.readouterr().out
    assert exit_code == 0
    assert not output.endswith(b"\n")
    assert parse_formal_producer_binding(output).core_wheel_digest == _digest(
        b"core-wheel"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("timeout_seconds", 0),
        ("timeout_seconds", 301),
        ("maximum_request_bytes", 65_535),
        ("maximum_response_bytes", 0),
        ("maximum_response_bytes", 16_777_217),
    ),
)
def test_binding_rejects_policy_mutations(
    field: str,
    value: int,
) -> None:
    arguments = {
        "core_wheel_digest": _digest(b"core-wheel"),
        "timeout_seconds": 30,
        "maximum_request_bytes": 65_536,
        "maximum_response_bytes": 4096,
    }
    arguments[field] = value
    with pytest.raises((LocalModelProcessError, ValueError)):
        materialize_formal_producer_binding(**arguments)


def test_binding_uses_exact_fixed_artifact_constants() -> None:
    binding = _binding()
    assert binding.producer_model_digest == FAULTLOOM_UTILITY_V1_MODEL_DIGEST
    assert (
        binding.producer_runtime_wrapper_digest
        == FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST
    )
