from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from faultloom import model_utility_process as bounded_process
import faultloom.model_utility_sandbox as model_utility_sandbox
from faultloom.model_utility_attestation_state import (
    AttestationStateError,
    MonotonicAttestationState,
)
from faultloom.model_utility_attestor import (
    ProducerAttestorRequest,
    ProducerAttestorResponse,
    TransientModelUtilityAttestor,
    exchange_with_transcript,
    parse_producer_attestor_request,
)
from faultloom.model_utility_process import BoundedProcessLaunch, BoundedProcessResult
from faultloom.model_utility_proxy import DigestPinnedLocalProcessProxy
from faultloom.model_utility_proxy_models import (
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelProcessRequest,
    LocalModelRuntimeProfile,
)
from faultloom.model_utility_sandbox import canonical_model_utility_launch_digest
from faultloom_protocol import (
    AuthoritySigner,
    verify_model_producer_attestation,
)
from faultloom_sdk import ModelUtilityArm, UtilityDecision


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _wire(value: object) -> bytes:
    assert hasattr(value, "model_dump")
    return json.dumps(
        value.model_dump(mode="json"),  # type: ignore[union-attr]
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _config() -> LocalModelProcessConfig:
    return LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=2,
        maximum_request_bytes=4096,
        maximum_response_bytes=4096,
    )


def _request(config: LocalModelProcessConfig) -> LocalModelProcessRequest:
    return LocalModelProcessRequest(
        request_id="utility-request-1",
        case_id="case-1",
        case_digest=_digest(b"case"),
        arm=ModelUtilityArm.BASELINE,
        model_snapshot_digest=config.model_snapshot_digest,
        runtime_artifact_digest=config.runtime_executable_digest,
        prompt_digest=_digest(b"prompt"),
        tool_schema_digest=_digest(b"schema"),
        budget_digest=_digest(b"budget"),
        generation_config_digest=_digest(b"generation"),
        seed=42,
        payload="private producer input",
    )


def _response(request: LocalModelProcessRequest) -> bytes:
    output = "model output"
    return json.dumps(
        {
            "request_id": request.request_id,
            "model_snapshot_digest": request.model_snapshot_digest,
            "runtime_artifact_digest": request.runtime_artifact_digest,
            "decision": UtilityDecision.POSITIVE.value,
            "output": output,
            "output_digest": _digest(output.encode()),
            "raw_llama_stdout_digest": _digest(b"actual llama stdout"),
            "input_tokens": 7,
            "output_tokens": 3,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _producer_frame(request: LocalModelProcessRequest) -> ProducerAttestorRequest:
    return ProducerAttestorRequest(
        request=request,
        session_id="model-session-1",
        evaluator_challenge="0123456789abcdef" * 4,
        allocation_id="producer-allocation-1",
        trusted_minimum_sequence=0,
    )


@contextmanager
def _held_launch(
    config: LocalModelProcessConfig,
    stdin: bytes = b"",
) -> Generator[BoundedProcessLaunch, None, None]:
    descriptors = tuple(os.open(os.devnull, os.O_RDONLY) for _ in range(4))
    try:
        yield model_utility_sandbox._launch(config, stdin, descriptors)
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_canonical_launch_digest_normalizes_only_four_held_descriptor_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    with _held_launch(config) as first, _held_launch(config) as second:
        first_digest = canonical_model_utility_launch_digest(first)
        assert canonical_model_utility_launch_digest(second) == first_digest

        altered_argv = list(first.argv)
        altered_argv[altered_argv.index("--uid") + 1] = "1"
        with pytest.raises(LocalModelProcessError, match="argv template is invalid"):
            canonical_model_utility_launch_digest(
                replace(first, argv=tuple(altered_argv))
            )

        with pytest.raises(LocalModelProcessError, match="descriptors are invalid"):
            canonical_model_utility_launch_digest(
                replace(first, pass_fds=first.pass_fds[:-1])
            )
        with pytest.raises(LocalModelProcessError, match="descriptors are invalid"):
            canonical_model_utility_launch_digest(
                replace(
                    first,
                    pass_fds=(
                        first.pass_fds[0],
                        first.pass_fds[1],
                        first.pass_fds[1],
                        first.pass_fds[3],
                    ),
                )
            )

        with monkeypatch.context() as scoped:
            scoped.setattr(
                model_utility_sandbox,
                "_DESCRIPTOR_TOKENS",
                ("same", "same", "model", "bundle"),
            )
            with pytest.raises(LocalModelProcessError, match="tokens are invalid"):
                canonical_model_utility_launch_digest(first)

        wrong_source = list(first.argv)
        first_binding = wrong_source.index("--ro-bind-data") + 1
        wrong_source[first_binding] = str(second.pass_fds[1])
        with pytest.raises(LocalModelProcessError, match="argv template is invalid"):
            canonical_model_utility_launch_digest(
                replace(first, argv=tuple(wrong_source))
            )

        misplaced_source = list(first.argv)
        misplaced_source[first_binding], misplaced_source[first_binding + 1] = (
            misplaced_source[first_binding + 1],
            misplaced_source[first_binding],
        )
        with pytest.raises(LocalModelProcessError, match="argv template is invalid"):
            canonical_model_utility_launch_digest(
                replace(first, argv=tuple(misplaced_source))
            )

    with _held_launch(config) as closed_launch:
        os.close(closed_launch.pass_fds[0])
        with pytest.raises(LocalModelProcessError, match="unavailable"):
            canonical_model_utility_launch_digest(closed_launch)


def test_supervisor_wrapper_does_not_change_canonical_model_launch_digest() -> None:
    config = _config()
    with _held_launch(config) as launch:
        expected = canonical_model_utility_launch_digest(launch)
        _ = bounded_process._supervisor_argv(launch)
        assert canonical_model_utility_launch_digest(launch) == expected


def test_state_is_monotonic_across_restart_and_concurrency(tmp_path: Path) -> None:
    path = tmp_path / "sequences.sqlite3"
    with MonotonicAttestationState(path) as state:
        assert state.allocate("initial") == 1
    with MonotonicAttestationState(path) as restarted:
        assert restarted.allocate("after-restart", trusted_minimum_sequence=1) == 2
        with pytest.raises(AttestationStateError, match="reuse"):
            restarted.allocate("initial")
        with ThreadPoolExecutor(max_workers=8) as pool:
            allocated = list(pool.map(lambda i: restarted.allocate(f"parallel-{i}"), range(16)))
    assert sorted(allocated) == list(range(3, 19))

    collision_path = tmp_path / "collision.sqlite3"

    def collide(_index: int) -> int | AttestationStateError:
        try:
            with MonotonicAttestationState(collision_path) as state:
                return state.allocate("same-allocation")
        except AttestationStateError as error:
            return error

    with ThreadPoolExecutor(max_workers=8) as pool:
        collisions = list(pool.map(collide, range(8)))
    assert [value for value in collisions if type(value) is int] == [1]
    assert len([value for value in collisions if isinstance(value, AttestationStateError)]) == 7
    assert path.stat().st_mode & 0o777 == 0o600


def test_state_rejects_symlink_hardlink_and_preexisting_0644(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    symlink = tmp_path / "symlink.sqlite3"
    symlink.symlink_to(target)
    with pytest.raises(AttestationStateError, match="metadata"):
        MonotonicAttestationState(symlink)

    insecure = tmp_path / "insecure.sqlite3"
    insecure.touch(mode=0o644)
    with pytest.raises(AttestationStateError, match="metadata"):
        MonotonicAttestationState(insecure)

    hardlink = tmp_path / "hardlink.sqlite3"
    os.link(target, hardlink)
    with pytest.raises(AttestationStateError, match="metadata"):
        MonotonicAttestationState(target)

    parent = tmp_path / "stable-parent"
    parent.mkdir()
    with MonotonicAttestationState(parent / "state.sqlite3") as state:
        parent.rename(tmp_path / "moved-parent")
        parent.mkdir()
        with pytest.raises(AttestationStateError, match="parent identity"):
            state.allocate("must-not-write")


def test_state_rejects_rollback_corruption_and_opt(tmp_path: Path) -> None:
    with MonotonicAttestationState(tmp_path / "rollback.sqlite3") as state:
        assert state.allocate("one") == 1
        with pytest.raises(AttestationStateError, match="rollback"):
            state.allocate("two", trusted_minimum_sequence=2)
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not sqlite")
    corrupt.chmod(0o600)
    with pytest.raises(AttestationStateError, match="corrupt"):
        MonotonicAttestationState(corrupt)
    with pytest.raises(AttestationStateError, match="outside /opt"):
        MonotonicAttestationState(Path("/opt/faultloom-state.sqlite3"))


def test_state_leaf_swap_never_redirects_open_fd_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.journal"
    moved = tmp_path / "original.journal"
    with MonotonicAttestationState(path) as state:
        original_identity = (path.stat().st_dev, path.stat().st_ino)
        original_validate = MonotonicAttestationState._validate_identities
        swapped = False

        def validate_then_swap(current: MonotonicAttestationState) -> None:
            nonlocal swapped
            original_validate(current)
            if not swapped:
                path.rename(moved)
                path.write_bytes(b"attacker-controlled replacement\n")
                path.chmod(0o600)
                swapped = True

        monkeypatch.setattr(
            MonotonicAttestationState,
            "_validate_identities",
            validate_then_swap,
        )
        with pytest.raises(AttestationStateError, match="identity changed"):
            state.allocate("swap-attempt")
    assert (moved.stat().st_dev, moved.stat().st_ino) == original_identity
    assert b"swap-attempt" in moved.read_bytes()
    assert path.read_bytes() == b"attacker-controlled replacement\n"


def test_state_cross_process_monotonicity_and_restart_durability(tmp_path: Path) -> None:
    state_path = tmp_path / "cross-process.journal"
    script = """
import pathlib
import sys
from faultloom.model_utility_attestation_state import MonotonicAttestationState
with MonotonicAttestationState(pathlib.Path(sys.argv[1])) as state:
    print(state.allocate(sys.argv[2], trusted_minimum_sequence=int(sys.argv[3])))
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = "packages/protocol/src:packages/sdk/src:packages/runtime/src"
    processes = [
        subprocess.Popen(
            (sys.executable, "-c", script, str(state_path), f"worker-{index}", "0"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        for index in range(8)
    ]
    completed = [process.communicate(timeout=10) for process in processes]
    assert [process.returncode for process in processes] == [0] * 8
    assert sorted(int(stdout) for stdout, _stderr in completed) == list(range(1, 9))
    restarted = subprocess.run(
        (sys.executable, "-c", script, str(state_path), "after-restart", "8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=10,
        check=False,
    )
    assert restarted.returncode == 0
    assert restarted.stdout == b"9\n"
    assert restarted.stderr == b""


def test_attestor_binds_actual_llama_digest_and_exact_canonical_transcript(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    request = _request(config)
    raw_wrapper_stdout = _response(request) + b"\n"
    @contextmanager
    def pinned(_config_value: object, encoded: bytes):
        assert encoded == _wire(request) + b"\n"
        with _held_launch(config, encoded) as launch:
            yield launch

    monkeypatch.setattr("faultloom.model_utility_attestor.pinned_process_launch", pinned)
    monkeypatch.setattr(
        "faultloom.model_utility_attestor.run_bounded_process",
        lambda _launch: BoundedProcessResult(returncode=0, stdout=raw_wrapper_stdout),
    )
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    with MonotonicAttestationState(tmp_path / "producer.sqlite3") as state:
        result = TransientModelUtilityAttestor(
            proxy=DigestPinnedLocalProcessProxy(config),
            signer=signer,
            sequence_state=state,
            core_wheel_digest=_digest(b"core-wheel"),
        ).exchange(
            request,
            session_id="model-session-1",
            evaluator_challenge="0123456789abcdef" * 4,
            allocation_id="producer-allocation-1",
        )
    payload = result.producer_receipt.payload
    assert payload.canonical_request_digest == _digest(_wire(request))
    assert payload.parsed_response_digest == _digest(_wire(result.response))
    assert payload.raw_llama_stdout_digest == _digest(b"actual llama stdout")
    assert payload.raw_llama_stdout_digest != _digest(raw_wrapper_stdout)
    assert payload.output_digest == result.response.output_digest
    with _held_launch(config) as equivalent_launch:
        assert payload.fixed_argv_digest == canonical_model_utility_launch_digest(
            equivalent_launch
        )
    verified = verify_model_producer_attestation(
        result.producer_receipt,
        {signer.key_id: signer.public_key_record},
        minimum_sequence=1,
        expected_session_id="model-session-1",
        expected_evaluator_challenge="0123456789abcdef" * 4,
    )
    assert verified.fixed_argv_digest == payload.fixed_argv_digest


def test_attestor_rejects_noncanonical_wrapper_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    request = _request(config)
    canonical = _response(request) + b"\n"
    noncanonical = json.dumps(json.loads(canonical), sort_keys=True).encode() + b"\n"
    @contextmanager
    def pinned(_config_value: object, _encoded: bytes):
        with _held_launch(config) as launch:
            yield launch

    monkeypatch.setattr("faultloom.model_utility_attestor.pinned_process_launch", pinned)
    monkeypatch.setattr(
        "faultloom.model_utility_attestor.run_bounded_process",
        lambda _launch: BoundedProcessResult(returncode=0, stdout=noncanonical),
    )
    with pytest.raises(LocalModelProcessError, match="not canonical"):
        exchange_with_transcript(DigestPinnedLocalProcessProxy(config), request)


def test_producer_cli_frame_rejects_noncanonical_oversize_and_trailing_input() -> None:
    request = _producer_frame(_request(_config()))
    canonical = _wire(request) + b"\n"
    assert parse_producer_attestor_request(canonical) == request
    spaced = json.dumps(request.model_dump(mode="json"), sort_keys=True).encode() + b"\n"
    with pytest.raises(LocalModelProcessError, match="canonical"):
        parse_producer_attestor_request(spaced)
    with pytest.raises(LocalModelProcessError, match="framing"):
        parse_producer_attestor_request(canonical + b"{}")
    with pytest.raises(LocalModelProcessError, match="framing"):
        parse_producer_attestor_request(b"x" * (16_781_312 + 1))


def test_producer_cli_rejects_missing_key_and_wrong_profile_without_output(
    tmp_path: Path,
) -> None:
    environment = dict(os.environ)
    roots = "packages/protocol/src:packages/sdk/src:packages/runtime/src"
    environment["PYTHONPATH"] = roots
    base = (
        sys.executable,
        "-m",
        "faultloom.model_utility_attestor",
        "--signing-key-fd",
        "99999",
        "--state",
        str(tmp_path / "state.sqlite3"),
        "--profile",
        LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1.value,
        "--timeout-seconds",
        "2",
        "--maximum-request-bytes",
        "4096",
        "--maximum-response-bytes",
        "4096",
        "--core-wheel-digest",
        _digest(b"wheel"),
    )
    framed = _wire(_producer_frame(_request(_config()))) + b"\n"
    missing_key = subprocess.run(
        base,
        input=framed,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=5,
        check=False,
    )
    assert missing_key.returncode == 2
    assert missing_key.stdout == b""
    wrong_profile = subprocess.run(
        tuple("unknown-profile" if value == LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1.value else value for value in base),
        input=framed,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=5,
        check=False,
    )
    assert wrong_profile.returncode == 2
    assert wrong_profile.stdout == b""


def test_producer_cli_one_shot_success_emits_one_canonical_signed_envelope(
    tmp_path: Path,
) -> None:
    config = _config()
    request = _request(config)
    framed = _wire(_producer_frame(request)) + b"\n"
    response = _response(request)
    script = f"""
import faultloom.model_utility_attestor as module
from faultloom.model_utility_attestor import ModelUtilityExchangeTranscript
from faultloom.model_utility_proxy_models import LocalModelProcessResponse
parsed = LocalModelProcessResponse.model_validate_json({response!r})
module.exchange_with_transcript = lambda _proxy, _request: ModelUtilityExchangeTranscript(
    response=parsed,
    fixed_argv_digest={_digest(b'fixed argv')!r},
)
raise SystemExit(module.main())
"""
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    read_fd, write_fd = os.pipe()
    os.write(write_fd, bytes(range(32)))
    os.close(write_fd)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = "packages/protocol/src:packages/sdk/src:packages/runtime/src"
    process = subprocess.run(
        (
            sys.executable,
            "-c",
            script,
            "--signing-key-fd",
            str(read_fd),
            "--state",
            str(tmp_path / "success.sqlite3"),
            "--profile",
            LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1.value,
            "--timeout-seconds",
            "2",
            "--maximum-request-bytes",
            "4096",
            "--maximum-response-bytes",
            "4096",
            "--core-wheel-digest",
            _digest(b"wheel"),
        ),
        input=framed,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(read_fd,),
        env=environment,
        timeout=5,
        check=False,
    )
    os.close(read_fd)
    assert process.returncode == 0
    assert process.stderr == b""
    assert process.stdout.endswith(b"\n") and process.stdout.count(b"\n") == 1
    parsed = ProducerAttestorResponse.model_validate_json(process.stdout[:-1])
    assert process.stdout[:-1] == _wire(parsed)
    verified = verify_model_producer_attestation(
        parsed.producer_receipt,
        {signer.key_id: signer.public_key_record},
        minimum_sequence=1,
        expected_session_id="model-session-1",
        expected_evaluator_challenge="0123456789abcdef" * 4,
    )
    assert verified.raw_llama_stdout_digest == _digest(b"actual llama stdout")
    assert (tmp_path / "success.sqlite3").stat().st_mode & 0o777 == 0o600


def test_operator_injected_signer_fingerprint_is_bound(tmp_path: Path) -> None:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    raw = base64.urlsafe_b64decode(signer.public_key_record.public_key + "==")
    assert _digest(raw).endswith(signer.key_id.removeprefix("ed25519:sha256:"))
    with pytest.raises(TypeError, match="operator-injected"):
        TransientModelUtilityAttestor(
            proxy=DigestPinnedLocalProcessProxy(_config()),
            signer=object(),  # type: ignore[arg-type]
            sequence_state=MonotonicAttestationState(tmp_path / "unused.sqlite3"),
            core_wheel_digest=_digest(b"wheel"),
        )
