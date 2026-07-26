from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from faultloom.model_utility_proxy import (
    MODEL_SNAPSHOT_TOKEN,
    BoundedProcessLaunch,
    BoundedProcessResult,
    DigestPinnedLocalProcessProxy,
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelProcessRequest,
    LocalModelRuntimeProfile,
)
from faultloom.model_utility_process import BoundedProcessError
from faultloom_sdk import ModelUtilityArm, UtilityDecision
from faultloom.model_utility_sandbox import pinned_process_launch


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _write(path: Path, value: bytes, *, executable: bool = False) -> str:
    _ = path.write_bytes(value)
    if executable:
        path.chmod(0o500)
    return _digest_bytes(value)


def _config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> LocalModelProcessConfig:
    profile_root = tmp_path / "profile"
    profile_root.mkdir()
    monkeypatch.setattr(
        "faultloom.model_utility_sandbox._PROFILE_ROOT",
        profile_root,
    )
    _ = _write(profile_root / "bwrap", b"sandbox", executable=True)
    _ = _write(profile_root / "runtime", b"runtime", executable=True)
    _ = _write(profile_root / "model.gguf", b"model")
    return LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=2,
        maximum_request_bytes=4096,
        maximum_response_bytes=4096,
    )


def _request(config: LocalModelProcessConfig) -> LocalModelProcessRequest:
    return LocalModelProcessRequest(
        request_id="utility-request-1",
        case_id="case.utility.1",
        case_digest=_digest_bytes(b"case"),
        arm=ModelUtilityArm.BASELINE,
        model_snapshot_digest=config.model_snapshot_digest,
        runtime_artifact_digest=config.runtime_executable_digest,
        prompt_digest=_digest_bytes(b"prompt"),
        tool_schema_digest=_digest_bytes(b"tools"),
        budget_digest=_digest_bytes(b"budget"),
        generation_config_digest=_digest_bytes(b"generation"),
        seed=42,
        payload="bounded prompt",
    )


def _response(request: LocalModelProcessRequest) -> bytes:
    output = "local result"
    return json.dumps(
        {
            "request_id": request.request_id,
            "model_snapshot_digest": request.model_snapshot_digest,
            "runtime_artifact_digest": request.runtime_artifact_digest,
            "decision": UtilityDecision.NEGATIVE.value,
            "output": output,
            "output_digest": _digest_bytes(output.encode()),
            "input_tokens": 4,
            "output_tokens": 2,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_proxy_uses_exact_argv_without_shell_and_disables_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: digest-pinned sandbox, runtime, and model artifacts.
    config = _config(tmp_path, monkeypatch)
    request = _request(config)
    captured: list[BoundedProcessLaunch] = []

    def completed(spec: BoundedProcessLaunch) -> BoundedProcessResult:
        captured.append(spec)
        return BoundedProcessResult(returncode=0, stdout=_response(request))

    monkeypatch.setattr(
        "faultloom.model_utility_proxy.run_bounded_process", completed
    )

    # When: the request crosses the local process proxy.
    response = DigestPinnedLocalProcessProxy(config).exchange(request)

    # Then: launch identity and isolation are fixed before output is accepted.
    assert response.request_id == request.request_id
    assert len(captured) == 1
    launch = captured[0]
    assert launch.shell is False
    assert "--unshare-net" in launch.argv
    assert "--clearenv" in launch.argv
    assert MODEL_SNAPSHOT_TOKEN not in launch.argv
    assert "/opt/faultloom/model-snapshot" in launch.argv
    assert launch.environment == {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}


def test_proxy_rejects_substituted_model_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a model file changed after its digest was pinned.
    config = _config(tmp_path, monkeypatch)
    _ = (tmp_path / "profile" / "model.gguf").write_bytes(b"substituted")
    launched = False

    def unexpected(_spec: BoundedProcessLaunch) -> BoundedProcessResult:
        nonlocal launched
        launched = True
        raise AssertionError("must not launch")

    monkeypatch.setattr(
        "faultloom.model_utility_proxy.run_bounded_process", unexpected
    )

    # When / Then: the mismatch stops before process launch.
    with pytest.raises(LocalModelProcessError, match="model snapshot digest"):
        _ = DigestPinnedLocalProcessProxy(config).exchange(_request(config))
    assert launched is False


@pytest.mark.parametrize(
    ("result", "message"),
    (
        (BoundedProcessResult(returncode=9, stdout=b""), "nonzero status"),
        (
            BoundedProcessResult(
                returncode=0,
                stdout=b'{"API_KEY":"do-not-leak"',
            ),
            "malformed response",
        ),
    ),
)
def test_proxy_rejects_nonzero_and_malformed_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: BoundedProcessResult,
    message: str,
) -> None:
    config = _config(tmp_path, monkeypatch)

    def completed(_spec: BoundedProcessLaunch) -> BoundedProcessResult:
        return result

    monkeypatch.setattr(
        "faultloom.model_utility_proxy.run_bounded_process",
        completed,
    )

    with pytest.raises(LocalModelProcessError, match=message) as proxy_error:
        _ = DigestPinnedLocalProcessProxy(config).exchange(_request(config))
    assert "do-not-leak" not in str(proxy_error.value)
    assert proxy_error.value.__context__ is None


def test_proxy_maps_timeout_and_scrubs_process_error_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, monkeypatch)
    request = _request(config)

    def timed_out(_spec: BoundedProcessLaunch) -> BoundedProcessResult:
        raise subprocess.TimeoutExpired("API_KEY=do-not-leak", 2)

    monkeypatch.setattr(
        "faultloom.model_utility_proxy.run_bounded_process", timed_out
    )
    with pytest.raises(LocalModelProcessError, match="timed out") as timeout_error:
        _ = DigestPinnedLocalProcessProxy(config).exchange(request)
    assert "do-not-leak" not in str(timeout_error.value)
    assert timeout_error.value.__cause__ is None
    assert timeout_error.value.__context__ is None

    def process_error(_spec: BoundedProcessLaunch) -> BoundedProcessResult:
        raise OSError("API_KEY=do-not-leak")

    monkeypatch.setattr(
        "faultloom.model_utility_proxy.run_bounded_process", process_error
    )
    with pytest.raises(LocalModelProcessError, match="launch failed") as launch_error:
        _ = DigestPinnedLocalProcessProxy(config).exchange(request)
    assert "do-not-leak" not in str(launch_error.value)
    assert launch_error.value.__cause__ is None
    assert launch_error.value.__context__ is None

    def bounded_error(_spec: BoundedProcessLaunch) -> BoundedProcessResult:
        raise BoundedProcessError("API_KEY=do-not-leak")

    monkeypatch.setattr(
        "faultloom.model_utility_proxy.run_bounded_process", bounded_error
    )
    with pytest.raises(LocalModelProcessError, match="I/O limit") as limit_error:
        _ = DigestPinnedLocalProcessProxy(config).exchange(request)
    assert "do-not-leak" not in str(limit_error.value)
    assert limit_error.value.__cause__ is None
    assert limit_error.value.__context__ is None


def test_config_rejects_caller_selected_artifacts_and_runtime_arguments(
    tmp_path: Path,
) -> None:
    # Given: an operator selects executable paths and server-style runtime arguments.
    document = {
        "sandbox_executable": tmp_path / "operator-bwrap",
        "sandbox_executable_digest": _digest_bytes(b"operator-bwrap"),
        "runtime_executable": tmp_path / "operator-runtime",
        "runtime_executable_digest": _digest_bytes(b"operator-runtime"),
        "model_snapshot": tmp_path / "operator-model",
        "model_snapshot_digest": _digest_bytes(b"operator-model"),
        "runtime_arguments": (
            "--listen",
            "0.0.0.0",
            "--api-key=secret",
            MODEL_SNAPSHOT_TOKEN,
        ),
        "timeout_seconds": 2,
        "maximum_request_bytes": 4096,
        "maximum_response_bytes": 4096,
    }

    # When / Then: the typed boundary exposes no caller-selected path or argv surface.
    with pytest.raises(ValidationError) as config_error:
        _ = LocalModelProcessConfig.model_validate(document)
    assert "secret" not in str(config_error.value)


def test_verified_model_bytes_are_immutable_after_source_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a verified model descriptor prepared for one sandbox launch.
    config = _config(tmp_path, monkeypatch)
    with pinned_process_launch(config, b"request") as launch:
        before = os.pread(launch.pass_fds[2], 5, 0)

        # When: the caller rewrites the original inode after verification.
        _ = (tmp_path / "profile" / "model.gguf").write_bytes(b"raced")
        after = os.pread(launch.pass_fds[2], 5, 0)

    # Then: launched bytes remain the exact verified snapshot.
    assert before == b"model"
    assert after == before


def test_artifact_open_error_does_not_retain_raw_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, monkeypatch)

    def denied(*_args: object, **_kwargs: object) -> int:
        raise OSError("API_KEY=do-not-leak")

    monkeypatch.setattr("faultloom.model_utility_sandbox.os.open", denied)
    with pytest.raises(LocalModelProcessError, match="unavailable") as artifact_error:
        with pinned_process_launch(config, b"request"):
            raise AssertionError("must not yield")
    assert "do-not-leak" not in str(artifact_error.value)
    assert artifact_error.value.__cause__ is None
    assert artifact_error.value.__context__ is None


def test_artifact_staging_error_does_not_retain_raw_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, monkeypatch)

    def denied(_descriptor: int) -> os.stat_result:
        raise OSError("API_KEY=do-not-leak")

    monkeypatch.setattr("faultloom.model_utility_sandbox.os.fstat", denied)
    with pytest.raises(LocalModelProcessError, match="unavailable") as artifact_error:
        with pinned_process_launch(config, b"request"):
            raise AssertionError("must not yield")
    assert "do-not-leak" not in str(artifact_error.value)
    assert artifact_error.value.__cause__ is None
    assert artifact_error.value.__context__ is None
