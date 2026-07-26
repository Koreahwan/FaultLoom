from __future__ import annotations

from pathlib import Path
from typing_extensions import TypedDict

import pytest
from pydantic import TypeAdapter

from faultloom import cli
from faultloom.adapter_cli import AdapterCliError
from faultloom.model_utility_proxy import (
    LocalModelProcessConfig,
    LocalModelRuntimeProfile,
)
from faultloom_protocol.models import AdapterManifest

class _AdapterListItem(TypedDict):
    adapter_id: str
    evidence_capability: str
    manifest_digest: str
    network_mode: str
    state: str
    update_policy: str
    version: str


class _AdapterListResult(TypedDict):
    adapters: list[_AdapterListItem]


class _DoctorResult(TypedDict):
    direct_target_socket: bool
    dispatch_performed: bool
    installed: bool
    manifest_pinned: bool


class _AdapterTestResult(TypedDict):
    contract: str
    dispatch_performed: bool
    fidelity: str
    model_utility: str
    network_access: str
    state: str


class _UtilityTestResult(TypedDict):
    model_utility: str
    reason: str
    state: str


_ADAPTER_LIST_RESULT = TypeAdapter(_AdapterListResult)
_DOCTOR_RESULT = TypeAdapter(_DoctorResult)
_ADAPTER_TEST_RESULT = TypeAdapter(_AdapterTestResult)
_UTILITY_TEST_RESULT = TypeAdapter(_UtilityTestResult)


def test_adapter_list_and_doctor_expose_only_pinned_offline_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["adapter", "list"]) == cli.EXIT_OK
    listed = _ADAPTER_LIST_RESULT.validate_json(capsys.readouterr().out)
    assert listed == {
        "adapters": [
            {
                "adapter_id": "adapter.reference",
                "evidence_capability": "candidate_only",
                "manifest_digest": listed["adapters"][0]["manifest_digest"],
                "network_mode": "none",
                "state": "pending_contract",
                "update_policy": "pinned_no_runtime_updates",
                "version": "0.1.0",
            }
        ]
    }
    assert listed["adapters"][0]["manifest_digest"].startswith("sha256:")

    assert cli.main(["adapter", "doctor", "adapter.reference"]) == cli.EXIT_OK
    doctor = _DOCTOR_RESULT.validate_json(capsys.readouterr().out)
    assert doctor["installed"] is True
    assert doctor["manifest_pinned"] is True
    assert doctor["direct_target_socket"] is False
    assert doctor["dispatch_performed"] is False


def test_adapter_test_is_local_and_stops_before_model_utility(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["adapter", "test", "adapter.reference"]) == cli.EXIT_UNAVAILABLE
    result = _ADAPTER_TEST_RESULT.validate_json(capsys.readouterr().out)
    assert result["contract"] == "passed"
    assert result["fidelity"] == "passed"
    assert result["model_utility"] == "not_run"
    assert result["state"] == "pending_model_utility"
    assert result["dispatch_performed"] is False
    assert result["network_access"] == "none"


def test_adapter_utility_test_is_pending_when_config_is_absent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: no typed local-model configuration artifact.
    missing = tmp_path / "missing-model-utility.json"

    # When: the explicit utility command is requested.
    exit_code = cli.main(
        ["adapter", "utility-test", "adapter.reference", "--config", str(missing)]
    )

    # Then: the CLI reports pending evidence and exits nonzero.
    assert exit_code == cli.EXIT_UNAVAILABLE
    result = _UTILITY_TEST_RESULT.validate_json(capsys.readouterr().out)
    assert result["state"] == "pending_model_utility"
    assert result["model_utility"] == "not_run"
    assert result["reason"] == "configuration_unavailable"


def test_adapter_utility_test_is_pending_when_pinned_artifacts_are_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: a valid typed config whose pinned local artifacts do not exist.
    monkeypatch.setattr(
        "faultloom.model_utility_sandbox._PROFILE_ROOT",
        tmp_path / "missing-profile",
    )
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=2,
        maximum_request_bytes=4096,
        maximum_response_bytes=4096,
    )
    config_path = tmp_path / "model-utility.json"
    _ = config_path.write_text(config.model_dump_json(), encoding="utf-8")

    # When: artifact preflight runs without launching a model.
    exit_code = cli.main(
        [
            "adapter",
            "utility-test",
            "adapter.reference",
            "--config",
            str(config_path),
        ]
    )

    # Then: missing evidence is explicit and cannot become admission.
    assert exit_code == cli.EXIT_UNAVAILABLE
    result = _UTILITY_TEST_RESULT.validate_json(capsys.readouterr().out)
    assert result["state"] == "pending_model_utility"
    assert result["reason"] == "artifact_unavailable"


@pytest.mark.parametrize("operation", ("doctor", "test"))
def test_adapter_commands_fail_closed_for_absent_adapter(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    process_started = False

    def unexpected_client(
        *,
        expected_adapter_manifest: AdapterManifest,
        timeout_seconds: int = 5,
    ) -> None:
        nonlocal process_started
        _ = expected_adapter_manifest
        _ = timeout_seconds
        process_started = True
        raise AdapterCliError("must not start")

    monkeypatch.setattr("faultloom.adapter_cli.ReferenceProcessClient", unexpected_client)
    assert cli.main(["adapter", operation, "adapter.absent"]) == cli.EXIT_UNAVAILABLE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "adapter is not installed" in captured.err
    assert process_started is False
