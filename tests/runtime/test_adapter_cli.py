from __future__ import annotations

import json

import pytest

from faultloom import cli
from faultloom.adapter_cli import AdapterCliError


def test_adapter_list_and_doctor_expose_only_pinned_offline_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["adapter", "list"]) == cli.EXIT_OK
    listed = json.loads(capsys.readouterr().out)
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
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["installed"] is True
    assert doctor["manifest_pinned"] is True
    assert doctor["direct_target_socket"] is False
    assert doctor["dispatch_performed"] is False


def test_adapter_test_is_local_and_stops_before_model_utility(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["adapter", "test", "adapter.reference"]) == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["contract"] == "passed"
    assert result["fidelity"] == "passed"
    assert result["model_utility"] == "not_run"
    assert result["state"] == "pending_model_utility"
    assert result["dispatch_performed"] is False
    assert result["network_access"] == "none"


@pytest.mark.parametrize("operation", ("doctor", "test"))
def test_adapter_commands_fail_closed_for_absent_adapter(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    process_started = False

    def unexpected_client(*_args: object, **_kwargs: object) -> None:
        nonlocal process_started
        process_started = True
        raise AdapterCliError("must not start")

    monkeypatch.setattr("faultloom.adapter_cli.ReferenceProcessClient", unexpected_client)
    assert cli.main(["adapter", operation, "adapter.absent"]) == cli.EXIT_UNAVAILABLE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "adapter is not installed" in captured.err
    assert process_started is False
