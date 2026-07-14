from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from faultloom import cli
from faultloom.resume import CheckpointController, trust_policy_for
from tests.protocol.factories import D1
from tests.runtime.resume_support import (
    KEY_BYTES,
    anchor_root,
    make_context,
    open_store,
    state_root,
    write_checkpoint,
)


def _resume_arguments(root: Path, *, command: str = "resume") -> list[str]:
    return [
        command,
        "run.1",
        "--state-root",
        str(state_root(root)),
        "--anchor-root",
        str(anchor_root(root)),
        "--trust-policy",
        str(root / "resume-trust.json"),
        "--engagement-key-file",
        str(root / "engagement.key"),
    ]


def _persist_resume_fixture(
    root: Path,
    *,
    unknown: tuple[str, ...] = (),
) -> None:
    with open_store(root) as active:
        packet = write_checkpoint(
            CheckpointController(active),
            make_context(unknown=unknown),
        )
        policy = trust_policy_for(packet, minimum_anchor=active.checkpoint())
    (root / "resume-trust.json").write_text(
        policy.model_dump_json(indent=2),
        encoding="utf-8",
    )
    key_path = root / "engagement.key"
    key_path.write_text(KEY_BYTES.hex() + "\n", encoding="ascii")
    key_path.chmod(0o600)


@pytest.mark.parametrize("command", ("resume", "inspect"))
def test_resume_commands_declare_offline_durable_inputs(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: the public offline resume command surface.
    # When: an operator requests command-specific help.
    with pytest.raises(SystemExit) as stopped:
        cli.main([command, "--help"])

    # Then: every trust and storage input is explicit and no network option exists.
    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    assert "--state-root" in help_text
    assert "--anchor-root" in help_text
    assert "--trust-policy" in help_text
    assert "--engagement-key-file" in help_text
    assert "--url" not in help_text


def test_resume_cli_restores_a_safe_checkpoint_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _persist_resume_fixture(tmp_path)

    def blocked_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("resume opened a network socket")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    exit_code = cli.main(_resume_arguments(tmp_path))

    assert exit_code == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["operation"] == "resume"
    assert result["network_access"] == "none"
    assert result["dispatch_performed"] is False
    assert result["checkpoint_id"] == "checkpoint.1"
    assert result["run_id"] == "run.1"
    assert result["automatic_retry_action_ids"] == []


def test_inspect_cli_reports_unknown_outcome_without_dispatch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _persist_resume_fixture(tmp_path, unknown=("action.unknown",))

    exit_code = cli.main(_resume_arguments(tmp_path, command="inspect"))

    assert exit_code == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["operation"] == "inspect"
    assert result["unknown_outcome_action_ids"] == ["action.unknown"]
    assert result["requires_reconciliation"] is True
    assert result["dispatch_performed"] is False


def test_resume_cli_refuses_unknown_outcome_actions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _persist_resume_fixture(tmp_path, unknown=("action.unknown",))

    exit_code = cli.main(_resume_arguments(tmp_path))

    assert exit_code == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "reconciliation" in captured.err
    assert "action.unknown" not in captured.err


def test_resume_cli_refuses_tampered_trust_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _persist_resume_fixture(tmp_path)
    policy_path = tmp_path / "resume-trust.json"
    document = json.loads(policy_path.read_text(encoding="utf-8"))
    document["goal_digest"] = D1
    policy_path.write_text(json.dumps(document), encoding="utf-8")

    exit_code = cli.main(_resume_arguments(tmp_path))

    assert exit_code == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""


def test_resume_cli_refuses_corrupt_checkpoint_ciphertext(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _persist_resume_fixture(tmp_path)
    with open_store(tmp_path) as active:
        assert active.ledger is not None
        reference = active.ledger.events()[0].payload["artifact_ref"]
    digest = reference["sha256"]
    namespace = hashlib.sha256(b"engagement.1").hexdigest()
    ciphertext = (
        state_root(tmp_path)
        / "cas"
        / namespace
        / digest[:2]
        / f"{digest}.flcas"
    )
    body = bytearray(ciphertext.read_bytes())
    body[-1] ^= 1
    ciphertext.write_bytes(body)

    exit_code = cli.main(_resume_arguments(tmp_path))

    assert exit_code == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""


def test_resume_cli_refuses_non_private_engagement_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _persist_resume_fixture(tmp_path)
    (tmp_path / "engagement.key").chmod(0o644)

    exit_code = cli.main(_resume_arguments(tmp_path))

    assert exit_code == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""
