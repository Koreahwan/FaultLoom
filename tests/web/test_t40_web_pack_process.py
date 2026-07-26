from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from faultloom.model_utility_process import BoundedProcessLaunch, run_bounded_process
from faultloom.t40_web_pack_process import WebPackProcessClient, WebPackProcessError
from faultloom_protocol import canonical_json_bytes
from faultloom_web import t40_worker
from labs.web_api import web_api_fixture


def _request_bytes() -> bytes:
    request = web_api_fixture().positive
    return canonical_json_bytes(request.model_dump(mode="json")) + b"\n"


def _wait_for_pid_exit(pid_file: Path) -> None:
    assert pid_file.is_file()
    pid = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 3.0
    while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not Path(f"/proc/{pid}").exists()


def test_worker_executes_the_real_web_facade_and_redacts_its_result() -> None:
    encoded = _request_bytes()
    response = json.loads(t40_worker._serve(encoded))

    assert response["request_digest"]
    assert response["result_digest"]
    assert response["component_use"] == {
        "api_async": True,
        "cross_surface_chain": True,
        "identity_workflow": True,
    }
    assert set(response["component_digests"]) == set(response["component_use"])
    assert "correlation" not in response
    assert "compiled_intents" not in response


def test_client_rejects_tampered_worker_output_via_its_only_private_exchange_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = web_api_fixture().positive
    response = json.loads(t40_worker._serve(_request_bytes()))
    response["worker_artifact_digest"] = "sha256:" + "0" * 64
    tampered = canonical_json_bytes(response) + b"\n"
    client = WebPackProcessClient()
    monkeypatch.setattr(client, "_fixed_exchange", lambda _encoded: tampered)

    with pytest.raises(WebPackProcessError, match="worker digest"):
        client.run(request)


def test_worker_rejects_extra_fields_noncanonical_framing_and_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extra = json.loads(_request_bytes())
    extra["unexpected"] = "rejected"
    with pytest.raises(ValueError, match="request is invalid"):
        t40_worker._serve(canonical_json_bytes(extra) + b"\n")
    with pytest.raises(ValueError, match="one JSON line"):
        t40_worker._serve(_request_bytes() + b"\n")
    monkeypatch.setattr(sys, "argv", ["t40_worker.py", "--path", "/tmp/nope"])
    assert t40_worker.main() == 64


def test_timeout_exchange_reaps_descendants_without_mutating_worker_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "descendant.pid"
    executable = (
        "import os, pathlib, signal, time\n"
        f"pid_file = pathlib.Path({str(pid_file)!r})\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    pid_file.write_text(str(os.getpid()), encoding='utf-8')\n"
        "    time.sleep(60)\n"
        "else:\n"
        "    time.sleep(60)\n"
    )
    client = WebPackProcessClient(timeout_seconds=1)

    def timeout_exchange(_encoded: bytes) -> bytes:
        launch = BoundedProcessLaunch(
            argv=(sys.executable, "-c", executable),
            stdin=b"",
            environment={"PATH": "/usr/bin:/bin"},
            pass_fds=(),
            timeout_seconds=1,
            maximum_stdout_bytes=4096,
            maximum_stderr_bytes=4096,
        )
        with pytest.raises(subprocess.TimeoutExpired):
            run_bounded_process(launch)
        raise WebPackProcessError("test timeout exchange")

    monkeypatch.setattr(client, "_fixed_exchange", timeout_exchange)
    with pytest.raises(WebPackProcessError, match="test timeout exchange"):
        client.run(web_api_fixture().positive)
    _wait_for_pid_exit(pid_file)
