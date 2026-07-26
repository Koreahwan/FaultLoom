from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import _cffi_backend
import annotated_types
import cryptography
import faultloom
import faultloom_protocol
import pydantic
import pydantic_core
import pytest
import typing_inspection
from faultloom import t40_web_pack_process as web_process
from faultloom.model_utility_process import BoundedProcessLaunch, run_bounded_process
from faultloom.t40_web_pack_process import (
    WebPackProcessClient,
    WebPackProcessError,
    WebPackRunKey,
)
from faultloom_protocol import canonical_json_bytes
from faultloom_web import t40_worker

from labs.web_api import web_api_fixture


@pytest.fixture(scope="module")
def installed_site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    site = tmp_path_factory.mktemp("formal-installed-site")
    modules = (
        faultloom,
        faultloom_protocol,
        t40_worker,
        pydantic,
        pydantic_core,
        cryptography,
        annotated_types,
        typing_inspection,
    )
    copied: set[str] = set()
    for module in modules:
        assert module.__file__ is not None
        source = Path(module.__file__).resolve()
        package = source.parent
        name = package.name
        if name in copied:
            continue
        shutil.copytree(
            package,
            site / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        copied.add(name)
    import typing_extensions

    assert typing_extensions.__file__ is not None
    shutil.copy2(typing_extensions.__file__, site / "typing_extensions.py")
    assert _cffi_backend.__file__ is not None
    shutil.copy2(_cffi_backend.__file__, site / Path(_cffi_backend.__file__).name)
    return site


def _request_bytes(run_key: str = "control") -> bytes:
    request = web_api_fixture().positive
    return (
        canonical_json_bytes(
            {
                "request": request.model_dump(mode="json"),
                "run_key": run_key,
                "schema_version": "faultloom.t40-web-pack-process-request.v1",
            }
        )
        + b"\n"
    )


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


def test_live_checkout_client_is_not_an_installed_worker() -> None:
    with pytest.raises(WebPackProcessError, match="unavailable"):
        WebPackProcessClient().run(web_api_fixture().positive)


@pytest.mark.parametrize(
    "run_key",
    ("control", "off.identity_workflow", "off.api_async", "off.cross_surface_chain"),
)
def test_client_executes_installed_worker_transport_without_import_environment(
    run_key: WebPackRunKey,
    installed_site: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_process, "FORMAL_SITE_ROOT", installed_site)
    response = WebPackProcessClient().run(web_api_fixture().positive, run_key=run_key)
    assert response.run_key == run_key
    assert response.worker_artifact_digest


@pytest.mark.parametrize(
    "run_key",
    (
        "off.identity_workflow",
        "off.api_async",
        "off.cross_surface_chain",
    ),
)
def test_worker_ablation_skips_exactly_one_real_component(
    run_key: str,
) -> None:
    response = json.loads(t40_worker._serve(_request_bytes(run_key)))

    assert response["run_key"] == run_key
    expected = {
        "identity_workflow": run_key != "off.identity_workflow",
        "api_async": run_key != "off.api_async",
        "cross_surface_chain": False,
    }
    assert response["component_use"] == expected


def test_client_rejects_tampered_worker_output_via_its_only_private_exchange_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = web_api_fixture().positive
    response = json.loads(t40_worker._serve(_request_bytes()))
    response["worker_artifact_digest"] = "sha256:" + "0" * 64
    tampered = canonical_json_bytes(response) + b"\n"
    client = WebPackProcessClient()
    monkeypatch.setattr(client, "_fixed_exchange", lambda _encoded: tampered)
    assert t40_worker.__file__ is not None
    monkeypatch.setattr(web_process, "FORMAL_SITE_ROOT", Path(t40_worker.__file__).parents[1])

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
