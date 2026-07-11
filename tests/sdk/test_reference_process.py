from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import faultloom_sdk
import faultloom_sdk.reference as reference
from faultloom_sdk import ReferenceProcessClient, ReferenceProcessError, reference_registry
from tests.protocol.factories import sample_models

from .conftest import reference_grant, reference_intent


def test_fixed_reference_process_describes_network_guarded_manifests() -> None:
    registry = reference_registry()
    response = ReferenceProcessClient(
        expected_adapter_manifest=registry.adapters[0]
    ).describe(request_id="rpc.describe.1")
    assert response.network_guard_active is True
    assert response.pack_manifest.process_isolation == "required"
    assert response.adapter_manifest.network_mode == "none"


def test_reference_process_compiles_non_dispatchable_action() -> None:
    registry = reference_registry()
    request = registry.prepare_compile(
        request_id="rpc.compile.3",
        grant=reference_grant(),
        intent=reference_intent(),
    )
    compiled = ReferenceProcessClient(
        expected_adapter_manifest=registry.adapters[0]
    ).compile(request).compiled_action
    assert compiled.dispatch_authorized is False
    assert compiled.required_network_mode == "gateway_only"


def test_reference_process_normalizes_only_a_digest_reference() -> None:
    registry = reference_registry()
    observation = sample_models()["ObservationRef"]
    request = registry.prepare_normalize(
        request_id="rpc.normalize.2",
        grant=reference_grant(),
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        observation=observation,
    )
    normalized = ReferenceProcessClient(
        expected_adapter_manifest=registry.adapters[0]
    ).normalize(request).normalized_observation
    assert normalized.source_digest == observation.cas_digest
    assert normalized.observation_id == observation.observation_id


def test_worker_rejects_unknown_rpc_method_without_loading_plugin_code() -> None:
    worker = Path(faultloom_sdk.__file__).resolve().parent / "reference_worker.py"
    worker_digest = reference.reference_adapter_manifest().image_digest
    assert worker_digest is not None
    request = {
        "schema_version": "0.1.0",
        "rpc_version": "0.1.0",
        "request_id": "rpc.unknown.1",
        "method": "open_target_socket",
    }
    completed = subprocess.run(
        (
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-E",
            str(worker),
            worker_digest,
        ),
        input=(json.dumps(request) + "\n").encode(),
        capture_output=True,
        check=False,
        timeout=5,
    )
    response = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert completed.stderr == b""
    assert response["status"] == "error"
    assert response["error_code"] == "rpc.unknown_method"


def test_worker_swap_is_rejected_before_subprocess_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = reference_registry()
    client = ReferenceProcessClient(expected_adapter_manifest=registry.adapters[0])
    replacement = tmp_path / "reference_worker.py"
    replacement.write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
    monkeypatch.setattr(reference, "_worker_path", lambda: replacement)
    subprocess_called = False

    def unexpected_run(*_args: object, **_kwargs: object) -> None:
        nonlocal subprocess_called
        subprocess_called = True

    monkeypatch.setattr(reference.subprocess, "run", unexpected_run)
    with pytest.raises(ReferenceProcessError, match="digest differs from admission"):
        client.describe(request_id="rpc.describe.swap")
    assert subprocess_called is False


def test_path_replacement_after_read_cannot_change_executed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = reference_registry()
    client = ReferenceProcessClient(expected_adapter_manifest=registry.adapters[0])
    packaged_worker = Path(faultloom_sdk.__file__).resolve().parent / "reference_worker.py"
    replacement = tmp_path / "reference_worker.py"
    replacement.write_bytes(packaged_worker.read_bytes())
    marker = tmp_path / "untrusted-source-executed"
    monkeypatch.setattr(reference, "_worker_path", lambda: replacement)
    real_run = subprocess.run

    def replace_then_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        replacement.write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
            encoding="utf-8",
        )
        return real_run(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(reference.subprocess, "run", replace_then_run)
    response = client.describe(request_id="rpc.describe.bound-source")
    assert response.network_guard_active is True
    assert not marker.exists()


def test_sdk_has_no_in_process_plugin_loader_or_target_address_contract() -> None:
    package = Path(faultloom_sdk.__file__).resolve().parent
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(package.glob("*.py"))
        if path.name != "reference_worker.py"
    )
    assert "importlib" not in source
    assert "entry_points" not in source
    assert "target_url" not in source
    assert "target_host" not in source
