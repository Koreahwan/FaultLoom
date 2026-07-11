from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

import faultloom_sdk
import faultloom_sdk.reference as reference
from faultloom_protocol import canonical_json
from faultloom_sdk import (
    CompileActionRequest,
    NormalizeObservationRequest,
    ReferenceProcessClient,
    ReferenceProcessError,
    reference_registry,
    rpc_input_schema,
)
from tests.protocol.factories import sample_models

from .conftest import reference_grant, reference_intent


def _run_worker(
    document: dict[str, object], *, schema_text: str | None = None
) -> dict[str, object]:
    worker = Path(faultloom_sdk.__file__).resolve().parent / "reference_worker.py"
    worker_digest = reference.reference_adapter_manifest().image_digest
    assert worker_digest is not None
    completed = subprocess.run(
        (
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-E",
            str(worker),
            worker_digest,
            canonical_json(rpc_input_schema()) if schema_text is None else schema_text,
        ),
        input=(json.dumps(document) + "\n").encode(),
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert completed.returncode == 0
    assert completed.stderr == b""
    response = json.loads(completed.stdout)
    assert isinstance(response, dict)
    return response


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
    request = {
        "schema_version": "0.1.0",
        "rpc_version": "0.1.0",
        "request_id": "rpc.unknown.1",
        "method": "open_target_socket",
    }
    response = _run_worker(request)
    assert response["status"] == "error"
    assert response["error_code"] == "rpc.unknown_method"


@pytest.mark.parametrize("tamper", ["noncanonical", "constraint"])
def test_worker_rejects_unbound_input_schema(tamper: str) -> None:
    schema = rpc_input_schema()
    if tamper == "noncanonical":
        schema_text = json.dumps(schema, indent=2, sort_keys=True)
    else:
        method_schema = schema["$defs"]["ActionIntent"]["properties"]["method"]
        string_schema = next(
            option for option in method_schema["anyOf"] if option.get("type") == "string"
        )
        string_schema["maxLength"] = 257
        schema_text = canonical_json(schema)

    response = _run_worker(
        {
            "schema_version": "0.1.0",
            "rpc_version": "0.1.0",
            "request_id": f"rpc.schema.{tamper}",
            "method": "describe",
        },
        schema_text=schema_text,
    )
    assert response["status"] == "error"
    assert response["error_code"] == "rpc.invalid_schema"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", ""),
        ("method", "m" * 257),
        ("path", ""),
        ("path", "p" * 4097),
    ],
)
def test_worker_matches_action_intent_string_schema_rejections(
    field: str, value: str
) -> None:
    registry = reference_registry()
    request = registry.prepare_compile(
        request_id=f"rpc.invalid.{field}.{len(value)}",
        grant=reference_grant(),
        intent=reference_intent(),
    ).model_dump(mode="json")
    request["action_intent"][field] = value

    with pytest.raises(ValidationError):
        CompileActionRequest.model_validate_json(json.dumps(request))
    response = _run_worker(request)
    assert response["status"] == "error"
    assert response["error_code"] == "rpc.invalid_request"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", "m"),
        ("method", "m" * 256),
        ("path", "p"),
        ("path", "p" * 4096),
    ],
)
def test_worker_matches_action_intent_string_schema_boundaries(
    field: str, value: str
) -> None:
    registry = reference_registry()
    request = registry.prepare_compile(
        request_id=f"rpc.valid.{field}.{len(value)}",
        grant=reference_grant(),
        intent=reference_intent(),
    ).model_dump(mode="json")
    request["action_intent"][field] = value

    CompileActionRequest.model_validate_json(json.dumps(request))
    response = _run_worker(request)
    assert response["status"] == "ok"


@pytest.mark.parametrize("value", ["", "m" * 257])
def test_worker_matches_media_type_schema_rejections(value: str) -> None:
    registry = reference_registry()
    request = registry.prepare_normalize(
        request_id=f"rpc.invalid.media-type.{len(value)}",
        grant=reference_grant(),
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        observation=sample_models()["ObservationRef"],
    ).model_dump(mode="json")
    request["observation"]["media_type"] = value

    with pytest.raises(ValidationError):
        NormalizeObservationRequest.model_validate_json(json.dumps(request))
    response = _run_worker(request)
    assert response["status"] == "error"
    assert response["error_code"] == "rpc.invalid_request"


@pytest.mark.parametrize("value", ["m", "m" * 256])
def test_worker_matches_media_type_schema_boundaries(value: str) -> None:
    registry = reference_registry()
    request = registry.prepare_normalize(
        request_id=f"rpc.valid.media-type.{len(value)}",
        grant=reference_grant(),
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        observation=sample_models()["ObservationRef"],
    ).model_dump(mode="json")
    request["observation"]["media_type"] = value

    NormalizeObservationRequest.model_validate_json(json.dumps(request))
    response = _run_worker(request)
    assert response["status"] == "ok"


@pytest.mark.parametrize("field", ["protocol", "method", "path"])
def test_worker_matches_whitespace_only_action_string_rejections(field: str) -> None:
    registry = reference_registry()
    request = registry.prepare_compile(
        request_id=f"rpc.invalid.whitespace.{field}",
        grant=reference_grant(),
        intent=reference_intent(),
    ).model_dump(mode="json")
    request["action_intent"][field] = " "

    with pytest.raises(ValidationError):
        CompileActionRequest.model_validate_json(json.dumps(request))
    response = _run_worker(request)
    assert response["status"] == "error"
    assert response["error_code"] == "rpc.invalid_request"


@pytest.mark.parametrize(
    ("field", "value", "normalized"),
    [
        ("protocol", " http ", "http"),
        ("method", " GET ", "GET"),
        ("path", " /v1/items ", "/v1/items"),
    ],
)
def test_worker_accepts_nonempty_action_strings_with_nearby_whitespace(
    field: str, value: str, normalized: str
) -> None:
    registry = reference_registry()
    request = registry.prepare_compile(
        request_id=f"rpc.valid.whitespace.{field}",
        grant=reference_grant(),
        intent=reference_intent(),
    ).model_dump(mode="json")
    request["action_intent"][field] = value

    parsed = CompileActionRequest.model_validate_json(json.dumps(request))
    assert getattr(parsed.action_intent, field) == normalized
    response = _run_worker(request)
    assert response["status"] == "ok"


def test_worker_matches_whitespace_only_media_type_rejection() -> None:
    registry = reference_registry()
    request = registry.prepare_normalize(
        request_id="rpc.invalid.whitespace.media-type",
        grant=reference_grant(),
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        observation=sample_models()["ObservationRef"],
    ).model_dump(mode="json")
    request["observation"]["media_type"] = " "

    with pytest.raises(ValidationError):
        NormalizeObservationRequest.model_validate_json(json.dumps(request))
    response = _run_worker(request)
    assert response["status"] == "error"
    assert response["error_code"] == "rpc.invalid_request"


def test_worker_accepts_nonempty_media_type_with_nearby_whitespace() -> None:
    registry = reference_registry()
    request = registry.prepare_normalize(
        request_id="rpc.valid.whitespace.media-type",
        grant=reference_grant(),
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        observation=sample_models()["ObservationRef"],
    ).model_dump(mode="json")
    request["observation"]["media_type"] = " application/json "

    parsed = NormalizeObservationRequest.model_validate_json(json.dumps(request))
    assert parsed.observation.media_type == "application/json"
    response = _run_worker(request)
    assert response["status"] == "ok"


@pytest.mark.parametrize(
    "value",
    [
        "20300102T030405+0000",
        "2030-W01-2T03:04:05+00:00",
        "2030-01-02T03:04:05+00",
    ],
)
def test_worker_matches_core_datetime_rejections(value: str) -> None:
    registry = reference_registry()
    compile_request = registry.prepare_compile(
        request_id="rpc.invalid.datetime.compile",
        grant=reference_grant(),
        intent=reference_intent(),
    ).model_dump(mode="json")
    compile_request["action_intent"]["requested_at"] = value
    normalize_request = registry.prepare_normalize(
        request_id="rpc.invalid.datetime.normalize",
        grant=reference_grant(),
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        observation=sample_models()["ObservationRef"],
    ).model_dump(mode="json")
    normalize_request["observation"]["created_at"] = value

    for model, request in (
        (CompileActionRequest, compile_request),
        (NormalizeObservationRequest, normalize_request),
    ):
        with pytest.raises(ValidationError):
            model.model_validate_json(json.dumps(request))
        response = _run_worker(request)
        assert response["status"] == "error"
        assert response["error_code"] == "rpc.invalid_request"


@pytest.mark.parametrize(
    "value",
    [
        "2030-01-02T03:04:05Z",
        "2030-01-02 03:04:05+00:00",
        "2030-01-02t03:04:05.1+09:30",
    ],
)
def test_worker_accepts_nearby_core_datetime_forms(value: str) -> None:
    registry = reference_registry()
    compile_request = registry.prepare_compile(
        request_id="rpc.valid.datetime.compile",
        grant=reference_grant(),
        intent=reference_intent(),
    ).model_dump(mode="json")
    compile_request["action_intent"]["requested_at"] = value
    normalize_request = registry.prepare_normalize(
        request_id="rpc.valid.datetime.normalize",
        grant=reference_grant(),
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        observation=sample_models()["ObservationRef"],
    ).model_dump(mode="json")
    normalize_request["observation"]["created_at"] = value

    for model, request in (
        (CompileActionRequest, compile_request),
        (NormalizeObservationRequest, normalize_request),
    ):
        model.model_validate_json(json.dumps(request))
        response = _run_worker(request)
        assert response["status"] == "ok"


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
