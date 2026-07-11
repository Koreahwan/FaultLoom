"""Fixed-command client for the bundled non-networked reference process."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from faultloom_protocol import (
    ActionClass,
    AdapterBudget,
    AdapterManifest,
    EvidenceCapability,
    LicenseClass,
    PackManifest,
    TelemetryPolicy,
    sha256_digest,
)

from .registry import ManifestRegistry
from .rpc import (
    CompileActionRequest,
    CompileActionResponse,
    DescribeRequest,
    DescribeResponse,
    NormalizeObservationRequest,
    NormalizeObservationResponse,
    RpcErrorResponse,
)

REFERENCE_INPUT_SCHEMA = {
    "methods": ("compile_action", "describe", "normalize_observation"),
    "name": "faultloom.reference.rpc.input",
    "version": "0.1.0",
}
REFERENCE_OUTPUT_SCHEMA = {
    "dispatch_authorized": False,
    "name": "faultloom.reference.rpc.output",
    "network_modes": ("gateway_only", "none"),
    "version": "0.1.0",
}
REFERENCE_PACK_DESCRIPTORS = frozenset(
    {
        "reference.local_transform",
        "reference.digest",
        "reference.observation_digest",
        "reference.hypothesis",
        "reference.verifier",
        "reference.evaluation",
    }
)
REFERENCE_ADAPTER_CAPABILITIES = frozenset({"reference.digest_normalizer"})
REFERENCE_GATEWAY_FEATURES = frozenset({"dispatch.leases"})


class ReferenceProcessError(RuntimeError):
    """The fixed reference child failed or returned an invalid response."""


def _worker_path() -> Path:
    package = Path(__file__).resolve().parent
    worker = package / "reference_worker.py"
    if worker.parent != package:
        raise ReferenceProcessError("bundled reference worker path is unsafe")
    return worker


def _read_worker_source(*, expected_digest: str | None = None) -> tuple[str, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_worker_path(), flags)
    except OSError as exc:
        raise ReferenceProcessError("bundled reference worker cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReferenceProcessError("bundled reference worker is not a private regular file")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 65_536):
            size += len(chunk)
            if size > ReferenceProcessClient._MAX_WORKER_BYTES:
                raise ReferenceProcessError("bundled reference worker exceeds the source limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_after != identity_before or size != before.st_size:
            raise ReferenceProcessError("bundled reference worker changed while being read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ReferenceProcessError("bundled reference worker digest differs from admission")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReferenceProcessError("bundled reference worker is not UTF-8 source") from exc
    if "\x00" in source:
        raise ReferenceProcessError("bundled reference worker contains a NUL byte")
    return source, digest


def reference_pack_manifest() -> PackManifest:
    return PackManifest(
        schema_version="0.1.0",
        pack_id="pack.reference",
        pack_version="0.1.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.reference.v1",
        capability_descriptors=("reference.local_transform",),
        action_compilers=("reference.digest",),
        observation_normalizers=("reference.observation_digest",),
        hypothesis_providers=("reference.hypothesis",),
        verifier_descriptors=("reference.verifier",),
        evaluation_descriptors=("reference.evaluation",),
        required_gateway_features=("dispatch.leases",),
        required_adapter_capabilities=("reference.digest_normalizer",),
    )


def _reference_adapter_manifest(worker_digest: str) -> AdapterManifest:
    return AdapterManifest(
        schema_version="0.1.0",
        adapter_id="adapter.reference",
        adapter_version="0.1.0",
        upstream_version="0.1.0",
        image_digest=worker_digest,
        license_class=LicenseClass.BUNDLED_OPEN_SOURCE,
        capabilities=("reference.digest_normalizer",),
        action_classes=(ActionClass.OBSERVE, ActionClass.SAFE_PROBE),
        network_mode="none",
        input_schema_digest=sha256_digest(REFERENCE_INPUT_SCHEMA),
        output_schema_digest=sha256_digest(REFERENCE_OUTPUT_SCHEMA),
        budget=AdapterBudget(
            schema_version="0.1.0",
            rate_per_minute=60,
            timeout_seconds=5,
            max_bytes=1_048_576,
            max_concurrency=1,
        ),
        telemetry_policy=TelemetryPolicy.DISABLED,
        evidence_capability=EvidenceCapability.CANDIDATE_ONLY,
    )


def reference_adapter_manifest() -> AdapterManifest:
    _, worker_digest = _read_worker_source()
    return _reference_adapter_manifest(worker_digest)


def reference_registry() -> ManifestRegistry:
    registry = ManifestRegistry(
        known_pack_descriptors=REFERENCE_PACK_DESCRIPTORS,
        known_adapter_capabilities=REFERENCE_ADAPTER_CAPABILITIES,
        available_gateway_features=REFERENCE_GATEWAY_FEATURES,
    )
    registry.install_adapter(reference_adapter_manifest())
    registry.install_pack(reference_pack_manifest())
    return registry


class ReferenceProcessClient:
    """Exchange one bounded JSON request with one fixed isolated child process."""

    _MAX_RPC_BYTES = 1_048_576

    _MAX_WORKER_BYTES = 262_144

    def __init__(
        self,
        *,
        expected_adapter_manifest: AdapterManifest,
        timeout_seconds: int = 5,
    ) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be an integer from 1 through 30")
        if (
            expected_adapter_manifest.image_digest is None
            or expected_adapter_manifest
            != _reference_adapter_manifest(expected_adapter_manifest.image_digest)
        ):
            raise ValueError("expected_adapter_manifest is not the bundled reference descriptor")
        self._expected_adapter_manifest = expected_adapter_manifest
        self._timeout_seconds = timeout_seconds

    def describe(self, *, request_id: str) -> DescribeResponse:
        request = DescribeRequest(schema_version="0.1.0", request_id=request_id)
        response = DescribeResponse.model_validate_json(
            json.dumps(self._exchange(request.model_dump(mode="json")))
        )
        self._require_response_id(request_id, response.request_id)
        if response.pack_manifest != reference_pack_manifest():
            raise ReferenceProcessError("reference pack manifest differs from bundled source")
        if response.adapter_manifest != self._expected_adapter_manifest:
            raise ReferenceProcessError("reference adapter manifest differs from bundled source")
        return response

    def compile(self, request: CompileActionRequest) -> CompileActionResponse:
        response = CompileActionResponse.model_validate_json(
            json.dumps(self._exchange(request.model_dump(mode="json")))
        )
        self._require_response_id(request.request_id, response.request_id)
        compiled = response.compiled_action
        if (
            compiled.action_id != request.action_intent.action_id
            or compiled.pack_id != request.action_intent.pack_id
            or compiled.compiler_id != request.action_intent.action_kind
            or compiled.intent_digest != sha256_digest(request.action_intent)
        ):
            raise ReferenceProcessError("compiled action is not bound to its request")
        return response

    def normalize(
        self, request: NormalizeObservationRequest
    ) -> NormalizeObservationResponse:
        response = NormalizeObservationResponse.model_validate_json(
            json.dumps(self._exchange(request.model_dump(mode="json")))
        )
        self._require_response_id(request.request_id, response.request_id)
        normalized = response.normalized_observation
        if (
            normalized.adapter_id != request.adapter_id
            or normalized.normalizer_id != request.capability
            or normalized.observation_id != request.observation.observation_id
            or normalized.source_digest != request.observation.cas_digest
        ):
            raise ReferenceProcessError("normalized observation is not bound to its request")
        return response

    @staticmethod
    def _require_response_id(expected: str, actual: str) -> None:
        if actual != expected:
            raise ReferenceProcessError("reference response request ID mismatch")

    def _exchange(self, document: dict[str, object]) -> dict[str, object]:
        encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(encoded) > self._MAX_RPC_BYTES:
            raise ReferenceProcessError("reference request exceeds the RPC byte limit")
        source, worker_digest = _read_worker_source(
            expected_digest=self._expected_adapter_manifest.image_digest
        )
        command = (
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-E",
            "-c",
            source,
            worker_digest,
        )
        environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        try:
            with tempfile.TemporaryDirectory(prefix="faultloom-reference-rpc-") as cwd:
                completed = subprocess.run(
                    command,
                    input=encoded,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=environment,
                    close_fds=True,
                    start_new_session=True,
                    timeout=self._timeout_seconds,
                    check=False,
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReferenceProcessError("reference process did not complete safely") from exc
        if completed.returncode != 0 or completed.stderr:
            raise ReferenceProcessError("reference process failed closed")
        if not completed.stdout or len(completed.stdout) > self._MAX_RPC_BYTES:
            raise ReferenceProcessError("reference response has an invalid size")
        try:
            decoded = completed.stdout.decode("utf-8")
            if not decoded.endswith("\n") or "\n" in decoded[:-1]:
                raise ValueError("response must contain one JSON line")
            value = json.loads(decoded)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise ReferenceProcessError("reference response is not one valid JSON object") from exc
        if not isinstance(value, dict):
            raise ReferenceProcessError("reference response is not a JSON object")
        if value.get("status") == "error":
            error = RpcErrorResponse.model_validate_json(json.dumps(value))
            raise ReferenceProcessError(f"reference process refused request: {error.error_code}")
        return value
