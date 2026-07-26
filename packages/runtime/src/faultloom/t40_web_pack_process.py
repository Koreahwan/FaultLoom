"""Fixed installed-process client for one real Web/API pack execution."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from faultloom_protocol import canonical_json_bytes, sha256_digest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .model_utility_process import BoundedProcessError, BoundedProcessLaunch, run_bounded_process
from .t40_faultloom_install import FORMAL_SITE_ROOT

WEB_PACK_PROCESS_SCHEMA_VERSION = "faultloom.t40-web-pack-process.v1"
_MAX_REQUEST_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 65_536
_MAX_ARTIFACT_BYTES = 1_048_576
_DIGEST = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
WebPackRunKey = Literal[
    "control",
    "off.identity_workflow",
    "off.api_async",
    "off.cross_surface_chain",
]


class WebPackProcessError(RuntimeError):
    """The installed Web pack worker failed or violated its fixed contract."""


class WebPackComponentUse(BaseModel):
    """The three actual engine paths selected by the closed run key."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    identity_workflow: bool
    api_async: bool
    cross_surface_chain: bool


class WebPackComponentDigests(BaseModel):
    """Redacted digests of the facade's three component outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    identity_workflow: _DIGEST
    api_async: _DIGEST
    cross_surface_chain: _DIGEST


class WebPackProcessRequest(BaseModel):
    """One fixed worker request with a closed component-ablation vocabulary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["faultloom.t40-web-pack-process-request.v1"] = (
        "faultloom.t40-web-pack-process-request.v1"
    )
    run_key: WebPackRunKey = "control"
    request: dict[str, object]


class WebPackProcessResponse(BaseModel):
    """The public-safe response from the fixed one-shot Web pack worker."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["faultloom.t40-web-pack-process.v1"]
    run_key: WebPackRunKey
    request_digest: _DIGEST
    result_digest: _DIGEST
    worker_artifact_digest: _DIGEST
    runtime_artifact_digest: _DIGEST
    component_digests: WebPackComponentDigests
    component_use: WebPackComponentUse


def _read_private_regular_file(path: Path, *, label: str) -> tuple[bytes, str]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise WebPackProcessError(f"{label} is unavailable") from exc
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise WebPackProcessError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise WebPackProcessError(f"{label} is not a private regular file")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 65_536):
            size += len(chunk)
            if size > _MAX_ARTIFACT_BYTES:
                raise WebPackProcessError(f"{label} exceeds its byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or size != before.st_size:
        raise WebPackProcessError(f"{label} changed while being read")
    raw = b"".join(chunks)
    return raw, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def runtime_artifact_digest() -> str:
    """Return the digest that pins this installed runtime client artifact."""

    path = Path(__file__)
    if path.name != "t40_web_pack_process.py" or path.parent.name != "faultloom":
        raise WebPackProcessError("runtime Web pack client origin is invalid")
    _, digest = _read_private_regular_file(path, label="runtime Web pack client")
    return digest


def _worker_path() -> Path:
    path = FORMAL_SITE_ROOT / "faultloom_web/t40_worker.py"
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise WebPackProcessError("installed Web pack worker is unavailable") from None
    if resolved != path or not resolved.is_relative_to(FORMAL_SITE_ROOT):
        raise WebPackProcessError("installed Web pack worker origin is invalid")
    return resolved


class WebPackProcessClient:
    """Run one canonical ``WebApiRunRequest`` through the fixed installed worker."""

    def __init__(self, *, timeout_seconds: int = 5) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be an integer from 1 through 30")
        self._timeout_seconds = timeout_seconds

    def run(
        self,
        request: object,
        *,
        run_key: WebPackRunKey = "control",
    ) -> WebPackProcessResponse:
        """Run the exact request without accepting a caller-selected process surface."""

        from faultloom_web.web_api.inputs import WebApiRunRequest

        if type(request) is not WebApiRunRequest:
            raise TypeError("Web pack process requires an exact WebApiRunRequest")
        envelope = {
            "request": request.model_dump(mode="json"),
            "run_key": run_key,
            "schema_version": "faultloom.t40-web-pack-process-request.v1",
        }
        encoded = canonical_json_bytes(envelope) + b"\n"
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise WebPackProcessError("Web pack request exceeds its byte limit")
        response = self._parse_response(self._fixed_exchange(encoded))
        expected_worker = _read_private_regular_file(
            _worker_path(), label="installed Web pack worker"
        )[1]
        expected_runtime = runtime_artifact_digest()
        if response.run_key != run_key:
            raise WebPackProcessError("Web pack response run key differs from its request")
        if response.request_digest != sha256_digest(envelope):
            raise WebPackProcessError("Web pack response is not bound to its request")
        if response.worker_artifact_digest != expected_worker:
            raise WebPackProcessError("Web pack worker digest differs from the installed artifact")
        if response.runtime_artifact_digest != expected_runtime:
            raise WebPackProcessError("Web pack runtime digest differs from the installed artifact")
        expected = {
            "identity_workflow": run_key != "off.identity_workflow",
            "api_async": run_key != "off.api_async",
            "cross_surface_chain": run_key == "control",
        }
        if response.component_use.model_dump() != expected:
            raise WebPackProcessError("Web pack response component use contradicts its run key")
        return response

    def _fixed_exchange(self, encoded: bytes) -> bytes:
        """Private test seam for the one immutable installed-worker exchange."""

        # Preserve the venv launcher path.  Resolving its symlink would select
        # the host interpreter and lose the installed pack under ``-I``.
        executable = Path(sys.executable)
        if not executable.is_absolute() or not executable.is_file():
            raise WebPackProcessError("installed Python executable is invalid")
        _ = _worker_path()
        bootstrap = (
            "import runpy,sys;"
            "sys.path[:0]=sys.argv[1:];"
            "sys.argv=['faultloom_web.t40_worker'];"
            "runpy.run_module('faultloom_web.t40_worker',run_name='__main__')"
        )
        launch = BoundedProcessLaunch(
            argv=(
                str(executable),
                "-I",
                "-S",
                "-B",
                "-c",
                bootstrap,
                FORMAL_SITE_ROOT.as_posix(),
            ),
            stdin=encoded,
            environment=MappingProxyType(
                {
                    "LANG": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            ),
            pass_fds=(),
            timeout_seconds=self._timeout_seconds,
            maximum_stdout_bytes=_MAX_RESPONSE_BYTES,
            maximum_stderr_bytes=4096,
        )
        try:
            completed = run_bounded_process(launch)
        except (BoundedProcessError, OSError, subprocess.TimeoutExpired) as exc:
            raise WebPackProcessError("installed Web pack worker did not complete safely") from exc
        if completed.returncode != 0:
            raise WebPackProcessError("installed Web pack worker failed closed")
        return completed.stdout

    @staticmethod
    def _parse_response(encoded: bytes) -> WebPackProcessResponse:
        if not encoded or len(encoded) > _MAX_RESPONSE_BYTES:
            raise WebPackProcessError("Web pack response has an invalid size")
        if not encoded.endswith(b"\n") or encoded.count(b"\n") != 1:
            raise WebPackProcessError("Web pack response must be one JSON line")
        try:
            response = WebPackProcessResponse.model_validate_json(encoded[:-1])
        except ValidationError as exc:
            raise WebPackProcessError("Web pack response is malformed") from exc
        if encoded != canonical_json_bytes(response.model_dump(mode="json")) + b"\n":
            raise WebPackProcessError("Web pack response is not canonical JSON")
        return response


__all__ = [
    "WEB_PACK_PROCESS_SCHEMA_VERSION",
    "WebPackComponentDigests",
    "WebPackComponentUse",
    "WebPackProcessClient",
    "WebPackProcessError",
    "WebPackProcessRequest",
    "WebPackProcessResponse",
    "WebPackRunKey",
    "runtime_artifact_digest",
]
