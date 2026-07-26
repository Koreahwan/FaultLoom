"""One-shot, networkless Web/API pack worker for the formal T40 runtime."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path

from faultloom.state import EngagementKey, StateStore
from faultloom.t40_web_pack_process import WEB_PACK_PROCESS_SCHEMA_VERSION, runtime_artifact_digest
from faultloom_protocol import canonical_json_bytes, sha256_digest
from pydantic import ValidationError

from .web_api import WebApiRunFacade, WebApiRunRequest, WebApiRunResult

_MAX_REQUEST_BYTES = 1_048_576


def _deny_network(event: str, _arguments: tuple[object, ...]) -> None:
    if event.startswith("socket."):
        raise PermissionError("network is disabled in the Web pack worker")


def worker_artifact_digest() -> str:
    """Return the digest of the exact worker source installed with this pack."""

    path = Path(__file__).resolve(strict=True)
    if path.name != "t40_worker.py" or path.parent.name != "faultloom_web":
        raise RuntimeError("Web pack worker origin is invalid")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("Web pack worker is not a private regular file")
        data = os.read(descriptor, _MAX_REQUEST_BYTES)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(data) != before.st_size:
        raise RuntimeError("Web pack worker changed while being read")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _component_digests(result: WebApiRunResult) -> dict[str, str]:
    correlation = result.correlation
    return {
        "api_async": sha256_digest(
            {
                "completed_effect_ids": correlation.completed_effect_ids,
                "surface_graph": correlation.surface_graph.model_dump(mode="json"),
            }
        ),
        "cross_surface_chain": sha256_digest(
            {
                "chain_search": result.chain_search.model_dump(mode="json"),
                "checkpoint": result.checkpoint.model_dump(mode="json"),
                "registry": result.registry.model_dump(mode="json"),
            }
        ),
        "identity_workflow": sha256_digest(
            {
                "identity_graph": correlation.identity_graph.model_dump(mode="json"),
                "workflow_graph": correlation.workflow_graph.model_dump(mode="json"),
            }
        ),
    }


def _serve(encoded: bytes) -> bytes:
    if not encoded or len(encoded) > _MAX_REQUEST_BYTES:
        raise ValueError("Web pack request size is invalid")
    if not encoded.endswith(b"\n") or encoded.count(b"\n") != 1:
        raise ValueError("Web pack request must be one JSON line")
    try:
        request = WebApiRunRequest.model_validate_json(encoded[:-1])
    except ValidationError as exc:
        raise ValueError("Web pack request is invalid") from exc
    canonical_request = canonical_json_bytes(request.model_dump(mode="json"))
    if encoded[:-1] != canonical_request:
        raise ValueError("Web pack request is not canonical")
    with tempfile.TemporaryDirectory(prefix="faultloom-t40-web-") as root:
        state_root = Path(root) / "state"
        anchor_root = Path(root) / "anchor"
        with StateStore(
            state_root,
            request.surface.binding.engagement_id,
            EngagementKey.generate(),
            anchor_root=anchor_root,
        ) as store:
            result = WebApiRunFacade(store).run(request)
    response = {
        "component_digests": _component_digests(result),
        "component_use": {
            "api_async": True,
            "cross_surface_chain": True,
            "identity_workflow": True,
        },
        "request_digest": sha256_digest(request.model_dump(mode="json")),
        "result_digest": sha256_digest(result.model_dump(mode="json")),
        "runtime_artifact_digest": runtime_artifact_digest(),
        "schema_version": WEB_PACK_PROCESS_SCHEMA_VERSION,
        "worker_artifact_digest": worker_artifact_digest(),
    }
    return canonical_json_bytes(response) + b"\n"


def main() -> int:
    """Read one canonical request and emit one redacted canonical response."""

    if len(sys.argv) != 1:
        return 64
    sys.addaudithook(_deny_network)
    try:
        output = _serve(sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1))
    except (OSError, PermissionError, RuntimeError, ValidationError, ValueError):
        return 2
    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
