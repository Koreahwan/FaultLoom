"""Digest-pinned, network-isolated local model process proxy."""

from __future__ import annotations

import json
import subprocess

from pydantic import ValidationError

from .model_utility_process import (
    BoundedProcessError,
    BoundedProcessLaunch,
    BoundedProcessResult,
    run_bounded_process,
)
from .model_utility_proxy_models import (
    MODEL_SNAPSHOT_TOKEN,
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelProcessRequest,
    LocalModelProcessResponse,
    LocalModelRuntimeProfile,
)
from .model_utility_sandbox import pinned_process_launch


def _run_scrubbed(
    config: LocalModelProcessConfig,
    encoded: bytes,
) -> BoundedProcessResult:
    try:
        with pinned_process_launch(config, encoded) as launch:
            return run_bounded_process(launch)
    except subprocess.TimeoutExpired:
        error = LocalModelProcessError("local model process timed out")
    except BoundedProcessError:
        error = LocalModelProcessError("local model process exceeded an I/O limit")
    except LocalModelProcessError:
        raise
    except OSError:
        error = LocalModelProcessError("local model process launch failed")
    raise error


def _parse_response(encoded: bytes) -> LocalModelProcessResponse:
    try:
        return LocalModelProcessResponse.model_validate_json(encoded)
    except ValidationError:
        error = LocalModelProcessError(
            "local model process returned a malformed response"
        )
    raise error


class DigestPinnedLocalProcessProxy:
    """Execute one request with fixed descriptors and a network namespace."""

    _config: LocalModelProcessConfig

    def __init__(self, config: LocalModelProcessConfig) -> None:
        if type(config) is not LocalModelProcessConfig:
            raise LocalModelProcessError("local model proxy requires an exact config")
        self._config = config

    def exchange(self, request: LocalModelProcessRequest) -> LocalModelProcessResponse:
        """Return a strictly bound model response or a scrubbed local error."""

        if type(request) is not LocalModelProcessRequest:
            raise LocalModelProcessError("local model proxy requires an exact request")
        config = self._config
        if (
            request.model_snapshot_digest != config.model_snapshot_digest
            or request.runtime_artifact_digest != config.runtime_executable_digest
        ):
            raise LocalModelProcessError("local model request artifact digest mismatch")
        encoded = (
            json.dumps(
                request.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        if len(encoded) > config.maximum_request_bytes:
            raise LocalModelProcessError("local model request exceeds its byte limit")
        completed = _run_scrubbed(config, encoded)
        if completed.returncode != 0:
            raise LocalModelProcessError(
                "local model process returned nonzero status"
            )
        response = _parse_response(completed.stdout)
        if (
            response.request_id != request.request_id
            or response.model_snapshot_digest != request.model_snapshot_digest
            or response.runtime_artifact_digest != request.runtime_artifact_digest
        ):
            raise LocalModelProcessError("local model response identity mismatch")
        return response


__all__ = [
    "MODEL_SNAPSHOT_TOKEN",
    "BoundedProcessLaunch",
    "BoundedProcessResult",
    "DigestPinnedLocalProcessProxy",
    "LocalModelProcessConfig",
    "LocalModelProcessError",
    "LocalModelProcessRequest",
    "LocalModelProcessResponse",
    "LocalModelRuntimeProfile",
]
