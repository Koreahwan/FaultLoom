"""Typed, fail-closed configuration preflight for model utility runs."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from .model_utility_proxy_models import (
    LocalModelProcessConfig,
    LocalModelProcessError,
)
from .model_utility_sandbox import pinned_process_launch

_MAX_CONFIG_BYTES = 64 * 1024
UtilityPendingReason = Literal[
    "configuration_unavailable",
    "configuration_invalid",
    "artifact_unavailable",
]


class ModelUtilityCliError(RuntimeError):
    """A utility CLI precondition is absent or invalid."""

    reason: UtilityPendingReason

    def __init__(self, reason: UtilityPendingReason) -> None:
        super().__init__(reason)
        self.reason = reason


def _open_config(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError:
        error = ModelUtilityCliError("configuration_unavailable")
    raise error


def _read_config(path: Path) -> bytes:
    descriptor = _open_config(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ModelUtilityCliError("configuration_invalid")
        raw = os.read(descriptor, _MAX_CONFIG_BYTES + 1)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if (
            len(raw) > _MAX_CONFIG_BYTES
            or len(raw) != before.st_size
            or identity_before != identity_after
        ):
            raise ModelUtilityCliError("configuration_invalid")
    except OSError:
        error = ModelUtilityCliError("configuration_unavailable")
    else:
        return raw
    finally:
        os.close(descriptor)
    raise error


def _parse_config(raw: bytes) -> LocalModelProcessConfig:
    try:
        return LocalModelProcessConfig.model_validate_json(raw)
    except ValidationError:
        error = ModelUtilityCliError("configuration_invalid")
    raise error


def _verify_artifacts(config: LocalModelProcessConfig) -> None:
    try:
        with pinned_process_launch(config, b""):
            return
    except LocalModelProcessError:
        error = ModelUtilityCliError("artifact_unavailable")
    raise error


def prepare_local_model_config(path: Path) -> LocalModelProcessConfig:
    """Validate typed JSON and all pinned artifacts without launching a model."""

    if not path.is_absolute():
        raise ModelUtilityCliError("configuration_invalid")
    config = _parse_config(_read_config(path))
    _verify_artifacts(config)
    return config


__all__ = ["ModelUtilityCliError", "prepare_local_model_config"]
