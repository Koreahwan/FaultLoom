from __future__ import annotations

from pathlib import Path
from typing import Never

import pytest

from faultloom.model_utility_cli import ModelUtilityCliError, prepare_local_model_config
from faultloom.model_utility_proxy import (
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelRuntimeProfile,
)


def test_missing_config_does_not_retain_open_context(tmp_path: Path) -> None:
    config_path = tmp_path / "API_KEY=do-not-leak.json"

    with pytest.raises(
        ModelUtilityCliError,
        match="configuration_unavailable",
    ) as config_error:
        _ = prepare_local_model_config(config_path)
    assert "do-not-leak" not in str(config_error.value)
    assert config_error.value.__cause__ is None
    assert config_error.value.__context__ is None


def test_config_read_error_does_not_retain_os_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "model-utility.json"
    _ = config_path.write_bytes(b"{}")

    def denied(_descriptor: int, _maximum_bytes: int) -> bytes:
        raise OSError("API_KEY=do-not-leak")

    monkeypatch.setattr("faultloom.model_utility_cli.os.read", denied)
    with pytest.raises(
        ModelUtilityCliError,
        match="configuration_unavailable",
    ) as config_error:
        _ = prepare_local_model_config(config_path)
    assert "do-not-leak" not in str(config_error.value)
    assert config_error.value.__cause__ is None
    assert config_error.value.__context__ is None


def test_invalid_config_does_not_retain_validation_context(tmp_path: Path) -> None:
    config_path = tmp_path / "model-utility.json"
    _ = config_path.write_text('{"API_KEY":"do-not-leak"', encoding="utf-8")

    with pytest.raises(ModelUtilityCliError, match="configuration_invalid") as config_error:
        _ = prepare_local_model_config(config_path)
    assert "do-not-leak" not in str(config_error.value)
    assert config_error.value.__cause__ is None
    assert config_error.value.__context__ is None


def test_artifact_failure_does_not_retain_process_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=2,
        maximum_request_bytes=4096,
        maximum_response_bytes=4096,
    )
    config_path = tmp_path / "model-utility.json"
    _ = config_path.write_text(config.model_dump_json(), encoding="utf-8")

    def unavailable(
        _config: LocalModelProcessConfig,
        _encoded: bytes,
    ) -> Never:
        raise LocalModelProcessError("API_KEY=do-not-leak")

    monkeypatch.setattr("faultloom.model_utility_cli.pinned_process_launch", unavailable)
    with pytest.raises(ModelUtilityCliError, match="artifact_unavailable") as artifact_error:
        _ = prepare_local_model_config(config_path)
    assert "do-not-leak" not in str(artifact_error.value)
    assert artifact_error.value.__cause__ is None
    assert artifact_error.value.__context__ is None
