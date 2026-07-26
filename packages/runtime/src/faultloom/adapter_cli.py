"""Offline adapter registry commands."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from faultloom_sdk import (
    AdapterAdmissionError,
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdmissionGate,
    AdmissionOutcome,
    ReferenceProcessClient,
    ReferenceProcessError,
    reference_registry,
)

EXIT_OK = 0
EXIT_UNAVAILABLE = 3


class AdapterCliError(RuntimeError):
    """An expected offline adapter command failure."""


class _AdapterArguments(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="ignore", frozen=True, strict=True
    )

    adapter_id: str


class _UtilityArguments(_AdapterArguments):
    config: Path


def _registry() -> AdapterAdmissionRegistry:
    return AdapterAdmissionRegistry(reference_registry())


def _emit(
    document: Mapping[str, bool | str | list[Mapping[str, str]]],
) -> None:
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))


def _list_adapters(_arguments: argparse.Namespace) -> int:
    snapshots = _registry().list()
    _emit(
        {
            "adapters": [
                {
                    "adapter_id": snapshot.manifest.adapter_id,
                    "evidence_capability": snapshot.manifest.evidence_capability.value,
                    "manifest_digest": snapshot.manifest_digest,
                    "network_mode": snapshot.manifest.network_mode,
                    "state": snapshot.state.value,
                    "update_policy": snapshot.manifest.update_policy,
                    "version": snapshot.manifest.adapter_version,
                }
                for snapshot in snapshots
            ]
        }
    )
    return EXIT_OK


def _doctor_adapter(arguments: argparse.Namespace) -> int:
    parsed = _AdapterArguments.model_validate(vars(arguments))
    try:
        snapshot = _registry().doctor(parsed.adapter_id)
    except AdapterAdmissionError as exc:
        return _fail(str(exc))
    manifest = snapshot.manifest
    _emit(
        {
            "adapter_id": manifest.adapter_id,
            "direct_target_socket": False,
            "dispatch_performed": False,
            "installed": True,
            "manifest_digest": snapshot.manifest_digest,
            "manifest_pinned": manifest.upstream_commit is not None
            or manifest.image_digest is not None,
            "network_mode": manifest.network_mode,
            "state": snapshot.state.value,
            "update_policy": manifest.update_policy,
        }
    )
    return EXIT_OK


def _test_adapter(arguments: argparse.Namespace) -> int:
    parsed = _AdapterArguments.model_validate(vars(arguments))
    registry = _registry()
    try:
        manifest = registry.prepare_test(parsed.adapter_id)
        if manifest.adapter_id != "adapter.reference":
            raise AdapterCliError("adapter has no fixed offline test harness")
        response = ReferenceProcessClient(
            expected_adapter_manifest=manifest
        ).describe(request_id="adapter.test.describe")
        if not response.network_guard_active:
            raise AdapterCliError("adapter network guard is inactive")
        digest = registry.doctor(manifest.adapter_id).manifest_digest
        contract = AdapterAdmissionReceipt(
            adapter_id=manifest.adapter_id,
            manifest_digest=digest,
            gate=AdmissionGate.CONTRACT,
            outcome=AdmissionOutcome.PASSED,
            artifact_digest=manifest.input_schema_digest,
        )
        _ = registry.record(contract)
        fidelity = AdapterAdmissionReceipt(
            adapter_id=manifest.adapter_id,
            manifest_digest=digest,
            gate=AdmissionGate.FIDELITY,
            outcome=AdmissionOutcome.PASSED,
            artifact_digest=manifest.output_schema_digest,
        )
        snapshot = registry.record(fidelity)
    except (AdapterAdmissionError, AdapterCliError, ReferenceProcessError) as exc:
        return _fail(str(exc))
    _emit(
        {
            "adapter_id": manifest.adapter_id,
            "contract": contract.outcome.value,
            "dispatch_performed": False,
            "fidelity": fidelity.outcome.value,
            "model_utility": "not_run",
            "network_access": "none",
            "state": snapshot.state.value,
        }
    )
    return EXIT_UNAVAILABLE


def _utility_test_adapter(arguments: argparse.Namespace) -> int:
    parsed = _UtilityArguments.model_validate(vars(arguments))
    try:
        from .model_utility_cli import ModelUtilityCliError, prepare_local_model_config
    except ImportError:
        return _fail("model utility is unavailable on this platform")
    try:
        _ = _registry().prepare_test(parsed.adapter_id)
        _ = prepare_local_model_config(parsed.config)
    except AdapterAdmissionError as exc:
        return _fail(str(exc))
    except ModelUtilityCliError as exc:
        _emit(
            {
                "adapter_id": parsed.adapter_id,
                "model_utility": "not_run",
                "reason": exc.reason,
                "state": "pending_model_utility",
            }
        )
        return EXIT_UNAVAILABLE
    _emit(
        {
            "adapter_id": parsed.adapter_id,
            "model_utility": "not_run",
            "reason": "evaluation_input_unavailable",
            "state": "pending_model_utility",
        }
    )
    return EXIT_UNAVAILABLE


def _fail(message: str) -> int:
    print(f"faultloom: error: {message}", file=sys.stderr)
    return EXIT_UNAVAILABLE


def configure_adapter_parser(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="adapter_command", required=True)
    list_command = commands.add_parser("list")
    list_command.set_defaults(handler=_list_adapters)
    for operation, handler in (("doctor", _doctor_adapter), ("test", _test_adapter)):
        command = commands.add_parser(operation)
        _ = command.add_argument("adapter_id")
        command.set_defaults(handler=handler)
    utility_test = commands.add_parser("utility-test")
    _ = utility_test.add_argument("adapter_id")
    _ = utility_test.add_argument("--config", type=Path, required=True)
    utility_test.set_defaults(handler=_utility_test_adapter)
