from __future__ import annotations

from enum import Enum
from pathlib import Path

import pytest
from pydantic import ValidationError

import faultloom.egress as egress_module
import faultloom_protocol.canonical as canonical_module
from faultloom.egress import DestinationResolution, EgressOutcome, EgressPlane
from faultloom.egress_wire import WireValue
from faultloom_protocol import SCHEMA_VERSION
from tests.runtime.test_egress import (
    MemoryKnowledgeTransport,
    MemoryProviderTransport,
    grant,
    knowledge_fetcher,
    knowledge_request,
    provider_proxy,
    provider_request,
)


class StrictWireError(TypeError):
    runtime_type: type[WireValue]

    def __init__(self, runtime_type: type[WireValue]) -> None:
        self.runtime_type = runtime_type
        super().__init__("runtime-local values cannot enter the protocol digest kernel")


def _reject_runtime_wire_values(value: WireValue) -> None:
    value_type = type(value)
    if value_type.__module__ == egress_module.__name__:
        raise StrictWireError(value_type)
    if value_type is dict and isinstance(value, dict):
        for child in value.values():
            _reject_runtime_wire_values(child)
    elif value_type is list and isinstance(value, list):
        for child in value:
            _reject_runtime_wire_values(child)
    elif value_type is tuple and isinstance(value, tuple):
        for child in value:
            _reject_runtime_wire_values(child)


def test_provider_and_knowledge_digests_use_only_protocol_wire_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = canonical_module.canonical_json_bytes

    def strict_canonical_json_bytes(value: WireValue) -> bytes:
        _reject_runtime_wire_values(value)
        return original(value)

    monkeypatch.setattr(canonical_module, "canonical_json_bytes", strict_canonical_json_bytes)
    authority = grant()
    provider_receipt = provider_proxy(
        authority,
        tmp_path / "provider.sqlite3",
        transport=MemoryProviderTransport(),
    ).dispatch(provider_request(authority))
    knowledge_receipt = knowledge_fetcher(
        authority,
        tmp_path / "knowledge.sqlite3",
        transport=MemoryKnowledgeTransport(),
    ).dispatch(knowledge_request(authority))

    assert provider_receipt.outcome is EgressOutcome.COMPLETED
    assert knowledge_receipt.outcome is EgressOutcome.COMPLETED


def test_counterfeit_plane_is_rejected_without_running_hooks() -> None:
    calls = {"repr": 0, "str": 0, "eq": 0, "hash": 0}

    class CounterfeitPlane(str, Enum):
        MODEL_PROVIDER = "model_provider"

        def __repr__(self) -> str:
            calls["repr"] += 1
            raise AssertionError("counterfeit repr hook executed")

        def __str__(self) -> str:
            calls["str"] += 1
            raise AssertionError("counterfeit str hook executed")

        def __eq__(self, other: object) -> bool:  # noqa: OBJECT_OK
            calls["eq"] += 1
            raise AssertionError("counterfeit equality hook executed")

        def __hash__(self) -> int:
            calls["hash"] += 1
            raise AssertionError("counterfeit hash hook executed")

    counterfeit = CounterfeitPlane.MODEL_PROVIDER
    calls.update({name: 0 for name in calls})
    with pytest.raises(ValidationError):
        DestinationResolution.model_validate(
            {
                "schema_version": SCHEMA_VERSION,
                "plane": counterfeit,
                "origin": "https://provider.example.invalid",
                "addresses": ("8.8.8.8",),
            }
        )

    assert calls == {"repr": 0, "str": 0, "eq": 0, "hash": 0}


def test_registered_plane_rejects_rebound_backing_without_running_hooks() -> None:
    calls = {"repr": 0, "str": 0, "eq": 0, "hash": 0}

    class HostileText(str):
        def __repr__(self) -> str:
            calls["repr"] += 1
            raise AssertionError("backing repr hook executed")

        def __str__(self) -> str:
            calls["str"] += 1
            raise AssertionError("backing str hook executed")

        def __eq__(self, other: object) -> bool:  # noqa: OBJECT_OK
            calls["eq"] += 1
            raise AssertionError("backing equality hook executed")

        def __hash__(self) -> int:
            calls["hash"] += 1
            raise AssertionError("backing hash hook executed")

    member = EgressPlane.MODEL_PROVIDER
    original = object.__getattribute__(member, "_value_")
    try:
        object.__setattr__(member, "_value_", HostileText("model_provider"))
        with pytest.raises(ValidationError):
            DestinationResolution(
                schema_version=SCHEMA_VERSION,
                plane=member,
                origin="https://provider.example.invalid",
                addresses=("8.8.8.8",),
            )
    finally:
        object.__setattr__(member, "_value_", original)

    assert calls == {"repr": 0, "str": 0, "eq": 0, "hash": 0}
