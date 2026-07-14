from __future__ import annotations

import socket
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from types import ModuleType
from typing import Never, override

import pytest
from pydantic import ValidationError

import faultloom.egress as egress_module
import faultloom.egress_enum_integrity as enum_integrity
from faultloom.egress import DestinationResolution, EgressPlane, KnowledgeFetchIntent
from faultloom.egress_wire import EgressWireError
from faultloom_protocol import SCHEMA_VERSION


def _resolution_input() -> dict[str, enum_integrity.IdentityValue]:
    return {
        "schema_version": SCHEMA_VERSION,
        "plane": EgressPlane.MODEL_PROVIDER,
        "origin": "https://provider.example.invalid",
        "addresses": ("8.8.8.8",),
    }


def test_model_rejects_later_hostile_key_without_invoking_hooks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"eq": 0, "hash": 0, "socket": 0}
    module_name = egress_module.__name__
    genuine_module = sys.modules[module_name]
    counterfeit_module = ModuleType(module_name)

    class HostileLaterKey(str):
        @override
        def __eq__(self, other: enum_integrity.IdentityValue, /) -> bool:
            calls["eq"] += 1
            sys.modules[module_name] = counterfeit_module
            return str.__eq__(self, other)

        @override
        def __hash__(self) -> int:
            calls["hash"] += 1
            return str.__hash__(self)

    def deny_socket(
        *_args: enum_integrity.IdentityValue,
        **_kwargs: enum_integrity.IdentityValue,
    ) -> Never:
        calls["socket"] += 1
        raise AssertionError("model validation must not construct a socket")

    hostile_key = HostileLaterKey("addresses")
    model_input: dict[
        enum_integrity.IdentityValue, enum_integrity.IdentityValue
    ] = {
        "schema_version": SCHEMA_VERSION,
        "plane": EgressPlane.MODEL_PROVIDER,
        "origin": "https://provider.example.invalid",
        hostile_key: ("8.8.8.8",),
    }
    calls.update(eq=0, hash=0, socket=0)
    monkeypatch.setattr(socket, "socket", deny_socket)

    try:
        with pytest.raises(ValidationError):
            _ = DestinationResolution.model_validate(model_input)
    finally:
        sys.modules[module_name] = genuine_module

    assert calls == {"eq": 0, "hash": 0, "socket": 0}
    assert sys.modules[module_name] is genuine_module


def test_model_rejects_dict_subclass_without_invoking_mapping_hooks() -> None:
    calls = {"getitem": 0, "iter": 0, "len": 0}

    class HostileMapping(dict[str, enum_integrity.IdentityValue]):
        @override
        def __getitem__(self, key: str, /) -> enum_integrity.IdentityValue:
            calls["getitem"] += 1
            raise AssertionError("foreign mapping lookup executed")

        @override
        def __iter__(self) -> Iterator[str]:
            calls["iter"] += 1
            raise AssertionError("foreign mapping iteration executed")

        @override
        def __len__(self) -> int:
            calls["len"] += 1
            raise AssertionError("foreign mapping length hook executed")

    model_input = HostileMapping(_resolution_input())

    with pytest.raises(ValidationError):
        _ = DestinationResolution.model_validate(model_input)

    assert calls == {"getitem": 0, "iter": 0, "len": 0}


def test_model_rechecks_catalog_after_later_value_parser_mutates_module() -> None:
    calls = {"eq": 0, "hash": 0}
    module_name = egress_module.__name__
    genuine_module = sys.modules[module_name]
    counterfeit_module = ModuleType(module_name)
    baseline_digest = egress_module.sha256_digest(EgressPlane.MODEL_PROVIDER)

    class HostileMethod(str):
        @override
        def __eq__(self, other: enum_integrity.IdentityValue, /) -> bool:
            calls["eq"] += 1
            sys.modules[module_name] = counterfeit_module
            return str.__eq__(self, other)

        @override
        def __hash__(self) -> int:
            calls["hash"] += 1
            sys.modules[module_name] = counterfeit_module
            return str.__hash__(self)

    try:
        with pytest.raises(ValidationError):
            _ = KnowledgeFetchIntent.model_validate(
                {
                    "schema_version": SCHEMA_VERSION,
                    "request_id": "request.1",
                    "run_id": "run.1",
                    "authority_digest": "sha256:" + "00" * 32,
                    "scope_epoch": 1,
                    "source_id": "source.1",
                    "method": HostileMethod("GET"),
                    "path": "/security",
                    "data_policy_id": "policy.1",
                    "requested_at": datetime(2030, 1, 1, tzinfo=timezone.utc),
                }
            )
    finally:
        sys.modules[module_name] = genuine_module

    assert calls["eq"] > 0
    assert calls["hash"] > 0
    assert egress_module.sha256_digest(EgressPlane.MODEL_PROVIDER) == baseline_digest


def test_boundaries_reject_replaced_sys_modules_mapping_identity() -> None:
    original_registry = sys.modules
    replacement_registry = dict(original_registry)

    try:
        sys.modules = replacement_registry
        with pytest.raises(EgressWireError, match="enum_identity"):
            _ = egress_module.sha256_digest(EgressPlane.MODEL_PROVIDER)
        with pytest.raises(ValidationError):
            _ = DestinationResolution.model_validate(_resolution_input())
    finally:
        sys.modules = original_registry


def test_model_boundary_preserves_stable_dict_and_instance_inputs() -> None:
    expected_digest = (
        "sha256:a93368aa650a25a4ed52ecd750e29ec4031455e1ebbf2fcfb6ca9c84b4424d06"
    )
    resolution = DestinationResolution.model_validate(_resolution_input())
    revalidated = DestinationResolution.model_validate(resolution)

    assert resolution.plane is EgressPlane.MODEL_PROVIDER
    assert revalidated == resolution
    assert revalidated is not resolution
    assert egress_module.sha256_digest(EgressPlane.MODEL_PROVIDER) == expected_digest
