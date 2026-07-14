from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import Callable, Final, Literal, override

import pytest
from pydantic import ValidationError

import faultloom.egress as egress_module
import faultloom.egress_enum_integrity as enum_integrity
from faultloom.egress import DestinationResolution, EgressPlane
from faultloom.egress_wire import EgressWireError
from faultloom_protocol import SCHEMA_VERSION

type _PublicBoundary = Literal["digest", "model"]


def _exercise_digest_boundary() -> None:
    member = EgressPlane.MODEL_PROVIDER
    _ = egress_module.sha256_digest(member)


def _exercise_model_boundary() -> None:
    member = EgressPlane.MODEL_PROVIDER
    _ = DestinationResolution.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "plane": member,
            "origin": "https://provider.example.invalid",
            "addresses": ("8.8.8.8",),
        }
    )


_BOUNDARY_ACTIONS: Final[dict[_PublicBoundary, Callable[[], None]]] = {
    "digest": _exercise_digest_boundary,
    "model": _exercise_model_boundary,
}
_BOUNDARY_ERRORS: Final[dict[_PublicBoundary, type[Exception]]] = {
    "digest": EgressWireError,
    "model": ValidationError,
}


def _exercise_public_boundary(boundary: _PublicBoundary) -> None:
    _BOUNDARY_ACTIONS[boundary]()


def _boundary_error(boundary: _PublicBoundary) -> type[Exception]:
    return _BOUNDARY_ERRORS[boundary]


def _enum_registries(
    enum_type: type[Enum],
) -> tuple[
    dict[enum_integrity.IdentityValue, enum_integrity.IdentityValue],
    dict[enum_integrity.IdentityValue, enum_integrity.IdentityValue],
]:
    class_entries = enum_integrity.exact_class_entries(
        enum_type, error=AssertionError("enum namespace")
    )
    member_map = enum_integrity.entry(class_entries, "_member_map_")
    value_map = enum_integrity.entry(class_entries, "_value2member_map_")
    if not enum_integrity.is_exact_dict(
        member_map
    ) or not enum_integrity.is_exact_dict(value_map):
        raise AssertionError("enum registries")
    return member_map, value_map


def _restore_registry(
    registry: dict[enum_integrity.IdentityValue, enum_integrity.IdentityValue],
    entries: tuple[
        tuple[enum_integrity.IdentityValue, enum_integrity.IdentityValue], ...
    ],
) -> None:
    registry.clear()
    registry.update(entries)


def test_digest_rejects_forged_registry_aliases() -> None:
    # Given
    member = EgressPlane.MODEL_PROVIDER
    member_map, value_map = _enum_registries(EgressPlane)
    member_entries = tuple(member_map.items())
    value_entries = tuple(value_map.items())

    try:
        member_map["FORGED_MODEL_PROVIDER"] = member
        value_map["forged_model_provider"] = member

        # When / Then
        with pytest.raises(EgressWireError, match="enum_identity"):
            _ = egress_module.sha256_digest(member)
    finally:
        _restore_registry(member_map, member_entries)
        _restore_registry(value_map, value_entries)


@pytest.mark.parametrize(
    ("registry_index", "target_key"),
    ((0, "MODEL_PROVIDER"), (1, "model_provider")),
)
def test_public_model_rejects_hostile_registry_key_without_hooks(
    registry_index: int,
    target_key: str,
) -> None:
    calls = {"eq": 0, "hash": 0}

    class HostileKey(str):
        @override
        def __eq__(self, other: enum_integrity.IdentityValue) -> bool:
            calls["eq"] += 1
            raise AssertionError("hostile registry equality hook executed")

        @override
        def __hash__(self) -> int:
            calls["hash"] += 1
            return str.__hash__(self)

    # Given
    member = EgressPlane.MODEL_PROVIDER
    registries = _enum_registries(EgressPlane)
    registry = registries[registry_index]
    registry_entries = tuple(registry.items())
    hostile_key = HostileKey(target_key)
    registry.clear()
    for key, registered_member in registry_entries:
        stored_key = hostile_key if key == target_key else key
        registry[stored_key] = registered_member
    calls.update(eq=0, hash=0)

    try:
        # When / Then
        with pytest.raises(ValidationError):
            _ = DestinationResolution.model_validate(
                {
                    "schema_version": SCHEMA_VERSION,
                    "plane": member,
                    "origin": "https://provider.example.invalid",
                    "addresses": ("8.8.8.8",),
                }
            )
    finally:
        _restore_registry(registry, registry_entries)

    assert calls == {"eq": 0, "hash": 0}


def test_digest_rejects_hostile_class_descriptor_without_hooks() -> None:
    calls = {"get": 0}

    class HostileDescriptor:
        def __get__(
            self,
            instance: enum_integrity.IdentityValue,
            owner: type[Enum] | None,
        ) -> EgressPlane:
            calls["get"] += 1
            raise AssertionError("hostile class descriptor executed")

    # Given
    member = EgressPlane.MODEL_PROVIDER
    type.__setattr__(EgressPlane, "MODEL_PROVIDER", HostileDescriptor())

    try:
        # When / Then
        with pytest.raises(EgressWireError, match="enum_identity"):
            _ = egress_module.sha256_digest(member)
    finally:
        type.__setattr__(EgressPlane, "MODEL_PROVIDER", member)

    assert calls == {"get": 0}


def test_digest_rejects_rebound_public_enum_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CounterfeitPlane(str, Enum):
        MODEL_PROVIDER = "model_provider"

    # Given
    member = EgressPlane.MODEL_PROVIDER
    monkeypatch.setattr(egress_module, "EgressPlane", CounterfeitPlane)

    # When / Then
    with pytest.raises(EgressWireError, match="enum_identity"):
        _ = egress_module.sha256_digest(member)


def test_retained_model_rejects_stale_plane_after_module_reload() -> None:
    # Given
    repository = Path(__file__).parents[2]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        (
            str(repository / "packages/runtime/src"),
            str(repository / "packages/protocol/src"),
            str(repository / "packages/sdk/src"),
        )
    )
    script = textwrap.dedent(
        """
        import importlib

        from pydantic import ValidationError

        import faultloom.egress as egress
        from faultloom_protocol import SCHEMA_VERSION

        retained_model = egress.DestinationResolution
        stale_plane = egress.EgressPlane.MODEL_PROVIDER
        importlib.reload(egress)

        try:
            retained_model.model_validate(
                {
                    "schema_version": SCHEMA_VERSION,
                    "plane": stale_plane,
                    "origin": "https://provider.example.invalid",
                    "addresses": ("8.8.8.8",),
                }
            )
        except ValidationError:
            raise SystemExit(0)
        raise SystemExit(7)
        """
    )

    # When
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    # Then
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("boundary", ("digest", "model"))
def test_public_boundary_rejects_replaced_canonical_module(
    boundary: _PublicBoundary,
) -> None:
    # Given
    module_name = egress_module.__name__
    retained_module = sys.modules[module_name]
    sys.modules[module_name] = ModuleType(module_name)

    try:
        # When / Then
        with pytest.raises(_boundary_error(boundary)):
            _exercise_public_boundary(boundary)
    finally:
        sys.modules[module_name] = retained_module


@pytest.mark.parametrize("boundary", ("digest", "model"))
def test_public_boundary_rejects_deleted_canonical_module(
    boundary: _PublicBoundary,
) -> None:
    # Given
    module_name = egress_module.__name__
    retained_module = sys.modules[module_name]
    del sys.modules[module_name]

    try:
        # When / Then
        with pytest.raises(_boundary_error(boundary)):
            _exercise_public_boundary(boundary)
    finally:
        sys.modules[module_name] = retained_module


@pytest.mark.parametrize("boundary", ("digest", "model"))
def test_public_boundary_rejects_renamed_retained_module(
    boundary: _PublicBoundary,
) -> None:
    # Given
    module_name = egress_module.__name__
    retained_module = sys.modules[module_name]
    retained_module.__name__ = "faultloom.counterfeit_egress"

    try:
        # When / Then
        with pytest.raises(_boundary_error(boundary)):
            _exercise_public_boundary(boundary)
    finally:
        retained_module.__name__ = module_name


def test_public_boundaries_accept_stable_canonical_module() -> None:
    # Given
    member = EgressPlane.MODEL_PROVIDER

    # When
    digest = egress_module.sha256_digest(member)
    resolution = DestinationResolution.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "plane": member,
            "origin": "https://provider.example.invalid",
            "addresses": ("8.8.8.8",),
        }
    )
    serialized = egress_module.canonical_json_bytes(resolution)

    # Then
    assert digest == (
        "sha256:a93368aa650a25a4ed52ecd750e29ec4031455e1ebbf2fcfb6ca9c84b4424d06"
    )
    assert resolution.plane is member
    assert b'"plane":"model_provider"' in serialized
