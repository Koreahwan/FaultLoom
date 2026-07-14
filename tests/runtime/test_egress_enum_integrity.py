from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from enum import Enum
from pathlib import Path

import pytest
from pydantic import ValidationError

import faultloom.egress as egress_module
from faultloom.egress import DestinationResolution, EgressPlane
from faultloom.egress_wire import EgressWireError
from faultloom_protocol import SCHEMA_VERSION


def _enum_registries(
    enum_type: type[Enum],
) -> tuple[dict[str, Enum], dict[str, Enum]]:
    member_map: dict[str, Enum] = type.__getattribute__(enum_type, "_member_map_")
    value_map: dict[str, Enum] = type.__getattribute__(
        enum_type, "_value2member_map_"
    )
    return member_map, value_map


def _restore_registry(
    registry: dict[str, Enum],
    entries: tuple[tuple[str, Enum], ...],
) -> None:
    dict.clear(registry)
    dict.update(registry, entries)


def test_digest_rejects_forged_registry_aliases() -> None:
    # Given
    member = EgressPlane.MODEL_PROVIDER
    member_map, value_map = _enum_registries(EgressPlane)
    member_entries = tuple(dict.items(member_map))
    value_entries = tuple(dict.items(value_map))

    try:
        dict.__setitem__(member_map, "FORGED_MODEL_PROVIDER", member)
        dict.__setitem__(value_map, "forged_model_provider", member)

        # When / Then
        with pytest.raises(EgressWireError, match="enum_identity"):
            egress_module.sha256_digest(member)
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
        def __eq__(self, other: object) -> bool:  # noqa: OBJECT_OK
            calls["eq"] += 1
            raise AssertionError("hostile registry equality hook executed")

        def __hash__(self) -> int:
            calls["hash"] += 1
            return str.__hash__(self)

    # Given
    member = EgressPlane.MODEL_PROVIDER
    registries = _enum_registries(EgressPlane)
    registry = registries[registry_index]
    registry_entries = tuple(dict.items(registry))
    hostile_key = HostileKey(target_key)
    dict.clear(registry)
    for key, registered_member in registry_entries:
        stored_key = hostile_key if key == target_key else key
        dict.__setitem__(registry, stored_key, registered_member)
    calls.update(eq=0, hash=0)

    try:
        # When / Then
        with pytest.raises(ValidationError):
            DestinationResolution.model_validate(
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
            instance: object,  # noqa: OBJECT_OK
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
            egress_module.sha256_digest(member)
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
        egress_module.sha256_digest(member)


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
