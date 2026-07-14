from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import ClassVar

import pytest

from faultloom_protocol import (
    AuthoritySigner,
    ProtocolModel,
    SignaturePurpose,
    canonical_json_bytes,
    sign_authority_grant,
    sign_engagement_bundle,
    sign_run_result_bundle,
    sign_scope_epoch,
)

from .factories import NOW, sample_models


class _HostileRegistryKey(str):
    hooks_enabled: ClassVar[bool] = False
    hook_calls: ClassVar[int] = 0

    def __eq__(self, other: object) -> bool:
        if type(self).hooks_enabled:
            type(self).hook_calls += 1
            raise AssertionError("hostile registry equality hook executed")
        return str.__eq__(self, other)

    def __hash__(self) -> int:
        if type(self).hooks_enabled:
            type(self).hook_calls += 1
            raise AssertionError("hostile registry hash hook executed")
        return str.__hash__(self)


class _HostileBinding:
    hook_calls: ClassVar[int] = 0

    def __init__(self, value: object) -> None:
        self._value = value

    def __get__(
        self,
        instance: object,
        owner: type[object] | None = None,
    ) -> object:
        type(self).hook_calls += 1
        raise AssertionError("hostile class binding descriptor executed")


class _HostileMemberField:
    hook_calls: ClassVar[int] = 0

    def __get__(self, instance: object, owner: type[object] | None = None) -> str:
        type(self).hook_calls += 1
        raise AssertionError("hostile member metadata descriptor executed")

    def __set__(self, instance: object, value: object) -> None:
        type(self).hook_calls += 1
        raise AssertionError("hostile member metadata descriptor executed")


@contextmanager
def _replaced_purpose_member(
    member_name: str,
    forged_value: str,
) -> Iterator[SignaturePurpose]:
    original_member = type.__getattribute__(SignaturePurpose, member_name)
    original_member_map = type.__getattribute__(SignaturePurpose, "_member_map_")
    original_value_map = type.__getattribute__(SignaturePurpose, "_value2member_map_")
    forged = str.__new__(SignaturePurpose, forged_value)
    object.__setattr__(forged, "_name_", member_name)
    object.__setattr__(forged, "_value_", forged_value)
    replacement_member_map = dict(original_member_map)
    replacement_member_map[member_name] = forged
    replacement_value_map = dict(original_value_map)
    replacement_value_map.pop(str.__str__(original_member), None)
    replacement_value_map[forged_value] = forged

    try:
        type.__setattr__(SignaturePurpose, member_name, forged)
        type.__setattr__(SignaturePurpose, "_member_map_", replacement_member_map)
        type.__setattr__(SignaturePurpose, "_value2member_map_", replacement_value_map)
        yield forged
    finally:
        type.__setattr__(SignaturePurpose, "_value2member_map_", original_value_map)
        type.__setattr__(SignaturePurpose, "_member_map_", original_member_map)
        type.__setattr__(SignaturePurpose, member_name, original_member)


def test_canonicalization_rejects_coordinated_member_name_and_map_mutation() -> None:
    # Given: a canonical member whose live name and member map agree on a forged name.
    member = SignaturePurpose.SCOPE_EPOCH
    original_name = object.__getattribute__(member, "_name_")
    member_map = type.__getattribute__(SignaturePurpose, "_member_map_")
    original_member_map = dict(member_map)

    try:
        object.__setattr__(member, "_name_", "FORGED_SCOPE_EPOCH")
        dict.clear(member_map)
        dict.__setitem__(member_map, "FORGED_SCOPE_EPOCH", member)

        # When/Then: canonicalization rejects the coordinated live-registry mutation.
        with pytest.raises(ValueError, match="immutable expected value"):
            canonical_json_bytes({"purpose": member})
    finally:
        object.__setattr__(member, "_name_", original_name)
        dict.clear(member_map)
        dict.update(member_map, original_member_map)


def test_canonicalization_rejects_forged_exact_enum_inserted_into_maps() -> None:
    # Given: an exact SignaturePurpose instance registered only after class creation.
    forged_value = "forged_scope_epoch"
    forged = str.__new__(SignaturePurpose, forged_value)
    object.__setattr__(forged, "_name_", "FORGED_SCOPE_EPOCH")
    object.__setattr__(forged, "_value_", forged_value)
    member_map = type.__getattribute__(SignaturePurpose, "_member_map_")
    value_map = type.__getattribute__(SignaturePurpose, "_value2member_map_")
    original_member_map = dict(member_map)
    original_value_map = dict(value_map)

    try:
        dict.__setitem__(member_map, "FORGED_SCOPE_EPOCH", forged)
        dict.__setitem__(value_map, forged_value, forged)

        # When/Then: live map membership cannot create a canonical protocol member.
        with pytest.raises(ValueError, match="registered protocol enum member"):
            canonical_json_bytes({"purpose": forged})
    finally:
        dict.clear(value_map)
        dict.update(value_map, original_value_map)
        dict.clear(member_map)
        dict.update(member_map, original_member_map)


def test_canonicalization_rejects_hostile_registry_keys_without_hooks() -> None:
    # Given: exact-size registries whose keys are hostile str subclasses.
    original_member_map = type.__getattribute__(SignaturePurpose, "_member_map_")
    original_value_map = type.__getattribute__(SignaturePurpose, "_value2member_map_")
    replacement_member_map = {
        _HostileRegistryKey(key): member
        for key, member in dict.items(original_member_map)
    }
    replacement_value_map = {
        _HostileRegistryKey(key): member
        for key, member in dict.items(original_value_map)
    }

    try:
        type.__setattr__(SignaturePurpose, "_member_map_", replacement_member_map)
        type.__setattr__(SignaturePurpose, "_value2member_map_", replacement_value_map)
        _HostileRegistryKey.hook_calls = 0
        _HostileRegistryKey.hooks_enabled = True

        # When/Then: raw key-type validation rejects before hash or equality dispatch.
        with pytest.raises(ValueError, match="immutable expected value"):
            canonical_json_bytes(SignaturePurpose.SCOPE_EPOCH)
        assert _HostileRegistryKey.hook_calls == 0
    finally:
        _HostileRegistryKey.hooks_enabled = False
        type.__setattr__(SignaturePurpose, "_value2member_map_", original_value_map)
        type.__setattr__(SignaturePurpose, "_member_map_", original_member_map)


def test_canonicalization_rejects_hostile_descriptors_without_hooks() -> None:
    # Given: hostile descriptors replace a member binding or its metadata field.
    member = SignaturePurpose.SCOPE_EPOCH
    raw_namespace = type.__getattribute__(SignaturePurpose, "__dict__")
    original_binding = raw_namespace["SCOPE_EPOCH"]
    original_member_map = raw_namespace["_member_map_"]

    try:
        type.__setattr__(SignaturePurpose, "SCOPE_EPOCH", _HostileBinding(member))
        _HostileBinding.hook_calls = 0

        # When/Then: raw class inspection rejects without descriptor dispatch.
        with pytest.raises(ValueError, match="immutable expected value"):
            canonical_json_bytes(member)
        assert _HostileBinding.hook_calls == 0
    finally:
        type.__setattr__(SignaturePurpose, "SCOPE_EPOCH", original_binding)

    try:
        type.__setattr__(SignaturePurpose, "_name_", _HostileMemberField())
        _HostileMemberField.hook_calls = 0

        # When/Then: raw instance metadata inspection rejects without dispatch.
        with pytest.raises(ValueError, match="immutable expected value"):
            canonical_json_bytes(member)
        assert _HostileMemberField.hook_calls == 0
    finally:
        type.__delattr__(SignaturePurpose, "_name_")

    try:
        type.__setattr__(
            SignaturePurpose,
            "_member_map_",
            _HostileBinding(original_member_map),
        )
        _HostileBinding.hook_calls = 0

        # When/Then: raw registry lookup rejects without descriptor dispatch.
        with pytest.raises(ValueError, match="immutable expected value"):
            canonical_json_bytes(member)
        assert _HostileBinding.hook_calls == 0
    finally:
        type.__setattr__(SignaturePurpose, "_member_map_", original_member_map)


@pytest.mark.parametrize(
    ("member_name", "model_name", "signer_call"),
    (
        ("AUTHORITY_GRANT", "AuthorityGrant", sign_authority_grant),
        ("SCOPE_EPOCH", "ScopeEpoch", sign_scope_epoch),
        ("ENGAGEMENT_BUNDLE", "EngagementBundle", sign_engagement_bundle),
        ("RUN_RESULT_BUNDLE", "RunResultBundle", sign_run_result_bundle),
    ),
)
def test_public_signers_reject_replaced_purpose_bindings_and_maps(
    member_name: str,
    model_name: str,
    signer_call: Callable[..., ProtocolModel],
) -> None:
    # Given: all payloads predate a coordinated class binding and registry replacement.
    models = sample_models()
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))

    with _replaced_purpose_member(member_name, f"forged_{member_name.casefold()}"):
        # When/Then: no public signer emits a signature with the forged wire purpose.
        with pytest.raises(ValueError, match="protocol enum"):
            signer_call(models[model_name], signer, signed_at=NOW)

    raw_namespace = type.__getattribute__(SignaturePurpose, "__dict__")
    canonical_member = raw_namespace[member_name]
    try:
        type.__setattr__(SignaturePurpose, member_name, _HostileBinding(canonical_member))
        _HostileBinding.hook_calls = 0
        with pytest.raises(ValueError, match="protocol enum"):
            signer_call(models[model_name], signer, signed_at=NOW)
        assert _HostileBinding.hook_calls == 0
    finally:
        type.__setattr__(SignaturePurpose, member_name, canonical_member)
