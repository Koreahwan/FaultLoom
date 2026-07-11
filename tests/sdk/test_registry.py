from __future__ import annotations

from itertools import combinations

import pytest

import faultloom_protocol.models as m
from faultloom_sdk import (
    AuthorityBindingError,
    DescriptorRoleConflictError,
    ManifestConflictError,
    ManifestRegistry,
    UnknownDescriptorError,
    reference_adapter_manifest,
    reference_pack_manifest,
    reference_registry,
)
from tests.protocol.factories import sample_models

from .conftest import reference_grant, reference_intent


DESCRIPTOR_ROLE_ARGUMENTS = (
    "known_capability_descriptors",
    "known_action_compilers",
    "known_observation_normalizers",
    "known_hypothesis_providers",
    "known_verifier_descriptors",
    "known_evaluation_descriptors",
)


def _role_specific_registry() -> ManifestRegistry:
    return ManifestRegistry(
        known_capability_descriptors={
            "reference.local_transform",
            "reference.alternate_capability",
        },
        known_action_compilers={"reference.digest"},
        known_observation_normalizers={"reference.observation_digest"},
        known_hypothesis_providers={"reference.hypothesis"},
        known_verifier_descriptors={"reference.verifier"},
        known_evaluation_descriptors={"reference.evaluation"},
        known_adapter_capabilities={"reference.digest_normalizer"},
        available_gateway_features={"dispatch.leases"},
    )


def test_installation_does_not_grant_pack_or_adapter_authority() -> None:
    registry = reference_registry()
    intent = reference_intent()
    unapproved = m.AuthorityGrant.model_validate(
        {
            **reference_grant().model_dump(mode="python"),
            "pack_ids": ("pack.other",),
            "adapter_ids": ("adapter.other",),
        }
    )
    with pytest.raises(AuthorityBindingError, match="installation does not grant"):
        registry.prepare_compile(request_id="rpc.compile.1", grant=unapproved, intent=intent)

    observation = sample_models()["ObservationRef"]
    with pytest.raises(AuthorityBindingError, match="installation does not grant"):
        registry.prepare_normalize(
            request_id="rpc.normalize.1",
            grant=unapproved,
            adapter_id="adapter.reference",
            capability="reference.digest_normalizer",
            observation=observation,
        )


def test_unknown_descriptors_and_action_kinds_fail_closed() -> None:
    empty = ManifestRegistry()
    with pytest.raises(UnknownDescriptorError, match="unknown pack capability_descriptors"):
        empty.install_pack(reference_pack_manifest())
    with pytest.raises(UnknownDescriptorError, match="unknown adapter capabilities"):
        empty.install_adapter(reference_adapter_manifest())

    registry = reference_registry()
    unknown = reference_intent().model_copy(update={"action_kind": "reference.unknown"})
    with pytest.raises(UnknownDescriptorError, match="unknown action kind"):
        registry.prepare_compile(
            request_id="rpc.compile.unknown",
            grant=reference_grant(),
            intent=unknown,
        )


def test_manifest_id_collision_requires_identical_bytes() -> None:
    registry = reference_registry()
    changed = reference_pack_manifest().model_copy(update={"pack_version": "0.1.1"})
    with pytest.raises(ManifestConflictError, match="already installed"):
        registry.install_pack(changed)


def test_prepared_requests_are_bound_but_never_leases() -> None:
    registry = reference_registry()
    grant = reference_grant()
    intent = reference_intent()
    request = registry.prepare_compile(
        request_id="rpc.compile.2",
        grant=grant,
        intent=intent,
    )

    assert request.action_intent == intent
    assert request.authority_grant_digest.startswith("sha256:")
    assert not isinstance(request, m.ActionLease)


def test_required_adapter_must_be_installed_and_granted_for_action_class() -> None:
    registry = ManifestRegistry(
        known_capability_descriptors={"reference.local_transform"},
        known_action_compilers={"reference.digest"},
        known_observation_normalizers={"reference.observation_digest"},
        known_hypothesis_providers={"reference.hypothesis"},
        known_verifier_descriptors={"reference.verifier"},
        known_evaluation_descriptors={"reference.evaluation"},
        known_adapter_capabilities={"reference.digest_normalizer"},
        available_gateway_features={"dispatch.leases"},
    )
    registry.install_pack(reference_pack_manifest())
    with pytest.raises(AuthorityBindingError, match="do not cover"):
        registry.prepare_compile(
            request_id="rpc.compile.no-adapter",
            grant=reference_grant(),
            intent=reference_intent(),
        )


@pytest.mark.parametrize(
    ("field", "misclassified", "original_role"),
    [
        ("capability_descriptors", "reference.digest", "action_compilers"),
        ("action_compilers", "reference.local_transform", "capability_descriptors"),
        ("observation_normalizers", "reference.hypothesis", "hypothesis_providers"),
        ("hypothesis_providers", "reference.verifier", "verifier_descriptors"),
        ("verifier_descriptors", "reference.evaluation", "evaluation_descriptors"),
        (
            "evaluation_descriptors",
            "reference.observation_digest",
            "observation_normalizers",
        ),
    ],
)
def test_pack_descriptor_roles_cannot_be_reclassified(
    field: str, misclassified: str, original_role: str
) -> None:
    source = reference_pack_manifest().model_dump(mode="python")
    source[field] = (misclassified,)
    source[original_role] = (
        ("reference.alternate_capability",)
        if original_role == "capability_descriptors"
        else ()
    )
    manifest = m.PackManifest.model_validate(source)

    with pytest.raises(UnknownDescriptorError, match=field):
        _role_specific_registry().install_pack(manifest)


@pytest.mark.parametrize(
    ("left", "right"),
    tuple(combinations(DESCRIPTOR_ROLE_ARGUMENTS, 2)),
)
def test_descriptor_admission_catalogs_must_not_overlap(
    left: str, right: str
) -> None:
    with pytest.raises(DescriptorRoleConflictError, match="reference.shared"):
        ManifestRegistry(**{left: {"reference.shared"}, right: {"reference.shared"}})
