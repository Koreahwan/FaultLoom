from __future__ import annotations

import pytest
from pydantic import ValidationError

import faultloom_protocol.models as m
from faultloom_sdk import reference_adapter_manifest, reference_pack_manifest


def test_reference_manifests_round_trip_and_pin_immutable_artifacts() -> None:
    pack = reference_pack_manifest()
    adapter = reference_adapter_manifest()

    assert m.PackManifest.model_validate_json(pack.model_dump_json()) == pack
    assert m.AdapterManifest.model_validate_json(adapter.model_dump_json()) == adapter
    assert adapter.image_digest is not None
    assert adapter.upstream_commit is None
    assert adapter.update_policy == "pinned_no_runtime_updates"
    assert adapter.network_mode == "none"


@pytest.mark.parametrize("version", ["1.0", "v1.0.0", "1.0.0-rc1", "01.0.0"])
def test_artifact_versions_require_stable_semver(version: str) -> None:
    source = reference_pack_manifest().model_dump(mode="python")
    source["pack_version"] = version
    with pytest.raises(ValidationError, match="semantic version"):
        m.PackManifest.model_validate(source)

    source = reference_adapter_manifest().model_dump(mode="python")
    source["adapter_version"] = version
    with pytest.raises(ValidationError, match="semantic version"):
        m.AdapterManifest.model_validate(source)


def test_pack_namespace_is_versioned_and_descriptor_lists_are_unique() -> None:
    source = reference_pack_manifest().model_dump(mode="python")
    source["schema_namespace"] = "faultloom_reference"
    with pytest.raises(ValidationError):
        m.PackManifest.model_validate(source)

    source = reference_pack_manifest().model_dump(mode="python")
    source["action_compilers"] = ("reference.digest", "reference.digest")
    with pytest.raises(ValidationError, match="unique"):
        m.PackManifest.model_validate(source)


def test_adapter_rejects_mutable_or_unidentified_upstream() -> None:
    source = reference_adapter_manifest().model_dump(mode="python")
    source["upstream_version"] = "latest"
    with pytest.raises(ValidationError, match="pinned release"):
        m.AdapterManifest.model_validate(source)

    source = reference_adapter_manifest().model_dump(mode="python")
    source["upstream_commit"] = None
    source["image_digest"] = None
    with pytest.raises(ValidationError, match="immutable upstream"):
        m.AdapterManifest.model_validate(source)

    source = reference_adapter_manifest().model_dump(mode="python")
    source["upstream_commit"] = "abcdef"
    with pytest.raises(ValidationError):
        m.AdapterManifest.model_validate(source)

    source = reference_adapter_manifest().model_dump(mode="python")
    source["telemetry_policy"] = "unbounded_upstream"
    with pytest.raises(ValidationError):
        m.AdapterManifest.model_validate(source)


@pytest.mark.parametrize("action_class", [m.ActionClass.HIGH_LOAD, m.ActionClass.DESTRUCTIVE])
def test_adapter_cannot_advertise_unsupported_v01_actions(
    action_class: m.ActionClass,
) -> None:
    source = reference_adapter_manifest().model_dump(mode="python")
    source["action_classes"] = (m.ActionClass.OBSERVE, action_class)
    with pytest.raises(ValidationError, match="unsupported v0.1"):
        m.AdapterManifest.model_validate(source)
