from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

import faultloom_protocol.models as m
from faultloom_protocol import sha256_digest
from faultloom_sdk import (
    CompileActionRequest,
    CompileActionResponse,
    NormalizeObservationRequest,
    reference_adapter_manifest,
    reference_pack_manifest,
    rpc_input_schema,
    rpc_output_schema,
)
from faultloom_sdk import reference_worker


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

    source = reference_pack_manifest().model_dump(mode="python")
    source["action_compilers"] = source["capability_descriptors"]
    with pytest.raises(ValidationError, match="cannot be reused across roles"):
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


def test_adapter_schema_digests_bind_complete_typed_rpc_contracts() -> None:
    input_schema = rpc_input_schema()
    output_schema = rpc_output_schema()
    manifest = reference_adapter_manifest()

    for model, schema in (
        (CompileActionRequest, input_schema),
        (NormalizeObservationRequest, input_schema),
        (CompileActionResponse, output_schema),
    ):
        expected = model.model_json_schema(mode="validation")
        nested = expected.pop("$defs", {})
        assert schema["$defs"][model.__name__] == expected
        assert all(schema["$defs"][name] == value for name, value in nested.items())
    assert manifest.input_schema_digest == sha256_digest(input_schema)
    assert manifest.output_schema_digest == sha256_digest(output_schema)
    assert reference_worker.INPUT_SCHEMA_DIGEST == manifest.input_schema_digest
    assert reference_worker.OUTPUT_SCHEMA_DIGEST == manifest.output_schema_digest

    compile_input = input_schema["$defs"]["CompileActionRequest"]
    assert set(compile_input["required"]) == {
        "schema_version",
        "rpc_version",
        "request_id",
        "method",
        "authority_grant_digest",
        "action_intent",
    }
    normalize_input = input_schema["$defs"]["NormalizeObservationRequest"]
    assert set(normalize_input["required"]) == {
        "schema_version",
        "rpc_version",
        "request_id",
        "method",
        "authority_grant_digest",
        "adapter_id",
        "capability",
        "observation",
    }
    compile_output = output_schema["$defs"]["CompileActionResponse"]
    assert set(compile_output["required"]) == {
        "schema_version",
        "rpc_version",
        "request_id",
        "status",
        "compiled_action",
    }
    assert "network_guard_active" in output_schema["$defs"]["DescribeResponse"][
        "required"
    ]
    compiled_action = output_schema["$defs"]["CompiledAction"]
    assert {
        "required_network_mode",
        "dispatch_authorized",
    }.issubset(compiled_action["required"])
    assert compiled_action["properties"]["dispatch_authorized"]["const"] is False
    assert compiled_action["properties"]["required_network_mode"]["const"] == (
        "gateway_only"
    )

    intent_properties = input_schema["$defs"]["ActionIntent"]["properties"]
    for field, maximum in (("method", 256), ("path", 4096)):
        string_schema = next(
            option
            for option in intent_properties[field]["anyOf"]
            if option.get("type") == "string"
        )
        assert string_schema["minLength"] == 1
        assert string_schema["maxLength"] == maximum
    media_type = input_schema["$defs"]["ObservationRef"]["properties"]["media_type"]
    assert media_type["minLength"] == 1
    assert media_type["maxLength"] == 256


def test_rpc_schema_constraint_drift_changes_advertised_digests() -> None:
    manifest = reference_adapter_manifest()

    input_drift = deepcopy(rpc_input_schema())
    input_drift["$defs"]["CompileActionRequest"]["required"].remove(
        "authority_grant_digest"
    )
    assert sha256_digest(input_drift) != manifest.input_schema_digest

    output_drift = deepcopy(rpc_output_schema())
    compiled = output_drift["$defs"]["CompiledAction"]
    compiled["properties"]["dispatch_authorized"]["const"] = True
    assert sha256_digest(output_drift) != manifest.output_schema_digest
