from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_protocol import IdentityProfile, schema_catalog
from labs.identity_workflow import identity_workflow_fixture


def test_t32_protocol_types_are_published_in_the_versioned_schema_catalog() -> None:
    # Given / When
    catalog = schema_catalog()

    # Then
    assert {
        "IdentityProfile",
        "IdentityContext",
        "TenantRef",
        "RoleGrant",
        "AuthSession",
        "IdentityGraph",
        "WorkflowGraph",
        "WorkflowState",
        "TransitionRecord",
        "DifferentialPlan",
    }.issubset(catalog)
    assert catalog["IdentityProfile"]["properties"]["schema_version"]["const"] == "0.1.0"


def test_identity_profile_boundary_rejects_raw_credentials() -> None:
    # Given
    profile = identity_workflow_fixture().identities[0]
    document = profile.model_dump(mode="json")
    document["credential_ref"] = "raw-password"

    # When / Then
    with pytest.raises(ValidationError):
        IdentityProfile.model_validate(document)


def test_fixture_serialization_contains_only_opaque_credential_and_session_references() -> None:
    # Given / When
    document = identity_workflow_fixture().model_dump_json()

    # Then
    assert "secret://lab/credential/" in document
    assert "secret://lab/session/" in document
    assert "raw-password" not in document
