from __future__ import annotations

import pytest

import faultloom_sdk
import faultloom_protocol.models as m
from faultloom_protocol import sha256_digest
from faultloom_sdk.external_domain import (
    EXTERNAL_DOMAIN_ABI_VERSION,
    ExternalAdapterBinding,
    ExternalDomainAdmissionError,
    ExternalDomainDeclaration,
    ExternalDomainRegistry,
)
from tests.protocol.factories import D1, D2, sample_models


def _pack(*, pack_id: str = "pack.external.cloud") -> m.PackManifest:
    return m.PackManifest(
        schema_version="0.1.0",
        pack_id=pack_id,
        pack_version="1.0.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="external.cloud.v1",
        capability_descriptors=("cloud.iam.observe",),
        action_compilers=("cloud.iam.read",),
        observation_normalizers=("cloud.iam.observation",),
        hypothesis_providers=("cloud.iam.hypothesis",),
        verifier_descriptors=("cloud.iam.verifier",),
        evaluation_descriptors=("cloud.iam.fixture",),
        required_gateway_features=("dispatch.leases",),
        required_adapter_capabilities=("cloud.read_only_api",),
    )


def _adapter(*, adapter_id: str = "adapter.external.cloud") -> m.AdapterManifest:
    return m.AdapterManifest(
        schema_version="0.1.0",
        adapter_id=adapter_id,
        adapter_version="1.0.0",
        upstream_version="1.2.3",
        image_digest=D1,
        license_class=m.LicenseClass.EXTERNAL_USER_MANAGED,
        capabilities=("cloud.read_only_api",),
        action_classes=(m.ActionClass.OBSERVE,),
        network_mode="gateway_only",
        input_schema_digest=D1,
        output_schema_digest=D2,
        budget=m.AdapterBudget(
            schema_version="0.1.0",
            rate_per_minute=10,
            timeout_seconds=5,
            max_bytes=65536,
            max_concurrency=1,
        ),
        telemetry_policy=m.TelemetryPolicy.LOCAL_RECEIPTS_ONLY,
        evidence_capability=m.EvidenceCapability.CANDIDATE_ONLY,
    )


def _declaration(
    *,
    pack: m.PackManifest | None = None,
    adapter: m.AdapterManifest | None = None,
) -> ExternalDomainDeclaration:
    pack = pack or _pack()
    adapter = adapter or _adapter()
    return ExternalDomainDeclaration(
        schema_version="0.1.0",
        abi_version=EXTERNAL_DOMAIN_ABI_VERSION,
        domain_id="domain.external.cloud",
        schema_namespace=pack.schema_namespace,
        pack_manifest=pack,
        pack_manifest_digest=sha256_digest(pack),
        adapter_bindings=(
            ExternalAdapterBinding(
                schema_version="0.1.0",
                manifest=adapter,
                manifest_digest=sha256_digest(adapter),
            ),
        ),
        declared_capabilities=("cloud.iam.observe", "cloud.read_only_api"),
        declared_actions=("cloud.iam.read",),
        egress_contract="gateway_only",
        cleanup_contract="receipt_required",
        evidence_contract="digest_references_only",
    )


def _grant(*, packs: tuple[str, ...] = ("pack.external.cloud",)) -> m.AuthorityGrant:
    source = sample_models()["AuthorityGrant"].model_dump(mode="python")
    source["pack_ids"] = packs
    source["adapter_ids"] = ("adapter.external.cloud",)
    policy = source["action_policy"]
    policy["allowed_families"] = ("cloud.iam.read",)
    source["action_policy"] = m.ActionPolicy.model_validate(policy)
    return m.AuthorityGrant.model_validate(source)


def _registry() -> ExternalDomainRegistry:
    return ExternalDomainRegistry(
        known_capability_descriptors={"cloud.iam.observe"},
        known_action_compilers={"cloud.iam.read"},
        known_observation_normalizers={"cloud.iam.observation"},
        known_hypothesis_providers={"cloud.iam.hypothesis"},
        known_verifier_descriptors={"cloud.iam.verifier"},
        known_evaluation_descriptors={"cloud.iam.fixture"},
        known_adapter_capabilities={"cloud.read_only_api"},
        available_gateway_features={"dispatch.leases"},
    )


def test_v1_fixture_admits_as_data_without_loading_or_execution() -> None:
    assert faultloom_sdk.EXTERNAL_DOMAIN_ABI_VERSION == EXTERNAL_DOMAIN_ABI_VERSION
    declaration = _declaration()
    receipt = _registry().admit(
        declaration,
        grant=_grant(),
        requested_capabilities=("cloud.iam.observe", "cloud.read_only_api"),
        requested_actions=("cloud.iam.read",),
    )

    assert receipt.abi_version == "1.0.0"
    assert receipt.pack_manifest_digest == declaration.pack_manifest_digest
    assert receipt.adapter_manifest_digests == (
        declaration.adapter_bindings[0].manifest_digest,
    )
    assert receipt.authority_grant_digest == sha256_digest(_grant())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("abi_version", "2.0.0", "unsupported external-domain ABI"),
        ("egress_contract", "direct", "direct egress is forbidden"),
        ("cleanup_contract", "best_effort", "cleanup receipt contract is required"),
        ("evidence_contract", "raw_payloads", "digest-only evidence contract"),
    ],
)
def test_unsupported_or_incomplete_boundary_contracts_fail_closed(
    field: str, value: str, message: str
) -> None:
    declaration = _declaration().model_copy(update={field: value})

    with pytest.raises(ExternalDomainAdmissionError, match=message):
        _registry().admit(declaration, grant=_grant())


def test_manifest_digest_mismatch_fails_closed() -> None:
    declaration = _declaration().model_copy(update={"pack_manifest_digest": D2})
    with pytest.raises(ExternalDomainAdmissionError, match="pack manifest digest mismatch"):
        _registry().admit(declaration, grant=_grant())

    original = _declaration()
    bad_binding = original.adapter_bindings[0].model_copy(
        update={"manifest_digest": D2}
    )
    declaration = original.model_copy(update={"adapter_bindings": (bad_binding,)})
    with pytest.raises(ExternalDomainAdmissionError, match="adapter manifest digest mismatch"):
        _registry().admit(declaration, grant=_grant())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("declared_capabilities", ("cloud.iam.observe",), "declared capabilities"),
        ("declared_actions", (), "declared actions"),
    ],
)
def test_manifest_entries_missing_from_declaration_fail_closed(
    field: str, value: tuple[str, ...], message: str
) -> None:
    declaration = _declaration().model_copy(update={field: value})
    with pytest.raises(ExternalDomainAdmissionError, match=message):
        _registry().admit(declaration, grant=_grant())


def test_bound_adapter_must_supply_the_pack_requirement() -> None:
    pack = _pack().model_copy(
        update={"required_adapter_capabilities": ("cloud.unbound_api",)}
    )
    declaration = _declaration(pack=pack).model_copy(
        update={"pack_manifest_digest": sha256_digest(pack)}
    )

    with pytest.raises(ExternalDomainAdmissionError, match="do not provide"):
        _registry().admit(declaration, grant=_grant())


def test_adapter_capability_cannot_reuse_a_pack_descriptor_role() -> None:
    adapter = _adapter().model_copy(
        update={"capabilities": ("cloud.iam.read", "cloud.read_only_api")}
    )
    declaration = _declaration(adapter=adapter).model_copy(
        update={
            "declared_capabilities": (
                "cloud.iam.observe",
                "cloud.iam.read",
                "cloud.read_only_api",
            )
        }
    )

    with pytest.raises(ExternalDomainAdmissionError, match="namespace is reused"):
        _registry().admit(declaration, grant=_grant())


def test_requested_undeclared_capability_and_action_fail_closed() -> None:
    with pytest.raises(ExternalDomainAdmissionError, match="undeclared capabilities"):
        _registry().admit(
            _declaration(),
            grant=_grant(),
            requested_capabilities=("cloud.admin.write",),
        )
    with pytest.raises(ExternalDomainAdmissionError, match="undeclared actions"):
        _registry().admit(
            _declaration(),
            grant=_grant(),
            requested_actions=("cloud.iam.write",),
        )


def test_existing_authority_is_required_for_pack_adapter_and_action() -> None:
    with pytest.raises(ExternalDomainAdmissionError, match="does not name pack"):
        _registry().admit(_declaration(), grant=_grant(packs=("pack.other",)))

    grant_source = _grant().model_dump(mode="python")
    grant_source["adapter_ids"] = ("adapter.other",)
    with pytest.raises(ExternalDomainAdmissionError, match="does not name adapters"):
        _registry().admit(
            _declaration(), grant=m.AuthorityGrant.model_validate(grant_source)
        )

    grant_source = _grant().model_dump(mode="python")
    policy = grant_source["action_policy"]
    policy["allowed_families"] = ("cloud.other.read",)
    grant_source["action_policy"] = m.ActionPolicy.model_validate(policy)
    with pytest.raises(ExternalDomainAdmissionError, match="does not allow"):
        _registry().admit(
            _declaration(),
            grant=m.AuthorityGrant.model_validate(grant_source),
            requested_actions=("cloud.iam.read",),
        )


def test_namespace_collision_fails_without_replacing_first_admission() -> None:
    registry = _registry()
    first = registry.admit(_declaration(), grant=_grant())
    other_pack = _pack(pack_id="pack.external.cloud.other")
    other = _declaration(pack=other_pack).model_copy(
        update={
            "domain_id": "domain.external.cloud.other",
            "pack_manifest_digest": sha256_digest(other_pack),
        }
    )

    with pytest.raises(ExternalDomainAdmissionError, match="schema namespace already"):
        registry.admit(
            other,
            grant=_grant(
                packs=("pack.external.cloud", "pack.external.cloud.other")
            ),
        )

    assert registry.admit(_declaration(), grant=_grant()) == first


def test_unknown_host_descriptor_is_rejected_by_existing_manifest_semantics() -> None:
    registry = ExternalDomainRegistry(
        known_adapter_capabilities={"cloud.read_only_api"},
        available_gateway_features={"dispatch.leases"},
    )
    with pytest.raises(ExternalDomainAdmissionError, match="unknown pack"):
        registry.admit(_declaration(), grant=_grant())
