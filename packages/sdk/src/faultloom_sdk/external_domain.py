"""Stable admission ABI for external-domain declarations.

The stable surface is the data-only ``1.0.0`` declaration and admission
receipt defined here.  Pack execution, plugin loading, transport, target
selection, signing, and lease issuance remain outside this ABI.  In
particular, admitting a declaration never grants authority or performs I/O.

Future declaration fields or execution protocols are unstable until a new ABI
version is explicitly admitted.  Unknown versions therefore fail closed.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import final

from faultloom_protocol import ProtocolModel, sha256_digest
from faultloom_protocol.models import (
    AdapterManifest,
    AuthorityGrant,
    PackManifest,
    SchemaNamespace,
)
from faultloom_protocol.base import Identifier, Sha256Digest, ShortStr

from .registry import ManifestRegistry, ManifestRegistryError


EXTERNAL_DOMAIN_ABI_VERSION = "1.0.0"


class ExternalDomainAdmissionError(ValueError):
    """An external-domain declaration is not admissible without broadening trust."""


class ExternalAdapterBinding(ProtocolModel):
    """Bind one existing adapter manifest to its canonical protocol digest."""

    manifest: AdapterManifest
    manifest_digest: Sha256Digest


class ExternalDomainDeclaration(ProtocolModel):
    """Versioned, data-only external-domain declaration.

    This is the stable ABI boundary.  It names already-defined protocol
    manifests and their descriptors; it cannot carry executable code, raw
    evidence, credentials, target material, or an alternate egress path.
    """

    abi_version: ShortStr
    domain_id: Identifier
    schema_namespace: SchemaNamespace
    pack_manifest: PackManifest
    pack_manifest_digest: Sha256Digest
    adapter_bindings: tuple[ExternalAdapterBinding, ...]
    declared_capabilities: tuple[Identifier, ...]
    declared_actions: tuple[Identifier, ...]
    egress_contract: ShortStr
    cleanup_contract: ShortStr
    evidence_contract: ShortStr


class ExternalDomainAdmission(ProtocolModel):
    """Data receipt proving admission checks, not execution or authority issuance."""

    abi_version: ShortStr
    domain_id: Identifier
    schema_namespace: SchemaNamespace
    declaration_digest: Sha256Digest
    pack_manifest_digest: Sha256Digest
    adapter_manifest_digests: tuple[Sha256Digest, ...]
    authority_grant_digest: Sha256Digest


def _unknown(values: Iterable[str], admitted: frozenset[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values) - admitted))


@final
class ExternalDomainRegistry:
    """Atomically admit external-domain declarations without loading code.

    Catalog arguments describe host-owned implementations.  A declaration may
    reference only those entries and still needs an existing ``AuthorityGrant``
    for its pack, adapters, and requested action families.
    """

    def __init__(
        self,
        *,
        known_capability_descriptors: Iterable[str] = (),
        known_action_compilers: Iterable[str] = (),
        known_observation_normalizers: Iterable[str] = (),
        known_hypothesis_providers: Iterable[str] = (),
        known_verifier_descriptors: Iterable[str] = (),
        known_evaluation_descriptors: Iterable[str] = (),
        known_adapter_capabilities: Iterable[str] = (),
        available_gateway_features: Iterable[str] = (),
    ) -> None:
        self._catalog = {
            "known_capability_descriptors": tuple(known_capability_descriptors),
            "known_action_compilers": tuple(known_action_compilers),
            "known_observation_normalizers": tuple(known_observation_normalizers),
            "known_hypothesis_providers": tuple(known_hypothesis_providers),
            "known_verifier_descriptors": tuple(known_verifier_descriptors),
            "known_evaluation_descriptors": tuple(known_evaluation_descriptors),
            "known_adapter_capabilities": tuple(known_adapter_capabilities),
            "available_gateway_features": tuple(available_gateway_features),
        }
        self._namespaces: dict[str, str] = {}
        self._domain_digests: dict[str, str] = {}
        self._pack_digests: dict[str, str] = {}
        self._adapter_digests: dict[str, str] = {}

    def admit(
        self,
        declaration: ExternalDomainDeclaration,
        *,
        grant: AuthorityGrant,
        requested_capabilities: Iterable[str] = (),
        requested_actions: Iterable[str] = (),
    ) -> ExternalDomainAdmission:
        """Validate and record one declaration without executing extension code."""

        if type(declaration) is not ExternalDomainDeclaration:
            raise ExternalDomainAdmissionError(
                "declaration must be an exact ExternalDomainDeclaration"
            )
        if type(grant) is not AuthorityGrant:
            raise ExternalDomainAdmissionError("grant must be an exact AuthorityGrant")
        clean = ExternalDomainDeclaration.model_validate(
            declaration.model_dump(mode="python")
        )
        if clean.abi_version != EXTERNAL_DOMAIN_ABI_VERSION:
            raise ExternalDomainAdmissionError(
                f"unsupported external-domain ABI: {clean.abi_version}"
            )
        if clean.schema_namespace != clean.pack_manifest.schema_namespace:
            raise ExternalDomainAdmissionError(
                "declaration namespace differs from pack manifest namespace"
            )
        if clean.egress_contract != "gateway_only":
            raise ExternalDomainAdmissionError("direct egress is forbidden")
        if clean.cleanup_contract != "receipt_required":
            raise ExternalDomainAdmissionError("cleanup receipt contract is required")
        if clean.evidence_contract != "digest_references_only":
            raise ExternalDomainAdmissionError(
                "digest-only evidence contract is required"
            )

        pack_digest = sha256_digest(clean.pack_manifest)
        if clean.pack_manifest_digest != pack_digest:
            raise ExternalDomainAdmissionError("pack manifest digest mismatch")

        adapter_ids: set[str] = set()
        adapter_capabilities: set[str] = set()
        adapter_digests: list[str] = []
        adapters: list[AdapterManifest] = []
        for binding in clean.adapter_bindings:
            adapter = binding.manifest
            if adapter.adapter_id in adapter_ids:
                raise ExternalDomainAdmissionError("duplicate adapter manifest ID")
            adapter_ids.add(adapter.adapter_id)
            actual_digest = sha256_digest(adapter)
            if binding.manifest_digest != actual_digest:
                raise ExternalDomainAdmissionError(
                    f"adapter manifest digest mismatch: {adapter.adapter_id}"
                )
            if adapter.network_mode not in {"none", "gateway_only"}:
                raise ExternalDomainAdmissionError(
                    f"adapter requests non-Gateway egress: {adapter.adapter_id}"
                )
            adapter_capabilities.update(adapter.capabilities)
            adapter_digests.append(actual_digest)
            adapters.append(adapter)

        missing_required_capabilities = tuple(
            sorted(
                set(clean.pack_manifest.required_adapter_capabilities)
                - adapter_capabilities
            )
        )
        if missing_required_capabilities:
            detail = missing_required_capabilities
            raise ExternalDomainAdmissionError(
                f"bound adapters do not provide required capabilities: {detail}"
            )

        manifest_capabilities = set(clean.pack_manifest.capability_descriptors)
        pack_descriptors: set[str] = {
            *clean.pack_manifest.capability_descriptors,
            *clean.pack_manifest.action_compilers,
            *clean.pack_manifest.observation_normalizers,
            *clean.pack_manifest.hypothesis_providers,
            *clean.pack_manifest.verifier_descriptors,
            *clean.pack_manifest.evaluation_descriptors,
        }
        if pack_descriptors.intersection(adapter_capabilities):
            raise ExternalDomainAdmissionError(
                "capability namespace is reused across pack and adapter roles"
            )
        expected_capabilities = manifest_capabilities | adapter_capabilities
        if len(clean.declared_capabilities) != len(set(clean.declared_capabilities)):
            raise ExternalDomainAdmissionError("declared capabilities must be unique")
        if set(clean.declared_capabilities) != expected_capabilities:
            raise ExternalDomainAdmissionError(
                "declared capabilities do not exactly match manifest capabilities"
            )
        if len(clean.declared_actions) != len(set(clean.declared_actions)):
            raise ExternalDomainAdmissionError("declared actions must be unique")
        if set(clean.declared_actions) != set(clean.pack_manifest.action_compilers):
            raise ExternalDomainAdmissionError(
                "declared actions do not exactly match pack action compilers"
            )

        requested_capability_set = frozenset(requested_capabilities)
        requested_action_set = frozenset(requested_actions)
        unknown_capabilities = _unknown(
            requested_capability_set, frozenset(clean.declared_capabilities)
        )
        if unknown_capabilities:
            raise ExternalDomainAdmissionError(
                f"requested undeclared capabilities: {unknown_capabilities}"
            )
        unknown_actions = _unknown(
            requested_action_set, frozenset(clean.declared_actions)
        )
        if unknown_actions:
            raise ExternalDomainAdmissionError(
                f"requested undeclared actions: {unknown_actions}"
            )

        pack = clean.pack_manifest
        if pack.pack_id not in grant.pack_ids:
            raise ExternalDomainAdmissionError("authority grant does not name pack")
        missing_adapters = tuple(sorted(adapter_ids - set(grant.adapter_ids)))
        if missing_adapters:
            raise ExternalDomainAdmissionError(
                f"authority grant does not name adapters: {missing_adapters}"
            )
        denied_actions = tuple(
            sorted(requested_action_set - set(grant.action_policy.allowed_families))
        )
        if denied_actions:
            raise ExternalDomainAdmissionError(
                f"authority grant does not allow requested actions: {denied_actions}"
            )

        try:
            manifest_registry = ManifestRegistry(**self._catalog)
            for adapter in adapters:
                manifest_registry.install_adapter(adapter)
            manifest_registry.install_pack(pack)
        except ManifestRegistryError as exc:
            raise ExternalDomainAdmissionError(str(exc)) from exc

        declaration_document = clean.model_dump(mode="python")
        declaration_digest = sha256_digest(declaration_document)
        existing_domain = self._namespaces.get(clean.schema_namespace)
        if existing_domain is not None and existing_domain != clean.domain_id:
            raise ExternalDomainAdmissionError(
                f"schema namespace already admitted by {existing_domain}"
            )
        existing_digest = self._domain_digests.get(clean.domain_id)
        if existing_digest is not None and existing_digest != declaration_digest:
            raise ExternalDomainAdmissionError("domain ID already admitted with other bytes")
        existing_pack_digest = self._pack_digests.get(pack.pack_id)
        if existing_pack_digest is not None and existing_pack_digest != pack_digest:
            raise ExternalDomainAdmissionError("pack ID already admitted with other bytes")
        for adapter, digest in zip(adapters, adapter_digests, strict=True):
            existing_adapter_digest = self._adapter_digests.get(adapter.adapter_id)
            if existing_adapter_digest is not None and existing_adapter_digest != digest:
                raise ExternalDomainAdmissionError(
                    f"adapter ID already admitted with other bytes: {adapter.adapter_id}"
                )

        receipt = ExternalDomainAdmission(
            schema_version="0.1.0",
            abi_version=EXTERNAL_DOMAIN_ABI_VERSION,
            domain_id=clean.domain_id,
            schema_namespace=clean.schema_namespace,
            declaration_digest=declaration_digest,
            pack_manifest_digest=pack_digest,
            adapter_manifest_digests=tuple(adapter_digests),
            authority_grant_digest=sha256_digest(grant),
        )
        self._namespaces[clean.schema_namespace] = clean.domain_id
        self._domain_digests[clean.domain_id] = declaration_digest
        self._pack_digests[pack.pack_id] = pack_digest
        self._adapter_digests.update(
            (adapter.adapter_id, digest)
            for adapter, digest in zip(adapters, adapter_digests, strict=True)
        )
        return receipt
