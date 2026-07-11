"""Fail-closed data registry for pack and adapter manifests.

Registry checks only bind a local compilation/normalization request to an
operator-approved manifest ID. They are not scope decisions and deliberately
cannot produce an ActionLease or dispatch receipt.
"""

from __future__ import annotations

from collections.abc import Iterable

from faultloom_protocol import (
    ActionClass,
    ActionIntent,
    AdapterManifest,
    AuthorityGrant,
    ObservationRef,
    PackManifest,
    sha256_digest,
)

from .rpc import CompileActionRequest, NormalizeObservationRequest, RpcMethod


class ManifestRegistryError(ValueError):
    """Base class for extension admission failures."""


class UnknownDescriptorError(ManifestRegistryError):
    """A manifest asks for code or capability absent from the admitted catalog."""


class ManifestConflictError(ManifestRegistryError):
    """An installed ID is reused for different immutable manifest bytes."""


class AuthorityBindingError(ManifestRegistryError):
    """A local extension request is not named by the supplied grant."""


def _unknown(values: Iterable[str], admitted: frozenset[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values) - admitted))


class ManifestRegistry:
    """Store validated manifests without importing extension code."""

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
        self._known_pack_descriptor_roles = {
            "capability_descriptors": frozenset(known_capability_descriptors),
            "action_compilers": frozenset(known_action_compilers),
            "observation_normalizers": frozenset(known_observation_normalizers),
            "hypothesis_providers": frozenset(known_hypothesis_providers),
            "verifier_descriptors": frozenset(known_verifier_descriptors),
            "evaluation_descriptors": frozenset(known_evaluation_descriptors),
        }
        self._known_adapter_capabilities = frozenset(known_adapter_capabilities)
        self._available_gateway_features = frozenset(available_gateway_features)
        self._packs: dict[str, PackManifest] = {}
        self._adapters: dict[str, AdapterManifest] = {}

    @property
    def packs(self) -> tuple[PackManifest, ...]:
        return tuple(self._packs[key] for key in sorted(self._packs))

    @property
    def adapters(self) -> tuple[AdapterManifest, ...]:
        return tuple(self._adapters[key] for key in sorted(self._adapters))

    def install_pack(self, manifest: PackManifest) -> None:
        for field, admitted in self._known_pack_descriptor_roles.items():
            unknown = _unknown(getattr(manifest, field), admitted)
            if unknown:
                raise UnknownDescriptorError(f"unknown pack {field}: {unknown}")
        unknown = _unknown(
            manifest.required_adapter_capabilities,
            self._known_adapter_capabilities,
        )
        if unknown:
            raise UnknownDescriptorError(f"unknown adapter capabilities: {unknown}")
        unknown = _unknown(
            manifest.required_gateway_features,
            self._available_gateway_features,
        )
        if unknown:
            raise UnknownDescriptorError(f"unavailable gateway features: {unknown}")
        self._store(self._packs, manifest.pack_id, manifest)

    def install_adapter(self, manifest: AdapterManifest) -> None:
        unknown = _unknown(manifest.capabilities, self._known_adapter_capabilities)
        if unknown:
            raise UnknownDescriptorError(f"unknown adapter capabilities: {unknown}")
        self._store(self._adapters, manifest.adapter_id, manifest)

    @staticmethod
    def _store(
        destination: dict[str, PackManifest] | dict[str, AdapterManifest],
        identifier: str,
        manifest: PackManifest | AdapterManifest,
    ) -> None:
        current = destination.get(identifier)
        if current is not None and sha256_digest(current) != sha256_digest(manifest):
            raise ManifestConflictError(f"manifest ID already installed: {identifier}")
        destination[identifier] = manifest  # type: ignore[assignment]

    def prepare_compile(
        self,
        *,
        request_id: str,
        grant: AuthorityGrant,
        intent: ActionIntent,
    ) -> CompileActionRequest:
        manifest = self._packs.get(intent.pack_id)
        if manifest is None:
            raise UnknownDescriptorError(f"pack is not installed: {intent.pack_id}")
        if intent.pack_id not in grant.pack_ids:
            raise AuthorityBindingError("pack installation does not grant authority")
        if intent.target_id not in {target.target_id for target in grant.targets}:
            raise AuthorityBindingError("target is absent from the supplied authority grant")
        if intent.action_kind not in manifest.action_compilers:
            raise UnknownDescriptorError(f"unknown action kind: {intent.action_kind}")
        if intent.action_kind not in grant.action_policy.allowed_families:
            raise AuthorityBindingError("action kind is absent from the supplied authority grant")
        if intent.action_class not in grant.action_policy.allowed_classes:
            raise AuthorityBindingError("action class is absent from the supplied authority grant")
        if intent.action_class in {ActionClass.HIGH_LOAD, ActionClass.DESTRUCTIVE}:
            raise AuthorityBindingError("unsupported v0.1 action class")
        self._require_adapter_coverage(manifest, grant, intent.action_class)
        return CompileActionRequest(
            schema_version="0.1.0",
            rpc_version="0.1.0",
            request_id=request_id,
            method=RpcMethod.COMPILE_ACTION,
            authority_grant_digest=sha256_digest(grant),
            action_intent=intent,
        )

    def prepare_normalize(
        self,
        *,
        request_id: str,
        grant: AuthorityGrant,
        adapter_id: str,
        capability: str,
        observation: ObservationRef,
    ) -> NormalizeObservationRequest:
        adapter = self._adapters.get(adapter_id)
        if adapter is None:
            raise UnknownDescriptorError(f"adapter is not installed: {adapter_id}")
        if adapter_id not in grant.adapter_ids:
            raise AuthorityBindingError("adapter installation does not grant authority")
        if capability not in adapter.capabilities:
            raise UnknownDescriptorError(f"unknown adapter capability: {capability}")
        return NormalizeObservationRequest(
            schema_version="0.1.0",
            rpc_version="0.1.0",
            request_id=request_id,
            method=RpcMethod.NORMALIZE_OBSERVATION,
            authority_grant_digest=sha256_digest(grant),
            adapter_id=adapter_id,
            capability=capability,
            observation=observation,
        )

    def _require_adapter_coverage(
        self,
        pack: PackManifest,
        grant: AuthorityGrant,
        action_class: ActionClass,
    ) -> None:
        granted = (
            adapter
            for adapter_id, adapter in self._adapters.items()
            if adapter_id in grant.adapter_ids
        )
        covered: set[str] = set()
        for adapter in granted:
            if action_class in adapter.action_classes:
                covered.update(adapter.capabilities)
        missing = tuple(sorted(set(pack.required_adapter_capabilities) - covered))
        if missing:
            raise AuthorityBindingError(
                f"granted adapters do not cover required capabilities: {missing}"
            )
