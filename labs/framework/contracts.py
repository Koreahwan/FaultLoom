"""Versioned fixture manifests and Gateway-backed evidence eligibility."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    ActionIntent,
    DispatchOutcome,
    DispatchReceipt,
    EgressPlane,
    sha256_digest,
)
from faultloom_protocol.base import Identifier, Sha256Digest

LAB_SCHEMA_VERSION: Final = "0.1.0"
DEFAULT_MANIFEST_PATH: Final = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "semantic_http_baseline"
    / "manifest.v1.json"
)

SemVer = Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
HttpStatus = Annotated[int, Field(ge=100, le=599)]


class _LabModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SemanticFixtureMode(StrEnum):
    VULNERABLE = "vulnerable"
    DENIED = "denied"


class OraclePolarity(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class NamespacedDescriptor(_LabModel):
    namespace: Identifier
    descriptor_version: SemVer
    descriptor_type: Identifier
    descriptor_ref: Annotated[
        str,
        Field(pattern=r"^fixtures/[A-Za-z0-9._/-]+\.json$"),
    ]


class OracleDescriptor(_LabModel):
    oracle_id: Identifier
    polarity: OraclePolarity
    effect_kind: Identifier
    expected_status: HttpStatus


class FixtureVariant(_LabModel):
    variant_id: Identifier
    mode: SemanticFixtureMode
    actor_tenant_id: Identifier
    request_method: Literal["GET"]
    request_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/-]+$")]
    oracle: OracleDescriptor


@dataclass(frozen=True, slots=True)
class LabManifestError(ValueError):
    detail: str

    def __str__(self) -> str:
        return self.detail


class LabManifest(_LabModel):
    schema_version: Literal["0.1.0"]
    lab_id: Identifier
    lab_version: SemVer
    fixture_id: Identifier
    fixture_version: SemVer
    target_id: Identifier
    bind_host: Literal["127.0.0.1"]
    state_id: Identifier
    descriptor: NamespacedDescriptor
    variants: tuple[FixtureVariant, ...]

    @model_validator(mode="after")
    def _variants_are_a_unique_control_pair(self) -> Self:
        variant_ids = tuple(variant.variant_id for variant in self.variants)
        modes = frozenset(variant.mode for variant in self.variants)
        if len(variant_ids) != len(set(variant_ids)):
            raise LabManifestError("fixture variant IDs must be unique")
        if modes != frozenset(
            {SemanticFixtureMode.VULNERABLE, SemanticFixtureMode.DENIED}
        ):
            raise LabManifestError("fixture requires vulnerable and denied variants")
        return self

    def variant(self, variant_id: str) -> FixtureVariant:
        for variant in self.variants:
            if variant.variant_id == variant_id:
                return variant
        raise LabManifestError(f"unknown fixture variant: {variant_id}")


class LabDiagnostic(_LabModel):
    """Direct fixture observations are never report evidence."""

    fixture_id: Identifier
    variant_id: Identifier
    status_code: HttpStatus
    body_digest: Sha256Digest
    evidence_eligible: Literal[False] = False


class GatewayEvidenceRequest(_LabModel):
    manifest: LabManifest
    variant_id: Identifier
    intent: ActionIntent
    receipt: DispatchReceipt


class GatewayRunEvidenceBinding(_LabModel):
    """A lab observation bound to one completed Target Gateway action."""

    schema_version: Literal["0.1.0"]
    fixture_id: Identifier
    variant_id: Identifier
    oracle_id: Identifier
    run_id: Identifier
    target_id: Identifier
    action_id: Identifier
    receipt_id: Identifier
    response_digest: Sha256Digest
    evidence_eligible: Literal[True] = True


@dataclass(frozen=True, slots=True)
class GatewayEvidenceBindingError(ValueError):
    detail: str

    def __str__(self) -> str:
        return self.detail


def bind_gateway_evidence(request: GatewayEvidenceRequest) -> GatewayRunEvidenceBinding:
    """Bind a lab oracle only after the Gateway produced a matching receipt."""

    variant = request.manifest.variant(request.variant_id)
    intent = request.intent
    receipt = request.receipt
    if intent.target_id != request.manifest.target_id:
        raise GatewayEvidenceBindingError("intent target does not match the lab manifest")
    if receipt.target_id != intent.target_id or receipt.action_id != intent.action_id:
        raise GatewayEvidenceBindingError("receipt action or target binding differs")
    if (
        intent.subject.tenant_id != variant.actor_tenant_id
        or receipt.tenant_id != variant.actor_tenant_id
    ):
        raise GatewayEvidenceBindingError("intent or receipt tenant differs from the oracle actor")
    if receipt.intent_digest != sha256_digest(intent):
        raise GatewayEvidenceBindingError("receipt is not bound to the run intent")
    if (
        receipt.action_kind != intent.action_kind
        or receipt.semantic_action_digest != intent.payload_digest
    ):
        raise GatewayEvidenceBindingError("receipt semantic action differs from the intent")
    if receipt.egress_plane is not EgressPlane.TARGET_GATEWAY:
        raise GatewayEvidenceBindingError("lab evidence requires Target Gateway egress")
    if receipt.outcome is not DispatchOutcome.COMPLETED:
        raise GatewayEvidenceBindingError("lab evidence requires a completed dispatch")
    if intent.method != variant.request_method or intent.path != variant.request_path:
        raise GatewayEvidenceBindingError("intent does not match the fixture operation")
    if receipt.response_status != variant.oracle.expected_status:
        raise GatewayEvidenceBindingError("receipt response does not satisfy the oracle")
    if receipt.response_digest is None:
        raise GatewayEvidenceBindingError("completed lab evidence requires a response digest")
    return GatewayRunEvidenceBinding(
        schema_version=LAB_SCHEMA_VERSION,
        fixture_id=request.manifest.fixture_id,
        variant_id=variant.variant_id,
        oracle_id=variant.oracle.oracle_id,
        run_id=intent.run_id,
        target_id=intent.target_id,
        action_id=intent.action_id,
        receipt_id=receipt.receipt_id,
        response_digest=receipt.response_digest,
    )


def load_semantic_http_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> LabManifest:
    """Parse a versioned public fixture manifest at the local file boundary."""

    return LabManifest.model_validate_json(path.read_bytes())
