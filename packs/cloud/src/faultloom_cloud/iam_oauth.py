"""Normalize supplied Cloud/IAM/OAuth projections without credential operations."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import faultloom_protocol.models as protocol_models
from faultloom_protocol import SCHEMA_VERSION, canonical_json_bytes, sha256_digest
from faultloom_sdk import NormalizedObservation

if TYPE_CHECKING:
    from faultloom.execution import GatewayDispatchCommand

_ADAPTER_ID = "adapter.cloud_iam_oauth.loopback"
_NORMALIZER_ID = "cloud.iam_oauth.trust_path.normalizer"
_PROJECTION_FIELDS = frozenset(
    {
        "surface",
        "token_material_present",
        "issuer_matches",
        "subject_matches",
        "audience_matches",
        "redirect_uri_matches",
        "privilege_path",
    }
)
CaseId = Literal[
    "iam-trust-mismatch",
    "oauth-redirect-mismatch",
    "iam-matched-negative",
    "oauth-matched-negative",
]
TrustSurface = Literal["iam", "oauth"]
CandidateReason = Literal[
    "issuer_binding_mismatch",
    "subject_binding_mismatch",
    "audience_binding_mismatch",
    "oauth_redirect_mismatch",
    "privilege_path_to_sensitive_role",
]
_CASE_IDS: tuple[CaseId, ...] = (
    "iam-trust-mismatch",
    "oauth-redirect-mismatch",
    "iam-matched-negative",
    "oauth-matched-negative",
)
_NEGATIVE_CONTROL_CASE_IDS: tuple[CaseId, ...] = (
    "iam-matched-negative",
    "oauth-matched-negative",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MANIFEST_SCHEMA_VERSION = "g45.cloud_iam_oauth.input.v1"
_MANIFEST_TOP_LEVEL_FIELDS = frozenset({"payload", "signature"})
_MANIFEST_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "fixture_id",
        "authority",
        "scope",
        "budget",
        "source_digests",
        "negative_control_case_ids",
        "candidate_only",
        "provider_egress",
    }
)
_MANIFEST_AUTHORITY_FIELDS = frozenset({"grant_id", "grant_version", "key_id"})
_MANIFEST_SCOPE_FIELDS = frozenset(
    {
        "scope_epoch",
        "target_id",
        "hostname",
        "path_prefix",
        "identity_id",
        "tenant_id",
    }
)
_MANIFEST_BUDGET_FIELDS = frozenset(
    {"action_count", "request_bytes", "response_bytes", "duration_seconds"}
)
_MANIFEST_SIGNATURE_FIELDS = frozenset(
    {"algorithm", "key_id", "public_key", "payload_digest", "signature"}
)


class ReadOnlyCloudTrustSnapshot(Protocol):
    """A supplied projection, never a cloud SDK, token, or credential handle."""

    @property
    def url(self) -> str: ...

    @property
    def body(self) -> bytes: ...


class CloudTrustObservationSource(Protocol):
    def read(self, case_id: CaseId) -> ReadOnlyCloudTrustSnapshot: ...


@dataclass(frozen=True)
class CloudTrustEvidence:
    normalized_observation: NormalizedObservation
    case_id: CaseId
    surface: TrustSurface
    issuer_matches: bool
    subject_matches: bool
    audience_matches: bool
    redirect_uri_matches: bool
    privilege_path: tuple[str, ...]
    candidate_reasons: tuple[CandidateReason, ...]
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    candidate_only: Literal[True] = True


@dataclass(frozen=True)
class CloudTrustVerdict:
    classification: Literal["candidate_only", "negative_control"]
    verified: Literal[False] = False
    gateway_required_for_followup: Literal[True] = True


@dataclass(frozen=True)
class CloudTrustRun:
    evidence: CloudTrustEvidence
    verdict: CloudTrustVerdict


@dataclass(frozen=True)
class CloudTrustInputManifest:
    """A signed, exact-schema description of the fully owned G45 inputs."""

    fixture_id: str
    authority_grant_id: str
    authority_grant_version: int
    authority_key_id: str
    scope_epoch: int
    target_id: str
    hostname: str
    path_prefix: str
    identity_id: str
    tenant_id: str
    action_count: int
    request_bytes: int
    response_bytes: int
    duration_seconds: int
    source_digests: tuple[tuple[CaseId, str], ...]
    negative_control_case_ids: tuple[CaseId, ...]
    signature_public_key: str
    signature: str
    signed_payload_digest: str

    @property
    def input_digest(self) -> str:
        return sha256_digest(self._unsigned_payload())

    def source_digest(self, case_id: CaseId) -> str:
        for known_case_id, digest in self.source_digests:
            if known_case_id == case_id:
                return digest
        raise ValueError("cloud trust input manifest has an unknown case")

    def verify(self) -> None:
        """Fail closed on payload, public-key, or Ed25519 signature drift."""

        payload = self._unsigned_payload()
        if self.input_digest != self.signed_payload_digest:
            raise ValueError("cloud trust input manifest digest does not match signature")
        public_key_bytes = _decode_base64url(self.signature_public_key, "public key")
        if len(public_key_bytes) != 32:
            raise ValueError("cloud trust input manifest public key has an invalid length")
        expected_key_id = f"ed25519:sha256:{hashlib.sha256(public_key_bytes).hexdigest()}"
        if self.authority_key_id != expected_key_id:
            raise ValueError("cloud trust input manifest authority key does not match public key")
        signature = _decode_base64url(self.signature, "signature")
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                signature, canonical_json_bytes(payload)
            )
        except InvalidSignature as error:
            raise ValueError("cloud trust input manifest signature is invalid") from error

    def _unsigned_payload(self) -> dict[str, object]:
        return {
            "schema_version": _MANIFEST_SCHEMA_VERSION,
            "fixture_id": self.fixture_id,
            "authority": {
                "grant_id": self.authority_grant_id,
                "grant_version": self.authority_grant_version,
                "key_id": self.authority_key_id,
            },
            "scope": {
                "scope_epoch": self.scope_epoch,
                "target_id": self.target_id,
                "hostname": self.hostname,
                "path_prefix": self.path_prefix,
                "identity_id": self.identity_id,
                "tenant_id": self.tenant_id,
            },
            "budget": {
                "action_count": self.action_count,
                "request_bytes": self.request_bytes,
                "response_bytes": self.response_bytes,
                "duration_seconds": self.duration_seconds,
            },
            "source_digests": dict(self.source_digests),
            "negative_control_case_ids": list(self.negative_control_case_ids),
            "candidate_only": True,
            "provider_egress": False,
        }


@dataclass(frozen=True)
class CloudTrustActionPlan:
    """An exact Gateway command that is deliberately never dispatched here."""

    command: "GatewayDispatchCommand"
    case_id: CaseId
    input_manifest_digest: str
    dispatch_performed: Literal[False] = False
    provider_api_used: Literal[False] = False
    credentials_present: Literal[False] = False
    candidate_only: Literal[True] = True


@dataclass(frozen=True)
class CloudTrustVerifierReceipt:
    """A deterministic local verifier result, not a Gateway dispatch receipt."""

    receipt_id: str
    case_id: CaseId
    input_manifest_digest: str
    source_digest: str
    action_plan_digest: str
    classification: Literal["candidate_only", "matched_negative_control"]
    verified: Literal[False] = False
    gateway_dispatch_performed: Literal[False] = False
    provider_api_calls: Literal[0] = 0
    credentials_present: Literal[False] = False


@dataclass(frozen=True)
class CloudTrustFixtureEvaluation:
    run: CloudTrustRun
    action_plan: CloudTrustActionPlan
    verifier_receipt: CloudTrustVerifierReceipt


def observe_cloud_trust(
    source: CloudTrustObservationSource, case_id: CaseId
) -> CloudTrustRun:
    """Classify one read-only trust projection; no follow-up is dispatched here.

    A future follow-up must be separately compiled, scope-bound, and sent by
    the Target Gateway. This module has no token, credential, cloud SDK, or
    network client.
    """

    evidence = normalize_cloud_trust(case_id, source.read(case_id))
    if evidence.classification == "matched_negative_control":
        return CloudTrustRun(evidence, CloudTrustVerdict("negative_control"))
    return CloudTrustRun(evidence, CloudTrustVerdict("candidate_only"))


def normalize_cloud_trust(
    case_id: CaseId, snapshot: ReadOnlyCloudTrustSnapshot
) -> CloudTrustEvidence:
    """Normalize a static projection with no credential or token material."""

    projection = _parse_projection(snapshot.body)
    reasons: list[CandidateReason] = []
    if not projection.issuer_matches:
        reasons.append("issuer_binding_mismatch")
    if not projection.subject_matches:
        reasons.append("subject_binding_mismatch")
    if not projection.audience_matches:
        reasons.append("audience_binding_mismatch")
    if not projection.redirect_uri_matches:
        reasons.append("oauth_redirect_mismatch")
    if projection.privilege_path[-1] in {"role:tenant-admin", "role:project-admin"}:
        reasons.append("privilege_path_to_sensitive_role")
    candidate_reasons = tuple(reasons)
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    classification = (
        "diagnostic_candidate" if candidate_reasons else "matched_negative_control"
    )
    return CloudTrustEvidence(
        normalized_observation=NormalizedObservation(
            schema_version=SCHEMA_VERSION,
            adapter_id=_ADAPTER_ID,
            normalizer_id=_NORMALIZER_ID,
            observation_id=f"observation.cloud-iam-oauth.{case_id}",
            source_digest=_digest(snapshot.body),
        ),
        case_id=case_id,
        surface=projection.surface,
        issuer_matches=projection.issuer_matches,
        subject_matches=projection.subject_matches,
        audience_matches=projection.audience_matches,
        redirect_uri_matches=projection.redirect_uri_matches,
        privilege_path=projection.privilege_path,
        candidate_reasons=candidate_reasons,
        classification=classification,
    )


def load_cloud_trust_input_manifest(path: Path) -> CloudTrustInputManifest:
    """Load the signed G45 input manifest with no permissive schema fallback."""

    try:
        decoded = cast(object, json.loads(path.read_bytes()))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("cloud trust input manifest must be readable JSON") from error
    if not isinstance(decoded, dict) or set(decoded) != _MANIFEST_TOP_LEVEL_FIELDS:
        raise ValueError("cloud trust input manifest has an unsupported schema")
    document = cast(dict[str, object], decoded)
    payload = _required_object(document, "payload", _MANIFEST_PAYLOAD_FIELDS)
    signature = _required_object(document, "signature", _MANIFEST_SIGNATURE_FIELDS)
    if payload.get("schema_version") != _MANIFEST_SCHEMA_VERSION:
        raise ValueError("cloud trust input manifest schema version is unsupported")
    if payload.get("candidate_only") is not True or payload.get("provider_egress") is not False:
        raise ValueError("cloud trust input manifest must remain candidate-only and provider-free")
    authority = _required_object(payload, "authority", _MANIFEST_AUTHORITY_FIELDS)
    scope = _required_object(payload, "scope", _MANIFEST_SCOPE_FIELDS)
    budget = _required_object(payload, "budget", _MANIFEST_BUDGET_FIELDS)
    source_digests = _source_digests(payload.get("source_digests"))
    negatives = _case_id_tuple(payload.get("negative_control_case_ids"), "negative controls")
    if negatives != _NEGATIVE_CONTROL_CASE_IDS:
        raise ValueError("cloud trust input manifest must contain the matched negative controls")
    manifest = CloudTrustInputManifest(
        fixture_id=_required_identifier(payload, "fixture_id"),
        authority_grant_id=_required_identifier(authority, "grant_id"),
        authority_grant_version=_positive_int(authority, "grant_version"),
        authority_key_id=_required_key_id(authority, "key_id"),
        scope_epoch=_positive_int(scope, "scope_epoch"),
        target_id=_required_identifier(scope, "target_id"),
        hostname=_required_hostname(scope, "hostname"),
        path_prefix=_required_path_prefix(scope, "path_prefix"),
        identity_id=_required_identifier(scope, "identity_id"),
        tenant_id=_required_identifier(scope, "tenant_id"),
        action_count=_positive_int(budget, "action_count"),
        request_bytes=_positive_int(budget, "request_bytes"),
        response_bytes=_nonnegative_int(budget, "response_bytes"),
        duration_seconds=_positive_int(budget, "duration_seconds"),
        source_digests=source_digests,
        negative_control_case_ids=negatives,
        signature_public_key=_required_base64(signature, "public_key"),
        signature=_required_base64(signature, "signature"),
        signed_payload_digest=_required_digest(signature, "payload_digest"),
    )
    if signature.get("algorithm") != "Ed25519":
        raise ValueError("cloud trust input manifest must use Ed25519")
    if signature.get("key_id") != manifest.authority_key_id:
        raise ValueError("cloud trust input manifest signature key differs from authority")
    if manifest.action_count != 1:
        raise ValueError("cloud trust input manifest must reserve exactly one inert action")
    manifest.verify()
    return manifest


def evaluate_owned_cloud_trust_fixture(
    source: CloudTrustObservationSource,
    manifest: CloudTrustInputManifest,
    case_id: CaseId,
) -> CloudTrustFixtureEvaluation:
    """Evaluate one signed, owned projection and prepare no-dispatch Gateway work."""

    manifest.verify()
    snapshot = source.read(case_id)
    _require_owned_loopback_snapshot(snapshot, case_id)
    evidence = normalize_cloud_trust(case_id, snapshot)
    if evidence.normalized_observation.source_digest != manifest.source_digest(case_id):
        raise ValueError("cloud trust projection digest differs from the signed manifest")
    run = CloudTrustRun(
        evidence=evidence,
        verdict=(
            CloudTrustVerdict("negative_control")
            if evidence.classification == "matched_negative_control"
            else CloudTrustVerdict("candidate_only")
        ),
    )
    plan = build_read_only_cloud_trust_action_plan(manifest, run)
    return CloudTrustFixtureEvaluation(
        run=run,
        action_plan=plan,
        verifier_receipt=verify_owned_cloud_trust_fixture(manifest, run, plan),
    )


def build_read_only_cloud_trust_action_plan(
    manifest: CloudTrustInputManifest, run: CloudTrustRun
) -> CloudTrustActionPlan:
    """Compile one read-only semantic HTTP command without opening a connection."""

    manifest.verify()
    evidence = run.evidence
    if evidence.normalized_observation.source_digest != manifest.source_digest(evidence.case_id):
        raise ValueError("cloud trust action plan requires a digest-pinned observation")
    expected_negative = evidence.case_id in manifest.negative_control_case_ids
    if expected_negative != (evidence.classification == "matched_negative_control"):
        raise ValueError("cloud trust action plan classification does not match its control")
    from faultloom.execution import (
        EndpointScheme,
        ExecutionIdentity,
        GatewayDispatchCommand,
        SemanticEndpoint,
        SemanticHttpRequest,
        semantic_payload_digest,
    )

    issued_at = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    endpoint = SemanticEndpoint(
        schema_version=SCHEMA_VERSION,
        scheme=EndpointScheme.HTTP,
        hostname=manifest.hostname,
        port=80,
        path=f"{manifest.path_prefix}{evidence.case_id}",
    )
    request = SemanticHttpRequest(schema_version=SCHEMA_VERSION, endpoint=endpoint, method="GET")
    identity = ExecutionIdentity(
        schema_version=SCHEMA_VERSION,
        context_id="context.g45.synthetic",
        identity_id=manifest.identity_id,
        tenant_id=manifest.tenant_id,
    )
    action_id = f"action.g45.{evidence.case_id}"
    subject = protocol_models.SubjectRef(
        schema_version=SCHEMA_VERSION,
        subject_id="subject.g45.synthetic",
        subject_kind="synthetic_fixture",
        identity_id=manifest.identity_id,
        tenant_id=manifest.tenant_id,
    )
    resource = protocol_models.ResourceRef(
        schema_version=SCHEMA_VERSION,
        resource_id=f"resource.g45.{evidence.case_id}",
        resource_kind="owned_simulation",
        target_id=manifest.target_id,
        tenant_id=manifest.tenant_id,
    )
    intent = protocol_models.ActionIntent(
        schema_version=SCHEMA_VERSION,
        action_id=action_id,
        run_id="run.g45.owned-fixture",
        target_id=manifest.target_id,
        pack_id="pack.cloud.iam_oauth",
        action_kind="http.semantic",
        action_class=protocol_models.ActionClass.OBSERVE,
        subject=subject,
        resource=resource,
        protocol="http",
        method="GET",
        path=endpoint.path,
        payload_digest=semantic_payload_digest(request, identity),
        requested_at=issued_at,
    )
    decision = protocol_models.PolicyDecision(
        schema_version=SCHEMA_VERSION,
        decision_id=f"decision.g45.{evidence.case_id}",
        intent_digest=sha256_digest(intent),
        grant_id=manifest.authority_grant_id,
        grant_version=manifest.authority_grant_version,
        scope_epoch=manifest.scope_epoch,
        outcome=protocol_models.DecisionOutcome.ALLOW,
        reason_codes=("owned_fixture.read_only",),
        evaluated_at=issued_at,
        lease_id=f"lease.g45.{evidence.case_id}",
    )
    lease = protocol_models.ActionLease(
        schema_version=SCHEMA_VERSION,
        lease_id=f"lease.g45.{evidence.case_id}",
        lease_key_id="key-1",
        action_id=action_id,
        correlation_id=f"correlation.g45.{evidence.case_id}",
        intent_digest=sha256_digest(intent),
        decision_digest=sha256_digest(decision),
        grant_id=manifest.authority_grant_id,
        grant_version=manifest.authority_grant_version,
        scope_epoch=manifest.scope_epoch,
        authority_key_id=manifest.authority_key_id,
        scope_epoch_binding_digest=manifest.input_digest,
        gateway_boot_id="gateway-boot.g45.simulated",
        boot_challenge_digest=_digest(b"g45 simulated gateway boot"),
        target_id=manifest.target_id,
        identity_id=manifest.identity_id,
        tenant_id=manifest.tenant_id,
        action_kind="http.semantic",
        semantic_action_digest=cast(str, intent.payload_digest),
        request_binding_digest=_digest(
            f"g45 request binding {evidence.case_id}".encode("ascii")
        ),
        resolution_digest=_digest(f"g45 resolution {evidence.case_id}".encode("ascii")),
        egress_plane=protocol_models.EgressPlane.TARGET_GATEWAY,
        dispatch_nonce=hashlib.sha256(f"g45 nonce {evidence.case_id}".encode("ascii")).hexdigest()[:32],
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=manifest.duration_seconds),
        reservation=protocol_models.BudgetReservation(
            schema_version=SCHEMA_VERSION,
            action_count=manifest.action_count,
            request_bytes=manifest.request_bytes,
            response_bytes=manifest.response_bytes,
            duration_seconds=manifest.duration_seconds,
        ),
    )
    command = GatewayDispatchCommand(
        schema_version=SCHEMA_VERSION,
        intent=intent,
        decision=decision,
        lease=lease,
        request=request,
        identity=identity,
    )
    return CloudTrustActionPlan(
        command=command,
        case_id=evidence.case_id,
        input_manifest_digest=manifest.input_digest,
    )


def verify_owned_cloud_trust_fixture(
    manifest: CloudTrustInputManifest, run: CloudTrustRun, plan: CloudTrustActionPlan
) -> CloudTrustVerifierReceipt:
    """Emit a deterministic local receipt while refusing any verification claim."""

    manifest.verify()
    evidence = run.evidence
    if plan.case_id != evidence.case_id or plan.input_manifest_digest != manifest.input_digest:
        raise ValueError("cloud trust verifier received an unbound action plan")
    if plan.dispatch_performed or plan.provider_api_used or plan.credentials_present:
        raise ValueError("cloud trust verifier accepts only inert, credential-free plans")
    from faultloom.execution import GatewayDispatchCommand

    command = plan.command
    if type(command) is not GatewayDispatchCommand:
        raise ValueError("cloud trust verifier requires an exact Gateway command")
    if (
        command.intent.target_id != manifest.target_id
        or command.lease.scope_epoch != manifest.scope_epoch
        or command.lease.reservation.request_bytes != manifest.request_bytes
        or command.lease.reservation.response_bytes != manifest.response_bytes
        or command.lease.reservation.duration_seconds != manifest.duration_seconds
    ):
        raise ValueError("cloud trust verifier action authority, scope, or budget drifted")
    source_digest = evidence.normalized_observation.source_digest
    if source_digest != manifest.source_digest(evidence.case_id):
        raise ValueError("cloud trust verifier source digest is not pinned")
    action_plan_digest = sha256_digest(command.model_dump(mode="json"))
    receipt_id = f"receipt.g45.{evidence.case_id}.{action_plan_digest.removeprefix('sha256:')[:16]}"
    classification: Literal["candidate_only", "matched_negative_control"] = (
        "matched_negative_control"
        if evidence.classification == "matched_negative_control"
        else "candidate_only"
    )
    return CloudTrustVerifierReceipt(
        receipt_id=receipt_id,
        case_id=evidence.case_id,
        input_manifest_digest=manifest.input_digest,
        source_digest=source_digest,
        action_plan_digest=action_plan_digest,
        classification=classification,
    )


@dataclass(frozen=True)
class _TrustProjection:
    surface: TrustSurface
    issuer_matches: bool
    subject_matches: bool
    audience_matches: bool
    redirect_uri_matches: bool
    privilege_path: tuple[str, ...]


def _parse_projection(body: bytes) -> _TrustProjection:
    """Parse the deliberately small, credential-free fixture projection format."""

    try:
        decoded = cast(object, json.loads(body))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("cloud trust projection must be valid JSON") from error
    if not isinstance(decoded, dict):
        raise ValueError("cloud trust projection must be an object")
    value = cast(dict[str, object], decoded)
    unknown_fields = set(value).difference(_PROJECTION_FIELDS)
    if unknown_fields:
        raise ValueError("cloud trust projection contains unsupported fields")
    if value.get("token_material_present") is not False:
        raise ValueError("cloud trust projection must not contain token material")
    surface_value = value.get("surface")
    if surface_value not in {"iam", "oauth"}:
        raise ValueError("cloud trust projection has an unknown surface")
    surface = cast(TrustSurface, surface_value)
    booleans = (
        "issuer_matches",
        "subject_matches",
        "audience_matches",
        "redirect_uri_matches",
    )
    issuer_matches, subject_matches, audience_matches, redirect_uri_matches = (
        _required_bool(value, name) for name in booleans
    )
    path_value = value.get("privilege_path")
    if not isinstance(path_value, list):
        raise ValueError("cloud trust projection requires a non-empty privilege path")
    path = cast(list[object], path_value)
    if len(path) < 2 or any(not isinstance(item, str) or not item for item in path):
        raise ValueError("cloud trust projection requires a non-empty privilege path")
    privilege_path = tuple(cast(str, item) for item in path)
    return _TrustProjection(
        surface=surface,
        issuer_matches=issuer_matches,
        subject_matches=subject_matches,
        audience_matches=audience_matches,
        redirect_uri_matches=redirect_uri_matches,
        privilege_path=privilege_path,
    )


def _required_bool(value: dict[str, object], name: str) -> bool:
    flag = value.get(name)
    if type(flag) is not bool:
        raise ValueError("cloud trust projection requires explicit boolean controls")
    return flag


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _required_object(
    value: dict[str, object], field: str, expected_fields: frozenset[str]
) -> dict[str, object]:
    nested = value.get(field)
    if not isinstance(nested, dict) or set(nested) != expected_fields:
        raise ValueError(f"cloud trust input manifest {field} has an unsupported schema")
    return cast(dict[str, object], nested)


def _source_digests(value: object) -> tuple[tuple[CaseId, str], ...]:
    if not isinstance(value, dict) or set(value) != set(_CASE_IDS):
        raise ValueError("cloud trust input manifest must pin every fixture source digest")
    digests: list[tuple[CaseId, str]] = []
    for case_id in _CASE_IDS:
        digest = value.get(case_id)
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise ValueError("cloud trust input manifest contains an invalid source digest")
        digests.append((case_id, digest))
    return tuple(digests)


def _case_id_tuple(value: object, label: str) -> tuple[CaseId, ...]:
    if not isinstance(value, list) or any(item not in _CASE_IDS for item in value):
        raise ValueError(f"cloud trust input manifest {label} are invalid")
    case_ids = cast(tuple[CaseId, ...], tuple(value))
    if len(case_ids) != len(set(case_ids)):
        raise ValueError(f"cloud trust input manifest {label} must be unique")
    return case_ids


def _required_identifier(value: dict[str, object], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or not item or len(item) > 256:
        raise ValueError(f"cloud trust input manifest {field} must be a non-empty identifier")
    return item


def _required_key_id(value: dict[str, object], field: str) -> str:
    item = _required_identifier(value, field)
    if _DIGEST.fullmatch(item.removeprefix("ed25519:")) is None:
        raise ValueError("cloud trust input manifest authority key ID is invalid")
    return item


def _positive_int(value: dict[str, object], field: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 1:
        raise ValueError(f"cloud trust input manifest {field} must be a positive integer")
    return item


def _nonnegative_int(value: dict[str, object], field: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 0:
        raise ValueError(f"cloud trust input manifest {field} must be a non-negative integer")
    return item


def _required_hostname(value: dict[str, object], field: str) -> str:
    item = _required_identifier(value, field)
    if item != item.lower() or any(character in item for character in "/:@"):
        raise ValueError("cloud trust input manifest hostname is invalid")
    return item


def _required_path_prefix(value: dict[str, object], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or not item.startswith("/") or not item.endswith("/"):
        raise ValueError("cloud trust input manifest path prefix is invalid")
    if any(character in item for character in "?#\r\n\x00"):
        raise ValueError("cloud trust input manifest path prefix is invalid")
    return item


def _required_digest(value: dict[str, object], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or _DIGEST.fullmatch(item) is None:
        raise ValueError(f"cloud trust input manifest {field} must be a lowercase sha256 digest")
    return item


def _required_base64(value: dict[str, object], field: str) -> str:
    item = value.get(field)
    if type(item) is not str:
        raise ValueError(f"cloud trust input manifest {field} must be canonical base64url")
    _ = _decode_base64url(item, field)
    return item


def _decode_base64url(value: str, label: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise ValueError(f"cloud trust input manifest {label} is not base64url") from error
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if encoded != value:
        raise ValueError(f"cloud trust input manifest {label} is not canonical base64url")
    return decoded


def _require_owned_loopback_snapshot(
    snapshot: ReadOnlyCloudTrustSnapshot, case_id: CaseId
) -> None:
    parsed = urlparse(snapshot.url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.path != f"/{case_id}"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("owned cloud trust evaluation accepts only its exact loopback route")
