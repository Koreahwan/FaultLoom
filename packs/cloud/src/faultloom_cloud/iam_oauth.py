"""Normalize supplied Cloud/IAM/OAuth projections without credential operations."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from faultloom_protocol import SCHEMA_VERSION
from faultloom_sdk import NormalizedObservation

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


class ReadOnlyCloudTrustSnapshot(Protocol):
    """A supplied projection, never a cloud SDK, token, or credential handle."""

    url: str
    body: bytes


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

    import json

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
