"""Normalize supplied mobile deep-link/API binding evidence without dispatching it."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, Protocol, cast
from urllib.parse import urlparse

from faultloom_protocol import SCHEMA_VERSION
from faultloom_sdk import NormalizedObservation

_ADAPTER_ID = "adapter.mobile.loopback"
_NORMALIZER_ID = "mobile.api_binding.normalizer"
CaseId = Literal["mismatch", "negative"]
EvidenceKind = Literal["app-link", "api-binding"]


class ReadOnlyMobileBindingResponse(Protocol):
    """A fixed observation returned by a read-only source."""

    @property
    def url(self) -> str: ...

    @property
    def body(self) -> bytes: ...


class MobileApiBindingObservationSource(Protocol):
    def read(
        self, case_id: CaseId, evidence: EvidenceKind
    ) -> ReadOnlyMobileBindingResponse: ...


@dataclass(frozen=True)
class MobileApiBindingEvidence:
    normalized_observation: NormalizedObservation
    case_id: CaseId
    app_link_scheme: str
    app_link_application_id: str
    api_binding_id: str
    app_link_uri: str
    api_bound_link_uri: str
    declared_api_audience: str
    observed_api_audience: str
    audience_matches: bool
    link_matches: bool
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    candidate_only: Literal[True] = True


@dataclass(frozen=True)
class MobileApiBindingVerdict:
    classification: Literal["candidate_only", "negative_control"]
    verified: Literal[False] = False
    gateway_required: Literal[True] = True


@dataclass(frozen=True)
class MobileApiBindingRun:
    evidence: MobileApiBindingEvidence
    verdict: MobileApiBindingVerdict


def observe_mobile_api_binding(
    source: MobileApiBindingObservationSource, case_id: CaseId
) -> MobileApiBindingRun:
    """Compare two supplied observations without using a device or an API client.

    This records a mismatch only as a candidate.  Any future follow-up must be
    separately authorized, compiled, and dispatched by the Gateway.
    """

    app_link = source.read(case_id, "app-link")
    api_binding = source.read(case_id, "api-binding")
    evidence = normalize_mobile_api_binding(case_id, app_link, api_binding)
    if evidence.classification == "matched_negative_control":
        return MobileApiBindingRun(evidence, MobileApiBindingVerdict("negative_control"))
    return MobileApiBindingRun(evidence, MobileApiBindingVerdict("candidate_only"))


def normalize_mobile_api_binding(
    case_id: CaseId,
    app_link: ReadOnlyMobileBindingResponse,
    api_binding: ReadOnlyMobileBindingResponse,
) -> MobileApiBindingEvidence:
    """Normalize a declared app-link audience and an observed API binding."""

    app_link_payload = _object_payload(app_link.body, "app-link")
    binding_payload = _object_payload(api_binding.body, "api-binding")
    deep_link = _required_string(app_link_payload, "deep_link", "app-link")
    parsed_link = urlparse(deep_link)
    if not parsed_link.scheme or not parsed_link.netloc:
        raise ValueError("app-link deep_link must be an absolute URI")
    application_id = _required_string(app_link_payload, "application_id", "app-link")
    declared_audience = _required_string(app_link_payload, "api_audience", "app-link")
    api_binding_id = _required_string(binding_payload, "api_id", "api-binding")
    bound_link = _required_string(binding_payload, "bound_deep_link", "api-binding")
    parsed_bound_link = urlparse(bound_link)
    if not parsed_bound_link.scheme or not parsed_bound_link.netloc:
        raise ValueError("api-binding bound_deep_link must be an absolute URI")
    observed_audience = _required_string(binding_payload, "api_audience", "api-binding")
    audience_matches = declared_audience == observed_audience
    link_matches = deep_link == bound_link
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    classification = (
        "matched_negative_control"
        if audience_matches and link_matches
        else "diagnostic_candidate"
    )
    return MobileApiBindingEvidence(
        normalized_observation=NormalizedObservation(
            schema_version=SCHEMA_VERSION,
            adapter_id=_ADAPTER_ID,
            normalizer_id=_NORMALIZER_ID,
            observation_id=f"observation.mobile-api-binding.{case_id}",
            source_digest=_digest(app_link.body + b"\0" + api_binding.body),
        ),
        case_id=case_id,
        app_link_scheme=parsed_link.scheme,
        app_link_application_id=application_id,
        api_binding_id=api_binding_id,
        app_link_uri=deep_link,
        api_bound_link_uri=bound_link,
        declared_api_audience=declared_audience,
        observed_api_audience=observed_audience,
        audience_matches=audience_matches,
        link_matches=link_matches,
        classification=classification,
    )


def _object_payload(body: bytes, evidence: str) -> dict[str, object]:
    try:
        payload = cast(object, json.loads(body))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{evidence} payload must be JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{evidence} payload must be a JSON object")
    return cast(dict[str, object], payload)


def _required_string(payload: dict[str, object], field: str, evidence: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{evidence} payload requires non-empty {field}")
    return value


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"
