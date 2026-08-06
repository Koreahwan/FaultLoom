"""Strict, offline data contracts for the personal HTTP/1 triad campaign."""

from __future__ import annotations

import hashlib
import json
import re
from typing import ClassVar, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

PERSONAL_HTTP1_TRIAD_SCHEMA = "faultloom.personal-http1-triad.v1"
PERSONAL_HTTP1_TRIAD_BOUND_SCHEMA = "faultloom.personal-http1-triad.v2"
PERSONAL_HTTP1_TRIAD_AUTOMATION_BINDING_SCHEMA = (
    "faultloom.personal-http1-triad.automation-binding.v1"
)
EXACT_BODY_DIGEST_CLASSIFIER = "exact_body_digest_v1"
_SAFE_CAMPAIGN_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SAFE_FILE_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SHA256 = r"^[0-9a-f]{64}$"


class PersonalCampaignError(ValueError):
    """Raised when a campaign document cannot be used safely."""


class _StrictFrozenModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class TriadRequest(_StrictFrozenModel):
    role: Literal["effect", "negative_control"]
    method: Literal["GET", "HEAD", "OPTIONS"]
    path: str = Field(min_length=1, max_length=2048)
    request_file: str = Field(pattern=_SAFE_FILE_NAME)
    response_bytes: int = Field(ge=0, le=1_048_576)

    @model_validator(mode="after")
    def _safe_path_and_file(self) -> "TriadRequest":
        if not self.path.startswith("/") or "\r" in self.path or "\n" in self.path:
            raise ValueError("path must be an absolute single-line HTTP request target")
        if self.request_file in {".", ".."} or "/" in self.request_file or "\\" in self.request_file:
            raise ValueError("request_file must be a basename")
        return self


class FindingMetadata(_StrictFrozenModel):
    title: str = Field(min_length=1, max_length=256)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    summary: str = Field(min_length=1, max_length=4096)
    impact: str = Field(min_length=1, max_length=4096)
    remediation: str = Field(min_length=1, max_length=4096)


class AutomationBinding(_StrictFrozenModel):
    """Offline provenance tying a v2 triad to one compiled automation item."""

    schema_: Literal["faultloom.personal-http1-triad.automation-binding.v1"] = Field(
        alias="schema"
    )
    result_path: str = Field(min_length=1)
    result_file_sha256: str = Field(pattern=_SHA256)
    result_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    receipt_path: str = Field(min_length=1)
    receipt_file_sha256: str = Field(pattern=_SHA256)
    template_path: str = Field(min_length=1)
    template_sha256: str = Field(pattern=_SHA256)
    candidate_id: str = Field(min_length=1, max_length=256)
    candidate_source: Literal["admitted_plan", "compiled_safe_poc_step"] = (
        "admitted_plan"
    )
    candidate_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effect_request_path: str = Field(min_length=1)
    effect_request_sha256: str = Field(pattern=_SHA256)
    negative_control_request_path: str = Field(min_length=1)
    negative_control_request_sha256: str = Field(pattern=_SHA256)
    run_id: str = Field(min_length=1, max_length=256)
    grant_id: str = Field(min_length=1, max_length=256)
    grant_version: int = Field(ge=1)
    grant_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class PersonalHttp1TriadSpec(_StrictFrozenModel):
    schema_: Literal[
        "faultloom.personal-http1-triad.v1", "faultloom.personal-http1-triad.v2"
    ] = Field(alias="schema")
    campaign_id: str = Field(pattern=_SAFE_CAMPAIGN_ID)
    authorization_reference: str = Field(min_length=1, max_length=512)
    authorization_document_sha256: str = Field(pattern=_SHA256)
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"]
    timeout_seconds: int = Field(ge=1, le=30)
    requests: tuple[TriadRequest, TriadRequest]
    finding: FindingMetadata
    automation_binding: AutomationBinding | None = None

    @field_validator("requests", mode="before")
    @classmethod
    def _json_array_to_tuple(cls, value: object) -> object:
        if type(value) is list:
            return tuple(cast(list[object], value))
        return value

    @model_validator(mode="after")
    def _valid_triad(self) -> "PersonalHttp1TriadSpec":
        if self.hostname != self.hostname.lower() or not self.hostname.isascii():
            raise ValueError("hostname must be lowercase ASCII")
        roles = {request.role for request in self.requests}
        if roles != {"effect", "negative_control"}:
            raise ValueError("requests must contain exactly effect and negative_control")
        effect, control = self.effect, self.negative_control
        if effect.method != control.method:
            raise ValueError("effect and negative_control must use the same method")
        if effect.response_bytes != control.response_bytes:
            raise ValueError("effect and negative_control must use the same response_bytes cap")
        if effect.path == control.path:
            raise ValueError("effect and negative_control paths must differ")
        if effect.request_file == control.request_file:
            raise ValueError("effect and negative_control request files must differ")
        if self.schema_ == PERSONAL_HTTP1_TRIAD_BOUND_SCHEMA and self.automation_binding is None:
            raise ValueError("v2 triad specs require an automation_binding")
        if self.schema_ == PERSONAL_HTTP1_TRIAD_SCHEMA and self.automation_binding is not None:
            raise ValueError("v1 triad specs cannot contain an automation_binding")
        return self

    @property
    def effect(self) -> TriadRequest:
        return next(request for request in self.requests if request.role == "effect")

    @property
    def negative_control(self) -> TriadRequest:
        return next(request for request in self.requests if request.role == "negative_control")


class TriadDigestOutcome(_StrictFrozenModel):
    classifier: Literal["exact_body_digest_v1"]
    status: Literal["draft_unverified", "negative_campaign"]


def parse_personal_http1_triad_spec(content: bytes) -> PersonalHttp1TriadSpec:
    """Decode one duplicate-key-free campaign JSON document without filesystem I/O."""

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PersonalCampaignError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = cast(object, json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicate_keys))
        return PersonalHttp1TriadSpec.model_validate(value)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, PersonalCampaignError) as exc:
        raise PersonalCampaignError(f"invalid personal HTTP/1 triad spec: {exc}") from exc


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def validate_campaign_id(value: str) -> str:
    if not re.fullmatch(_SAFE_CAMPAIGN_ID, value):
        raise PersonalCampaignError("campaign_id is not a safe identifier")
    return value


def classify_exact_body_digest_triad(
    *, effect_body_sha256: str, reproduction_body_sha256: str, negative_control_body_sha256: str
) -> TriadDigestOutcome:
    """Classify only exact body digest equality; it never validates a vulnerability."""

    digest_pattern = re.compile(_SHA256)
    if not all(
        digest_pattern.fullmatch(value)
        for value in (effect_body_sha256, reproduction_body_sha256, negative_control_body_sha256)
    ):
        raise PersonalCampaignError("body digest is not a lowercase SHA-256 hex value")
    status: Literal["draft_unverified", "negative_campaign"] = (
        "draft_unverified"
        if effect_body_sha256 == reproduction_body_sha256
        and effect_body_sha256 != negative_control_body_sha256
        else "negative_campaign"
    )
    return TriadDigestOutcome(classifier=EXACT_BODY_DIGEST_CLASSIFIER, status=status)
