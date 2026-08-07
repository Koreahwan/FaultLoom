"""Narrow authenticated operator-canary observation contracts.

This module deliberately supports one carrier, one method, and one semantic
observation.  It is not a general authenticated HTTP client or vulnerability oracle.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Literal, cast

from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from faultloom_protocol import (
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    SecretRef,
    canonical_json,
    load_public_key,
)


CANARY_CASE_SCHEMA = "faultloom.authenticated-operator-canary.case.v1"
CANARY_RUN_SCHEMA = "faultloom.authenticated-operator-canary.run.v1"
CANARY_HANDOFF_SCHEMA = "faultloom.authenticated-operator-canary.handoff.v1"
CANARY_RESULT_SCHEMA = "faultloom.authenticated-operator-canary.result.v1"
CANARY_SEMANTIC_OUTCOME = "operator_canary_cross_identity_read_reproduced"
_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SECRET_URI = re.compile(r"^secret://target-env/([A-Z][A-Z0-9_]{2,127})$")
_BEARER = re.compile(r"^[A-Za-z0-9._~+/=-]{16,512}$")
_CANARY_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{1,2047}$")


class AuthenticatedCanaryError(ValueError):
    """Fail-closed contract or observation error."""


class _StrictFrozenModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class CanaryCase(_StrictFrozenModel):
    schema_: Literal["faultloom.authenticated-operator-canary.case.v1"] = Field(alias="schema")
    campaign_id: str = Field(pattern=_SAFE_ID)
    phase: Literal["source", "reviewer"]
    source_handoff_sha256: str | None = Field(default=None, pattern=_SHA256)
    source_claim: str = Field(min_length=1, max_length=2048)
    source_claim_status: Literal["operator_asserted_unverified"] = "operator_asserted_unverified"
    owner_relation_status: Literal["operator_asserted_owned"] = "operator_asserted_owned"
    sensitivity_status: Literal["operator_reviewed_non_sensitive"] = (
        "operator_reviewed_non_sensitive"
    )
    target_id: str = Field(min_length=1, max_length=256)
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"]
    owner_identity: str = Field(min_length=1, max_length=256)
    requester_identity: str = Field(min_length=1, max_length=256)
    canary_path: str = Field(min_length=1, max_length=2048)
    missing_control_path: str = Field(min_length=1, max_length=2048)
    canary_sha256: str = Field(pattern=_SHA256)
    requester_session_ref: SecretRef
    requester_session_expires_at: str = Field(
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$"
    )
    response_bytes: int = Field(ge=1, le=1_048_576)
    timeout_seconds: int = Field(ge=1, le=30)
    run_id: str = Field(min_length=1, max_length=256)
    grant_id: str = Field(min_length=1, max_length=256)
    grant_version: int = Field(ge=1)
    grant_sha256: str = Field(pattern=_SHA256)
    operator_actor_id: str = Field(min_length=1, max_length=256)
    signed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$")

    @model_validator(mode="after")
    def _narrow_contract(self) -> "CanaryCase":
        if self.owner_identity == self.requester_identity:
            raise ValueError("owner and requester identities must differ")
        if self.operator_actor_id in {self.owner_identity, self.requester_identity}:
            raise ValueError("operator actor must differ from both target identities")
        if self.canary_path == self.missing_control_path:
            raise ValueError("canary and missing-control paths must differ")
        if any(
            _CANARY_PATH.fullmatch(value) is None
            for value in (self.canary_path, self.missing_control_path)
        ):
            raise ValueError("canary paths must be conservative ASCII path-only targets")
        if self.hostname != self.hostname.lower() or not self.hostname.isascii():
            raise ValueError("hostname must be lowercase ASCII")
        if self.requester_session_ref.purpose != "target-bearer-session":
            raise ValueError("requester session SecretRef has the wrong purpose")
        if _SECRET_URI.fullmatch(self.requester_session_ref.uri) is None:
            raise ValueError("requester session must use secret://target-env/NAME")
        if self.phase == "source" and self.source_handoff_sha256 is not None:
            raise ValueError("source case cannot bind a source handoff")
        if self.phase == "reviewer" and self.source_handoff_sha256 is None:
            raise ValueError("reviewer case must bind a source handoff")
        return self


class SignedCanaryCase(_StrictFrozenModel):
    case: CanaryCase
    signer_key_id: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=86, max_length=86)


class CanaryObservation(_StrictFrozenModel):
    role: Literal["effect", "reproduction", "missing_control"]
    path: str
    reservation_id: str
    redacted_request_sha256: str = Field(pattern=_SHA256)
    response_sha256: str = Field(pattern=_SHA256)
    response_bytes: int = Field(ge=1)
    status_code: int = Field(ge=200, le=299)
    canary_value_sha256: str = Field(pattern=_SHA256)
    expected_canary: bool
    response_file: str = Field(pattern=r"^responses/[A-Za-z0-9._-]+\.raw$")


class CanaryRunResult(_StrictFrozenModel):
    schema_: Literal["faultloom.authenticated-operator-canary.run.v1"] = Field(alias="schema")
    campaign_id: str = Field(pattern=_SAFE_ID)
    phase: Literal["source", "reviewer"]
    case_sha256: str = Field(pattern=_SHA256)
    status: Literal["observation_recorded", "unresolved_not_evaluated"]
    dispatch_count: int = Field(ge=0, le=3)
    observations: tuple[CanaryObservation, ...] = ()
    semantic_verdict: Literal["not_evaluated"] = "not_evaluated"
    taxonomy_verdict: Literal["not_evaluated"] = "not_evaluated"
    automatic_submission: Literal[False] = False

    @field_validator("observations", mode="before")
    @classmethod
    def _tuple_observations(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def _complete_observation(self) -> "CanaryRunResult":
        expected_roles = ("effect", "reproduction", "missing_control")
        if self.status == "observation_recorded":
            if self.dispatch_count != 3 or tuple(item.role for item in self.observations) != expected_roles:
                raise ValueError("completed canary run requires the exact three observations")
        elif len(self.observations) > self.dispatch_count:
            raise ValueError("unresolved canary observations exceed dispatch count")
        return self


class SignedCanaryRun(_StrictFrozenModel):
    run: CanaryRunResult
    signer_key_id: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=86, max_length=86)


class CanaryHandoff(_StrictFrozenModel):
    schema_: Literal["faultloom.authenticated-operator-canary.handoff.v1"] = Field(alias="schema")
    source_workspace_sha256: str = Field(pattern=_SHA256)
    source_case: SignedCanaryCase
    source_case_sha256: str = Field(pattern=_SHA256)
    source_run: SignedCanaryRun
    source_run_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str
    signature: str = Field(min_length=86, max_length=86)


class CanarySemanticResult(_StrictFrozenModel):
    schema_: Literal["faultloom.authenticated-operator-canary.result.v1"] = Field(alias="schema")
    campaign_id: str = Field(pattern=_SAFE_ID)
    status: Literal["operator_canary_cross_identity_read_reproduced"]
    source_claim_status: Literal["operator_asserted_unverified"]
    owner_relation_status: Literal["operator_asserted_owned"]
    sensitivity_status: Literal["operator_reviewed_non_sensitive"]
    observed_fact: Literal["operator_canary_cross_identity_read_reproduced"]
    semantic_verdict: Literal["operator_canary_cross_identity_read_reproduced"]
    taxonomy_verdict: Literal["not_evaluated"] = "not_evaluated"
    report_status: Literal["draft_manual_review"] = "draft_manual_review"
    source_case_sha256: str = Field(pattern=_SHA256)
    source_run_sha256: str = Field(pattern=_SHA256)
    reviewer_case_sha256: str = Field(pattern=_SHA256)
    reviewer_run_sha256: str = Field(pattern=_SHA256)
    automatic_submission: Literal[False] = False


@dataclass(frozen=True, slots=True)
class ParsedCanaryResponse:
    response_sha256: str
    size: int
    status_code: int
    canary_value_sha256: str
    expected_canary: bool


def _json_load(content: bytes, *, label: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise AuthenticatedCanaryError(f"{label} contains duplicate JSON key {key!r}")
            output[key] = value
        return output

    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, AuthenticatedCanaryError) as exc:
        raise AuthenticatedCanaryError(f"invalid {label}") from exc


def _canonical_bytes(value: BaseModel) -> bytes:
    return canonical_json(value.model_dump(mode="json", by_alias=True)).encode("utf-8")


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sign_canary_case(case: CanaryCase, signer: AuthoritySigner) -> SignedCanaryCase:
    return SignedCanaryCase(
        case=case,
        signer_key_id=signer.key_id,
        signature=signer.sign(_canonical_bytes(case)),
    )


def parse_signed_canary_case(content: bytes) -> SignedCanaryCase:
    try:
        return SignedCanaryCase.model_validate(_json_load(content, label="signed canary case"))
    except ValidationError as exc:
        raise AuthenticatedCanaryError("invalid signed canary case") from exc


def verify_signed_canary_case(
    signed: SignedCanaryCase, trusted_key: Ed25519PublicKeyRecord
) -> CanaryCase:
    if signed.signer_key_id != trusted_key.key_id:
        raise AuthenticatedCanaryError("canary case signer differs from trusted authority")
    try:
        signature = base64.urlsafe_b64decode(signed.signature + "==")
        if base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != signed.signature:
            raise ValueError("non-canonical signature")
        load_public_key(trusted_key).verify(signature, _canonical_bytes(signed.case))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise AuthenticatedCanaryError("canary case signature is invalid") from exc
    return signed.case


def signed_case_bytes(signed: SignedCanaryCase) -> bytes:
    return (_canonical_bytes(signed) + b"\n")


def resolve_target_bearer(secret_ref: SecretRef, environment: Mapping[str, str]) -> str:
    """Resolve only the target bearer namespace; never consult provider settings."""
    match = _SECRET_URI.fullmatch(secret_ref.uri)
    if match is None or secret_ref.purpose != "target-bearer-session":
        raise AuthenticatedCanaryError("target bearer SecretRef binding is invalid")
    value = environment.get(match.group(1))
    if value is None or _BEARER.fullmatch(value) is None:
        raise AuthenticatedCanaryError("target bearer secret is missing or invalid")
    return value


def require_active_target_session(case: CanaryCase, *, now: datetime) -> None:
    try:
        expires_at = datetime.fromisoformat(
            case.requester_session_expires_at.removesuffix("Z") + "+00:00"
        )
    except ValueError as exc:
        raise AuthenticatedCanaryError("target bearer session expiry is invalid") from exc
    if now.tzinfo is None or now.astimezone(UTC) >= expires_at:
        raise AuthenticatedCanaryError("target bearer session is expired")


def build_authenticated_get(case: CanaryCase, *, path: str, bearer: str) -> bytes:
    default_port = (case.scheme == "https" and case.port == 443) or (
        case.scheme == "http" and case.port == 80
    )
    host = case.hostname if default_port else f"{case.hostname}:{case.port}"
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Authorization: Bearer {bearer}\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def redacted_request_sha256(case: CanaryCase, *, role: str, path: str) -> str:
    """Hash only signed semantics and the opaque SecretRef, never bearer-derived bytes."""
    return sha256_hex(
        canonical_json(
            {
                "method": "GET",
                "path": path,
                "phase": case.phase,
                "requester_identity": case.requester_identity,
                "requester_session_ref": case.requester_session_ref.model_dump(mode="json"),
                "role": role,
                "target": {
                    "hostname": case.hostname,
                    "port": case.port,
                    "scheme": case.scheme,
                    "target_id": case.target_id,
                },
            }
        ).encode("utf-8")
    )


def parse_canary_http_response(
    content: bytes, *, response_limit: int, expected_canary_sha256: str
) -> ParsedCanaryResponse:
    if not content or len(content) > response_limit or b"\r\n\r\n" not in content:
        raise AuthenticatedCanaryError("canary response is missing, oversized, or malformed")
    headers, body = content.split(b"\r\n\r\n", 1)
    lines = headers.split(b"\r\n")
    if lines[0] != b"HTTP/1.1 200 OK":
        raise AuthenticatedCanaryError("canary response requires exact HTTP/1.1 200 OK")
    status_code = 200
    parsed: dict[str, str] = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            raise AuthenticatedCanaryError("canary response headers are malformed")
        name, value = line.split(b":", 1)
        try:
            key = name.decode("ascii").lower()
            text = value.strip().decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise AuthenticatedCanaryError("canary response headers are malformed") from exc
        if key in parsed:
            raise AuthenticatedCanaryError("canary response has duplicate headers")
        parsed[key] = text
    if (
        set(parsed) != {"content-type", "content-length", "connection"}
        or parsed.get("content-type") != "application/json"
        or parsed.get("connection") != "close"
        or "content-length" not in parsed
        or not parsed["content-length"].isdigit()
        or int(parsed["content-length"]) != len(body)
    ):
        raise AuthenticatedCanaryError("canary response is not bounded uncompressed JSON")
    value = _json_load(body, label="canary response body")
    if type(value) is not dict or set(value) != {"faultloom_canary"}:
        raise AuthenticatedCanaryError("canary response body has an invalid shape")
    canary = cast(dict[str, object], value)["faultloom_canary"]
    if type(canary) is not str:
        raise AuthenticatedCanaryError("canary response value is not a string")
    digest = sha256_hex(canary.encode("utf-8"))
    return ParsedCanaryResponse(
        response_sha256=sha256_hex(content),
        size=len(content),
        status_code=status_code,
        canary_value_sha256=digest,
        expected_canary=digest == expected_canary_sha256,
    )


def sign_canary_run(run: CanaryRunResult, signer: AuthoritySigner) -> SignedCanaryRun:
    return SignedCanaryRun(
        run=run,
        signer_key_id=signer.key_id,
        signature=signer.sign(_canonical_bytes(run)),
    )


def parse_canary_run(content: bytes) -> SignedCanaryRun:
    try:
        return SignedCanaryRun.model_validate(_json_load(content, label="signed canary run result"))
    except ValidationError as exc:
        raise AuthenticatedCanaryError("invalid canary run result") from exc


def verify_signed_canary_run(
    signed: SignedCanaryRun, trusted_key: Ed25519PublicKeyRecord
) -> CanaryRunResult:
    if signed.signer_key_id != trusted_key.key_id:
        raise AuthenticatedCanaryError("canary run signer differs from trusted authority")
    try:
        signature = base64.urlsafe_b64decode(signed.signature + "==")
        if base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != signed.signature:
            raise ValueError("non-canonical signature")
        load_public_key(trusted_key).verify(signature, _canonical_bytes(signed.run))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise AuthenticatedCanaryError("canary run signature is invalid") from exc
    return signed.run


def _handoff_payload(handoff: CanaryHandoff) -> bytes:
    value = handoff.model_dump(mode="json", by_alias=True, exclude={"signature"})
    return canonical_json(value).encode("utf-8")


def build_canary_handoff(
    *, source_workspace_sha256: str, source_case: SignedCanaryCase,
    source_case_sha256: str, source_run: SignedCanaryRun, source_run_sha256: str,
    signer: AuthoritySigner,
) -> CanaryHandoff:
    unsigned = CanaryHandoff(
        schema=CANARY_HANDOFF_SCHEMA,
        source_workspace_sha256=source_workspace_sha256,
        source_case=source_case,
        source_case_sha256=source_case_sha256,
        source_run=source_run,
        source_run_sha256=source_run_sha256,
        signer_key_id=signer.key_id,
        signature="A" * 86,
    )
    return unsigned.model_copy(update={"signature": signer.sign(_handoff_payload(unsigned))})


def parse_canary_handoff(content: bytes) -> CanaryHandoff:
    try:
        return CanaryHandoff.model_validate(_json_load(content, label="canary handoff"))
    except ValidationError as exc:
        raise AuthenticatedCanaryError("invalid canary handoff") from exc


def verify_canary_handoff(
    handoff: CanaryHandoff, trusted_key: Ed25519PublicKeyRecord
) -> CanaryHandoff:
    if handoff.signer_key_id != trusted_key.key_id:
        raise AuthenticatedCanaryError("canary handoff signer differs from source authority")
    try:
        signature = base64.urlsafe_b64decode(handoff.signature + "==")
        load_public_key(trusted_key).verify(signature, _handoff_payload(handoff))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise AuthenticatedCanaryError("canary handoff signature is invalid") from exc
    if (
        handoff.source_case_sha256 != sha256_hex(signed_case_bytes(handoff.source_case))
        or handoff.source_run_sha256 != sha256_hex(
            (_canonical_bytes(handoff.source_run) + b"\n")
        )
        or handoff.source_run.run.case_sha256 != handoff.source_case_sha256
        or handoff.source_case.case.phase != "source"
        or handoff.source_run.run.phase != "source"
    ):
        raise AuthenticatedCanaryError("canary handoff binding is invalid")
    _ = verify_signed_canary_case(handoff.source_case, trusted_key)
    _ = verify_signed_canary_run(handoff.source_run, trusted_key)
    return handoff


def semantic_result(
    *, handoff: CanaryHandoff, reviewer_case: SignedCanaryCase,
    reviewer_case_sha256: str, reviewer_run: CanaryRunResult, reviewer_run_sha256: str,
) -> CanarySemanticResult:
    source_case = handoff.source_case.case
    review_case = reviewer_case.case
    if (
        handoff.source_run.run.status != "observation_recorded"
        or reviewer_run.status != "observation_recorded"
        or review_case.phase != "reviewer"
        or reviewer_run.phase != "reviewer"
        or review_case.source_handoff_sha256 is None
        or reviewer_run.case_sha256 != reviewer_case_sha256
        or review_case.requester_session_ref.uri == source_case.requester_session_ref.uri
        or review_case.operator_actor_id == source_case.operator_actor_id
        or review_case.grant_sha256 == source_case.grant_sha256
        or any(
            getattr(review_case, field) != getattr(source_case, field)
            for field in (
                "campaign_id", "source_claim", "target_id", "hostname", "port", "scheme",
                "owner_identity", "requester_identity", "canary_path", "missing_control_path",
                "canary_sha256", "response_bytes",
            )
        )
    ):
        raise AuthenticatedCanaryError("source and reviewer canary bindings are not independent and equal")
    for run in (handoff.source_run.run, reviewer_run):
        observations = run.observations
        if (
            len(observations) != 3
            or not observations[0].expected_canary
            or not observations[1].expected_canary
            or observations[2].expected_canary
            or observations[0].canary_value_sha256 != source_case.canary_sha256
            or observations[1].canary_value_sha256 != source_case.canary_sha256
        ):
            raise AuthenticatedCanaryError("canary/control relation was not reproduced")
    return CanarySemanticResult(
        schema=CANARY_RESULT_SCHEMA,
        campaign_id=source_case.campaign_id,
        status=CANARY_SEMANTIC_OUTCOME,
        source_claim_status="operator_asserted_unverified",
        owner_relation_status="operator_asserted_owned",
        sensitivity_status="operator_reviewed_non_sensitive",
        observed_fact=CANARY_SEMANTIC_OUTCOME,
        semantic_verdict=CANARY_SEMANTIC_OUTCOME,
        source_case_sha256=handoff.source_case_sha256,
        source_run_sha256=handoff.source_run_sha256,
        reviewer_case_sha256=reviewer_case_sha256,
        reviewer_run_sha256=reviewer_run_sha256,
    )


def canonical_model_bytes(value: BaseModel) -> bytes:
    return _canonical_bytes(value) + b"\n"
