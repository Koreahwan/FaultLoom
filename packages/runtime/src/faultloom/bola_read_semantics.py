"""Signed evidence contract for one read-only BOLA/IDOR observation class.

This is intentionally an offline semantic check.  Dispatch, accounting, and
private evidence storage remain outside this module; callers provide only the
already-captured raw HTTP responses needed to verify the signed observations.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
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
    IdentityContext,
    ResourceRef,
    SubjectRef,
    canonical_json,
    load_public_key,
)


BOLA_READ_CASE_SCHEMA = "faultloom.bola-read.case.v1"
BOLA_READ_RUN_SCHEMA = "faultloom.bola-read.run.v1"
BOLA_READ_HANDOFF_SCHEMA = "faultloom.bola-read.handoff.v1"
BOLA_READ_RESULT_SCHEMA = "faultloom.bola-read.result.v1"
BOLA_READ_SEMANTIC_OUTCOME = "cross_principal_owner_object_read_reproduced"

_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{1,2047}$")
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_SECRET_URI = re.compile(r"^secret://target-env/[A-Z][A-Z0-9_]{2,127}$")
_BEARER = re.compile(r"^[A-Za-z0-9._~+/=-]{16,512}$")
_RESPONSE_FILE = r"^responses/[A-Za-z0-9._-]+\.raw$"
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class BolaReadSemanticError(ValueError):
    """A signed BOLA read evidence set is incomplete, ambiguous, or tampered."""


class _StrictFrozenModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


def _parse_utc(value: str, *, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise BolaReadSemanticError(f"BOLA read semantic {label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise BolaReadSemanticError(f"BOLA read semantic {label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise BolaReadSemanticError(f"BOLA read semantic {label} must be UTC")
    canonical = parsed.isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise BolaReadSemanticError(f"BOLA read semantic {label} is not canonical")
    return parsed


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_bytes(value: BaseModel) -> bytes:
    return canonical_json(value.model_dump(mode="json", by_alias=True)).encode("utf-8")


def bola_model_bytes(value: BaseModel) -> bytes:
    """Canonical, newline-delimited serialization for hashable evidence records."""
    if not isinstance(value, _StrictFrozenModel):
        raise BolaReadSemanticError("BOLA read semantic serialization requires a typed model")
    return _canonical_bytes(value) + b"\n"


class BolaReadCase(_StrictFrozenModel):
    schema_: Literal["faultloom.bola-read.case.v1"] = Field(alias="schema")
    campaign_id: str = Field(pattern=_SAFE_ID)
    phase: Literal["source", "reviewer"]
    source_handoff_sha256: str | None = Field(default=None, pattern=_SHA256)
    source_claim: str = Field(min_length=1, max_length=2048)
    source_claim_status: Literal["operator_asserted_unverified"] = (
        "operator_asserted_unverified"
    )
    workspace_sha256: str = Field(pattern=_SHA256)
    target_id: str = Field(pattern=_SAFE_ID)
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"]
    object_resource: ResourceRef
    owner_subject: SubjectRef
    requester_subject: SubjectRef
    requester_identity_context: IdentityContext
    requester_session_expires_at: str = Field(min_length=20, max_length=40)
    principal_control_path: str = Field(min_length=1, max_length=2048)
    object_read_path: str = Field(min_length=1, max_length=2048)
    principal_id_field: str = "principal_id"
    object_id_field: str = "object_id"
    owner_principal_field: str = "owner_id"
    owner_binding_method: Literal["target_response_field"] = "target_response_field"
    requester_principal_binding_method: Literal["target_principal_response"] = (
        "target_principal_response"
    )
    authorization_expectation: Literal["deny_cross_principal_read"] = "deny_cross_principal_read"
    authorization_expectation_status: Literal["operator_asserted_unverified"] = (
        "operator_asserted_unverified"
    )
    denied_read_expected: Literal[True] = True
    response_bytes: int = Field(ge=1, le=1_048_576)
    timeout_seconds: int = Field(ge=1, le=30)
    run_id: str = Field(pattern=_SAFE_ID)
    grant_id: str = Field(pattern=_SAFE_ID)
    grant_version: int = Field(ge=1)
    grant_sha256: str = Field(pattern=_SHA256)
    operator_actor_id: str = Field(pattern=_SAFE_ID)
    signed_at: str = Field(min_length=20, max_length=40)

    @model_validator(mode="after")
    def _narrow_contract(self) -> "BolaReadCase":
        owner = self.owner_subject
        requester = self.requester_subject
        context = self.requester_identity_context
        if owner.identity_id is None or requester.identity_id is None:
            raise ValueError("owner and requester subjects require identities")
        if owner.identity_id == requester.identity_id:
            raise ValueError("owner and requester principals must differ")
        if owner.tenant_id is None or requester.tenant_id is None:
            raise ValueError("owner and requester subjects require tenants")
        if (
            owner.tenant_id != requester.tenant_id
            or owner.tenant_id != self.object_resource.tenant_id
            or owner.tenant_id != context.tenant_id
        ):
            raise ValueError("BOLA resource, subjects, and context must share a tenant")
        if self.object_resource.target_id != self.target_id:
            raise ValueError("BOLA resource target must match case target")
        if context.identity_id != requester.identity_id:
            raise ValueError("requester identity context does not bind requester subject")
        if context.api_session_ref is None or context.browser_context_ref is not None:
            raise ValueError("BOLA read requires one API session and no browser context")
        if (
            context.api_session_ref.purpose != "target-bearer-session"
            or _SECRET_URI.fullmatch(context.api_session_ref.uri) is None
        ):
            raise ValueError("BOLA read requires a target bearer SecretRef")
        try:
            address = ipaddress.ip_address(self.hostname)
        except ValueError:
            if (
                re.fullmatch(r"[0-9.]+", self.hostname) is not None
                or _DNS_NAME.fullmatch(self.hostname) is None
            ):
                raise ValueError("hostname must be a canonical IP or lowercase DNS name")
        else:
            if str(address) != self.hostname:
                raise ValueError("IP hostname must use canonical spelling")
        if any(_PATH.fullmatch(value) is None for value in (self.principal_control_path, self.object_read_path)):
            raise ValueError("BOLA read paths must be exact safe ASCII paths")
        if self.principal_control_path == self.object_read_path:
            raise ValueError("principal control and object read paths must differ")
        if any(_FIELD.fullmatch(value) is None for value in (
            self.principal_id_field, self.object_id_field, self.owner_principal_field,
        )) or len({self.principal_id_field, self.object_id_field, self.owner_principal_field}) != 3:
            raise ValueError("BOLA response field identifiers must be unique safe top-level names")
        if self.operator_actor_id in {owner.identity_id, requester.identity_id}:
            raise ValueError("operator actor must differ from target principals")
        _parse_utc(self.signed_at, label="signed_at")
        # Expiry is enforced by the runner immediately before SecretRef
        # resolution and before any target I/O.  Keeping an expired signed case
        # parseable lets that fail-closed boundary be independently tested and
        # preserves historical evidence after a session naturally expires.
        _parse_utc(self.requester_session_expires_at, label="requester session expiry")
        if self.phase == "source" and self.source_handoff_sha256 is not None:
            raise ValueError("source BOLA case cannot bind a source handoff")
        if self.phase == "reviewer" and self.source_handoff_sha256 is None:
            raise ValueError("reviewer BOLA case must bind the source handoff")
        return self


class SignedBolaReadCase(_StrictFrozenModel):
    case: BolaReadCase
    signer_key_id: str = Field(min_length=1, max_length=256)
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")


class BolaReadObservation(_StrictFrozenModel):
    role: Literal["principal_control", "object_read", "anonymous_control"]
    auth_mode: Literal["requester", "anonymous"]
    path: str = Field(min_length=1, max_length=2048)
    reservation_id: str = Field(pattern=_SAFE_ID)
    redacted_request_sha256: str = Field(pattern=_SHA256)
    response_sha256: str = Field(pattern=_SHA256)
    response_bytes: int = Field(ge=1, le=1_048_576)
    status_code: int = Field(ge=100, le=599)
    response_file: str = Field(pattern=_RESPONSE_FILE)


class BolaReadRunResult(_StrictFrozenModel):
    schema_: Literal["faultloom.bola-read.run.v1"] = Field(alias="schema")
    campaign_id: str = Field(pattern=_SAFE_ID)
    phase: Literal["source", "reviewer"]
    case_sha256: str = Field(pattern=_SHA256)
    status: Literal["observation_recorded", "unresolved_not_evaluated"]
    dispatch_count: int = Field(ge=0, le=3)
    observations: tuple[BolaReadObservation, ...] = ()
    semantic_verdict: Literal["not_evaluated"] = "not_evaluated"
    taxonomy_verdict: Literal["not_evaluated"] = "not_evaluated"
    automatic_submission: Literal[False] = False

    @field_validator("observations", mode="before")
    @classmethod
    def _tuple_observations(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def _complete_observation(self) -> "BolaReadRunResult":
        if self.status == "observation_recorded":
            if self.dispatch_count != 3 or len(self.observations) != 3:
                raise ValueError("completed BOLA read requires exactly three observations")
        elif len(self.observations) > self.dispatch_count:
            raise ValueError("unresolved BOLA observations exceed dispatch count")
        if len({item.reservation_id for item in self.observations}) != len(self.observations):
            raise ValueError("BOLA observations must have distinct reservations")
        if len({item.response_file for item in self.observations}) != len(self.observations):
            raise ValueError("BOLA observations must have distinct response files")
        return self


class SignedBolaReadRun(_StrictFrozenModel):
    run: BolaReadRunResult
    signer_key_id: str = Field(min_length=1, max_length=256)
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")


class BolaReadHandoff(_StrictFrozenModel):
    schema_: Literal["faultloom.bola-read.handoff.v1"] = Field(alias="schema")
    source_workspace_sha256: str = Field(pattern=_SHA256)
    source_case: SignedBolaReadCase
    source_case_sha256: str = Field(pattern=_SHA256)
    source_run: SignedBolaReadRun
    source_run_sha256: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(min_length=1, max_length=256)
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")


class BolaReadSemanticResult(_StrictFrozenModel):
    schema_: Literal["faultloom.bola-read.result.v1"] = Field(alias="schema")
    campaign_id: str = Field(pattern=_SAFE_ID)
    status: Literal["cross_principal_owner_object_read_reproduced"]
    observed_fact: Literal["cross_principal_owner_object_read_reproduced"]
    source_claim: str = Field(min_length=1, max_length=2048)
    source_claim_status: Literal["operator_asserted_unverified"] = (
        "operator_asserted_unverified"
    )
    semantic_verdict: Literal["not_evaluated"] = "not_evaluated"
    candidate_class: Literal["bola_idor"] = "bola_idor"
    candidate_class_status: Literal["operator_asserted_unverified"] = (
        "operator_asserted_unverified"
    )
    owner_binding_status: Literal["target_response_observed"] = "target_response_observed"
    requester_principal_binding_status: Literal["target_response_observed"] = (
        "target_response_observed"
    )
    authorization_expectation_status: Literal["operator_asserted_unverified"] = (
        "operator_asserted_unverified"
    )
    object_resource: ResourceRef
    owner_subject: SubjectRef
    requester_subject: SubjectRef
    source_case_sha256: str = Field(pattern=_SHA256)
    source_run_sha256: str = Field(pattern=_SHA256)
    reviewer_case_sha256: str = Field(pattern=_SHA256)
    reviewer_run_sha256: str = Field(pattern=_SHA256)
    taxonomy_verdict: Literal["not_evaluated"] = "not_evaluated"
    impact_verdict: Literal["not_evaluated"] = "not_evaluated"
    report_status: Literal["draft_manual_review"] = "draft_manual_review"
    automatic_submission: Literal[False] = False


@dataclass(frozen=True, slots=True)
class ParsedBolaReadResponse:
    response_sha256: str
    size: int
    status_code: int
    body: dict[str, object]


def sign_bola_read_case(case: BolaReadCase, signer: AuthoritySigner) -> SignedBolaReadCase:
    if type(case) is not BolaReadCase or type(signer) is not AuthoritySigner:
        raise BolaReadSemanticError("BOLA read semantic case signing requires typed inputs")
    try:
        validated = BolaReadCase.model_validate(
            case.model_dump(mode="python", by_alias=True)
        )
    except ValidationError as exc:
        raise BolaReadSemanticError(
            "BOLA read semantic case structure is invalid"
        ) from exc
    return SignedBolaReadCase(
        case=validated,
        signer_key_id=signer.key_id,
        signature=signer.sign(_canonical_bytes(validated)),
    )


def signed_bola_case_bytes(signed: SignedBolaReadCase) -> bytes:
    if type(signed) is not SignedBolaReadCase:
        raise BolaReadSemanticError("BOLA read semantic requires a typed signed case")
    try:
        validated = SignedBolaReadCase.model_validate(
            signed.model_dump(mode="python", by_alias=True)
        )
    except ValidationError as exc:
        raise BolaReadSemanticError(
            "BOLA read semantic signed case structure is invalid"
        ) from exc
    return bola_model_bytes(validated)


def sign_bola_read_run(run: BolaReadRunResult, signer: AuthoritySigner) -> SignedBolaReadRun:
    if type(run) is not BolaReadRunResult or type(signer) is not AuthoritySigner:
        raise BolaReadSemanticError("BOLA read semantic run signing requires typed inputs")
    try:
        validated = BolaReadRunResult.model_validate(
            run.model_dump(mode="python", by_alias=True)
        )
    except ValidationError as exc:
        raise BolaReadSemanticError(
            "BOLA read semantic run structure is invalid"
        ) from exc
    return SignedBolaReadRun(
        run=validated,
        signer_key_id=signer.key_id,
        signature=signer.sign(_canonical_bytes(validated)),
    )


def signed_bola_run_bytes(signed: SignedBolaReadRun) -> bytes:
    if type(signed) is not SignedBolaReadRun:
        raise BolaReadSemanticError("BOLA read semantic requires a typed signed run")
    try:
        validated = SignedBolaReadRun.model_validate(
            signed.model_dump(mode="python", by_alias=True)
        )
    except ValidationError as exc:
        raise BolaReadSemanticError(
            "BOLA read semantic signed run structure is invalid"
        ) from exc
    return bola_model_bytes(validated)


def _verify_signature(document: bytes, signature_text: str, *, key: Ed25519PublicKeyRecord, label: str) -> None:
    try:
        signature = base64.urlsafe_b64decode(signature_text + "==")
        if base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != signature_text:
            raise ValueError("non-canonical signature")
        load_public_key(key).verify(signature, document)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise BolaReadSemanticError(f"BOLA read semantic {label} signature is invalid") from exc


def _verify_case(signed: SignedBolaReadCase, *, key: Ed25519PublicKeyRecord, label: str) -> BolaReadCase:
    if type(signed) is not SignedBolaReadCase or type(key) is not Ed25519PublicKeyRecord:
        raise BolaReadSemanticError("BOLA read semantic case/key types are invalid")
    try:
        validated = SignedBolaReadCase.model_validate(
            signed.model_dump(mode="python", by_alias=True)
        )
    except ValidationError as exc:
        raise BolaReadSemanticError(
            f"BOLA read semantic {label} case structure is invalid"
        ) from exc
    if validated.signer_key_id != key.key_id:
        raise BolaReadSemanticError(f"BOLA read semantic {label} case signer is untrusted")
    _verify_signature(
        _canonical_bytes(validated.case),
        validated.signature,
        key=key,
        label=f"{label} case",
    )
    return validated.case


def _verify_run(signed: SignedBolaReadRun, *, key: Ed25519PublicKeyRecord, label: str) -> BolaReadRunResult:
    if type(signed) is not SignedBolaReadRun or type(key) is not Ed25519PublicKeyRecord:
        raise BolaReadSemanticError("BOLA read semantic run/key types are invalid")
    try:
        validated = SignedBolaReadRun.model_validate(
            signed.model_dump(mode="python", by_alias=True)
        )
    except ValidationError as exc:
        raise BolaReadSemanticError(
            f"BOLA read semantic {label} run structure is invalid"
        ) from exc
    if validated.signer_key_id != key.key_id:
        raise BolaReadSemanticError(f"BOLA read semantic {label} run signer is untrusted")
    _verify_signature(
        _canonical_bytes(validated.run),
        validated.signature,
        key=key,
        label=f"{label} run",
    )
    return validated.run


def verify_signed_bola_case(
    signed: SignedBolaReadCase, trusted_key: Ed25519PublicKeyRecord
) -> BolaReadCase:
    """Verify a case before resolving a SecretRef or dispatching a request."""
    return _verify_case(signed, key=trusted_key, label="BOLA")


def verify_signed_bola_run(
    signed: SignedBolaReadRun, trusted_key: Ed25519PublicKeyRecord
) -> BolaReadRunResult:
    """Verify a recorded run before consuming its response artifacts."""
    return _verify_run(signed, key=trusted_key, label="BOLA")


def _handoff_payload(handoff: BolaReadHandoff) -> bytes:
    return canonical_json(handoff.model_dump(mode="json", by_alias=True, exclude={"signature"})).encode("utf-8")


def build_bola_read_handoff(
    *, source_workspace_sha256: str, source_case: SignedBolaReadCase,
    source_case_sha256: str, source_run: SignedBolaReadRun, source_run_sha256: str,
    signer: AuthoritySigner,
) -> BolaReadHandoff:
    if type(signer) is not AuthoritySigner:
        raise BolaReadSemanticError("BOLA read semantic handoff signer is invalid")
    source = _verify_case(
        source_case, key=signer.public_key_record, label="source"
    )
    run = _verify_run(source_run, key=signer.public_key_record, label="source")
    if (
        source_case_sha256 != _sha256(signed_bola_case_bytes(source_case))
        or source_run_sha256 != _sha256(signed_bola_run_bytes(source_run))
        or source.phase != "source"
        or run.phase != "source"
        or run.campaign_id != source.campaign_id
        or run.case_sha256 != source_case_sha256
        or source.workspace_sha256 != source_workspace_sha256
    ):
        raise BolaReadSemanticError(
            "BOLA read semantic source handoff relation is invalid"
        )
    unsigned = BolaReadHandoff(
        schema=BOLA_READ_HANDOFF_SCHEMA,
        source_workspace_sha256=source_workspace_sha256,
        source_case=source_case,
        source_case_sha256=source_case_sha256,
        source_run=source_run,
        source_run_sha256=source_run_sha256,
        signer_key_id=signer.key_id,
        signature="A" * 86,
    )
    return unsigned.model_copy(update={"signature": signer.sign(_handoff_payload(unsigned))})


def _verify_handoff(handoff: BolaReadHandoff, *, key: Ed25519PublicKeyRecord) -> tuple[BolaReadCase, BolaReadRunResult]:
    if type(handoff) is not BolaReadHandoff or type(key) is not Ed25519PublicKeyRecord:
        raise BolaReadSemanticError("BOLA read semantic handoff/key types are invalid")
    try:
        validated = BolaReadHandoff.model_validate(
            handoff.model_dump(mode="python", by_alias=True)
        )
    except ValidationError as exc:
        raise BolaReadSemanticError(
            "BOLA read semantic source handoff structure is invalid"
        ) from exc
    if validated.signer_key_id != key.key_id:
        raise BolaReadSemanticError("BOLA read semantic handoff signer is untrusted")
    _verify_signature(
        _handoff_payload(validated),
        validated.signature,
        key=key,
        label="source handoff",
    )
    if (
        validated.source_case_sha256 != _sha256(signed_bola_case_bytes(validated.source_case))
        or validated.source_run_sha256 != _sha256(signed_bola_run_bytes(validated.source_run))
    ):
        raise BolaReadSemanticError("BOLA read semantic handoff digest binding is invalid")
    source_case = _verify_case(validated.source_case, key=key, label="source")
    source_run = _verify_run(validated.source_run, key=key, label="source")
    if (
        validated.source_workspace_sha256 != source_case.workspace_sha256
        or source_case.phase != "source"
        or source_run.phase != "source"
        or source_run.campaign_id != source_case.campaign_id
        or source_run.case_sha256 != validated.source_case_sha256
    ):
        raise BolaReadSemanticError("BOLA read semantic source handoff relation is invalid")
    return source_case, source_run


def verify_bola_read_handoff(
    handoff: BolaReadHandoff, trusted_key: Ed25519PublicKeyRecord
) -> BolaReadHandoff:
    """Verify source signatures and source case/run digest relations in a handoff."""
    _verify_handoff(handoff, key=trusted_key)
    return handoff


def _expected_role(case: BolaReadCase, role: str) -> tuple[str, str]:
    if role == "principal_control":
        return "requester", case.principal_control_path
    if role == "object_read":
        return "requester", case.object_read_path
    if role == "anonymous_control":
        return "anonymous", case.object_read_path
    raise BolaReadSemanticError("BOLA read semantic request role is invalid")


def build_bola_read_get(
    case: BolaReadCase, *, role: str, path: str, bearer: str | None
) -> bytes:
    if type(case) is not BolaReadCase:
        raise BolaReadSemanticError("BOLA read semantic request requires a typed case")
    auth_mode, expected_path = _expected_role(case, role)
    if path != expected_path or _PATH.fullmatch(path) is None:
        raise BolaReadSemanticError("BOLA read semantic request path does not match its role")
    if auth_mode == "requester":
        if type(bearer) is not str or _BEARER.fullmatch(bearer) is None:
            raise BolaReadSemanticError("BOLA read semantic authenticated request requires a bearer")
    elif bearer is not None:
        raise BolaReadSemanticError("BOLA read semantic anonymous request cannot carry a bearer")
    default_port = (case.scheme == "https" and case.port == 443) or (case.scheme == "http" and case.port == 80)
    address = ipaddress.ip_address(case.hostname) if ":" in case.hostname else None
    host_name = f"[{case.hostname}]" if address is not None and address.version == 6 else case.hostname
    host = host_name if default_port else f"{host_name}:{case.port}"
    authorization = f"Authorization: Bearer {bearer}\r\n" if bearer is not None else ""
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{authorization}"
        "Accept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def redacted_bola_request_sha256(case: BolaReadCase, *, role: str, path: str) -> str:
    if type(case) is not BolaReadCase:
        raise BolaReadSemanticError("BOLA read semantic request digest requires a typed case")
    auth_mode, expected_path = _expected_role(case, role)
    if path != expected_path:
        raise BolaReadSemanticError("BOLA read semantic request digest path does not match its role")
    session_ref = case.requester_identity_context.api_session_ref
    if session_ref is None:
        raise BolaReadSemanticError("BOLA read semantic request has no API session reference")
    return _sha256(canonical_json({
        "method": "GET", "role": role, "auth_mode": auth_mode, "path": path,
        "requester_session_ref": session_ref.model_dump(mode="json"),
        "target": {"target_id": case.target_id, "hostname": case.hostname, "port": case.port, "scheme": case.scheme},
    }).encode("utf-8"))


def _json_object(content: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise BolaReadSemanticError(f"BOLA read semantic {label} has duplicate JSON keys")
            output[key] = value
        return output

    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, BolaReadSemanticError) as exc:
        raise BolaReadSemanticError(f"BOLA read semantic {label} JSON is invalid") from exc
    if type(value) is not dict:
        raise BolaReadSemanticError(f"BOLA read semantic {label} JSON must be an object")
    return cast(dict[str, object], value)


def parse_bola_http_response(content: bytes, *, response_limit: int) -> ParsedBolaReadResponse:
    if type(content) is not bytes or not content or len(content) > response_limit:
        raise BolaReadSemanticError("BOLA read semantic response is missing or oversized")
    if content.count(b"\r\n\r\n") != 1:
        raise BolaReadSemanticError("BOLA read semantic response framing is invalid")
    headers, body = content.split(b"\r\n\r\n", 1)
    lines = headers.split(b"\r\n")
    if not lines or re.fullmatch(rb"HTTP/1\.1 ([1-5][0-9]{2}) [A-Za-z ]{1,64}", lines[0]) is None:
        raise BolaReadSemanticError("BOLA read semantic response status line is invalid")
    status_code = int(lines[0][9:12])
    parsed: dict[str, str] = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            raise BolaReadSemanticError("BOLA read semantic response headers are malformed")
        name, value = line.split(b":", 1)
        try:
            key = name.decode("ascii").lower()
            text = value.strip().decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise BolaReadSemanticError("BOLA read semantic response headers are malformed") from exc
        if not re.fullmatch(r"[a-z0-9-]+", key) or key in parsed:
            raise BolaReadSemanticError("BOLA read semantic response headers are ambiguous")
        parsed[key] = text
    if (
        set(parsed) != {"content-type", "content-length", "connection"}
        or parsed["content-type"] != "application/json"
        or parsed["connection"] != "close"
        or not parsed["content-length"].isdigit()
        or int(parsed["content-length"]) != len(body)
    ):
        raise BolaReadSemanticError("BOLA read semantic response is not bounded JSON")
    return ParsedBolaReadResponse(
        response_sha256=_sha256(content),
        size=len(content),
        status_code=status_code,
        body=_json_object(body, label="response body"),
    )


def _validated_run(
    *, case: BolaReadCase, signed_run: SignedBolaReadRun, response_bytes: Mapping[str, bytes],
    expected_case_sha256: str, label: str,
) -> tuple[ParsedBolaReadResponse, ParsedBolaReadResponse, ParsedBolaReadResponse]:
    run = signed_run.run
    # Re-validate model-copy constructed values before reasoning over them.
    try:
        run = BolaReadRunResult.model_validate(run.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise BolaReadSemanticError("BOLA read semantic run shape is invalid") from exc
    if (
        run.status != "observation_recorded" or run.campaign_id != case.campaign_id
        or run.phase != case.phase or run.case_sha256 != expected_case_sha256
        or run.dispatch_count != 3 or run.semantic_verdict != "not_evaluated"
        or run.taxonomy_verdict != "not_evaluated" or run.automatic_submission is not False
    ):
        raise BolaReadSemanticError("BOLA read semantic signed run state is invalid")
    expected = (
        ("principal_control", "requester", case.principal_control_path, 200),
        ("object_read", "requester", case.object_read_path, 200),
        ("anonymous_control", "anonymous", case.object_read_path, None),
    )
    if not isinstance(response_bytes, Mapping):
        raise BolaReadSemanticError("BOLA read semantic raw response mapping is invalid")
    paths = {item.response_file for item in run.observations}
    if set(response_bytes) != paths:
        raise BolaReadSemanticError("BOLA read semantic raw response mapping is incomplete")
    parsed_items: list[ParsedBolaReadResponse] = []
    for observation, (role, auth_mode, path, expected_status) in zip(run.observations, expected, strict=True):
        if (
            observation.role != role or observation.auth_mode != auth_mode or observation.path != path
            or observation.redacted_request_sha256 != redacted_bola_request_sha256(case, role=role, path=path)
        ):
            raise BolaReadSemanticError("BOLA read semantic observation binding is invalid")
        raw = response_bytes.get(observation.response_file)
        if type(raw) is not bytes or len(raw) != observation.response_bytes or _sha256(raw) != observation.response_sha256:
            raise BolaReadSemanticError("BOLA read semantic raw response binding is invalid")
        if observation.response_bytes > case.response_bytes:
            raise BolaReadSemanticError("BOLA read semantic observation exceeds response cap")
        parsed = parse_bola_http_response(raw, response_limit=case.response_bytes)
        if parsed.status_code != observation.status_code:
            raise BolaReadSemanticError("BOLA read semantic signed response status is false")
        if expected_status is not None and parsed.status_code != expected_status:
            raise BolaReadSemanticError("BOLA read semantic authenticated observation is not successful")
        if role == "anonymous_control" and parsed.status_code not in {401, 403, 404}:
            raise BolaReadSemanticError("BOLA read semantic anonymous control was not denied")
        parsed_items.append(parsed)
    return cast(
        tuple[ParsedBolaReadResponse, ParsedBolaReadResponse, ParsedBolaReadResponse],
        tuple(parsed_items),
    )


def _assert_response_semantics(
    case: BolaReadCase,
    responses: tuple[ParsedBolaReadResponse, ParsedBolaReadResponse, ParsedBolaReadResponse],
) -> None:
    principal, object_read, anonymous = responses
    requester_id = case.requester_subject.identity_id
    owner_id = case.owner_subject.identity_id
    if (
        type(requester_id) is not str or type(owner_id) is not str
        or principal.body.get(case.principal_id_field) != requester_id
        or object_read.body.get(case.object_id_field) != case.object_resource.resource_id
        or object_read.body.get(case.owner_principal_field) != owner_id
    ):
        raise BolaReadSemanticError("BOLA read semantic response identity binding is invalid")
    if anonymous.body.get(case.object_id_field) == case.object_resource.resource_id:
        raise BolaReadSemanticError("BOLA read semantic anonymous control exposes the object")


def semantic_bola_read_result(
    *, handoff: BolaReadHandoff, source_trusted_key: Ed25519PublicKeyRecord,
    source_response_bytes: Mapping[str, bytes], reviewer_case: SignedBolaReadCase,
    reviewer_run: SignedBolaReadRun, reviewer_trusted_key: Ed25519PublicKeyRecord,
    reviewer_response_bytes: Mapping[str, bytes],
) -> BolaReadSemanticResult:
    """Verify independently signed read evidence without upgrading taxonomy or impact."""
    source_case, source_run = _verify_handoff(handoff, key=source_trusted_key)
    reviewer = _verify_case(reviewer_case, key=reviewer_trusted_key, label="reviewer")
    _ = _verify_run(reviewer_run, key=reviewer_trusted_key, label="reviewer")
    source_case_sha256 = handoff.source_case_sha256
    reviewer_case_sha256 = _sha256(signed_bola_case_bytes(reviewer_case))
    reviewer_run_sha256 = _sha256(signed_bola_run_bytes(reviewer_run))
    if (
        reviewer.phase != "reviewer"
        or reviewer.source_handoff_sha256 != _sha256(bola_model_bytes(handoff))
        or reviewer_case.signer_key_id == handoff.source_case.signer_key_id
        or reviewer.workspace_sha256 == source_case.workspace_sha256
        or reviewer.operator_actor_id == source_case.operator_actor_id
        or reviewer.grant_sha256 == source_case.grant_sha256
        or reviewer.requester_identity_context.api_session_ref is None
        or source_case.requester_identity_context.api_session_ref is None
        or reviewer.requester_identity_context.api_session_ref.uri
        == source_case.requester_identity_context.api_session_ref.uri
        or reviewer.requester_identity_context.auth_session_id
        == source_case.requester_identity_context.auth_session_id
        or reviewer.requester_identity_context.role_ids
        != source_case.requester_identity_context.role_ids
    ):
        raise BolaReadSemanticError("BOLA read semantic source and reviewer are not independent")
    equal_fields = (
        "campaign_id", "source_claim", "source_claim_status", "target_id", "hostname",
        "port", "scheme", "object_resource",
        "owner_subject", "requester_subject", "principal_control_path", "object_read_path",
        "principal_id_field", "object_id_field", "owner_principal_field",
        "owner_binding_method", "requester_principal_binding_method",
        "authorization_expectation", "authorization_expectation_status",
        "denied_read_expected", "response_bytes", "timeout_seconds",
    )
    if any(getattr(source_case, field) != getattr(reviewer, field) for field in equal_fields):
        raise BolaReadSemanticError("BOLA read semantic source and reviewer cases differ")
    source_responses = _validated_run(
        case=source_case, signed_run=handoff.source_run, response_bytes=source_response_bytes,
        expected_case_sha256=source_case_sha256, label="source",
    )
    reviewer_responses = _validated_run(
        case=reviewer, signed_run=reviewer_run, response_bytes=reviewer_response_bytes,
        expected_case_sha256=reviewer_case_sha256, label="reviewer",
    )
    _assert_response_semantics(source_case, source_responses)
    _assert_response_semantics(reviewer, reviewer_responses)
    return BolaReadSemanticResult(
        schema=BOLA_READ_RESULT_SCHEMA,
        campaign_id=source_case.campaign_id,
        status=BOLA_READ_SEMANTIC_OUTCOME,
        observed_fact=BOLA_READ_SEMANTIC_OUTCOME,
        source_claim=source_case.source_claim,
        object_resource=source_case.object_resource,
        owner_subject=source_case.owner_subject,
        requester_subject=source_case.requester_subject,
        source_case_sha256=source_case_sha256,
        source_run_sha256=handoff.source_run_sha256,
        reviewer_case_sha256=reviewer_case_sha256,
        reviewer_run_sha256=reviewer_run_sha256,
    )
