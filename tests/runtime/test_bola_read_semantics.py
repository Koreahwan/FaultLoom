"""RED contracts for signed, class-specific, read-only BOLA evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    IdentityContext,
    ResourceRef,
    SecretRef,
    SubjectRef,
)

from faultloom.bola_read_semantics import (
    BOLA_READ_SEMANTIC_OUTCOME,
    BolaReadCase,
    BolaReadHandoff,
    BolaReadObservation,
    BolaReadRunResult,
    BolaReadSemanticError,
    BolaReadSemanticResult,
    SignedBolaReadCase,
    SignedBolaReadRun,
    bola_model_bytes,
    build_bola_read_get,
    build_bola_read_handoff,
    redacted_bola_request_sha256,
    semantic_bola_read_result,
    sign_bola_read_case,
    sign_bola_read_run,
    signed_bola_case_bytes,
    signed_bola_run_bytes,
)


CAMPAIGN = "owned-invoice-read"
OBJECT_ID = "invoice.7d4bc9"
OWNER = "identity.owner-a"
OTHER_OWNER = "identity.owner-c"
REQUESTER = "identity.requester-b"
PRINCIPAL_PATH = "/api/principal"
OBJECT_PATH = f"/api/invoices/{OBJECT_ID}"
SOURCE_BEARER = "source-bearer-token-7f4ab912"
REVIEWER_BEARER = "reviewer-bearer-token-9c2de831"
NOW = datetime(2026, 8, 12, tzinfo=UTC)
SESSION_EXPIRES_AT = "2026-08-13T00:00:00Z"
SOURCE_CLAIM = "Requester B may have read owner A's invoice despite an owner-only policy."


@dataclass(frozen=True)
class _Material:
    source_case: SignedBolaReadCase
    source_run: SignedBolaReadRun
    source_signer: AuthoritySigner
    reviewer_case: SignedBolaReadCase
    reviewer_run: SignedBolaReadRun
    reviewer_signer: AuthoritySigner
    handoff: BolaReadHandoff
    source_responses: dict[str, bytes]
    reviewer_responses: dict[str, bytes]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _response(status: int, body: dict[str, str]) -> bytes:
    reason = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}[status]
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + encoded


def _resource() -> ResourceRef:
    return ResourceRef(
        schema_version=SCHEMA_VERSION,
        resource_id=OBJECT_ID,
        resource_kind="invoice",
        target_id="target.owned-loopback",
        tenant_id="tenant.alpha",
    )


def _subject(identity_id: str) -> SubjectRef:
    return SubjectRef(
        schema_version=SCHEMA_VERSION,
        subject_id=f"subject.{identity_id.rsplit('.', maxsplit=1)[-1]}",
        subject_kind="human",
        identity_id=identity_id,
        tenant_id="tenant.alpha",
    )


def _context(
    phase: str, roles: tuple[str, ...] = ("role.requester",)
) -> IdentityContext:
    return IdentityContext(
        schema_version=SCHEMA_VERSION,
        identity_context_id=f"identity-context.requester.{phase}",
        identity_id=REQUESTER,
        tenant_id="tenant.alpha",
        role_ids=roles,
        auth_session_id=f"auth-session.requester.{phase}",
        api_session_ref=SecretRef(
            schema_version=SCHEMA_VERSION,
            uri=f"secret://target-env/REQUESTER_{phase.upper()}_SESSION",
            purpose="target-bearer-session",
        ),
    )


def _case(
    *,
    phase: str,
    signer: AuthoritySigner,
    owner: str,
    source_handoff_sha256: str | None = None,
    workspace_sha256: str | None = None,
    actor_id: str | None = None,
    grant_sha256: str | None = None,
    context_phase: str | None = None,
    context_roles: tuple[str, ...] = ("role.requester",),
) -> SignedBolaReadCase:
    case = BolaReadCase(
        schema="faultloom.bola-read.case.v1",
        campaign_id=CAMPAIGN,
        phase=phase,
        source_handoff_sha256=source_handoff_sha256,
        source_claim=SOURCE_CLAIM,
        workspace_sha256=workspace_sha256 or (("d" if phase == "source" else "e") * 64),
        target_id="target.owned-loopback",
        hostname="127.0.0.1",
        port=8443,
        scheme="https",
        object_resource=_resource(),
        owner_subject=_subject(owner),
        requester_subject=_subject(REQUESTER),
        requester_identity_context=_context(context_phase or phase, context_roles),
        requester_session_expires_at=SESSION_EXPIRES_AT,
        principal_control_path=PRINCIPAL_PATH,
        object_read_path=OBJECT_PATH,
        denied_read_expected=True,
        response_bytes=4096,
        timeout_seconds=3,
        run_id=f"run.{phase}",
        grant_id=f"grant.{phase}",
        grant_version=1,
        grant_sha256=grant_sha256 or (("b" if phase == "source" else "c") * 64),
        operator_actor_id=actor_id or (
            "researcher.source" if phase == "source" else "reviewer.independent"
        ),
        signed_at=NOW.isoformat().replace("+00:00", "Z"),
    )
    return sign_bola_read_case(case, signer)


def _run(
    *,
    signed_case: SignedBolaReadCase,
    signer: AuthoritySigner,
    principal_body: dict[str, str],
    object_body: dict[str, str],
    anonymous_status: int,
    anonymous_body: dict[str, str],
) -> tuple[SignedBolaReadRun, dict[str, bytes]]:
    case = signed_case.case
    raw = {
        "principal.raw": _response(200, principal_body),
        "object.raw": _response(200, object_body),
        "anonymous.raw": _response(anonymous_status, anonymous_body),
    }
    observations = (
        BolaReadObservation(
            role="principal_control",
            auth_mode="requester",
            path=case.principal_control_path,
            reservation_id=f"reservation.{case.phase}.principal",
            redacted_request_sha256=redacted_bola_request_sha256(
                case, role="principal_control", path=case.principal_control_path
            ),
            response_sha256=_sha256(raw["principal.raw"]),
            response_bytes=len(raw["principal.raw"]),
            status_code=200,
            response_file="responses/principal.raw",
        ),
        BolaReadObservation(
            role="object_read",
            auth_mode="requester",
            path=case.object_read_path,
            reservation_id=f"reservation.{case.phase}.object",
            redacted_request_sha256=redacted_bola_request_sha256(
                case, role="object_read", path=case.object_read_path
            ),
            response_sha256=_sha256(raw["object.raw"]),
            response_bytes=len(raw["object.raw"]),
            status_code=200,
            response_file="responses/object.raw",
        ),
        BolaReadObservation(
            role="anonymous_control",
            auth_mode="anonymous",
            path=case.object_read_path,
            reservation_id=f"reservation.{case.phase}.anonymous",
            redacted_request_sha256=redacted_bola_request_sha256(
                case, role="anonymous_control", path=case.object_read_path
            ),
            response_sha256=_sha256(raw["anonymous.raw"]),
            response_bytes=len(raw["anonymous.raw"]),
            status_code=anonymous_status,
            response_file="responses/anonymous.raw",
        ),
    )
    run = BolaReadRunResult(
        schema="faultloom.bola-read.run.v1",
        campaign_id=case.campaign_id,
        phase=case.phase,
        case_sha256=_sha256(signed_bola_case_bytes(signed_case)),
        status="observation_recorded",
        dispatch_count=3,
        observations=observations,
    )
    return sign_bola_read_run(run, signer), {
        "responses/principal.raw": raw["principal.raw"],
        "responses/object.raw": raw["object.raw"],
        "responses/anonymous.raw": raw["anonymous.raw"],
    }


def _material(
    *,
    reviewer_owner: str = OWNER,
    reviewer_workspace_sha256: str | None = None,
    reviewer_actor_id: str | None = None,
    reviewer_grant_sha256: str | None = None,
    reviewer_context_phase: str | None = None,
    reviewer_roles: tuple[str, ...] = ("role.requester",),
    **response_overrides: object,
) -> _Material:
    source_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    reviewer_signer = AuthoritySigner.from_private_bytes(bytes(range(1, 33)))
    source_case = _case(phase="source", signer=source_signer, owner=OWNER)
    source_run, source_responses = _run(
        signed_case=source_case,
        signer=source_signer,
        principal_body=response_overrides.get("source_principal", {"principal_id": REQUESTER}),
        object_body=response_overrides.get(
            "source_object", {"object_id": OBJECT_ID, "owner_id": OWNER}
        ),
        anonymous_status=response_overrides.get("source_anonymous_status", 403),
        anonymous_body=response_overrides.get("source_anonymous", {"error": "forbidden"}),
    )
    handoff = build_bola_read_handoff(
        source_workspace_sha256="d" * 64,
        source_case=source_case,
        source_case_sha256=_sha256(signed_bola_case_bytes(source_case)),
        source_run=source_run,
        source_run_sha256=_sha256(signed_bola_run_bytes(source_run)),
        signer=source_signer,
    )
    reviewer_case = _case(
        phase="reviewer",
        signer=reviewer_signer,
        owner=reviewer_owner,
        source_handoff_sha256=_sha256(bola_model_bytes(handoff)),
        workspace_sha256=reviewer_workspace_sha256,
        actor_id=reviewer_actor_id,
        grant_sha256=reviewer_grant_sha256,
        context_phase=reviewer_context_phase,
        context_roles=reviewer_roles,
    )
    reviewer_run, reviewer_responses = _run(
        signed_case=reviewer_case,
        signer=reviewer_signer,
        principal_body=response_overrides.get("reviewer_principal", {"principal_id": REQUESTER}),
        object_body=response_overrides.get(
            "reviewer_object", {"object_id": OBJECT_ID, "owner_id": reviewer_owner}
        ),
        anonymous_status=response_overrides.get("reviewer_anonymous_status", 403),
        anonymous_body=response_overrides.get("reviewer_anonymous", {"error": "forbidden"}),
    )
    return _Material(
        source_case=source_case,
        source_run=source_run,
        source_signer=source_signer,
        reviewer_case=reviewer_case,
        reviewer_run=reviewer_run,
        reviewer_signer=reviewer_signer,
        handoff=handoff,
        source_responses=source_responses,
        reviewer_responses=reviewer_responses,
    )


def _result(material: _Material) -> BolaReadSemanticResult:
    return semantic_bola_read_result(
        handoff=material.handoff,
        source_trusted_key=material.source_signer.public_key_record,
        source_response_bytes=material.source_responses,
        reviewer_case=material.reviewer_case,
        reviewer_run=material.reviewer_run,
        reviewer_trusted_key=material.reviewer_signer.public_key_record,
        reviewer_response_bytes=material.reviewer_responses,
    )


def test_signed_independent_read_triad_emits_only_a_local_bola_semantic_result() -> None:
    material = _material()

    result = _result(material)

    assert isinstance(result, BolaReadSemanticResult)
    assert BOLA_READ_SEMANTIC_OUTCOME == "cross_principal_owner_object_read_reproduced"
    assert result.status == "cross_principal_owner_object_read_reproduced"
    assert result.observed_fact == "cross_principal_owner_object_read_reproduced"
    assert result.source_claim == SOURCE_CLAIM
    assert result.source_claim_status == "operator_asserted_unverified"
    assert result.semantic_verdict == "not_evaluated"
    assert result.candidate_class == "bola_idor"
    assert result.candidate_class_status == "operator_asserted_unverified"
    assert result.owner_binding_status == "target_response_observed"
    assert result.requester_principal_binding_status == "target_response_observed"
    assert result.authorization_expectation_status == "operator_asserted_unverified"
    assert result.object_resource == _resource()
    assert result.owner_subject == _subject(OWNER)
    assert result.requester_subject == _subject(REQUESTER)
    assert result.taxonomy_verdict == "not_evaluated"
    assert result.impact_verdict == "not_evaluated"
    assert result.report_status == "draft_manual_review"
    assert result.automatic_submission is False
    for signed_run in (material.source_run, material.reviewer_run):
        anonymous_control = signed_run.run.observations[2]
        assert anonymous_control.status_code in {401, 403, 404}
        # A nonpublic control only rules out public exposure; it proves no policy.
        assert result.authorization_expectation_status == "operator_asserted_unverified"


def test_signed_cases_runs_and_redacted_request_digests_never_serialize_bearers() -> None:
    material = _material()
    raw_authenticated_request_digests: list[str] = []
    for signed_case, bearer in (
        (material.source_case, SOURCE_BEARER),
        (material.reviewer_case, REVIEWER_BEARER),
    ):
        case = signed_case.case
        principal_get = build_bola_read_get(
            case, role="principal_control", path=PRINCIPAL_PATH, bearer=bearer
        )
        object_get = build_bola_read_get(case, role="object_read", path=OBJECT_PATH, bearer=bearer)
        anonymous_get = build_bola_read_get(
            case, role="anonymous_control", path=OBJECT_PATH, bearer=None
        )
        assert principal_get.startswith(b"GET /api/principal HTTP/1.1\r\n")
        assert object_get.startswith(b"GET /api/invoices/invoice.7d4bc9 HTTP/1.1\r\n")
        assert b"Authorization: Bearer " + bearer.encode() in principal_get
        assert b"Authorization: Bearer " + bearer.encode() in object_get
        assert b"Authorization:" not in anonymous_get
        assert b"GET /api/invoices/invoice.7d4bc9 HTTP/1.1\r\n" in anonymous_get
        principal_raw_sha256 = _sha256(principal_get)
        object_raw_sha256 = _sha256(object_get)
        raw_authenticated_request_digests.extend((principal_raw_sha256, object_raw_sha256))
        assert redacted_bola_request_sha256(
            case, role="principal_control", path=PRINCIPAL_PATH
        ) != principal_raw_sha256
        assert redacted_bola_request_sha256(
            case, role="object_read", path=OBJECT_PATH
        ) != object_raw_sha256
    serialized = b"".join(
        bola_model_bytes(value)
        for value in (
            material.source_case,
            material.source_run,
            material.handoff,
            material.reviewer_case,
            material.reviewer_run,
        )
    )
    assert SOURCE_BEARER.encode() not in serialized
    assert REVIEWER_BEARER.encode() not in serialized
    assert b"Authorization: Bearer " not in serialized
    assert all(digest.encode() not in serialized for digest in raw_authenticated_request_digests)


@pytest.mark.parametrize(
    ("role", "path", "bearer"),
    [
        ("principal_control", PRINCIPAL_PATH, None),
        ("object_read", OBJECT_PATH, None),
        ("anonymous_control", OBJECT_PATH, SOURCE_BEARER),
        ("principal_control", OBJECT_PATH, SOURCE_BEARER),
        ("object_read", PRINCIPAL_PATH, SOURCE_BEARER),
    ],
)
def test_request_builder_rejects_authentication_or_path_role_confusion(
    role: str, path: str, bearer: str | None
) -> None:
    case = _material().source_case.case

    with pytest.raises(BolaReadSemanticError, match="BOLA read semantic"):
        build_bola_read_get(case, role=role, path=path, bearer=bearer)


@pytest.mark.parametrize(
    "hostname",
    ("example.com\r\nauthorization: bearer injected", "Example.com", "127.0.0.01"),
)
def test_case_rejects_noncanonical_or_header_injecting_hostname(hostname: str) -> None:
    values = _material().source_case.case.model_dump(mode="python", by_alias=True)
    values["hostname"] = hostname

    with pytest.raises(ValueError):
        BolaReadCase.model_validate(values)


@pytest.mark.parametrize(
    ("label", "material"),
    [
        ("wrong source public key", _material()),
        ("tampered source case signature", _material()),
        ("tampered source handoff signature", _material()),
        ("tampered signed raw object response", _material()),
        ("wrong reviewer public key", _material()),
        ("tampered reviewer run signature", _material()),
        ("reviewer run case digest mismatch", _material()),
        (
            "principal response identity mismatch",
            _material(source_principal={"principal_id": OWNER}),
        ),
        (
            "object response identity mismatch",
            _material(source_object={"object_id": "invoice.other", "owner_id": OWNER}),
        ),
        (
            "object response owner mismatch",
            _material(source_object={"object_id": OBJECT_ID, "owner_id": REQUESTER}),
        ),
        (
            "anonymous control returns the owner object",
            _material(
                source_anonymous_status=200,
                source_anonymous={"object_id": OBJECT_ID, "owner_id": OWNER},
            ),
        ),
        ("source reviewer owner binding mismatch", _material(reviewer_owner=OTHER_OWNER)),
    ],
)
def test_hostile_signed_or_raw_evidence_never_emits_a_bola_semantic_result(
    label: str, material: _Material
) -> None:
    if label == "wrong source public key":
        material = _Material(
            **{
                **material.__dict__,
                "source_signer": AuthoritySigner.from_private_bytes(bytes(range(2, 34))),
            }
        )
    elif label == "tampered source case signature":
        bad_case = material.source_case.model_copy(update={"signature": "A" * 86})
        bad_run = sign_bola_read_run(
            material.source_run.run.model_copy(
                update={"case_sha256": _sha256(signed_bola_case_bytes(bad_case))}
            ),
            material.source_signer,
        )
        with pytest.raises(BolaReadSemanticError, match="BOLA read semantic"):
            build_bola_read_handoff(
                source_workspace_sha256="d" * 64,
                source_case=bad_case,
                source_case_sha256=_sha256(signed_bola_case_bytes(bad_case)),
                source_run=bad_run,
                source_run_sha256=_sha256(signed_bola_run_bytes(bad_run)),
                signer=material.source_signer,
            )
        return
    elif label == "tampered source handoff signature":
        material = _Material(
            **{
                **material.__dict__,
                "handoff": material.handoff.model_copy(update={"signature": "A" * 86}),
            }
        )
    elif label == "tampered signed raw object response":
        responses = dict(material.source_responses)
        responses["responses/object.raw"] = _response(
            200, {"object_id": OBJECT_ID, "owner_id": REQUESTER}
        )
        material = _Material(**{**material.__dict__, "source_responses": responses})
    elif label == "wrong reviewer public key":
        material = _Material(
            **{
                **material.__dict__,
                "reviewer_signer": AuthoritySigner.from_private_bytes(bytes(range(3, 35))),
            }
        )
    elif label == "tampered reviewer run signature":
        material = _Material(
            **{
                **material.__dict__,
                "reviewer_run": material.reviewer_run.model_copy(update={"signature": "A" * 86}),
            }
        )
    elif label == "reviewer run case digest mismatch":
        bad_run = sign_bola_read_run(
            material.reviewer_run.run.model_copy(update={"case_sha256": "f" * 64}),
            material.reviewer_signer,
        )
        material = _Material(**{**material.__dict__, "reviewer_run": bad_run})

    with pytest.raises(BolaReadSemanticError, match="BOLA read semantic"):
        _result(material)


@pytest.mark.parametrize(
    ("label", "material"),
    [
        ("shared workspace", _material(reviewer_workspace_sha256="d" * 64)),
        ("shared operator actor", _material(reviewer_actor_id="researcher.source")),
        ("shared grant digest", _material(reviewer_grant_sha256="b" * 64)),
        ("shared requester session context", _material(reviewer_context_phase="source")),
        ("mismatched requester roles", _material(reviewer_roles=("role.elevated",))),
    ],
)
def test_source_reviewer_independence_requires_distinct_workspace_actor_grant_and_session(
    label: str, material: _Material
) -> None:
    with pytest.raises(BolaReadSemanticError, match="BOLA read semantic"):
        _result(material)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("role", "principal_control"),
        ("auth_mode", "anonymous"),
        ("path", PRINCIPAL_PATH),
    ],
)
def test_signed_runs_require_the_exact_role_authentication_and_path_sequence(
    field: str, value: str
) -> None:
    material = _material()
    changed = material.source_run.run.observations[1].model_copy(update={field: value})
    run = material.source_run.run.model_copy(
        update={
            "observations": (
                material.source_run.run.observations[0],
                changed,
                material.source_run.run.observations[2],
            )
        }
    )
    source_run = sign_bola_read_run(run, material.source_signer)
    handoff = build_bola_read_handoff(
        source_workspace_sha256="d" * 64,
        source_case=material.source_case,
        source_case_sha256=_sha256(signed_bola_case_bytes(material.source_case)),
        source_run=source_run,
        source_run_sha256=_sha256(signed_bola_run_bytes(source_run)),
        signer=material.source_signer,
    )
    material = _Material(**{**material.__dict__, "source_run": source_run, "handoff": handoff})

    with pytest.raises(BolaReadSemanticError, match="BOLA read semantic"):
        _result(material)
