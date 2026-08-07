"""Offline independent-verification bridge for finalized HTTP/1 triads."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from faultloom_protocol import SCHEMA_VERSION, EvidenceRef, ReplayPlan

from .contracts import (
    ControlResult,
    ReplayExecutionRequest,
    ReplayExecutionResult,
)


HTTP1_DIFFERENTIAL_OBSERVATION = "exact_http_response_body_differential"
HTTP1_DIFFERENTIAL_OBSERVATION_CLAIM = (
    "The exact HTTP response body differential was independently reproduced."
)
HTTP1_DIFFERENTIAL_OBSERVATION_REASON = (
    "verification.http_response_body_differential_reproduced_only"
)
HTTP1_DIFFERENTIAL_OBSERVATION_TITLE = (
    "Independent HTTP response-body differential observation"
)
HTTP1_DIFFERENTIAL_PUBLIC_OUTCOME = "observation_reproduced"


@dataclass(frozen=True, slots=True)
class Http1TriadVerificationError(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class StrictHttp1Request:
    method: str
    path: str
    host: str
    content: bytes


def parse_strict_http1_request(content: bytes) -> StrictHttp1Request:
    """Accept only a bodyless GET/OPTIONS with Host and Connection: close."""
    if not content or content.count(b"\r\n\r\n") != 1:
        raise Http1TriadVerificationError("request framing is not one HTTP/1.1 message")
    header_block, body = content.split(b"\r\n\r\n", 1)
    if body:
        raise Http1TriadVerificationError("verification requests must have an empty body")
    lines = header_block.split(b"\r\n")
    if len(lines) != 3:
        raise Http1TriadVerificationError(
            "verification requests require exactly Host and Connection headers"
        )
    try:
        method, path, version = lines[0].decode("ascii").split(" ")
        headers = [line.decode("ascii") for line in lines[1:]]
    except (UnicodeDecodeError, ValueError) as exc:
        raise Http1TriadVerificationError("verification request is not canonical ASCII") from exc
    if method not in {"GET", "OPTIONS"} or version != "HTTP/1.1":
        raise Http1TriadVerificationError("verification method must be GET or OPTIONS")
    if not path.startswith("/") or any(ord(value) < 0x21 or ord(value) == 0x7F for value in path):
        raise Http1TriadVerificationError("verification request target is invalid")
    parsed: dict[str, str] = {}
    for header in headers:
        if ":" not in header or header[:1] in {" ", "\t"}:
            raise Http1TriadVerificationError("verification request header is malformed")
        name, value = header.split(":", 1)
        if (
            not name
            or any(ord(character) < 0x21 or ord(character) == 0x7F for character in name)
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise Http1TriadVerificationError("verification request contains a control character")
        lowered = name.lower()
        if lowered in parsed or lowered not in {"host", "connection"}:
            raise Http1TriadVerificationError("verification request has an extra header")
        parsed[lowered] = value.strip()
    if not parsed.get("host") or parsed.get("connection", "").lower() != "close":
        raise Http1TriadVerificationError(
            "verification request requires Host and Connection: close"
        )
    return StrictHttp1Request(method=method, path=path, host=parsed["host"], content=content)


def require_separate_workspaces(source: Path, verifier: Path) -> None:
    try:
        source_root = source.resolve(strict=True)
        verifier_root = verifier.resolve(strict=True)
    except OSError as exc:
        raise Http1TriadVerificationError("source or verifier workspace is unavailable") from exc
    if source_root == verifier_root:
        raise Http1TriadVerificationError("verifier workspace must differ from source workspace")
    for parent, child in ((source_root, verifier_root), (verifier_root, source_root)):
        try:
            child.relative_to(parent)
        except ValueError:
            continue
        raise Http1TriadVerificationError("source and verifier workspaces cannot be nested")


def require_independent_identity(
    *,
    source_actor: str,
    verifier_actor: str,
    source_key_id: str,
    verifier_key_id: str,
    source_authority_digest: str,
    verifier_authority_digest: str,
) -> None:
    if source_actor == verifier_actor:
        raise Http1TriadVerificationError("verifier actor must differ from source actor")
    if source_key_id == verifier_key_id:
        raise Http1TriadVerificationError("verifier authority key must differ from source key")
    if source_authority_digest == verifier_authority_digest:
        raise Http1TriadVerificationError("verifier authority must differ from source authority")


def _derived_evidence(
    *, run_id: str, role: str, digest: str, created_at: datetime
) -> EvidenceRef:
    return EvidenceRef.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": f"evidence.independent-{role}.{digest[-16:]}",
            "run_id": run_id,
            "cas_digest": f"sha256:{digest}",
            "observation_ids": (),
            "redaction_digest": None,
            "created_at": created_at,
        }
    )


class FinalizedTriadReplayExecutor:
    """ReplayExecutor backed only by an already-finalized verifier transcript."""

    def __init__(
        self,
        *,
        replay_plan: ReplayPlan,
        verifier_run_id: str,
        effect_response: bytes,
        reproduction_response: bytes,
        negative_response: bytes,
        effect_body_digest: str,
        reproduction_body_digest: str,
        negative_body_digest: str,
        source_effect_body_digest: str,
        source_negative_body_digest: str,
        created_at: datetime,
        cleanup_receipt_digest: str,
    ) -> None:
        self._plan = replay_plan
        self._run_id = verifier_run_id
        self._responses = (effect_response, reproduction_response, negative_response)
        self._body_digests = (
            effect_body_digest,
            reproduction_body_digest,
            negative_body_digest,
        )
        self._source_body_digests = (source_effect_body_digest, source_negative_body_digest)
        self._created_at = created_at
        self._cleanup = cleanup_receipt_digest

    def execute(self, request: ReplayExecutionRequest) -> ReplayExecutionResult:
        if request.verifier_run_id != self._run_id or request.replay_plan != self._plan:
            raise Http1TriadVerificationError("replay request differs from finalized verifier case")
        effect, reproduction, negative = self._body_digests
        source_effect, source_negative = self._source_body_digests
        response_digests = tuple(hashlib.sha256(value).hexdigest() for value in self._responses)
        evidence = tuple(
            _derived_evidence(
                run_id=self._run_id,
                role=role,
                digest=digest,
                created_at=self._created_at,
            )
            for role, digest in zip(
                ("effect", "reproduction", "negative-control"), response_digests, strict=True
            )
        )
        return ReplayExecutionResult(
            verifier_run_id=self._run_id,
            reset_state_refs=self._plan.reset_state_refs,
            positive_controls=tuple(
                ControlResult(
                    edge_id=edge,
                    passed=(
                        effect == reproduction == source_effect
                        and negative == source_negative
                        and effect != negative
                    ),
                    evidence_refs=(evidence[0], evidence[1]),
                )
                for edge in self._plan.edge_ids
            ),
            negative_controls=(
                ControlResult(
                    edge_id=self._plan.negative_control_edge_ids[0],
                    passed=negative == source_negative and effect != negative,
                    evidence_refs=(evidence[2],),
                ),
            ),
            final_effect_observed=(
                effect == reproduction == source_effect
                and negative == source_negative
                and effect != negative
            ),
            cleanup_receipt_digests=(self._cleanup,),
        )
