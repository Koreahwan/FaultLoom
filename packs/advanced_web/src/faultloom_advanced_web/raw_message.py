"""Normalize raw-message framing as observation-only candidate evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Protocol

from faultloom_protocol import SCHEMA_VERSION
from faultloom_sdk import NormalizedObservation

_ADAPTER_ID = "adapter.advanced_web.loopback"
_NORMALIZER_ID = "advanced_web.raw_message.normalizer"
CaseId = Literal["ambiguous", "malformed", "negative"]
FramingClassification = Literal[
    "conflicting_content_length",
    "transfer_encoding_with_content_length",
    "duplicate_identical_content_length",
    "malformed_content_length",
    "body_shorter_than_content_length",
    "body_longer_than_content_length",
    "malformed_header",
    "malformed_request_line",
    "well_formed",
]


class ReadOnlyRawMessage(Protocol):
    """A transcript obtained by a read-only source, never a send primitive."""

    @property
    def url(self) -> str: ...

    @property
    def body(self) -> bytes: ...


class RawMessageObservationSource(Protocol):
    def read(self, case_id: CaseId) -> ReadOnlyRawMessage: ...


@dataclass(frozen=True)
class RawMessageEvidence:
    normalized_observation: NormalizedObservation
    case_id: CaseId
    request_method: str | None
    request_target: str | None
    framing: FramingClassification
    canonical_content_length: int | None
    raw_request_bytes: int
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    candidate_only: Literal[True] = True


@dataclass(frozen=True)
class RawMessageVerdict:
    classification: Literal["candidate_only", "negative_control"]
    verified: Literal[False] = False
    gateway_required: Literal[True] = True


@dataclass(frozen=True)
class RawMessageRun:
    evidence: RawMessageEvidence
    verdict: RawMessageVerdict


def observe_raw_message(
    source: RawMessageObservationSource, case_id: CaseId
) -> RawMessageRun:
    """Normalize one supplied transcript without sending it anywhere.

    Any future follow-up based on this evidence must be compiled and dispatched
    by the Gateway; this module has no action compiler or network client.
    """

    evidence = normalize_raw_message(case_id, source.read(case_id))
    if evidence.classification == "matched_negative_control":
        return RawMessageRun(evidence, RawMessageVerdict("negative_control"))
    return RawMessageRun(evidence, RawMessageVerdict("candidate_only"))


def normalize_raw_message(
    case_id: CaseId, response: ReadOnlyRawMessage
) -> RawMessageEvidence:
    """Classify HTTP/1.x framing without interpreting it as an executable request."""

    request_line, header_lines, body, has_header_terminator = _split_message(
        response.body
    )
    method, target, request_line_valid = _parse_request_line(request_line)
    framing, content_length = _classify_framing(
        header_lines, body, request_line_valid and has_header_terminator
    )
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    classification = (
        "matched_negative_control"
        if framing in {"duplicate_identical_content_length", "well_formed"}
        else "diagnostic_candidate"
    )
    return RawMessageEvidence(
        normalized_observation=NormalizedObservation(
            schema_version=SCHEMA_VERSION,
            adapter_id=_ADAPTER_ID,
            normalizer_id=_NORMALIZER_ID,
            observation_id=f"observation.raw-message.{case_id}",
            source_digest=_digest(response.body),
        ),
        case_id=case_id,
        request_method=method,
        request_target=target,
        framing=framing,
        canonical_content_length=content_length,
        raw_request_bytes=len(response.body),
        classification=classification,
    )


def _split_message(
    raw_message: bytes,
) -> tuple[bytes, tuple[bytes, ...], bytes, bool]:
    header_block, separator, body = raw_message.partition(b"\r\n\r\n")
    lines = tuple(header_block.split(b"\r\n"))
    if not lines:
        return b"", (), body, bool(separator)
    return lines[0], lines[1:], body, bool(separator)


def _parse_request_line(request_line: bytes) -> tuple[str | None, str | None, bool]:
    try:
        method, target, version = request_line.decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError):
        return None, None, False
    if not method.isalpha() or not target.startswith("/") or version != "HTTP/1.1":
        return None, None, False
    return method, target, True


def _classify_framing(
    header_lines: tuple[bytes, ...], body: bytes, request_is_valid: bool
) -> tuple[FramingClassification, int | None]:
    if not request_is_valid:
        return "malformed_request_line", None
    content_lengths: list[str] = []
    transfer_encoding_present = False
    for header_line in header_lines:
        try:
            name, value = header_line.split(b":", 1)
            name_text = name.decode("ascii")
            value_text = value.decode("ascii").strip()
        except (UnicodeDecodeError, ValueError):
            return "malformed_header", None
        if not name_text or not _is_header_name(name_text):
            return "malformed_header", None
        if name_text.casefold() == "content-length":
            content_lengths.append(value_text)
        if name_text.casefold() == "transfer-encoding":
            transfer_encoding_present = True

    if any(not value.isdecimal() for value in content_lengths):
        return "malformed_content_length", None
    parsed_lengths = tuple(int(value) for value in content_lengths)
    if transfer_encoding_present and parsed_lengths:
        return "transfer_encoding_with_content_length", None
    if len(set(parsed_lengths)) > 1:
        return "conflicting_content_length", None
    if parsed_lengths and len(body) < parsed_lengths[0]:
        return "body_shorter_than_content_length", parsed_lengths[0]
    if parsed_lengths and len(body) > parsed_lengths[0]:
        return "body_longer_than_content_length", parsed_lengths[0]
    if len(parsed_lengths) > 1:
        return "duplicate_identical_content_length", parsed_lengths[0]
    if parsed_lengths:
        return "well_formed", parsed_lengths[0]
    return "well_formed", None


def _is_header_name(value: str) -> bool:
    return all(
        character.isalnum() or character in "!#$%&'*+-.^_`|~"
        for character in value
    )


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"
