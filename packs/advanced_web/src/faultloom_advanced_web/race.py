"""Normalize a bounded race-window transcript as observation-only evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from faultloom_protocol import SCHEMA_VERSION
from faultloom_sdk import NormalizedObservation

_ADAPTER_ID = "adapter.advanced_web.loopback"
_NORMALIZER_ID = "advanced_web.race_window.normalizer"
_FINAL_EFFECT = "inert-race-window-canary"
CaseId = Literal["positive", "negative"]


class ReadOnlyRaceWindowResponse(Protocol):
    """A fixed transcript read from an owned source, never a dispatch primitive."""

    @property
    def url(self) -> str: ...

    @property
    def body(self) -> bytes: ...


class RaceWindowObservationSource(Protocol):
    def read(
        self, case_id: CaseId, evidence: Literal["trace", "final-effect"]
    ) -> ReadOnlyRaceWindowResponse: ...


@dataclass(frozen=True)
class RaceTransition:
    sequence: int
    actor: str
    operation: str
    from_state: str
    to_state: str


@dataclass(frozen=True)
class RaceWindowEvidence:
    normalized_observation: NormalizedObservation
    case_id: CaseId
    transition_id: str
    transitions: tuple[RaceTransition, ...]
    revocation_sequence: int
    contender_sequence: int
    stale_precondition: bool
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    candidate_only: Literal[True] = True


@dataclass(frozen=True)
class RaceWindowVerdict:
    classification: Literal[
        "candidate_only", "synthetic_canary_observed", "negative_control"
    ]
    final_effect_id: str | None
    verified: Literal[False] = False
    candidate_only: Literal[True] = True
    gateway_required: Literal[True] = True


@dataclass(frozen=True)
class RaceWindowRun:
    evidence: RaceWindowEvidence
    verdict: RaceWindowVerdict


def observe_race_window(
    source: RaceWindowObservationSource,
    case_id: CaseId,
    *,
    read_final_effect: bool = True,
) -> RaceWindowRun:
    """Read one bounded transcript and optional inert canary without dispatching."""

    trace = source.read(case_id, "trace")
    evidence = normalize_race_window(case_id, trace)
    final = source.read(case_id, "final-effect") if read_final_effect else None
    return RaceWindowRun(evidence, verify_race_final_effect(evidence, final))


def normalize_race_window(
    case_id: CaseId, response: ReadOnlyRaceWindowResponse
) -> RaceWindowEvidence:
    """Recognize a stale completion after a recorded revocation.

    The transcript has exactly three ordered, synthetic transitions. It is a
    candidate signal only: any future follow-up must be Gateway-dispatched.
    """

    transition_id, transitions = _parse_transcript(response.body)
    revocation, contender = transitions[1:]
    stale_precondition = (
        revocation.to_state == "revoked"
        and contender.operation == "complete"
        and contender.to_state == "completed"
        and contender.from_state != revocation.to_state
    )
    classification: Literal["diagnostic_candidate", "matched_negative_control"]
    classification = (
        "diagnostic_candidate" if stale_precondition else "matched_negative_control"
    )
    return RaceWindowEvidence(
        normalized_observation=NormalizedObservation(
            schema_version=SCHEMA_VERSION,
            adapter_id=_ADAPTER_ID,
            normalizer_id=_NORMALIZER_ID,
            observation_id=f"observation.race-window.{case_id}",
            source_digest=_digest(response.body),
        ),
        case_id=case_id,
        transition_id=transition_id,
        transitions=transitions,
        revocation_sequence=revocation.sequence,
        contender_sequence=contender.sequence,
        stale_precondition=stale_precondition,
        classification=classification,
    )


def verify_race_final_effect(
    evidence: RaceWindowEvidence,
    final: ReadOnlyRaceWindowResponse | None = None,
) -> RaceWindowVerdict:
    """Observe a separate inert canary without treating it as source attestation."""

    if evidence.classification != "diagnostic_candidate":
        return RaceWindowVerdict("negative_control", final_effect_id=None)
    if final is None:
        return RaceWindowVerdict("candidate_only", final_effect_id=None)
    payload = _parse_final_effect(final.body)
    if payload == {
        "effect": _FINAL_EFFECT,
        "transition_id": evidence.transition_id,
        "observed_sequence": evidence.contender_sequence,
    }:
        return RaceWindowVerdict(
            "synthetic_canary_observed", final_effect_id=_FINAL_EFFECT
        )
    return RaceWindowVerdict("candidate_only", final_effect_id=None)


def _parse_transcript(body: bytes) -> tuple[str, tuple[RaceTransition, ...]]:
    payload = _parse_json_object(body, "race-window transcript")
    if set(payload) != {"transition_id", "transitions"}:
        raise ValueError("race-window transcript fields are invalid")
    transition_id = payload["transition_id"]
    raw_transitions = payload["transitions"]
    if (
        not isinstance(transition_id, str)
        or not transition_id
        or not isinstance(raw_transitions, list)
    ):
        raise ValueError("race-window transcript shape is invalid")
    transitions = tuple(
        _parse_transition(cast(object, raw)) for raw in cast(list[object], raw_transitions)
    )
    if len(transitions) != 3 or tuple(item.sequence for item in transitions) != (1, 2, 3):
        raise ValueError("race-window transcript must contain the ordered 1,2,3 trace")
    if transitions[0].operation != "reserve" or transitions[1].operation != "revoke":
        raise ValueError("race-window transcript must reserve before revocation")
    return transition_id, transitions


def _parse_transition(raw: object) -> RaceTransition:
    if not isinstance(raw, dict):
        raise ValueError("race-window transition fields are invalid")
    fields = {
        key: cast(object, value) for key, value in raw.items() if isinstance(key, str)
    }
    if len(fields) != len(raw) or set(fields) != {
        "sequence",
        "actor",
        "operation",
        "from_state",
        "to_state",
    }:
        raise ValueError("race-window transition fields are invalid")
    sequence = fields["sequence"]
    actor = fields["actor"]
    operation = fields["operation"]
    from_state = fields["from_state"]
    to_state = fields["to_state"]
    if type(sequence) is not int:
        raise ValueError("race-window transition values are invalid")
    if not isinstance(actor, str) or not actor:
        raise ValueError("race-window transition values are invalid")
    if not isinstance(operation, str) or not operation:
        raise ValueError("race-window transition values are invalid")
    if not isinstance(from_state, str) or not from_state:
        raise ValueError("race-window transition values are invalid")
    if not isinstance(to_state, str) or not to_state:
        raise ValueError("race-window transition values are invalid")
    return RaceTransition(sequence, actor, operation, from_state, to_state)


def _parse_final_effect(body: bytes) -> dict[str, object]:
    return _parse_json_object(body, "race-window final effect")


def _parse_json_object(body: bytes, label: str) -> dict[str, object]:
    try:
        payload: object = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    result = {
        key: cast(object, value) for key, value in payload.items() if isinstance(key, str)
    }
    if len(result) != len(payload):
        raise ValueError(f"{label} must use string keys")
    return result


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"
