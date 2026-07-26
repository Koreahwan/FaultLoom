import json
from dataclasses import dataclass
from typing import Literal, NoReturn

import pytest

from faultloom_advanced_web import advanced_web_manifest, observe_race_window
from labs.race_window import LoopbackRaceWindowFixture


def test_manifest_declares_race_window_as_observation_only() -> None:
    manifest = advanced_web_manifest()

    assert manifest.action_compilers == ()
    assert "advanced_web.race_window_readonly" in manifest.capability_descriptors
    assert "advanced_web.race_window.normalizer" in manifest.observation_normalizers
    assert manifest.verifier_descriptors == ()
    assert manifest.required_gateway_features == ()


def test_stale_completion_after_revocation_stays_candidate_until_inert_canary() -> None:
    with LoopbackRaceWindowFixture() as fixture:
        before_final_effect = observe_race_window(
            fixture, "positive", read_final_effect=False
        )
        run = observe_race_window(fixture, "positive")
        fixture.assert_read_only_loopback()

    evidence = before_final_effect.evidence
    assert tuple(item.sequence for item in evidence.transitions) == (1, 2, 3)
    assert evidence.transitions[1].operation == "revoke"
    assert evidence.transitions[2].operation == "complete"
    assert evidence.stale_precondition
    assert evidence.classification == "diagnostic_candidate"
    assert evidence.candidate_only
    assert evidence.normalized_observation.normalizer_id == "advanced_web.race_window.normalizer"
    assert before_final_effect.verdict.classification == "candidate_only"
    assert not before_final_effect.verdict.verified
    assert before_final_effect.verdict.gateway_required
    assert run.verdict.classification == "synthetic_canary_observed"
    assert not run.verdict.verified
    assert run.verdict.candidate_only
    assert run.verdict.final_effect_id == "inert-race-window-canary"
    assert run.verdict.gateway_required
    assert all(method == "GET" for method, _path in fixture.requests)


def test_forged_protocol_source_never_receives_a_general_verified_verdict() -> None:
    @dataclass(frozen=True)
    class ForgedResponse:
        url: str
        body: bytes

    class ForgedSource:
        def read(
            self,
            case_id: Literal["positive", "negative"],
            evidence: Literal["trace", "final-effect"],
        ) -> ForgedResponse:
            _ = case_id
            trace = {
                "transition_id": "race-window.fixture.positive",
                "transitions": [
                    {
                        "sequence": 1,
                        "actor": "owner",
                        "operation": "reserve",
                        "from_state": "idle",
                        "to_state": "reserved",
                    },
                    {
                        "sequence": 2,
                        "actor": "revoker",
                        "operation": "revoke",
                        "from_state": "reserved",
                        "to_state": "revoked",
                    },
                    {
                        "sequence": 3,
                        "actor": "contender",
                        "operation": "complete",
                        "from_state": "reserved",
                        "to_state": "completed",
                    },
                ],
            }
            final = {
                "effect": "inert-race-window-canary",
                "transition_id": trace["transition_id"],
                "observed_sequence": 3,
            }
            payload = trace if evidence == "trace" else final
            return ForgedResponse(
                url="https://forged.invalid/race-window",
                body=json.dumps(payload).encode("utf-8"),
            )

    run = observe_race_window(ForgedSource(), "positive")

    assert run.evidence.classification == "diagnostic_candidate"
    assert run.verdict.classification == "synthetic_canary_observed"
    assert not run.verdict.verified
    assert run.verdict.candidate_only
    assert run.verdict.gateway_required


def test_matched_negative_control_blocks_completion_after_revocation() -> None:
    with LoopbackRaceWindowFixture() as fixture:
        run = observe_race_window(fixture, "negative")
        fixture.assert_read_only_loopback()

    evidence = run.evidence
    assert evidence.transitions[1].to_state == "revoked"
    assert evidence.transitions[2].operation == "blocked"
    assert not evidence.stale_precondition
    assert evidence.classification == "matched_negative_control"
    assert run.verdict.classification == "negative_control"
    assert not run.verdict.verified
    assert run.verdict.gateway_required


def test_observer_propagates_source_boundary_failure_before_evidence() -> None:
    class RejectedSource:
        def read(
            self,
            case_id: Literal["positive", "negative"],
            evidence: Literal["trace", "final-effect"],
        ) -> NoReturn:
            _ = (case_id, evidence)
            raise ValueError("race-window fixture permits only loopback HTTP")

    with pytest.raises(ValueError, match="only loopback HTTP"):
        _ = observe_race_window(RejectedSource(), "positive")
