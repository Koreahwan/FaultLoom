from dataclasses import dataclass
from typing import final

from faultloom_advanced_web import advanced_web_manifest, observe_raw_message
from labs.raw_message import LoopbackRawMessageFixture


@dataclass(frozen=True)
class StaticTranscript:
    url: str
    body: bytes


@final
class StaticTranscriptSource:
    _body: bytes

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, case_id: object) -> StaticTranscript:
        _ = case_id
        return StaticTranscript(url="fixture://raw-message", body=self._body)


def test_advanced_web_manifest_declares_raw_message_as_observation_only() -> None:
    manifest = advanced_web_manifest()

    assert manifest.action_compilers == ()
    assert "advanced_web.raw_message_readonly" in manifest.capability_descriptors
    assert "advanced_web.raw_message.normalizer" in manifest.observation_normalizers
    assert manifest.required_gateway_features == ()


def test_conflicting_content_lengths_become_gateway_bound_candidate_evidence() -> None:
    with LoopbackRawMessageFixture() as fixture:
        run = observe_raw_message(fixture, "ambiguous")
        fixture.assert_read_only_loopback()

    evidence = run.evidence
    assert evidence.request_method == "POST"
    assert evidence.request_target == "/probe"
    assert evidence.framing == "conflicting_content_length"
    assert evidence.canonical_content_length is None
    assert evidence.classification == "diagnostic_candidate"
    assert evidence.candidate_only
    assert evidence.normalized_observation.normalizer_id == "advanced_web.raw_message.normalizer"
    assert evidence.normalized_observation.source_digest.startswith("sha256:")
    assert run.verdict.classification == "candidate_only"
    assert not run.verdict.verified
    assert run.verdict.gateway_required
    assert fixture.requests == (("GET", "/ambiguous"),)


def test_malformed_header_is_normalized_without_any_dispatch() -> None:
    with LoopbackRawMessageFixture() as fixture:
        run = observe_raw_message(fixture, "malformed")
        fixture.assert_read_only_loopback()

    assert run.evidence.framing == "malformed_header"
    assert run.evidence.classification == "diagnostic_candidate"
    assert run.verdict.classification == "candidate_only"
    assert run.verdict.gateway_required
    assert fixture.requests == (("GET", "/malformed"),)


def test_identical_duplicate_content_lengths_are_a_matched_negative_control() -> None:
    with LoopbackRawMessageFixture() as fixture:
        run = observe_raw_message(fixture, "negative")
        fixture.assert_read_only_loopback()

    assert run.evidence.framing == "duplicate_identical_content_length"
    assert run.evidence.canonical_content_length == 4
    assert run.evidence.classification == "matched_negative_control"
    assert run.verdict.classification == "negative_control"
    assert not run.verdict.verified
    assert run.verdict.gateway_required


def test_body_shorter_than_fixed_content_length_stays_candidate_only() -> None:
    run = observe_raw_message(
        StaticTranscriptSource(
            b"POST /probe HTTP/1.1\r\nHost: fixture\r\nContent-Length: 8\r\n\r\nPING"
        ),
        "negative",
    )

    assert run.evidence.framing == "body_shorter_than_content_length"
    assert run.evidence.canonical_content_length == 8
    assert run.evidence.classification == "diagnostic_candidate"
    assert run.verdict.classification == "candidate_only"
    assert run.verdict.gateway_required


def test_extra_bytes_after_fixed_content_length_stay_candidate_only() -> None:
    run = observe_raw_message(
        StaticTranscriptSource(
            b"POST /probe HTTP/1.1\r\nHost: fixture\r\nContent-Length: 4\r\n\r\nPINGEXTRA"
        ),
        "negative",
    )

    assert run.evidence.framing == "body_longer_than_content_length"
    assert run.evidence.canonical_content_length == 4
    assert run.evidence.classification == "diagnostic_candidate"
    assert run.verdict.classification == "candidate_only"
    assert run.verdict.gateway_required
