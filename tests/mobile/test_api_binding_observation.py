from pathlib import Path
from typing import Never

import pytest

from faultloom_mobile import mobile_manifest, observe_mobile_api_binding
from labs.mobile_api import LoopbackMobileApiBindingFixture


def test_mobile_manifest_is_observation_only() -> None:
    manifest = mobile_manifest()

    assert manifest.pack_id == "pack.mobile"
    assert manifest.action_compilers == ()
    assert manifest.required_gateway_features == ()
    assert manifest.required_adapter_capabilities == ()
    assert manifest.observation_normalizers == ("mobile.api_binding.normalizer",)


def test_deep_link_api_audience_mismatch_stays_gateway_bound_candidate() -> None:
    with LoopbackMobileApiBindingFixture() as fixture:
        run = observe_mobile_api_binding(fixture, "mismatch")
        fixture.assert_read_only_loopback()

    evidence = run.evidence
    assert evidence.app_link_scheme == "fixture"
    assert evidence.app_link_application_id == "com.fixture.mobile"
    assert evidence.declared_api_audience == "mobile.client.public"
    assert evidence.observed_api_audience == "mobile.client.private"
    assert not evidence.audience_matches
    assert evidence.classification == "diagnostic_candidate"
    assert evidence.candidate_only
    assert evidence.normalized_observation.source_digest.startswith("sha256:")
    assert run.verdict.classification == "candidate_only"
    assert not run.verdict.verified
    assert run.verdict.gateway_required
    assert fixture.requests == (
        ("GET", "/mismatch/app-link"),
        ("GET", "/mismatch/api-binding"),
    )


def test_matching_audience_is_a_matched_negative_control() -> None:
    with LoopbackMobileApiBindingFixture() as fixture:
        run = observe_mobile_api_binding(fixture, "negative")
        fixture.assert_read_only_loopback()

    assert run.evidence.audience_matches
    assert run.evidence.classification == "matched_negative_control"
    assert run.verdict.classification == "negative_control"
    assert not run.verdict.verified
    assert run.verdict.gateway_required
    assert fixture.requests == (
        ("GET", "/negative/app-link"),
        ("GET", "/negative/api-binding"),
    )


def test_observer_propagates_source_boundary_failure_before_evidence() -> None:
    class RejectedSource:
        def read(self, case_id: str, evidence: str) -> Never:
            _ = (case_id, evidence)
            raise ValueError("mobile/API fixture permits only loopback HTTP")

    with pytest.raises(ValueError, match="only loopback HTTP"):
        _ = observe_mobile_api_binding(RejectedSource(), "mismatch")


def test_pack_source_has_no_device_or_network_execution_imports() -> None:
    source_root = Path(__file__).resolve().parents[2] / "packs" / "mobile" / "src"
    source = "\n".join(path.read_text() for path in source_root.rglob("*.py"))

    for forbidden in ("urllib.request", "socket", "subprocess", "adb"):
        assert forbidden not in source
