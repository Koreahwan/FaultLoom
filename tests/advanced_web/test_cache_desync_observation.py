import os
from pathlib import Path
import subprocess
import sys

import pytest

from faultloom_advanced_web import advanced_web_manifest, observe_cache_desync
from labs.cache_desync import LoopbackCacheDesyncFixture
from labs.cache_desync.fixture import FixtureResponse


def test_advanced_web_manifest_is_observation_only() -> None:
    manifest = advanced_web_manifest()

    assert manifest.pack_id == "pack.advanced_web"
    assert manifest.action_compilers == ()
    assert "advanced_web.cache_desync.normalizer" in manifest.observation_normalizers
    assert manifest.verifier_descriptors == ()
    assert manifest.required_gateway_features == ()


def test_stale_epoch_signal_stays_candidate_until_read_only_final_effect() -> None:
    with LoopbackCacheDesyncFixture() as fixture:
        before_final_effect = observe_cache_desync(
            fixture, "positive", read_final_effect=False
        )
        run = observe_cache_desync(fixture, "positive")
        fixture.assert_read_only_loopback()

    evidence = before_final_effect.evidence
    assert evidence.classification == "diagnostic_candidate"
    assert evidence.epoch_mismatch
    assert evidence.normalized_observation.normalizer_id == "advanced_web.cache_desync.normalizer"
    assert evidence.normalized_observation.source_digest.startswith("sha256:")
    assert before_final_effect.verdict.classification == "candidate_only"
    assert run.verdict.classification == "candidate_only"
    assert all(method == "GET" for method, _path in fixture.requests)


def test_matched_negative_control_has_stale_cache_signal_but_no_verified_effect() -> None:
    with LoopbackCacheDesyncFixture() as fixture:
        run = observe_cache_desync(fixture, "negative")
        fixture.assert_read_only_loopback()

    evidence = run.evidence
    assert evidence.stale_cache_hit
    assert evidence.stale_age == 120
    assert not evidence.epoch_mismatch
    assert evidence.classification == "matched_negative_control"
    assert run.verdict.classification == "negative_control"


def test_observer_propagates_source_boundary_failure_before_evidence() -> None:
    class RejectedSource:
        def read(self, *_args: object) -> object:
            raise ValueError("cache/desync fixture permits only loopback HTTP")

    with pytest.raises(ValueError, match="only loopback HTTP"):
        observe_cache_desync(RejectedSource(), "positive")  # type: ignore[arg-type]


def test_forged_protocol_shaped_source_stays_candidate_only() -> None:
    class ForgedSource:
        def read(
            self, _case_id: object, evidence: str
        ) -> FixtureResponse:
            if evidence == "stale":
                return FixtureResponse(
                    "http://127.0.0.1/positive/stale",
                    b'{"canary":"inert-cache-desync","revision":"epoch-41"}',
                    (("Age", "120"), ("X-Cache", "HIT"), ("X-Fixture-Epoch", "41")),
                )
            if evidence == "fresh":
                return FixtureResponse(
                    "http://127.0.0.1/positive/fresh",
                    b'{"canary":"inert-cache-desync","revision":"epoch-42"}',
                    (("Age", "0"), ("X-Cache", "MISS"), ("X-Fixture-Epoch", "42")),
                )
            return FixtureResponse(
                "http://127.0.0.1/positive/final-effect",
                b'{"effect":"inert-cache-desync-canary","observed_epoch":42}',
                (("X-Final-Effect", "inert-cache-desync-canary"),),
            )

    run = observe_cache_desync(ForgedSource(), "positive")  # type: ignore[arg-type]

    assert run.evidence.classification == "diagnostic_candidate"
    assert run.verdict.classification == "candidate_only"


def test_pack_import_does_not_depend_on_labs_from_tmp() -> None:
    root = Path(__file__).resolve().parents[2]
    protocol = root / "packages" / "protocol" / "src"
    sdk = root / "packages" / "sdk" / "src"
    pack = root / "packs" / "advanced_web" / "src"
    script = "\n".join(
        (
            "import sys",
            f"sys.path[:0] = {([str(protocol), str(sdk), str(pack)])!r}",
            "import faultloom_advanced_web.cache_desync",
        )
    )
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    result = subprocess.run(
        (sys.executable, "-c", script),
        cwd="/tmp",
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
