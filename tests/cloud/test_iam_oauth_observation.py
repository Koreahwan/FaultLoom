import json

import pytest

from faultloom_cloud import cloud_iam_oauth_manifest, observe_cloud_trust
from labs.cloud_iam_oauth import LoopbackCloudTrustFixture


def test_cloud_manifest_is_observation_only_and_gateway_bound_for_future_followup() -> None:
    manifest = cloud_iam_oauth_manifest()

    assert manifest.pack_id == "pack.cloud.iam_oauth"
    assert manifest.action_compilers == ()
    assert manifest.verifier_descriptors == ()
    assert manifest.observation_normalizers == ("cloud.iam_oauth.trust_path.normalizer",)
    assert manifest.required_gateway_features == (
        "gateway.action_lease",
        "gateway.scope_epoch",
        "gateway.target_egress",
    )


def test_iam_trust_mismatch_and_sensitive_privilege_path_stay_candidate_only() -> None:
    with LoopbackCloudTrustFixture() as fixture:
        run = observe_cloud_trust(fixture, "iam-trust-mismatch")
        fixture.assert_read_only_loopback()

    evidence = run.evidence
    assert evidence.surface == "iam"
    assert evidence.issuer_matches
    assert not evidence.subject_matches
    assert evidence.candidate_reasons == (
        "subject_binding_mismatch",
        "privilege_path_to_sensitive_role",
    )
    assert evidence.classification == "diagnostic_candidate"
    assert evidence.candidate_only
    assert evidence.normalized_observation.source_digest.startswith("sha256:")
    assert run.verdict.classification == "candidate_only"
    assert not run.verdict.verified
    assert run.verdict.gateway_required_for_followup
    assert fixture.requests == (("GET", "/iam-trust-mismatch"),)


def test_oauth_redirect_mismatch_and_sensitive_path_stay_candidate_only() -> None:
    with LoopbackCloudTrustFixture() as fixture:
        run = observe_cloud_trust(fixture, "oauth-redirect-mismatch")
        fixture.assert_read_only_loopback()

    evidence = run.evidence
    assert evidence.surface == "oauth"
    assert not evidence.redirect_uri_matches
    assert evidence.candidate_reasons == (
        "oauth_redirect_mismatch",
        "privilege_path_to_sensitive_role",
    )
    assert evidence.classification == "diagnostic_candidate"
    assert run.verdict.classification == "candidate_only"
    assert not run.verdict.verified


@pytest.mark.parametrize("case_id", ["iam-matched-negative", "oauth-matched-negative"])
def test_matched_controls_have_no_candidate_reason_or_verification(
    case_id: str,
) -> None:
    with LoopbackCloudTrustFixture() as fixture:
        run = observe_cloud_trust(fixture, case_id)  # type: ignore[arg-type]
        fixture.assert_read_only_loopback()

    assert run.evidence.classification == "matched_negative_control"
    assert run.evidence.candidate_reasons == ()
    assert run.verdict.classification == "negative_control"
    assert not run.verdict.verified
    assert run.verdict.gateway_required_for_followup


def test_credential_or_token_material_is_rejected_before_candidate_creation() -> None:
    class CredentialBearingSource:
        url = "http://127.0.0.1/owned-fixture"
        body = (
            b'{"surface":"iam","token_material_present":true,'
            b'"issuer_matches":true,"subject_matches":true,'
            b'"audience_matches":true,"redirect_uri_matches":true,'
            b'"privilege_path":["principal:fixture","role:storage-viewer"]}'
        )

    class Source:
        def read(self, _case_id: object) -> CredentialBearingSource:
            return CredentialBearingSource()

    with pytest.raises(ValueError, match="must not contain token material"):
        observe_cloud_trust(Source(), "iam-matched-negative")


@pytest.mark.parametrize("hidden_field", ["access_token", "credentials", "unknown"])
def test_unknown_or_hidden_credential_fields_are_rejected_even_with_false_token_flag(
    hidden_field: str,
) -> None:
    class HiddenFieldSource:
        url = "http://127.0.0.1/owned-fixture"
        body = json.dumps(
            {
                "surface": "iam",
                "token_material_present": False,
                "issuer_matches": True,
                "subject_matches": True,
                "audience_matches": True,
                "redirect_uri_matches": True,
                "privilege_path": ["principal:fixture", "role:storage-viewer"],
                hidden_field: "not-accepted",
            }
        ).encode()

    class Source:
        def read(self, _case_id: object) -> HiddenFieldSource:
            return HiddenFieldSource()

    with pytest.raises(ValueError, match="contains unsupported fields"):
        observe_cloud_trust(Source(), "iam-matched-negative")
