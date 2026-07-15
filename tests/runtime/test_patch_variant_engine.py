from __future__ import annotations

from faultloom.patch_variant import (
    AdvisorySourceKind,
    PatchArtifactKind,
    PatchState,
    VariantConfidence,
    VariantDimension,
)
from labs.patch_variant import load_patch_variant_manifest, replay_patch_variant_fixture


def test_deployment_matrix_never_treats_an_advisory_as_proof() -> None:
    manifest = load_patch_variant_manifest()
    expected = {
        "fixture.vulnerable": "reachable",
        "fixture.patched": "not_reachable",
        "fixture.backported": "not_reachable",
        "fixture.ambiguous": "ambiguous",
        "fixture.advisory-only": "not_reachable",
    }

    for case_id, conclusion in expected.items():
        result = replay_patch_variant_fixture(manifest, case_id)

        assert result.reachability.claim.conclusion == conclusion
        assert result.zero_day_claimed is False
        assert result.claim_status == "candidate_requires_independent_verification"

    advisory_only = replay_patch_variant_fixture(manifest, "fixture.advisory-only")
    assert advisory_only.reachability.component_present is False
    assert advisory_only.reachability.claim.conclusion == "not_reachable"


def test_fingerprint_uses_multiple_signals_and_preserves_backport_state() -> None:
    manifest = load_patch_variant_manifest()

    vulnerable = replay_patch_variant_fixture(manifest, "fixture.vulnerable")
    backported = replay_patch_variant_fixture(manifest, "fixture.backported")

    assert vulnerable.fingerprint.fingerprint.evidence_kinds == (
        "header",
        "behavior",
        "sbom",
    )
    assert vulnerable.fingerprint.version_hypotheses[0].confidence_bps == 10_000
    assert backported.fingerprint.version_hypotheses[0].backport_possible is True
    assert backported.reachability.patch_state is PatchState.BACKPORTED


def test_advisory_resolution_retains_every_offline_provenance_kind() -> None:
    result = replay_patch_variant_fixture(
        load_patch_variant_manifest(),
        "fixture.vulnerable",
    )

    sources = {item.source_kind for item in result.advisories[0].provenance}

    assert sources == {
        AdvisorySourceKind.OSV,
        AdvisorySourceKind.NVD,
        AdvisorySourceKind.VENDOR,
        AdvisorySourceKind.RELEASE_NOTE,
        AdvisorySourceKind.SECURITY_COMMIT,
    }
    assert result.advisories[0].match.security_commit == "a" * 40


def test_patch_diff_extracts_condition_invariant_sink_and_all_artifacts() -> None:
    result = replay_patch_variant_fixture(
        load_patch_variant_manifest(),
        "fixture.vulnerable",
    )

    kinds = {delta.kind for delta in result.patch.artifact_deltas}
    change = result.patch.invariant_changes[0]

    assert kinds == {
        PatchArtifactKind.SOURCE,
        PatchArtifactKind.CONFIG,
        PatchArtifactKind.TEST,
        PatchArtifactKind.API_BEHAVIOR,
    }
    assert change.changed_condition == "tenant_id == resource.tenant_id"
    assert change.invariant == "resource access is tenant-bound"
    assert change.sink_or_boundary == "resource lookup | tenant trust boundary"


def test_incomplete_fix_search_covers_all_dimensions_and_confidence_classes() -> None:
    result = replay_patch_variant_fixture(
        load_patch_variant_manifest(),
        "fixture.incomplete-fix",
    )

    confidences = {item.confidence for item in result.variants.assessments}
    dimensions = set(result.variants.search_dimensions)

    assert confidences == {
        VariantConfidence.EXACT,
        VariantConfidence.SIMILAR,
        VariantConfidence.SPECULATIVE,
    }
    assert dimensions == set(VariantDimension)
    assert any(item.black_box_differential for item in result.variants.assessments)
    assert any(
        item.hypothesis.variant_kind == "sibling_path"
        and item.hypothesis.confidence_class.value == "EXACT"
        for item in result.variants.assessments
    )


def test_adaptation_removes_unsafe_and_nonessential_steps() -> None:
    result = replay_patch_variant_fixture(
        load_patch_variant_manifest(),
        "fixture.vulnerable",
    )

    adaptation = result.adaptation
    recipe = adaptation.recipe

    assert len(adaptation.adaptation.removed_unsafe_step_digests) == 3
    assert adaptation.omitted_nonessential_step_ids == ("step.optional-banner",)
    assert len(recipe.steps) == 1
    assert recipe.steps[0].action_intent.action_class.value == "safe_probe"
    assert recipe.steps[0].action_intent.path == "/owned/canary"
    assert recipe.cleanup_plan_ref == "cleanup.canary-reset"
    assert recipe.negative_controls == ("patched route denies the inert canary",)


def test_clean_fixture_replay_is_deterministic_and_evidence_bound() -> None:
    manifest = load_patch_variant_manifest()

    first = replay_patch_variant_fixture(manifest, "fixture.incomplete-fix")
    second = replay_patch_variant_fixture(manifest, "fixture.incomplete-fix")

    assert first.model_dump_json() == second.model_dump_json()
    assert first.patch.patch_delta.evidence_refs
    assert first.variants.assessments[0].hypothesis.evidence_refs
    assert first.adaptation.recipe.evidence_refs
