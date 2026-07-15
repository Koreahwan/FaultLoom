from pathlib import Path

from faultloom_web.web_api import (
    WebApiRunFacade,
    compare_reset_stability,
    evaluate_web_api_run,
    verify_web_api_run,
    web_api_manifest,
)
from labs.web_api import web_api_fixture
from tests.runtime.resume_support import open_store


def test_web_api_manifest_declares_isolated_gateway_bound_descriptors() -> None:
    manifest = web_api_manifest()

    assert manifest.pack_id == "pack.web"
    assert manifest.process_isolation == "required"
    assert manifest.action_compilers == ("web.api.action_compiler",)
    assert manifest.observation_normalizers == (
        "web.api.observation_normalizer",
    )
    assert manifest.hypothesis_providers == (
        "web.api.bridge_hypothesis_provider",
    )
    assert manifest.verifier_descriptors == (
        "web.api.clean_chain_verifier",
    )
    assert manifest.evaluation_descriptors == (
        "web.api.integration_evaluator",
    )
    assert "gateway.target_egress" in manifest.required_gateway_features


def test_one_run_correlates_identity_async_chain_and_resumes_stably(
    tmp_path: Path,
) -> None:
    fixture = web_api_fixture()
    engagement_id = fixture.positive.surface.binding.engagement_id

    with open_store(tmp_path, engagement_id=engagement_id) as store:
        facade = WebApiRunFacade(store)
        initial = facade.run(fixture.positive)
        negative = facade.resume(fixture.negative)
        anchor = store.checkpoint()

    assert initial.chain_search.forward is not None
    assert initial.chain_search.forward.plan.edge_ids == (
        fixture.expected_chain_edge_id,
    )
    assert initial.correlation.completed_effect_ids == (
        fixture.expected_async_effect_id,
    )
    assert initial.hypotheses[0].identity_graph_id == "identity-graph.web-api"
    assert initial.hypotheses[0].async_flow_id == "async-flow.web-api.job"
    assert initial.compiled_intents[0].action_id == "action.web-api.observe-job"
    assert initial.normalized_observations[0].observation.observation_id == (
        "observation.web-api.job"
    )
    verification = verify_web_api_run(initial)
    assert verification.passed
    assert evaluate_web_api_run(initial, verification).verified

    assert negative.chain_search.forward is None
    assert tuple(
        item.missing_precondition for item in negative.chain_search.missing_links
    ) == ("effect.missing",)

    with open_store(
        tmp_path,
        engagement_id=engagement_id,
        minimum_anchor=anchor,
    ) as reopened:
        resumed = WebApiRunFacade(reopened).resume(fixture.positive)

    assert compare_reset_stability(initial, resumed).reset_stable
    assert resumed.correlation.completed_effect_ids == (
        fixture.expected_async_effect_id,
    )
