from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from faultloom import cli
from faultloom.automation.models import AuthorizedAutomationResult
from faultloom.tool_planner import (
    PlanningBudget,
    ToolCandidate,
    ToolEstimate,
    ToolEvidenceRole,
    ToolPlan,
    ToolPlanItem,
    ToolPlanReceipt,
)
from faultloom_protocol import ActionClass, canonical_json, sha256_digest

from tests.protocol.factories import sample_models
from tests.runtime.test_personal_campaign import (
    _campaign_run_arguments,
    _listener,
    _request,
    _serve,
    _spec,
    _workspace,
)


def _prepare_arguments(
    workspace: Path, key: Path, template: Path, result: Path, receipt: Path, out: Path, *, candidate_id: str = "candidate.triad"
) -> list[str]:
    return [
        "campaign", "prepare-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--template", str(template), "--result", str(result), "--receipt", str(receipt),
        "--candidate-id", candidate_id, "--out", str(out),
    ]


def _bundle(workspace: Path, key: Path, template: Path, port: int) -> tuple[Path, Path]:
    # Reuse the live verifier to obtain the typed authority, instead of trusting test JSON.
    verified_manifest, typed_grant, target, _ = cli._verified_request_workspace(
        workspace, key
    )
    effect = (template.parent / "effect.raw").read_bytes()
    source = sample_models()["ActionIntent"]
    intent = source.model_copy(
        update={
            "run_id": verified_manifest["run_id"], "target_id": target.target_id,
            "pack_id": verified_manifest["pack_id"], "action_class": ActionClass.SAFE_PROBE,
            "protocol": "http", "method": "GET", "path": "/api/effect",
            "payload_digest": "sha256:" + hashlib.sha256(effect).hexdigest(),
            "resource": source.resource.model_copy(update={"target_id": target.target_id}),
        }
    )
    candidate = ToolCandidate(
        candidate_id="candidate.triad", hypothesis_id="hypothesis.triad", intent=intent,
        adapter_id="adapter.triad", capability="capability.triad", expected_information_gain_bps=1,
        estimate=ToolEstimate(rate_slots=1, duration_seconds=1, bytes=1, concurrency=1, actions=1, cost_microunits=0),
    )
    item = ToolPlanItem(
        candidate=candidate, evidence_role=ToolEvidenceRole.CANDIDATE,
        receipt=ToolPlanReceipt(
            candidate_id=candidate.candidate_id, candidate_digest=sha256_digest(candidate.model_dump(mode="json")),
            hypothesis_id=candidate.hypothesis_id, hypothesis_digest="sha256:" + "1" * 64,
            authority_digest="sha256:" + "2" * 64, adapter_id=candidate.adapter_id,
            manifest_digest="sha256:" + "3" * 64, admission_snapshot_digest="sha256:" + "4" * 64,
            utility_receipt_digest="sha256:" + "5" * 64, budget_digest="sha256:" + "6" * 64,
        ),
    )
    result = AuthorizedAutomationResult(
        run_id=verified_manifest["run_id"], authority_grant_id=typed_grant.grant_id,
        authority_grant_version=typed_grant.grant_version, authority_grant_digest=sha256_digest(typed_grant),
        observation_bundle_digest="sha256:" + "7" * 64, action_context_digest="sha256:" + "8" * 64,
        hypotheses=(), negative_results=(),
        admitted_plans=(ToolPlan(hypothesis_id=candidate.hypothesis_id, selected=item, remaining=PlanningBudget(rate_slots=0, duration_seconds=0, bytes=0, concurrency=0, actions=0, cost_microunits=0)),),
        stop_reason="Await independent verification.", provider_network_access="none",
    )
    result_path = template.parent / "result.json"
    receipt_path = template.parent / "receipt.json"
    result_path.write_text(canonical_json(result.model_dump(mode="json")), encoding="utf-8")
    result_digest = sha256_digest(result.model_dump(mode="json"))
    receipt_path.write_text(canonical_json({
        "schema": "faultloom.automation.result.receipt.v1", "automatic_submission": False,
        "candidate_digest": None, "candidate_only": True, "entry_id": "result.test",
        "evidence_existence_independently_verified": False, "independent_verification": False,
        "network_access": "none", "result_digest": result_digest, "target_dispatch": False,
    }), encoding="utf-8")
    return result_path, receipt_path


def test_prepared_candidate_runs_exactly_three_and_preserves_provenance(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    capsys.readouterr()
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["status"] == "review_required"
    captured: list[bytes] = []
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, captured)
    assert cli.main(_campaign_run_arguments(workspace, key, bound)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    assert captured == [_request(port, "/api/effect"), _request(port, "/api/effect"), _request(port, "/api/control")]
    run = json.loads(capsys.readouterr().out)
    start = json.loads(Path(run["startRecord"]).read_text(encoding="utf-8"))
    assert start["automation_binding"]["candidate_id"] == "candidate.triad"
    assert "automation_binding_digest" in start
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_OK
    final = json.loads(Path(json.loads(capsys.readouterr().out)["receipt"]).read_text(encoding="utf-8"))
    assert final["automation_binding_digest"] == start["automation_binding_digest"]
    assert final["automation_binding"] == start["automation_binding"]


@pytest.mark.parametrize("source", ("result", "receipt", "template", "request"))
def test_bound_source_tamper_fails_before_socket(tmp_path: Path, source: str) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    if source == "result":
        result.write_text(result.read_text(encoding="utf-8") + " ", encoding="utf-8")
    elif source == "receipt":
        receipt.write_text(receipt.read_text(encoding="utf-8") + " ", encoding="utf-8")
    elif source == "template":
        template.write_text(template.read_text(encoding="utf-8") + " ", encoding="utf-8")
    else:
        (tmp_path / "effect.raw").write_bytes(_request(port, "/api/effect?changed=1"))
    assert cli.main(_campaign_run_arguments(workspace, key, bound)) == cli.EXIT_AUTHORITY
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_prepare_rejects_unknown_candidate_without_writing_spec(tmp_path: Path) -> None:
    listener, port = _listener()
    listener.close()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound, candidate_id="candidate.unknown")) == cli.EXIT_AUTHORITY
    assert not bound.exists()


@pytest.mark.parametrize("mutation", ("intent_path", "result_run"))
def test_model_candidate_cannot_override_template_or_workspace(mutation: str, tmp_path: Path) -> None:
    listener, port = _listener()
    listener.close()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result_path, receipt_path = _bundle(workspace, key, template, port)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    if mutation == "intent_path":
        value["admitted_plans"][0]["selected"]["candidate"]["intent"]["path"] = "/api/control"
        value["admitted_plans"][0]["selected"]["receipt"]["candidate_digest"] = sha256_digest(
            value["admitted_plans"][0]["selected"]["candidate"]
        )
    else:
        value["run_id"] = "run.other"
    result = AuthorizedAutomationResult.model_validate_json(json.dumps(value))
    result_path.write_text(canonical_json(result.model_dump(mode="json")), encoding="utf-8")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["result_digest"] = sha256_digest(result.model_dump(mode="json"))
    receipt_path.write_text(canonical_json(receipt), encoding="utf-8")
    bound = tmp_path / "bound.json"
    assert cli.main(_prepare_arguments(workspace, key, template, result_path, receipt_path, bound)) == cli.EXIT_AUTHORITY
    assert not bound.exists()


def test_finalization_revalidates_v2_sources(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    capsys.readouterr()
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    capsys.readouterr()
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    assert cli.main(_campaign_run_arguments(workspace, key, bound)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    result.write_text(result.read_text(encoding="utf-8") + " ", encoding="utf-8")
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_AUTHORITY
    assert not list((workspace / "campaigns").glob("*.final-receipt.json"))
