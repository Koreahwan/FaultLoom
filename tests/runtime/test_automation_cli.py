from __future__ import annotations

import hashlib
import json
import socket
import stat
from datetime import timedelta
from pathlib import Path

import pytest

from faultloom import cli
from faultloom.automation import (
    ActionContext,
    AutomationRequest,
    ModelDisclosureApproval,
    ObservationBundle,
    ObservationExcerpt,
    sign_model_disclosure_approval,
)
from faultloom.provider import provider_canonical_json_bytes
from faultloom_protocol import AuthorityGrant, AuthoritySigner, sign_authority_grant, sha256_digest
from faultloom.tool_planner import PlanningBudget
from tests.protocol.factories import NOW, sample_models


DISCLOSURE_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("42" * 32))
EXCERPT = "Owned observation: the response normalization differs."


def _workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, AuthorityGrant]:
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    source = sample_models()["AuthorityGrant"]
    grant = source.model_copy(
        update={
            "issued_at": NOW,
            "not_before": NOW,
            "expires_at": NOW + timedelta(hours=1),
            "pack_ids": ("pack.web",),
            "execution_windows": (
                source.execution_windows[0].model_copy(
                    update={"starts_at": NOW, "ends_at": NOW + timedelta(hours=1)}
                ),
            ),
        }
    )
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    authority = tmp_path / "authority.json"
    trusted_key = tmp_path / "trusted-key.json"
    authority.write_text(
        sign_authority_grant(grant, signer, signed_at=NOW).model_dump_json(),
        encoding="utf-8",
    )
    trusted_key.write_text(signer.public_key_record.model_dump_json(), encoding="utf-8")
    workspace = tmp_path / "workspace"
    assert (
        cli.main(
            [
                "run",
                "--authority",
                str(authority),
                "--trusted-key",
                str(trusted_key),
                "--target",
                grant.targets[0].target_id,
                "--pack",
                "web",
                "--workspace",
                str(workspace),
            ]
        )
        == cli.EXIT_OK
    )
    return workspace, trusted_key, grant


def _request(workspace: Path, grant: AuthorityGrant) -> AutomationRequest:
    source = sample_models()
    source_intent = source["ActionIntent"]
    evidence = source["EvidenceRef"].model_copy(
        update={"run_id": json.loads((workspace / "run.json").read_text())["run_id"]}
    )
    run_id = evidence.run_id
    content_digest = "sha256:" + hashlib.sha256(EXCERPT.encode()).hexdigest()
    disclosure = sign_model_disclosure_approval(
        ModelDisclosureApproval(
            approval_id="model-disclosure.compile-1",
            run_id=run_id,
            evidence_id=evidence.evidence_id,
            source_cas_digest=evidence.cas_digest,
            redaction_digest=evidence.redaction_digest,
            content_digest=content_digest,
            media_type="text/plain",
            data_policy_id=grant.provider_policy.data_policy_id,
            allowed_provider_ids=("provider.test",),
            approved_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            approver_key_id=DISCLOSURE_SIGNER.key_id,
        ),
        DISCLOSURE_SIGNER,
    )
    return AutomationRequest(
        observations=ObservationBundle(
            run_id=run_id,
            evidence_refs=(evidence,),
            excerpts=(
                ObservationExcerpt(
                    evidence_id=evidence.evidence_id,
                    media_type="text/plain",
                    content=EXCERPT,
                    content_digest=content_digest,
                    redacted=True,
                    untrusted=True,
                    model_disclosure_approved=True,
                    approval=disclosure,
                ),
            ),
            observed_experiment_digests=("sha256:" + "1" * 64,),
        ),
        issued_at=NOW,
        authority_grant=grant,
        planning_budget=PlanningBudget(
            rate_slots=3,
            duration_seconds=20,
            bytes=2_000,
            concurrency=2,
            actions=3,
            cost_microunits=100,
        ),
        action_context=ActionContext(
            run_id=run_id,
            target_id=source_intent.target_id,
            pack_id="pack.web",
            subject=source_intent.subject,
            resource=source_intent.resource,
            protocol=source_intent.protocol,
            method=source_intent.method,
            path=source_intent.path,
            payload_digest="sha256:" + "a" * 64,
            cleanup_plan_ref="cleanup.compile-1",
        ),
        provider_network_access="none",
    )


def _turn(request: AutomationRequest, *, action: bool = False, finding: bool = True) -> bytes:
    evidence_id = request.observations.evidence_refs[0].evidence_id
    document: dict[str, object] = {
        "hypotheses": [
            {
                "proposal_id": "hypothesis.compile-1",
                "statement": "The owned route has a bounded normalization difference.",
                "provenance": ["behavior"],
                "supporting_evidence_ids": [evidence_id],
                "contradicting_evidence_ids": [],
                "prerequisite_ids": ["identity.owner"],
            }
        ],
        "negative_results": [],
        "actions": [],
        "poc": None,
        "finding_draft": None,
        "stop_reason": "Await independent verification.",
    }
    if finding:
        document["finding_draft"] = {
            "hypothesis_proposal_id": "hypothesis.compile-1",
            "poc_recipe_id": None,
            "title": "Candidate sk-CompileSecretMarker1234567890",
            "severity": "low",
            "summary": "A candidate needs independent replay.",
            "impact": "No impact is verified yet.",
            "reproduction_steps": ["Replay the admitted candidate only."],
            "remediation": "Confirm independently before remediation.",
        }
    if action:
        document["actions"] = [
            {
                "candidate_id": "candidate.compile-1",
                "hypothesis_proposal_id": "hypothesis.compile-1",
                "adapter_id": "adapter.reference",
                "capability": "reference.digest_normalizer",
                "action_kind": "reference.digest",
                "action_class": "safe_probe",
                "expected_information_gain_bps": 7_000,
                "estimate": {
                    "rate_slots": 1,
                    "duration_seconds": 2,
                    "bytes": 200,
                    "concurrency": 1,
                    "cost_microunits": 1,
                },
            }
        ]
    return json.dumps(document).encode()


def _compile_arguments(workspace: Path, trusted_key: Path, request: Path, turn: Path) -> list[str]:
    return [
        "automation",
        "compile",
        "--workspace",
        str(workspace),
        "--trusted-key",
        str(trusted_key),
        "--request",
        str(request),
        "--model-turn",
        str(turn),
    ]


def _disclosure_key(path: Path) -> Path:
    path.write_text(DISCLOSURE_SIGNER.public_key_record.model_dump_json(), encoding="utf-8")
    return path


def _export_arguments(
    workspace: Path,
    trusted_key: Path,
    request: Path,
    out: Path,
    disclosure_keys: tuple[Path, ...],
    *,
    provider_id: str = "provider.test",
) -> list[str]:
    arguments = [
        "automation",
        "export-handoff",
        "--workspace",
        str(workspace),
        "--trusted-key",
        str(trusted_key),
        "--request",
        str(request),
        "--provider-id",
        provider_id,
        "--out",
        str(out),
    ]
    for disclosure_key in disclosure_keys:
        arguments.extend(("--trusted-disclosure-key", str(disclosure_key)))
    return arguments


def _request_with_approval(request: AutomationRequest, approval: object) -> AutomationRequest:
    excerpt = request.observations.excerpts[0].model_copy(update={"approval": approval})
    observations = request.observations.model_copy(update={"excerpts": (excerpt,)})
    return request.model_copy(update={"observations": observations})


def test_automation_compile_publishes_scrubbed_offline_candidate_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    request_path = tmp_path / "request.json"
    turn_path = tmp_path / "turn.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    turn_path.write_bytes(_turn(request))

    def reject_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("automation compile opened a network socket")

    def reject_provider_or_gateway(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("automation compile used provider or gateway execution")

    import faultloom.automation.execution_bridge as execution_bridge
    import faultloom.automation.provider_runner as provider_runner

    monkeypatch.setattr(socket, "socket", reject_network)
    monkeypatch.setattr(
        provider_runner, "run_provider_automation_turn", reject_provider_or_gateway
    )
    monkeypatch.setattr(
        execution_bridge, "execute_admitted_tool_plan", reject_provider_or_gateway
    )
    assert cli.main(_compile_arguments(workspace, trusted_key, request_path, turn_path)) == 0
    output = json.loads(capsys.readouterr().out.splitlines()[-1])
    result_path = Path(output["result"])
    receipt_path = Path(output["receipt"])
    candidate_path = Path(output["candidate"])
    result = json.loads(result_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert sha256_digest(result) == output["digest"] == receipt["result_digest"]
    assert output["network_access"] == "none"
    assert output["target_dispatch"] is False
    assert output["automatic_submission"] is False
    assert receipt["evidence_existence_independently_verified"] is False
    assert "CompileSecretMarker" not in candidate_path.read_text(encoding="utf-8")
    for path in (result_path, receipt_path, candidate_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_automation_compile_allows_hypothesis_only_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    request_path = tmp_path / "request.json"
    turn_path = tmp_path / "turn.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    turn_path.write_bytes(_turn(request, finding=False))

    assert cli.main(_compile_arguments(workspace, trusted_key, request_path, turn_path)) == 0
    output = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert output["candidate"] is None
    assert sorted(Path(output["result"]).parent.iterdir()) == [
        Path(output["receipt"]),
        Path(output["result"]),
    ]


def test_automation_compile_action_fails_without_result_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    request_path = tmp_path / "request.json"
    turn_path = tmp_path / "turn.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    turn_path.write_bytes(_turn(request, action=True))

    assert cli.main(_compile_arguments(workspace, trusted_key, request_path, turn_path)) == cli.EXIT_AUTHORITY
    assert "faultloom: error:" in capsys.readouterr().err
    assert not (workspace / "automation").exists()


@pytest.mark.parametrize(
    "content",
    (
        b'{"request":1,"request":2}',
        b"[" * 129 + b"0" + b"]" * 129,
    ),
)
def test_automation_compile_rejects_duplicate_or_deep_request_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    content: bytes,
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    request_path = tmp_path / "request.json"
    turn_path = tmp_path / "turn.json"
    request_path.write_bytes(content)
    turn_path.write_bytes(_turn(request))

    assert cli.main(_compile_arguments(workspace, trusted_key, request_path, turn_path)) == cli.EXIT_USAGE
    assert "invalid automation request file" in capsys.readouterr().err
    assert not (workspace / "automation").exists()


def test_automation_compile_refuses_symlinked_output_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    request_path = tmp_path / "request.json"
    turn_path = tmp_path / "turn.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    turn_path.write_bytes(_turn(request))
    external = tmp_path / "external"
    external.mkdir()
    (workspace / "automation").symlink_to(external, target_is_directory=True)

    assert cli.main(_compile_arguments(workspace, trusted_key, request_path, turn_path)) == cli.EXIT_USAGE
    assert list(external.iterdir()) == []


@pytest.mark.parametrize("failure", ("grant", "run", "future", "minimum"))
def test_automation_compile_rejects_authority_binding_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    arguments_extra: list[str] = []
    if failure == "grant":
        request = request.model_copy(
            update={"authority_grant": grant.model_copy(update={"grant_id": "grant.other"})}
        )
    elif failure == "run":
        evidence = request.observations.evidence_refs[0].model_copy(
            update={"run_id": "run.other"}
        )
        excerpt = request.observations.excerpts[0]
        approval = sign_model_disclosure_approval(
            excerpt.approval.payload.model_copy(update={"run_id": "run.other"}),
            DISCLOSURE_SIGNER,
        )
        observations = request.observations.model_copy(
            update={
                "run_id": "run.other",
                "evidence_refs": (evidence,),
                "excerpts": (excerpt.model_copy(update={"approval": approval}),),
            }
        )
        context = request.action_context.model_copy(update={"run_id": "run.other"})
        request = request.model_copy(update={"observations": observations, "action_context": context})
    elif failure == "future":
        request = request.model_copy(update={"issued_at": NOW + timedelta(minutes=1)})
    else:
        arguments_extra = ["--minimum-grant-version", str(grant.grant_version + 1)]
    request_path = tmp_path / "request.json"
    turn_path = tmp_path / "turn.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    turn_path.write_bytes(_turn(request))

    assert (
        cli.main(_compile_arguments(workspace, trusted_key, request_path, turn_path) + arguments_extra)
        == cli.EXIT_AUTHORITY
    )
    assert "Traceback" not in capsys.readouterr().err
    assert not (workspace / "automation").exists()


def test_automation_export_handoff_is_canonical_offline_and_compilable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    request_path = tmp_path / "request.json"
    out_path = tmp_path / "model-handoff.json"
    second_out_path = tmp_path / "model-handoff-copy.json"
    disclosure_key = _disclosure_key(tmp_path / "disclosure-key.json")
    request_path.write_text(request.model_dump_json(), encoding="utf-8")

    def reject_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("automation export-handoff opened a network socket")

    def reject_provider_or_gateway(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("automation export-handoff used provider or gateway execution")

    import faultloom.automation.execution_bridge as execution_bridge
    import faultloom.automation.provider_runner as provider_runner

    monkeypatch.setattr(socket, "socket", reject_network)
    monkeypatch.setattr(
        provider_runner, "run_provider_automation_turn", reject_provider_or_gateway
    )
    monkeypatch.setattr(
        execution_bridge, "execute_admitted_tool_plan", reject_provider_or_gateway
    )
    assert (
        cli.main(
            _export_arguments(
                workspace, trusted_key, request_path, out_path, (disclosure_key,)
            )
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out.splitlines()[-1])
    content = out_path.read_bytes()
    document = json.loads(content)
    assert content == provider_canonical_json_bytes(document) + b"\n"
    assert receipt == {
        "automatic_submission": False,
        "handoff": str(out_path),
        "independent_verification": False,
        "network_access": "none",
        "provider_dispatch": False,
        "sha256": hashlib.sha256(content).hexdigest(),
        "target_dispatch": False,
    }
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    assert document["schema"] == "faultloom.model-handoff.v1"
    assert document["run_id"] == request.observations.run_id
    assert document["request_digest"] == sha256_digest(request.model_dump(mode="json"))
    assert document["model_provenance"] == "unattested_manual_handoff"
    assert document["approved_provider_id"] == "provider.test"
    assert document["provider_disclosure_verification"] == "verified"
    assert document["network_access"] == "none"
    assert document["generation"] == {
        "max_output_tokens": 1024,
        "response_format": "json",
        "seed": 0,
        "schema_version": "0.1.0",
        "temperature_milli": 0,
        "top_p_milli": 1000,
    }
    tool = document["function_tool"]
    assert tool["id"] == "faultloom-model-turn-v1"
    assert tool["name"] == "faultloom-model-turn-v1"
    assert document["tool_schema_digest"] == sha256_digest(tool["parameters"])
    assert document["output_schema_digest"] != document["tool_schema_digest"]
    assert document["limits"] == request.limits.model_dump(mode="json")
    assert document["messages"][0]["role"] == "system"
    assert all("provider.test" not in message["content"] for message in document["messages"])

    assert (
        cli.main(
            _export_arguments(
                workspace, trusted_key, request_path, second_out_path, (disclosure_key,)
            )
        )
        == 0
    )
    assert second_out_path.read_bytes() == content
    _ = capsys.readouterr()

    turn_path = tmp_path / "model-turn.json"
    turn_path.write_bytes(_turn(request))
    assert cli.main(_compile_arguments(workspace, trusted_key, request_path, turn_path)) == 0
    compile_receipt = json.loads(capsys.readouterr().out.splitlines()[-1])
    result = json.loads(Path(compile_receipt["result"]).read_text(encoding="utf-8"))
    assert result["verification_status"] == "candidate_only_requires_independent_verification"
    assert result["target_dispatch_performed"] is False
    assert result["automatic_submission_performed"] is False


def test_automation_export_handoff_is_create_once_and_refuses_symlink_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request_path = tmp_path / "request.json"
    request_path.write_text(_request(workspace, grant).model_dump_json(), encoding="utf-8")
    out_path = tmp_path / "model-handoff.json"
    disclosure_key = _disclosure_key(tmp_path / "disclosure-key.json")
    arguments = _export_arguments(
        workspace, trusted_key, request_path, out_path, (disclosure_key,)
    )
    assert cli.main(arguments) == 0
    original = out_path.read_bytes()
    _ = capsys.readouterr()
    assert cli.main(arguments) == cli.EXIT_USAGE
    assert out_path.read_bytes() == original
    assert "cannot create" in capsys.readouterr().err

    external = tmp_path / "external.json"
    external.write_text("external", encoding="utf-8")
    symlink_out = tmp_path / "symlink-handoff.json"
    symlink_out.symlink_to(external)
    assert (
        cli.main(
            _export_arguments(
                workspace, trusted_key, request_path, symlink_out, (disclosure_key,)
            )
        )
        == cli.EXIT_USAGE
    )
    assert external.read_text(encoding="utf-8") == "external"


@pytest.mark.parametrize(
    ("content", "expected_exit"),
    (
        (b"not-json", cli.EXIT_USAGE),
        (b'{"request":1,"request":2}', cli.EXIT_USAGE),
        (b"[" * 129 + b"0" + b"]" * 129, cli.EXIT_USAGE),
        (b" " * (cli.MAX_PROTOCOL_FILE_BYTES + 1), cli.EXIT_AUTHORITY),
    ),
)
def test_automation_export_handoff_rejects_malformed_duplicate_deep_or_oversized_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    content: bytes,
    expected_exit: int,
) -> None:
    workspace, trusted_key, _grant = _workspace(tmp_path, monkeypatch)
    request_path = tmp_path / "request.json"
    out_path = tmp_path / "model-handoff.json"
    disclosure_key = _disclosure_key(tmp_path / "disclosure-key.json")
    request_path.write_bytes(content)
    assert (
        cli.main(
            _export_arguments(
                workspace, trusted_key, request_path, out_path, (disclosure_key,)
            )
        )
        == expected_exit
    )
    assert not out_path.exists()
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("failure", ("provider_only", "workspace_drift"))
def test_automation_export_handoff_rejects_provider_or_workspace_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    if failure == "provider_only":
        request = request.model_copy(update={"provider_network_access": "provider_only"})
    else:
        manifest_path = workspace / "run.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["run_id"] = "run.workspace-drift"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    request_path = tmp_path / "request.json"
    out_path = tmp_path / "model-handoff.json"
    disclosure_key = _disclosure_key(tmp_path / "disclosure-key.json")
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    assert (
        cli.main(
            _export_arguments(
                workspace, trusted_key, request_path, out_path, (disclosure_key,)
            )
        )
        == cli.EXIT_AUTHORITY
    )
    assert not out_path.exists()
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "failure",
    (
        "provider_other",
        "wrong_approval",
        "expired_approval",
        "missing_approval",
        "missing_key",
        "malformed_key",
        "duplicate_key",
        "reused_key",
    ),
)
def test_automation_export_handoff_requires_verified_provider_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    workspace, trusted_key, grant = _workspace(tmp_path, monkeypatch)
    request = _request(workspace, grant)
    primary_key = _disclosure_key(tmp_path / "disclosure-key.json")
    disclosure_keys = (primary_key,)
    provider_id = "provider.test"
    request_content = request.model_dump_json()
    if failure == "provider_other":
        provider_id = "provider.other"
    elif failure == "wrong_approval":
        approval = sign_model_disclosure_approval(
            request.observations.excerpts[0].approval.payload.model_copy(
                update={"allowed_provider_ids": ("provider.other",)}
            ),
            DISCLOSURE_SIGNER,
        )
        request = _request_with_approval(request, approval)
    elif failure == "expired_approval":
        approval = sign_model_disclosure_approval(
            request.observations.excerpts[0].approval.payload.model_copy(
                update={
                    "approved_at": NOW - timedelta(minutes=1),
                    "expires_at": NOW,
                }
            ),
            DISCLOSURE_SIGNER,
        )
        request = _request_with_approval(request, approval)
        request_content = request.model_dump_json()
    elif failure == "missing_approval":
        document = json.loads(request_content)
        del document["observations"]["excerpts"][0]["approval"]
        request_content = json.dumps(document)
    elif failure == "missing_key":
        other_key = tmp_path / "other-disclosure-key.json"
        other_key.write_text(
            AuthoritySigner.from_private_bytes(bytes.fromhex("43" * 32))
            .public_key_record.model_dump_json(),
            encoding="utf-8",
        )
        disclosure_keys = (other_key,)
    elif failure == "malformed_key":
        primary_key.write_text('{"key_id":', encoding="utf-8")
    elif failure == "duplicate_key":
        second_key = _disclosure_key(tmp_path / "second-disclosure-key.json")
        disclosure_keys = (primary_key, second_key)
    elif failure == "reused_key":
        disclosure_keys = (primary_key, primary_key)
    request_path = tmp_path / "request.json"
    out_path = tmp_path / "model-handoff.json"
    if failure != "missing_approval":
        request_content = request.model_dump_json()
    request_path.write_text(request_content, encoding="utf-8")

    assert (
        cli.main(
            _export_arguments(
                workspace,
                trusted_key,
                request_path,
                out_path,
                disclosure_keys,
                provider_id=provider_id,
            )
        )
        == cli.EXIT_AUTHORITY
    )
    assert not out_path.exists()
    assert "Traceback" not in capsys.readouterr().err
