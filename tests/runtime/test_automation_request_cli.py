from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from faultloom import cli
from faultloom_protocol import AuthoritySigner

from tests.runtime.test_cli import _authority_files, _run_arguments
from tests.runtime.test_personal_campaign import (
    _campaign_run_arguments,
    _listener,
    _request,
    _serve,
    _spec,
)

DISCLOSURE_SEED = bytes.fromhex("42" * 32)


def _workspace(tmp_path: Path, port: int) -> tuple[Path, Path]:
    authority, key = _authority_files(
        tmp_path / "grant",
        hostnames=("127.0.0.1",),
        ports=(port,),
        paths=("/api/*",),
        methods=("GET",),
        protocols=("http",),
        budget_updates={"total_actions": 4, "rate_per_minute": 4, "max_concurrency": 1},
        now=datetime.now(UTC) - timedelta(minutes=1),
    )
    workspace = tmp_path / "workspace"
    assert cli.main(_run_arguments(authority, key) + ["--workspace", str(workspace)]) == 0
    return workspace, key


def _archived_exchange(
    tmp_path: Path, workspace: Path, key: Path, port: int, capsys: pytest.CaptureFixture[str]
) -> tuple[str, Path]:
    request = tmp_path / "observed.raw"
    response = tmp_path / "observed-response.raw"
    request.write_bytes(_request(port, "/api/effect"))
    response.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect")
    assert cli.main(
        [
            "scope", "verify-request", "--workspace", str(workspace),
            "--trusted-key", str(key), "--hostname", "127.0.0.1", "--port", str(port),
            "--scheme", "http", "--method", "GET", "--path", "/api/effect",
            "--request-file", str(request), "--response-bytes", "512",
        ]
    ) == cli.EXIT_OK
    reservation = json.loads(capsys.readouterr().out)["reservation_id"]
    assert cli.main(
        [
            "scope", "complete-request", "--workspace", str(workspace),
            "--trusted-key", str(key), "--reservation-id", reservation,
            "--request-file", str(request), "--response-file", str(response),
        ]
    ) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(
        [
            "evidence", "add-exchange", "--workspace", str(workspace),
            "--trusted-key", str(key), "--reservation-id", reservation,
            "--request-file", str(request), "--response-file", str(response),
        ]
    ) == cli.EXIT_OK
    archived = json.loads(capsys.readouterr().out)
    return archived["evidence_id"], Path(archived["record"])


def _prepare_arguments(
    workspace: Path,
    key: Path,
    evidence_id: str,
    excerpt: Path,
    disclosure_private: Path,
    port: int,
    out: Path,
    *,
    provider_id: str = "provider.test",
    path: str = "/api/effect",
) -> list[str]:
    return [
        "automation", "prepare-http1-request", "--workspace", str(workspace),
        "--trusted-key", str(key), "--evidence-id", evidence_id,
        "--excerpt-file", str(excerpt), "--provider-id", provider_id,
        "--disclosure-private-key", str(disclosure_private),
        "--hostname", "127.0.0.1", "--port", str(port), "--scheme", "http",
        "--method", "GET", "--path", path, "--out", str(out),
        "--confirm-redacted-non-sensitive",
    ]


def _safe_poc_turn(request: dict[str, object]) -> bytes:
    evidence_id = request["observations"]["evidence_refs"][0]["evidence_id"]
    payload_digest = request["action_context"]["payload_digest"]
    return json.dumps(
        {
            "hypotheses": [
                {
                    "proposal_id": "hypothesis.archived-effect",
                    "statement": "The owned route has a bounded observable effect.",
                    "provenance": ["behavior"],
                    "supporting_evidence_ids": [evidence_id],
                    "contradicting_evidence_ids": [],
                    "prerequisite_ids": ["prerequisite.archived-effect"],
                }
            ],
            "negative_results": [],
            "actions": [],
            "poc": {
                "adaptation_id": "adaptation.archived-effect",
                "recipe_id": "recipe.archived-effect",
                "hypothesis_proposal_id": "hypothesis.archived-effect",
                "expected_observable_effect": "The exact effect response is reproduced.",
                "negative_controls": ["The request-target-only control differs."],
                "evidence_ids": [evidence_id],
                "steps": [
                    {
                        "step_id": "step.archived-effect",
                        "action_class": "safe_probe",
                        "action_kind": "http.semantic",
                        "method": "GET",
                        "payload_digest": payload_digest,
                        "expected_effect": "The exact effect response is reproduced.",
                        "negative_control": "The request-target-only control differs.",
                        "required": True,
                        "hazard": "safe",
                    }
                ],
            },
            "finding_draft": {
                "hypothesis_proposal_id": "hypothesis.archived-effect",
                "poc_recipe_id": "recipe.archived-effect",
                "title": "Owned loopback candidate",
                "severity": "low",
                "summary": "A bounded candidate requires independent verification.",
                "impact": "No impact is independently verified.",
                "reproduction_steps": ["Run only the reviewed three-request triad."],
                "remediation": "Review independently before changing the service.",
            },
            "stop_reason": "Await independent verification.",
        }
    ).encode()


def test_archived_exchange_to_compiled_safe_poc_triad(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    evidence_id, _ = _archived_exchange(tmp_path, workspace, key, port, capsys)
    excerpt = tmp_path / "redacted.txt"
    excerpt.write_text("Owned response returned the reviewed marker.", encoding="utf-8")
    disclosure_private = tmp_path / "disclosure.key"
    disclosure_private.write_text(DISCLOSURE_SEED.hex() + "\n", encoding="ascii")
    disclosure_private.chmod(0o600)
    disclosure_public = tmp_path / "disclosure-public.json"
    disclosure_public.write_text(
        AuthoritySigner.from_private_bytes(DISCLOSURE_SEED).public_key_record.model_dump_json(),
        encoding="utf-8",
    )
    request_path = workspace / "automation-request.json"
    assert cli.main(
        _prepare_arguments(
            workspace, key, evidence_id, excerpt, disclosure_private, port, request_path
        )
    ) == cli.EXIT_OK
    prepared = json.loads(capsys.readouterr().out)
    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert prepared["target_dispatch"] is False
    assert request["provider_network_access"] == "none"
    assert request["limits"]["max_actions"] == 0
    assert request["limits"]["max_poc_steps"] == 1
    assert request["action_context"]["payload_digest"] == (
        "sha256:" + hashlib.sha256(_request(port, "/api/effect")).hexdigest()
    )

    handoff = workspace / "handoff.json"
    assert cli.main(
        [
            "automation", "export-handoff", "--workspace", str(workspace),
            "--trusted-key", str(key), "--request", str(request_path),
            "--provider-id", "provider.test", "--model-snapshot",
            "frontier-2030-01-01", "--trusted-disclosure-key",
            str(disclosure_public), "--out", str(handoff),
        ]
    ) == cli.EXIT_OK
    capsys.readouterr()
    turn = tmp_path / "model-turn.json"
    turn.write_bytes(_safe_poc_turn(request))
    assert cli.main(
        [
            "automation", "compile", "--workspace", str(workspace),
            "--trusted-key", str(key), "--request", str(request_path),
            "--model-turn", str(turn),
        ]
    ) == cli.EXIT_OK
    compiled = json.loads(capsys.readouterr().out)
    template = _spec(workspace, port)
    bound = workspace / "bound.json"
    assert cli.main(
        [
            "campaign", "prepare-http1-triad", "--workspace", str(workspace),
            "--trusted-key", str(key), "--template", str(template),
            "--result", compiled["result"], "--receipt", compiled["receipt"],
            "--candidate-id", "step.archived-effect", "--out", str(bound),
        ]
    ) == cli.EXIT_OK
    capsys.readouterr()
    binding = json.loads(bound.read_text(encoding="utf-8"))["automation_binding"]
    assert binding["candidate_source"] == "compiled_safe_poc_step"

    captured: list[bytes] = []
    thread = _serve(
        listener,
        [
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
        ],
        captured,
    )
    assert cli.main(_campaign_run_arguments(workspace, key, bound)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    assert captured == [
        _request(port, "/api/effect"),
        _request(port, "/api/effect"),
        _request(port, "/api/control"),
    ]
    run = json.loads(capsys.readouterr().out)
    start = json.loads(Path(run["startRecord"]).read_text(encoding="utf-8"))
    assert start["automation_binding"]["candidate_source"] == "compiled_safe_poc_step"
    assert cli.main(
        [
            "campaign", "finalize-http1-triad", "--workspace", str(workspace),
            "--trusted-key", str(key), "--campaign-id", "owned-loopback",
            "--confirm-reviewed-non-sensitive",
        ]
    ) == cli.EXIT_OK
    capsys.readouterr()
    verification_handoff = workspace / "verification-handoff.json"
    assert cli.main(
        [
            "campaign", "export-verification-handoff", "--workspace", str(workspace),
            "--trusted-key", str(key), "--campaign-id", "owned-loopback",
            "--out", str(verification_handoff),
        ]
    ) == cli.EXIT_OK
    handoff_document = json.loads(verification_handoff.read_text(encoding="utf-8"))
    assert handoff_document["automation"]["candidateSource"] == "compiled_safe_poc_step"


@pytest.mark.parametrize("mutation", ("endpoint", "provider", "response"))
def test_prepare_rejects_relabel_or_tamper_before_output(
    mutation: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    listener.close()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    evidence_id, record_path = _archived_exchange(tmp_path, workspace, key, port, capsys)
    excerpt = tmp_path / "redacted.txt"
    excerpt.write_text("Reviewed non-sensitive excerpt.", encoding="utf-8")
    disclosure = tmp_path / "disclosure.key"
    disclosure.write_text(DISCLOSURE_SEED.hex(), encoding="ascii")
    disclosure.chmod(0o600)
    out = tmp_path / "automation-request.json"
    arguments = _prepare_arguments(
        workspace,
        key,
        evidence_id,
        excerpt,
        disclosure,
        port,
        out,
        provider_id="provider.other" if mutation == "provider" else "provider.test",
        path="/api/control" if mutation == "endpoint" else "/api/effect",
    )
    if mutation == "response":
        record = json.loads(record_path.read_text(encoding="utf-8"))
        response_path = record_path.parent / record["response"]["stored_file"]
        response_path.write_bytes(response_path.read_bytes() + b"tamper")
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert not out.exists()


def test_prepare_rejects_evidence_id_relabel_before_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    listener.close()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    evidence_id, record_path = _archived_exchange(tmp_path, workspace, key, port, capsys)
    relabeled_id = evidence_id.rsplit(".", 1)[0] + ".00000000"
    if relabeled_id == evidence_id:
        relabeled_id = evidence_id.rsplit(".", 1)[0] + ".ffffffff"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["evidence_id"] = relabeled_id
    relabeled_record = record_path.with_name(f"{relabeled_id}.json")
    relabeled_record.write_text(json.dumps(record), encoding="utf-8")
    excerpt = tmp_path / "redacted.txt"
    excerpt.write_text("Reviewed non-sensitive excerpt.", encoding="utf-8")
    disclosure = tmp_path / "disclosure.key"
    disclosure.write_text(DISCLOSURE_SEED.hex(), encoding="ascii")
    disclosure.chmod(0o600)
    out = tmp_path / "automation-request.json"
    assert cli.main(
        _prepare_arguments(
            workspace,
            key,
            relabeled_id,
            excerpt,
            disclosure,
            port,
            out,
        )
    ) == cli.EXIT_AUTHORITY
    assert not out.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-file mode gate")
def test_prepare_rejects_group_readable_disclosure_seed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    listener.close()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    evidence_id, _ = _archived_exchange(tmp_path, workspace, key, port, capsys)
    excerpt = tmp_path / "redacted.txt"
    excerpt.write_text("Reviewed non-sensitive excerpt.", encoding="utf-8")
    disclosure = tmp_path / "disclosure.key"
    disclosure.write_text(DISCLOSURE_SEED.hex(), encoding="ascii")
    disclosure.chmod(0o644)
    out = tmp_path / "automation-request.json"

    assert cli.main(
        _prepare_arguments(
            workspace,
            key,
            evidence_id,
            excerpt,
            disclosure,
            port,
            out,
        )
    ) == cli.EXIT_AUTHORITY
    assert not out.exists()
