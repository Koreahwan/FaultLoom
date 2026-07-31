from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from faultloom.automation.candidate_outbox import (
    CandidateOutboxError,
    write_candidate_outbox,
)
from faultloom.automation.models import (
    AuthorizedAutomationResult,
    CandidateFindingDraft,
)
from faultloom_protocol import canonical_json


def _result(*, draft: CandidateFindingDraft | None = None) -> AuthorizedAutomationResult:
    finding = draft or CandidateFindingDraft(
        hypothesis_id="hypothesis.candidate-1",
        title="Owned route normalization candidate",
        severity="low",
        summary="The observation needs an independent replay.",
        impact="No impact is verified yet.",
        reproduction_steps=("Replay the admitted safe probe only.",),
        remediation="Confirm independently before changing the service.",
    )
    return AuthorizedAutomationResult(
        run_id="run.candidate-1",
        authority_grant_id="grant.candidate-1",
        authority_grant_version=1,
        authority_grant_digest="sha256:" + "1" * 64,
        observation_bundle_digest="sha256:" + "2" * 64,
        action_context_digest="sha256:" + "3" * 64,
        hypotheses=(),
        negative_results=(),
        admitted_plans=(),
        finding_draft=finding,
        stop_reason="Await independent verification.",
        provider_network_access="none",
    )


def test_candidate_outbox_publishes_canonical_manual_review_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("candidate outbox opened a network socket")

    monkeypatch.setattr(socket, "socket", reject_network)
    publication = write_candidate_outbox(_result(), tmp_path / "outbox")

    assert publication.entry_dir.is_dir()
    assert sorted(path.name for path in publication.entry_dir.iterdir()) == [
        "candidate.md",
        "receipt.json",
    ]
    candidate = publication.candidate_path.read_text(encoding="utf-8")
    assert "Status: `draft_unverified`" in candidate
    assert "Review: `manual_review`" in candidate
    assert "Independent verification: `false`" in candidate
    assert "Automatic submission: `false`" in candidate
    assert "Network access: `none`" in candidate

    receipt_text = publication.receipt_path.read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)
    assert canonical_json(receipt) == receipt_text
    assert receipt == {
        "action_context_digest": "sha256:" + "3" * 64,
        "automatic_submission": False,
        "authority_grant_digest": "sha256:" + "1" * 64,
        "candidate_digest": publication.candidate_digest,
        "candidate_format": "md",
        "entry_id": publication.entry_id,
        "hypothesis_id": "hypothesis.candidate-1",
        "independent_verification": False,
        "network_access": "none",
        "observation_bundle_digest": "sha256:" + "2" * 64,
        "poc_context_digest": None,
        "review_status": "manual_review",
        "run_id": "run.candidate-1",
        "schema": "faultloom.candidate_outbox.receipt.v1",
        "source_result_digest": publication.source_result_digest,
        "status": "draft_unverified",
        "target_dispatch": False,
    }


def test_candidate_outbox_scrubs_secret_shaped_model_text(tmp_path: Path) -> None:
    bearer = "candidate-bearer-marker-1234567890"
    api_key = "sk-candidateApiKeyMarker1234567890"
    github_token = "gh" + "p_CandidateGithubTokenMarker1234567890"
    private_body = "candidate-private-body-marker"
    draft = CandidateFindingDraft(
        hypothesis_id="hypothesis.secret-shaped",
        title=f"Authorization: Bearer {bearer}",
        severity="low",
        summary=f"Provider token {api_key}",
        impact=f"client_secret={github_token}",
        reproduction_steps=(
            "-----BEGIN " + "PRIVATE KEY-----\n"
            f"{private_body}\n"
            "-----END PRIVATE KEY-----",
        ),
        remediation=f"Remove secret://run/{github_token} and {github_token}.",
    )

    publication = write_candidate_outbox(
        _result(draft=draft),
        tmp_path / "outbox",
    )
    persisted = b"".join(
        path.read_bytes() for path in sorted(publication.entry_dir.iterdir())
    )

    for secret in (bearer, api_key, github_token, private_body):
        assert secret.encode() not in persisted
    assert b"secret-ref" in persisted
    assert b"private-key-ref" in persisted


def test_candidate_outbox_requires_a_finding_draft(tmp_path: Path) -> None:
    result = _result().model_copy(update={"finding_draft": None})

    with pytest.raises(CandidateOutboxError, match="no candidate finding draft"):
        write_candidate_outbox(result, tmp_path / "outbox")

    assert not (tmp_path / "outbox").exists()


def test_candidate_outbox_rejects_secret_shaped_binding_metadata(
    tmp_path: Path,
) -> None:
    draft = _result().finding_draft
    assert draft is not None
    secret_shaped = "sk-candidateBindingMarker1234567890"
    result = _result(
        draft=draft.model_copy(update={"hypothesis_id": secret_shaped})
    )

    with pytest.raises(CandidateOutboxError, match="hypothesis ID"):
        write_candidate_outbox(result, tmp_path / "outbox")

    assert not (tmp_path / "outbox").exists()


def test_candidate_outbox_refuses_overwrite_and_preserves_first_entry(
    tmp_path: Path,
) -> None:
    result = _result()
    publication = write_candidate_outbox(result, tmp_path / "outbox")
    first = {
        path.name: path.read_bytes() for path in publication.entry_dir.iterdir()
    }

    with pytest.raises(CandidateOutboxError, match="already exists"):
        write_candidate_outbox(result, tmp_path / "outbox")

    assert {
        path.name: path.read_bytes() for path in publication.entry_dir.iterdir()
    } == first


def test_candidate_outbox_interruption_has_no_visible_entry_and_can_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    result = _result()
    out_dir = tmp_path / "outbox"
    original = outbox_module._create_file_once
    calls = 0

    def interrupt_second_write(path: Path, content: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        original(path, content)

    monkeypatch.setattr(outbox_module, "_create_file_once", interrupt_second_write)
    with pytest.raises(KeyboardInterrupt):
        write_candidate_outbox(result, out_dir)

    assert list(out_dir.iterdir()) == []
    monkeypatch.setattr(outbox_module, "_create_file_once", original)
    publication = write_candidate_outbox(result, out_dir)
    assert publication.candidate_path.is_file()
    assert publication.receipt_path.is_file()
