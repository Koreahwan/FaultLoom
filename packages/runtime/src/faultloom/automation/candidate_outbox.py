from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, final, override

from pydantic import ValidationError

from faultloom.verification.reporting import (
    _scrub as _verified_report_scrub,  # pyright: ignore[reportPrivateUsage]
)
from faultloom_protocol import canonical_json, sha256_digest

from .models import AuthorizedAutomationResult, CandidateFindingDraft


_PRIVATE_KEY_BLOCK = re.compile(
    "".join(
        (
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?",
            r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
        )
    ),
    re.IGNORECASE | re.DOTALL,
)
_SECRET_FIELD = re.compile(
    "".join(
        (
            r"(?i)\b(client[_-]?secret|private[_-]?key|refresh[_-]?token|",
            r"auth[_-]?token|credential|secret)\s*[:=]\s*[^\s,;]+",
        )
    )
)
_COMMON_TOKEN = re.compile(
    "".join(
        (
            r"(?<![A-Za-z0-9])(?:",
            r"sk-[A-Za-z0-9_-]{16,}|",
            r"gh[opusr]_[A-Za-z0-9]{20,}|",
            r"AKIA[0-9A-Z]{16}|",
            r"AIza[0-9A-Za-z_-]{20,}|",
            r"xox[baprs]-[A-Za-z0-9-]{10,}|",
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            r")(?![A-Za-z0-9])",
        )
    )
)


@final
class CandidateOutboxError(RuntimeError):
    __slots__: ClassVar[tuple[str, ...]] = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason: str = reason

    @override
    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class CandidateOutboxPublication:
    entry_id: str
    entry_dir: Path
    candidate_path: Path
    receipt_path: Path
    candidate_digest: str
    source_result_digest: str


def _scrub_candidate_text(value: str) -> str:
    scrubbed = _verified_report_scrub(value)
    scrubbed = _PRIVATE_KEY_BLOCK.sub("<private-key-ref>", scrubbed)
    scrubbed = _SECRET_FIELD.sub(
        lambda match: f"{match.group(1)}: <secret-ref>", scrubbed
    )
    scrubbed = _COMMON_TOKEN.sub("<secret-ref>", scrubbed)
    if (
        _PRIVATE_KEY_BLOCK.search(scrubbed) is not None
        or _COMMON_TOKEN.search(scrubbed) is not None
    ):
        raise CandidateOutboxError("candidate report contains unredacted secret material")
    return scrubbed


def _markdown(value: str) -> str:
    escaped = _scrub_candidate_text(value).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "<", ">", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _require_secret_free_metadata(label: str, value: str) -> str:
    if _scrub_candidate_text(value) != value:
        raise CandidateOutboxError(f"candidate {label} contains secret-shaped material")
    return value


def _candidate_markdown(
    result: AuthorizedAutomationResult,
    draft: CandidateFindingDraft,
) -> str:
    steps = "\n".join(
        f"{index}. {_markdown(step)}"
        for index, step in enumerate(draft.reproduction_steps, start=1)
    )
    run_id = _require_secret_free_metadata("run ID", result.run_id)
    hypothesis_id = _require_secret_free_metadata(
        "hypothesis ID", draft.hypothesis_id
    )
    poc_recipe = (
        "none"
        if draft.poc_recipe_id is None
        else _require_secret_free_metadata("PoC recipe ID", draft.poc_recipe_id)
    )
    return (
        f"# {_markdown(draft.title)}\n\n"
        "- Status: `draft_unverified`\n"
        "- Review: `manual_review`\n"
        "- Independent verification: `false`\n"
        "- Automatic submission: `false`\n"
        "- Network access: `none`\n"
        "- Target dispatch: `false`\n"
        f"- Run: `{run_id}`\n"
        f"- Hypothesis: `{hypothesis_id}`\n"
        f"- PoC recipe: `{poc_recipe}`\n"
        f"- Severity: `{draft.severity}`\n\n"
        "## Summary\n\n"
        f"{_markdown(draft.summary)}\n\n"
        "## Unverified impact\n\n"
        f"{_markdown(draft.impact)}\n\n"
        "## Candidate reproduction steps\n\n"
        f"{steps}\n\n"
        "## Candidate remediation\n\n"
        f"{_markdown(draft.remediation)}\n"
    )


def _content_digest(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def _create_file_once(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            descriptor = -1
            _ = output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_candidate_outbox(
    result: AuthorizedAutomationResult,
    out_dir: Path,
) -> CandidateOutboxPublication:
    """Publish one secret-scrubbed, candidate-only report without network I/O."""

    if type(result) is not AuthorizedAutomationResult:
        raise CandidateOutboxError("candidate outbox requires an exact automation result")
    try:
        validated = AuthorizedAutomationResult.model_validate(result)
    except ValidationError as exc:
        raise CandidateOutboxError("candidate outbox received an invalid automation result") from exc
    draft = validated.finding_draft
    if draft is None:
        raise CandidateOutboxError("automation result has no candidate finding draft")
    run_id = _require_secret_free_metadata("run ID", validated.run_id)
    hypothesis_id = _require_secret_free_metadata(
        "hypothesis ID", draft.hypothesis_id
    )

    candidate_content = _candidate_markdown(validated, draft)
    candidate_digest = _content_digest(candidate_content)
    source_result_digest = sha256_digest(validated.model_dump(mode="json"))
    entry_id = f"candidate.{candidate_digest.removeprefix('sha256:')[:32]}"
    entry_dir = out_dir / entry_id
    candidate_path = entry_dir / "candidate.md"
    receipt_path = entry_dir / "receipt.json"
    receipt_content = canonical_json(
        {
            "action_context_digest": validated.action_context_digest,
            "automatic_submission": False,
            "authority_grant_digest": validated.authority_grant_digest,
            "candidate_digest": candidate_digest,
            "candidate_format": "md",
            "entry_id": entry_id,
            "hypothesis_id": hypothesis_id,
            "independent_verification": False,
            "network_access": "none",
            "observation_bundle_digest": validated.observation_bundle_digest,
            "poc_context_digest": validated.poc_context_digest,
            "review_status": "manual_review",
            "run_id": run_id,
            "schema": "faultloom.candidate_outbox.receipt.v1",
            "source_result_digest": source_result_digest,
            "status": "draft_unverified",
            "target_dispatch": False,
        }
    )

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        if not out_dir.is_dir():
            raise OSError("outbox path is not a directory")
        if os.path.lexists(entry_dir):
            raise FileExistsError("candidate outbox entry already exists")
        staging_dir = Path(
            tempfile.mkdtemp(prefix=f".{entry_id}.", suffix=".tmp", dir=out_dir)
        )
    except OSError as exc:
        raise CandidateOutboxError(f"unable to create candidate outbox: {exc}") from exc

    committed = False
    try:
        _create_file_once(staging_dir / "candidate.md", candidate_content)
        _create_file_once(staging_dir / "receipt.json", receipt_content)
        _fsync_directory(staging_dir)
        if os.path.lexists(entry_dir):
            raise FileExistsError("candidate outbox entry already exists")
        os.rename(staging_dir, entry_dir)
        committed = True
        _fsync_directory(out_dir)
    except BaseException as exc:
        if not committed:
            shutil.rmtree(staging_dir, ignore_errors=True)
        if isinstance(exc, OSError):
            raise CandidateOutboxError(
                f"unable to create candidate outbox: {exc}"
            ) from exc
        raise

    return CandidateOutboxPublication(
        entry_id=entry_id,
        entry_dir=entry_dir,
        candidate_path=candidate_path,
        receipt_path=receipt_path,
        candidate_digest=candidate_digest,
        source_result_digest=source_result_digest,
    )
