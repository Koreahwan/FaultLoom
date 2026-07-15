from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass

from faultloom_protocol import InvariantChange, PatchDelta

from .inputs import PatchArtifact, PatchArtifactKind, PatchRequest
from .results import ArtifactDelta, PatchAnalysis


@dataclass(frozen=True, slots=True)
class _SecuritySemantics:
    condition: str
    invariant: str
    sink: str
    boundary: str


def analyze_patch(advisory_match_id: str, request: PatchRequest) -> PatchAnalysis:
    """Diff supplied offline artifacts and extract the changed security invariant."""

    deltas = tuple(_artifact_delta(artifact) for artifact in request.artifacts)
    source_delta = next(
        delta for delta in deltas if delta.kind is PatchArtifactKind.SOURCE
    )
    config_delta = next(
        (delta for delta in deltas if delta.kind is PatchArtifactKind.CONFIG),
        None,
    )
    test_delta = next(
        (delta for delta in deltas if delta.kind is PatchArtifactKind.TEST),
        None,
    )
    semantics = _extract_semantics(source_delta)
    evidence_refs = tuple(
        {
            reference.evidence_id: reference
            for reference in (
                *request.evidence_refs,
                *(reference for artifact in request.artifacts for reference in artifact.evidence_refs),
            )
        }.values()
    )
    patch_delta = PatchDelta(
        schema_version="0.1.0",
        patch_delta_id=request.patch_delta_id,
        advisory_match_id=advisory_match_id,
        vulnerable_revision=request.vulnerable_revision,
        fixed_revision=request.fixed_revision,
        source_diff_digest=source_delta.diff_digest,
        test_diff_digest=test_delta.diff_digest if test_delta is not None else None,
        config_diff_digest=(config_delta.diff_digest if config_delta is not None else None),
        evidence_refs=evidence_refs,
    )
    invariant = InvariantChange(
        schema_version="0.1.0",
        invariant_change_id=request.invariant_change_id,
        patch_delta_id=request.patch_delta_id,
        invariant=semantics.invariant,
        changed_condition=semantics.condition,
        sink_or_boundary=f"{semantics.sink} | {semantics.boundary}",
        evidence_refs=evidence_refs,
    )
    return PatchAnalysis(
        patch_delta=patch_delta,
        artifact_deltas=deltas,
        invariant_changes=(invariant,),
    )


def _artifact_delta(artifact: PatchArtifact) -> ArtifactDelta:
    vulnerable_lines = artifact.vulnerable_content.splitlines()
    fixed_lines = artifact.fixed_content.splitlines()
    unified = "\n".join(
        difflib.unified_diff(
            vulnerable_lines,
            fixed_lines,
            fromfile=f"{artifact.artifact_id}.vulnerable",
            tofile=f"{artifact.artifact_id}.fixed",
            lineterm="",
        )
    )
    comparison = tuple(difflib.ndiff(vulnerable_lines, fixed_lines))
    return ArtifactDelta(
        artifact_id=artifact.artifact_id,
        kind=artifact.kind,
        diff_digest=_text_digest(unified),
        added_lines=tuple(line[2:].strip() for line in comparison if line.startswith("+ ")),
        removed_lines=tuple(line[2:].strip() for line in comparison if line.startswith("- ")),
    )


def _extract_semantics(delta: ArtifactDelta) -> _SecuritySemantics:
    condition = _marked_value(delta.added_lines, "condition:")
    invariant = _marked_value(delta.added_lines, "invariant:")
    sink = _marked_value(delta.added_lines, "sink:")
    boundary = _marked_value(delta.added_lines, "boundary:")
    return _SecuritySemantics(
        condition=condition or _first_condition(delta.added_lines),
        invariant=invariant or "the fixed revision enforces the changed access condition",
        sink=sink or "changed execution sink",
        boundary=boundary or "changed trust boundary",
    )


def _marked_value(lines: tuple[str, ...], marker: str) -> str | None:
    for line in lines:
        normalized = line.lstrip("# /-*\t").strip()
        if normalized.casefold().startswith(marker):
            return normalized[len(marker) :].strip()
    return None


def _first_condition(lines: tuple[str, ...]) -> str:
    return next(
        (line.strip() for line in lines if "if " in line or line.startswith("if")),
        "fixed revision changes the vulnerable branch condition",
    )


def _text_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
