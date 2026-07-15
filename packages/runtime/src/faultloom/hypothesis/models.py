from __future__ import annotations

import hashlib
from typing import Self, assert_never

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    ContextCheckpoint,
    EvidenceRef,
    HypothesisRecord,
    HypothesisStatus,
    NegativeResult,
    ProvenanceKind,
    SCHEMA_VERSION,
    sha256_digest,
)
from faultloom_protocol.base import AwareDatetime, Identifier, NonEmptyStr, Sha256Digest


class _HypothesisModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class HypothesisModelError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class HypothesisCursorError(HypothesisModelError):
    pass


class HypothesisSeed(_HypothesisModel):
    run_id: Identifier
    statement: NonEmptyStr
    provenance: tuple[ProvenanceKind, ...] = Field(min_length=1)
    prerequisite_ids: tuple[Identifier, ...] = ()
    created_at: AwareDatetime
    supporting_evidence: tuple[EvidenceRef, ...] = ()
    contradicting_evidence: tuple[EvidenceRef, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.provenance)) != len(self.provenance):
            raise HypothesisModelError("hypothesis provenance must be unique")
        if len(set(self.prerequisite_ids)) != len(self.prerequisite_ids):
            raise HypothesisModelError("hypothesis prerequisites must be unique")
        evidence = self.supporting_evidence + self.contradicting_evidence
        if any(reference.run_id != self.run_id for reference in evidence):
            raise HypothesisModelError("hypothesis evidence belongs to another run")
        return self

    def as_record(self) -> HypothesisRecord:
        return HypothesisRecord(
            schema_version=SCHEMA_VERSION,
            hypothesis_id=hypothesis_id_for(self),
            run_id=self.run_id,
            statement=self.statement,
            provenance=self.provenance,
            status=HypothesisStatus.ACTIVE,
            created_at=self.created_at,
            updated_at=self.created_at,
            supporting_evidence=self.supporting_evidence,
            contradicting_evidence=self.contradicting_evidence,
            prerequisite_ids=self.prerequisite_ids,
        )


class NegativeResultSeed(_HypothesisModel):
    run_id: Identifier
    hypothesis_id: Identifier
    experiment_digest: Sha256Digest
    conclusion: NonEmptyStr
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def _evidence_matches_run(self) -> Self:
        if any(reference.run_id != self.run_id for reference in self.evidence_refs):
            raise HypothesisModelError("negative-result evidence belongs to another run")
        return self

    def as_record(self) -> NegativeResult:
        return NegativeResult(
            schema_version=SCHEMA_VERSION,
            negative_result_id=negative_result_id_for(self),
            run_id=self.run_id,
            hypothesis_id=self.hypothesis_id,
            experiment_digest=self.experiment_digest,
            conclusion=self.conclusion,
            evidence_refs=self.evidence_refs,
            recorded_at=self.recorded_at,
        )


class HypothesisCursor(_HypothesisModel):
    run_id: Identifier
    watermark: int = Field(ge=0)
    offset: int = Field(ge=0)
    binding_digest: Sha256Digest

    @model_validator(mode="after")
    def _bound(self) -> Self:
        if self.binding_digest != _cursor_digest(self.run_id, self.watermark, self.offset):
            raise HypothesisCursorError("hypothesis cursor binding is invalid")
        return self


class HypothesisPage(_HypothesisModel):
    run_id: Identifier
    watermark: int = Field(ge=0)
    entries: tuple[HypothesisRecord | NegativeResult, ...]
    next_cursor: HypothesisCursor | None = None


class ResearchContextRecords(_HypothesisModel):
    active_hypotheses: tuple[HypothesisRecord, ...]
    important_negative_results: tuple[NegativeResult, ...]


class HypothesisGraphState(_HypothesisModel):
    run_id: Identifier
    watermark: int = Field(ge=0)
    hypotheses: tuple[HypothesisRecord, ...]
    negative_results: tuple[NegativeResult, ...]

    def context_records(self, checkpoint: ContextCheckpoint) -> ResearchContextRecords:
        if checkpoint.run_id != self.run_id:
            raise HypothesisModelError("checkpoint belongs to another research run")
        hypotheses = {item.hypothesis_id: item for item in self.hypotheses}
        negatives = {item.negative_result_id: item for item in self.negative_results}
        try:
            active = tuple(hypotheses[item] for item in checkpoint.active_hypothesis_ids)
            important = tuple(
                negatives[item] for item in checkpoint.important_negative_result_ids
            )
        except KeyError as exc:
            raise HypothesisModelError(
                "checkpoint references missing durable research state"
            ) from exc
        if any(
            item.status not in {HypothesisStatus.ACTIVE, HypothesisStatus.SUPPORTED}
            for item in active
        ):
            raise HypothesisModelError(
                "checkpoint active hypotheses include a closed record"
            )
        return ResearchContextRecords(
            active_hypotheses=active,
            important_negative_results=important,
        )


def hypothesis_id_for(seed: HypothesisSeed) -> str:
    digest = sha256_digest(
        {
            "prerequisite_ids": sorted(seed.prerequisite_ids),
            "provenance": sorted(item.value for item in seed.provenance),
            "run_id": seed.run_id,
            "statement": seed.statement,
        }
    )
    return f"hypothesis.{digest.removeprefix('sha256:')}"


def negative_result_id_for(seed: NegativeResultSeed) -> str:
    digest = sha256_digest(
        {
            "conclusion": seed.conclusion,
            "evidence_ids": sorted(item.evidence_id for item in seed.evidence_refs),
            "experiment_digest": seed.experiment_digest,
            "hypothesis_id": seed.hypothesis_id,
            "run_id": seed.run_id,
        }
    )
    return f"negative.{digest.removeprefix('sha256:')}"


def make_cursor(run_id: str, watermark: int, offset: int) -> HypothesisCursor:
    return HypothesisCursor(
        run_id=run_id,
        watermark=watermark,
        offset=offset,
        binding_digest=_cursor_digest(run_id, watermark, offset),
    )


def entry_sort_key(
    entry: HypothesisRecord | NegativeResult,
) -> tuple[int, str]:
    match entry:
        case HypothesisRecord(hypothesis_id=hypothesis_id):
            return 0, hypothesis_id
        case NegativeResult(negative_result_id=negative_result_id):
            return 1, negative_result_id
        case unreachable:
            assert_never(unreachable)


def _cursor_digest(run_id: str, watermark: int, offset: int) -> str:
    material = f"faultloom-hypothesis-cursor-v1\0{run_id}\0{watermark}\0{offset}"
    return f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"
