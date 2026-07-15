from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from faultloom_protocol import HypothesisRecord, NegativeResult

from .models import HypothesisModelError, HypothesisSeed, hypothesis_id_for


class _EventModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
    )


class HypothesisEvent(_EventModel):
    researcher_id: str
    record: HypothesisRecord


class NegativeResultEvent(_EventModel):
    researcher_id: str
    record: NegativeResult


def validate_hypothesis_identity(record: HypothesisRecord) -> None:
    seed = HypothesisSeed(
        run_id=record.run_id,
        statement=record.statement,
        provenance=record.provenance,
        prerequisite_ids=record.prerequisite_ids,
        created_at=record.created_at,
        supporting_evidence=record.supporting_evidence,
        contradicting_evidence=record.contradicting_evidence,
    )
    if record.hypothesis_id != hypothesis_id_for(seed):
        raise HypothesisModelError("hypothesis ID is not its stable fingerprint")
