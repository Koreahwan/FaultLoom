from __future__ import annotations

from pydantic import ValidationError

from faultloom._research_durable import (
    EncryptedEventSpec,
    append_encrypted,
    canonical_model_bytes,
    durable_events,
    load_encrypted,
)
from faultloom.state import EventRecord, StateStore, StorageError
from faultloom_protocol import HypothesisRecord, NegativeResult

from .models import (
    HypothesisCursor,
    HypothesisCursorError,
    HypothesisGraphState,
    HypothesisPage,
    HypothesisSeed,
    NegativeResultSeed,
    entry_sort_key,
    make_cursor,
)
from .wire import HypothesisEvent, NegativeResultEvent, validate_hypothesis_identity


HYPOTHESIS_EVENT_TYPE = "research.hypothesis.v1"
NEGATIVE_EVENT_TYPE = "research.negative_result.v1"
AUTHORITATIVE_ACTOR_STREAM = "research.authoritative"
HYPOTHESIS_MEDIA_TYPE = "application/vnd.faultloom.hypothesis+json"
NEGATIVE_MEDIA_TYPE = "application/vnd.faultloom.negative-result+json"


class HypothesisConflictError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class HypothesisJournal:
    def __init__(self, store: StateStore, run_id: str, researcher_id: str) -> None:
        self._store = store
        self._run_id = run_id
        self._researcher_id = researcher_id

    def state(self) -> HypothesisGraphState:
        hypotheses: dict[str, HypothesisRecord] = {}
        negatives: dict[str, NegativeResult] = {}
        watermark = 0
        for event in durable_events(self._store):
            if event.event_type == HYPOTHESIS_EVENT_TYPE:
                envelope = self._decode_hypothesis(event)
                if envelope.record.run_id != self._run_id:
                    continue
                if envelope.researcher_id != self._researcher_id:
                    raise HypothesisConflictError(
                        "hypothesis event was written by another researcher"
                    )
                validate_hypothesis_identity(envelope.record)
                self._apply_hypothesis(hypotheses, envelope.record)
                watermark = event.seq
            if event.event_type == NEGATIVE_EVENT_TYPE:
                envelope = self._decode_negative(event)
                if envelope.record.run_id != self._run_id:
                    continue
                if envelope.researcher_id != self._researcher_id:
                    raise HypothesisConflictError(
                        "negative result was written by another researcher"
                    )
                if envelope.record.hypothesis_id not in hypotheses:
                    raise HypothesisConflictError(
                        "negative result references missing durable hypothesis"
                    )
                prior = negatives.get(envelope.record.negative_result_id)
                if prior is not None and prior != envelope.record:
                    raise HypothesisConflictError(
                        "negative-result ID is bound to different state"
                    )
                negatives[envelope.record.negative_result_id] = envelope.record
                watermark = event.seq
        return HypothesisGraphState(
            run_id=self._run_id,
            watermark=watermark,
            hypotheses=tuple(hypotheses[key] for key in sorted(hypotheses)),
            negative_results=tuple(negatives[key] for key in sorted(negatives)),
        )

    def record_hypothesis(self, seed: HypothesisSeed) -> HypothesisRecord:
        if seed.run_id != self._run_id:
            raise HypothesisConflictError("hypothesis seed belongs to another run")
        record = seed.as_record()
        self.update_hypothesis(record)
        return record

    def update_hypothesis(self, record: HypothesisRecord) -> HypothesisRecord:
        exact = HypothesisRecord.model_validate(record.model_dump(mode="python"))
        if exact.run_id != self._run_id:
            raise HypothesisConflictError("hypothesis belongs to another run")
        validate_hypothesis_identity(exact)
        with self._store.serialized():
            state = self.state()
            prior = next(
                (item for item in state.hypotheses if item.hypothesis_id == exact.hypothesis_id),
                None,
            )
            if prior == exact:
                return exact
            if prior is not None:
                self._validate_update(prior, exact)
            envelope = HypothesisEvent(
                researcher_id=self._researcher_id,
                record=exact,
            )
            append_encrypted(
                self._store,
                envelope,
                self._spec(HYPOTHESIS_EVENT_TYPE, HYPOTHESIS_MEDIA_TYPE, exact.hypothesis_id),
            )
        return exact

    def record_negative_result(self, seed: NegativeResultSeed) -> NegativeResult:
        if seed.run_id != self._run_id:
            raise HypothesisConflictError("negative-result seed belongs to another run")
        exact = seed.as_record()
        with self._store.serialized():
            state = self.state()
            if exact.hypothesis_id not in {item.hypothesis_id for item in state.hypotheses}:
                raise HypothesisConflictError(
                    "negative result references missing durable hypothesis"
                )
            prior = next(
                (
                    item
                    for item in state.negative_results
                    if item.negative_result_id == exact.negative_result_id
                ),
                None,
            )
            if prior == exact:
                return exact
            if prior is not None:
                raise HypothesisConflictError(
                    "negative-result ID is bound to different state"
                )
            envelope = NegativeResultEvent(
                researcher_id=self._researcher_id,
                record=exact,
            )
            append_encrypted(
                self._store,
                envelope,
                self._spec(NEGATIVE_EVENT_TYPE, NEGATIVE_MEDIA_TYPE, exact.negative_result_id),
            )
        return exact

    def page(
        self,
        *,
        limit: int = 100,
        cursor: HypothesisCursor | None = None,
    ) -> HypothesisPage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise HypothesisCursorError("hypothesis page limit must be between 1 and 100")
        state = self.state()
        exact_cursor = self._validated_cursor(cursor, state)
        offset = 0 if exact_cursor is None else exact_cursor.offset
        entries = tuple(
            sorted(
                state.hypotheses + state.negative_results,
                key=entry_sort_key,
            )
        )
        page = entries[offset : offset + limit]
        next_offset = offset + len(page)
        next_cursor = (
            make_cursor(self._run_id, state.watermark, next_offset)
            if next_offset < len(entries)
            else None
        )
        return HypothesisPage(
            run_id=self._run_id,
            watermark=state.watermark,
            entries=page,
            next_cursor=next_cursor,
        )

    def _validated_cursor(
        self,
        cursor: HypothesisCursor | None,
        state: HypothesisGraphState,
    ) -> HypothesisCursor | None:
        if cursor is None:
            return None
        try:
            exact = HypothesisCursor.model_validate(cursor.model_dump(mode="python"))
        except (ValidationError, ValueError) as exc:
            raise HypothesisCursorError("hypothesis cursor is invalid") from exc
        if exact.run_id != self._run_id or exact.watermark != state.watermark:
            raise HypothesisCursorError("hypothesis cursor is stale or belongs to another run")
        return exact

    def _decode_hypothesis(self, event: EventRecord) -> HypothesisEvent:
        spec = self._spec(HYPOTHESIS_EVENT_TYPE, HYPOTHESIS_MEDIA_TYPE, "record")
        raw = load_encrypted(self._store, event, spec)
        try:
            envelope = HypothesisEvent.model_validate_json(raw)
        except (ValidationError, ValueError) as exc:
            raise HypothesisConflictError("durable hypothesis event is invalid") from exc
        if canonical_model_bytes(envelope) != raw:
            raise HypothesisConflictError("durable hypothesis event is not canonical")
        return envelope

    def _decode_negative(self, event: EventRecord) -> NegativeResultEvent:
        spec = self._spec(NEGATIVE_EVENT_TYPE, NEGATIVE_MEDIA_TYPE, "record")
        raw = load_encrypted(self._store, event, spec)
        try:
            envelope = NegativeResultEvent.model_validate_json(raw)
        except (ValidationError, ValueError, StorageError) as exc:
            raise HypothesisConflictError("durable negative-result event is invalid") from exc
        if canonical_model_bytes(envelope) != raw:
            raise HypothesisConflictError("durable negative-result event is not canonical")
        return envelope

    @staticmethod
    def _apply_hypothesis(
        records: dict[str, HypothesisRecord],
        record: HypothesisRecord,
    ) -> None:
        prior = records.get(record.hypothesis_id)
        if prior is not None:
            HypothesisJournal._validate_update(prior, record)
        records[record.hypothesis_id] = record

    @staticmethod
    def _validate_update(prior: HypothesisRecord, current: HypothesisRecord) -> None:
        immutable_prior = (
            prior.run_id,
            prior.statement,
            prior.provenance,
            prior.created_at,
            prior.prerequisite_ids,
        )
        immutable_current = (
            current.run_id,
            current.statement,
            current.provenance,
            current.created_at,
            current.prerequisite_ids,
        )
        if immutable_current != immutable_prior or current.updated_at < prior.updated_at:
            raise HypothesisConflictError("hypothesis update changed immutable state")
        if not set(prior.supporting_evidence).issubset(current.supporting_evidence):
            raise HypothesisConflictError("hypothesis update removed supporting evidence")
        if not set(prior.contradicting_evidence).issubset(current.contradicting_evidence):
            raise HypothesisConflictError("hypothesis update removed contradicting evidence")

    def _spec(self, event_type: str, media_type: str, record_id: str) -> EncryptedEventSpec:
        return EncryptedEventSpec(
            actor_stream=AUTHORITATIVE_ACTOR_STREAM,
            event_type=event_type,
            media_type=media_type,
            run_id=self._run_id,
            record_id=record_id,
        )
