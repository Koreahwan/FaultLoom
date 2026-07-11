from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo

import pytest
from pydantic import ValidationError

from faultloom.context import (
    BoundedRetriever,
    ContextAllocation,
    ContextBudgetError,
    ContextCompiler,
    ContextError,
    ContextGraphEdge,
    ContextGraphNode,
    ContextGraphSlice,
    ContextGraphSlices,
    ContextScopeError,
    ContextState,
    ProviderContextMetadata,
    ProviderMetadataError,
    RetrievalAccessError,
    RetrievalCursorError,
    RetrievalEncodingError,
    RetrievalError,
    RetrievalRangeError,
    RetrievalUnit,
    RetrievedContent,
    RetrievedView,
    ScopeTrustAnchor,
    checkpoint_binding_tag_for,
    content_id_for,
)
from faultloom_protocol import AuthoritySigner, sign_scope_epoch
from tests.protocol.factories import D1, D2, NOW, sample_models


VERIFY_AT = NOW + timedelta(minutes=1)
SCOPE_SIGNER = AuthoritySigner.from_private_bytes(bytes(range(32)))
DEFAULT_RETRIEVAL_KEY = b"retrieval-engagement-1-key" + b"x" * 32


class MemoryBackend:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], RetrievedContent] = {}

    def add(
        self,
        body: bytes,
        *,
        engagement_id: str = "engagement.1",
        run_id: str = "run.1",
        media_type: str = "text/plain",
        watermark: int = 10,
    ) -> RetrievedContent:
        record = RetrievedContent(
            engagement_id=engagement_id,
            run_id=run_id,
            content_id=content_id_for(body),
            media_type=media_type,
            body=body,
            watermark=watermark,
        )
        self.records[(engagement_id, record.content_id)] = record
        return record

    def load(self, *, engagement_id: str, content_id: str) -> RetrievedContent | None:
        return self.records.get((engagement_id, content_id))


def provider(*, context_window: int | None = 50_000) -> ProviderContextMetadata:
    return ProviderContextMetadata(
        provider_id="provider.test",
        requested_alias="frontier",
        actual_snapshot="frontier-2030-01-01",
        runtime_version="runtime-1.0.0",
        tokenizer_id="tokenizer-2030-01-01",
        context_window=context_window,
        prompt_digest=D1,
        tool_schema_digest=D2,
        snapshot_exact=True,
        context_window_exact=True,
        prompt_overhead_tokens=32,
        prompt_overhead_exact=True,
    )


def graph_slice(graph_id: str, *, reverse: bool = False) -> ContextGraphSlice:
    nodes = (
        ContextGraphNode(node_id="node.1", node_kind="subject", summary="Owned subject"),
        ContextGraphNode(node_id="node.2", node_kind="resource", summary="Canary resource"),
    )
    edges = (
        ContextGraphEdge(
            edge_id="edge.1",
            edge_kind="observed",
            source_id="node.1",
            target_id="node.2",
            summary="Evidence-linked observation",
            evidence_ids=("evidence.1",),
        ),
    )
    return ContextGraphSlice(
        graph_id=graph_id,
        watermark=10,
        nodes=tuple(reversed(nodes)) if reverse else nodes,
        edges=edges,
    )


def context_state(*, reverse_graph_nodes: bool = False) -> ContextState:
    models = sample_models()
    goal = "Rebuild FaultLoom v0.1 without widening authority."
    checkpoint = models["ContextCheckpoint"].model_copy(
        update={
            "goal_digest": content_id_for(goal.encode()),
            "pending_action_ids": ("action.pending",),
            "unknown_outcome_action_ids": ("action.unknown",),
        }
    )
    return ContextState(
        engagement_id="engagement.1",
        goal=goal,
        checkpoint=checkpoint,
        checkpoint_binding_tag=checkpoint_binding_tag_for(
            checkpoint,
            engagement_id="engagement.1",
            binding_key=DEFAULT_RETRIEVAL_KEY,
        ),
        signed_scope_epoch=sign_scope_epoch(
            models["ScopeEpoch"],
            SCOPE_SIGNER,
            signed_at=NOW,
        ),
        active_hypotheses=(models["HypothesisRecord"],),
        important_negative_results=(models["NegativeResult"],),
        graph_slices=ContextGraphSlices(
            identity=graph_slice("identity-graph.1", reverse=reverse_graph_nodes),
            workflow=graph_slice("workflow-graph.1", reverse=reverse_graph_nodes),
            surface=graph_slice("surface-graph.1", reverse=reverse_graph_nodes),
            chain=graph_slice("chain-graph.1", reverse=reverse_graph_nodes),
        ),
        retrieved_views=(),
    )


def scope_anchor(*, minimum_epoch: int = 7) -> ScopeTrustAnchor:
    checkpoint = context_state().checkpoint
    return ScopeTrustAnchor(
        authority_digest=checkpoint.authority_digest,
        grant_id="grant.1",
        public_key=SCOPE_SIGNER.public_key_record,
        minimum_epoch=minimum_epoch,
    )


def compiler(
    *,
    minimum_epoch: int = 7,
    retrieval_keys: dict[str, bytes] | None = None,
    lab_context_window: int = 4096,
    lab_unknown_prompt_overhead_tokens: int = 1024,
) -> ContextCompiler:
    return ContextCompiler(
        scope_anchors=(scope_anchor(minimum_epoch=minimum_epoch),),
        retrieval_binding_keys=(
            {"engagement.1": DEFAULT_RETRIEVAL_KEY}
            if retrieval_keys is None
            else retrieval_keys
        ),
        lab_context_window=lab_context_window,
        lab_unknown_prompt_overhead_tokens=lab_unknown_prompt_overhead_tokens,
    )


def compile_context(
    state: ContextState,
    metadata: ProviderContextMetadata,
    *,
    live: bool,
    context_compiler: ContextCompiler | None = None,
):
    return (context_compiler or compiler()).compile(
        state,
        metadata,
        live=live,
        verification_time=VERIFY_AT,
    )


@pytest.mark.parametrize(
    ("window", "input_limit", "output_reserve", "observation_reserve"),
    [
        (4, 2, 1, 1),
        (100, 75, 15, 10),
        (101, 74, 16, 11),
        (10_001, 7_499, 1_501, 1_001),
    ],
)
def test_budget_math_never_spends_reserves(
    window: int,
    input_limit: int,
    output_reserve: int,
    observation_reserve: int,
) -> None:
    allocation = ContextAllocation.for_window(window)
    assert allocation.input_limit == input_limit
    assert allocation.output_reserve == output_reserve
    assert allocation.observation_reserve == observation_reserve
    assert allocation.input_limit * 100 <= window * 75
    assert allocation.output_reserve * 100 >= window * 15
    assert allocation.observation_reserve * 100 >= window * 10
    assert sum(
        (
            allocation.input_limit,
            allocation.output_reserve,
            allocation.observation_reserve,
        )
    ) <= window


def test_budget_rejects_windows_too_small_for_all_three_allocations() -> None:
    with pytest.raises(ProviderMetadataError, match="too small"):
        ContextAllocation.for_window(2)
    with pytest.raises(ProviderMetadataError, match="positive integer"):
        ContextAllocation.for_window(True)  # type: ignore[arg-type]


def test_compiler_contains_every_mandatory_section_and_is_canonical() -> None:
    compiled = compile_context(context_state(), provider(), live=True)
    document = json.loads(compiled.payload)

    assert compiled.context_id == content_id_for(compiled.payload)
    assert compiled.input_tokens == len(compiled.payload) + 32
    assert compiled.input_tokens <= compiled.allocation.input_limit
    assert document["goal"]["text"].startswith("Rebuild FaultLoom")
    assert document["goal"]["digest"] == content_id_for(
        context_state().goal.encode()
    )
    assert document["plan"]["digest"] == D2
    assert set(document["scope"]) == {
        "grant_digest",
        "grant_id",
        "epoch",
        "signed_epoch_digest",
        "trusted_key_id",
        "signed_epoch",
    }
    assert document["scope"]["grant_id"] == "grant.1"
    assert document["scope"]["epoch"] == 7
    assert document["scope"]["trusted_key_id"] == SCOPE_SIGNER.key_id
    assert document["checkpoint_binding_tag"] == context_state().checkpoint_binding_tag
    assert set(document["research"]) == {
        "active_hypotheses",
        "important_negative_results",
    }
    assert set(document["graphs"]) == {"identity", "workflow", "surface", "chain"}
    assert set(document["actions"]) == {"pending_ids", "unknown_outcome_ids"}
    assert document["actions"] == {
        "pending_ids": ["action.pending"],
        "unknown_outcome_ids": ["action.unknown"],
    }
    assert set(document["evidence"]) == {
        "recent_refs",
        "retrieval_cursors",
        "bounded_views",
    }
    assert [item["evidence_id"] for item in document["evidence"]["recent_refs"]] == [
        "evidence.1"
    ]
    assert document["evidence"]["retrieval_cursors"] == [
        {
            "cursor": "cursor.1",
            "index_id": "evidence-index",
            "schema_version": "0.1.0",
            "watermark": 10,
        }
    ]
    assert document["secret_refs"] == [
        {
            "purpose": "owned identity",
            "schema_version": "0.1.0",
            "uri": "secret://run/identity-owner",
        }
    ]
    assert document["remaining_budget"] == {
        "actions": 80,
        "cost_microunits": 500000,
        "duration_seconds": 3000,
        "model_tokens": 100000,
        "schema_version": "0.1.0",
    }
    assert document["stable_watermark"] == 10
    assert b'"chain_of_thought"' not in compiled.payload
    assert compiled.payload == json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def test_compilation_order_is_deterministic() -> None:
    first = compile_context(context_state(), provider(), live=True)
    second = compile_context(
        context_state(reverse_graph_nodes=True),
        provider(),
        live=True,
    )
    assert first.payload == second.payload
    assert first.context_id == second.context_id


def test_context_reset_round_trip_preserves_all_state_and_context_ids() -> None:
    state = context_state(reverse_graph_nodes=True)
    restored = ContextState.model_validate_json(state.model_dump_json())
    first = compile_context(state, provider(), live=True)
    second = compile_context(restored, provider(), live=True)

    assert restored.checkpoint.checkpoint_id == state.checkpoint.checkpoint_id
    assert restored.signed_scope_epoch == state.signed_scope_epoch
    assert restored.checkpoint.pending_action_ids == ("action.pending",)
    assert restored.checkpoint.unknown_outcome_action_ids == ("action.unknown",)
    assert first.context_id == second.context_id
    assert first.payload == second.payload


def test_scope_epoch_is_bound_to_external_authority_and_current_minimum() -> None:
    state = context_state()
    with pytest.raises(ContextScopeError, match="at least one"):
        ContextCompiler(scope_anchors=())

    stale_compiler = compiler(minimum_epoch=8)
    with pytest.raises(ContextScopeError, match="trusted minimum"):
        compile_context(
            state,
            provider(),
            live=True,
            context_compiler=stale_compiler,
        )

    other_authority = state.model_copy(
        update={
            "checkpoint": state.checkpoint.model_copy(
                update={"authority_digest": "sha256:" + "99" * 32}
            )
        }
    )
    with pytest.raises(ContextScopeError, match="no external"):
        compile_context(other_authority, provider(), live=True)


def test_scope_signature_tamper_expiry_and_epoch_mismatch_fail_closed() -> None:
    state = context_state()
    signature = state.signed_scope_epoch.signature
    replacement = "A" if signature.signature[0] != "A" else "B"
    tampered = state.signed_scope_epoch.model_copy(
        update={
            "signature": signature.model_copy(
                update={"signature": replacement + signature.signature[1:]}
            )
        }
    )
    tampered_state = state.model_copy(update={"signed_scope_epoch": tampered})
    with pytest.raises(ContextScopeError, match="rejected"):
        compile_context(tampered_state, provider(), live=True)

    with pytest.raises(ContextScopeError, match="expired"):
        compiler().compile(
            state,
            provider(),
            live=True,
            verification_time=NOW + timedelta(hours=3),
        )

    mismatched = state.model_copy(
        update={
            "checkpoint": state.checkpoint.model_copy(update={"scope_epoch": 6})
        }
    )
    with pytest.raises(ValidationError, match="signed scope epoch"):
        ContextState.model_validate(mismatched.model_dump(mode="python"))


def test_checkpoint_binding_covers_cursors_actions_budget_and_engagement() -> None:
    state = context_state()
    changed_checkpoint = state.checkpoint.model_copy(
        update={"pending_action_ids": ("action.changed",)}
    )
    changed = state.model_copy(update={"checkpoint": changed_checkpoint})
    with pytest.raises(RetrievalAccessError, match="checkpoint.*unauthentic"):
        compile_context(changed, provider(), live=True)

    relabeled = state.model_copy(update={"engagement_id": "engagement.b"})
    with pytest.raises(RetrievalAccessError, match="checkpoint.*unauthentic"):
        compile_context(
            relabeled,
            provider(),
            live=True,
            context_compiler=compiler(
                retrieval_keys={"engagement.b": b"b" * 32}
            ),
        )


def test_goal_digest_and_invalid_unicode_cannot_cross_a_reset() -> None:
    state = context_state()
    changed_goal = state.model_copy(update={"goal": "Different aggregate goal"})
    with pytest.raises(ValidationError, match="goal digest"):
        ContextState.model_validate(changed_goal.model_dump(mode="python"))

    invalid_goal = state.model_copy(update={"goal": "bad\ud800goal"})
    with pytest.raises(ValidationError, match="unicode string|valid UTF-8"):
        ContextState.model_validate(invalid_goal.model_dump(mode="python"))

    invalid_hypothesis = state.active_hypotheses[0].model_copy(
        update={"statement": "bad\ud800hypothesis"}
    )
    invalid_research = state.model_copy(
        update={"active_hypotheses": (invalid_hypothesis,)}
    )
    with pytest.raises((ValidationError, ContextError), match="unicode string|valid UTF-8"):
        compile_context(invalid_research, provider(), live=False)


def test_missing_mandatory_fields_fail_closed() -> None:
    complete = context_state().model_dump(mode="python")
    for field in (
        "engagement_id",
        "goal",
        "checkpoint",
        "checkpoint_binding_tag",
        "signed_scope_epoch",
        "active_hypotheses",
        "important_negative_results",
        "graph_slices",
        "retrieved_views",
    ):
        incomplete = dict(complete)
        del incomplete[field]
        with pytest.raises(ValidationError, match=field):
            ContextState.model_validate(incomplete)

    graph_document = dict(complete["graph_slices"])
    del graph_document["chain"]
    incomplete = dict(complete)
    incomplete["graph_slices"] = graph_document
    with pytest.raises(ValidationError, match="chain"):
        ContextState.model_validate(incomplete)


def test_checkpoint_graph_and_research_mismatches_fail_closed() -> None:
    state = context_state()
    missing_graph = state.model_copy(
        update={
            "graph_slices": state.graph_slices.model_copy(update={"chain": None}),
        }
    )
    with pytest.raises(ValidationError, match="chain graph slice is required"):
        ContextState.model_validate(missing_graph.model_dump(mode="python"))

    checkpoint = state.checkpoint.model_copy(update={"active_hypothesis_ids": ()})
    mismatch = state.model_copy(update={"checkpoint": checkpoint})
    with pytest.raises(ValidationError, match="exactly match"):
        ContextState.model_validate(mismatch.model_dump(mode="python"))

    with pytest.raises(ValidationError, match="chain graph slice is required"):
        compile_context(missing_graph, provider(), live=False)


def test_checkpoint_rejects_overlapping_actions_and_unstable_cursors() -> None:
    state = context_state()
    overlapping = state.checkpoint.model_copy(
        update={
            "pending_action_ids": ("action.same",),
            "unknown_outcome_action_ids": ("action.same",),
        }
    )
    with pytest.raises(ValidationError, match="both pending and unknown"):
        ContextState.model_validate(
            state.model_copy(update={"checkpoint": overlapping}).model_dump(mode="python")
        )

    cursor = state.checkpoint.retrieval_cursors[0].model_copy(update={"watermark": 11})
    unstable = state.checkpoint.model_copy(update={"retrieval_cursors": (cursor,)})
    with pytest.raises(ValidationError, match="stable watermark"):
        ContextState.model_validate(
            state.model_copy(update={"checkpoint": unstable}).model_dump(mode="python")
        )


def test_unicode_overflow_is_counted_by_utf8_bytes_without_truncation() -> None:
    goal = "한" * 4_000
    original = context_state()
    checkpoint = original.checkpoint.model_copy(
        update={"goal_digest": content_id_for(goal.encode())}
    )
    state = original.model_copy(
        update={
            "goal": goal,
            "checkpoint": checkpoint,
            "checkpoint_binding_tag": checkpoint_binding_tag_for(
                checkpoint,
                engagement_id="engagement.1",
                binding_key=DEFAULT_RETRIEVAL_KEY,
            ),
        }
    )
    with pytest.raises(ContextBudgetError, match="exceeds the input allocation"):
        compile_context(state, provider(context_window=10_000), live=False)
    assert state.goal == "한" * 4_000


@pytest.mark.parametrize(
    ("updates", "detail"),
    [
        ({"actual_snapshot": None}, "actual_snapshot"),
        ({"runtime_version": None}, "runtime_version"),
        ({"tokenizer_id": None}, "tokenizer_id"),
        ({"context_window": None}, "context_window"),
        ({"prompt_digest": None}, "prompt_digest"),
        ({"tool_schema_digest": None}, "tool_schema_digest"),
        ({"snapshot_exact": False}, "exactness flags"),
        ({"context_window_exact": False}, "exactness flags"),
        ({"prompt_overhead_exact": False}, "exactness flags"),
    ],
)
def test_live_compilation_rejects_ambiguous_provider_metadata(
    updates: dict[str, object], detail: str
) -> None:
    ambiguous = provider().model_copy(update=updates)
    with pytest.raises(ProviderMetadataError, match=detail):
        compile_context(context_state(), ambiguous, live=True)


def test_lab_uses_explicit_conservative_fallback_for_missing_window() -> None:
    ambiguous = provider(context_window=None).model_copy(
        update={
            "actual_snapshot": None,
            "runtime_version": None,
            "tokenizer_id": None,
            "prompt_digest": None,
            "tool_schema_digest": None,
            "snapshot_exact": False,
            "context_window_exact": False,
            "prompt_overhead_exact": False,
        }
    )
    compiled = compile_context(
        context_state(),
        ambiguous,
        live=False,
        context_compiler=compiler(lab_context_window=50_000),
    )
    assert compiled.allocation.context_window == 50_000
    document = json.loads(compiled.payload)
    assert document["context_allocation"]["effective_prompt_overhead_tokens"] == 1024
    assert compiled.input_tokens == len(compiled.payload) + 1024


def test_lab_ambiguous_window_never_expands_past_conservative_fallback() -> None:
    ambiguous = provider(context_window=500_000).model_copy(
        update={
            "context_window_exact": False,
            "prompt_overhead_exact": False,
        }
    )
    compiled = compile_context(
        context_state(),
        ambiguous,
        live=False,
        context_compiler=compiler(
            lab_context_window=50_000,
            lab_unknown_prompt_overhead_tokens=2048,
        ),
    )
    assert compiled.allocation.context_window == 50_000
    assert compiled.input_tokens == len(compiled.payload) + 2048


def test_scope_verification_time_must_be_explicitly_aware() -> None:
    with pytest.raises(ContextScopeError, match="timezone"):
        compiler().compile(
            context_state(),
            provider(),
            live=True,
            verification_time=NOW.replace(tzinfo=None),
        )


def test_scope_verification_time_rejects_datetime_alias_before_comparison() -> None:
    class MasqueradingDatetime(datetime):
        magic_calls = 0

        @classmethod
        def _unexpected(cls):
            cls.magic_calls += 1
            raise AssertionError("datetime subclass behavior executed")

        def __add__(self, other: object):
            return type(self)._unexpected()

        def __lt__(self, other: object) -> bool:
            return type(self)._unexpected()

        def __le__(self, other: object) -> bool:
            return type(self)._unexpected()

        def __gt__(self, other: object) -> bool:
            return type(self)._unexpected()

        def __ge__(self, other: object) -> bool:
            return type(self)._unexpected()

        def utcoffset(self):
            return type(self)._unexpected()

    expired = NOW + timedelta(hours=3)
    with pytest.raises(ContextScopeError, match="expired"):
        compiler().compile(
            context_state(),
            provider(),
            live=True,
            verification_time=expired,
        )

    alias = MasqueradingDatetime(
        expired.year,
        expired.month,
        expired.day,
        expired.hour,
        expired.minute,
        expired.second,
        expired.microsecond,
        tzinfo=expired.tzinfo,
        fold=expired.fold,
    )
    with pytest.raises(ContextScopeError, match="exact datetime"):
        compiler().compile(
            context_state(),
            provider(),
            live=True,
            verification_time=alias,
        )
    assert MasqueradingDatetime.magic_calls == 0


def test_scope_verification_time_rejects_custom_tzinfo_without_hooks() -> None:
    class CountingTimezone(tzinfo):
        calls = 0

        def utcoffset(self, value: datetime | None) -> timedelta:
            type(self).calls += 1
            return timedelta(0)

        def dst(self, value: datetime | None) -> timedelta:
            type(self).calls += 1
            return timedelta(0)

        def tzname(self, value: datetime | None) -> str:
            type(self).calls += 1
            return "UTC"

    class ExplodingTimezone(tzinfo):
        calls = 0

        @classmethod
        def _unexpected(cls):
            cls.calls += 1
            raise AssertionError("caller-controlled tzinfo hook executed")

        def utcoffset(self, value: datetime | None):
            return type(self)._unexpected()

        def dst(self, value: datetime | None):
            return type(self)._unexpected()

        def tzname(self, value: datetime | None):
            return type(self)._unexpected()

    assert VERIFY_AT.tzinfo is timezone.utc
    for hostile in (CountingTimezone(), ExplodingTimezone()):
        supplied = datetime(
            VERIFY_AT.year,
            VERIFY_AT.month,
            VERIFY_AT.day,
            VERIFY_AT.hour,
            VERIFY_AT.minute,
            VERIFY_AT.second,
            VERIFY_AT.microsecond,
            tzinfo=hostile,
            fold=VERIFY_AT.fold,
        )
        with pytest.raises(ContextScopeError, match=r"timezone\.utc"):
            compiler().compile(
                context_state(),
                provider(),
                live=True,
                verification_time=supplied,
            )
    assert CountingTimezone.calls == 0
    assert ExplodingTimezone.calls == 0


def test_compile_rejects_non_boolean_live_scalar_before_truth_testing() -> None:
    class ExplodingTruth:
        truth_calls = 0

        def __bool__(self) -> bool:
            type(self).truth_calls += 1
            raise AssertionError("caller-controlled truth test executed")

    live = ExplodingTruth()
    with pytest.raises(ProviderMetadataError, match="exact boolean"):
        compiler().compile(
            context_state(),
            provider(),
            live=live,  # type: ignore[arg-type]
            verification_time=VERIFY_AT,
        )
    assert ExplodingTruth.truth_calls == 0


def test_line_ranges_reference_full_output_and_continue_without_loss() -> None:
    backend = MemoryBackend()
    body = "첫째\n둘째\n셋째\n".encode()
    record = backend.add(body)
    retriever = BoundedRetriever(backend, cursor_key=b"c" * 32, max_page_lines=2)

    first = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=2,
    )
    repeated = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=2,
    )
    assert first.value == "첫째\n둘째\n"
    assert first.content_id == content_id_for(body)
    assert first.full_byte_length == len(body)
    assert (first.start, first.end, first.total_units) == (0, 2, 3)
    assert first.next_cursor is not None
    assert first.next_cursor == repeated.next_cursor

    final = retriever.continue_range(
        engagement_id="engagement.1",
        cursor=first.next_cursor,
    )
    assert final.value == "셋째\n"
    assert (final.start, final.end, final.total_units) == (2, 3, 3)
    assert final.next_cursor is None
    assert (first.value + final.value).encode() == body


def test_byte_ranges_preserve_arbitrary_original_bytes() -> None:
    backend = MemoryBackend()
    body = b"\xff\x00\x80binary\n"
    record = backend.add(body, media_type="application/octet-stream")
    retriever = BoundedRetriever(backend, cursor_key=b"d" * 32, max_page_bytes=4)

    first = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.BYTES,
        start=0,
        count=4,
    )
    assert base64.b64decode(first.value) == body[:4]
    assert first.content_id == content_id_for(body)
    with pytest.raises(RetrievalEncodingError, match="UTF-8"):
        retriever.read_range(
            engagement_id="engagement.1",
            content_id=record.content_id,
            unit=RetrievalUnit.LINES,
            start=0,
            count=1,
        )


def test_context_rejects_a_retrieved_view_bound_to_another_engagement() -> None:
    backend = MemoryBackend()
    record = backend.add(b"private\n", engagement_id="engagement.a")
    view = BoundedRetriever(backend, cursor_key=b"j" * 32).read_range(
        engagement_id="engagement.a",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    state = context_state().model_copy(update={"retrieved_views": (view,)})
    with pytest.raises(ValidationError, match="context engagement"):
        ContextState.model_validate(state.model_dump(mode="python"))


def test_retrieved_view_digest_and_range_cannot_be_forged() -> None:
    backend = MemoryBackend()
    record = backend.add(b"one\ntwo\n")
    view = BoundedRetriever(backend, cursor_key=b"k" * 32).read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    forged = view.model_dump(mode="python")
    forged["value"] = "changed\n"
    with pytest.raises(ValidationError, match="page digest"):
        type(view).model_validate(forged)


def test_retrieval_range_limits_fail_closed() -> None:
    backend = MemoryBackend()
    record = backend.add(b"one\ntwo\nthree\n")
    retriever = BoundedRetriever(
        backend,
        cursor_key=b"e" * 32,
        max_page_bytes=4,
        max_page_lines=2,
    )
    with pytest.raises(RetrievalRangeError, match="configured bound"):
        retriever.read_range(
            engagement_id="engagement.1",
            content_id=record.content_id,
            unit=RetrievalUnit.BYTES,
            start=0,
            count=5,
        )
    with pytest.raises(RetrievalRangeError, match="configured bound"):
        retriever.read_range(
            engagement_id="engagement.1",
            content_id=record.content_id,
            unit=RetrievalUnit.LINES,
            start=0,
            count=3,
        )
    with pytest.raises(RetrievalRangeError, match="non-negative"):
        retriever.read_range(
            engagement_id="engagement.1",
            content_id=record.content_id,
            unit=RetrievalUnit.BYTES,
            start=-1,
            count=1,
        )

    large_line = backend.add(b"x" * 5 + b"\n")
    with pytest.raises(RetrievalRangeError, match="byte bound"):
        retriever.read_range(
            engagement_id="engagement.1",
            content_id=large_line.content_id,
            unit=RetrievalUnit.LINES,
            start=0,
            count=1,
        )


def test_cursor_tamper_and_watermark_change_fail_closed() -> None:
    backend = MemoryBackend()
    record = backend.add(b"one\ntwo\n")
    retriever = BoundedRetriever(backend, cursor_key=b"f" * 32, max_page_lines=1)
    first = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    assert first.next_cursor is not None
    replacement = "A" if first.next_cursor[-1] != "A" else "B"
    tampered = first.next_cursor[:-1] + replacement
    with pytest.raises(RetrievalCursorError, match="authentication"):
        retriever.continue_range(engagement_id="engagement.1", cursor=tampered)

    backend.records[("engagement.1", record.content_id)] = replace(record, watermark=11)
    with pytest.raises(RetrievalCursorError, match="watermark"):
        retriever.continue_range(
            engagement_id="engagement.1",
            cursor=first.next_cursor,
        )


def test_cursor_is_bound_to_the_original_run() -> None:
    backend = MemoryBackend()
    record = backend.add(b"one\ntwo\n")
    retriever = BoundedRetriever(backend, cursor_key=b"u" * 32, max_page_lines=1)
    first = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    assert first.next_cursor is not None
    backend.records[("engagement.1", record.content_id)] = replace(
        record,
        run_id="run.2",
    )
    with pytest.raises(RetrievalCursorError, match="stored run"):
        retriever.continue_range(
            engagement_id="engagement.1",
            cursor=first.next_cursor,
        )


@pytest.mark.parametrize(
    ("original_media_type", "replacement_media_type"),
    (
        ("text/plain", "text/html"),
        ("application/octet-stream", "text/plain"),
        ("text/plain", "application/octet-stream"),
    ),
)
def test_cursor_is_bound_to_the_exact_media_type(
    original_media_type: str,
    replacement_media_type: str,
) -> None:
    backend = MemoryBackend()
    record = backend.add(
        b"one\ntwo\n",
        media_type=original_media_type,
    )
    retriever = BoundedRetriever(
        backend,
        cursor_key=b"media-type-cursor-key" + b"m" * 32,
        max_page_lines=1,
    )
    first = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    assert first.next_cursor is not None
    unchanged = retriever.continue_range(
        engagement_id="engagement.1",
        cursor=first.next_cursor,
    )
    assert unchanged.media_type == original_media_type

    backend.records[("engagement.1", record.content_id)] = replace(
        record,
        media_type=replacement_media_type,
    )
    with pytest.raises(RetrievalCursorError, match="media type"):
        retriever.continue_range(
            engagement_id="engagement.1",
            cursor=first.next_cursor,
        )


def test_direct_and_cursor_access_are_strictly_engagement_scoped() -> None:
    backend = MemoryBackend()
    record = backend.add(b"private-a\nsecond\n", engagement_id="engagement.a")
    retriever = BoundedRetriever(backend, cursor_key=b"g" * 32, max_page_lines=1)
    first = retriever.read_range(
        engagement_id="engagement.a",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    assert first.next_cursor is not None

    with pytest.raises(RetrievalAccessError, match="unavailable"):
        retriever.read_range(
            engagement_id="engagement.b",
            content_id=record.content_id,
            unit=RetrievalUnit.LINES,
            start=0,
            count=1,
        )
    with pytest.raises(RetrievalAccessError, match="unavailable"):
        retriever.continue_range(
            engagement_id="engagement.b",
            cursor=first.next_cursor,
        )


def test_backend_cannot_substitute_other_engagement_or_changed_content() -> None:
    class LyingBackend:
        def __init__(self, record: RetrievedContent) -> None:
            self.record = record

        def load(self, *, engagement_id: str, content_id: str) -> RetrievedContent | None:
            return self.record

    original = RetrievedContent(
        engagement_id="engagement.a",
        run_id="run.1",
        content_id=content_id_for(b"original"),
        media_type="text/plain",
        body=b"original",
        watermark=1,
    )
    retriever = BoundedRetriever(LyingBackend(original), cursor_key=b"h" * 32)
    with pytest.raises(RetrievalAccessError, match="unavailable"):
        retriever.read_range(
            engagement_id="engagement.b",
            content_id=original.content_id,
            unit=RetrievalUnit.BYTES,
            start=0,
            count=1,
        )

    changed = replace(original, body=b"changed!")
    retriever = BoundedRetriever(LyingBackend(changed), cursor_key=b"i" * 32)
    with pytest.raises(RetrievalAccessError, match="unavailable"):
        retriever.read_range(
            engagement_id="engagement.a",
            content_id=original.content_id,
            unit=RetrievalUnit.BYTES,
            start=0,
            count=1,
        )


def test_backend_subclass_cannot_change_body_between_validation_and_view() -> None:
    original = b"AAAA"
    changed = b"BBBB"

    class SideEffectingContent(RetrievedContent):
        def __getattribute__(self, name: str):
            if name == "body":
                accesses = object.__getattribute__(self, "_body_accesses")
                object.__setattr__(self, "_body_accesses", accesses + 1)
                return original if accesses < 2 else changed
            return super().__getattribute__(name)

    record = SideEffectingContent(
        engagement_id="engagement.1",
        run_id="run.1",
        content_id=content_id_for(original),
        media_type="application/octet-stream",
        body=original,
        watermark=1,
    )
    object.__setattr__(record, "_body_accesses", 0)

    class Backend:
        def load(
            self, *, engagement_id: str, content_id: str
        ) -> RetrievedContent | None:
            return record

    retriever = BoundedRetriever(Backend(), cursor_key=DEFAULT_RETRIEVAL_KEY)
    with pytest.raises(RetrievalError, match="invalid record"):
        retriever.read_range(
            engagement_id="engagement.1",
            content_id=content_id_for(original),
            unit=RetrievalUnit.BYTES,
            start=0,
            count=4,
        )
    assert object.__getattribute__(record, "_body_accesses") == 0


def test_backend_snapshot_is_detached_from_post_validation_mutation() -> None:
    original = b"original"
    record = RetrievedContent(
        engagement_id="engagement.1",
        run_id="run.1",
        content_id=content_id_for(original),
        media_type="application/octet-stream",
        body=original,
        watermark=1,
    )

    class Backend:
        def load(
            self, *, engagement_id: str, content_id: str
        ) -> RetrievedContent | None:
            return record

    class MutatingAfterLoadRetriever(BoundedRetriever):
        def _load(self, *, engagement_id: str, content_id: str):
            snapshot = super()._load(
                engagement_id=engagement_id,
                content_id=content_id,
            )
            object.__setattr__(record, "body", b"changed!")
            return snapshot

    view = MutatingAfterLoadRetriever(
        Backend(), cursor_key=DEFAULT_RETRIEVAL_KEY
    ).read_range(
        engagement_id="engagement.1",
        content_id=content_id_for(original),
        unit=RetrievalUnit.BYTES,
        start=0,
        count=len(original),
    )
    assert base64.b64decode(view.value) == original
    assert view.full_byte_length == len(original)
    compile_context(
        context_state().model_copy(update={"retrieved_views": (view,)}),
        provider(),
        live=True,
    )


@pytest.mark.parametrize("body", [bytearray(b"mutable"), memoryview(b"aliased")])
def test_backend_rejects_non_bytes_body(body: object) -> None:
    record = RetrievedContent(
        engagement_id="engagement.1",
        run_id="run.1",
        content_id=content_id_for(bytes(body)),
        media_type="application/octet-stream",
        body=body,  # type: ignore[arg-type]
        watermark=1,
    )

    class Backend:
        def load(
            self, *, engagement_id: str, content_id: str
        ) -> RetrievedContent | None:
            return record

    with pytest.raises(RetrievalError, match="exact immutable bytes"):
        BoundedRetriever(Backend(), cursor_key=b"v" * 32).read_range(
            engagement_id="engagement.1",
            content_id=record.content_id,
            unit=RetrievalUnit.BYTES,
            start=0,
            count=1,
        )


def test_backend_rejects_bytes_subclass_before_oversize_conversion() -> None:
    class OversizeOnConversion(bytes):
        conversion_attempted = False

        def __bytes__(self) -> bytes:
            type(self).conversion_attempted = True
            return b"x" * 1_048_577

    body = OversizeOnConversion(b"safe")
    record = RetrievedContent(
        engagement_id="engagement.1",
        run_id="run.1",
        content_id=content_id_for(b"safe"),
        media_type="application/octet-stream",
        body=body,
        watermark=1,
    )

    class Backend:
        def load(
            self, *, engagement_id: str, content_id: str
        ) -> RetrievedContent | None:
            return record

    with pytest.raises(RetrievalError, match="exact immutable bytes"):
        BoundedRetriever(Backend(), cursor_key=b"w" * 32).read_range(
            engagement_id="engagement.1",
            content_id=record.content_id,
            unit=RetrievalUnit.BYTES,
            start=0,
            count=1,
        )
    assert not OversizeOnConversion.conversion_attempted


def test_public_retrieval_boundaries_reject_string_aliases_before_lookup() -> None:
    class MasqueradingStr(str):
        def __new__(cls, visible: str, target: str):
            instance = super().__new__(cls, visible)
            instance.target = target
            instance.magic_calls = 0
            return instance

        def __hash__(self) -> int:
            self.magic_calls += 1
            return hash(self.target)

        def __eq__(self, other: object) -> bool:
            self.magic_calls += 1
            return type(other) is str and other == self.target

        def __len__(self) -> int:
            self.magic_calls += 1
            return len(self.target)

        def __iter__(self):
            self.magic_calls += 1
            return iter(self.target)

        def startswith(self, prefix: object, *args: object) -> bool:
            self.magic_calls += 1
            return self.target.startswith(prefix, *args)

        def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
            self.magic_calls += 1
            return self.target.encode(encoding, errors)

    class MasqueradingCursor(str):
        def __new__(cls, visible: str, target: str):
            instance = super().__new__(cls, visible)
            instance.target = target
            instance.magic_calls = 0
            return instance

        def __len__(self) -> int:
            self.magic_calls += 1
            return len(self.target)

        def count(self, value: str, *args: object) -> int:
            self.magic_calls += 1
            return self.target.count(value, *args)

        def split(self, separator: str | None = None, maxsplit: int = -1):
            self.magic_calls += 1
            return self.target.split(separator, maxsplit)

    class CountingBackend(MemoryBackend):
        def __init__(self) -> None:
            super().__init__()
            self.load_calls = 0

        def load(
            self, *, engagement_id: str, content_id: str
        ) -> RetrievedContent | None:
            self.load_calls += 1
            return super().load(
                engagement_id=engagement_id,
                content_id=content_id,
            )

    victim_engagement = "engagement.victim"
    attacker_engagement = "engagement.attacker"
    backend = CountingBackend()
    victim = backend.add(
        b"victim-page-one\nvictim-page-two\n",
        engagement_id=victim_engagement,
    )
    retriever = BoundedRetriever(
        backend,
        cursor_key=b"public-boundary-key" + b"x" * 32,
        max_page_lines=1,
    )
    first = retriever.read_range(
        engagement_id=victim_engagement,
        content_id=victim.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    assert first.next_cursor is not None
    assert backend.load_calls == 1

    attacker_content_id = content_id_for(b"attacker-placeholder")
    hostile_engagement_only = MasqueradingStr(
        attacker_engagement,
        victim_engagement,
    )
    hostile_content_only = MasqueradingStr(
        attacker_content_id,
        victim.content_id,
    )
    hostile_engagement_pair = MasqueradingStr(
        attacker_engagement,
        victim_engagement,
    )
    hostile_content_pair = MasqueradingStr(
        attacker_content_id,
        victim.content_id,
    )
    hostile_values = (
        (
            hostile_engagement_only,
            victim.content_id,
            (hostile_engagement_only,),
        ),
        (
            victim_engagement,
            hostile_content_only,
            (hostile_content_only,),
        ),
        (
            hostile_engagement_pair,
            hostile_content_pair,
            (hostile_engagement_pair, hostile_content_pair),
        ),
    )
    for engagement_id, content_id, aliases in hostile_values:
        with pytest.raises(RetrievalError):
            retriever.read_range(
                engagement_id=engagement_id,
                content_id=content_id,
                unit=RetrievalUnit.LINES,
                start=0,
                count=1,
            )
        assert all(alias.magic_calls == 0 for alias in aliases)
        assert backend.load_calls == 1

    hostile_engagement = MasqueradingStr(
        attacker_engagement,
        victim_engagement,
    )
    unconsumed_cursor = MasqueradingCursor("attacker.cursor", first.next_cursor)
    with pytest.raises(RetrievalError):
        retriever.continue_range(
            engagement_id=hostile_engagement,
            cursor=unconsumed_cursor,
        )
    assert hostile_engagement.magic_calls == 0
    assert unconsumed_cursor.magic_calls == 0
    assert backend.load_calls == 1

    hostile_cursor = MasqueradingCursor("attacker.cursor", first.next_cursor)
    with pytest.raises(RetrievalCursorError):
        retriever.continue_range(
            engagement_id=victim_engagement,
            cursor=hostile_cursor,
        )
    assert hostile_cursor.magic_calls == 0
    assert backend.load_calls == 1


def test_public_scalar_boundaries_reject_subclasses_without_conversion() -> None:
    class ExplodingStr(str):
        magic_calls = 0

        def __hash__(self) -> int:
            type(self).magic_calls += 1
            return str.__hash__(self)

        def __len__(self) -> int:
            type(self).magic_calls += 1
            raise AssertionError("string subclass length executed")

        def __iter__(self):
            type(self).magic_calls += 1
            raise AssertionError("string subclass iteration executed")

        def encode(self, *args: object, **kwargs: object) -> bytes:
            type(self).magic_calls += 1
            raise AssertionError("string subclass encoding executed")

    class ExplodingBytes(bytes):
        magic_calls = 0

        def __len__(self) -> int:
            type(self).magic_calls += 1
            raise AssertionError("bytes subclass length executed")

        def __bytes__(self) -> bytes:
            type(self).magic_calls += 1
            raise AssertionError("bytes subclass conversion executed")

        def __hash__(self) -> int:
            type(self).magic_calls += 1
            raise AssertionError("bytes subclass hash executed")

    class ExplodingInt(int):
        magic_calls = 0

        def __lt__(self, other: object) -> bool:
            type(self).magic_calls += 1
            raise AssertionError("int subclass comparison executed")

        def __gt__(self, other: object) -> bool:
            type(self).magic_calls += 1
            raise AssertionError("int subclass comparison executed")

        def __add__(self, other: object):
            type(self).magic_calls += 1
            raise AssertionError("int subclass addition executed")

    backend = MemoryBackend()
    record = backend.add(b"bounded")
    explosive_key = ExplodingBytes(b"k" * 32)
    with pytest.raises(ValueError, match="cursor_key"):
        BoundedRetriever(backend, cursor_key=explosive_key)
    assert ExplodingBytes.magic_calls == 0

    for key in (bytearray(b"k" * 32), memoryview(b"k" * 32)):
        with pytest.raises(ValueError, match="cursor_key"):
            BoundedRetriever(backend, cursor_key=key)  # type: ignore[arg-type]

    retriever = BoundedRetriever(backend, cursor_key=b"k" * 32)
    for start, count in ((ExplodingInt(0), 1), (0, ExplodingInt(1))):
        with pytest.raises(RetrievalRangeError):
            retriever.read_range(
                engagement_id="engagement.1",
                content_id=record.content_id,
                unit=RetrievalUnit.BYTES,
                start=start,
                count=count,
            )
    assert ExplodingInt.magic_calls == 0

    for option in ("max_page_bytes", "max_page_lines"):
        with pytest.raises(ValueError, match=option):
            BoundedRetriever(
                backend,
                cursor_key=b"k" * 32,
                **{option: ExplodingInt(1)},
            )
    assert ExplodingInt.magic_calls == 0

    with pytest.raises(ProviderMetadataError, match="context window"):
        ContextAllocation.for_window(ExplodingInt(4096))
    assert ExplodingInt.magic_calls == 0

    ExplodingBytes.magic_calls = 0
    with pytest.raises(TypeError, match="body must be bytes"):
        content_id_for(ExplodingBytes(b"body"))
    assert ExplodingBytes.magic_calls == 0
    for body in (bytearray(b"body"), memoryview(b"body")):
        with pytest.raises(TypeError, match="body must be bytes"):
            content_id_for(body)  # type: ignore[arg-type]

    ExplodingBytes.magic_calls = 0
    with pytest.raises(ValueError, match="binding key"):
        checkpoint_binding_tag_for(
            context_state().checkpoint,
            engagement_id="engagement.1",
            binding_key=ExplodingBytes(b"b" * 32),
        )
    assert ExplodingBytes.magic_calls == 0

    hostile_engagement = ExplodingStr("engagement.1")
    with pytest.raises(RetrievalError, match="engagement_id"):
        checkpoint_binding_tag_for(
            context_state().checkpoint,
            engagement_id=hostile_engagement,
            binding_key=b"b" * 32,
        )
    assert ExplodingStr.magic_calls == 0

    ExplodingBytes.magic_calls = 0
    with pytest.raises(ValueError, match="retrieval binding keys"):
        compiler(
            retrieval_keys={"engagement.1": ExplodingBytes(b"b" * 32)}
        )
    assert ExplodingBytes.magic_calls == 0

    hostile_retrieval_key = ExplodingStr("engagement.1")
    hostile_mapping = {hostile_retrieval_key: b"b" * 32}
    ExplodingStr.magic_calls = 0
    with pytest.raises(RetrievalError, match="retrieval key engagement_id"):
        compiler(retrieval_keys=hostile_mapping)
    assert ExplodingStr.magic_calls == 0


def test_backend_rejects_scalar_subclasses_before_magic_methods() -> None:
    class StoredStr(str):
        magic_calls = 0

        def __eq__(self, other: object) -> bool:
            type(self).magic_calls += 1
            raise AssertionError("stored string equality executed")

        def __hash__(self) -> int:
            type(self).magic_calls += 1
            raise AssertionError("stored string hash executed")

        def encode(self, *args: object, **kwargs: object) -> bytes:
            type(self).magic_calls += 1
            raise AssertionError("stored string encoding executed")

    class StoredInt(int):
        magic_calls = 0

        def __le__(self, other: object) -> bool:
            type(self).magic_calls += 1
            raise AssertionError("stored integer comparison executed")

    original = b"stored-scalars"
    records = (
        RetrievedContent(
            engagement_id=StoredStr("engagement.1"),
            run_id="run.1",
            content_id=content_id_for(original),
            media_type="application/octet-stream",
            body=original,
            watermark=1,
        ),
        RetrievedContent(
            engagement_id="engagement.1",
            run_id="run.1",
            content_id=content_id_for(original),
            media_type="application/octet-stream",
            body=original,
            watermark=StoredInt(1),
        ),
    )

    class Backend:
        def __init__(self, record: RetrievedContent) -> None:
            self.record = record

        def load(
            self, *, engagement_id: str, content_id: str
        ) -> RetrievedContent | None:
            return self.record

    for record in records:
        with pytest.raises(RetrievalError):
            BoundedRetriever(Backend(record), cursor_key=b"z" * 32).read_range(
                engagement_id="engagement.1",
                content_id=content_id_for(original),
                unit=RetrievalUnit.BYTES,
                start=0,
                count=1,
            )
    assert StoredStr.magic_calls == 0
    assert StoredInt.magic_calls == 0


def test_cursor_replay_is_read_only_and_watermark_change_expires_it() -> None:
    backend = MemoryBackend()
    record = backend.add(b"page-one\npage-two\n", watermark=14)
    retriever = BoundedRetriever(
        backend,
        cursor_key=b"replay-expiry-key" + b"r" * 32,
        max_page_lines=1,
    )
    first = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    assert first.next_cursor is not None
    replayed_once = retriever.continue_range(
        engagement_id="engagement.1",
        cursor=first.next_cursor,
    )
    replayed_twice = retriever.continue_range(
        engagement_id="engagement.1",
        cursor=first.next_cursor,
    )
    assert replayed_once == replayed_twice

    backend.records[("engagement.1", record.content_id)] = replace(
        record,
        watermark=15,
    )
    with pytest.raises(RetrievalCursorError, match="watermark"):
        retriever.continue_range(
            engagement_id="engagement.1",
            cursor=first.next_cursor,
        )


def test_backend_rejects_control_characters_in_media_type() -> None:
    backend = MemoryBackend()
    record = backend.add(b"data", media_type="text/plain\nforged")
    retriever = BoundedRetriever(backend, cursor_key=b"m" * 32)
    with pytest.raises(RetrievalError, match="media type"):
        retriever.read_range(
            engagement_id="engagement.1",
            content_id=record.content_id,
            unit=RetrievalUnit.BYTES,
            start=0,
            count=1,
        )


def test_range_cursor_and_full_cas_ids_are_stable_across_reset() -> None:
    backend = MemoryBackend()
    body = b"one\ntwo\nthree\n"
    record = backend.add(body)
    first_retriever = BoundedRetriever(
        backend,
        cursor_key=DEFAULT_RETRIEVAL_KEY,
        max_page_lines=2,
    )
    second_retriever = BoundedRetriever(
        backend,
        cursor_key=DEFAULT_RETRIEVAL_KEY,
        max_page_lines=2,
    )
    first = first_retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=2,
    )
    after_reset = second_retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=2,
    )
    restored_view = RetrievedView.model_validate_json(first.model_dump_json())

    assert first.content_id == content_id_for(body)
    assert first.full_byte_length == len(body)
    assert first.range_id == after_reset.range_id == restored_view.range_id
    assert first.next_cursor == after_reset.next_cursor == restored_view.next_cursor
    assert first.next_cursor_id == after_reset.next_cursor_id

    state = context_state().model_copy(update={"retrieved_views": (first,)})
    restored_state = ContextState.model_validate_json(state.model_dump_json())
    context_compiler = compiler(
        retrieval_keys={"engagement.1": DEFAULT_RETRIEVAL_KEY}
    )
    before = compile_context(
        state,
        provider(),
        live=True,
        context_compiler=context_compiler,
    )
    after = compile_context(
        restored_state,
        provider(),
        live=True,
        context_compiler=context_compiler,
    )
    assert before.context_id == after.context_id
    assert before.payload == after.payload


def test_context_requires_an_authentic_engagement_binding_for_every_view() -> None:
    backend = MemoryBackend()
    record = backend.add(b"private\nsecond\n")
    view = BoundedRetriever(
        backend,
        cursor_key=DEFAULT_RETRIEVAL_KEY,
        max_page_lines=1,
    ).read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    state = context_state().model_copy(update={"retrieved_views": (view,)})

    with pytest.raises(RetrievalAccessError, match="no trusted"):
        compile_context(
            state,
            provider(),
            live=True,
            context_compiler=compiler(retrieval_keys={}),
        )

    tag = view.binding_tag
    replacement = "0" if tag[-1] != "0" else "1"
    forged = view.model_copy(update={"binding_tag": tag[:-1] + replacement})
    forged_state = state.model_copy(update={"retrieved_views": (forged,)})
    with pytest.raises(RetrievalAccessError, match="unauthentic"):
        compile_context(
            forged_state,
            provider(),
            live=True,
            context_compiler=compiler(
                retrieval_keys={"engagement.1": DEFAULT_RETRIEVAL_KEY}
            ),
        )


def test_cross_engagement_view_relabel_is_rejected_even_when_shape_is_valid() -> None:
    backend = MemoryBackend()
    body = b"same digest, separate engagement\nnext\n"
    record_a = backend.add(body, engagement_id="engagement.a")
    record_b = backend.add(body, engagement_id="engagement.b")
    key_a = b"a" * 32
    key_b = b"b" * 32
    view_a = BoundedRetriever(backend, cursor_key=key_a, max_page_lines=1).read_range(
        engagement_id="engagement.a",
        content_id=record_a.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    view_b = BoundedRetriever(backend, cursor_key=key_b, max_page_lines=1).read_range(
        engagement_id="engagement.b",
        content_id=record_b.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    forged_b = view_b.model_copy(update={"binding_tag": view_a.binding_tag})
    base = context_state()
    state_b = base.model_copy(
        update={
            "engagement_id": "engagement.b",
            "checkpoint_binding_tag": checkpoint_binding_tag_for(
                base.checkpoint,
                engagement_id="engagement.b",
                binding_key=key_b,
            ),
            "retrieved_views": (forged_b,),
        }
    )
    ContextState.model_validate(state_b.model_dump(mode="python"))

    with pytest.raises(RetrievalAccessError, match="unauthentic"):
        compile_context(
            state_b,
            provider(),
            live=True,
            context_compiler=compiler(retrieval_keys={"engagement.b": key_b}),
        )


def test_range_id_and_hard_oversize_bounds_cannot_be_forged() -> None:
    backend = MemoryBackend()
    record = backend.add(b"bounded\n")
    view = BoundedRetriever(backend, cursor_key=b"r" * 32).read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    forged = view.model_dump(mode="python")
    forged["range_id"] = "sha256:" + "00" * 32
    with pytest.raises(ValidationError, match="range ID"):
        RetrievedView.model_validate(forged)

    with pytest.raises(ValueError, match="max_page_bytes"):
        BoundedRetriever(
            backend,
            cursor_key=b"s" * 32,
            max_page_bytes=1_048_577,
        )
    with pytest.raises(ValueError, match="max_page_lines"):
        BoundedRetriever(
            backend,
            cursor_key=b"s" * 32,
            max_page_lines=50_001,
        )


def test_cursor_rejects_oversize_and_noncanonical_base64url() -> None:
    backend = MemoryBackend()
    record = backend.add(b"one\ntwo\n")
    retriever = BoundedRetriever(backend, cursor_key=b"t" * 32, max_page_lines=1)
    first = retriever.read_range(
        engagement_id="engagement.1",
        content_id=record.content_id,
        unit=RetrievalUnit.LINES,
        start=0,
        count=1,
    )
    assert first.next_cursor is not None

    with pytest.raises(RetrievalCursorError, match="malformed"):
        retriever.continue_range(
            engagement_id="engagement.1",
            cursor="A" * 4097,
        )

    payload_part, signature_part = first.next_cursor.split(".", 1)
    decoded = base64.urlsafe_b64decode(signature_part + "=" * (-len(signature_part) % 4))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    alternate = next(
        candidate
        for candidate in alphabet
        if candidate != signature_part[-1]
        and base64.urlsafe_b64decode(
            signature_part[:-1] + candidate + "=" * (-len(signature_part) % 4)
        )
        == decoded
    )
    noncanonical = f"{payload_part}.{signature_part[:-1]}{alternate}"
    with pytest.raises(RetrievalCursorError, match="malformed"):
        retriever.continue_range(
            engagement_id="engagement.1",
            cursor=noncanonical,
        )
