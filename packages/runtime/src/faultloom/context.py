"""Deterministic, bounded model context and engagement-scoped retrieval.

The compiler accepts only structured state.  Full tool outputs stay in the
engagement CAS; a model context contains bounded views plus stable content
identifiers and cursors.  Hidden reasoning is not an input to this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal, Protocol, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from faultloom_protocol import (
    ContextCheckpoint,
    Ed25519PublicKeyRecord,
    EvidenceRef,
    HypothesisRecord,
    HypothesisStatus,
    NegativeResult,
    SignedScopeEpoch,
    canonical_json_bytes,
    verify_scope_epoch,
)
from faultloom_protocol.base import Identifier, MAX_INT64, NonEmptyStr, Sha256Digest, ShortStr
from faultloom_protocol.models import NonNegativeInt, PositiveInt
from faultloom_protocol.signing import SignatureVerificationError


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CURSOR_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_CURSOR_VERSION = 1
_CHECKPOINT_BINDING_DOMAIN = b"faultloom-context-checkpoint-v1\0"
_CURSOR_AUTH_DOMAIN = b"faultloom-range-cursor-v1\0"
_VIEW_BINDING_DOMAIN = b"faultloom-retrieved-view-v1\0"
MAX_RETRIEVAL_PAGE_BYTES = 1_048_576
MAX_RETRIEVAL_PAGE_LINES = 50_000
MAX_RETRIEVED_VALUE_CHARACTERS = 1_398_104


class ContextError(ValueError):
    """Base error for deterministic context preparation."""


class ContextBudgetError(ContextError):
    """The complete structured context does not fit the input allocation."""


class ProviderMetadataError(ContextError):
    """Provider metadata is insufficient for safe context accounting."""


class ContextScopeError(ContextError):
    """Signed scope state is absent, stale, revoked, or unauthentic."""


class RetrievalError(ValueError):
    """Base error for bounded retrieval."""


class RetrievalAccessError(RetrievalError):
    """Content is unavailable to the requested engagement."""


class RetrievalCursorError(RetrievalError):
    """An opaque retrieval cursor is malformed or unauthentic."""


class RetrievalRangeError(RetrievalError):
    """A requested range exceeds the configured per-view bound."""


class RetrievalEncodingError(RetrievalError):
    """Line retrieval was requested for non-UTF-8 content."""


class _RuntimeModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        str_strip_whitespace=False,
        validate_default=True,
    )


class ContextGraphNode(_RuntimeModel):
    node_id: Identifier
    node_kind: Identifier
    summary: NonEmptyStr
    evidence_ids: tuple[Identifier, ...] = ()

    @field_validator("summary")
    @classmethod
    def _summary_is_not_padded(cls, value: str) -> str:
        return _require_unpadded_text(value, "graph node summary")

    @model_validator(mode="after")
    def _unique_evidence(self) -> Self:
        _require_unique(self.evidence_ids, "graph node evidence IDs")
        return self


class ContextGraphEdge(_RuntimeModel):
    edge_id: Identifier
    edge_kind: Identifier
    source_id: Identifier
    target_id: Identifier
    summary: NonEmptyStr
    evidence_ids: tuple[Identifier, ...] = ()

    @field_validator("summary")
    @classmethod
    def _summary_is_not_padded(cls, value: str) -> str:
        return _require_unpadded_text(value, "graph edge summary")

    @model_validator(mode="after")
    def _unique_evidence(self) -> Self:
        _require_unique(self.evidence_ids, "graph edge evidence IDs")
        return self


class ContextGraphSlice(_RuntimeModel):
    graph_id: Identifier
    watermark: PositiveInt
    nodes: tuple[ContextGraphNode, ...]
    edges: tuple[ContextGraphEdge, ...]

    @model_validator(mode="after")
    def _valid_graph(self) -> Self:
        node_ids = tuple(node.node_id for node in self.nodes)
        edge_ids = tuple(edge.edge_id for edge in self.edges)
        _require_unique(node_ids, "graph node IDs")
        _require_unique(edge_ids, "graph edge IDs")
        known_nodes = frozenset(node_ids)
        for edge in self.edges:
            if edge.source_id not in known_nodes or edge.target_id not in known_nodes:
                raise ValueError("graph edges must reference nodes present in the slice")
        return self


class ContextGraphSlices(_RuntimeModel):
    """Explicit slices; ``None`` means that graph does not yet exist."""

    identity: ContextGraphSlice | None
    workflow: ContextGraphSlice | None
    surface: ContextGraphSlice | None
    chain: ContextGraphSlice | None


class ScopeTrustAnchor(_RuntimeModel):
    """Externally trusted scope identity, never accepted from model state."""

    authority_digest: Sha256Digest
    grant_id: Identifier
    public_key: Ed25519PublicKeyRecord
    minimum_epoch: PositiveInt


class RetrievalUnit(str, Enum):
    BYTES = "bytes"
    LINES = "lines"


class RetrievedView(_RuntimeModel):
    engagement_digest: Sha256Digest
    run_id: Identifier
    content_id: Sha256Digest
    range_id: Sha256Digest
    media_type: ShortStr
    full_byte_length: NonNegativeInt
    unit: RetrievalUnit
    start: NonNegativeInt
    end: NonNegativeInt
    total_units: NonNegativeInt
    encoding: Literal["base64", "utf-8"]
    value: str = Field(max_length=MAX_RETRIEVED_VALUE_CHARACTERS)
    page_digest: Sha256Digest
    watermark: PositiveInt
    next_cursor: str | None = Field(default=None, min_length=3, max_length=4096)
    next_cursor_id: Sha256Digest | None = None
    binding_tag: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")

    @field_validator("media_type")
    @classmethod
    def _media_type_is_not_padded(cls, value: str) -> str:
        return _require_unpadded_text(value, "media type")

    @model_validator(mode="after")
    def _valid_bounds(self) -> Self:
        if self.end < self.start or self.end > self.total_units:
            raise ValueError("retrieved view bounds are invalid")
        if (self.next_cursor is not None) != (self.end < self.total_units):
            raise ValueError("a partial retrieved view requires a continuation cursor")
        if (self.next_cursor is None) != (self.next_cursor_id is None):
            raise ValueError("cursor and cursor ID must be present together")
        if self.next_cursor is not None:
            try:
                cursor_bytes = self.next_cursor.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError("continuation cursor must be ASCII") from exc
            if self.next_cursor_id != _raw_digest(cursor_bytes):
                raise ValueError("cursor ID does not identify the continuation cursor")
        expected_range_id = _range_id(
            engagement_digest=self.engagement_digest,
            run_id=self.run_id,
            content_id=self.content_id,
            unit=self.unit,
            start=self.start,
            end=self.end,
            total_units=self.total_units,
            page_digest=self.page_digest,
            watermark=self.watermark,
        )
        if self.range_id != expected_range_id:
            raise ValueError("range ID does not identify the retrieved range")
        if self.unit is RetrievalUnit.BYTES and self.encoding != "base64":
            raise ValueError("byte views must use base64 encoding")
        if self.unit is RetrievalUnit.LINES and self.encoding != "utf-8":
            raise ValueError("line views must use UTF-8 encoding")
        if self.unit is RetrievalUnit.BYTES:
            try:
                page = base64.b64decode(self.value, validate=True)
            except binascii.Error as exc:
                raise ValueError("byte view is not canonical base64") from exc
            if base64.b64encode(page).decode("ascii") != self.value:
                raise ValueError("byte view is not canonical base64")
            if self.full_byte_length != self.total_units:
                raise ValueError("byte view total must equal the full byte length")
        else:
            try:
                page = self.value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("line view is not valid UTF-8") from exc
            if len(_utf8_lines(page)) != self.end - self.start:
                raise ValueError("line view content does not match its range")
        if len(page) > MAX_RETRIEVAL_PAGE_BYTES:
            raise ValueError("retrieved view exceeds the hard byte bound")
        if len(page) > self.full_byte_length or _raw_digest(page) != self.page_digest:
            raise ValueError("retrieved view page digest does not match its content")
        if self.unit is RetrievalUnit.BYTES and len(page) != self.end - self.start:
            raise ValueError("byte view content does not match its range")
        return self


class ProviderContextMetadata(_RuntimeModel):
    """Provider facts used before T22 supplies the concrete adapter."""

    provider_id: Identifier
    requested_alias: ShortStr | None
    actual_snapshot: ShortStr | None
    runtime_version: ShortStr | None
    tokenizer_id: ShortStr | None
    context_window: PositiveInt | None
    prompt_digest: Sha256Digest | None
    tool_schema_digest: Sha256Digest | None
    snapshot_exact: bool
    context_window_exact: bool
    prompt_overhead_tokens: NonNegativeInt
    prompt_overhead_exact: bool

    @field_validator(
        "requested_alias",
        "actual_snapshot",
        "runtime_version",
        "tokenizer_id",
    )
    @classmethod
    def _metadata_is_not_padded(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _require_unpadded_text(value, "provider metadata")

    def require_live_safe(self) -> None:
        required = {
            "actual_snapshot": self.actual_snapshot,
            "runtime_version": self.runtime_version,
            "tokenizer_id": self.tokenizer_id,
            "context_window": self.context_window,
            "prompt_digest": self.prompt_digest,
            "tool_schema_digest": self.tool_schema_digest,
        }
        missing = sorted(name for name, value in required.items() if value is None)
        if missing or not (
            self.snapshot_exact and self.context_window_exact and self.prompt_overhead_exact
        ):
            details = ", ".join(missing) if missing else "exactness flags"
            raise ProviderMetadataError(f"live provider metadata is ambiguous: {details}")


class ContextState(_RuntimeModel):
    """All state that must cross every model-call boundary."""

    engagement_id: Identifier
    goal: NonEmptyStr
    checkpoint: ContextCheckpoint
    checkpoint_binding_tag: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    signed_scope_epoch: SignedScopeEpoch
    active_hypotheses: tuple[HypothesisRecord, ...]
    important_negative_results: tuple[NegativeResult, ...]
    graph_slices: ContextGraphSlices
    retrieved_views: tuple[RetrievedView, ...]

    @field_validator("goal")
    @classmethod
    def _goal_is_not_padded(cls, value: str) -> str:
        return _require_unpadded_text(value, "goal")

    @model_validator(mode="after")
    def _consistent_with_checkpoint(self) -> Self:
        checkpoint = self.checkpoint
        if _raw_digest(self.goal.encode("utf-8")) != checkpoint.goal_digest:
            raise ValueError("goal text does not match the checkpoint goal digest")
        if self.signed_scope_epoch.payload.epoch != checkpoint.scope_epoch:
            raise ValueError("signed scope epoch does not match the checkpoint epoch")
        hypotheses = {record.hypothesis_id: record for record in self.active_hypotheses}
        negatives = {
            record.negative_result_id: record for record in self.important_negative_results
        }
        if len(hypotheses) != len(self.active_hypotheses):
            raise ValueError("active hypothesis IDs must be unique")
        if len(negatives) != len(self.important_negative_results):
            raise ValueError("important negative-result IDs must be unique")
        _require_unique(checkpoint.active_hypothesis_ids, "checkpoint active hypothesis IDs")
        _require_unique(
            checkpoint.important_negative_result_ids,
            "checkpoint important negative-result IDs",
        )
        if frozenset(hypotheses) != frozenset(checkpoint.active_hypothesis_ids):
            raise ValueError("active hypotheses must exactly match the checkpoint IDs")
        if frozenset(negatives) != frozenset(checkpoint.important_negative_result_ids):
            raise ValueError("important negative results must exactly match the checkpoint IDs")

        for hypothesis in hypotheses.values():
            if hypothesis.run_id != checkpoint.run_id:
                raise ValueError("hypotheses must belong to the checkpoint run")
            if hypothesis.status not in {HypothesisStatus.ACTIVE, HypothesisStatus.SUPPORTED}:
                raise ValueError("active context cannot contain closed hypotheses")
        for negative in negatives.values():
            if negative.run_id != checkpoint.run_id:
                raise ValueError("negative results must belong to the checkpoint run")

        _validate_evidence_runs(self, checkpoint.run_id)
        _require_unique(checkpoint.pending_action_ids, "pending action IDs")
        _require_unique(checkpoint.unknown_outcome_action_ids, "unknown-outcome action IDs")
        if set(checkpoint.pending_action_ids) & set(checkpoint.unknown_outcome_action_ids):
            raise ValueError("an action cannot be both pending and unknown-outcome")
        _require_unique(
            tuple(secret.uri for secret in checkpoint.secret_refs),
            "secret references",
        )
        _require_unique(
            tuple(
                (cursor.index_id, cursor.cursor, cursor.watermark)
                for cursor in checkpoint.retrieval_cursors
            ),
            "retrieval cursors",
        )
        if any(
            cursor.watermark > checkpoint.stable_watermark
            for cursor in checkpoint.retrieval_cursors
        ):
            raise ValueError("retrieval cursors cannot exceed the stable watermark")

        expected_engagement_digest = _engagement_digest(self.engagement_id)
        view_keys: list[tuple[object, ...]] = []
        for view in self.retrieved_views:
            if not hmac.compare_digest(view.engagement_digest, expected_engagement_digest):
                raise ValueError("retrieved views must belong to the context engagement")
            if view.run_id != checkpoint.run_id:
                raise ValueError("retrieved views must belong to the checkpoint run")
            if view.watermark > checkpoint.stable_watermark:
                raise ValueError("retrieved views cannot exceed the stable watermark")
            view_keys.append((view.content_id, view.unit.value, view.start, view.end))
        _require_unique(tuple(view_keys), "retrieved view ranges")

        graph_pairs = (
            ("identity", checkpoint.identity_graph_id, self.graph_slices.identity),
            ("workflow", checkpoint.workflow_graph_id, self.graph_slices.workflow),
            ("surface", checkpoint.surface_graph_id, self.graph_slices.surface),
            ("chain", checkpoint.chain_graph_id, self.graph_slices.chain),
        )
        for name, expected_id, graph_slice in graph_pairs:
            if expected_id is None and graph_slice is not None:
                raise ValueError(f"{name} graph slice is present without a checkpoint graph ID")
            if expected_id is not None and graph_slice is None:
                raise ValueError(f"{name} graph slice is required by the checkpoint")
            if graph_slice is not None:
                if graph_slice.graph_id != expected_id:
                    raise ValueError(f"{name} graph slice ID does not match the checkpoint")
                if graph_slice.watermark > checkpoint.stable_watermark:
                    raise ValueError(f"{name} graph slice exceeds the stable watermark")
        return self


@dataclass(frozen=True)
class ContextAllocation:
    context_window: int
    input_limit: int
    output_reserve: int
    observation_reserve: int

    @classmethod
    def for_window(cls, context_window: int) -> ContextAllocation:
        if (
            type(context_window) is not int
            or context_window <= 0
            or context_window > MAX_INT64
        ):
            raise ProviderMetadataError("context window must be a positive integer")
        output_reserve = _ceil_percent(context_window, 15)
        observation_reserve = _ceil_percent(context_window, 10)
        remaining = context_window - output_reserve - observation_reserve
        input_limit = min((context_window * 75) // 100, remaining)
        if input_limit <= 0:
            raise ProviderMetadataError("context window is too small for mandatory reserves")
        return cls(
            context_window=context_window,
            input_limit=input_limit,
            output_reserve=output_reserve,
            observation_reserve=observation_reserve,
        )


@dataclass(frozen=True)
class CompiledContext:
    context_id: str
    payload: bytes
    input_tokens: int
    allocation: ContextAllocation

    @property
    def text(self) -> str:
        return self.payload.decode("utf-8")


class ContextCompiler:
    """Compile mandatory state without silently dropping overflow content."""

    def __init__(
        self,
        *,
        scope_anchors: tuple[ScopeTrustAnchor, ...],
        retrieval_binding_keys: Mapping[str, bytes] | None = None,
        lab_context_window: int = 4096,
        lab_unknown_prompt_overhead_tokens: int = 1024,
    ) -> None:
        self._lab_context_window = ContextAllocation.for_window(lab_context_window).context_window
        if (
            type(lab_unknown_prompt_overhead_tokens) is not int
            or not 0 <= lab_unknown_prompt_overhead_tokens <= MAX_INT64
        ):
            raise ProviderMetadataError(
                "lab unknown prompt overhead must be a non-negative integer"
            )
        self._lab_unknown_prompt_overhead_tokens = lab_unknown_prompt_overhead_tokens

        anchors: dict[str, ScopeTrustAnchor] = {}
        for candidate in scope_anchors:
            anchor = ScopeTrustAnchor.model_validate(candidate.model_dump(mode="python"))
            if anchor.authority_digest in anchors:
                raise ContextScopeError("scope authority digests must be unique")
            anchors[anchor.authority_digest] = anchor
        if not anchors:
            raise ContextScopeError("at least one external scope trust anchor is required")
        self._scope_anchors = anchors

        binding_keys: dict[str, bytes] = {}
        for engagement_id, key in (retrieval_binding_keys or {}).items():
            _require_identifier(engagement_id, "retrieval key engagement_id")
            if not isinstance(key, bytes) or len(key) < 32:
                raise ValueError("retrieval binding keys must contain at least 32 bytes")
            binding_keys[engagement_id] = bytes(key)
        self._retrieval_binding_keys = binding_keys

    def compile(
        self,
        state: ContextState,
        provider: ProviderContextMetadata,
        *,
        live: bool,
        verification_time: datetime,
    ) -> CompiledContext:
        state = ContextState.model_validate(state.model_dump(mode="python"))
        provider = ProviderContextMetadata.model_validate(provider.model_dump(mode="python"))
        _require_aware_datetime(verification_time)
        scope_anchor = self._verify_scope(state, verification_time=verification_time)
        self._verify_engagement_bindings(state)
        if live:
            provider.require_live_safe()
        context_window, prompt_overhead_tokens = self._effective_provider_limits(
            provider,
            live=live,
        )
        allocation = ContextAllocation.for_window(context_window)
        try:
            payload = canonical_json_bytes(
                _context_document(
                    state,
                    provider,
                    allocation,
                    scope_anchor=scope_anchor,
                    effective_prompt_overhead_tokens=prompt_overhead_tokens,
                    live=live,
                )
            )
        except UnicodeEncodeError as exc:
            raise ContextError("context contains text that is not valid UTF-8") from exc
        input_tokens = len(payload) + prompt_overhead_tokens
        if input_tokens > allocation.input_limit:
            payload_digest = _raw_digest(payload)
            raise ContextBudgetError(
                "compiled context exceeds the input allocation "
                f"({input_tokens}>{allocation.input_limit}, payload={payload_digest})"
            )
        return CompiledContext(
            context_id=_raw_digest(payload),
            payload=payload,
            input_tokens=input_tokens,
            allocation=allocation,
        )

    def _verify_scope(
        self,
        state: ContextState,
        *,
        verification_time: datetime,
    ) -> ScopeTrustAnchor:
        checkpoint = state.checkpoint
        anchor = self._scope_anchors.get(checkpoint.authority_digest)
        if anchor is None:
            raise ContextScopeError("checkpoint authority has no external scope trust anchor")
        if checkpoint.scope_epoch < anchor.minimum_epoch:
            raise ContextScopeError("checkpoint scope epoch is below the trusted minimum")
        try:
            verified = verify_scope_epoch(
                state.signed_scope_epoch,
                anchor.public_key,
                now=verification_time,
                minimum_epoch=anchor.minimum_epoch,
                expected_grant_id=anchor.grant_id,
            )
        except SignatureVerificationError as exc:
            raise ContextScopeError(f"signed scope epoch was rejected: {exc}") from exc
        if verified.epoch != checkpoint.scope_epoch:
            raise ContextScopeError("verified scope epoch does not match the checkpoint")
        return anchor

    def _verify_engagement_bindings(self, state: ContextState) -> None:
        key = self._retrieval_binding_keys.get(state.engagement_id)
        if key is None:
            raise RetrievalAccessError("context has no trusted engagement binding key")
        expected_checkpoint_tag = checkpoint_binding_tag_for(
            state.checkpoint,
            engagement_id=state.engagement_id,
            binding_key=key,
        )
        if not hmac.compare_digest(state.checkpoint_binding_tag, expected_checkpoint_tag):
            raise RetrievalAccessError("checkpoint engagement binding is unauthentic")
        for view in state.retrieved_views:
            expected = _view_binding_tag(key, view)
            if not hmac.compare_digest(view.binding_tag, expected):
                raise RetrievalAccessError("retrieved view binding is unauthentic")

    def _effective_provider_limits(
        self,
        provider: ProviderContextMetadata,
        *,
        live: bool,
    ) -> tuple[int, int]:
        if live:
            if provider.context_window is None:
                raise ProviderMetadataError("live context window is unavailable")
            return provider.context_window, provider.prompt_overhead_tokens
        if provider.context_window is None or not provider.context_window_exact:
            context_window = self._lab_context_window
            if provider.context_window is not None:
                context_window = min(context_window, provider.context_window)
        else:
            context_window = provider.context_window
        if provider.prompt_overhead_exact:
            prompt_overhead_tokens = provider.prompt_overhead_tokens
        else:
            prompt_overhead_tokens = max(
                provider.prompt_overhead_tokens,
                self._lab_unknown_prompt_overhead_tokens,
            )
        return context_window, prompt_overhead_tokens


@dataclass(frozen=True)
class RetrievedContent:
    """Immutable full output returned by an engagement-aware CAS adapter."""

    engagement_id: str
    run_id: str
    content_id: str
    media_type: str
    body: bytes
    watermark: int


class RetrievalBackend(Protocol):
    def load(self, *, engagement_id: str, content_id: str) -> RetrievedContent | None:
        """Return content only when it belongs to ``engagement_id``."""


class BoundedRetriever:
    """Produce authenticated range views over immutable full outputs."""

    def __init__(
        self,
        backend: RetrievalBackend,
        *,
        cursor_key: bytes,
        max_page_bytes: int = 65_536,
        max_page_lines: int = 500,
    ) -> None:
        if not isinstance(cursor_key, bytes) or len(cursor_key) < 32:
            raise ValueError("cursor_key must contain at least 32 bytes")
        if (
            type(max_page_bytes) is not int
            or not 0 < max_page_bytes <= MAX_RETRIEVAL_PAGE_BYTES
        ):
            raise ValueError(
                f"max_page_bytes must be between 1 and {MAX_RETRIEVAL_PAGE_BYTES}"
            )
        if (
            type(max_page_lines) is not int
            or not 0 < max_page_lines <= MAX_RETRIEVAL_PAGE_LINES
        ):
            raise ValueError(
                f"max_page_lines must be between 1 and {MAX_RETRIEVAL_PAGE_LINES}"
            )
        self._backend = backend
        self._cursor_key = bytes(cursor_key)
        self._max_page_bytes = max_page_bytes
        self._max_page_lines = max_page_lines

    def read_range(
        self,
        *,
        engagement_id: str,
        content_id: str,
        unit: RetrievalUnit,
        start: int,
        count: int,
    ) -> RetrievedView:
        _require_identifier(engagement_id, "engagement_id")
        _require_digest(content_id, "content_id")
        if not isinstance(unit, RetrievalUnit):
            raise RetrievalRangeError("unit must be a RetrievalUnit")
        _validate_range(start, count)
        maximum = self._max_page_bytes if unit is RetrievalUnit.BYTES else self._max_page_lines
        if count > maximum:
            raise RetrievalRangeError(f"requested {unit.value} count exceeds the configured bound")
        content = self._load(engagement_id=engagement_id, content_id=content_id)
        return self._view(content, unit=unit, start=start, count=count)

    def continue_range(self, *, engagement_id: str, cursor: str) -> RetrievedView:
        _require_identifier(engagement_id, "engagement_id")
        cursor_payload = self._decode_cursor(cursor)
        expected_engagement = _engagement_digest(engagement_id)
        if not hmac.compare_digest(cursor_payload["engagement_digest"], expected_engagement):
            raise RetrievalAccessError("retrieval unavailable for engagement")
        unit = RetrievalUnit(cursor_payload["unit"])
        count = cursor_payload["count"]
        maximum = self._max_page_bytes if unit is RetrievalUnit.BYTES else self._max_page_lines
        if count > maximum:
            raise RetrievalCursorError("cursor range exceeds the configured bound")
        content = self._load(
            engagement_id=engagement_id,
            content_id=cursor_payload["content_id"],
        )
        if content.run_id != cursor_payload["run_id"]:
            raise RetrievalCursorError("cursor no longer identifies the stored run")
        if content.watermark != cursor_payload["watermark"]:
            raise RetrievalCursorError("cursor watermark no longer identifies the stored output")
        return self._view(
            content,
            unit=unit,
            start=cursor_payload["start"],
            count=count,
        )

    def _load(self, *, engagement_id: str, content_id: str) -> RetrievedContent:
        content = self._backend.load(engagement_id=engagement_id, content_id=content_id)
        if content is None:
            raise RetrievalAccessError("retrieval unavailable for engagement")
        if not isinstance(content, RetrievedContent):
            raise RetrievalError("retrieval backend returned an invalid record")
        if not isinstance(content.body, bytes):
            raise RetrievalError("stored output must be bytes")
        if not isinstance(content.media_type, str):
            raise RetrievalError("stored media type is invalid")
        valid_identity = (
            content.engagement_id == engagement_id
            and content.content_id == content_id
            and _raw_digest(content.body) == content_id
        )
        if not valid_identity:
            raise RetrievalAccessError("retrieval unavailable for engagement")
        _require_identifier(content.run_id, "stored run_id")
        if (
            not content.media_type
            or content.media_type != content.media_type.strip()
            or len(content.media_type) > 256
            or any(not 32 <= ord(character) <= 126 for character in content.media_type)
        ):
            raise RetrievalError("stored media type is invalid")
        if type(content.watermark) is not int or content.watermark <= 0:
            raise RetrievalError("stored watermark is invalid")
        return content

    def _view(
        self,
        content: RetrievedContent,
        *,
        unit: RetrievalUnit,
        start: int,
        count: int,
    ) -> RetrievedView:
        if unit is RetrievalUnit.BYTES:
            total_units = len(content.body)
            if start > total_units:
                raise RetrievalRangeError("byte range starts beyond the full output")
            end = min(start + count, total_units)
            page = content.body[start:end]
            value = base64.b64encode(page).decode("ascii")
            encoding: Literal["base64", "utf-8"] = "base64"
        else:
            lines = _utf8_lines(content.body)
            total_units = len(lines)
            if start > total_units:
                raise RetrievalRangeError("line range starts beyond the full output")
            end = min(start + count, total_units)
            page = b"".join(lines[start:end])
            if len(page) > self._max_page_bytes:
                raise RetrievalRangeError(
                    "line page exceeds the byte bound; request a bounded byte range"
                )
            value = page.decode("utf-8")
            encoding = "utf-8"
        next_cursor = None
        if end < total_units:
            next_cursor = self._encode_cursor(
                engagement_id=content.engagement_id,
                run_id=content.run_id,
                content_id=content.content_id,
                unit=unit,
                start=end,
                count=count,
                watermark=content.watermark,
            )
        next_cursor_id = _raw_digest(next_cursor.encode("ascii")) if next_cursor else None
        range_id = _range_id(
            engagement_digest=_engagement_digest(content.engagement_id),
            run_id=content.run_id,
            content_id=content.content_id,
            unit=unit,
            start=start,
            end=end,
            total_units=total_units,
            page_digest=_raw_digest(page),
            watermark=content.watermark,
        )
        values: dict[str, object] = {
            "engagement_digest": _engagement_digest(content.engagement_id),
            "run_id": content.run_id,
            "content_id": content.content_id,
            "range_id": range_id,
            "media_type": content.media_type,
            "full_byte_length": len(content.body),
            "unit": unit,
            "start": start,
            "end": end,
            "total_units": total_units,
            "encoding": encoding,
            "value": value,
            "page_digest": _raw_digest(page),
            "watermark": content.watermark,
            "next_cursor": next_cursor,
            "next_cursor_id": next_cursor_id,
        }
        binding_tag = _view_binding_tag_from_values(self._cursor_key, values)
        return RetrievedView(
            engagement_digest=_engagement_digest(content.engagement_id),
            run_id=content.run_id,
            content_id=content.content_id,
            range_id=range_id,
            media_type=content.media_type,
            full_byte_length=len(content.body),
            unit=unit,
            start=start,
            end=end,
            total_units=total_units,
            encoding=encoding,
            value=value,
            page_digest=_raw_digest(page),
            watermark=content.watermark,
            next_cursor=next_cursor,
            next_cursor_id=next_cursor_id,
            binding_tag=binding_tag,
        )

    def _encode_cursor(
        self,
        *,
        engagement_id: str,
        run_id: str,
        content_id: str,
        unit: RetrievalUnit,
        start: int,
        count: int,
        watermark: int,
    ) -> str:
        payload = canonical_json_bytes(
            {
                "version": _CURSOR_VERSION,
                "engagement_digest": _engagement_digest(engagement_id),
                "run_id": run_id,
                "content_id": content_id,
                "unit": unit.value,
                "start": start,
                "count": count,
                "watermark": watermark,
            }
        )
        signature = hmac.digest(
            self._cursor_key,
            _CURSOR_AUTH_DOMAIN + payload,
            "sha256",
        )
        return f"{_b64url(payload)}.{_b64url(signature)}"

    def _decode_cursor(self, cursor: str) -> dict[str, object]:
        if not isinstance(cursor, str) or len(cursor) > 4096 or cursor.count(".") != 1:
            raise RetrievalCursorError("cursor is malformed")
        encoded_payload, encoded_signature = cursor.split(".", 1)
        try:
            payload = _b64url_decode(encoded_payload)
            signature = _b64url_decode(encoded_signature)
        except (ValueError, binascii.Error) as exc:
            raise RetrievalCursorError("cursor is malformed") from exc
        expected = hmac.digest(
            self._cursor_key,
            _CURSOR_AUTH_DOMAIN + payload,
            "sha256",
        )
        if len(signature) != 32 or not hmac.compare_digest(signature, expected):
            raise RetrievalCursorError("cursor authentication failed")
        try:
            document = json.loads(payload, object_pairs_hook=_unique_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RetrievalCursorError("cursor payload is invalid") from exc
        if not isinstance(document, dict) or canonical_json_bytes(document) != payload:
            raise RetrievalCursorError("cursor payload is not canonical")
        expected_keys = {
            "version",
            "engagement_digest",
            "run_id",
            "content_id",
            "unit",
            "start",
            "count",
            "watermark",
        }
        if set(document) != expected_keys or document.get("version") != _CURSOR_VERSION:
            raise RetrievalCursorError("cursor schema is unsupported")
        try:
            _require_digest(document["engagement_digest"], "cursor engagement digest")
            _require_identifier(document["run_id"], "cursor run_id")
            _require_digest(document["content_id"], "cursor content ID")
            RetrievalUnit(document["unit"])
            _validate_range(document["start"], document["count"])
            if type(document["watermark"]) is not int or document["watermark"] <= 0:
                raise ValueError("invalid watermark")
        except (TypeError, ValueError) as exc:
            raise RetrievalCursorError("cursor fields are invalid") from exc
        return document


def content_id_for(body: bytes) -> str:
    """Return the stable identifier for a complete immutable output."""

    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    return _raw_digest(body)


def checkpoint_binding_tag_for(
    checkpoint: ContextCheckpoint,
    *,
    engagement_id: str,
    binding_key: bytes,
) -> str:
    """Bind every checkpoint field to one engagement outside model-controlled state."""

    _require_identifier(engagement_id, "checkpoint engagement_id")
    if not isinstance(binding_key, bytes) or len(binding_key) < 32:
        raise ValueError("checkpoint binding key must contain at least 32 bytes")
    checkpoint = ContextCheckpoint.model_validate(checkpoint.model_dump(mode="python"))
    document = canonical_json_bytes(
        {
            "engagement_digest": _engagement_digest(engagement_id),
            "checkpoint": checkpoint,
        }
    )
    digest = hmac.digest(binding_key, _CHECKPOINT_BINDING_DOMAIN + document, "sha256")
    return f"hmac-sha256:{digest.hex()}"


def _context_document(
    state: ContextState,
    provider: ProviderContextMetadata,
    allocation: ContextAllocation,
    *,
    scope_anchor: ScopeTrustAnchor,
    effective_prompt_overhead_tokens: int,
    live: bool,
) -> dict[str, object]:
    checkpoint = state.checkpoint
    signed_epoch = state.signed_scope_epoch
    return {
        "schema_version": "0.1.0",
        "context_kind": "faultloom.model_context",
        "engagement_id": state.engagement_id,
        "run_id": checkpoint.run_id,
        "checkpoint_binding_tag": state.checkpoint_binding_tag,
        "goal": {"text": state.goal, "digest": checkpoint.goal_digest},
        "plan": {"digest": checkpoint.plan_digest},
        "scope": {
            "grant_digest": checkpoint.authority_digest,
            "grant_id": scope_anchor.grant_id,
            "epoch": signed_epoch.payload.epoch,
            "signed_epoch_digest": _raw_digest(canonical_json_bytes(signed_epoch)),
            "trusted_key_id": scope_anchor.public_key.key_id,
            "signed_epoch": signed_epoch.model_dump(mode="python"),
        },
        "research": {
            "active_hypotheses": [
                _hypothesis_document(record)
                for record in sorted(
                    state.active_hypotheses,
                    key=lambda item: item.hypothesis_id,
                )
            ],
            "important_negative_results": [
                _negative_document(record)
                for record in sorted(
                    state.important_negative_results,
                    key=lambda item: item.negative_result_id,
                )
            ],
        },
        "graphs": {
            "identity": _graph_document(state.graph_slices.identity),
            "workflow": _graph_document(state.graph_slices.workflow),
            "surface": _graph_document(state.graph_slices.surface),
            "chain": _graph_document(state.graph_slices.chain),
        },
        "actions": {
            "pending_ids": sorted(checkpoint.pending_action_ids),
            "unknown_outcome_ids": sorted(checkpoint.unknown_outcome_action_ids),
        },
        "secret_refs": [
            secret.model_dump(mode="python")
            for secret in sorted(checkpoint.secret_refs, key=lambda item: item.uri)
        ],
        "evidence": {
            "recent_refs": [
                _evidence_document(reference)
                for reference in sorted(
                    checkpoint.recent_evidence_refs,
                    key=lambda item: item.evidence_id,
                )
            ],
            "retrieval_cursors": [
                cursor.model_dump(mode="python")
                for cursor in sorted(
                    checkpoint.retrieval_cursors,
                    key=lambda item: (item.index_id, item.cursor, item.watermark),
                )
            ],
            "bounded_views": [
                view.model_dump(mode="python")
                for view in sorted(
                    state.retrieved_views,
                    key=lambda item: (
                        item.content_id,
                        item.unit.value,
                        item.start,
                        item.end,
                    ),
                )
            ],
        },
        "remaining_budget": checkpoint.remaining_budget.model_dump(mode="python"),
        "stable_watermark": checkpoint.stable_watermark,
        "provider": provider.model_dump(mode="python"),
        "context_allocation": {
            "context_window": allocation.context_window,
            "input_limit": allocation.input_limit,
            "output_reserve": allocation.output_reserve,
            "next_observation_reserve": allocation.observation_reserve,
            "accounting": "utf8_bytes_conservative",
            "effective_prompt_overhead_tokens": effective_prompt_overhead_tokens,
        },
        "live": live,
    }


def _graph_document(graph_slice: ContextGraphSlice | None) -> dict[str, object] | None:
    if graph_slice is None:
        return None
    return {
        "graph_id": graph_slice.graph_id,
        "watermark": graph_slice.watermark,
        "nodes": [
            {
                "node_id": node.node_id,
                "node_kind": node.node_kind,
                "summary": node.summary,
                "evidence_ids": sorted(node.evidence_ids),
            }
            for node in sorted(graph_slice.nodes, key=lambda item: item.node_id)
        ],
        "edges": [
            {
                "edge_id": edge.edge_id,
                "edge_kind": edge.edge_kind,
                "source_id": edge.source_id,
                "target_id": edge.target_id,
                "summary": edge.summary,
                "evidence_ids": sorted(edge.evidence_ids),
            }
            for edge in sorted(graph_slice.edges, key=lambda item: item.edge_id)
        ],
    }


def _hypothesis_document(record: HypothesisRecord) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "hypothesis_id": record.hypothesis_id,
        "run_id": record.run_id,
        "statement": record.statement,
        "provenance": sorted(item.value for item in record.provenance),
        "status": record.status.value,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "supporting_evidence": [
            _evidence_document(reference)
            for reference in sorted(
                record.supporting_evidence,
                key=lambda item: item.evidence_id,
            )
        ],
        "contradicting_evidence": [
            _evidence_document(reference)
            for reference in sorted(
                record.contradicting_evidence,
                key=lambda item: item.evidence_id,
            )
        ],
        "prerequisite_ids": sorted(record.prerequisite_ids),
    }


def _negative_document(record: NegativeResult) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "negative_result_id": record.negative_result_id,
        "run_id": record.run_id,
        "hypothesis_id": record.hypothesis_id,
        "experiment_digest": record.experiment_digest,
        "conclusion": record.conclusion,
        "evidence_refs": [
            _evidence_document(reference)
            for reference in sorted(record.evidence_refs, key=lambda item: item.evidence_id)
        ],
        "recorded_at": record.recorded_at,
    }


def _evidence_document(reference: EvidenceRef) -> dict[str, object]:
    document = reference.model_dump(mode="python")
    document["observation_ids"] = sorted(reference.observation_ids)
    return document


def _validate_evidence_runs(state: ContextState, run_id: str) -> None:
    references: list[EvidenceRef] = list(state.checkpoint.recent_evidence_refs)
    for hypothesis in state.active_hypotheses:
        references.extend(hypothesis.supporting_evidence)
        references.extend(hypothesis.contradicting_evidence)
    for negative in state.important_negative_results:
        references.extend(negative.evidence_refs)
    seen: dict[str, bytes] = {}
    for reference in references:
        if reference.run_id != run_id:
            raise ValueError("evidence references must belong to the checkpoint run")
        digest = canonical_json_bytes(_evidence_document(reference))
        previous = seen.setdefault(reference.evidence_id, digest)
        if not hmac.compare_digest(previous, digest):
            raise ValueError("one evidence ID cannot identify conflicting records")


def _require_unique(values: tuple[object, ...], label: str) -> None:
    try:
        unique = set(values)
    except TypeError as exc:
        raise ValueError(f"{label} must be hashable") from exc
    if len(unique) != len(values):
        raise ValueError(f"{label} must be unique")


def _require_unpadded_text(value: str, label: str) -> str:
    if not value.strip() or value != value.strip():
        raise ValueError(f"{label} must be non-blank and unpadded")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be valid UTF-8 text") from exc
    return value


def _ceil_percent(value: int, percent: int) -> int:
    return (value * percent + 99) // 100


def _raw_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _engagement_digest(engagement_id: str) -> str:
    return _raw_digest(engagement_id.encode("utf-8"))


def _range_id(
    *,
    engagement_digest: str,
    run_id: str,
    content_id: str,
    unit: RetrievalUnit,
    start: int,
    end: int,
    total_units: int,
    page_digest: str,
    watermark: int,
) -> str:
    return _raw_digest(
        canonical_json_bytes(
            {
                "engagement_digest": engagement_digest,
                "run_id": run_id,
                "content_id": content_id,
                "unit": unit.value,
                "start": start,
                "end": end,
                "total_units": total_units,
                "page_digest": page_digest,
                "watermark": watermark,
            }
        )
    )


def _view_binding_document(values: Mapping[str, object]) -> dict[str, object]:
    return {
        key: values[key]
        for key in (
            "engagement_digest",
            "run_id",
            "content_id",
            "range_id",
            "media_type",
            "full_byte_length",
            "unit",
            "start",
            "end",
            "total_units",
            "encoding",
            "page_digest",
            "watermark",
            "next_cursor",
            "next_cursor_id",
        )
    }


def _view_binding_tag_from_values(key: bytes, values: Mapping[str, object]) -> str:
    document = canonical_json_bytes(_view_binding_document(values))
    digest = hmac.digest(key, _VIEW_BINDING_DOMAIN + document, "sha256")
    return f"hmac-sha256:{digest.hex()}"


def _view_binding_tag(key: bytes, view: RetrievedView) -> str:
    return _view_binding_tag_from_values(key, view.model_dump(mode="python"))


def _require_aware_datetime(value: object) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ContextScopeError("scope verification time must include a timezone")


def _require_identifier(value: object, label: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise RetrievalError(f"{label} is invalid")


def _require_digest(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise RetrievalError(f"{label} is invalid")


def _validate_range(start: object, count: object) -> None:
    if type(start) is not int or start < 0 or start > MAX_INT64:
        raise RetrievalRangeError("range start must be a non-negative integer")
    if type(count) is not int or count <= 0 or count > MAX_INT64:
        raise RetrievalRangeError("range count must be a positive integer")
    if start + count > MAX_INT64:
        raise RetrievalRangeError("range end exceeds the supported integer bound")


def _utf8_lines(body: bytes) -> tuple[bytes, ...]:
    try:
        body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RetrievalEncodingError("line retrieval requires UTF-8 content") from exc
    if not body:
        return ()
    lines: list[bytes] = []
    start = 0
    while True:
        newline = body.find(b"\n", start)
        if newline < 0:
            if start < len(body):
                lines.append(body[start:])
            break
        lines.append(body[start : newline + 1])
        start = newline + 1
        if start == len(body):
            break
    return tuple(lines)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not value or _CURSOR_COMPONENT_RE.fullmatch(value) is None:
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if _b64url(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
