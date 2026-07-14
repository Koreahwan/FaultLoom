from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import ModelIdentity, RunManifest, sha256_digest
from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest, ShortStr
from faultloom_protocol.models import NonNegativeInt, PositiveInt

from ..context import ContextState
from ..state import AnchorCheckpoint


ZERO_HASH = "0" * 64


class ResumeError(ValueError):
    __slots__ = ("detail",)

    detail: str

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class CheckpointIntegrityError(ResumeError):
    pass


class CheckpointConflictError(ResumeError):
    pass


class CheckpointNotFoundError(ResumeError):
    pass


class ResumeTrustError(ResumeError):
    pass


class ReconciliationRequiredError(ResumeError):
    pass


class CheckpointReason(StrEnum):
    BEFORE_STATE_CHANGE = "before_state_change"
    BEFORE_LONG_BATCH = "before_long_batch"
    BEFORE_PROVIDER_FAILOVER = "before_provider_failover"
    BEFORE_COMPACTION = "before_compaction"
    STABLE_WATERMARK = "stable_watermark"
    TURN_END = "turn_end"


class _ResumeModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        str_strip_whitespace=False,
        validate_default=True,
    )


class FailoverIntent(_ResumeModel):
    from_model_digest: Sha256Digest
    to_model: ModelIdentity
    requested_at: AwareDatetime
    reason: ShortStr

    @model_validator(mode="after")
    def _changes_exact_model(self) -> Self:
        if hmac.compare_digest(
            self.from_model_digest,
            sha256_digest(self.to_model),
        ):
            raise ValueError("provider failover must select a different exact model")
        return self


class CheckpointEnvelope(_ResumeModel):
    format_version: Literal[1] = 1
    kind: Literal["faultloom.resume_checkpoint"] = "faultloom.resume_checkpoint"
    reason: CheckpointReason
    run_manifest: RunManifest
    context_state: ContextState
    model_digest: Sha256Digest
    failover_intent: FailoverIntent | None = None

    @model_validator(mode="after")
    def _is_consistent(self) -> Self:
        manifest = self.run_manifest
        context = self.context_state
        checkpoint = context.checkpoint
        if not hmac.compare_digest(self.model_digest, sha256_digest(manifest.model)):
            raise ValueError("model digest does not match the run manifest")
        if manifest.engagement_id != context.engagement_id:
            raise ValueError("run manifest and checkpoint engagement differ")
        if manifest.run_id != checkpoint.run_id:
            raise ValueError("run manifest and checkpoint run differ")
        if manifest.plan_digest != checkpoint.plan_digest:
            raise ValueError("run manifest and checkpoint plan differ")
        if manifest.authority_digest != checkpoint.authority_digest:
            raise ValueError("run manifest and checkpoint scope authority differ")
        if manifest.scope_epoch != checkpoint.scope_epoch:
            raise ValueError("run manifest and checkpoint scope epoch differ")
        if checkpoint.created_at < manifest.started_at:
            raise ValueError("checkpoint predates its run manifest")
        requires_failover = self.reason is CheckpointReason.BEFORE_PROVIDER_FAILOVER
        if requires_failover != (self.failover_intent is not None):
            raise ValueError("provider failover boundary requires exactly one failover intent")
        if self.failover_intent is not None:
            if not hmac.compare_digest(
                self.failover_intent.from_model_digest,
                self.model_digest,
            ):
                raise ValueError("failover intent source differs from the active model")
            if self.failover_intent.requested_at < checkpoint.created_at:
                raise ValueError("failover intent predates its checkpoint")
        return self


class ResumeTrustPolicy(_ResumeModel):
    policy_version: Literal[1] = 1
    engagement_id: Identifier
    run_id: Identifier
    checkpoint_digest: Sha256Digest
    goal_digest: Sha256Digest
    plan_digest: Sha256Digest
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    run_manifest_digest: Sha256Digest
    model_digest: Sha256Digest
    prompt_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    minimum_checkpoint_sequence: PositiveInt
    minimum_stable_watermark: PositiveInt
    minimum_anchor_seq: NonNegativeInt
    minimum_anchor_head: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _has_valid_anchor_floor(self) -> Self:
        empty_floor = self.minimum_anchor_seq == 0
        if empty_floor != (self.minimum_anchor_head == ZERO_HASH):
            raise ValueError("anchor floor sequence and hash disagree")
        return self

    def anchor_floor(self) -> AnchorCheckpoint:
        return AnchorCheckpoint(
            engagement_id=self.engagement_id,
            seq=self.minimum_anchor_seq,
            head=self.minimum_anchor_head,
        )


@dataclass(frozen=True, slots=True)
class ResumePacket:
    checkpoint_digest: str
    event_sequence: int
    event_hash: str
    reason: CheckpointReason
    run_manifest: RunManifest
    context_state: ContextState
    blocked_action_ids: tuple[str, ...]
    automatic_retry_action_ids: tuple[str, ...]
    dispatch_ready: bool
    requires_reconciliation: bool


@dataclass(frozen=True, slots=True)
class CheckpointRecord:
    event_sequence: int
    event_hash: str
    checkpoint_digest: str
    canonical_bytes: bytes
    envelope: CheckpointEnvelope
