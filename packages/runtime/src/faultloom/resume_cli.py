from __future__ import annotations

import argparse
import json
import os
import re
import stat
from collections.abc import Callable
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Literal, Protocol, assert_never

from pydantic import BaseModel, ConfigDict

from .resume import (
    ActionReconciliation,
    CheckpointController,
    FailoverIntent,
    ReconciliationRequiredError,
    ResumeError,
    ResumePacket,
    ResumeTrustPolicy,
)
from .state import EngagementKey, StateStore, StorageError


STATE_ROOT_ENV = "FAULTLOOM_STATE_ROOT"
ANCHOR_ROOT_ENV = "FAULTLOOM_ANCHOR_ROOT"
TRUST_POLICY_ENV = "FAULTLOOM_RESUME_TRUST_POLICY"
ENGAGEMENT_KEY_FILE_ENV = "FAULTLOOM_ENGAGEMENT_KEY_FILE"
_ENGAGEMENT_KEY_PATTERN = re.compile(rb"[0-9a-f]{64}\n?")

JsonDepthValidator = Callable[[str], None]
DuplicateKeyRejector = Callable[[list[tuple[str, object]]], dict[str, object]]


class ProtocolPairCapture(Protocol):
    def __call__(
        self,
        authority_path: Path,
        key_path: Path,
        *,
        private_second: bool = False,
    ) -> tuple[bytes, bytes]: ...


class ResumeCliError(RuntimeError):
    pass


class ResumeOperation(StrEnum):
    RESUME = "resume"
    INSPECT = "inspect"


class _ResumeReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation: ResumeOperation
    network_access: Literal["none"] = "none"
    dispatch_performed: Literal[False] = False
    run_id: str
    engagement_id: str
    checkpoint_id: str
    checkpoint_sequence: int
    checkpoint_reason: str
    checkpoint_digest: str
    event_sequence: int
    event_hash: str
    goal_digest: str
    plan_digest: str
    authority_digest: str
    scope_epoch: int
    stable_watermark: int
    active_hypothesis_ids: tuple[str, ...]
    important_negative_result_ids: tuple[str, ...]
    identity_graph_id: str | None
    workflow_graph_id: str | None
    surface_graph_id: str | None
    chain_graph_id: str | None
    pending_action_ids: tuple[str, ...]
    unknown_outcome_action_ids: tuple[str, ...]
    automatic_retry_action_ids: tuple[str, ...]
    failover_intent: FailoverIntent | None
    action_reconciliations: tuple[ActionReconciliation, ...]
    requires_reconciliation: bool
    failover_required: bool
    dispatch_ready: bool


def configure_resume_parser(
    parser: argparse.ArgumentParser,
    *,
    operation: ResumeOperation,
    capture_protocol_pair: ProtocolPairCapture,
    validate_json_depth: JsonDepthValidator,
    reject_duplicate_keys: DuplicateKeyRejector,
) -> None:
    parser.add_argument("run_id")
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--anchor-root", type=Path)
    parser.add_argument("--trust-policy", type=Path)
    parser.add_argument("--engagement-key-file", type=Path)
    parser.set_defaults(
        handler=partial(
            _handle_resume,
            operation=operation,
            capture_protocol_pair=capture_protocol_pair,
            validate_json_depth=validate_json_depth,
            reject_duplicate_keys=reject_duplicate_keys,
        )
    )


def _required_path(value: Path | None, *, environment: str, label: str) -> Path:
    configured = value if value is not None else os.environ.get(environment)
    if configured is None:
        raise ResumeCliError(
            f"{label} is required via its command option or {environment}"
        )
    return Path(configured)


def _require_existing_directory(path: Path, *, label: str) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ResumeCliError(
            f"{label} is not an accessible existing directory"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ResumeCliError(
            f"{label} is not an accessible existing directory"
        )


def _parse_trust_policy(
    path: Path,
    content: bytes,
    *,
    validate_json_depth: JsonDepthValidator,
    reject_duplicate_keys: DuplicateKeyRejector,
) -> ResumeTrustPolicy:
    try:
        text = content.decode("utf-8")
        validate_json_depth(text)
        json.loads(text, object_pairs_hook=reject_duplicate_keys)
        return ResumeTrustPolicy.model_validate_json(text)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ResumeCliError(f"invalid resume trust policy {path}") from exc


def _parse_engagement_key(content: bytes) -> EngagementKey:
    if _ENGAGEMENT_KEY_PATTERN.fullmatch(content) is None:
        raise ResumeCliError(
            "engagement key file must contain one lowercase 32-byte hex key"
        )
    material = bytes.fromhex(content.removesuffix(b"\n").decode("ascii"))
    return EngagementKey(material)


def _load_inputs(
    arguments: argparse.Namespace,
    *,
    capture_protocol_pair: ProtocolPairCapture,
    validate_json_depth: JsonDepthValidator,
    reject_duplicate_keys: DuplicateKeyRejector,
) -> tuple[Path, Path, ResumeTrustPolicy, EngagementKey]:
    state_root = _required_path(
        arguments.state_root,
        environment=STATE_ROOT_ENV,
        label="state root",
    )
    anchor_root = _required_path(
        arguments.anchor_root,
        environment=ANCHOR_ROOT_ENV,
        label="anchor root",
    )
    trust_path = _required_path(
        arguments.trust_policy,
        environment=TRUST_POLICY_ENV,
        label="resume trust policy",
    )
    key_path = _required_path(
        arguments.engagement_key_file,
        environment=ENGAGEMENT_KEY_FILE_ENV,
        label="engagement key file",
    )
    _require_existing_directory(state_root, label="state root")
    _require_existing_directory(anchor_root, label="anchor root")
    trust_content, key_content = capture_protocol_pair(
        trust_path,
        key_path,
        private_second=True,
    )
    return (
        state_root,
        anchor_root,
        _parse_trust_policy(
            trust_path,
            trust_content,
            validate_json_depth=validate_json_depth,
            reject_duplicate_keys=reject_duplicate_keys,
        ),
        _parse_engagement_key(key_content),
    )


def _report(operation: ResumeOperation, packet: ResumePacket) -> _ResumeReport:
    checkpoint = packet.context_state.checkpoint
    return _ResumeReport(
        operation=operation,
        run_id=checkpoint.run_id,
        engagement_id=packet.context_state.engagement_id,
        checkpoint_id=checkpoint.checkpoint_id,
        checkpoint_sequence=checkpoint.sequence,
        checkpoint_reason=packet.reason.value,
        checkpoint_digest=packet.checkpoint_digest,
        event_sequence=packet.event_sequence,
        event_hash=packet.event_hash,
        goal_digest=checkpoint.goal_digest,
        plan_digest=checkpoint.plan_digest,
        authority_digest=checkpoint.authority_digest,
        scope_epoch=checkpoint.scope_epoch,
        stable_watermark=checkpoint.stable_watermark,
        active_hypothesis_ids=checkpoint.active_hypothesis_ids,
        important_negative_result_ids=checkpoint.important_negative_result_ids,
        identity_graph_id=checkpoint.identity_graph_id,
        workflow_graph_id=checkpoint.workflow_graph_id,
        surface_graph_id=checkpoint.surface_graph_id,
        chain_graph_id=checkpoint.chain_graph_id,
        pending_action_ids=checkpoint.pending_action_ids,
        unknown_outcome_action_ids=checkpoint.unknown_outcome_action_ids,
        automatic_retry_action_ids=packet.automatic_retry_action_ids,
        failover_intent=packet.failover_intent,
        action_reconciliations=packet.action_reconciliations,
        requires_reconciliation=packet.requires_reconciliation,
        failover_required=packet.failover_required,
        dispatch_ready=packet.dispatch_ready,
    )


def _handle_resume(
    arguments: argparse.Namespace,
    *,
    operation: ResumeOperation,
    capture_protocol_pair: ProtocolPairCapture,
    validate_json_depth: JsonDepthValidator,
    reject_duplicate_keys: DuplicateKeyRejector,
) -> int:
    state_root, anchor_root, policy, key = _load_inputs(
        arguments,
        capture_protocol_pair=capture_protocol_pair,
        validate_json_depth=validate_json_depth,
        reject_duplicate_keys=reject_duplicate_keys,
    )
    if policy.run_id != arguments.run_id:
        raise ResumeCliError(
            "requested run differs from the trusted resume policy"
        )
    try:
        with StateStore(
            state_root,
            policy.engagement_id,
            key,
            anchor_root=anchor_root,
            minimum_anchor=policy.anchor_floor(),
        ) as store:
            controller = CheckpointController(store)
            if operation is ResumeOperation.INSPECT:
                packet = controller.inspect(policy)
            elif operation is ResumeOperation.RESUME:
                packet = controller.resume(policy)
            else:
                assert_never(operation)
    except ReconciliationRequiredError as exc:
        raise ResumeCliError(
            "resume requires reconciliation before any action can be dispatched"
        ) from exc
    except (ResumeError, StorageError) as exc:
        raise ResumeCliError(
            "resume refused because durable state differs from trusted expectations"
        ) from exc
    print(_report(operation, packet).model_dump_json())
    return 0
