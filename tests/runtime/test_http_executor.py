from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

import faultloom_protocol.models as m
import pytest

from faultloom.execution import (
    DispatchReplayError,
    DispatchUncertainError,
    ExecutionContractError,
    GatewayDeniedResult,
    GatewayDispatchResult,
    LocalDispatchState,
    SemanticHttpExecutor,
)
from faultloom_protocol import SCHEMA_VERSION

from .execution_helpers import D1, NOW, RecordingGateway, command, completed_result, model


def test_only_injected_gateway_receives_an_approved_semantic_request() -> None:
    approved = command()
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    result = executor.execute(approved)

    assert isinstance(result, GatewayDispatchResult)
    assert gateway.calls == [approved]
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.COMPLETED


def test_expired_or_future_lease_is_rejected_before_gateway_call() -> None:
    expired = command()
    future = command(
        action_id="action.future",
        lease_id="lease.future",
        lease_issued_at=NOW + timedelta(seconds=1),
        lease_expires_at=NOW + timedelta(minutes=1),
    )
    gateway = RecordingGateway(completed_result)
    expired_executor = SemanticHttpExecutor(gateway, now=lambda: NOW + timedelta(minutes=2))
    future_executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    with pytest.raises(ExecutionContractError, match="not currently valid"):
        expired_executor.execute(expired)
    with pytest.raises(ExecutionContractError, match="not currently valid"):
        future_executor.execute(future)
    assert gateway.calls == []


def test_zero_byte_lease_is_rejected_before_gateway_call() -> None:
    approved = command()
    lease_values = approved.lease.model_dump(mode="python")
    reservation_values = approved.lease.reservation.model_dump(mode="python")
    reservation_values["request_bytes"] = 0
    lease_values["reservation"] = m.BudgetReservation.model_validate(reservation_values)
    command_values = approved.model_dump(mode="python")
    command_values["lease"] = m.ActionLease.model_validate(lease_values)
    zero_byte = type(approved).model_validate(command_values)
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    with pytest.raises(ExecutionContractError, match="non-zero byte reservations"):
        executor.execute(zero_byte)
    assert gateway.calls == []


def test_gateway_denial_is_bound_and_never_automatically_retried() -> None:
    approved = command()
    denial = GatewayDeniedResult(
        schema_version=SCHEMA_VERSION,
        action_id=approved.intent.action_id,
        request_digest=D1,
        reason_code="scope.revoked",
    )
    gateway = RecordingGateway(lambda _: denial)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    assert executor.execute(approved) == denial
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.DENIED
    with pytest.raises(DispatchReplayError):
        executor.execute(approved)
    assert len(gateway.calls) == 1


def test_gateway_exception_becomes_unknown_and_blocks_replay() -> None:
    approved = command()

    def fail(_: object) -> object:
        raise OSError("local Gateway channel closed")

    gateway = RecordingGateway(fail)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    with pytest.raises(DispatchUncertainError, match="reconciliation"):
        executor.execute(approved)
    assert executor.unknown_action_ids() == (approved.intent.action_id,)
    with pytest.raises(DispatchReplayError):
        executor.execute(approved)
    assert len(gateway.calls) == 1


def test_forged_receipt_is_unknown_and_cannot_be_replayed() -> None:
    approved = command()
    valid = completed_result(approved)
    receipt_values = valid.receipt.model_dump(mode="python")
    receipt_values["lease_id"] = "lease.forged"
    forged_receipt = m.DispatchReceipt.model_validate(receipt_values)
    forged = GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=forged_receipt,
        observation=valid.observation,
    )
    gateway = RecordingGateway(lambda _: forged)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    with pytest.raises(ExecutionContractError, match="binding mismatch"):
        executor.execute(approved)
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.UNKNOWN
    with pytest.raises(DispatchReplayError):
        executor.execute(approved)


def test_receipt_dispatched_outside_lease_window_is_rejected() -> None:
    approved = command()
    valid = completed_result(approved)
    receipt_values = valid.receipt.model_dump(mode="python")
    receipt_values["dispatched_at"] = approved.lease.expires_at
    receipt_values["completed_at"] = approved.lease.expires_at + timedelta(seconds=1)
    forged = GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=m.DispatchReceipt.model_validate(receipt_values),
        observation=valid.observation,
    )
    gateway = RecordingGateway(lambda _: forged)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    with pytest.raises(ExecutionContractError, match="outside the lease window"):
        executor.execute(approved)
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.UNKNOWN


def test_unknown_outcome_requires_reconciliation_and_never_retries() -> None:
    approved = command()
    receipt = model(
        m.DispatchReceipt,
        receipt_id="receipt.unknown",
        lease_id=approved.lease.lease_id,
        intent_digest=approved.intent_digest,
        decision_digest=approved.decision_digest,
        scope_epoch=approved.lease.scope_epoch,
        request_digest=D1,
        outcome=m.DispatchOutcome.UNKNOWN_OUTCOME,
        dispatched_at=NOW,
        bytes_sent=64,
        bytes_received=0,
        reconciliation_required=True,
    )
    result = GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=receipt,
    )
    gateway = RecordingGateway(lambda _: result)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    assert executor.execute(approved) == result
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.UNKNOWN
    with pytest.raises(DispatchReplayError):
        executor.execute(approved)
    assert len(gateway.calls) == 1


def test_receipt_cannot_exceed_reserved_request_or_response_bytes() -> None:
    approved = command()
    oversized = completed_result(approved, bytes_received=8193)
    gateway = RecordingGateway(lambda _: oversized)
    executor = SemanticHttpExecutor(gateway, now=lambda: NOW)

    with pytest.raises(ExecutionContractError, match="reserved response bytes"):
        executor.execute(approved)
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.UNKNOWN


def test_execution_modules_have_no_target_network_or_browser_client_imports() -> None:
    root = Path(__file__).parents[2] / "packages" / "runtime" / "src" / "faultloom" / "execution"
    forbidden_roots = {
        "aiohttp",
        "http.client",
        "httpx",
        "playwright",
        "requests",
        "socket",
        "urllib.request",
        "websockets",
    }
    imported: set[str] = set()
    for source_path in root.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
    assert forbidden_roots.isdisjoint(imported)
