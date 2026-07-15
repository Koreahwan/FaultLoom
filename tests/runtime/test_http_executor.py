from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path
from typing import Never

import faultloom_protocol.models as m
import pytest

from faultloom.execution import (
    AuthenticatedGatewayClient,
    DispatchReplayError,
    DispatchUncertainError,
    ExecutionContractError,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    LocalDispatchState,
    ReconciliationStateError,
    SemanticHttpExecutor,
    canonical_dispatch_receipt_id,
    gateway_dispatch_frame,
    gateway_frame_digest,
)
from faultloom_protocol import SCHEMA_VERSION

from .execution_helpers import (
    CHANNEL_KEY,
    NOW,
    RecordingGateway,
    command,
    completed_result,
)


class _UntrustedGatewayClient(AuthenticatedGatewayClient):
    pass


def test_production_executor_rejects_an_in_process_gateway_port() -> None:
    gateway = RecordingGateway(completed_result)
    untrusted = _UntrustedGatewayClient.__new__(_UntrustedGatewayClient)

    with pytest.raises(ExecutionContractError, match="authenticated supervised"):
        SemanticHttpExecutor(untrusted, now=lambda: NOW)

    assert gateway.calls == []


def test_only_injected_gateway_receives_an_approved_semantic_request() -> None:
    approved = command()
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    result = executor.execute(approved)

    assert isinstance(result, GatewayDispatchResult)
    assert [frame.command for frame in gateway.calls] == [approved]
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
    expired_executor = SemanticHttpExecutor._for_test(
        gateway,
        channel_key=CHANNEL_KEY,
        now=lambda: NOW + timedelta(minutes=2),
    )
    future_executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with pytest.raises(ExecutionContractError, match="not currently valid"):
        expired_executor.execute(expired)
    with pytest.raises(ExecutionContractError, match="not currently valid"):
        future_executor.execute(future)
    assert gateway.calls == []


def test_zero_byte_lease_cannot_be_constructed() -> None:
    approved = command()
    reservation_values = approved.lease.reservation.model_dump(mode="python")
    reservation_values["request_bytes"] = 0

    with pytest.raises(ValueError, match="request_bytes"):
        m.BudgetReservation.model_validate(reservation_values)


def test_gateway_denial_is_bound_and_never_automatically_retried() -> None:
    approved = command()
    frame = gateway_dispatch_frame(approved)
    denial = GatewayDeniedResult(
        schema_version=SCHEMA_VERSION,
        action_id=approved.intent.action_id,
        request_digest=gateway_frame_digest(frame),
        reason_code="scope.revoked",
    )
    gateway = RecordingGateway(lambda _: denial)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    assert executor.execute(approved) == denial
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.DENIED
    with pytest.raises(DispatchReplayError):
        executor.execute(approved)
    assert len(gateway.calls) == 1


def test_gateway_exception_becomes_unknown_and_blocks_replay() -> None:
    approved = command()

    def fail(_: GatewayDispatchCommand) -> Never:
        raise RuntimeError("local Gateway channel failed")

    gateway = RecordingGateway(fail)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

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
    provisional_receipt = m.DispatchReceipt.model_validate(receipt_values)
    receipt_values["receipt_id"] = canonical_dispatch_receipt_id(provisional_receipt)
    forged_receipt = m.DispatchReceipt.model_validate(receipt_values)
    forged = GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=forged_receipt,
        observation=valid.observation,
    )
    gateway = RecordingGateway(lambda _: forged)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

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
    provisional_receipt = m.DispatchReceipt.model_validate(receipt_values)
    receipt_values["receipt_id"] = canonical_dispatch_receipt_id(provisional_receipt)
    forged = GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=m.DispatchReceipt.model_validate(receipt_values),
        observation=valid.observation,
    )
    gateway = RecordingGateway(lambda _: forged)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with pytest.raises(ExecutionContractError, match="outside the lease window"):
        executor.execute(approved)
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.UNKNOWN


def test_unknown_outcome_requires_reconciliation_and_never_retries() -> None:
    approved = command()
    receipt_values = completed_result(approved).receipt.model_dump(mode="python")
    receipt_values.update(
        receipt_id="receipt.unknown",
        response_digest=None,
        outcome=m.DispatchOutcome.UNKNOWN_OUTCOME,
        completed_at=None,
        response_status=None,
        bytes_received=0,
        reconciliation_required=True,
    )
    provisional_receipt = m.DispatchReceipt.model_validate(receipt_values)
    receipt_values["receipt_id"] = canonical_dispatch_receipt_id(provisional_receipt)
    receipt = m.DispatchReceipt.model_validate(receipt_values)
    result = GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=receipt,
    )
    reconciled = completed_result(approved)
    gateway = RecordingGateway(lambda _: result, reconciler=lambda _: reconciled)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    assert executor.execute(approved) == result
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.UNKNOWN
    with pytest.raises(DispatchReplayError):
        executor.execute(approved)
    assert len(gateway.calls) == 1

    assert executor.reconcile(approved.intent.action_id) == reconciled
    assert executor.state_for(approved.intent.action_id) is LocalDispatchState.COMPLETED
    assert len(gateway.calls) == 1
    assert len(gateway.reconcile_calls) == 1
    with pytest.raises(ReconciliationStateError, match="not awaiting"):
        executor.reconcile(approved.intent.action_id)


def test_receipt_cannot_exceed_reserved_request_or_response_bytes() -> None:
    approved = command()
    oversized = completed_result(approved, bytes_received=8193)
    gateway = RecordingGateway(lambda _: oversized)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

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
