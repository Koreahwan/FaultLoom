from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Literal, cast

import pytest

from faultloom.execution import GatewayDispatchCommand, SemanticBodyRef
from faultloom_web.burp import (
    ActiveBurpRequestPreparer,
    BurpHeader,
    BurpPolicyError,
    BurpScope,
    BurpSelectedBudget,
    BurpSelectedIdentity,
    BurpSelectedRequest,
)
from tests.runtime.execution_helpers import command, semantic_request


def _preparer() -> ActiveBurpRequestPreparer:
    return ActiveBurpRequestPreparer(
        BurpScope(hosts=("lab.test",), path_prefixes=("/approved",))
    )


def _selection(dispatch: GatewayDispatchCommand) -> BurpSelectedRequest:
    endpoint = dispatch.request.endpoint
    reservation = dispatch.lease.reservation
    identity = dispatch.identity
    assert endpoint.scheme.value in {"http", "https"}
    assert identity.identity_id is not None
    assert identity.tenant_id is not None
    return BurpSelectedRequest(
        selection_source="burp.user_selected",
        selection_id="burp-selection.1",
        scheme=cast(Literal["http", "https"], endpoint.scheme.value),
        host=endpoint.hostname,
        port=endpoint.port,
        method=dispatch.request.method,
        path=endpoint.path,
        body_digest=(None if dispatch.request.body_ref is None else dispatch.request.body_ref.cas_digest),
        body_length=(0 if dispatch.request.body_ref is None else dispatch.request.body_ref.byte_length),
        headers=(
            BurpHeader(name="Authorization", value="Bearer must-not-leak"),
            BurpHeader(name="X-Trace-ID", value="trace-safe"),
        ),
        identity=BurpSelectedIdentity(
            context_id=identity.context_id,
            identity_id=identity.identity_id,
            tenant_id=identity.tenant_id,
        ),
        budget=BurpSelectedBudget(
            request_bytes=reservation.request_bytes,
            response_bytes=reservation.response_bytes,
            duration_seconds=reservation.duration_seconds,
        ),
    )


def _approved_command() -> GatewayDispatchCommand:
    return command(request=semantic_request(path="/approved/object", hostname="lab.test"))


def test_user_selected_request_prepares_exact_gateway_command_without_dispatch() -> None:
    dispatch = _approved_command()

    prepared = _preparer().prepare(_selection(dispatch), dispatch)

    assert prepared.gateway_command() is dispatch
    assert prepared.preview.dispatch_performed is False
    assert prepared.preview.gateway_only is True
    assert prepared.preview.headers == (
        BurpHeader(name="Authorization", value="<redacted>"),
        BurpHeader(name="X-Trace-ID", value="<redacted>"),
    )
    serialized = prepared.preview.model_dump_json()
    assert "must-not-leak" not in serialized
    assert "Bearer" not in serialized
    assert "trace-safe" not in serialized


@pytest.mark.parametrize(
    ("change", "error_code"),
    (
        (lambda selection: selection.model_copy(update={"host": "other.test"}), "out_of_scope"),
        (lambda selection: selection.model_copy(update={"method": "POST"}), "method_mismatch"),
        (lambda selection: selection.model_copy(update={"path": "/approved/other"}), "path_mismatch"),
        (
            lambda selection: selection.model_copy(
                update={"budget": selection.budget.model_copy(update={"request_bytes": 1})}
            ),
            "budget_mismatch",
        ),
        (
            lambda selection: selection.model_copy(
                update={
                    "identity": selection.identity.model_copy(update={"identity_id": "identity.other"})
                }
            ),
            "identity_mismatch",
        ),
    ),
)
def test_scope_method_path_budget_and_identity_mismatches_fail_closed(
    change: Callable[[BurpSelectedRequest], BurpSelectedRequest],
    error_code: str,
) -> None:
    dispatch = _approved_command()

    with pytest.raises(BurpPolicyError) as raised:
        _ = _preparer().prepare(change(_selection(dispatch)), dispatch)

    assert raised.value.code == error_code


def test_body_mismatch_fails_closed_before_gateway_handoff() -> None:
    request = semantic_request(path="/approved/body", hostname="lab.test").model_copy(
        update={
            "body_ref": SemanticBodyRef(
                schema_version="0.1.0",
                cas_digest="sha256:" + "a1" * 32,
                byte_length=12,
                media_type="application/json",
            )
        }
    )
    dispatch = command(request=request)
    selection = _selection(dispatch).model_copy(
        update={"body_digest": "sha256:" + "b2" * 32}
    )

    with pytest.raises(BurpPolicyError) as raised:
        _ = _preparer().prepare(selection, dispatch)

    assert raised.value.code == "body_mismatch"


def test_active_adapter_has_no_network_client_or_dispatch_entrypoint() -> None:
    import faultloom_web.burp.active as active

    source = inspect.getsource(active)
    assert "GatewayLauncher" not in source
    assert all(module not in source for module in ("socket", "urllib", "requests", "httpx"))
    assert not hasattr(ActiveBurpRequestPreparer, "dispatch")
