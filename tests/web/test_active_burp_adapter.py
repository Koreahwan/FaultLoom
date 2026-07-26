from __future__ import annotations

import http.client
import socket
import urllib.request
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from typing import Literal, cast

import pytest

from faultloom.execution import GatewayDispatchCommand, GatewayDispatchResult, SemanticBodyRef
from faultloom_protocol import (
    AuthoritySigner,
    sign_authority_grant,
    sign_scope_epoch,
)
from faultloom_protocol.models import ActionBudget, ActionPolicy, AuthorityGrant, ScopeEpoch, TargetAsset
from faultloom_web.burp import (
    ActiveBurpDispatchAuthority,
    ActiveBurpGatewayHandoff,
    ActiveBurpRequestPreparer,
    BurpHeader,
    BurpPolicyError,
    BurpScope,
    BurpSelectedBudget,
    BurpSelectedIdentity,
    BurpSelectedRequest,
)
from tests.protocol.factories import LATER, NOW, sample_models
from tests.runtime.execution_helpers import command, completed_result, semantic_request


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


def _loopback_command() -> GatewayDispatchCommand:
    unsigned = command(
        request=semantic_request(path="/approved/object", hostname="127.0.0.1"),
        lease_expires_at=NOW + timedelta(seconds=30),
    )
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    return unsigned.model_copy(
        update={
            "lease": unsigned.lease.model_copy(
                update={"authority_key_id": signer.public_key_record.key_id}
            )
        }
    )


def _nonloopback_command() -> GatewayDispatchCommand:
    unsigned = command(
        request=semantic_request(path="/approved/object", hostname="lab.test"),
        lease_expires_at=NOW + timedelta(seconds=30),
    )
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    return unsigned.model_copy(
        update={
            "lease": unsigned.lease.model_copy(
                update={"authority_key_id": signer.public_key_record.key_id}
            )
        }
    )


def _loopback_authority(command: GatewayDispatchCommand) -> ActiveBurpDispatchAuthority:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    models = sample_models()
    target = TargetAsset(
        schema_version="0.1.0",
        target_id="target.loopback",
        hostnames=("127.0.0.1",),
        ports=(80,),
        protocols=("http",),
        paths=("/approved/*",),
        methods=("GET",),
    )
    policy = ActionPolicy(
        schema_version="0.1.0",
        allowed_classes=(command.intent.action_class,),
        allowed_families=(command.intent.action_kind,),
        allowed_methods=(command.request.method,),
        allowed_path_patterns=("/approved/*",),
    )
    budget = ActionBudget(
        schema_version="0.1.0",
        total_actions=1,
        rate_per_minute=1,
        max_concurrency=1,
        max_request_bytes=command.lease.reservation.request_bytes,
        max_response_bytes=command.lease.reservation.response_bytes,
        max_duration_seconds=command.lease.reservation.duration_seconds,
    )
    grant = cast(AuthorityGrant, models["AuthorityGrant"]).model_copy(
        update={
            "targets": (target,),
            "pack_ids": (command.intent.pack_id,),
            "action_policy": policy,
            "identities": (command.identity.identity_id,),
            "tenants": (command.identity.tenant_id,),
            "budget": budget,
        }
    )
    assert grant.grant_id == command.lease.grant_id
    assert grant.grant_version == command.lease.grant_version
    epoch = ScopeEpoch(
        schema_version="0.1.0",
        grant_id=grant.grant_id,
        epoch=command.lease.scope_epoch,
        issued_at=NOW,
        expires_at=LATER,
    )
    return ActiveBurpDispatchAuthority(
        authority=sign_authority_grant(grant, signer, signed_at=NOW),
        authority_public_key=signer.public_key_record,
        scope_epoch=sign_scope_epoch(epoch, signer, signed_at=NOW),
        scope_public_key=signer.public_key_record,
        verified_at=NOW + timedelta(seconds=10),
    )


def _loopback_preparer() -> ActiveBurpRequestPreparer:
    return ActiveBurpRequestPreparer(
        BurpScope(hosts=("127.0.0.1",), path_prefixes=("/approved",))
    )


class _OwnedLoopbackGateway:
    """Test double for the existing Gateway dispatch surface, never a transport."""

    def __init__(self) -> None:
        self.commands: list[GatewayDispatchCommand] = []

    def dispatch(self, command: GatewayDispatchCommand) -> GatewayDispatchResult:
        assert command.request.endpoint.hostname == "127.0.0.1"
        self.commands.append(command)
        return completed_result(command, body=b'{"canary":"owned-active-burp"}')


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


def test_owned_loopback_handoff_dispatches_only_the_preapproved_gateway_command() -> None:
    dispatch = _loopback_command()
    prepared = _loopback_preparer().prepare(_selection(dispatch), dispatch)
    gateway = _OwnedLoopbackGateway()

    receipt = ActiveBurpGatewayHandoff(_loopback_authority(dispatch)).execute(prepared, gateway)

    assert gateway.commands == [dispatch]
    assert receipt.selection_id == "burp-selection.1"
    assert receipt.gateway_receipt_id.startswith("receipt.")
    assert receipt.target_id == "target.loopback"
    assert receipt.gateway_dispatched is True
    assert receipt.candidate_only is True
    assert receipt.verification_evidence is False
    assert receipt.verification_status == "unverified"


def test_signed_authority_and_scope_are_verified_separately_before_gateway_handoff() -> None:
    dispatch = _loopback_command()
    prepared = _loopback_preparer().prepare(_selection(dispatch), dispatch)
    authority = _loopback_authority(dispatch)
    gateway = _OwnedLoopbackGateway()
    invalid_authority = replace(
        authority,
        authority=authority.authority.model_copy(
            update={"signature": authority.authority.signature.model_copy(update={"signature": "A" * 86})}
        ),
    )
    invalid_scope = replace(
        authority,
        scope_epoch=authority.scope_epoch.model_copy(
            update={"signature": authority.scope_epoch.signature.model_copy(update={"signature": "B" * 86})}
        ),
    )

    for material in (invalid_authority, invalid_scope):
        with pytest.raises(BurpPolicyError) as raised:
            _ = ActiveBurpGatewayHandoff(material).execute(prepared, gateway)
        assert raised.value.code == "authority_invalid"

    assert gateway.commands == []


def test_signed_target_and_budget_are_enforced_before_gateway_handoff() -> None:
    dispatch = _loopback_command()
    gateway = _OwnedLoopbackGateway()
    outsider = dispatch.model_copy(
        update={"intent": dispatch.intent.model_copy(update={"target_id": "target.outsider"})}
    )
    excessive = dispatch.model_copy(
        update={
            "lease": dispatch.lease.model_copy(
                update={
                    "reservation": dispatch.lease.reservation.model_copy(
                        update={"request_bytes": dispatch.lease.reservation.request_bytes + 1}
                    )
                }
            )
        }
    )

    for changed, code in ((outsider, "target_not_authorized"), (excessive, "budget_not_authorized")):
        prepared = _loopback_preparer().prepare(_selection(changed), changed)
        with pytest.raises(BurpPolicyError) as raised:
            _ = ActiveBurpGatewayHandoff(_loopback_authority(dispatch)).execute(prepared, gateway)
        assert raised.value.code == code

    assert gateway.commands == []


def test_non_loopback_target_is_rejected_before_gateway_handoff() -> None:
    dispatch = _nonloopback_command()
    prepared = ActiveBurpRequestPreparer(
        BurpScope(hosts=("lab.test",), path_prefixes=("/approved",))
    ).prepare(_selection(dispatch), dispatch)
    gateway = _OwnedLoopbackGateway()

    with pytest.raises(BurpPolicyError) as raised:
        _ = ActiveBurpGatewayHandoff(_loopback_authority(_loopback_command())).execute(
            prepared, gateway
        )

    assert raised.value.code == "target_not_owned_loopback"
    assert gateway.commands == []


def test_changed_command_is_rejected_before_gateway_handoff() -> None:
    dispatch = _loopback_command()
    prepared = _loopback_preparer().prepare(_selection(dispatch), dispatch)
    changed = dispatch.model_copy(
        update={"request": dispatch.request.model_copy(update={"path": "/approved/changed"})}
    )
    gateway = _OwnedLoopbackGateway()

    with pytest.raises(BurpPolicyError) as raised:
        _ = ActiveBurpGatewayHandoff(_loopback_authority(dispatch)).execute(
            replace(prepared, command=changed), gateway
        )

    assert raised.value.code == "command_changed"
    assert gateway.commands == []


def test_active_burp_runtime_paths_do_not_call_direct_egress_primitives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fail_direct_egress(*_args: object, **_kwargs: object) -> None:
        calls.append("direct-egress")
        raise AssertionError("active Burp pack must not invoke direct egress")

    class SentinelSocket:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            calls.append("socket.socket")

        def connect(self, *_args: object, **_kwargs: object) -> None:
            calls.append("socket.socket.connect")
            raise AssertionError("active Burp pack must not connect direct sockets")

    monkeypatch.setattr(socket, "create_connection", fail_direct_egress)
    monkeypatch.setattr(socket, "socket", SentinelSocket)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", fail_direct_egress)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", fail_direct_egress)
    monkeypatch.setattr(http.client.HTTPConnection, "request", fail_direct_egress)
    monkeypatch.setattr(urllib.request, "urlopen", fail_direct_egress)

    dispatch = _loopback_command()
    with pytest.raises(BurpPolicyError):
        _ = _loopback_preparer().prepare(
            _selection(dispatch).model_copy(update={"host": "outside.test"}), dispatch
        )
    prepared = _loopback_preparer().prepare(_selection(dispatch), dispatch)
    authority = _loopback_authority(dispatch)
    gateway = _OwnedLoopbackGateway()

    receipt = ActiveBurpGatewayHandoff(authority).execute(prepared, gateway)
    invalid_authority = replace(
        authority,
        authority=authority.authority.model_copy(
            update={"signature": authority.authority.signature.model_copy(update={"signature": "A" * 86})}
        ),
    )
    invalid_scope = replace(
        authority,
        scope_epoch=authority.scope_epoch.model_copy(
            update={"signature": authority.scope_epoch.signature.model_copy(update={"signature": "B" * 86})}
        ),
    )
    for rejected_authority in (invalid_authority, invalid_scope):
        with pytest.raises(BurpPolicyError):
            _ = ActiveBurpGatewayHandoff(rejected_authority).execute(prepared, gateway)
    changed = dispatch.model_copy(
        update={"request": dispatch.request.model_copy(update={"path": "/approved/changed"})}
    )
    with pytest.raises(BurpPolicyError):
        _ = ActiveBurpGatewayHandoff(authority).execute(replace(prepared, command=changed), gateway)

    assert receipt.gateway_dispatched is True
    assert gateway.commands == [dispatch]
    assert calls == []
