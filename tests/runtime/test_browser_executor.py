from __future__ import annotations

import pytest

from faultloom.execution import (
    BrowserChildKind,
    BrowserContractError,
    BrowserExecutionCoordinator,
    ExecutionFlowKind,
    GatewayDispatchCommand,
    GatewayResult,
    SemanticHttpExecutor,
    UnsupportedBrowserTransport,
)
from .browser_execution_helpers import browser_context, http_candidate, websocket_candidate
from .execution_helpers import (
    CHANNEL_KEY,
    NOW,
    RecordingGateway,
    command,
    completed_result,
    execution_identity,
    semantic_request,
)


def test_identity_contexts_cannot_share_session_or_storage_partition() -> None:
    gateway = RecordingGateway(completed_result)
    browser = BrowserExecutionCoordinator(
        SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        )
    )
    owner = browser_context()
    browser.register_context(owner)

    shared_session = browser_context(
        context_id="browser.member",
        identity_id="identity.member",
        session_uri=owner.session_uri,
        partition_id="partition.member",
    )
    with pytest.raises(BrowserContractError, match="session handle"):
        browser.register_context(shared_session)

    shared_partition = browser_context(
        context_id="browser.outsider",
        identity_id="identity.outsider",
        session_uri="secret://run/identity-outsider",
        partition_id=owner.storage_partition_id,
    )
    with pytest.raises(BrowserContractError, match="storage partition"):
        browser.register_context(shared_partition)


def test_navigation_rejects_cross_identity_session_before_gateway() -> None:
    gateway = RecordingGateway(completed_result)
    browser = BrowserExecutionCoordinator(
        SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        )
    )
    browser.register_context(browser_context())
    member = execution_identity(
        context_id="browser.member",
        identity_id="identity.member",
        tenant_id="tenant.alpha",
        session_uri="secret://run/identity-member",
    )
    member_command = command(identity=member)

    with pytest.raises(BrowserContractError, match="session differs"):
        browser.navigate("browser.owner", member_command)
    assert gateway.calls == []


def test_every_http_browser_child_requires_a_fresh_bound_gateway_action() -> None:
    candidates = (
        http_candidate(BrowserChildKind.REDIRECT, suffix="redirect"),
        http_candidate(BrowserChildKind.IFRAME, suffix="frame"),
        http_candidate(BrowserChildKind.SUBRESOURCE, suffix="script"),
        http_candidate(BrowserChildKind.SERVICE_WORKER, suffix="worker"),
        http_candidate(BrowserChildKind.DOWNLOAD, suffix="download"),
        websocket_candidate(),
    )

    def handle(dispatch_command: GatewayDispatchCommand) -> GatewayResult:
        if dispatch_command.intent.action_id == "action.nav":
            return completed_result(dispatch_command, child_candidates=candidates)
        return completed_result(dispatch_command)

    gateway = RecordingGateway(handle)
    http = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    browser = BrowserExecutionCoordinator(http)
    context = browser_context()
    browser.register_context(context)
    browser.navigate("browser.owner", command(identity=context.identity))

    for index, candidate in enumerate(candidates[:-1], start=1):
        child_command = command(
            action_id=f"action.child.{index}",
            lease_id=f"lease.child.{index}",
            request=candidate.request,
            identity=context.identity,
            parent_action_ids=(candidate.parent_action_id,),
        )
        browser.execute_child("browser.owner", candidate.candidate_id, child_command)

    assert [frame.command.intent.action_id for frame in gateway.calls] == [
        "action.nav",
        "action.child.1",
        "action.child.2",
        "action.child.3",
        "action.child.4",
        "action.child.5",
    ]
    assert [frame.flow_kind for frame in gateway.calls] == [
        ExecutionFlowKind.NAVIGATION,
        ExecutionFlowKind.REDIRECT,
        ExecutionFlowKind.IFRAME,
        ExecutionFlowKind.SUBRESOURCE,
        ExecutionFlowKind.SERVICE_WORKER,
        ExecutionFlowKind.DOWNLOAD,
    ]
    assert [frame.context_generation for frame in gateway.calls] == [1] * 6
    assert [frame.parent_action_id for frame in gateway.calls] == [
        None,
        "action.nav",
        "action.nav",
        "action.nav",
        "action.nav",
        "action.nav",
    ]
    assert browser.pending_candidate_ids("browser.owner") == ("child.websocket",)

    websocket_command = command(
        action_id="action.websocket",
        lease_id="lease.websocket",
        identity=context.identity,
        parent_action_ids=("action.nav",),
    )
    with pytest.raises(UnsupportedBrowserTransport, match="separately admitted"):
        browser.execute_child("browser.owner", "child.websocket", websocket_command)
    assert len(gateway.calls) == 6


def test_forged_or_mismatched_child_never_reaches_gateway() -> None:
    candidate = http_candidate(BrowserChildKind.REDIRECT, suffix="redirect")
    gateway = RecordingGateway(
        lambda dispatch_command: completed_result(
            dispatch_command,
            child_candidates=(candidate,)
            if dispatch_command.intent.action_id == "action.nav"
            else (),
        )
    )
    browser = BrowserExecutionCoordinator(
        SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        )
    )
    context = browser_context()
    browser.register_context(context)
    browser.navigate("browser.owner", command(identity=context.identity))

    forged = command(
        action_id="action.forged",
        lease_id="lease.forged",
        request=semantic_request(path="/not-the-redirect"),
        identity=context.identity,
        parent_action_ids=("action.nav",),
    )
    with pytest.raises(BrowserContractError, match="differs from the discovered child"):
        browser.execute_child("browser.owner", candidate.candidate_id, forged)

    missing_parent = command(
        action_id="action.no-parent",
        lease_id="lease.no-parent",
        request=candidate.request,
        identity=context.identity,
    )
    with pytest.raises(BrowserContractError, match="parent binding"):
        browser.execute_child("browser.owner", candidate.candidate_id, missing_parent)

    with pytest.raises(BrowserContractError, match="not discovered"):
        browser.execute_child("browser.owner", "child.attacker", missing_parent)
    assert len(gateway.calls) == 1


def test_reused_child_candidate_is_poisoned_before_execution() -> None:
    candidate = http_candidate(BrowserChildKind.REDIRECT, suffix="redirect")
    second_candidate = candidate.model_copy(update={"parent_action_id": "action.nav.second"})

    def handle(dispatch_command: GatewayDispatchCommand) -> GatewayResult:
        if dispatch_command.intent.action_id == "action.nav":
            return completed_result(dispatch_command, child_candidates=(candidate,))
        return completed_result(dispatch_command, child_candidates=(second_candidate,))

    gateway = RecordingGateway(handle)
    browser = BrowserExecutionCoordinator(
        SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        )
    )
    context = browser_context()
    browser.register_context(context)
    browser.navigate("browser.owner", command(identity=context.identity))
    second_navigation = command(
        action_id="action.nav.second",
        lease_id="lease.nav.second",
        identity=context.identity,
    )

    with pytest.raises(BrowserContractError, match="candidate ID was reused"):
        browser.navigate("browser.owner", second_navigation)

    assert browser.pending_candidate_ids("browser.owner") == ()


def test_closing_context_discards_pending_children_and_prevents_further_actions() -> None:
    candidate = http_candidate(BrowserChildKind.SUBRESOURCE, suffix="script")
    gateway = RecordingGateway(
        lambda dispatch_command: completed_result(dispatch_command, child_candidates=(candidate,))
    )
    browser = BrowserExecutionCoordinator(
        SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        )
    )
    context = browser_context()
    browser.register_context(context)
    browser.navigate("browser.owner", command(identity=context.identity))

    browser.close_context("browser.owner")

    child_command = command(
        action_id="action.child",
        lease_id="lease.child",
        request=candidate.request,
        identity=context.identity,
        parent_action_ids=("action.nav",),
    )
    with pytest.raises(BrowserContractError, match="not active"):
        browser.execute_child("browser.owner", candidate.candidate_id, child_command)
    assert len(gateway.calls) == 1
