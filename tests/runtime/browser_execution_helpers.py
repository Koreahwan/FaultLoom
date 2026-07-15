from __future__ import annotations

from faultloom.execution import (
    BrowserChildCandidate,
    BrowserChildKind,
    BrowserIdentityContext,
    EndpointScheme,
    SemanticEndpoint,
)
from faultloom_protocol import SCHEMA_VERSION

from .execution_helpers import D1, execution_identity, semantic_request


def browser_context(
    *,
    context_id: str = "browser.owner",
    identity_id: str = "identity.owner",
    tenant_id: str = "tenant.alpha",
    session_uri: str = "secret://run/identity-owner",
    partition_id: str = "partition.owner",
) -> BrowserIdentityContext:
    identity = execution_identity(
        context_id=context_id,
        identity_id=identity_id,
        tenant_id=tenant_id,
        session_uri=session_uri,
    )
    return BrowserIdentityContext(
        schema_version=SCHEMA_VERSION,
        browser_context_id=context_id,
        storage_partition_id=partition_id,
        identity=identity,
    )


def http_candidate(
    kind: BrowserChildKind,
    *,
    suffix: str,
    context_id: str = "browser.owner",
) -> BrowserChildCandidate:
    request = semantic_request(path=f"/{suffix}")
    return BrowserChildCandidate(
        schema_version=SCHEMA_VERSION,
        candidate_id=f"child.{suffix}",
        parent_action_id="action.nav",
        browser_context_id=context_id,
        kind=kind,
        endpoint=request.endpoint,
        request=request,
        discovery_digest=D1,
    )


def websocket_candidate() -> BrowserChildCandidate:
    endpoint = SemanticEndpoint(
        schema_version=SCHEMA_VERSION,
        scheme=EndpointScheme.WSS,
        hostname="loopback.test",
        port=443,
        path="/events",
    )
    return BrowserChildCandidate(
        schema_version=SCHEMA_VERSION,
        candidate_id="child.websocket",
        parent_action_id="action.nav",
        browser_context_id="browser.owner",
        kind=BrowserChildKind.WEBSOCKET,
        endpoint=endpoint,
        discovery_digest=D1,
    )
