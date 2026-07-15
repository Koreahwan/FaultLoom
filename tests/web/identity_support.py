from __future__ import annotations

from labs.identity_workflow import IdentityWorkflowFixture
from faultloom_web.identity_workflow import (
    IdentitySessionVault,
    SessionChannel,
    SessionRegistration,
)


def registration_for(
    fixture: IdentityWorkflowFixture,
    context_id: str,
) -> SessionRegistration:
    contexts = {
        context.identity_context_id: context
        for context in fixture.identity_contexts
    }
    sessions = {
        session.auth_session_id: session for session in fixture.auth_sessions
    }
    profiles = {profile.identity_id: profile for profile in fixture.identities}
    context = contexts[context_id]
    if context.browser_context_ref is not None:
        channel = SessionChannel.BROWSER
    else:
        channel = SessionChannel.API
    return SessionRegistration(
        channel=channel,
        profile=profiles[context.identity_id],
        session=sessions[context.auth_session_id],
        context=context,
    )


def registered_vault(fixture: IdentityWorkflowFixture) -> IdentitySessionVault:
    vault = IdentitySessionVault()
    for context in fixture.identity_contexts:
        vault.register(registration_for(fixture, context.identity_context_id))
    return vault
