from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_protocol import ActionClass
from faultloom_web.identity_workflow import (
    IdentityActionFamily,
    IdentitySafetyGate,
    IdentitySafetyRequest,
    IdentitySessionVault,
    IdentityWorkflowError,
    SessionChannel,
    SessionRegistration,
)
from labs.identity_workflow import identity_workflow_fixture

from .identity_support import registered_vault, registration_for


def test_vault_keeps_every_browser_and_api_session_owned_by_one_context() -> None:
    # Given
    fixture = identity_workflow_fixture()
    vault = IdentitySessionVault()

    # When
    for context in fixture.identity_contexts:
        vault.register(registration_for(fixture, context.identity_context_id))

    # Then
    assert vault.context_ids() == tuple(
        sorted(context.identity_context_id for context in fixture.identity_contexts)
    )


def test_vault_rejects_a_session_handle_shared_across_identities() -> None:
    # Given
    fixture = identity_workflow_fixture()
    owner = registration_for(fixture, "context.identity.owner.browser")
    outsider = registration_for(fixture, "context.identity.outsider.browser")
    shared_session = outsider.session.model_copy(
        update={"session_handle_ref": owner.session.session_handle_ref}
    )
    vault = IdentitySessionVault()
    vault.register(owner)

    # When / Then
    with pytest.raises(IdentityWorkflowError, match="session_reference_shared"):
        vault.register(
            SessionRegistration(
                channel=SessionChannel.BROWSER,
                profile=outsider.profile,
                session=shared_session,
                context=outsider.context,
            )
        )


def test_registration_rejects_one_context_aliasing_browser_and_api() -> None:
    # Given
    fixture = identity_workflow_fixture()
    browser = registration_for(fixture, "context.identity.owner.browser")
    api = registration_for(fixture, "context.identity.owner.api")
    aliased_context = browser.context.model_copy(
        update={"api_session_ref": api.context.api_session_ref}
    )

    # When / Then
    with pytest.raises(ValidationError, match="identity.channel_alias"):
        SessionRegistration(
            channel=SessionChannel.BROWSER,
            profile=browser.profile,
            session=browser.session,
            context=aliased_context,
        )


def test_registration_rejects_role_state_from_another_identity() -> None:
    # Given
    fixture = identity_workflow_fixture()
    outsider = registration_for(fixture, "context.identity.outsider.browser")
    contaminated = outsider.context.model_copy(update={"role_ids": ("role.admin",)})

    # When / Then
    with pytest.raises(ValidationError, match="identity.role_unprovisioned"):
        SessionRegistration(
            channel=SessionChannel.BROWSER,
            profile=outsider.profile,
            session=outsider.session,
            context=contaminated,
        )


def test_state_change_requires_a_canary_and_cleanup_plan() -> None:
    # Given / When / Then
    with pytest.raises(ValidationError, match="safety.cleanup_required"):
        IdentitySafetyRequest(
            request_id="safety.missing-cleanup",
            identity_context_id="context.identity.owner.browser",
            action_class=ActionClass.STATE_CHANGE,
            action_family=IdentityActionFamily.WORKFLOW_TRANSITION,
        )


@pytest.mark.parametrize(
    "family",
    [
        IdentityActionFamily.ACCOUNT_ENUMERATION,
        IdentityActionFamily.LOCKOUT_TRIGGER,
        IdentityActionFamily.EXTERNAL_MESSAGE,
        IdentityActionFamily.PAYMENT,
        IdentityActionFamily.REAL_ASSET,
    ],
)
def test_safety_gate_blocks_unsafe_identity_action_families(
    family: IdentityActionFamily,
) -> None:
    # Given
    gate = IdentitySafetyGate(registered_vault(identity_workflow_fixture()))
    request = IdentitySafetyRequest(
        request_id=f"safety.{family.value}",
        identity_context_id="context.identity.owner.browser",
        action_class=ActionClass.SAFE_PROBE,
        action_family=family,
    )

    # When / Then
    with pytest.raises(IdentityWorkflowError, match="action_family_blocked"):
        gate.admit(request)


def test_safety_gate_admits_reversible_canary_transition_only_with_gateway_lease() -> None:
    # Given
    gate = IdentitySafetyGate(registered_vault(identity_workflow_fixture()))
    request = IdentitySafetyRequest(
        request_id="safety.invite-transition",
        identity_context_id="context.identity.owner.browser",
        action_class=ActionClass.STATE_CHANGE,
        action_family=IdentityActionFamily.WORKFLOW_TRANSITION,
        canary_id="canary.invite",
        cleanup_plan_id="cleanup.invite",
    )

    # When
    admission = gate.admit(request)

    # Then
    assert admission.admitted is True
    assert admission.gateway_lease_required is True
