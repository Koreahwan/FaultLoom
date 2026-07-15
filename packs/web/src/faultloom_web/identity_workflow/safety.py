"""Deterministic safety admission for identity/workflow experiments."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self, assert_never

from pydantic import model_validator

from faultloom_protocol import ActionClass
from faultloom_protocol.base import Identifier

from ._base import IdentityWorkflowModel
from .errors import IdentityWorkflowError
from .sessions import IdentitySessionVault


class IdentityActionFamily(StrEnum):
    OBSERVE = "observe"
    READ_OBJECT = "read_object"
    WORKFLOW_TRANSITION = "workflow_transition"
    ACCOUNT_ENUMERATION = "account_enumeration"
    LOCKOUT_TRIGGER = "lockout_trigger"
    EXTERNAL_MESSAGE = "external_message"
    PAYMENT = "payment"
    REAL_ASSET = "real_asset"


class IdentitySafetyRequest(IdentityWorkflowModel):
    request_id: Identifier
    identity_context_id: Identifier
    action_class: ActionClass
    action_family: IdentityActionFamily
    canary_id: Identifier | None = None
    cleanup_plan_id: Identifier | None = None

    @model_validator(mode="after")
    def _state_change_is_reversible(self) -> Self:
        if self.action_class is ActionClass.STATE_CHANGE and (
            self.canary_id is None or self.cleanup_plan_id is None
        ):
            raise IdentityWorkflowError(
                code="safety.cleanup_required",
                detail="state changes require both a canary and cleanup plan",
            )
        return self


class IdentitySafetyAdmission(IdentityWorkflowModel):
    request_id: Identifier
    identity_context_id: Identifier
    action_family: IdentityActionFamily
    admitted: Literal[True] = True
    gateway_lease_required: Literal[True] = True


class IdentitySafetyGate:
    def __init__(self, vault: IdentitySessionVault) -> None:
        self._vault = vault

    def admit(self, request: IdentitySafetyRequest) -> IdentitySafetyAdmission:
        registration = self._vault.registration(request.identity_context_id)
        if not registration.profile.operator_provisioned:
            raise IdentityWorkflowError(
                code="safety.identity_unprovisioned",
                detail="only operator-provisioned identities may execute experiments",
            )
        match request.action_class:
            case ActionClass.OBSERVE | ActionClass.SAFE_PROBE | ActionClass.STATE_CHANGE:
                pass
            case ActionClass.HIGH_LOAD | ActionClass.DESTRUCTIVE:
                raise IdentityWorkflowError(
                    code="safety.action_class_unsupported",
                    detail="high-load and destructive actions are unsupported in v0.1",
                )
            case unreachable:
                assert_never(unreachable)
        match request.action_family:
            case (
                IdentityActionFamily.OBSERVE
                | IdentityActionFamily.READ_OBJECT
                | IdentityActionFamily.WORKFLOW_TRANSITION
            ):
                blocked_detail = None
            case IdentityActionFamily.ACCOUNT_ENUMERATION:
                blocked_detail = "account enumeration is unsupported"
            case IdentityActionFamily.LOCKOUT_TRIGGER:
                blocked_detail = "lockout-capable behavior is unsupported"
            case IdentityActionFamily.EXTERNAL_MESSAGE:
                blocked_detail = "external email or SMS delivery is unsupported"
            case IdentityActionFamily.PAYMENT:
                blocked_detail = "payment changes are unsupported"
            case IdentityActionFamily.REAL_ASSET:
                blocked_detail = "real-asset changes are unsupported"
            case unreachable:
                assert_never(unreachable)
        if blocked_detail is not None:
            raise IdentityWorkflowError(
                code="safety.action_family_blocked",
                detail=blocked_detail,
            )
        if (
            request.action_family is IdentityActionFamily.WORKFLOW_TRANSITION
            and request.action_class is not ActionClass.STATE_CHANGE
        ):
            raise IdentityWorkflowError(
                code="safety.action_class_mismatch",
                detail="workflow transitions must be declared as state changes",
            )
        return IdentitySafetyAdmission(
            request_id=request.request_id,
            identity_context_id=request.identity_context_id,
            action_family=request.action_family,
        )
