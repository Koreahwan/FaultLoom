"""In-memory identity/workflow lab state with deterministic clean replay."""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterator, Literal, assert_never

from pydantic import BaseModel, ConfigDict, Field

from faultloom_protocol.base import Identifier, Sha256Digest
from faultloom_web.identity_workflow import (
    IdentityActionFamily,
    IdentitySafetyAdmission,
    WorkflowTrace,
)
from .contracts import IdentityWorkflowFixture


class FixtureMode(StrEnum):
    VULNERABLE = "vulnerable"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class IdentityLabError(ValueError):
    detail: str

    def __str__(self) -> str:
        return self.detail


class _LabStateModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class LabWorkflowValue(_LabStateModel):
    workflow_id: Identifier
    workflow_state_id: Identifier


class LabSnapshot(_LabStateModel):
    fixture_id: Identifier
    generation: int = Field(ge=0)
    workflow_values: tuple[LabWorkflowValue, ...]
    state_digest: Sha256Digest


class LabAccessOutcome(_LabStateModel):
    context_id: Identifier
    resource_id: Identifier
    status_code: Literal[200, 403]
    data_digest: Sha256Digest
    state_digest: Sha256Digest
    effect_digest: Sha256Digest
    data_exposed: bool
    state_changed: Literal[False] = False
    effect_occurred: Literal[False] = False


class IdentityWorkflowLab:
    """Mutable state machine limited to owned deterministic fixture canaries."""

    def __init__(self, fixture: IdentityWorkflowFixture) -> None:
        self.fixture = fixture
        self._generation = 0
        self._workflow_states = self._clean_states()
        self._contexts = {
            context.identity_context_id: context
            for context in fixture.identity_contexts
        }

    def snapshot(self) -> LabSnapshot:
        values = tuple(
            LabWorkflowValue(workflow_id=workflow_id, workflow_state_id=state_id)
            for workflow_id, state_id in sorted(self._workflow_states.items())
        )
        material = "\0".join(
            f"{value.workflow_id}:{value.workflow_state_id}" for value in values
        )
        return LabSnapshot(
            fixture_id=self.fixture.fixture_id,
            generation=self._generation,
            workflow_values=values,
            state_digest=_digest(f"state:{material}"),
        )

    def inspect_idor(self, context_id: Identifier, mode: FixtureMode) -> LabAccessOutcome:
        context = self._contexts.get(context_id)
        if context is None:
            raise IdentityLabError(f"unknown fixture context: {context_id}")
        case = self.fixture.idor_case
        same_tenant = context.tenant_id == case.resource_tenant_id
        match mode:
            case FixtureMode.VULNERABLE:
                exposed = True
            case FixtureMode.DENIED:
                exposed = same_tenant
            case unreachable:
                assert_never(unreachable)
        status: Literal[200, 403] = 200 if exposed else 403
        data_label = case.resource_id if exposed else "denied"
        return LabAccessOutcome(
            context_id=context_id,
            resource_id=case.resource_id,
            status_code=status,
            data_digest=_digest(f"data:{data_label}"),
            state_digest=self.snapshot().state_digest,
            effect_digest=_digest("effect:none"),
            data_exposed=exposed,
        )

    def apply_workflow(
        self,
        trace: WorkflowTrace,
        admission: IdentitySafetyAdmission,
    ) -> LabSnapshot:
        if admission.action_family is not IdentityActionFamily.WORKFLOW_TRANSITION:
            raise IdentityLabError("workflow replay requires a transition admission")
        if len(trace.steps) != 1:
            raise IdentityLabError("fixture workflow replay requires one transition")
        step = trace.steps[0]
        if step.identity_context_id != admission.identity_context_id:
            raise IdentityLabError("workflow admission belongs to another identity context")
        current = self._workflow_states.get(trace.workflow_id)
        if current != step.from_state_id:
            raise IdentityLabError("workflow replay did not start from clean fixture state")
        self._workflow_states[trace.workflow_id] = step.to_state_id
        self._generation += 1
        return self.snapshot()

    def reset(self) -> LabSnapshot:
        self._generation = 0
        self._workflow_states = self._clean_states()
        return self.snapshot()

    def _clean_states(self) -> dict[str, str]:
        return {
            trace.workflow_id: trace.steps[0].from_state_id
            for trace in self.fixture.workflows
        }


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


@contextmanager
def clean_identity_replay(lab: IdentityWorkflowLab) -> Iterator[IdentityWorkflowLab]:
    """Reset before replay and guarantee cleanup on exit."""

    lab.reset()
    try:
        yield lab
    finally:
        lab.reset()
