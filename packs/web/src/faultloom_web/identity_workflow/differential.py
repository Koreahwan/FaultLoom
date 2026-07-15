"""Deterministic one-dimension differential planning and comparison."""

from __future__ import annotations

from enum import StrEnum
from typing import Self, assert_never

from pydantic import Field, model_validator

from faultloom_protocol import DifferentialCase, DifferentialPlan, SCHEMA_VERSION
from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest

from ._base import IdentityWorkflowModel
from .errors import IdentityWorkflowError
from .sessions import IdentitySessionVault


class DifferentialDimension(StrEnum):
    IDENTITY = "identity"
    TENANT = "tenant"
    ROLE = "role"
    SESSION = "session"
    OBJECT = "object"
    ORDER = "order"


class ExpectedRelation(StrEnum):
    EQUIVALENT = "equivalent"
    ISOLATED = "isolated"


class DifferentialVariant(IdentityWorkflowModel):
    case_id: Identifier
    operation_id: Identifier
    baseline_identity_context_id: Identifier
    comparison_identity_context_id: Identifier
    dimension: DifferentialDimension
    baseline_value_digest: Sha256Digest
    comparison_value_digest: Sha256Digest
    expected_invariant_id: Identifier
    expected_relation: ExpectedRelation
    negative_control: bool = False

    @model_validator(mode="after")
    def _changes_one_declared_dimension(self) -> Self:
        if self.baseline_value_digest == self.comparison_value_digest:
            raise IdentityWorkflowError(
                code="differential.dimension_unchanged",
                detail="the declared differential dimension must change",
            )
        match self.dimension:
            case (
                DifferentialDimension.IDENTITY
                | DifferentialDimension.TENANT
                | DifferentialDimension.ROLE
                | DifferentialDimension.SESSION
            ):
                if (
                    self.baseline_identity_context_id
                    == self.comparison_identity_context_id
                ):
                    raise IdentityWorkflowError(
                        code="differential.context_unchanged",
                        detail="identity-bound dimensions require distinct contexts",
                    )
            case DifferentialDimension.OBJECT | DifferentialDimension.ORDER:
                pass
            case unreachable:
                assert_never(unreachable)
        return self


class DifferentialPlanSeed(IdentityWorkflowModel):
    plan_id: Identifier
    run_id: Identifier
    workflow_graph_id: Identifier
    created_at: AwareDatetime
    variants: tuple[DifferentialVariant, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _contains_unique_cases_and_a_control(self) -> Self:
        case_ids = {variant.case_id for variant in self.variants}
        if len(case_ids) != len(self.variants):
            raise IdentityWorkflowError(
                code="differential.case_reused",
                detail="differential case IDs must be unique",
            )
        if not any(variant.negative_control for variant in self.variants):
            raise IdentityWorkflowError(
                code="differential.control_missing",
                detail="differential plans require a negative control",
            )
        return self


class DifferentialObservation(IdentityWorkflowModel):
    case_id: Identifier
    identity_context_id: Identifier
    status_code: int = Field(ge=100, le=599)
    data_digest: Sha256Digest
    state_digest: Sha256Digest
    effect_digest: Sha256Digest
    data_exposed: bool
    state_changed: bool
    effect_occurred: bool


class DifferentialComparison(IdentityWorkflowModel):
    case_id: Identifier
    expected_invariant_id: Identifier
    status_equal: bool
    data_equal: bool
    state_equal: bool
    effect_equal: bool
    invariant_holds: bool
    negative_control: bool


class MultiUserDifferentialPlanner:
    def __init__(self, vault: IdentitySessionVault) -> None:
        self._vault = vault

    def plan(self, seed: DifferentialPlanSeed) -> DifferentialPlan:
        variants = tuple(sorted(seed.variants, key=lambda variant: variant.case_id))
        for variant in variants:
            self._vault.registration(variant.baseline_identity_context_id)
            self._vault.registration(variant.comparison_identity_context_id)
        cases = tuple(
            DifferentialCase(
                schema_version=SCHEMA_VERSION,
                case_id=variant.case_id,
                operation_id=variant.operation_id,
                baseline_identity_context_id=variant.baseline_identity_context_id,
                comparison_identity_context_id=variant.comparison_identity_context_id,
                varied_dimension=variant.dimension.value,
                expected_invariant_id=variant.expected_invariant_id,
            )
            for variant in variants
        )
        return DifferentialPlan(
            schema_version=SCHEMA_VERSION,
            plan_id=seed.plan_id,
            run_id=seed.run_id,
            workflow_graph_id=seed.workflow_graph_id,
            cases=cases,
            negative_control_case_ids=tuple(
                variant.case_id for variant in variants if variant.negative_control
            ),
            created_at=seed.created_at,
        )

    def compare(
        self,
        variant: DifferentialVariant,
        observations: tuple[DifferentialObservation, DifferentialObservation],
    ) -> DifferentialComparison:
        baseline, comparison = observations
        if baseline.case_id != variant.case_id or comparison.case_id != variant.case_id:
            raise IdentityWorkflowError(
                code="differential.observation_foreign",
                detail="observations must identify the planned case",
            )
        if (
            baseline.identity_context_id != variant.baseline_identity_context_id
            or comparison.identity_context_id
            != variant.comparison_identity_context_id
        ):
            raise IdentityWorkflowError(
                code="differential.actor_foreign",
                detail="observations must preserve the planned actor ordering",
            )
        status_equal = baseline.status_code == comparison.status_code
        data_equal = baseline.data_digest == comparison.data_digest
        state_equal = baseline.state_digest == comparison.state_digest
        effect_equal = baseline.effect_digest == comparison.effect_digest
        match variant.expected_relation:
            case ExpectedRelation.EQUIVALENT:
                invariant_holds = (
                    status_equal and data_equal and state_equal and effect_equal
                )
            case ExpectedRelation.ISOLATED:
                invariant_holds = not (
                    comparison.data_exposed
                    or comparison.state_changed
                    or comparison.effect_occurred
                )
            case unreachable:
                assert_never(unreachable)
        return DifferentialComparison(
            case_id=variant.case_id,
            expected_invariant_id=variant.expected_invariant_id,
            status_equal=status_equal,
            data_equal=data_equal,
            state_equal=state_equal,
            effect_equal=effect_equal,
            invariant_holds=invariant_holds,
            negative_control=variant.negative_control,
        )
