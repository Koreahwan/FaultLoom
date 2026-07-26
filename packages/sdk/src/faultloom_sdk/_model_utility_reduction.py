"""Pure paired-outcome reduction without SDK model imports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ArmValue = Literal["baseline", "treatment"]
VerdictValue = Literal[
    "true_positive",
    "true_negative",
    "false_positive",
    "false_negative",
    "inconclusive",
]
_VERIFIER_TRUTH: dict[VerdictValue, bool | None] = {
    "true_positive": True,
    "false_negative": True,
    "true_negative": False,
    "false_positive": False,
    "inconclusive": None,
}


class MetricReductionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MetricObservation:
    case_id: str
    arm: ArmValue
    verdict: VerdictValue
    model_tokens: int
    dispatched_oos: int
    escaped_oos: int


@dataclass(frozen=True, slots=True)
class MetricValues:
    recall_gain_bps: int
    unique_verified_positives: int
    efficiency_gain_bps: int
    recall_loss_bps: int
    dispatched_oos: int
    escaped_oos: int
    tool_only_false_verified: int


def _verifier_truth(verdict: VerdictValue) -> bool | None:
    return _VERIFIER_TRUTH[verdict]


def derive_metric_values(
    observations: tuple[MetricObservation, ...],
) -> MetricValues:
    pairs: dict[str, dict[ArmValue, MetricObservation]] = {}
    for observation in observations:
        pair = pairs.setdefault(observation.case_id, {})
        if observation.arm in pair:
            raise MetricReductionError("utility outcome arm is duplicated")
        pair[observation.arm] = observation
    if any(set(pair) != {"baseline", "treatment"} for pair in pairs.values()):
        raise MetricReductionError("utility outcomes are not paired")
    ordered = tuple(
        (pair["baseline"], pair["treatment"])
        for pair in pairs.values()
    )
    if any(
        _verifier_truth(left.verdict) != _verifier_truth(right.verdict)
        for left, right in ordered
    ):
        raise MetricReductionError("independent verifier truth differs between arms")
    positive = tuple(pair for pair in ordered if _verifier_truth(pair[0].verdict))
    baseline_hits = sum(left.verdict == "true_positive" for left, _ in positive)
    treatment_hits = sum(right.verdict == "true_positive" for _, right in positive)
    denominator = len(positive)
    baseline_recall = 0 if denominator == 0 else baseline_hits * 10_000 // denominator
    treatment_recall = 0 if denominator == 0 else treatment_hits * 10_000 // denominator
    gain = treatment_recall - baseline_recall
    baseline_tokens = sum(left.model_tokens for left, _ in ordered)
    treatment_tokens = sum(right.model_tokens for _, right in ordered)
    efficiency = (
        0
        if baseline_tokens == 0 or treatment_hits < baseline_hits
        else max(0, (baseline_tokens - treatment_tokens) * 10_000 // baseline_tokens)
    )
    return MetricValues(
        recall_gain_bps=gain,
        unique_verified_positives=sum(
            right.verdict == "true_positive" and left.verdict != "true_positive"
            for left, right in positive
        ),
        efficiency_gain_bps=efficiency,
        recall_loss_bps=max(0, -gain),
        dispatched_oos=sum(item.dispatched_oos for item in observations),
        escaped_oos=sum(item.escaped_oos for item in observations),
        tool_only_false_verified=sum(
            item.verdict == "false_positive" for item in observations
        ),
    )


__all__ = ["MetricObservation", "MetricReductionError", "derive_metric_values"]
