from __future__ import annotations

import json
from collections import defaultdict
from fnmatch import fnmatchcase

from pydantic import ValidationError

from faultloom.hypothesis.models import HypothesisSeed, NegativeResultSeed
from faultloom.patch_variant import (
    AdaptationResult,
    AdaptationRequest,
    CandidatePoCStep,
    StepHazard,
)
from faultloom.patch_variant.adaptation import adapt_recipe
from faultloom_protocol import (
    ActionClass,
    ActionIntent,
    AuthorityGrant,
    EvidenceRef,
    ExplicitDeny,
    HypothesisRecord,
    ResourceRef,
    SubjectRef,
    sha256_digest,
)
from faultloom_protocol.base import AwareDatetime
from faultloom.tool_planner import (
    ToolCandidate,
    ToolEstimate,
    ToolPlan,
    ToolPlanner,
    ToolPlanningError,
)

from .models import (
    ActionContext,
    AuthorizedAutomationError,
    AuthorizedAutomationResult,
    AutomationLimits,
    AutomationRequest,
    ModelTurn,
    CandidateFindingDraft,
    SafePoCProposal,
    ToolActionProposal,
)


class AuthorizedAutomationCoordinator:
    """Compile one untrusted model turn into offline, candidate-only research state."""

    def __init__(
        self,
        *,
        planner: ToolPlanner,
    ) -> None:
        self._planner = planner

    def run(
        self,
        *,
        request: AutomationRequest,
        raw_model_turn: bytes,
    ) -> AuthorizedAutomationResult:
        request = validate_automation_request(request)
        turn = parse_model_turn(raw_model_turn, limits=request.limits)
        prepared = _prepare(request, turn, self._planner)

        # Compilation is deliberately pure.  Durable publication is a separate
        # create-once outbox step, so a failed journal/sink can never expose a
        # partially committed automation turn.
        recorded_hypotheses = tuple(seed.as_record() for seed in prepared.hypothesis_seeds)
        recorded_negative_results = tuple(seed.as_record() for seed in prepared.negative_seeds)
        return AuthorizedAutomationResult(
            run_id=request.observations.run_id,
            authority_grant_id=request.authority_grant.grant_id,
            authority_grant_version=request.authority_grant.grant_version,
            authority_grant_digest=sha256_digest(request.authority_grant),
            observation_bundle_digest=sha256_digest(
                request.observations.model_dump(mode="python")
            ),
            action_context_digest=sha256_digest(
                request.action_context.model_dump(mode="python")
            ),
            poc_context_digest=(
                None
                if request.poc_context is None
                else sha256_digest(request.poc_context.model_dump(mode="python"))
            ),
            hypotheses=recorded_hypotheses,
            negative_results=recorded_negative_results,
            admitted_plans=prepared.plans,
            poc=prepared.poc,
            finding_draft=prepared.finding_draft,
            stop_reason=turn.stop_reason,
            provider_network_access=request.provider_network_access,
        )


def validate_automation_request(request: AutomationRequest) -> AutomationRequest:
    """Revalidate and admit a request before any provider or target side effect."""

    if type(request) is not AutomationRequest:
        raise AuthorizedAutomationError("automation requires an exact automation request")
    try:
        exact = AutomationRequest.model_validate(request.model_dump(mode="python"))
    except ValidationError as exc:
        raise AuthorizedAutomationError("automation request is malformed") from exc
    _validate_request_binding(exact)
    return exact


class _PreparedTurn:
    __slots__ = ("hypothesis_seeds", "negative_seeds", "plans", "poc", "finding_draft")

    def __init__(
        self,
        *,
        hypothesis_seeds: tuple[HypothesisSeed, ...],
        negative_seeds: tuple[NegativeResultSeed, ...],
        plans: tuple[ToolPlan, ...],
        poc: AdaptationResult | None,
        finding_draft: CandidateFindingDraft | None,
    ) -> None:
        self.hypothesis_seeds = hypothesis_seeds
        self.negative_seeds = negative_seeds
        self.plans = plans
        self.poc = poc
        self.finding_draft = finding_draft


def parse_model_turn(raw_model_turn: bytes, *, limits: AutomationLimits) -> ModelTurn:
    """Validate raw structured output, including provider tool-call arguments bytes."""
    if type(raw_model_turn) is not bytes:
        raise AuthorizedAutomationError("model turn must be exact UTF-8 bytes")
    if len(raw_model_turn) > limits.max_response_bytes:
        raise AuthorizedAutomationError("model turn exceeds response byte limit")
    try:
        document = json.loads(
            raw_model_turn.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        AuthorizedAutomationError,
        RecursionError,
    ) as exc:
        raise AuthorizedAutomationError("model turn is not valid bounded JSON") from exc
    if _json_depth(document) > limits.max_json_depth:
        raise AuthorizedAutomationError("model turn exceeds JSON depth limit")
    try:
        # Re-encode after duplicate-key validation so pydantic validates in JSON
        # mode while no second parser can see a duplicate key.
        return ModelTurn.model_validate_json(
            json.dumps(document, separators=(",", ":"), ensure_ascii=False)
        )
    except (TypeError, ValidationError) as exc:
        raise AuthorizedAutomationError("model turn does not match the proposal schema") from exc


def _prepare(
    request: AutomationRequest,
    turn: ModelTurn,
    planner: ToolPlanner,
) -> _PreparedTurn:
    _validate_counts(turn, request.limits)
    evidence = {item.evidence_id: item for item in request.observations.evidence_refs}
    seeds = tuple(
        HypothesisSeed(
            run_id=request.observations.run_id,
            statement=proposal.statement,
            provenance=proposal.provenance,
            prerequisite_ids=proposal.prerequisite_ids,
            created_at=request.issued_at,
            supporting_evidence=_resolve_evidence(
                proposal.supporting_evidence_ids, evidence
            ),
            contradicting_evidence=_resolve_evidence(
                proposal.contradicting_evidence_ids, evidence
            ),
        )
        for proposal in turn.hypotheses
    )
    records = tuple(seed.as_record() for seed in seeds)
    if len({item.hypothesis_id for item in records}) != len(records):
        raise AuthorizedAutomationError("model turn produces duplicate canonical hypotheses")
    by_proposal = {
        proposal.proposal_id: record for proposal, record in zip(turn.hypotheses, records, strict=True)
    }
    observed_experiments = set(request.observations.observed_experiment_digests)
    if any(
        item.experiment_digest not in observed_experiments
        for item in turn.negative_results
    ):
        raise AuthorizedAutomationError(
            "negative conclusion references an unobserved experiment"
        )
    negatives = tuple(
        NegativeResultSeed(
            run_id=request.observations.run_id,
            hypothesis_id=_hypothesis_for(item.hypothesis_proposal_id, by_proposal).hypothesis_id,
            experiment_digest=item.experiment_digest,
            conclusion=item.conclusion,
            evidence_refs=_resolve_evidence(item.evidence_ids, evidence),
            recorded_at=request.issued_at,
        )
        for item in turn.negative_results
    )
    if len({item.as_record().negative_result_id for item in negatives}) != len(negatives):
        raise AuthorizedAutomationError("model turn produces duplicate negative conclusions")
    plans = _prepare_plans(request, turn, by_proposal, planner)
    poc = _prepare_poc(request, turn.poc, by_proposal, evidence)
    finding_draft = _prepare_finding_draft(turn, by_proposal)
    return _PreparedTurn(
        hypothesis_seeds=seeds,
        negative_seeds=negatives,
        plans=plans,
        poc=poc,
        finding_draft=finding_draft,
    )


def _prepare_plans(
    request: AutomationRequest,
    turn: ModelTurn,
    hypotheses: dict[str, HypothesisRecord],
    planner: ToolPlanner,
) -> tuple[ToolPlan, ...]:
    grouped: dict[str, list[ToolCandidate]] = defaultdict(list)
    for proposal in turn.actions:
        if proposal.action_class not in {ActionClass.OBSERVE, ActionClass.SAFE_PROBE}:
            raise AuthorizedAutomationError("only observe and safe_probe actions are accepted")
        hypothesis = _hypothesis_for(proposal.hypothesis_proposal_id, hypotheses)
        intent = _intent_for(request.action_context, proposal, request.issued_at)
        _validate_proposed_action(intent, request.authority_grant)
        grouped[proposal.hypothesis_proposal_id].append(
            ToolCandidate(
                candidate_id=proposal.candidate_id,
                hypothesis_id=hypothesis.hypothesis_id,
                intent=intent,
                adapter_id=proposal.adapter_id,
                capability=proposal.capability,
                expected_information_gain_bps=proposal.expected_information_gain_bps,
                estimate=ToolEstimate(
                    rate_slots=proposal.estimate.rate_slots,
                    duration_seconds=proposal.estimate.duration_seconds,
                    bytes=proposal.estimate.bytes,
                    concurrency=proposal.estimate.concurrency,
                    actions=1,
                    cost_microunits=proposal.estimate.cost_microunits,
                ),
            )
        )
    remaining = request.planning_budget
    plans: list[ToolPlan] = []
    for proposal in turn.hypotheses:
        candidates = grouped.get(proposal.proposal_id, ())
        if not candidates:
            continue
        try:
            plan = planner.select(
                hypothesis=_hypothesis_for(proposal.proposal_id, hypotheses),
                grant=request.authority_grant,
                budget=remaining,
                candidates=tuple(candidates),
            )
        except ToolPlanningError as exc:
            raise AuthorizedAutomationError("model action proposal is not admitted") from exc
        plans.append(plan)
        remaining = plan.remaining
    return tuple(plans)


def _prepare_poc(
    request: AutomationRequest,
    proposal: SafePoCProposal | None,
    hypotheses: dict[str, HypothesisRecord],
    evidence: dict[str, EvidenceRef],
) -> AdaptationResult | None:
    if proposal is None:
        return None
    context = request.poc_context
    if context is None:
        raise AuthorizedAutomationError("PoC proposal requires an operator-supplied PoC context")
    hypothesis = _hypothesis_for(proposal.hypothesis_proposal_id, hypotheses)
    if any(
        step.action_class not in {ActionClass.OBSERVE, ActionClass.SAFE_PROBE}
        or step.hazard != "safe"
        or step.action_class not in request.authority_grant.action_policy.allowed_classes
        or step.action_kind not in request.authority_grant.action_policy.allowed_families
        for step in proposal.steps
    ):
        raise AuthorizedAutomationError("PoC proposal contains an unsafe or unauthorized step")
    for step in proposal.steps:
        _validate_proposed_action(
            ActionIntent(
                schema_version="0.1.0",
                action_id=f"{context.run_id}.{step.step_id}",
                run_id=context.run_id,
                target_id=context.target_id,
                pack_id=context.pack_id,
                action_kind=step.action_kind,
                action_class=step.action_class,
                subject=context.subject,
                resource=context.route_ref,
                protocol=context.transport,
                method=step.method,
                path=context.route_path,
                requested_at=request.issued_at,
                cleanup_plan_ref=context.cleanup_plan_ref,
            ),
            request.authority_grant,
        )
    adaptation = AdaptationRequest(
        adaptation_id=proposal.adaptation_id,
        recipe_id=proposal.recipe_id,
        run_id=context.run_id,
        target_id=context.target_id,
        pack_id=context.pack_id,
        route_ref=context.route_ref,
        route_path=context.route_path,
        subject=context.subject,
        transport=context.transport,
        prerequisite_ids=context.prerequisite_ids,
        prerequisites=context.prerequisites,
        candidate_steps=tuple(
            CandidatePoCStep(
                step_id=step.step_id,
                action_class=step.action_class,
                action_kind=step.action_kind,
                method=step.method,
                payload_digest=step.payload_digest,
                expected_effect=step.expected_effect,
                negative_control=step.negative_control,
                required=step.required,
                hazard=StepHazard.SAFE,
            )
            for step in proposal.steps
        ),
        expected_observable_effect=proposal.expected_observable_effect,
        negative_controls=proposal.negative_controls,
        cleanup_plan_ref=context.cleanup_plan_ref,
        requested_at=request.issued_at,
        evidence_refs=_resolve_evidence(proposal.evidence_ids, evidence),
    )
    result = adapt_recipe(
        context.advisory_match_id,
        hypothesis.hypothesis_id,
        adaptation,
    )
    if result.adaptation.removed_unsafe_step_digests:
        raise AuthorizedAutomationError("PoC proposal required unsafe-step removal")
    return result


def _prepare_finding_draft(
    turn: ModelTurn,
    hypotheses: dict[str, HypothesisRecord],
) -> CandidateFindingDraft | None:
    proposal = turn.finding_draft
    if proposal is None:
        return None
    hypothesis = _hypothesis_for(proposal.hypothesis_proposal_id, hypotheses)
    if proposal.poc_recipe_id is not None:
        if turn.poc is None or proposal.poc_recipe_id != turn.poc.recipe_id:
            raise AuthorizedAutomationError("finding draft references an absent PoC recipe")
    return CandidateFindingDraft(
        hypothesis_id=hypothesis.hypothesis_id,
        poc_recipe_id=proposal.poc_recipe_id,
        title=proposal.title,
        severity=proposal.severity,
        summary=proposal.summary,
        impact=proposal.impact,
        reproduction_steps=proposal.reproduction_steps,
        remediation=proposal.remediation,
    )


def _intent_for(
    context: ActionContext,
    proposal: ToolActionProposal,
    requested_at: AwareDatetime,
) -> ActionIntent:
    return ActionIntent(
        schema_version="0.1.0",
        action_id=f"{context.run_id}.{proposal.candidate_id}",
        run_id=context.run_id,
        target_id=context.target_id,
        pack_id=context.pack_id,
        action_kind=proposal.action_kind,
        action_class=proposal.action_class,
        subject=context.subject,
        resource=context.resource,
        protocol=context.protocol,
        method=context.method,
        path=context.path,
        payload_digest=context.payload_digest,
        requested_at=requested_at,
        cleanup_plan_ref=context.cleanup_plan_ref,
    )


def _resolve_evidence(
    ids: tuple[str, ...],
    available: dict[str, EvidenceRef],
) -> tuple[EvidenceRef, ...]:
    if len(ids) != len(set(ids)):
        raise AuthorizedAutomationError("model turn repeats an evidence reference")
    try:
        return tuple(available[item] for item in ids)
    except KeyError as exc:
        raise AuthorizedAutomationError("model turn references evidence outside the observation bundle") from exc


def _hypothesis_for(
    proposal_id: str,
    records: dict[str, HypothesisRecord],
) -> HypothesisRecord:
    try:
        return records[proposal_id]
    except KeyError as exc:
        raise AuthorizedAutomationError("model turn references an unknown hypothesis proposal") from exc


def _validate_counts(turn: ModelTurn, limits: AutomationLimits) -> None:
    if len(turn.hypotheses) > limits.max_hypotheses:
        raise AuthorizedAutomationError("model turn exceeds hypothesis limit")
    if len(turn.negative_results) > limits.max_negative_results:
        raise AuthorizedAutomationError("model turn exceeds negative-result limit")
    if len(turn.actions) > limits.max_actions:
        raise AuthorizedAutomationError("model turn exceeds action limit")
    if turn.poc is not None and len(turn.poc.steps) > limits.max_poc_steps:
        raise AuthorizedAutomationError("model turn exceeds PoC step limit")


def _validate_request_binding(request: AutomationRequest) -> None:
    run_id = request.observations.run_id
    grant = request.authority_grant
    if any(item.run_id != run_id for item in request.observations.evidence_refs):
        raise AuthorizedAutomationError("observation evidence belongs to another run")
    if request.action_context.run_id != run_id:
        raise AuthorizedAutomationError("action context belongs to another run")
    if request.action_context.resource.target_id != request.action_context.target_id:
        raise AuthorizedAutomationError("action context resource belongs to another target")
    if not grant.not_before <= request.issued_at < grant.expires_at:
        raise AuthorizedAutomationError("automation request is outside the authority validity window")
    if not any(
        window.starts_at <= request.issued_at < window.ends_at
        for window in grant.execution_windows
    ):
        raise AuthorizedAutomationError("automation request is outside every execution window")
    _validate_context_authority(
        target_id=request.action_context.target_id,
        pack_id=request.action_context.pack_id,
        subject=request.action_context.subject,
        resource=request.action_context.resource,
        protocol=request.action_context.protocol,
        method=request.action_context.method,
        path=request.action_context.path,
        grant=grant,
    )
    context = request.poc_context
    if context is not None and (
        context.run_id != run_id or context.route_ref.target_id != context.target_id
    ):
        raise AuthorizedAutomationError("PoC context belongs to another run or target")
    if context is not None:
        if (
            context.target_id != request.action_context.target_id
            or context.pack_id != request.action_context.pack_id
            or context.subject != request.action_context.subject
        ):
            raise AuthorizedAutomationError("PoC context differs from the admitted action context")
        _validate_context_authority(
            target_id=context.target_id,
            pack_id=context.pack_id,
            subject=context.subject,
            resource=context.route_ref,
            protocol=context.transport,
            method=None,
            path=context.route_path,
            grant=grant,
        )


def _validate_context_authority(
    *,
    target_id: str,
    pack_id: str,
    subject: SubjectRef,
    resource: ResourceRef,
    protocol: str,
    method: str | None,
    path: str | None,
    grant: AuthorityGrant,
) -> None:
    # Revalidate exact protocol models before reading security-sensitive fields.
    exact_grant = AuthorityGrant.model_validate(grant.model_dump(mode="python"))
    exact_subject = SubjectRef.model_validate(subject.model_dump(mode="python"))
    exact_resource = ResourceRef.model_validate(resource.model_dump(mode="python"))
    target = next(
        (item for item in exact_grant.targets if item.target_id == target_id),
        None,
    )
    if target is None:
        raise AuthorizedAutomationError("context target is outside the authority grant")
    if pack_id not in exact_grant.pack_ids:
        raise AuthorizedAutomationError("context pack is outside the authority grant")
    if exact_resource.target_id != target_id:
        raise AuthorizedAutomationError("context resource belongs to another target")
    if (
        exact_subject.identity_id is not None
        and exact_subject.identity_id not in exact_grant.identities
    ):
        raise AuthorizedAutomationError("context identity is outside the authority grant")
    for tenant_id in (exact_subject.tenant_id, exact_resource.tenant_id):
        if tenant_id is not None and tenant_id not in exact_grant.tenants:
            raise AuthorizedAutomationError("context tenant is outside the authority grant")
    if target.protocols and protocol not in target.protocols:
        raise AuthorizedAutomationError("context protocol is outside the target scope")
    if method is not None and (
        (target.methods and method not in target.methods)
        or (
            exact_grant.action_policy.allowed_methods
            and method not in exact_grant.action_policy.allowed_methods
        )
    ):
        raise AuthorizedAutomationError("context method is outside the authority grant")
    if path is not None and (
        (target.paths and not any(_target_path_matches(pattern, path) for pattern in target.paths))
        or (
            exact_grant.action_policy.allowed_path_patterns
            and not any(
                fnmatchcase(path, pattern)
                for pattern in exact_grant.action_policy.allowed_path_patterns
            )
        )
    ):
        raise AuthorizedAutomationError("context path is outside the authority grant")
    if any(
        not deny.action_families
        and _context_deny_matches(
            target_id=target_id,
            hostnames=target.hostnames,
            method=method,
            path=path,
            deny=deny,
        )
        for deny in exact_grant.action_policy.denied
    ):
        raise AuthorizedAutomationError("context matches an explicit deny")


def _validate_proposed_action(intent: ActionIntent, grant: AuthorityGrant) -> None:
    target = next(
        (item for item in grant.targets if item.target_id == intent.target_id),
        None,
    )
    if target is None or intent.pack_id not in grant.pack_ids:
        raise AuthorizedAutomationError("proposed action target or pack is unauthorized")
    policy = grant.action_policy
    if (
        intent.action_class not in policy.allowed_classes
        or intent.action_kind not in policy.allowed_families
    ):
        raise AuthorizedAutomationError("proposed action is outside the authority policy")
    if (target.methods or policy.allowed_methods) and intent.method is None:
        raise AuthorizedAutomationError("proposed action is missing an authorized method")
    if intent.method is not None and (
        (target.methods and intent.method not in target.methods)
        or (policy.allowed_methods and intent.method not in policy.allowed_methods)
    ):
        raise AuthorizedAutomationError("proposed action method is unauthorized")
    if (target.paths or policy.allowed_path_patterns) and intent.path is None:
        raise AuthorizedAutomationError("proposed action is missing an authorized path")
    if intent.path is not None and (
        (target.paths and not any(_target_path_matches(item, intent.path) for item in target.paths))
        or (
            policy.allowed_path_patterns
            and not any(fnmatchcase(intent.path, item) for item in policy.allowed_path_patterns)
        )
    ):
        raise AuthorizedAutomationError("proposed action path is unauthorized")
    if any(_deny_matches(intent, target.hostnames, deny) for deny in policy.denied):
        raise AuthorizedAutomationError("proposed action matches an explicit deny")


def _deny_matches(
    intent: ActionIntent,
    hostnames: tuple[str, ...],
    deny: ExplicitDeny,
) -> bool:
    return (
        (deny.target_id is None or deny.target_id == intent.target_id)
        and (not deny.action_families or intent.action_kind in deny.action_families)
        and (deny.path_pattern is None or fnmatchcase(intent.path or "", deny.path_pattern))
        and (not deny.methods or intent.method in deny.methods)
        and (
            deny.host_pattern is None
            or any(fnmatchcase(host, deny.host_pattern) for host in hostnames)
        )
    )


def _context_deny_matches(
    *,
    target_id: str,
    hostnames: tuple[str, ...],
    method: str | None,
    path: str | None,
    deny: ExplicitDeny,
) -> bool:
    """Match only family-agnostic denies before a model chooses an action.

    Family-specific denies remain enforced against each concrete action/PoC
    step by ``_deny_matches``. Treating them as blanket context denies would
    incorrectly suppress unrelated, explicitly allowed action families.
    """

    return (
        (deny.target_id is None or deny.target_id == target_id)
        and (deny.path_pattern is None or fnmatchcase(path or "", deny.path_pattern))
        and (not deny.methods or method in deny.methods)
        and (
            deny.host_pattern is None
            or any(fnmatchcase(host, deny.host_pattern) for host in hostnames)
        )
    )


def _target_path_matches(scope_path: str, candidate_path: str) -> bool:
    if "*" in scope_path or "?" in scope_path or "[" in scope_path:
        return fnmatchcase(candidate_path, scope_path)
    return candidate_path == scope_path or candidate_path.startswith(
        scope_path.rstrip("/") + "/"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorizedAutomationError("model turn contains duplicate JSON keys")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise AuthorizedAutomationError(f"model turn contains non-JSON constant {value}")


def _json_depth(value: object, current: int = 0) -> int:
    if isinstance(value, dict):
        return max((_json_depth(item, current + 1) for item in value.values()), default=current)
    if isinstance(value, list):
        return max((_json_depth(item, current + 1) for item in value), default=current)
    return current
