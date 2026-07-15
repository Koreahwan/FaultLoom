from faultloom.chain import PrimitiveStatus, SyntheticLlmPrimitive
from faultloom_protocol import (
    ActionClass,
    ActionIntent,
    PrimitiveRecord,
    ResourceRef,
    StateRef,
    sha256_digest,
)
from faultloom_llm import (
    AgentObservation,
    AgentObservationNormalizer,
    t35_admission,
)

from .chain_contracts import ObservationSeed
from .fixture import D1, D2, D3, NOW, LlmAgentFixture


def chain_states() -> tuple[StateRef, StateRef, StateRef]:
    return tuple(
        StateRef(
            schema_version="0.1.0",
            state_id="state.llm.chain",
            state_kind=kind,
            state_version=index,
            state_digest=digest,
        )
        for index, (kind, digest) in enumerate(
            (("web_input", D1), ("prompt_control", D2), ("tool_canary", D3)),
            start=1,
        )
    )


def prompt_intent(fixture: LlmAgentFixture, state: StateRef) -> ActionIntent:
    return ActionIntent(
        schema_version="0.1.0",
        action_id="action.llm.prompt",
        run_id=fixture.web_content.run_id,
        target_id="target.llm.loopback",
        pack_id="pack.llm.agent",
        action_kind="llm.prompt.observe",
        action_class=ActionClass.OBSERVE,
        subject=fixture.subject,
        resource=ResourceRef(
            schema_version="0.1.0",
            resource_id="resource.llm.prompt",
            resource_kind="local_prompt_trace",
            target_id="target.llm.loopback",
            tenant_id=fixture.subject.tenant_id,
        ),
        state=state,
        protocol="agent_local",
        method="OBSERVE",
        path="/agent/prompt",
        payload_digest=fixture.web_content.content_digest,
        requested_at=NOW,
        parent_action_ids=("action.web.submit",),
    )


def web_admission(
    fixture: LlmAgentFixture,
    state: StateRef,
) -> SyntheticLlmPrimitive:
    resource = ResourceRef(
        schema_version="0.1.0",
        resource_id="resource.web.input",
        resource_kind="owned_web_form",
        target_id="target.llm.loopback",
        tenant_id=fixture.subject.tenant_id,
    )
    primitive = PrimitiveRecord(
        schema_version="0.1.0",
        primitive_id="primitive.web.input",
        run_id=fixture.web_content.run_id,
        primitive_kind="web.untrusted_input",
        subject=fixture.subject,
        resource=resource,
        pre_state=state,
        post_state=state,
        action_intent_digest=D1,
        dispatch_receipt_digest=D2,
        evidence_refs=(fixture.prompt_evidence,),
        verified=True,
    )
    return SyntheticLlmPrimitive(
        admission_id="admission.web.input",
        capability_id="capability.web.input",
        primitive=primitive,
        capability_kind="web.untrusted_input",
        source_pack_id="pack.web.identity_workflow",
        status=PrimitiveStatus.VERIFIED,
        effect_ids=("effect.web.input",),
        contract_id="faultloom.lab.web_input.v1",
    )


def llm_admission(
    fixture: LlmAgentFixture,
    seed: ObservationSeed,
) -> SyntheticLlmPrimitive:
    source = AgentObservation(
        observation_id=seed.observation_id,
        run_id=fixture.web_content.run_id,
        capability_kind=seed.capability_kind,
        subject=fixture.subject,
        resource=seed.intent.resource,
        pre_state=seed.pre_state,
        post_state=seed.post_state,
        action_intent_digest=sha256_digest(seed.intent),
        dispatch_receipt_digest=seed.dispatch_digest,
        evidence_refs=(fixture.prompt_evidence,),
        content_provenance=(fixture.web_content,),
        precondition_ids=seed.precondition_ids,
        effect_ids=seed.effect_ids,
        final_effect_observed=True,
        clean_replay=True,
        negative_control_passed=True,
        authorized_lease_observed=True,
    )
    return t35_admission(AgentObservationNormalizer().normalize(source))
