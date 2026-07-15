use crate::Digest;
use crate::ipc::{
    ActionKind, DenialCode, DeniedResponse, DispatchRequest, EgressPlane, FlowKind,
    GatewayResponse, RequiredFeature, encode_request,
};
use crate::supervisor_durable::ReservedResponseSlot;
use crate::supervisor_protocol::{SupervisorDispatch, SupervisorResponse};

use super::SupervisorRuntime;

#[must_use]
pub(crate) struct PreflightedDispatch {
    request: DispatchRequest,
    response_slot: ReservedResponseSlot,
}

#[must_use]
pub(crate) struct DispatchPreflightRejection {
    response_slot: ReservedResponseSlot,
    reason: DenialCode,
}

impl DispatchPreflightRejection {
    pub(crate) fn into_parts(self) -> (ReservedResponseSlot, DenialCode) {
        (self.response_slot, self.reason)
    }
}

impl PreflightedDispatch {
    pub(crate) fn into_response_slot(self) -> ReservedResponseSlot {
        self.response_slot
    }
}

#[must_use]
pub(crate) struct DispatchedResponse {
    response_slot: ReservedResponseSlot,
    response: SupervisorResponse,
}

impl DispatchedResponse {
    pub(crate) fn into_parts(self) -> (ReservedResponseSlot, SupervisorResponse) {
        (self.response_slot, self.response)
    }
}

impl SupervisorRuntime {
    pub(crate) fn preflight_dispatch(
        &self,
        intent: SupervisorDispatch,
        response_slot: ReservedResponseSlot,
    ) -> Result<PreflightedDispatch, DispatchPreflightRejection> {
        let preflighted = self.canonical_request(intent).and_then(|request| {
            self.lease.preflight_issue(
                &request.grant_id,
                request.grant_version,
                request.intent_digest,
            )?;
            Ok(request)
        });
        match preflighted {
            Ok(request) => Ok(PreflightedDispatch {
                request,
                response_slot,
            }),
            Err(reason) => Err(DispatchPreflightRejection {
                response_slot,
                reason,
            }),
        }
    }

    pub(crate) fn dispatch(
        &self,
        preflighted: PreflightedDispatch,
        command_digest: Digest,
    ) -> std::io::Result<DispatchedResponse> {
        let PreflightedDispatch {
            request,
            response_slot,
        } = preflighted;
        let action_id = request.action_id.clone();
        let control_envelope_id = response_slot.request_envelope_id();
        let response = match self.prepare_request(request, control_envelope_id) {
            Ok(request) => match encode_request(&request) {
                Ok(frame) => self.gateway.handle_terminal(request, Digest::of(&frame))?,
                Err(reason) => GatewayResponse::Denied(DeniedResponse::bound(
                    action_id.clone(),
                    command_digest,
                    reason,
                )),
            },
            Err(reason) => {
                GatewayResponse::Denied(DeniedResponse::bound(action_id, command_digest, reason))
            }
        };
        Ok(DispatchedResponse {
            response_slot,
            response: SupervisorResponse::Gateway(Box::new(response)),
        })
    }

    fn canonical_request(&self, intent: SupervisorDispatch) -> Result<DispatchRequest, DenialCode> {
        if intent.target_id != self.selection.target_id() {
            return Err(DenialCode::ScopeTargetDenied);
        }
        let mut request = DispatchRequest {
            action_id: intent.action_id,
            correlation_id: intent.correlation_id,
            grant_id: self.grant_id.clone(),
            grant_version: self.grant_version,
            target_id: self.selection.target_id().to_owned(),
            pack_id: self.selection.pack_id().to_owned(),
            action_family: self.selection.action_family().to_owned(),
            identity_id: self.selection.identity_id().to_owned(),
            tenant_id: self.selection.tenant_id().map(str::to_owned),
            intent_digest: intent.intent_digest,
            decision_digest: intent.decision_digest,
            lease_id: intent.lease_id,
            scope_epoch: intent.scope_epoch,
            action_kind: ActionKind::SemanticHttpV1,
            action_class: intent.action_class,
            egress_plane: EgressPlane::TargetGateway,
            flow_kind: FlowKind::TopLevel,
            parent_action_id: None,
            required_features: vec![RequiredFeature::GatewayDispatchV1],
            hostname: self.selection.hostname().to_owned(),
            protocol: self.selection.protocol().to_owned(),
            method: intent.method,
            path: intent.path,
            target: self.selection.socket(),
            resolution_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            dispatch_nonce: intent.dispatch_nonce,
            request_issued_at_millis: intent.issued_at_millis,
            request_expires_at_millis: intent.expires_at_millis,
            retry_of_intent_digest: intent.retry_of_intent_digest,
            payload: intent.payload,
            scope_proof: vec![1],
            lease_proof: vec![1],
            compiler_proof: vec![1],
            canary_ref: intent.canary_ref,
            checkpoint_ref: intent.checkpoint_ref,
            cleanup_plan_ref: intent.cleanup_plan_ref,
        };
        request.bind_canonical_semantics();
        request.validate()?;
        Ok(request)
    }

    fn prepare_request(
        &self,
        mut request: DispatchRequest,
        control_envelope_id: Digest,
    ) -> Result<DispatchRequest, DenialCode> {
        let mut prepared = self.scope.prepare_dispatch(&request)?;
        request.scope_proof = std::mem::take(&mut prepared.scope_proof);
        let mut compiler_binding = self.compiler.issue_proof(&request)?;
        request.compiler_proof = std::mem::take(&mut compiler_binding.proof);
        let issued = crate::supervisor_policy::issue_lease(
            &self.lease,
            &self.budget,
            crate::supervisor_policy::LeaseIssuanceBindings {
                request: &request,
                control_envelope_id,
                scope: prepared,
                compiler: &compiler_binding,
            },
        )?;
        request.lease_proof = issued.proof;
        Ok(request)
    }
}
