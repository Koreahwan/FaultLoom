use std::time::{SystemTime, UNIX_EPOCH};

use crate::Digest;
use crate::ipc::{
    DenialCode, DeniedResponse, DispatchOutcome, DispatchReceipt, DispatchRequest, GatewayResponse,
};
use crate::policy::{ActionCompiler, LeaseVerifier, ScopeVerifier};
use crate::transport::{TargetTransport, TransportObservation};

pub(crate) trait Clock {
    fn now_millis(&self) -> u64;
}

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

pub(crate) struct Gateway<S, L, C, T, K> {
    scope: S,
    lease: L,
    compiler: C,
    transport: T,
    clock: K,
}

impl<S, L, C, T, K> Gateway<S, L, C, T, K>
where
    S: ScopeVerifier,
    L: LeaseVerifier,
    C: ActionCompiler,
    T: TargetTransport,
    K: Clock,
{
    pub(crate) const fn new(scope: S, lease: L, compiler: C, transport: T, clock: K) -> Self {
        Self {
            scope,
            lease,
            compiler,
            transport,
            clock,
        }
    }

    pub(crate) fn handle(
        &self,
        request: DispatchRequest,
        request_frame_digest: Digest,
    ) -> GatewayResponse {
        if let Err(reason) = request.validate() {
            return denied(&request, request_frame_digest, reason);
        }
        let scope = match self.scope.verify(&request) {
            Ok(approval) => approval,
            Err(reason) => return denied(&request, request_frame_digest, reason),
        };
        if scope.intent_digest != request.intent_digest
            || scope.decision_digest != request.decision_digest
            || scope.lease_id != request.lease_id
            || scope.grant_id != request.grant_id
            || scope.grant_version != request.grant_version
            || scope.scope_epoch != request.scope_epoch
            || scope.scope_binding_digest != request.scope_binding_digest()
            || scope.target != request.target
            || scope.action_kind != request.action_kind
            || scope.action_class != request.action_class
            || scope.required_features != request.required_features
        {
            return denied(
                &request,
                request_frame_digest,
                DenialCode::VerificationBindingMismatch,
            );
        }
        let lease = match self.lease.verify(&request) {
            Ok(approval) => approval,
            Err(reason) => return denied(&request, request_frame_digest, reason),
        };
        if lease.intent_digest != request.intent_digest
            || lease.lease_id != request.lease_id
            || lease.scope_epoch != request.scope_epoch
            || lease.maximum_dispatches != 1
        {
            return denied(
                &request,
                request_frame_digest,
                DenialCode::VerificationBindingMismatch,
            );
        }
        let compiled = match self.compiler.compile(&request) {
            Ok(compiled) => compiled,
            Err(reason) => return denied(&request, request_frame_digest, reason),
        };
        if compiled.intent_digest != request.intent_digest
            || compiled.action_kind != request.action_kind
            || compiled.target != scope.target
            || compiled.bytes.is_empty()
        {
            return denied(
                &request,
                request_frame_digest,
                DenialCode::VerificationBindingMismatch,
            );
        }

        let dispatched_at_millis = self.clock.now_millis();
        let observation = self.transport.dispatch(&compiled);
        let completed_at_millis = self.clock.now_millis().max(dispatched_at_millis);
        let receipt = make_receipt(
            &request,
            &compiled.bytes,
            observation,
            dispatched_at_millis,
            completed_at_millis,
        );
        GatewayResponse::Receipt {
            action_id: request.action_id,
            receipt,
        }
    }
}

fn denied(
    request: &DispatchRequest,
    request_frame_digest: Digest,
    reason: DenialCode,
) -> GatewayResponse {
    GatewayResponse::Denied(DeniedResponse {
        action_id: request.action_id.clone(),
        request_digest: request_frame_digest,
        reason,
    })
}

fn make_receipt(
    request: &DispatchRequest,
    compiled_bytes: &[u8],
    observation: TransportObservation,
    dispatched_at_millis: u64,
    completed_at_millis: u64,
) -> DispatchReceipt {
    let request_digest = Digest::of(compiled_bytes);
    let response_digest = match observation.outcome {
        DispatchOutcome::Completed => Some(Digest::of(&observation.response)),
        DispatchOutcome::UnknownOutcome if !observation.response.is_empty() => {
            Some(Digest::of(&observation.response))
        }
        DispatchOutcome::Failed | DispatchOutcome::UnknownOutcome => None,
    };
    let bytes_received = observation.response.len() as u64;
    let reconciliation_required = observation.outcome == DispatchOutcome::UnknownOutcome;
    let receipt_id = receipt_digest(
        request,
        request_digest,
        response_digest,
        observation.outcome,
        dispatched_at_millis,
        completed_at_millis,
        observation.bytes_sent,
        bytes_received,
        reconciliation_required,
    );
    DispatchReceipt {
        receipt_id,
        lease_id: request.lease_id.clone(),
        intent_digest: request.intent_digest,
        decision_digest: request.decision_digest,
        scope_epoch: request.scope_epoch,
        request_digest,
        response_digest,
        outcome: observation.outcome,
        dispatched_at_millis,
        completed_at_millis,
        bytes_sent: observation.bytes_sent,
        bytes_received,
        reconciliation_required,
    }
}

#[allow(clippy::too_many_arguments)]
fn receipt_digest(
    request: &DispatchRequest,
    request_digest: Digest,
    response_digest: Option<Digest>,
    outcome: DispatchOutcome,
    dispatched_at_millis: u64,
    completed_at_millis: u64,
    bytes_sent: u64,
    bytes_received: u64,
    reconciliation_required: bool,
) -> Digest {
    let mut canonical = Vec::with_capacity(256);
    canonical.extend_from_slice(b"faultloom-gateway-receipt-v1\0");
    push_string(&mut canonical, &request.lease_id);
    canonical.extend_from_slice(request.intent_digest.as_bytes());
    canonical.extend_from_slice(request.decision_digest.as_bytes());
    canonical.extend_from_slice(&request.scope_epoch.to_be_bytes());
    canonical.extend_from_slice(request_digest.as_bytes());
    match response_digest {
        Some(digest) => {
            canonical.push(1);
            canonical.extend_from_slice(digest.as_bytes());
        }
        None => canonical.push(0),
    }
    canonical.push(outcome as u8);
    canonical.extend_from_slice(&dispatched_at_millis.to_be_bytes());
    canonical.extend_from_slice(&completed_at_millis.to_be_bytes());
    canonical.extend_from_slice(&bytes_sent.to_be_bytes());
    canonical.extend_from_slice(&bytes_received.to_be_bytes());
    canonical.push(u8::from(reconciliation_required));
    Digest::of(&canonical)
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::*;
    use crate::ipc::{ActionClass, ActionKind, FlowKind, RequiredFeature, encode_request};
    use crate::policy::{
        CompiledAction, LeaseApproval, ScopeApproval, UnavailableActionCompiler,
        UnavailableLeaseVerifier, UnavailableScopeVerifier,
    };
    use crate::transport::{TcpTargetTransport, TransportObservation};

    struct FixtureScope;

    impl ScopeVerifier for FixtureScope {
        fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
            if request.scope_proof != b"fixture-scope-proof" {
                return Err(DenialCode::ScopeDenied);
            }
            Ok(ScopeApproval::fixture(request))
        }
    }

    struct FixtureLease;

    impl LeaseVerifier for FixtureLease {
        fn verify(&self, request: &DispatchRequest) -> Result<LeaseApproval, DenialCode> {
            if request.lease_proof != b"fixture-lease-proof" {
                return Err(DenialCode::LeaseDenied);
            }
            Ok(LeaseApproval::fixture(request))
        }
    }

    struct FixtureCompiler;

    impl ActionCompiler for FixtureCompiler {
        fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
            if request.compiler_proof != b"fixture-compiler-proof" || request.payload != b"PING" {
                return Err(DenialCode::CompilerDenied);
            }
            Ok(CompiledAction::fixture(request))
        }
    }

    #[derive(Clone)]
    struct FixedClock {
        calls: Arc<AtomicUsize>,
    }

    impl FixedClock {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Clock for FixedClock {
        fn now_millis(&self) -> u64 {
            1_000 + (self.calls.fetch_add(1, Ordering::SeqCst) % 2) as u64
        }
    }

    fn request(target: std::net::SocketAddr) -> DispatchRequest {
        DispatchRequest {
            action_id: "action:loopback".to_owned(),
            grant_id: "grant:fixture".to_owned(),
            grant_version: 1,
            target_id: "target:owned-loopback".to_owned(),
            pack_id: "web".to_owned(),
            action_family: "http.semantic".to_owned(),
            identity_id: "identity:operator".to_owned(),
            tenant_id: Some("tenant:owned".to_owned()),
            intent_digest: Digest::of(b"fixture-intent"),
            decision_digest: Digest::of(b"fixture-decision"),
            lease_id: "lease:fixture".to_owned(),
            scope_epoch: 7,
            action_kind: ActionKind::SemanticHttpV1,
            action_class: ActionClass::SafeProbe,
            flow_kind: FlowKind::TopLevel,
            parent_action_id: None,
            required_features: vec![RequiredFeature::GatewayDispatchV1],
            hostname: "localhost".to_owned(),
            protocol: "http".to_owned(),
            method: "GET".to_owned(),
            path: "/".to_owned(),
            target,
            payload: b"PING".to_vec(),
            scope_proof: b"fixture-scope-proof".to_vec(),
            lease_proof: b"fixture-lease-proof".to_vec(),
            compiler_proof: b"fixture-compiler-proof".to_vec(),
            canary_ref: None,
            cleanup_plan_ref: None,
        }
    }

    fn handle<S, L, C, T, K>(
        gateway: &Gateway<S, L, C, T, K>,
        request: DispatchRequest,
    ) -> GatewayResponse
    where
        S: ScopeVerifier,
        L: LeaseVerifier,
        C: ActionCompiler,
        T: TargetTransport,
        K: Clock,
    {
        let frame = encode_request(&request).expect("canonical request frame");
        gateway.handle(request, Digest::of(&frame))
    }

    #[test]
    fn production_kernel_denies_before_opening_target_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let gateway = Gateway::new(
            UnavailableScopeVerifier,
            UnavailableLeaseVerifier,
            UnavailableActionCompiler,
            TcpTargetTransport::new(),
            SystemClock,
        );
        let response = handle(
            &gateway,
            request(listener.local_addr().expect("listener address")),
        );
        assert!(matches!(
            response,
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::ScopeVerifierUnavailable,
                ..
            })
        ));
        assert_eq!(
            listener.accept().expect_err("no target connection").kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn fixture_only_loopback_dispatch_produces_deterministic_receipts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
        let target = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("Gateway connection");
                let mut request = Vec::new();
                stream.read_to_end(&mut request).expect("read request");
                assert_eq!(request, b"PING");
                stream.write_all(b"PONG").expect("write response");
            }
        });
        let gateway = Gateway::new(
            FixtureScope,
            FixtureLease,
            FixtureCompiler,
            TcpTargetTransport::new(),
            FixedClock::new(),
        );
        let first = handle(&gateway, request(target));
        let second = handle(&gateway, request(target));
        server.join().expect("loopback server");
        assert_eq!(first, second);
        let GatewayResponse::Receipt { receipt, .. } = first else {
            panic!("expected a dispatch receipt");
        };
        assert_eq!(receipt.outcome, DispatchOutcome::Completed);
        assert_eq!(receipt.request_digest, Digest::of(b"PING"));
        assert_eq!(receipt.response_digest, Some(Digest::of(b"PONG")));
        assert_eq!((receipt.bytes_sent, receipt.bytes_received), (4, 4));
        assert!(!receipt.reconciliation_required);
    }

    struct UnknownTransport(Arc<AtomicUsize>);

    impl TargetTransport for UnknownTransport {
        fn dispatch(&self, _action: &CompiledAction) -> TransportObservation {
            self.0.fetch_add(1, Ordering::SeqCst);
            TransportObservation {
                outcome: DispatchOutcome::UnknownOutcome,
                bytes_sent: 4,
                response: Vec::new(),
            }
        }
    }

    #[test]
    fn unknown_outcome_is_not_retried_and_requires_reconciliation() {
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            FixtureScope,
            FixtureLease,
            FixtureCompiler,
            UnknownTransport(dispatches.clone()),
            FixedClock::new(),
        );
        let response = handle(&gateway, request("127.0.0.1:9".parse().expect("address")));
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
        let GatewayResponse::Receipt { receipt, .. } = response else {
            panic!("expected a dispatch receipt");
        };
        assert_eq!(receipt.outcome, DispatchOutcome::UnknownOutcome);
        assert!(receipt.reconciliation_required);
        assert_eq!(receipt.response_digest, None);
    }

    struct MismatchedScope;

    impl ScopeVerifier for MismatchedScope {
        fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
            let mut approval = ScopeApproval::fixture(request);
            approval.scope_epoch += 1;
            Ok(approval)
        }
    }

    struct PanicTransport;

    impl TargetTransport for PanicTransport {
        fn dispatch(&self, _action: &CompiledAction) -> TransportObservation {
            panic!("binding mismatch reached target transport");
        }
    }

    #[test]
    fn verifier_output_must_remain_bound_to_the_request() {
        let gateway = Gateway::new(
            MismatchedScope,
            FixtureLease,
            FixtureCompiler,
            PanicTransport,
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, request("127.0.0.1:9".parse().expect("address")),),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::VerificationBindingMismatch,
                ..
            })
        ));
    }

    #[test]
    fn invalid_scope_and_lease_proofs_never_reach_transport() {
        let target = "127.0.0.1:9".parse().expect("address");
        let mut invalid_scope = request(target);
        invalid_scope.scope_proof = b"forged".to_vec();
        let gateway = Gateway::new(
            FixtureScope,
            FixtureLease,
            FixtureCompiler,
            PanicTransport,
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, invalid_scope),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::ScopeDenied,
                ..
            })
        ));

        let mut invalid_lease = request(target);
        invalid_lease.lease_proof = b"forged".to_vec();
        assert!(matches!(
            handle(&gateway, invalid_lease),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::LeaseDenied,
                ..
            })
        ));
    }

    #[test]
    fn absent_semantic_compiler_never_reaches_transport() {
        let gateway = Gateway::new(
            FixtureScope,
            FixtureLease,
            UnavailableActionCompiler,
            PanicTransport,
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, request("127.0.0.1:9".parse().expect("address")),),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::CompilerUnavailable,
                ..
            })
        ));
    }
}
