use std::time::{SystemTime, UNIX_EPOCH};

use crate::Digest;
use crate::ipc::{
    DenialCode, DeniedResponse, DispatchOutcome, DispatchReceipt, DispatchRequest, GatewayResponse,
    encode_request,
};
use crate::policy::{ActionCompiler, LeaseApproval, LeaseCompletion, LeaseVerifier, ScopeVerifier};
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
        let canonical_frame_digest = match encode_request(&request) {
            Ok(frame) => Digest::of(&frame),
            Err(reason) => return denied(&request, request_frame_digest, reason),
        };
        if canonical_frame_digest != request_frame_digest {
            return denied(
                &request,
                canonical_frame_digest,
                DenialCode::VerificationBindingMismatch,
            );
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
        let reserved_at_millis = self.clock.now_millis();
        let lease = match self.lease.reserve(&request, reserved_at_millis) {
            Ok(approval) => approval,
            Err(reason) => return denied(&request, request_frame_digest, reason),
        };
        if lease.intent_digest != request.intent_digest
            || lease.decision_digest != request.decision_digest
            || lease.grant_id != request.grant_id
            || lease.grant_version != request.grant_version
            || lease.lease_id != request.lease_id
            || lease.scope_epoch != request.scope_epoch
            || lease.authority_key_id != scope.authority_key_id
            || lease.scope_epoch_binding_digest != scope.scope_epoch_binding_digest
            || lease.gateway_boot_id != scope.gateway_boot_id
            || lease.boot_challenge_digest == Digest::ZERO
            || lease.request_binding_digest != request.lease_binding_digest()
            || lease.semantic_action_digest != request.semantic_action_digest
            || lease.resolution_digest != request.resolution_digest
            || lease.correlation_id != request.correlation_id
            || lease.egress_plane != request.egress_plane
            || lease.dispatch_nonce != request.dispatch_nonce
            || lease.issued_at_millis != request.request_issued_at_millis
            || lease.expires_at_millis != request.request_expires_at_millis
            || lease.retry_of_intent_digest != request.retry_of_intent_digest
            || lease.maximum_dispatches != 1
            || lease.reservation.action_count != 1
        {
            return self.abandon_then_deny(
                &request,
                request_frame_digest,
                &lease,
                DenialCode::VerificationBindingMismatch,
            );
        }
        let compiled = match self.compiler.compile(&request) {
            Ok(compiled) => compiled,
            Err(reason) => {
                return self.abandon_then_deny(&request, request_frame_digest, &lease, reason);
            }
        };
        if compiled.intent_digest != request.intent_digest
            || compiled.action_kind != request.action_kind
            || compiled.target != scope.target
            || compiled.egress_plane != request.egress_plane
            || compiled.semantic_action_digest != request.semantic_action_digest
            || compiled.resolution_digest != request.resolution_digest
            || compiled.request_binding_digest != request.lease_binding_digest()
            || compiled.bytes.is_empty()
        {
            return self.abandon_then_deny(
                &request,
                request_frame_digest,
                &lease,
                DenialCode::VerificationBindingMismatch,
            );
        }
        if !u64::try_from(compiled.bytes.len())
            .is_ok_and(|length| length <= lease.reservation.request_bytes)
        {
            return self.abandon_then_deny(
                &request,
                request_frame_digest,
                &lease,
                DenialCode::LeaseReservationExceeded,
            );
        }
        if let Err(reason) = self.scope.register_dispatch(&request, &lease) {
            return self.abandon_then_deny(&request, request_frame_digest, &lease, reason);
        }

        let dispatched_at_millis = self.clock.now_millis();
        let mut observation = self
            .transport
            .dispatch_cancellable(&compiled, &lease.cancellation);
        let completed_at_millis = self.clock.now_millis().max(dispatched_at_millis);
        if self.scope.finish_dispatch(&lease).is_err() {
            observation.outcome = DispatchOutcome::UnknownOutcome;
        }
        let bytes_received = u64::try_from(observation.response.len()).unwrap_or(u64::MAX);
        let finalization = self.lease.finalize(
            &lease,
            LeaseCompletion {
                outcome: observation.outcome,
                bytes_sent: observation.bytes_sent,
                bytes_received,
                elapsed_millis: completed_at_millis.saturating_sub(dispatched_at_millis),
            },
        );
        if finalization.as_ref().map_or(true, |result| {
            result.reconciliation_required || result.reservation_overrun
        }) {
            observation.outcome = DispatchOutcome::UnknownOutcome;
        }
        let mut receipt = make_receipt(
            &request,
            request_frame_digest,
            &scope,
            &lease,
            &compiled.bytes,
            observation,
            (dispatched_at_millis, completed_at_millis),
        );
        receipt.receipt_authentication_tag = match self.lease.authenticate_receipt(&lease, &receipt)
        {
            Ok(authentication_tag) => authentication_tag,
            Err(reason) => return denied(&request, request_frame_digest, reason),
        };
        GatewayResponse::Receipt {
            action_id: request.action_id,
            receipt,
        }
    }

    fn abandon_then_deny(
        &self,
        request: &DispatchRequest,
        request_frame_digest: Digest,
        approval: &LeaseApproval,
        reason: DenialCode,
    ) -> GatewayResponse {
        let final_reason = self.lease.abandon(approval).err().unwrap_or(reason);
        denied(request, request_frame_digest, final_reason)
    }
}

fn denied(
    request: &DispatchRequest,
    request_frame_digest: Digest,
    reason: DenialCode,
) -> GatewayResponse {
    GatewayResponse::Denied(DeniedResponse::bound(
        request.action_id.clone(),
        request_frame_digest,
        reason,
    ))
}

fn make_receipt(
    request: &DispatchRequest,
    request_frame_digest: Digest,
    scope: &crate::policy::ScopeApproval,
    lease: &LeaseApproval,
    compiled_bytes: &[u8],
    observation: TransportObservation,
    timing: (u64, u64),
) -> DispatchReceipt {
    let (dispatched_at_millis, completed_at_millis) = timing;
    let request_digest = Digest::of(compiled_bytes);
    let response_digest = match observation.outcome {
        DispatchOutcome::Completed => Some(Digest::of(&observation.response)),
        DispatchOutcome::UnknownOutcome if !observation.response.is_empty() => {
            Some(Digest::of(&observation.response))
        }
        DispatchOutcome::Failed | DispatchOutcome::UnknownOutcome => None,
    };
    let bytes_received = u64::try_from(observation.response.len()).unwrap_or(u64::MAX);
    let reconciliation_required = observation.outcome == DispatchOutcome::UnknownOutcome;
    let mut receipt = DispatchReceipt {
        receipt_id: Digest::ZERO,
        receipt_authentication_tag: Digest::ZERO,
        action_id: request.action_id.clone(),
        correlation_id: request.correlation_id.clone(),
        lease_id: request.lease_id.clone(),
        grant_id: request.grant_id.clone(),
        grant_version: request.grant_version,
        authority_key_id: scope.authority_key_id.clone(),
        scope_epoch_binding_digest: scope.scope_epoch_binding_digest,
        lease_key_id: lease.lease_key_id.clone(),
        gateway_boot_id: scope.gateway_boot_id.clone(),
        boot_challenge_digest: lease.boot_challenge_digest,
        intent_digest: request.intent_digest,
        decision_digest: request.decision_digest,
        scope_epoch: request.scope_epoch,
        semantic_action_digest: request.semantic_action_digest,
        request_binding_digest: request.lease_binding_digest(),
        request_frame_digest,
        resolution_digest: request.resolution_digest,
        egress_plane: request.egress_plane,
        dispatch_nonce: request.dispatch_nonce,
        lease_issued_at_millis: lease.issued_at_millis,
        lease_expires_at_millis: lease.expires_at_millis,
        retry_of_intent_digest: lease.retry_of_intent_digest,
        reserved_action_count: lease.reservation.action_count,
        reserved_request_bytes: lease.reservation.request_bytes,
        reserved_response_bytes: lease.reservation.response_bytes,
        reserved_duration_seconds: lease.reservation.duration_seconds,
        request_digest,
        response_digest,
        outcome: observation.outcome,
        dispatched_at_millis,
        completed_at_millis,
        bytes_sent: observation.bytes_sent,
        bytes_received,
        reconciliation_required,
    };
    receipt.receipt_id = receipt.canonical_id();
    receipt
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::*;
    use crate::ipc::{
        ActionClass, ActionKind, EgressPlane, FlowKind, RequiredFeature, encode_request,
    };
    use crate::lease::{GrantBudget, LeaseAuthority, LeaseBudgetReservation, LeaseSpec};
    use crate::policy::{
        CompiledAction, LeaseApproval, LeaseFinalization, ScopeApproval, UnavailableActionCompiler,
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

        fn register_dispatch(
            &self,
            _request: &DispatchRequest,
            _approval: &LeaseApproval,
        ) -> Result<(), DenialCode> {
            Ok(())
        }

        fn finish_dispatch(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
            Ok(())
        }
    }

    struct FixtureLease;

    impl LeaseVerifier for FixtureLease {
        fn reserve(
            &self,
            request: &DispatchRequest,
            _now_millis: u64,
        ) -> Result<LeaseApproval, DenialCode> {
            if request.lease_proof != b"fixture-lease-proof" {
                return Err(DenialCode::LeaseDenied);
            }
            Ok(LeaseApproval::fixture(request))
        }

        fn abandon(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
            Ok(())
        }

        fn finalize(
            &self,
            _approval: &LeaseApproval,
            completion: LeaseCompletion,
        ) -> Result<LeaseFinalization, DenialCode> {
            Ok(LeaseFinalization {
                reconciliation_required: completion.outcome == DispatchOutcome::UnknownOutcome,
                reservation_overrun: false,
            })
        }

        fn authenticate_receipt(
            &self,
            _approval: &LeaseApproval,
            receipt: &DispatchReceipt,
        ) -> Result<Digest, DenialCode> {
            if receipt.receipt_id != receipt.canonical_id() {
                return Err(DenialCode::LeaseBindingMismatch);
            }
            Ok(Digest::of(b"fixture receipt authentication"))
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
    struct FixedClock;

    impl FixedClock {
        const fn new() -> Self {
            Self
        }
    }

    impl Clock for FixedClock {
        fn now_millis(&self) -> u64 {
            1_000
        }
    }

    fn request(target: std::net::SocketAddr) -> DispatchRequest {
        let mut request = DispatchRequest {
            action_id: "action:loopback".to_owned(),
            correlation_id: "correlation:loopback".to_owned(),
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
            egress_plane: EgressPlane::TargetGateway,
            flow_kind: FlowKind::TopLevel,
            parent_action_id: None,
            required_features: vec![RequiredFeature::GatewayDispatchV1],
            hostname: "localhost".to_owned(),
            protocol: "http".to_owned(),
            method: "GET".to_owned(),
            path: "/".to_owned(),
            target,
            resolution_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            dispatch_nonce: *b"0123456789abcdef",
            request_issued_at_millis: 999,
            request_expires_at_millis: 6_000,
            retry_of_intent_digest: None,
            payload: b"PING".to_vec(),
            scope_proof: b"fixture-scope-proof".to_vec(),
            lease_proof: b"fixture-lease-proof".to_vec(),
            compiler_proof: b"fixture-compiler-proof".to_vec(),
            canary_ref: None,
            checkpoint_ref: None,
            cleanup_plan_ref: None,
        };
        request.bind_canonical_semantics();
        request
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

    #[derive(Clone)]
    struct RecordingTransport {
        dispatches: Arc<AtomicUsize>,
        outcome: DispatchOutcome,
        response: Vec<u8>,
    }

    impl TargetTransport for RecordingTransport {
        fn dispatch(&self, action: &CompiledAction) -> TransportObservation {
            self.dispatches.fetch_add(1, Ordering::SeqCst);
            TransportObservation {
                outcome: self.outcome,
                bytes_sent: action.bytes.len() as u64,
                response: self.response.clone(),
            }
        }
    }

    fn lease_authority() -> LeaseAuthority {
        let authority = LeaseAuthority::new(
            "lease-key:fixture".to_owned(),
            std::array::from_fn(|index| u8::try_from(index + 17).expect("small fixture key byte")),
            "gateway:boot:fixture".to_owned(),
            Digest::of(b"fixture-gateway-challenge"),
        )
        .expect("lease authority");
        authority
            .register_grant(
                "grant:fixture",
                1,
                GrantBudget {
                    total_actions: 10,
                    rate_per_minute: 10,
                    max_concurrency: 2,
                    max_request_bytes: 64,
                    max_response_bytes: 64,
                    max_duration_seconds: 5,
                },
            )
            .expect("register grant");
        authority
    }

    fn issue_request(authority: &LeaseAuthority, request: &mut DispatchRequest) {
        let spec = lease_spec(request);
        let issued = authority.issue(spec).expect("issue request lease");
        request.lease_proof = issued.proof;
    }

    fn lease_spec(request: &DispatchRequest) -> LeaseSpec {
        LeaseSpec {
            lease_id: request.lease_id.clone(),
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            scope_epoch: request.scope_epoch,
            authority_key_id: format!("ed25519:sha256:{}", "11".repeat(32)),
            scope_epoch_binding_digest: Digest::of(b"fixture-scope-epoch-binding"),
            gateway_boot_id: "gateway:boot:fixture".to_owned(),
            request_binding_digest: request.lease_binding_digest(),
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            correlation_id: request.correlation_id.clone(),
            egress_plane: request.egress_plane,
            dispatch_nonce: request.dispatch_nonce,
            retry_of_intent_digest: request.retry_of_intent_digest,
            issued_at_millis: request.request_issued_at_millis,
            expires_at_millis: request.request_expires_at_millis,
            reservation: LeaseBudgetReservation {
                action_count: 1,
                request_bytes: request.payload.len() as u64,
                response_bytes: 8,
                duration_seconds: 2,
            },
        }
    }

    #[test]
    fn authenticated_lease_replay_never_reaches_mock_transport() {
        let authority = lease_authority();
        let mut request = request("127.0.0.1:9".parse().expect("address"));
        issue_request(&authority, &mut request);
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            FixtureScope,
            authority,
            FixtureCompiler,
            RecordingTransport {
                dispatches: Arc::clone(&dispatches),
                outcome: DispatchOutcome::Completed,
                response: b"PONG".to_vec(),
            },
            FixedClock::new(),
        );

        let first = handle(&gateway, request.clone());
        let GatewayResponse::Receipt { receipt, .. } = &first else {
            panic!("first dispatch must produce a receipt");
        };
        assert_eq!(receipt.receipt_id, receipt.canonical_id());
        let encoded = crate::ipc::encode_response(&first).expect("canonical receipt frame");
        assert_eq!(crate::ipc::decode_response(&encoded), Ok(first));
        assert!(matches!(
            handle(&gateway, request),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::LeaseReplay,
                ..
            })
        ));
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn compiler_failure_consumes_lease_without_target_dispatch() {
        let authority = lease_authority();
        let mut request = request("127.0.0.1:9".parse().expect("address"));
        issue_request(&authority, &mut request);
        request.compiler_proof = b"forged".to_vec();
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            FixtureScope,
            authority,
            FixtureCompiler,
            RecordingTransport {
                dispatches: Arc::clone(&dispatches),
                outcome: DispatchOutcome::Completed,
                response: b"PONG".to_vec(),
            },
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, request.clone()),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::CompilerDenied,
                ..
            })
        ));
        request.compiler_proof = b"fixture-compiler-proof".to_vec();
        assert!(matches!(
            handle(&gateway, request),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::LeaseReplay,
                ..
            })
        ));
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expired_lease_is_denied_before_mock_transport() {
        let authority = lease_authority();
        let mut request = request("127.0.0.1:9".parse().expect("address"));
        request.request_expires_at_millis = 1_000;
        let issued = authority
            .issue(lease_spec(&request))
            .expect("issue expiring lease");
        request.lease_proof = issued.proof;
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            FixtureScope,
            authority,
            FixtureCompiler,
            RecordingTransport {
                dispatches: Arc::clone(&dispatches),
                outcome: DispatchOutcome::Completed,
                response: b"PONG".to_vec(),
            },
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, request),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::LeaseExpired,
                ..
            })
        ));
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unknown_outcome_blocks_a_fresh_lease_for_the_same_intent() {
        let authority = lease_authority();
        let mut first = request("127.0.0.1:9".parse().expect("address"));
        first.lease_id = "lease:unknown-first".to_owned();
        first.decision_digest = Digest::of(b"decision:unknown-first");
        first.bind_canonical_semantics();
        issue_request(&authority, &mut first);
        let mut retry = first.clone();
        retry.action_id = "action:unknown-retry".to_owned();
        retry.lease_id = "lease:unknown-retry".to_owned();
        retry.decision_digest = Digest::of(b"decision:unknown-retry");
        retry.dispatch_nonce = *b"fedcba9876543210";
        retry.bind_canonical_semantics();
        issue_request(&authority, &mut retry);
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            FixtureScope,
            authority,
            FixtureCompiler,
            RecordingTransport {
                dispatches: Arc::clone(&dispatches),
                outcome: DispatchOutcome::UnknownOutcome,
                response: Vec::new(),
            },
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, first),
            GatewayResponse::Receipt {
                receipt: DispatchReceipt {
                    outcome: DispatchOutcome::UnknownOutcome,
                    reconciliation_required: true,
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            handle(&gateway, retry),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::LeaseReconciliationRequired,
                ..
            })
        ));
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    }

    struct MismatchedScope;

    impl ScopeVerifier for MismatchedScope {
        fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
            let mut approval = ScopeApproval::fixture(request);
            approval.scope_epoch += 1;
            Ok(approval)
        }
    }

    struct UncoupledScope;

    impl ScopeVerifier for UncoupledScope {
        fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
            Ok(ScopeApproval::fixture(request))
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
    fn verifier_without_cancellation_registration_cannot_dispatch() {
        let gateway = Gateway::new(
            UncoupledScope,
            FixtureLease,
            FixtureCompiler,
            PanicTransport,
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, request("127.0.0.1:9".parse().expect("address"))),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::ScopeDenied,
                ..
            })
        ));
    }

    struct MismatchedLease;

    impl LeaseVerifier for MismatchedLease {
        fn reserve(
            &self,
            request: &DispatchRequest,
            _now_millis: u64,
        ) -> Result<LeaseApproval, DenialCode> {
            let mut approval = LeaseApproval::fixture(request);
            approval.request_binding_digest = Digest::of(b"substituted request binding");
            Ok(approval)
        }

        fn abandon(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
            Ok(())
        }

        fn finalize(
            &self,
            _approval: &LeaseApproval,
            _completion: LeaseCompletion,
        ) -> Result<LeaseFinalization, DenialCode> {
            panic!("mismatched lease reached finalization")
        }

        fn authenticate_receipt(
            &self,
            _approval: &LeaseApproval,
            _receipt: &DispatchReceipt,
        ) -> Result<Digest, DenialCode> {
            panic!("mismatched lease reached receipt authentication")
        }
    }

    struct MismatchedCompiler;

    impl ActionCompiler for MismatchedCompiler {
        fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
            let mut compiled = CompiledAction::fixture(request);
            compiled.resolution_digest = Digest::of(b"mutable resolver substitution");
            Ok(compiled)
        }
    }

    #[test]
    fn forged_frame_digest_lease_binding_and_resolver_output_never_dispatch() {
        let target = "127.0.0.1:9".parse().expect("address");
        let request = request(target);
        let gateway = Gateway::new(
            FixtureScope,
            FixtureLease,
            FixtureCompiler,
            PanicTransport,
            FixedClock::new(),
        );
        assert!(matches!(
            gateway.handle(request.clone(), Digest::of(b"substituted request frame")),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::VerificationBindingMismatch,
                ..
            })
        ));

        let gateway = Gateway::new(
            FixtureScope,
            MismatchedLease,
            FixtureCompiler,
            PanicTransport,
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, request.clone()),
            GatewayResponse::Denied(DeniedResponse {
                reason: DenialCode::VerificationBindingMismatch,
                ..
            })
        ));

        let gateway = Gateway::new(
            FixtureScope,
            FixtureLease,
            MismatchedCompiler,
            PanicTransport,
            FixedClock::new(),
        );
        assert!(matches!(
            handle(&gateway, request),
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
