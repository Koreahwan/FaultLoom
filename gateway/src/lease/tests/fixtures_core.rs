    fn lease_key() -> [u8; 32] {
        std::array::from_fn(|index| u8::try_from(index + 1).expect("small key byte"))
    }

    fn budget() -> GrantBudget {
        GrantBudget {
            total_actions: 3,
            rate_per_minute: 2,
            max_concurrency: 1,
            max_request_bytes: 64,
            max_response_bytes: 128,
            max_duration_seconds: 5,
        }
    }

    fn authority(budget: GrantBudget) -> LeaseAuthority {
        authority_for_boot(budget, "gateway:boot:test", b"gateway challenge:test")
    }

    fn authority_for_boot(budget: GrantBudget, boot_id: &str, challenge: &[u8]) -> LeaseAuthority {
        let authority = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            boot_id.to_owned(),
            Digest::of(challenge),
        )
        .expect("valid key");
        authority
            .register_grant("grant:1", 3, budget)
            .expect("register grant");
        authority
    }

    fn spec(lease_id: &str, intent: &[u8]) -> LeaseSpec {
        let nonce_digest = Digest::of(lease_id.as_bytes());
        let mut dispatch_nonce = [0_u8; 16];
        dispatch_nonce.copy_from_slice(&nonce_digest.as_bytes()[..16]);
        let mut spec = LeaseSpec {
            lease_id: lease_id.to_owned(),
            intent_digest: Digest::of(intent),
            decision_digest: Digest::of(format!("decision:{lease_id}").as_bytes()),
            grant_id: "grant:1".to_owned(),
            grant_version: 3,
            scope_epoch: 7,
            authority_key_id: "authority-key:test".to_owned(),
            scope_epoch_binding_digest: Digest::of(b"scope epoch binding:test"),
            gateway_boot_id: "gateway:boot:test".to_owned(),
            control_envelope_id: Digest::of(format!("control-envelope:{lease_id}").as_bytes()),
            request_binding_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            resolution_digest: Digest::ZERO,
            compiled_request_digest: Digest::ZERO,
            effect_digest: Digest::ZERO,
            correlation_id: "correlation:1".to_owned(),
            egress_plane: EgressPlane::TargetGateway,
            dispatch_nonce,
            retry_of_intent_digest: None,
            issued_at_millis: NOW - 1,
            expires_at_millis: NOW + 5_000,
            reservation: LeaseBudgetReservation {
                action_count: 1,
                request_bytes: 4,
                response_bytes: 8,
                duration_seconds: 2,
            },
        };
        seal_spec(&mut spec);
        spec
    }

    fn seal_spec(spec: &mut LeaseSpec) {
        let bound = request(spec, vec![1]);
        spec.request_binding_digest = bound.lease_binding_digest();
        spec.semantic_action_digest = bound.semantic_action_digest;
        spec.resolution_digest = bound.resolution_digest;
        spec.compiled_request_digest = Digest::of(&bound.payload);
        spec.effect_digest = crate::policy::target_effect_digest(
            bound.action_kind,
            bound.egress_plane,
            bound.resolution_digest,
            Digest::of(&bound.payload),
        );
    }

    fn request(spec: &LeaseSpec, proof: Vec<u8>) -> DispatchRequest {
        let mut request = DispatchRequest {
            action_id: "action:1".to_owned(),
            correlation_id: "correlation:1".to_owned(),
            target_id: "target:loopback".to_owned(),
            grant_id: spec.grant_id.clone(),
            grant_version: spec.grant_version,
            pack_id: "web".to_owned(),
            action_family: "http.semantic".to_owned(),
            identity_id: "identity:operator".to_owned(),
            tenant_id: Some("tenant:owned".to_owned()),
            intent_digest: spec.intent_digest,
            decision_digest: spec.decision_digest,
            lease_id: spec.lease_id.clone(),
            scope_epoch: spec.scope_epoch,
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
            target: "127.0.0.1:8080".parse().expect("address"),
            resolution_digest: Digest::ZERO,
            semantic_action_digest: Digest::ZERO,
            dispatch_nonce: spec.dispatch_nonce,
            request_issued_at_millis: spec.issued_at_millis,
            request_expires_at_millis: spec.expires_at_millis,
            retry_of_intent_digest: spec.retry_of_intent_digest,
            payload: b"PING".to_vec(),
            scope_proof: b"scope-proof".to_vec(),
            lease_proof: proof,
            compiler_proof: b"compiler-proof".to_vec(),
            canary_ref: None,
            checkpoint_ref: None,
            cleanup_plan_ref: None,
        };
        request.bind_canonical_semantics();
        request
    }

    fn spec_for_request(request: &DispatchRequest) -> LeaseSpec {
        LeaseSpec {
            lease_id: request.lease_id.clone(),
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            scope_epoch: request.scope_epoch,
            authority_key_id: "authority-key:test".to_owned(),
            scope_epoch_binding_digest: Digest::of(b"scope epoch binding:test"),
            gateway_boot_id: "gateway:boot:test".to_owned(),
            control_envelope_id: Digest::of(b"control-envelope:request-fixture"),
            request_binding_digest: request.lease_binding_digest(),
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            compiled_request_digest: Digest::of(&request.payload),
            effect_digest: crate::policy::target_effect_digest(
                request.action_kind,
                request.egress_plane,
                request.resolution_digest,
                Digest::of(&request.payload),
            ),
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

    fn retry_candidate(
        parent: &LeaseSpec,
        coordinates: (&str, &[u8]),
        mutate: impl FnOnce(&mut DispatchRequest),
    ) -> (LeaseSpec, DispatchRequest) {
        let (lease_id, intent) = coordinates;
        let mut seed = spec(lease_id, intent);
        seed.decision_digest = parent.decision_digest;
        seed.grant_id.clone_from(&parent.grant_id);
        seed.grant_version = parent.grant_version;
        seed.scope_epoch = parent.scope_epoch;
        seed.authority_key_id.clone_from(&parent.authority_key_id);
        seed.scope_epoch_binding_digest = parent.scope_epoch_binding_digest;
        seed.gateway_boot_id.clone_from(&parent.gateway_boot_id);
        seed.retry_of_intent_digest = Some(parent.intent_digest);
        seal_spec(&mut seed);
        let mut candidate = request(&seed, vec![1]);
        mutate(&mut candidate);
        candidate.bind_canonical_semantics();
        let mut lease = spec_for_request(&candidate);
        lease.control_envelope_id =
            Digest::of(format!("retry-control-envelope:{lease_id}").as_bytes());
        (lease, candidate)
    }
