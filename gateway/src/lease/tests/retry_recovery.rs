    #[test]
    fn failed_resolution_authorizes_only_one_exact_retry_and_recovery_preserves_consumption() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let parent = spec("lease:retry-parent", b"intent:retry-parent");
        let receipt = authenticated_unknown_receipt(&authority, &parent);
        let failed = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Failed,
                Digest::of(b"failed parent terminal evidence"),
                *b"retry-proof-0001",
                NOW + 2,
            )
            .expect("failed parent reconciliation");
        authority
            .reconcile(&receipt, &failed)
            .expect("store failed parent resolution");

        let (cross_effect, mut cross_effect_request) = retry_candidate(
            &parent,
            ("lease:retry-cross-effect", b"intent:retry-cross-effect"),
            |request| request.payload = b"PONG".to_vec(),
        );
        cross_effect_request.lease_proof = authority
            .issue(cross_effect)
            .expect("admit pending cross-effect candidate")
            .proof;
        assert_eq!(
            authority.reserve(&cross_effect_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid)
        );

        let (cross_tenant, mut cross_tenant_request) = retry_candidate(
            &parent,
            ("lease:retry-cross-tenant", b"intent:retry-cross-tenant"),
            |request| request.tenant_id = Some("tenant:other".to_owned()),
        );
        cross_tenant_request.lease_proof = authority
            .issue(cross_tenant)
            .expect("admit pending cross-tenant candidate")
            .proof;
        assert_eq!(
            authority.reserve(&cross_tenant_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid)
        );

        let (cross_target, mut cross_target_request) = retry_candidate(
            &parent,
            ("lease:retry-cross-target", b"intent:retry-cross-target"),
            |request| {
                request.target_id = "target:other-loopback".to_owned();
                request.hostname = "other.localhost".to_owned();
                request.target = "127.0.0.1:8081".parse().expect("alternate address");
            },
        );
        cross_target_request.lease_proof = authority
            .issue(cross_target)
            .expect("admit pending cross-target candidate")
            .proof;
        assert_eq!(
            authority.reserve(&cross_target_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid)
        );

        let (first, mut first_request) = retry_candidate(
            &parent,
            ("lease:retry-exact-a", b"intent:retry-exact-a"),
            |request| {
                request.action_id = "action:retry-exact-a".to_owned();
                request.correlation_id = "correlation:retry-exact-a".to_owned();
                request.request_issued_at_millis = NOW;
                request.request_expires_at_millis = NOW + 4_000;
            },
        );
        first_request.lease_proof = authority
            .issue(first)
            .expect("admit first exact pending retry")
            .proof;
        let (second, mut second_request) = retry_candidate(
            &parent,
            ("lease:retry-exact-b", b"intent:retry-exact-b"),
            |request| {
                request.action_id = "action:retry-exact-b".to_owned();
                request.correlation_id = "correlation:retry-exact-b".to_owned();
                request.request_issued_at_millis = NOW + 1;
                request.request_expires_at_millis = NOW + 4_001;
            },
        );
        second_request.lease_proof = authority
            .issue(second)
            .expect("admit second exact pending retry")
            .proof;

        let first_approval = authority
            .reserve(&first_request, NOW + 3)
            .expect("first exact retry atomically consumes authorization");
        authority
            .abandon(&first_approval)
            .expect("release exact retry reservation");
        assert_eq!(
            authority.reserve(&second_request, NOW + 3),
            Err(DenialCode::RetryAliasInvalid),
            "a failed parent authorizes at most one exact retry"
        );

        let checkpoint = authority
            .checkpoint()
            .expect("checkpoint consumed retry parent");
        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:retry-restored".to_owned(),
            Digest::of(b"retry restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("fresh retry restore authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore consumed retry authorization");
        let (mut after_restart, _) = retry_candidate(
            &parent,
            ("lease:retry-after-restart", b"intent:retry-after-restart"),
            |_| {},
        );
        after_restart.gateway_boot_id = "gateway:boot:retry-restored".to_owned();
        seal_spec(&mut after_restart);
        assert_eq!(
            restored.issue(after_restart),
            Err(DenialCode::RetryAliasInvalid),
            "retry consumption survives recovery"
        );
    }

    #[test]
    fn response_or_duration_overrun_forces_reconciliation() {
        let authority = authority(budget());
        let lease = spec("lease:overrun", b"intent:overrun");
        let proof = authority.issue(lease.clone()).expect("issue").proof;
        let approval = authority
            .reserve(&request(&lease, proof), NOW)
            .expect("reserve");
        let finalization = authority
            .finalize(
                &approval,
                LeaseCompletion {
                    outcome: DispatchOutcome::Completed,
                    bytes_sent: 4,
                    bytes_received: 9,
                    elapsed_millis: 50,
                },
            )
            .expect("finalize");
        assert!(finalization.reservation_overrun);
        assert!(finalization.reconciliation_required);
    }
