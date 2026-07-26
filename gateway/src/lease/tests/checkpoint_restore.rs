    #[test]
    fn sealed_checkpoint_preserves_budget_replay_and_unknown_outcome_across_boots() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        let source = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:source".to_owned(),
            Digest::of(b"source challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("source authority");
        source
            .register_grant("grant:1", 3, limits.clone())
            .expect("source grant");
        let mut active = spec("lease:crash-active", b"intent:crash-active");
        active.gateway_boot_id = "gateway:boot:source".to_owned();
        seal_spec(&mut active);
        let proof = source.issue(active.clone()).expect("issue active").proof;
        source
            .reserve(&request(&active, proof.clone()), NOW)
            .expect("reserve active before crash");
        let mut available = spec("lease:crash-available", b"intent:crash-available");
        available.gateway_boot_id = "gateway:boot:source".to_owned();
        seal_spec(&mut available);
        source.issue(available.clone()).expect("issue available");
        let checkpoint = source.checkpoint().expect("sealed checkpoint");

        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:restored".to_owned(),
            Digest::of(b"restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("fresh authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore checkpoint");
        let usage = restored.usage("grant:1", 3).expect("restored usage");
        assert_eq!(usage.dispatched_actions, 1);
        assert_eq!(usage.active_dispatches, 0);
        assert_eq!(
            restored.reserve(&request(&active, proof), NOW + 1),
            Err(DenialCode::LeaseDenied)
        );

        let mut retry = spec("lease:crash-retry", b"intent:crash-active");
        retry.gateway_boot_id = "gateway:boot:restored".to_owned();
        seal_spec(&mut retry);
        assert_eq!(
            restored.issue(retry),
            Err(DenialCode::LeaseReconciliationRequired),
            "a recovered exact-effect hold preserves reconciliation precedence"
        );
        let reconciler = ReconciliationAuthority::new(
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("reconciliation signer");
        let wrong_effect = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: Digest::of(b"wrong crash effect"),
                    hold_binding_digest: active
                        .hold_binding_digest("lease-key:test", Digest::of(b"source challenge")),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"wrong-effect terminal evidence"),
                    nonce: *b"wrong-effect-001",
                    resolved_at_millis: NOW + 2,
                },
            )
            .expect("authenticated wrong-effect proof");
        assert_eq!(
            restored.reconcile_control_plane_hold(&wrong_effect),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        let wrong_binding = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: active.effect_digest,
                    hold_binding_digest: Digest::of(b"wrong exact crash hold binding"),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"wrong-binding terminal evidence"),
                    nonce: *b"wrong-binding001",
                    resolved_at_millis: NOW + 2,
                },
            )
            .expect("authenticated wrong-binding proof");
        assert_eq!(
            restored.reconcile_control_plane_hold(&wrong_binding),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        let reconciliation = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: active.effect_digest,
                    hold_binding_digest: active
                        .hold_binding_digest("lease-key:test", Digest::of(b"source challenge")),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"crash terminal evidence"),
                    nonce: *b"crash-proof-0001",
                    resolved_at_millis: NOW + 2,
                },
            )
            .expect("crash reconciliation proof");
        restored
            .reconcile_control_plane_hold(&reconciliation)
            .expect("reconcile crash uncertainty");

        let mut next = spec("lease:after-crash", b"intent:after-crash");
        next.gateway_boot_id = "gateway:boot:restored".to_owned();
        seal_spec(&mut next);
        let next_proof = restored
            .issue(next.clone())
            .expect("post-crash issue")
            .proof;
        assert!(
            restored
                .reserve(&request(&next, next_proof), NOW + 2)
                .is_ok()
        );
        let mut replayed_available = available;
        replayed_available.gateway_boot_id = "gateway:boot:restored".to_owned();
        seal_spec(&mut replayed_available);
        assert_eq!(
            restored.issue(replayed_available),
            Err(DenialCode::LeaseReplay)
        );
    }

    #[test]
    fn completed_intent_cannot_be_reissued_with_fresh_coordinates_after_restore() {
        // Given: a completed intent under a grant that still has action budget.
        let mut limits = budget();
        limits.total_actions = 2;
        let source = authority_for_boot(
            limits,
            "gateway:boot:retired-source",
            b"retired source challenge",
        );
        let mut completed = spec("lease:retired-original", b"intent:retired-terminal");
        completed.gateway_boot_id = "gateway:boot:retired-source".to_owned();
        seal_spec(&mut completed);
        let proof = source
            .issue(completed.clone())
            .expect("issue original intent")
            .proof;
        let approval = source
            .reserve(&request(&completed, proof), NOW)
            .expect("reserve original intent");
        source
            .finalize(&approval, completion(DispatchOutcome::Completed))
            .expect("acknowledge completed intent");
        assert_eq!(
            source
                .usage(&completed.grant_id, completed.grant_version)
                .expect("completed usage")
                .dispatched_actions,
            1
        );
        let checkpoint = source.checkpoint().expect("checkpoint completed intent");
        let restored = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:retired-restored".to_owned(),
            Digest::of(b"retired restored challenge"),
        )
        .expect("fresh restore authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore completed intent");

        // When: the new boot issues the same semantic intent with fresh coordinates.
        let mut replay = spec("lease:retired-replay", b"intent:retired-terminal");
        replay.gateway_boot_id = "gateway:boot:retired-restored".to_owned();
        seal_spec(&mut replay);
        assert_ne!(replay.lease_id, completed.lease_id);
        assert_ne!(replay.dispatch_nonce, completed.dispatch_nonce);

        // Then: semantic retirement, rather than exhausted budget, rejects it.
        assert_eq!(
            restored.issue(replay),
            Err(DenialCode::LeaseBindingMismatch)
        );
        let mut distinct = spec("lease:retired-distinct", b"intent:retired-distinct");
        distinct.gateway_boot_id = "gateway:boot:retired-restored".to_owned();
        seal_spec(&mut distinct);
        let distinct_proof = restored
            .issue(distinct.clone())
            .expect("remaining budget admits a distinct intent")
            .proof;
        assert!(
            restored
                .reserve(&request(&distinct, distinct_proof), NOW + 1)
                .is_ok()
        );
    }
