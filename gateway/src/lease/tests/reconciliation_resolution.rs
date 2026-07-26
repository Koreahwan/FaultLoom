    #[test]
    fn completed_resolution_is_monotonic_and_checkpoint_remains_restorable() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:monotonic-resolution", b"intent:monotonic-resolution");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let completed = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"completed terminal evidence"),
                *b"completed-proof1",
                NOW + 2,
            )
            .expect("completed reconciliation");
        authority
            .reconcile(&receipt, &completed)
            .expect("store completed resolution");
        let failed = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Failed,
                Digest::of(b"later contradictory evidence"),
                *b"failed-proof-001",
                NOW + 3,
            )
            .expect("well-formed contradictory reconciliation");
        assert_eq!(
            authority.reconcile(&receipt, &failed),
            Err(DenialCode::LeaseReplay),
            "a terminal resolution cannot be overwritten"
        );

        let checkpoint = authority
            .checkpoint()
            .expect("checkpoint monotonic resolution");
        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:monotonic-restored".to_owned(),
            Digest::of(b"monotonic restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("fresh restore authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("every emitted checkpoint must restore");
        let state = restored.state.lock().expect("inspect restored resolution");
        let resolution = state
            .reconciliation_receipts
            .get(&ReconciliationKey::from_spec(&lease))
            .expect("restored resolution");
        assert_eq!(resolution.terminal_outcome, DispatchOutcome::Completed);
        assert!(!resolution.retry_consumed);
    }

    #[test]
    fn reconciliation_grant_binding_cannot_be_recomputed_without_the_control_plane_key() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        authority
            .register_grant("grant:2", 9, budget())
            .expect("register unrelated grant");
        let lease = spec("lease:grant-bound-proof", b"intent:grant-bound-proof");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let valid = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"grant-bound terminal evidence"),
                *b"grant-proof-0001",
                NOW + 2,
            )
            .expect("issue grant-bound reconciliation proof");

        let mut forged_grant = valid.clone();
        forged_grant.grant_id = "grant:2".to_owned();
        forged_grant.grant_version = 9;
        forged_grant.reconciliation_id = forged_grant.canonical_id();
        forged_grant.authentication_tag = forged_grant.reconciliation_id;
        assert_eq!(
            authority.reconcile(&receipt, &forged_grant),
            Err(DenialCode::LeaseReconciliationRequired)
        );

        let mut forged_version = valid.clone();
        forged_version.grant_version = lease.grant_version + 1;
        forged_version.reconciliation_id = forged_version.canonical_id();
        forged_version.authentication_tag = forged_version.reconciliation_id;
        assert_eq!(
            authority.reconcile(&receipt, &forged_version),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Ok(None),
            "forged grant bindings must leave the exact hold intact"
        );
        authority
            .reconcile(&receipt, &valid)
            .expect("unaltered authenticated proof still reconciles the exact hold");
    }

    #[test]
    fn concurrent_reconciliation_reuse_has_one_winner_and_one_replay() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:concurrent-reconcile", b"intent:concurrent-reconcile");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let reconciliation = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"concurrent terminal evidence"),
                *b"concurrent-proof",
                NOW + 2,
            )
            .expect("issue reusable reconciliation candidate");
        let authority = Arc::new(authority);
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let receipt = receipt.clone();
                let reconciliation = reconciliation.clone();
                thread::spawn(move || {
                    barrier.wait();
                    authority.reconcile(&receipt, &reconciliation)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("reconciliation thread"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DenialCode::LeaseReplay)))
                .count(),
            1
        );
    }

    #[test]
    fn control_plane_proof_cannot_bypass_dispatch_receipt_binding() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:receipt-bound-hold", b"intent:receipt-bound-hold");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let bypass = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: lease.grant_id.clone(),
                    grant_version: lease.grant_version,
                    intent_digest: lease.intent_digest,
                    effect_digest: lease.effect_digest,
                    hold_binding_digest: receipt.hold_binding_digest,
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Completed,
                    evidence_digest: Digest::of(b"unbound terminal evidence"),
                    nonce: *b"bypass-proof-001",
                    resolved_at_millis: NOW + 2,
                },
            )
            .expect("well-formed but unbound proof");

        assert_eq!(
            authority.reconcile_control_plane_hold(&bypass),
            Err(DenialCode::LeaseReconciliationRequired)
        );
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Ok(None)
        );

        let checkpoint = authority.checkpoint().expect("typed hold checkpoint");
        let restored = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:restored".to_owned(),
            Digest::of(b"restored challenge"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("restored authority");
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore typed hold");
        assert_eq!(
            restored.reconcile_control_plane_hold(&bypass),
            Err(DenialCode::LeaseReconciliationRequired)
        );

        let exact = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"bound terminal evidence"),
                *b"exact-proof-0001",
                NOW + 3,
            )
            .expect("receipt-bound proof");
        restored
            .reconcile(&receipt, &exact)
            .expect("typed receipt hold survives recovery");
    }
