    #[test]
    fn poisoned_lease_state_denies_every_authority_operation() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let unknown = spec("lease:poison-unknown", b"intent:poison-unknown");
        let receipt = authenticated_unknown_receipt(&authority, &unknown);
        let reconciliation = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"poison test terminal evidence"),
                *b"poison-proof-001",
                NOW + 2,
            )
            .expect("reconciliation proof before poison");
        let authority = Arc::new(authority);
        let lease = spec("lease:poison", b"intent:poison");
        let proof = authority
            .issue(lease.clone())
            .expect("issue before poison")
            .proof;
        let candidate = request(&lease, proof);

        let poisoner = Arc::clone(&authority);
        assert!(
            thread::spawn(move || {
                let _guard = poisoner.state.lock().expect("lock state before poison");
                panic!("poison lease accounting state");
            })
            .join()
            .is_err()
        );

        assert_eq!(
            authority.reserve(&candidate, NOW),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.issue(spec("lease:after-poison", b"intent:after-poison")),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.register_grant("grant:after-poison", 1, budget()),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.usage("grant:1", 3),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.reconcile(&receipt, &reconciliation),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
    }

    #[test]
    fn unknown_outcome_blocks_new_lease_until_explicit_reconciliation() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let first = spec("lease:unknown", b"intent:shared");
        let receipt = authenticated_unknown_receipt(&authority, &first);

        let mut retry = spec("lease:retry", b"intent:shared");
        retry.decision_digest = Digest::of(b"new-decision");
        seal_spec(&mut retry);
        assert_eq!(
            authority.issue(retry),
            Err(DenialCode::LeaseReconciliationRequired),
            "an exact-effect durable hold takes precedence over the general binding collision"
        );
        let relabelled = spec("lease:relabelled", b"intent:relabelled");
        assert_eq!(relabelled.effect_digest, first.effect_digest);
        let relabelled_proof = authority
            .issue(relabelled.clone())
            .expect("preissued relabelled lease")
            .proof;
        let relabelled_request = request(&relabelled, relabelled_proof);
        assert_eq!(
            authority.reserve(&relabelled_request, NOW + 1),
            Err(DenialCode::LeaseReconciliationRequired),
            "fresh intent and lease identifiers cannot bypass an exact-effect hold"
        );
        let reconciliation = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Failed,
                Digest::of(b"operator terminal evidence"),
                *b"operator-proof01",
                NOW + 2,
            )
            .expect("authenticated operator reconciliation");
        authority
            .reconcile(&receipt, &reconciliation)
            .expect("explicit reconciliation");
        assert_eq!(
            authority
                .reconciliation_receipt(&first.grant_id, first.grant_version, first.intent_digest,)
                .expect("recorded reconciliation"),
            Some(reconciliation.reconciliation_id)
        );
        let (explicit_retry, mut retry_request) =
            retry_candidate(&first, ("lease:retry-alias", b"intent:retry-alias"), |_| {});
        let proof = authority
            .issue(explicit_retry.clone())
            .expect("append-only retry alias")
            .proof;
        retry_request.lease_proof = proof;
        assert!(authority.reserve(&retry_request, NOW + 2).is_ok());
    }
