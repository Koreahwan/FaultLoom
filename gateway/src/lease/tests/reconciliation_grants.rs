    #[test]
    fn reconciliation_for_one_grant_cannot_authorize_same_intent_in_another_grant() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let (first, first_receipt, second, second_receipt) =
            same_intent_unknown_receipts(&authority, "grant:2", 9);
        let first_reconciliation = reconciler
            .issue(
                &first_receipt,
                DispatchOutcome::Completed,
                Digest::of(b"first grant terminal evidence"),
                *b"reconcile-grant1",
                NOW + 2,
            )
            .expect("first grant reconciliation");
        authority
            .reconcile(&first_receipt, &first_reconciliation)
            .expect("reconcile first grant only");
        let mut completed_retry = spec(
            "lease:grant-1-completed-retry",
            b"intent:grant-1-completed-retry",
        );
        completed_retry.retry_of_intent_digest = Some(first.intent_digest);
        seal_spec(&mut completed_retry);
        assert_eq!(
            authority.issue(completed_retry),
            Err(DenialCode::RetryAliasInvalid),
            "a terminally completed dispatch cannot be retried"
        );

        let mut unauthorized_retry = spec(
            "lease:grant-2-unauthorized-retry",
            b"intent:grant-2-unauthorized-retry",
        );
        unauthorized_retry.grant_id = second.grant_id.clone();
        unauthorized_retry.grant_version = second.grant_version;
        unauthorized_retry.retry_of_intent_digest = Some(second.intent_digest);
        seal_spec(&mut unauthorized_retry);
        assert_eq!(
            authority.issue(unauthorized_retry),
            Err(DenialCode::RetryAliasInvalid),
            "grant-1 reconciliation must not authorize a grant-2 retry"
        );

        let second_reconciliation = reconciler
            .issue(
                &second_receipt,
                DispatchOutcome::Failed,
                Digest::of(b"second grant terminal evidence"),
                *b"reconcile-grant2",
                NOW + 2,
            )
            .expect("failed second-grant reconciliation");
        authority
            .reconcile(&second_receipt, &second_reconciliation)
            .expect("second grant retains an independent hold");

        let (authorized_retry, mut authorized_request) = retry_candidate(
            &second,
            (
                "lease:grant-2-authorized-retry",
                b"intent:grant-2-authorized-retry",
            ),
            |_| {},
        );
        let proof = authority
            .issue(authorized_retry.clone())
            .expect("exact failed reconciliation authorizes a fresh retry")
            .proof;
        authorized_request.lease_proof = proof;
        authority
            .reserve(&authorized_request, NOW + 3)
            .expect("fresh grant-2 retry reserves after exact failed reconciliation");
        assert_ne!(first.grant_id, authorized_retry.grant_id);
    }

    #[test]
    fn reconciliation_for_one_grant_version_cannot_clear_another_version() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let (first, first_receipt, second, second_receipt) =
            same_intent_unknown_receipts(&authority, "grant:1", 4);
        let first_reconciliation = reconciler
            .issue(
                &first_receipt,
                DispatchOutcome::Completed,
                Digest::of(b"first version terminal evidence"),
                *b"reconcile-vers01",
                NOW + 2,
            )
            .expect("first version reconciliation");
        authority
            .reconcile(&first_receipt, &first_reconciliation)
            .expect("reconcile first version only");
        assert_eq!(
            authority.reconciliation_receipt(
                &second.grant_id,
                second.grant_version,
                second.intent_digest,
            ),
            Ok(None)
        );

        let second_reconciliation = reconciler
            .issue(
                &second_receipt,
                DispatchOutcome::Failed,
                Digest::of(b"second version terminal evidence"),
                *b"reconcile-vers02",
                NOW + 2,
            )
            .expect("second version reconciliation");
        authority
            .reconcile(&second_receipt, &second_reconciliation)
            .expect("second version retains an independent hold");
        assert_eq!(first.grant_id, second.grant_id);
        assert_ne!(first.grant_version, second.grant_version);
    }

    #[test]
    fn same_intent_grant_holds_survive_checkpoint_and_reconcile_concurrently() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let (_, first_receipt, _, second_receipt) =
            same_intent_unknown_receipts(&authority, "grant:2", 9);
        let checkpoint = authority.checkpoint().expect("checkpoint both grant holds");
        let restored = Arc::new(
            LeaseAuthority::new_with_reconciliation_verifier(
                "lease-key:test".to_owned(),
                lease_key(),
                "gateway:boot:restored-grants".to_owned(),
                Digest::of(b"restored grant challenge"),
                "reconciliation-key:test".to_owned(),
                reconciliation_key(),
            )
            .expect("restored authority"),
        );
        restored
            .restore_checkpoint(&checkpoint, checkpoint.checkpoint_id())
            .expect("restore both scoped holds");
        let reconciliations = [
            reconciler
                .issue(
                    &first_receipt,
                    DispatchOutcome::Completed,
                    Digest::of(b"first restored terminal evidence"),
                    *b"checkpoint-one01",
                    NOW + 2,
                )
                .expect("first restored reconciliation"),
            reconciler
                .issue(
                    &second_receipt,
                    DispatchOutcome::Failed,
                    Digest::of(b"second restored terminal evidence"),
                    *b"checkpoint-two02",
                    NOW + 2,
                )
                .expect("second restored reconciliation"),
        ];
        let receipts = [first_receipt, second_receipt];
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = receipts
            .into_iter()
            .zip(reconciliations)
            .map(|(receipt, reconciliation)| {
                let authority = Arc::clone(&restored);
                let barrier = Arc::clone(&barrier);
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
        assert!(
            results.iter().all(Result::is_ok),
            "each grant must retain an independent durable hold: {results:?}"
        );
    }
