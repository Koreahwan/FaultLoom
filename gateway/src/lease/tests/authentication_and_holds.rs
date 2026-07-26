    #[test]
    fn recomputable_unkeyed_receipt_cannot_forge_gateway_authenticity() {
        let (authority, _) = authority_with_reconciliation(budget());
        let lease = spec(
            "lease:authenticated-receipt",
            b"intent:authenticated-receipt",
        );
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        authority
            .verify_dispatch_receipt(&receipt)
            .expect("gateway-authenticated receipt");

        let mut forged = receipt.clone();
        forged.bytes_received = 1;
        forged.receipt_id = forged.canonical_id();
        forged.receipt_authentication_tag = forged.receipt_id;
        assert_eq!(
            authority.verify_dispatch_receipt(&forged),
            Err(DenialCode::LeaseBindingMismatch)
        );
    }

    #[test]
    fn arbitrary_reconciliation_digest_cannot_clear_unknown_outcome_hold() {
        let (authority, reconciler) = authority_with_reconciliation(budget());
        let lease = spec("lease:reconciliation-proof", b"intent:reconciliation-proof");
        let receipt = authenticated_unknown_receipt(&authority, &lease);
        let valid = reconciler
            .issue(
                &receipt,
                DispatchOutcome::Completed,
                Digest::of(b"durable terminal evidence"),
                *b"reconcile-proof1",
                NOW + 2,
            )
            .expect("issue exact reconciliation proof");

        let mut forged = valid.clone();
        forged.terminal_evidence_digest = Digest::of(b"attacker-selected digest");
        forged.reconciliation_id = forged.canonical_id();
        forged.authentication_tag = forged.reconciliation_id;
        assert_eq!(
            authority.reconcile(&receipt, &forged),
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

        authority
            .reconcile(&receipt, &valid)
            .expect("authenticated reconciliation");
        assert_eq!(
            authority.reconciliation_receipt(
                &lease.grant_id,
                lease.grant_version,
                lease.intent_digest,
            ),
            Ok(Some(valid.reconciliation_id))
        );
        assert_eq!(
            authority.reconcile(&receipt, &valid),
            Err(DenialCode::LeaseReplay)
        );
    }

    #[test]
    fn exact_hold_collision_is_rejected_before_active_accounting_changes() {
        let authority = authority(budget());
        let first = spec("lease:hold-collision-a", b"intent:hold-collision");
        let first_proof = authority
            .issue(first.clone())
            .expect("issue first lease")
            .proof;
        let first_request = request(&first, first_proof);
        let approval = authority
            .reserve(&first_request, NOW)
            .expect("reserve first lease");

        let second = spec("lease:hold-collision-b", b"intent:hold-collision");
        assert_eq!(
            authority.issue(second),
            Err(DenialCode::LeaseBindingMismatch),
            "one intent key cannot name two exact hold bindings"
        );

        let key = ReconciliationKey::from_spec(&first);
        let mut state = authority
            .state
            .lock()
            .expect("inject conflicting durable hold");
        state.reconciliation_required.insert(
            key.clone(),
            ReconciliationHold {
                kind: ReconciliationHoldKind::DispatchReceipt,
                binding_digest: Digest::of(b"conflicting exact hold"),
                retry_invariant_digest: Digest::of(b"conflicting retry invariant"),
            },
        );
        state.held_effects.insert(key, first.effect_digest);
        drop(state);

        let before = authority
            .usage("grant:1", 3)
            .expect("usage before collision");
        assert_eq!(
            authority.finalize(&approval, completion(DispatchOutcome::UnknownOutcome)),
            Err(DenialCode::LeaseAccountingUnavailable)
        );
        let after = authority
            .usage("grant:1", 3)
            .expect("usage after collision");
        assert_eq!(
            after, before,
            "failed finalization cannot consume accounting"
        );
        let state = authority
            .state
            .lock()
            .expect("inspect active lease after collision");
        assert!(matches!(
            state.leases.get(&first.lease_id).map(|entry| &entry.status),
            Some(LeaseStatus::Active { .. })
        ));
    }

    #[test]
    fn same_effect_reconciliation_hold_denies_issue_without_state_consumption() {
        let authority = authority(budget());
        let held = spec("lease:held-effect", b"intent:held-effect");
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let candidate = spec("lease:same-held-effect", b"intent:held-effect");
        assert_eq!(candidate.effect_digest, held.effect_digest);
        let usage_before = authority
            .usage(&candidate.grant_id, candidate.grant_version)
            .expect("usage before denied issue");

        assert_eq!(
            authority.issue(candidate.clone()),
            Err(DenialCode::LeaseReconciliationRequired)
        );

        assert_eq!(
            authority
                .usage(&candidate.grant_id, candidate.grant_version)
                .expect("usage after denied issue"),
            usage_before
        );
        let key = ReconciliationKey::from_spec(&candidate);
        let state = authority.state.lock().expect("inspect denied issue state");
        assert!(!state.leases.contains_key(&candidate.lease_id));
        assert!(!state.dispatch_nonces.contains(&candidate.dispatch_nonce));
        assert!(!state.retired_lease_ids.contains(&candidate.lease_id));
        assert!(state.reconciliation_required.contains_key(&key));
        assert_eq!(state.held_effects.get(&key), Some(&held.effect_digest));
    }
