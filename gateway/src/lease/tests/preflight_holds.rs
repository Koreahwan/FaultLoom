    #[test]
    fn preflight_denies_an_exact_held_intent_without_mutating_lease_state() {
        // Given: an exact intent key is held for reconciliation after an
        // ambiguous dispatch.
        let authority = authority(budget());
        let held = spec("lease:preflight-held", b"intent:preflight-held");
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let usage_before = authority
            .usage(&held.grant_id, held.grant_version)
            .expect("usage before preflight");
        let key = ReconciliationKey::from_spec(&held);
        let state_before = authority.state.lock().expect("inspect held state");
        let lease_count_before = state_before.leases.len();
        let nonce_count_before = state_before.dispatch_nonces.len();
        let retired_count_before = state_before.retired_lease_ids.len();
        let checkpoint_sequence_before = state_before.checkpoint_sequence;
        let hold_before = state_before
            .reconciliation_required
            .get(&key)
            .copied()
            .expect("exact reconciliation hold");
        let effect_before = *state_before
            .held_effects
            .get(&key)
            .expect("exact held effect");
        drop(state_before);

        // When: the main thread performs the read-only precompile check.
        let result =
            authority.preflight_issue(&held.grant_id, held.grant_version, held.intent_digest);

        // Then: reconciliation is required and no lease, proof, nonce, budget,
        // hold, or checkpoint state changes.
        assert_eq!(result, Err(DenialCode::LeaseReconciliationRequired));
        assert_eq!(
            authority
                .usage(&held.grant_id, held.grant_version)
                .expect("usage after preflight"),
            usage_before
        );
        let state_after = authority.state.lock().expect("inspect denied state");
        assert_eq!(state_after.leases.len(), lease_count_before);
        assert_eq!(state_after.dispatch_nonces.len(), nonce_count_before);
        assert_eq!(state_after.retired_lease_ids.len(), retired_count_before);
        assert_eq!(state_after.checkpoint_sequence, checkpoint_sequence_before);
        assert_eq!(
            state_after.reconciliation_required.get(&key),
            Some(&hold_before)
        );
        assert_eq!(state_after.held_effects.get(&key), Some(&effect_before));
    }

    #[test]
    fn preflight_conservatively_denies_a_held_intent_before_effect_compilation() {
        // Given: a held intent and a later request that would compile to a
        // different effect under the same exact intent key.
        let authority = authority(budget());
        let held = spec(
            "lease:preflight-effect-held",
            b"intent:preflight-effect-held",
        );
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let mut different_effect = spec(
            "lease:preflight-effect-different",
            b"intent:preflight-effect-held",
        );
        different_effect.effect_digest = Digest::of(b"different preflight effect");

        // When: the effect-free preflight and the later effect-aware issuance
        // inspect the same key.
        let preflight = authority.preflight_issue(
            &different_effect.grant_id,
            different_effect.grant_version,
            different_effect.intent_digest,
        );
        let issue = authority.issue(different_effect);

        // Then: preflight never guesses an effect mismatch, while issuance
        // retains the exact effect-aware precedence contract.
        assert_eq!(preflight, Err(DenialCode::LeaseReconciliationRequired));
        assert_eq!(issue, Err(DenialCode::LeaseBindingMismatch));
    }

    #[test]
    fn preflight_allows_a_distinct_nonheld_intent_to_reach_normal_issuance() {
        // Given: one intent is held and another well-formed intent is distinct.
        let authority = authority(budget());
        let held = spec(
            "lease:preflight-distinct-held",
            b"intent:preflight-distinct-held",
        );
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let candidate = spec(
            "lease:preflight-distinct-candidate",
            b"intent:preflight-distinct-candidate",
        );

        // When: the distinct intent is preflighted and issued normally.
        let preflight = authority.preflight_issue(
            &candidate.grant_id,
            candidate.grant_version,
            candidate.intent_digest,
        );
        let issue = authority.issue(candidate);

        // Then: the exact-key gate does not broaden the hold.
        assert_eq!(preflight, Ok(()));
        assert!(issue.is_ok());
    }

    #[test]
    fn preflight_fails_closed_for_one_sided_hold_state() {
        // Given: each impossible one-sided durable hold representation.
        for hold_present in [true, false] {
            let authority = authority(budget());
            let candidate = spec("lease:preflight-one-sided", b"intent:preflight-one-sided");
            let key = ReconciliationKey::from_spec(&candidate);
            let mut state = authority.state.lock().expect("inject one-sided hold");
            if hold_present {
                state.reconciliation_required.insert(
                    key,
                    ReconciliationHold {
                        kind: ReconciliationHoldKind::ControlPlane,
                        binding_digest: Digest::of(b"preflight one-sided binding"),
                        retry_invariant_digest: Digest::of(b"preflight one-sided retry"),
                    },
                );
            } else {
                state.held_effects.insert(key, candidate.effect_digest);
            }
            drop(state);

            // When: the key is preflighted.
            let result = authority.preflight_issue(
                &candidate.grant_id,
                candidate.grant_version,
                candidate.intent_digest,
            );

            // Then: corrupt paired state is never treated as unheld.
            assert_eq!(result, Err(DenialCode::LeaseAccountingUnavailable));
        }
    }

    #[test]
    fn different_effect_reconciliation_hold_remains_a_binding_mismatch() {
        let authority = authority(budget());
        let held = spec("lease:held-other-effect", b"intent:held-other-effect");
        let _receipt = authenticated_unknown_receipt(&authority, &held);
        let mut candidate = spec("lease:different-held-effect", b"intent:held-other-effect");
        candidate.effect_digest = Digest::of(b"different candidate effect");
        let usage_before = authority
            .usage(&candidate.grant_id, candidate.grant_version)
            .expect("usage before denied issue");

        assert_eq!(
            authority.issue(candidate.clone()),
            Err(DenialCode::LeaseBindingMismatch)
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

    #[test]
    fn one_sided_reconciliation_hold_state_fails_closed() {
        for hold_present in [true, false] {
            let authority = authority(budget());
            let candidate = spec("lease:one-sided-hold", b"intent:one-sided-hold");
            let key = ReconciliationKey::from_spec(&candidate);
            let mut state = authority.state.lock().expect("inject one-sided hold");
            if hold_present {
                state.reconciliation_required.insert(
                    key,
                    ReconciliationHold {
                        kind: ReconciliationHoldKind::DispatchReceipt,
                        binding_digest: Digest::of(b"one-sided hold binding"),
                        retry_invariant_digest: Digest::of(b"one-sided retry invariant"),
                    },
                );
            } else {
                state.held_effects.insert(key, candidate.effect_digest);
            }
            drop(state);

            assert_eq!(
                authority.issue(candidate.clone()),
                Err(DenialCode::LeaseAccountingUnavailable)
            );
            let state = authority.state.lock().expect("inspect denied issue state");
            assert!(!state.leases.contains_key(&candidate.lease_id));
            assert!(!state.dispatch_nonces.contains(&candidate.dispatch_nonce));
            assert!(!state.retired_lease_ids.contains(&candidate.lease_id));
        }
    }
