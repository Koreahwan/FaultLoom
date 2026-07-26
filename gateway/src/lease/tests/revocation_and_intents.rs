    #[test]
    fn grant_revocation_cancels_available_and_active_leases_atomically() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        limits.max_concurrency = 2;
        let (authority, reconciler) = authority_with_reconciliation(limits);
        let active = spec("lease:revoke-active", b"intent:revoke-active");
        let active_proof = authority.issue(active.clone()).expect("active issue").proof;
        authority
            .reserve(&request(&active, active_proof), NOW)
            .expect("active reserve");
        let available = spec("lease:revoke-available", b"intent:revoke-available");
        let available_proof = authority
            .issue(available.clone())
            .expect("available issue")
            .proof;

        let summary = authority
            .revoke_grant("grant:1", 3, 7)
            .expect("revoke grant");
        assert_eq!(
            summary,
            LeaseRevocationSummary {
                canceled_available: 1,
                interrupted_active: 1,
            }
        );
        let usage = authority.usage("grant:1", 3).expect("revoked usage");
        assert_eq!(usage.active_dispatches, 0);
        assert_eq!(usage.active_reserved_request_bytes, 0);
        assert_eq!(
            authority.reserve(&request(&available, available_proof), NOW + 1),
            Err(DenialCode::LeaseReplay)
        );
        assert_eq!(
            authority.issue(spec("lease:after-revoke", b"intent:after-revoke")),
            Err(DenialCode::LeaseRevoked)
        );
        let reconciliation = reconciler
            .issue_control_plane_hold(
                ControlPlaneReconciliationHold {
                    grant_id: active.grant_id.clone(),
                    grant_version: active.grant_version,
                    intent_digest: active.intent_digest,
                    effect_digest: active.effect_digest,
                    hold_binding_digest: active.hold_binding_digest(
                        "lease-key:test",
                        Digest::of(b"gateway challenge:test"),
                    ),
                },
                ReconciliationTerminal {
                    outcome: DispatchOutcome::Failed,
                    evidence_digest: Digest::of(b"revocation terminal evidence"),
                    nonce: *b"revoke-proof-001",
                    resolved_at_millis: NOW + 2,
                },
            )
            .expect("revocation reconciliation proof");
        assert_eq!(
            authority.reconcile_control_plane_hold(&reconciliation),
            Ok(())
        );
    }

    #[test]
    fn nonce_and_lease_id_reservations_are_append_only() {
        let authority = authority(budget());
        let first = spec("lease:append-only", b"intent:append-only");
        authority.issue(first.clone()).expect("first issue");

        let mut reused_nonce = spec("lease:other", b"intent:other");
        reused_nonce.dispatch_nonce = first.dispatch_nonce;
        seal_spec(&mut reused_nonce);
        assert_eq!(authority.issue(reused_nonce), Err(DenialCode::LeaseReplay));
        let mut reused_id = spec("lease:append-only", b"intent:new");
        reused_id.dispatch_nonce = *b"fedcba9876543210";
        seal_spec(&mut reused_id);
        assert_eq!(authority.issue(reused_id), Err(DenialCode::LeaseReplay));
    }

    #[test]
    fn child_batch_and_state_change_each_require_their_own_exact_lease() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        limits.max_concurrency = 3;
        let authority = authority(limits);
        let parent = spec("lease:parent", b"intent:parent");
        let parent_proof = authority.issue(parent.clone()).expect("parent issue").proof;
        let parent_request = request(&parent, parent_proof.clone());

        let mut forged_child = parent_request.clone();
        forged_child.action_id = "action:batch-child-forged".to_owned();
        forged_child.flow_kind = FlowKind::BatchChild;
        forged_child.parent_action_id = Some(parent_request.action_id.clone());
        forged_child.bind_canonical_semantics();
        assert_eq!(
            authority.reserve(&forged_child, NOW),
            Err(DenialCode::LeaseBindingMismatch)
        );

        let mut child = forged_child;
        child.action_id = "action:batch-child".to_owned();
        child.lease_id = "lease:batch-child".to_owned();
        child.intent_digest = Digest::of(b"intent:batch-child");
        child.decision_digest = Digest::of(b"decision:batch-child");
        child.dispatch_nonce = *b"batch-child-0001";
        child.lease_proof = vec![1];
        child.bind_canonical_semantics();
        let child_spec = spec_for_request(&child);
        child.lease_proof = authority.issue(child_spec).expect("child issue").proof;
        let child_approval = authority
            .reserve(&child, NOW)
            .expect("child has independent lease");
        authority
            .finalize(&child_approval, completion(DispatchOutcome::Completed))
            .expect("finalize child");

        let mut state_change = parent_request;
        state_change.action_id = "action:state-change".to_owned();
        state_change.lease_id = "lease:state-change".to_owned();
        state_change.intent_digest = Digest::of(b"intent:state-change");
        state_change.decision_digest = Digest::of(b"decision:state-change");
        state_change.dispatch_nonce = *b"state-change-001";
        state_change.action_class = ActionClass::StateChange;
        state_change.canary_ref = Some("canary:state-change".to_owned());
        state_change.checkpoint_ref = Some("checkpoint:before-state-change".to_owned());
        state_change.cleanup_plan_ref = Some("cleanup:state-change".to_owned());
        state_change.lease_proof = vec![1];
        state_change.bind_canonical_semantics();
        let state_spec = spec_for_request(&state_change);
        state_change.lease_proof = authority.issue(state_spec).expect("state lease").proof;
        let mut forged_checkpoint = state_change.clone();
        forged_checkpoint.checkpoint_ref = Some("checkpoint:substituted".to_owned());
        forged_checkpoint.bind_canonical_semantics();
        assert_eq!(
            authority.reserve(&forged_checkpoint, NOW + 1),
            Err(DenialCode::LeaseBindingMismatch)
        );
        assert!(authority.reserve(&state_change, NOW + 1).is_ok());
    }
