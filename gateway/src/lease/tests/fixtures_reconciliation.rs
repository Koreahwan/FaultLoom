    fn completion(outcome: DispatchOutcome) -> LeaseCompletion {
        LeaseCompletion {
            outcome,
            bytes_sent: 4,
            bytes_received: 4,
            elapsed_millis: 50,
        }
    }

    fn reconciliation_key() -> [u8; 32] {
        std::array::from_fn(|index| u8::try_from(index + 65).expect("small key byte"))
    }

    fn authority_with_reconciliation(
        budget: GrantBudget,
    ) -> (LeaseAuthority, ReconciliationAuthority) {
        let authority = LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:test".to_owned(),
            Digest::of(b"gateway challenge:test"),
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("valid lease and reconciliation keys");
        authority
            .register_grant("grant:1", 3, budget)
            .expect("register grant");
        let reconciler = ReconciliationAuthority::new(
            "reconciliation-key:test".to_owned(),
            reconciliation_key(),
        )
        .expect("valid reconciliation signer");
        (authority, reconciler)
    }

    fn authenticated_unknown_receipt(
        authority: &LeaseAuthority,
        lease: &LeaseSpec,
    ) -> DispatchReceipt {
        let issued = authority.issue(lease.clone()).expect("issue unknown lease");
        let request = request(lease, issued.proof.clone());
        let approval = authority
            .reserve(&request, NOW)
            .expect("reserve unknown lease");
        finalize_unknown_receipt(authority, lease, issued, request, approval)
    }

    fn finalize_unknown_receipt(
        authority: &LeaseAuthority,
        lease: &LeaseSpec,
        issued: IssuedLease,
        request: DispatchRequest,
        approval: LeaseApproval,
    ) -> DispatchReceipt {
        authority
            .finalize(&approval, completion(DispatchOutcome::UnknownOutcome))
            .expect("finalize unknown lease");
        let request_binding_digest = request.lease_binding_digest();
        let request_digest = Digest::of(&request.payload);
        let mut receipt = DispatchReceipt {
            receipt_id: Digest::ZERO,
            receipt_authentication_tag: Digest::ZERO,
            action_id: request.action_id,
            correlation_id: request.correlation_id,
            lease_id: request.lease_id,
            grant_id: request.grant_id,
            grant_version: request.grant_version,
            authority_key_id: lease.authority_key_id.clone(),
            scope_epoch_binding_digest: lease.scope_epoch_binding_digest,
            lease_key_id: issued.lease_key_id,
            gateway_boot_id: issued.gateway_boot_id,
            boot_challenge_digest: issued.boot_challenge_digest,
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            scope_epoch: request.scope_epoch,
            semantic_action_digest: request.semantic_action_digest,
            request_binding_digest,
            request_frame_digest: Digest::of(b"canonical request frame"),
            control_envelope_id: approval.control_envelope_id,
            hold_binding_digest: approval.hold_binding_digest,
            resolution_digest: request.resolution_digest,
            action_kind: request.action_kind,
            egress_plane: request.egress_plane,
            effect_digest: lease.effect_digest,
            dispatch_nonce: request.dispatch_nonce,
            lease_issued_at_millis: request.request_issued_at_millis,
            lease_expires_at_millis: request.request_expires_at_millis,
            retry_of_intent_digest: request.retry_of_intent_digest,
            reserved_action_count: lease.reservation.action_count,
            reserved_request_bytes: lease.reservation.request_bytes,
            reserved_response_bytes: lease.reservation.response_bytes,
            reserved_duration_seconds: lease.reservation.duration_seconds,
            request_digest,
            response_digest: None,
            outcome: DispatchOutcome::UnknownOutcome,
            dispatched_at_millis: NOW,
            completed_at_millis: NOW + 1,
            bytes_sent: 4,
            bytes_received: 0,
            reconciliation_required: true,
        };
        receipt.receipt_id = receipt.canonical_id();
        receipt.receipt_authentication_tag = authority
            .authenticate_receipt(&approval, &receipt)
            .expect("authenticate exact receipt");
        receipt
    }

    fn same_intent_unknown_receipts(
        authority: &LeaseAuthority,
        second_grant_id: &str,
        second_grant_version: u64,
    ) -> (LeaseSpec, DispatchReceipt, LeaseSpec, DispatchReceipt) {
        authority
            .register_grant(second_grant_id, second_grant_version, budget())
            .expect("register second grant");
        let mut first = spec("lease:same-intent-grant-1", b"intent:shared-across-grants");
        seal_spec(&mut first);
        let mut second = spec("lease:same-intent-grant-2", b"intent:shared-across-grants");
        second.grant_id = second_grant_id.to_owned();
        second.grant_version = second_grant_version;
        seal_spec(&mut second);

        let first_issued = authority.issue(first.clone()).expect("issue first grant");
        let first_request = request(&first, first_issued.proof.clone());
        let first_approval = authority
            .reserve(&first_request, NOW)
            .expect("reserve first grant");
        let second_issued = authority.issue(second.clone()).expect("issue second grant");
        let second_request = request(&second, second_issued.proof.clone());
        let second_approval = authority
            .reserve(&second_request, NOW)
            .expect("reserve second grant before either finalization");

        let first_receipt = finalize_unknown_receipt(
            authority,
            &first,
            first_issued,
            first_request,
            first_approval,
        );
        let second_receipt = finalize_unknown_receipt(
            authority,
            &second,
            second_issued,
            second_request,
            second_approval,
        );
        (first, first_receipt, second, second_receipt)
    }
