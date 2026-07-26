    #[test]
    fn hmac_matches_rfc_4231_case_one() {
        let digest = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            digest.to_hex(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn proof_is_bound_and_one_use_even_after_completion() {
        let authority = authority(budget());
        let lease = spec("lease:one", b"intent:one");
        let issued = authority.issue(lease.clone()).expect("issue lease");
        let dispatch_request = request(&lease, issued.proof);
        assert_eq!(
            lease.request_binding_digest,
            dispatch_request.lease_binding_digest()
        );
        assert_eq!(
            lease.semantic_action_digest,
            dispatch_request.semantic_action_digest
        );
        assert_eq!(lease.resolution_digest, dispatch_request.resolution_digest);
        assert_eq!(lease.correlation_id, dispatch_request.correlation_id);
        assert_eq!(lease.dispatch_nonce, dispatch_request.dispatch_nonce);
        assert_eq!(
            lease.issued_at_millis,
            dispatch_request.request_issued_at_millis
        );
        assert_eq!(
            lease.expires_at_millis,
            dispatch_request.request_expires_at_millis
        );
        let approval = authority
            .reserve(&dispatch_request, NOW)
            .expect("reserve once");
        authority
            .finalize(&approval, completion(DispatchOutcome::Completed))
            .expect("finalize");
        assert_eq!(
            authority.reserve(&dispatch_request, NOW + 1),
            Err(DenialCode::LeaseReplay)
        );

        let second = spec("lease:bound", b"intent:bound");
        let issued = authority.issue(second.clone()).expect("issue lease");
        let mut forged = request(&second, issued.proof);
        forged.intent_digest = Digest::of(b"different-intent");
        assert_eq!(
            authority.reserve(&forged, NOW),
            Err(DenialCode::LeaseBindingMismatch)
        );
    }

    #[test]
    fn every_authority_and_decision_binding_is_checked_before_consumption() {
        let authority = authority(budget());
        let lease = spec("lease:all-bindings", b"intent:all-bindings");
        let proof = authority.issue(lease.clone()).expect("issue lease").proof;
        let base = request(&lease, proof);
        let mut variants = Vec::new();
        let mut decision = base.clone();
        decision.decision_digest = Digest::of(b"different-decision");
        variants.push(decision);
        let mut grant = base.clone();
        grant.grant_id = "grant:other".to_owned();
        variants.push(grant);
        let mut version = base.clone();
        version.grant_version += 1;
        variants.push(version);
        let mut epoch = base.clone();
        epoch.scope_epoch += 1;
        variants.push(epoch);
        for variant in variants {
            assert_eq!(
                authority.reserve(&variant, NOW),
                Err(DenialCode::LeaseBindingMismatch)
            );
        }
        assert!(authority.reserve(&base, NOW).is_ok());
    }

    #[test]
    fn forged_not_yet_valid_and_expired_proofs_fail_closed() {
        let authority = authority(budget());
        let mut lease = spec("lease:time", b"intent:time");
        lease.issued_at_millis = NOW + 1;
        seal_spec(&mut lease);
        let issued = authority.issue(lease.clone()).expect("issue lease");
        let mut candidate = request(&lease, issued.proof);
        assert_eq!(
            authority.reserve(&candidate, NOW),
            Err(DenialCode::LeaseNotYetValid)
        );
        candidate.lease_proof[0] ^= 1;
        assert_eq!(
            authority.reserve(&candidate, NOW + 1),
            Err(DenialCode::LeaseDenied)
        );

        let mut expired = spec("lease:expired", b"intent:expired");
        expired.expires_at_millis = NOW;
        seal_spec(&mut expired);
        let issued = authority.issue(expired.clone()).expect("issue lease");
        assert_eq!(
            authority.reserve(&request(&expired, issued.proof), NOW),
            Err(DenialCode::LeaseExpired)
        );
    }

    #[test]
    fn invalid_reservations_and_oversized_requests_are_denied_before_consumption() {
        let authority = authority(budget());
        let mut excessive_ttl = spec("lease:ttl", b"intent:ttl");
        excessive_ttl.expires_at_millis = excessive_ttl.issued_at_millis + MAX_LEASE_TTL_MILLIS + 1;
        seal_spec(&mut excessive_ttl);
        assert_eq!(
            authority.issue(excessive_ttl),
            Err(DenialCode::LeaseBindingMismatch)
        );
        let mut invalid = spec("lease:zero-request", b"intent:zero-request");
        invalid.reservation.request_bytes = 0;
        assert_eq!(
            authority.issue(invalid),
            Err(DenialCode::LeaseReservationExceeded)
        );
        let mut excessive = spec("lease:excessive", b"intent:excessive");
        excessive.reservation.response_bytes = 129;
        assert_eq!(
            authority.issue(excessive),
            Err(DenialCode::LeaseReservationExceeded)
        );

        let lease = spec("lease:request-cap", b"intent:request-cap");
        let proof = authority
            .issue(lease.clone())
            .expect("issue valid lease")
            .proof;
        let mut oversized = request(&lease, proof);
        oversized.payload.push(b'!');
        assert_eq!(
            authority.reserve(&oversized, NOW),
            Err(DenialCode::LeaseReservationExceeded)
        );
        oversized.payload.pop();
        assert!(authority.reserve(&oversized, NOW).is_ok());
    }
