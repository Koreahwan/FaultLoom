    #[test]
    fn reservation_total_rate_and_concurrency_are_accounted_atomically() {
        let mut limits = budget();
        limits.total_actions = 2;
        limits.rate_per_minute = 1;
        let authority = authority(limits);

        let first = spec("lease:first", b"intent:first");
        let first_proof = authority.issue(first.clone()).expect("first").proof;
        let first_approval = authority
            .reserve(&request(&first, first_proof), NOW)
            .expect("reserve first");
        let concurrent = spec("lease:concurrent", b"intent:concurrent");
        let concurrent_proof = authority
            .issue(concurrent.clone())
            .expect("concurrent")
            .proof;
        assert_eq!(
            authority.reserve(&request(&concurrent, concurrent_proof), NOW),
            Err(DenialCode::LeaseRateExceeded)
        );
        authority
            .finalize(&first_approval, completion(DispatchOutcome::Completed))
            .expect("finalize first");

        let mut second = spec("lease:second", b"intent:second");
        second.issued_at_millis = NOW + RATE_WINDOW_MILLIS;
        second.expires_at_millis = second.issued_at_millis + 5_000;
        seal_spec(&mut second);
        let second_proof = authority.issue(second.clone()).expect("second").proof;
        let second_approval = authority
            .reserve(
                &request(&second, second_proof),
                NOW + RATE_WINDOW_MILLIS + 1,
            )
            .expect("reserve after rate window");
        authority
            .finalize(&second_approval, completion(DispatchOutcome::Completed))
            .expect("finalize second");

        let mut exhausted = spec("lease:exhausted", b"intent:exhausted");
        exhausted.issued_at_millis = NOW + RATE_WINDOW_MILLIS;
        exhausted.expires_at_millis = exhausted.issued_at_millis + 5_000;
        seal_spec(&mut exhausted);
        let exhausted_proof = authority.issue(exhausted.clone()).expect("exhausted").proof;
        assert_eq!(
            authority.reserve(
                &request(&exhausted, exhausted_proof),
                NOW + RATE_WINDOW_MILLIS + 2,
            ),
            Err(DenialCode::GrantBudgetExhausted)
        );
        let usage = authority.usage("grant:1", 3).expect("usage");
        assert_eq!(usage.dispatched_actions, 2);
        assert_eq!(usage.active_dispatches, 0);
        assert_eq!(usage.actual_request_bytes, 8);
    }

    #[test]
    fn concurrency_precedes_dispatch_and_abandon_still_consumes_lease() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        let authority = authority(limits);
        let first = spec("lease:active", b"intent:active");
        let first_proof = authority.issue(first.clone()).expect("first").proof;
        let first_approval = authority
            .reserve(&request(&first, first_proof), NOW)
            .expect("reserve first");
        let second = spec("lease:blocked", b"intent:blocked");
        let second_proof = authority.issue(second.clone()).expect("second").proof;
        assert_eq!(
            authority.reserve(&request(&second, second_proof), NOW + 1),
            Err(DenialCode::LeaseConcurrencyExceeded)
        );
        authority.abandon(&first_approval).expect("abandon");
        assert_eq!(
            authority.reserve(
                &request(&first, authority.sign_spec(&first).as_bytes().to_vec()),
                NOW + 2
            ),
            Err(DenialCode::LeaseReplay)
        );
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_the_grant_limit() {
        let mut limits = budget();
        limits.rate_per_minute = 3;
        let authority = Arc::new(authority(limits));
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for index in 0..2 {
            let lease = spec(
                &format!("lease:thread-{index}"),
                format!("intent:thread-{index}").as_bytes(),
            );
            let proof = authority
                .issue(lease.clone())
                .expect("issue concurrent lease")
                .proof;
            let request = request(&lease, proof);
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                authority.reserve(&request, NOW)
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("reservation worker"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| { matches!(result, Err(DenialCode::LeaseConcurrencyExceeded)) })
                .count(),
            1
        );
        let approval = results
            .into_iter()
            .find_map(Result::ok)
            .expect("one successful reservation");
        authority.abandon(&approval).expect("release reservation");
        assert_eq!(
            authority
                .usage("grant:1", 3)
                .expect("usage")
                .active_dispatches,
            0
        );
    }
