use super::*;

#[test]
fn sequence_and_nonce_commit_atomically_under_concurrency() {
    let challenge = challenge("gateway:boot:concurrency");
    let client =
        ChannelClient::new(key(), challenge.clone(), "session:one".to_owned()).expect("client");
    let server = Arc::new(ChannelServer::new(key(), challenge).expect("server"));
    let request = client
        .seal_request(b"request".to_vec(), *b"request-nonce-01", NOW, NOW + 1_000)
        .expect("request");
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let server = Arc::clone(&server);
        let request = request.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            server.verify_request(request, NOW)
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(DenialCode::IpcReplay)))
            .count(),
        1
    );
}

#[test]
fn expired_request_and_expired_boot_challenge_are_distinct_typed_denials() {
    let current = challenge("gateway:boot:expiry");
    let client =
        ChannelClient::new(key(), current.clone(), "session:expiry".to_owned()).expect("client");
    let server = ChannelServer::new(key(), current).expect("server");
    let request = client
        .seal_request(
            b"expiring request".to_vec(),
            *b"request-expiry01",
            NOW,
            NOW + 1,
        )
        .expect("expiring request");
    assert_eq!(
        server.verify_request(request, NOW + 1),
        Err(DenialCode::IpcSessionExpired)
    );

    let expired_challenge = ChannelChallenge::new(
        "channel-key:expired".to_owned(),
        "gateway:boot:expired".to_owned(),
        *b"fedcba9876543210",
        NOW - 10,
        NOW - 1,
    )
    .expect("historical challenge shape");
    let expired_client = ChannelClient::new(
        key(),
        expired_challenge.clone(),
        "session:expired".to_owned(),
    )
    .expect("expired client shape");
    assert_eq!(
        expired_client.seal_request(b"request".to_vec(), *b"request-expiry02", NOW, NOW + 1,),
        Err(DenialCode::IpcAuthenticationFailed)
    );
}
