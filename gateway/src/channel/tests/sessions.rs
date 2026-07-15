use super::*;

#[test]
fn pinned_server_rejects_wrong_session_without_consuming_replay_state() {
    let challenge = challenge("gateway:boot:pinned-session");
    let expected_client =
        ChannelClient::new(key(), challenge.clone(), "session:expected".to_owned())
            .expect("expected-session client");
    let wrong_client = ChannelClient::new(key(), challenge.clone(), "session:wrong".to_owned())
        .expect("wrong-session client");
    let server = ChannelServer::new_pinned_session(key(), challenge, "session:expected".to_owned())
        .expect("pinned server");

    let wrong_request = wrong_client
        .seal_request(
            b"wrong-session request".to_vec(),
            *b"request-nonce-01",
            NOW,
            NOW + 1_000,
        )
        .expect("wrong-session request");
    assert_eq!(
        server.verify_request(wrong_request, NOW),
        Err(DenialCode::IpcAuthenticationFailed)
    );

    let expected_request = expected_client
        .seal_request(
            b"expected-session request".to_vec(),
            *b"request-nonce-01",
            NOW,
            NOW + 1_000,
        )
        .expect("expected-session request");
    assert!(server.verify_request(expected_request, NOW).is_ok());
}

#[test]
fn pinned_server_rejects_inner_replay_resealed_in_a_new_session() {
    let challenge = challenge("gateway:boot:pinned-replay");
    let expected_client =
        ChannelClient::new(key(), challenge.clone(), "session:expected".to_owned())
            .expect("expected-session client");
    let wrong_client = ChannelClient::new(key(), challenge.clone(), "session:new".to_owned())
        .expect("new-session client");
    let server = ChannelServer::new_pinned_session(key(), challenge, "session:expected".to_owned())
        .expect("pinned server");
    let inner_frame = b"same inner command".to_vec();

    let first = expected_client
        .seal_request(inner_frame.clone(), *b"request-nonce-01", NOW, NOW + 1_000)
        .expect("first request");
    assert!(server.verify_request(first, NOW).is_ok());

    let resealed = wrong_client
        .seal_request(inner_frame, *b"request-nonce-02", NOW, NOW + 1_000)
        .expect("resealed request");
    assert_eq!(
        server.verify_request(resealed, NOW),
        Err(DenialCode::IpcAuthenticationFailed)
    );

    let second = expected_client
        .seal_request(
            b"next expected request".to_vec(),
            *b"request-nonce-03",
            NOW,
            NOW + 1_000,
        )
        .expect("second request");
    assert!(server.verify_request(second, NOW).is_ok());
}

#[test]
fn generic_server_preserves_independent_session_sequences() {
    let challenge = challenge("gateway:boot:generic-sessions");
    let first_client = ChannelClient::new(key(), challenge.clone(), "session:first".to_owned())
        .expect("first client");
    let second_client = ChannelClient::new(key(), challenge.clone(), "session:second".to_owned())
        .expect("second client");
    let server = ChannelServer::new(key(), challenge).expect("generic server");

    let first = first_client
        .seal_request(
            b"first session request".to_vec(),
            *b"request-nonce-01",
            NOW,
            NOW + 1_000,
        )
        .expect("first request");
    let second = second_client
        .seal_request(
            b"second session request".to_vec(),
            *b"request-nonce-02",
            NOW,
            NOW + 1_000,
        )
        .expect("second request");

    assert!(server.verify_request(first, NOW).is_ok());
    assert!(server.verify_request(second, NOW).is_ok());
}
