use super::*;

#[test]
fn exact_authenticated_request_and_response_round_trip() {
    let challenge = challenge("gateway:boot:one");
    let client =
        ChannelClient::new(key(), challenge.clone(), "session:one".to_owned()).expect("client");
    let server = ChannelServer::new(key(), challenge).expect("server");
    let request = client
        .seal_request(
            b"canonical request frame".to_vec(),
            *b"request-nonce-01",
            NOW,
            NOW + 1_000,
        )
        .expect("seal request");
    let decoded = AuthenticatedRequest::from_bytes(&request.as_bytes()).expect("decode request");
    assert_eq!(decoded, request);
    let verified = server.verify_request(decoded, NOW).expect("verify request");
    let response_bytes = b"canonical response frame".to_vec();
    let response = server
        .seal_response(
            &verified,
            response_bytes.clone(),
            *b"response-nonce01",
            NOW,
            NOW + 1_000,
        )
        .expect("seal response");
    let decoded = AuthenticatedResponse::from_bytes(&response.as_bytes()).expect("decode response");
    assert_eq!(
        client.verify_response(&request, decoded, NOW),
        Ok(response_bytes)
    );
}

#[test]
fn tamper_wrong_key_stale_boot_and_replay_fail_closed() {
    let current_challenge = challenge("gateway:boot:current");
    let client = ChannelClient::new(key(), current_challenge.clone(), "session:one".to_owned())
        .expect("client");
    let server = ChannelServer::new(key(), current_challenge.clone()).expect("server");
    let request = client
        .seal_request(b"request".to_vec(), *b"request-nonce-01", NOW, NOW + 1_000)
        .expect("request");

    let mut tampered = request.as_bytes();
    let payload_offset = tampered.len() - 32 - b"request".len();
    tampered[payload_offset] ^= 1;
    let tampered = AuthenticatedRequest::from_bytes(&tampered).expect("canonical altered frame");
    assert_eq!(
        server.verify_request(tampered, NOW),
        Err(DenialCode::IpcAuthenticationFailed)
    );
    assert!(server.verify_request(request.clone(), NOW).is_ok());
    assert_eq!(
        server.verify_request(request, NOW),
        Err(DenialCode::IpcReplay)
    );

    let wrong_server = ChannelServer::new(
        std::array::from_fn(|index| u8::try_from(index + 65).expect("small key byte")),
        current_challenge,
    )
    .expect("wrong-key server");
    let second = client
        .seal_request(b"second".to_vec(), *b"request-nonce-02", NOW, NOW + 1_000)
        .expect("second request");
    assert_eq!(
        wrong_server.verify_request(second, NOW),
        Err(DenialCode::IpcAuthenticationFailed)
    );

    let stale_server =
        ChannelServer::new(key(), challenge("gateway:boot:old")).expect("old server");
    let current_client = ChannelClient::new(
        key(),
        challenge("gateway:boot:new"),
        "session:new".to_owned(),
    )
    .expect("new client");
    let current = current_client
        .seal_request(b"current".to_vec(), *b"request-nonce-03", NOW, NOW + 1_000)
        .expect("current request");
    assert_eq!(
        stale_server.verify_request(current, NOW),
        Err(DenialCode::IpcAuthenticationFailed)
    );
}
