use faultloom_gateway::Digest;
use faultloom_gateway::ipc::DenialCode;
use faultloom_gateway::supervisor_journal::{
    JournalDenial, JournalOperation, JournalReply, JournalRequest, JournalResult,
};

use super::support::{KEY, request, sample_snapshot};

#[test]
fn requests_round_trip_canonically_for_every_operation() {
    // Given
    let snapshot = sample_snapshot();
    let requests = [
        request(JournalOperation::Open {
            expected_anchor: None,
        }),
        request(JournalOperation::Open {
            expected_anchor: Some(Digest::of(b"expected anchor")),
        }),
        request(JournalOperation::Commit {
            previous_anchor: Some(Digest::of(b"previous anchor")),
            snapshot,
        }),
    ];

    for expected in requests {
        // When
        let encoded = expected.to_bytes(&KEY).expect("encode journal request");
        let decoded = JournalRequest::from_bytes(&encoded, &KEY).expect("decode journal request");

        // Then
        assert_eq!(decoded, expected);
        assert_eq!(decoded.to_bytes(&KEY), Ok(encoded));
    }
}

#[test]
fn replies_round_trip_canonically_for_every_result() {
    // Given
    let request = request(JournalOperation::Open {
        expected_anchor: None,
    });
    let snapshot = sample_snapshot();
    let previous_anchor = Digest::of(b"previous anchor");
    let current_anchor = Digest::of(b"current anchor");
    let snapshot_digest = snapshot.snapshot_digest().expect("snapshot digest");
    let mut results = vec![
        JournalResult::Opened {
            current_anchor: None,
            snapshot: None,
        },
        JournalResult::Opened {
            current_anchor: Some(current_anchor),
            snapshot: Some(snapshot),
        },
        JournalResult::Committed {
            previous_anchor: Some(previous_anchor),
            current_anchor,
            snapshot_digest,
        },
    ];
    results.extend(
        [
            JournalDenial::StorageUnavailable,
            JournalDenial::AnchorMismatch,
            JournalDenial::SnapshotInvalid,
            JournalDenial::AuthenticationFailed,
            JournalDenial::SequenceRejected,
            JournalDenial::StableBindingMismatch,
            JournalDenial::PendingResponseMissing,
        ]
        .map(JournalResult::Denied),
    );

    for result in results {
        let expected = JournalReply::for_request(&request, result).expect("bind journal reply");
        assert_eq!(expected.session_id, request.session_id);
        assert_eq!(expected.stable_binding, request.stable_binding);
        assert_eq!(expected.sequence, request.sequence);
        assert_eq!(
            expected.request_id,
            request.request_id().expect("request id")
        );

        // When
        let encoded = expected.to_bytes(&KEY).expect("encode journal reply");
        let decoded = JournalReply::from_bytes(&encoded, &KEY).expect("decode journal reply");

        // Then
        assert_eq!(decoded, expected);
        assert_eq!(decoded.to_bytes(&KEY), Ok(encoded));
    }
}

#[test]
fn reply_binding_characterization_preserves_exact_request_coordinates() {
    // Given
    let request = request(JournalOperation::Open {
        expected_anchor: None,
    });
    let reply = JournalReply::for_request(
        &request,
        JournalResult::Denied(JournalDenial::StorageUnavailable),
    )
    .expect("bind exact journal reply");

    // When
    let encoded = reply.to_bytes(&KEY).expect("encode exact journal reply");
    let decoded = JournalReply::from_bytes(&encoded, &KEY).expect("decode exact journal reply");

    // Then
    assert_eq!(decoded.session_id, request.session_id);
    assert_eq!(decoded.stable_binding, request.stable_binding);
    assert_eq!(decoded.sequence, request.sequence);
    assert_eq!(
        decoded.request_id,
        request.request_id().expect("request id")
    );
}

#[test]
fn reply_validation_rejects_every_near_match_request_coordinate() {
    // Given
    let request = request(JournalOperation::Open {
        expected_anchor: None,
    });
    let exact = JournalReply::for_request(
        &request,
        JournalResult::Denied(JournalDenial::StorageUnavailable),
    )
    .expect("bind exact journal reply");
    let mut variants = Vec::new();
    for mutation in 0..4 {
        let mut variant = exact.clone();
        match mutation {
            0 => variant.session_id = "journal-session:other".to_owned(),
            1 => variant.stable_binding = Digest::of(b"other stable binding"),
            2 => variant.sequence += 1,
            3 => variant.request_id = Digest::of(b"other request id"),
            _ => unreachable!("bounded mutation set"),
        }
        variants.push(variant);
    }

    // When / Then
    assert_eq!(exact.validate_for(&request), Ok(()));
    for near_match in variants {
        assert_eq!(
            near_match.validate_for(&request),
            Err(DenialCode::DurabilityAnchorMismatch)
        );
    }
}
