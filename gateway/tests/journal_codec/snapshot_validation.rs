use faultloom_gateway::Digest;
use faultloom_gateway::ipc::DenialCode;
use faultloom_gateway::supervisor_journal::{
    AcknowledgedResponseTombstone, JournalOperation, JournalRequest, JournalSnapshot,
    MAX_DURABLE_RESPONSE_SLOTS, PendingInnerResponse,
};

use super::support::{KEY, request, sample_snapshot};

#[test]
fn snapshot_digest_is_stable_and_changes_with_content() {
    // Given
    let original = sample_snapshot();
    let mut changed_binding = original.clone();
    changed_binding.prepared_dispatches[0].action_id = "action:changed".to_owned();
    let mut changed_tombstone = original.clone();
    changed_tombstone.acknowledged_responses[0].inner_response_digest =
        Digest::of(b"changed acknowledged response");

    // When
    let original_digest = original.snapshot_digest().expect("original digest");
    let cloned_digest = original.clone().snapshot_digest().expect("cloned digest");
    let binding_digest = changed_binding.snapshot_digest().expect("binding digest");
    let tombstone_digest = changed_tombstone
        .snapshot_digest()
        .expect("tombstone digest");

    // Then
    assert_eq!(original_digest, cloned_digest);
    assert_ne!(original_digest, binding_digest);
    assert_ne!(original_digest, tombstone_digest);
}

#[test]
fn snapshot_validation_rejects_invalid_digest_order_and_item_count() {
    // Given
    let mut invalid_checkpoint = sample_snapshot();
    invalid_checkpoint.lease_checkpoint_id = Digest::ZERO;
    let mut invalid_response = sample_snapshot();
    invalid_response.pending_responses[0].inner_response_digest = Digest::of(b"not the response");
    let mut unordered = sample_snapshot();
    let mut later = unordered.prepared_dispatches[0].clone();
    later.request_frame_digest = Digest::from_bytes([2; 32]);
    unordered.prepared_dispatches.insert(0, later);
    let mut oversized = sample_snapshot();
    oversized.prepared_dispatches = (1_u8..=65)
        .map(|value| {
            let mut item = oversized.prepared_dispatches[0].clone();
            item.request_frame_digest = Digest::from_bytes([value; 32]);
            item
        })
        .collect();

    // When / Then
    for snapshot in [invalid_checkpoint, invalid_response, unordered, oversized] {
        assert_eq!(
            snapshot.snapshot_digest(),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );
    }
}

#[test]
fn snapshot_validation_rejects_duplicate_cross_pending_and_unbounded_tombstones() {
    // Given: duplicate, cross-pending, zero-bound, and oversized ACK histories.
    let mut duplicate = sample_snapshot();
    duplicate
        .acknowledged_responses
        .push(duplicate.acknowledged_responses[0].clone());
    let mut cross_pending = sample_snapshot();
    cross_pending.acknowledged_responses[0].original_request_envelope_id =
        cross_pending.pending_responses[0].original_request_envelope_id;
    let mut zero_digest = sample_snapshot();
    zero_digest.acknowledged_responses[0].inner_response_digest = Digest::ZERO;
    let mut oversized = sample_snapshot();
    oversized.acknowledged_responses = (0
        ..=faultloom_gateway::supervisor_journal::MAX_DURABLE_RESPONSE_SLOTS)
        .map(|value| AcknowledgedResponseTombstone {
            original_request_envelope_id: Digest::of(
                format!("oversized request {value}").as_bytes(),
            ),
            inner_response_digest: Digest::of(format!("oversized response {value}").as_bytes()),
        })
        .collect();

    // When / Then: every ambiguous or unbounded history fails codec validation.
    for snapshot in [duplicate, cross_pending, zero_digest, oversized] {
        assert_eq!(
            snapshot.snapshot_digest(),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );
    }
}

#[test]
fn exactly_64_mixed_response_slots_round_trip_without_wire_version_change() {
    // Given
    let snapshot = mixed_full_slot_snapshot();
    let request = request(JournalOperation::Commit {
        previous_anchor: Some(Digest::of(b"mixed full previous anchor")),
        snapshot: snapshot.clone(),
    });

    // When
    let encoded = request.to_bytes(&KEY).expect("encode 64 mixed slots");
    let decoded = JournalRequest::from_bytes(&encoded, &KEY).expect("decode 64 mixed slots");

    // Then
    assert_eq!(encoded.get(4), Some(&3));
    assert_eq!(decoded, request);
    assert_eq!(
        snapshot.snapshot_digest(),
        decoded_snapshot(&decoded).snapshot_digest()
    );
}

#[test]
fn combined_65_response_slots_are_rejected_when_each_collection_is_bounded() {
    // Given
    let mut snapshot = mixed_full_slot_snapshot();
    snapshot
        .acknowledged_responses
        .push(AcknowledgedResponseTombstone {
            original_request_envelope_id: Digest::from_bytes([0xa0; 32]),
            inner_response_digest: Digest::of(b"sixty-fifth response"),
        });

    // When
    let result = snapshot.snapshot_digest();

    // Then
    assert_eq!(result, Err(DenialCode::RecoveryCheckpointInvalid));
}

#[test]
fn response_slot_ids_reject_duplicate_prepared_and_every_cross_list_collision() {
    // Given
    let base = sample_snapshot();
    let mut duplicate_prepared = base.clone();
    let mut second = duplicate_prepared.prepared_dispatches[0].clone();
    second.request_frame_digest = Digest::from_bytes([2; 32]);
    duplicate_prepared.prepared_dispatches.push(second);

    let mut prepared_pending = base.clone();
    prepared_pending.prepared_dispatches[0].control_envelope_id =
        prepared_pending.pending_responses[0].original_request_envelope_id;

    let mut prepared_acknowledged = base.clone();
    prepared_acknowledged.prepared_dispatches[0].control_envelope_id =
        prepared_acknowledged.acknowledged_responses[0].original_request_envelope_id;

    // When / Then
    for invalid in [duplicate_prepared, prepared_pending, prepared_acknowledged] {
        assert_eq!(
            invalid.snapshot_digest(),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );
    }
}

fn mixed_full_slot_snapshot() -> JournalSnapshot {
    let mut snapshot = sample_snapshot();
    let prepared_template = snapshot.prepared_dispatches[0].clone();
    let pending_template = snapshot.pending_responses[0].clone();
    snapshot.prepared_dispatches = (1_u8..=22)
        .map(|value| {
            let mut item = prepared_template.clone();
            item.request_frame_digest = Digest::from_bytes([value; 32]);
            item.control_envelope_id = Digest::from_bytes([0x40 + value; 32]);
            item.action_id = format!("action:mixed:{value}");
            item.correlation_id = format!("correlation:mixed:{value}");
            item.lease_id = format!("lease:mixed:{value}");
            item
        })
        .collect();
    snapshot.pending_responses = (1_u8..=21)
        .map(|value| {
            let inner_response = format!("mixed pending response {value}").into_bytes();
            PendingInnerResponse {
                original_request_envelope_id: Digest::from_bytes([0x60 + value; 32]),
                inner_response_digest: Digest::of(&inner_response),
                inner_response,
            }
        })
        .collect();
    snapshot.acknowledged_responses = (1_u8..=21)
        .map(|value| AcknowledgedResponseTombstone {
            original_request_envelope_id: Digest::from_bytes([0x80 + value; 32]),
            inner_response_digest: Digest::of(format!("mixed acknowledged {value}").as_bytes()),
        })
        .collect();
    assert_eq!(
        snapshot.prepared_dispatches.len()
            + snapshot.pending_responses.len()
            + snapshot.acknowledged_responses.len(),
        MAX_DURABLE_RESPONSE_SLOTS
    );
    assert_eq!(
        pending_template.inner_response_digest,
        Digest::of(&pending_template.inner_response)
    );
    snapshot
}

fn decoded_snapshot(request: &JournalRequest) -> &JournalSnapshot {
    match &request.operation {
        JournalOperation::Commit { snapshot, .. } => snapshot,
        JournalOperation::Open { .. } => panic!("expected commit snapshot"),
    }
}
