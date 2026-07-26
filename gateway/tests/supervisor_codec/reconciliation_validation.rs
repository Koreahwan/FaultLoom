use faultloom_gateway::ipc::{DenialCode, DispatchOutcome};
use faultloom_gateway::lease::{ControlPlaneReconciliationHold, ReconciliationTerminal};
use faultloom_gateway::supervisor_protocol::{
    ControlEgressDisposition, SupervisorCommand, SupervisorControlReceipt,
    SupervisorReconciliation, SupervisorResponse,
};

use super::codec::{nonce, now_millis};
use super::fixture::{reconciliation_authority, unknown_receipt};

#[test]
fn reconciliation_codec_v5_preserves_exact_hold_binding_and_rejects_tamper() {
    // Given: an unknown receipt and proof bound to the same nonzero hold.
    let unknown = unknown_receipt("hold-binding", 0x75);
    let hold_binding_digest = unknown.hold_binding_digest;
    let reconciliation = reconciliation_authority()
        .issue(
            &unknown,
            DispatchOutcome::Failed,
            faultloom_gateway::Digest::of(b"hold-binding terminal evidence"),
            nonce(0x86),
            unknown.completed_at_millis + 1,
        )
        .expect("issue exactly bound reconciliation");
    let command =
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::DispatchReceipt {
            unknown_receipt: Box::new(unknown),
            reconciliation,
        }));

    // When: the exact reconciliation command is encoded.
    let encoded = command.to_bytes().expect("encode v5 reconciliation");

    // Then: v5 carries both bindings canonically and rejects version rollback
    // and proof tampering.
    assert_eq!(encoded.get(4), Some(&5));
    let mut stale_version = encoded.clone();
    stale_version[4] = 4;
    assert_eq!(
        SupervisorCommand::from_bytes(&stale_version),
        Err(DenialCode::MalformedFrame)
    );
    let binding_offsets = encoded
        .windows(hold_binding_digest.as_bytes().len())
        .enumerate()
        .filter_map(|(offset, window)| (window == hold_binding_digest.as_bytes()).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(binding_offsets.len(), 2);
    assert_eq!(SupervisorCommand::from_bytes(&encoded), Ok(command));

    let mut tampered = encoded;
    let reconciliation_binding_offset = *binding_offsets
        .last()
        .expect("unknown receipt and reconciliation binding offsets");
    tampered[reconciliation_binding_offset] ^= 1;
    assert_eq!(
        SupervisorCommand::from_bytes(&tampered),
        Err(DenialCode::MalformedFrame)
    );
}

#[test]
fn reconciliation_commands_reject_cross_shape_and_unbound_evidence() {
    let first_unknown = unknown_receipt("first", 0x72);
    let second_unknown = unknown_receipt("second", 0x73);
    let dispatch_reconciliation = reconciliation_authority()
        .issue(
            &second_unknown,
            DispatchOutcome::Failed,
            faultloom_gateway::Digest::of(b"second terminal evidence"),
            nonce(0x83),
            second_unknown.completed_at_millis + 1,
        )
        .expect("issue dispatch reconciliation");
    let control_reconciliation = reconciliation_authority()
        .issue_control_plane_hold(
            ControlPlaneReconciliationHold {
                grant_id: "grant:codec".to_owned(),
                grant_version: 1,
                intent_digest: faultloom_gateway::Digest::of(b"control intent"),
                effect_digest: faultloom_gateway::Digest::of(b"control effect"),
                hold_binding_digest: faultloom_gateway::Digest::of(b"control hold binding"),
            },
            ReconciliationTerminal {
                outcome: DispatchOutcome::Failed,
                evidence_digest: faultloom_gateway::Digest::of(b"control terminal evidence"),
                nonce: nonce(0x84),
                resolved_at_millis: now_millis(),
            },
        )
        .expect("issue control-plane reconciliation");

    let unbound_dispatch =
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::DispatchReceipt {
            unknown_receipt: Box::new(first_unknown.clone()),
            reconciliation: dispatch_reconciliation.clone(),
        }));
    let control_with_dispatch_evidence =
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::ControlPlane {
            reconciliation: dispatch_reconciliation,
        }));
    let dispatch_with_control_evidence =
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::DispatchReceipt {
            unknown_receipt: Box::new(first_unknown),
            reconciliation: control_reconciliation,
        }));

    for invalid in [
        unbound_dispatch,
        control_with_dispatch_evidence,
        dispatch_with_control_evidence,
    ] {
        assert_eq!(invalid.to_bytes(), Err(DenialCode::InvalidRequest));
    }
}

#[test]
fn reconciliation_commands_and_receipts_reject_zero_or_active_egress_ids() {
    let unknown = unknown_receipt("zero", 0x74);
    let mut reconciliation = reconciliation_authority()
        .issue(
            &unknown,
            DispatchOutcome::Failed,
            faultloom_gateway::Digest::of(b"terminal evidence"),
            nonce(0x85),
            unknown.completed_at_millis + 1,
        )
        .expect("issue reconciliation");
    reconciliation.reconciliation_id = faultloom_gateway::Digest::ZERO;

    let command =
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::DispatchReceipt {
            unknown_receipt: Box::new(unknown),
            reconciliation,
        }));
    let zero_id = SupervisorResponse::Control(SupervisorControlReceipt::HoldReconciled {
        reconciliation_id: faultloom_gateway::Digest::ZERO,
        removed_prepared_dispatches: 0,
        egress_disposition: ControlEgressDisposition::NoActiveEgress,
    });
    let active_egress = SupervisorResponse::Control(SupervisorControlReceipt::HoldReconciled {
        reconciliation_id: faultloom_gateway::Digest::of(b"reconciliation receipt"),
        removed_prepared_dispatches: 0,
        egress_disposition: ControlEgressDisposition::TargetOutcomeUnknown,
    });

    assert_eq!(command.to_bytes(), Err(DenialCode::InvalidRequest));
    assert_eq!(zero_id.to_bytes(), Err(DenialCode::InvalidRequest));
    assert_eq!(active_egress.to_bytes(), Err(DenialCode::InvalidRequest));
}
