use faultloom_gateway::ipc::DispatchOutcome;
use faultloom_gateway::lease::{ControlPlaneReconciliationHold, ReconciliationTerminal};
use faultloom_gateway::supervisor_protocol::{
    ControlEgressDisposition, SupervisorCommand, SupervisorControlReceipt,
    SupervisorReconciliation, SupervisorResponse,
};

use super::codec::{dispatch, nonce, now_millis};
use super::fixture::{reconciliation_authority, unknown_receipt};

#[test]
fn commands_round_trip_canonically() {
    let unknown = unknown_receipt("codec", 0x71);
    let dispatch_reconciliation = reconciliation_authority()
        .issue(
            &unknown,
            DispatchOutcome::Failed,
            faultloom_gateway::Digest::of(b"operator verified no effect"),
            nonce(0x81),
            unknown.completed_at_millis + 1,
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
                evidence_digest: faultloom_gateway::Digest::of(b"operator verified interruption"),
                nonce: nonce(0x82),
                resolved_at_millis: now_millis(),
            },
        )
        .expect("issue control-plane reconciliation");
    let commands = [
        SupervisorCommand::AdmitEpoch {
            canonical_envelope: b"canonical-epoch".to_vec(),
            verifier_receipt: b"verified-epoch".to_vec(),
        },
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "codec",
            7,
            "target:owned-loopback",
            0x44,
        ))),
        SupervisorCommand::ReconcileExpiry,
        SupervisorCommand::RecoverPendingResponse {
            original_request_id: faultloom_gateway::Digest::of(b"original request"),
        },
        SupervisorCommand::AcknowledgePendingResponse {
            original_request_id: faultloom_gateway::Digest::of(b"original request"),
            response_digest: faultloom_gateway::Digest::of(b"exact response"),
        },
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::DispatchReceipt {
            unknown_receipt: Box::new(unknown),
            reconciliation: dispatch_reconciliation,
        })),
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::ControlPlane {
            reconciliation: control_reconciliation,
        })),
    ];
    for command in commands {
        let encoded = command.to_bytes().expect("encode command");
        assert_eq!(SupervisorCommand::from_bytes(&encoded), Ok(command));
    }
}

#[test]
fn hold_reconciled_response_round_trips_with_no_active_egress() {
    let response = SupervisorResponse::Control(SupervisorControlReceipt::HoldReconciled {
        reconciliation_id: faultloom_gateway::Digest::of(b"reconciliation receipt"),
        removed_prepared_dispatches: 1,
        egress_disposition: ControlEgressDisposition::NoActiveEgress,
    });

    let encoded = response.to_bytes().expect("encode response");

    assert_eq!(SupervisorResponse::from_bytes(&encoded), Ok(response));
}
