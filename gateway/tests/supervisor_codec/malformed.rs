use faultloom_gateway::ipc::DenialCode;
use faultloom_gateway::supervisor_protocol::SupervisorCommand;

use super::codec::dispatch;

#[test]
fn command_encoders_reject_values_the_decoders_cannot_accept() {
    let oversized_epoch = SupervisorCommand::AdmitEpoch {
        canonical_envelope: vec![0_u8; 36_865],
        verifier_receipt: vec![1_u8; 1],
    };
    assert_eq!(oversized_epoch.to_bytes(), Err(DenialCode::InvalidRequest));

    let mut oversized_dispatch = dispatch("oversized", 7, "target:owned-loopback", 0x45);
    oversized_dispatch.payload = vec![0_u8; 32_769];
    assert_eq!(
        SupervisorCommand::Dispatch(Box::new(oversized_dispatch)).to_bytes(),
        Err(DenialCode::InvalidRequest)
    );
}

#[test]
fn command_decoders_reject_tamper_truncation_and_trailing_bytes() {
    let command_frame = SupervisorCommand::Dispatch(Box::new(dispatch(
        "malformed",
        7,
        "target:owned-loopback",
        0x46,
    )))
    .to_bytes()
    .expect("encode dispatch");
    reject_command_mutations(&command_frame);
}

fn reject_command_mutations(frame: &[u8]) {
    let mut wrong_magic = frame.to_vec();
    wrong_magic[0] ^= 0xff;
    assert_eq!(
        SupervisorCommand::from_bytes(&wrong_magic),
        Err(DenialCode::MalformedFrame)
    );
    assert_eq!(
        SupervisorCommand::from_bytes(&frame[..frame.len() - 1]),
        Err(DenialCode::MalformedFrame)
    );
    let mut trailing = frame.to_vec();
    trailing.push(0);
    assert_eq!(
        SupervisorCommand::from_bytes(&trailing),
        Err(DenialCode::MalformedFrame)
    );
}
