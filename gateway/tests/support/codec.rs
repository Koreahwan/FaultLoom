use std::time::{SystemTime, UNIX_EPOCH};

use faultloom_gateway::Digest;
use faultloom_gateway::ipc::ActionClass;
use faultloom_gateway::supervisor_protocol::SupervisorDispatch;

pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis()
        .try_into()
        .expect("millisecond clock")
}

pub(super) fn nonce(seed: u8) -> [u8; 16] {
    std::array::from_fn(|index| seed.wrapping_add(index as u8))
}

pub(super) fn dispatch(label: &str, epoch: u64, target_id: &str, seed: u8) -> SupervisorDispatch {
    let now = now_millis();
    let intent_material: &[u8] = if matches!(label, "active" | "automatic-retry") {
        b"control-intent"
    } else {
        label.as_bytes()
    };
    let payload_label = if label == "automatic-retry" {
        "active"
    } else {
        label
    };
    SupervisorDispatch {
        action_id: format!("action:{label}"),
        correlation_id: format!("correlation:{label}"),
        lease_id: format!("lease:{label}"),
        target_id: target_id.to_owned(),
        scope_epoch: epoch,
        action_class: ActionClass::Observe,
        method: "POST".to_owned(),
        path: "/probe".to_owned(),
        intent_digest: Digest::of(intent_material),
        decision_digest: Digest::of(format!("decision:{label}").as_bytes()),
        dispatch_nonce: nonce(seed),
        issued_at_millis: now,
        expires_at_millis: now + 20_000,
        retry_of_intent_digest: None,
        payload: format!("probe-{payload_label}").into_bytes(),
        canary_ref: None,
        checkpoint_ref: None,
        cleanup_plan_ref: None,
    }
}
