use std::sync::{Arc, Barrier};
use std::thread;

use super::*;
use crate::ipc::{
    ActionClass, ActionKind, DispatchReceipt, EgressPlane, FlowKind, RequiredFeature,
};

const NOW: u64 = 1_000_000;

include!("fixtures_core.rs");
include!("fixtures_reconciliation.rs");
include!("authentication_and_holds.rs");
include!("preflight_holds.rs");
include!("reconciliation_resolution.rs");
include!("reconciliation_grants.rs");
include!("proof_and_bindings.rs");
include!("reservation_accounting.rs");
include!("failure_state.rs");
include!("retry_recovery.rs");
include!("revocation_and_intents.rs");
include!("checkpoint_restore.rs");
include!("recovery_rejection.rs");
