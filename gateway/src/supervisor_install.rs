use crate::ipc::DenialCode;
use crate::lease::GrantBudget;

use super::supervisor_journal::MAX_DURABLE_RESPONSE_SLOTS;

pub(crate) const SUPERVISOR_BOOTSTRAP_FD: &str = "3";
pub(crate) const SUPERVISOR_JOURNAL_WRITE_FD: &str = "4";
pub(crate) const SUPERVISOR_JOURNAL_READ_FD: &str = "5";
pub(crate) const MAX_SUPERVISOR_BOOTSTRAP_BYTES_U64: u64 = 65_536;

pub(crate) fn validate_response_capacity(budget: &GrantBudget) -> Result<(), DenialCode> {
    let maximum =
        u64::try_from(MAX_DURABLE_RESPONSE_SLOTS).map_err(|_| DenialCode::InvalidRequest)?;
    if (1..=maximum).contains(&budget.total_actions) {
        Ok(())
    } else {
        Err(DenialCode::InvalidRequest)
    }
}
