use super::response::DecodeError;
use super::tags::DenialCode;

pub(super) fn denial_code(value: u8) -> Result<DenialCode, DecodeError> {
    let reason = match value {
        1 => DenialCode::MalformedFrame,
        2 => DenialCode::UnknownActionKind,
        3 => DenialCode::UnsupportedActionClass,
        4 => DenialCode::UnknownRequiredFeature,
        5 => DenialCode::InvalidRequest,
        6 => DenialCode::StateChangeContractMissing,
        7 => DenialCode::ScopeVerifierUnavailable,
        8 => DenialCode::ScopeDenied,
        9 => DenialCode::LeaseVerifierUnavailable,
        10 => DenialCode::LeaseDenied,
        11 => DenialCode::CompilerUnavailable,
        12 => DenialCode::CompilerDenied,
        13 => DenialCode::VerificationBindingMismatch,
        14 => DenialCode::ScopeEpochUnavailable,
        15 => DenialCode::ScopeEpochStale,
        16 => DenialCode::ScopeEpochRevoked,
        17 => DenialCode::ScopeEpochExpired,
        18 => DenialCode::ExplicitScopeDeny,
        19 => DenialCode::ScopeTargetDenied,
        20 => DenialCode::ScopeActionDenied,
        21 => DenialCode::ScopeIdentityDenied,
        22 => DenialCode::ScopeTenantDenied,
        23 => DenialCode::ScopeTimeDenied,
        24 => DenialCode::InvalidChildFlow,
        25 => DenialCode::ScopeProofInvalid,
        26 => DenialCode::LeaseBindingMismatch,
        27 => DenialCode::LeaseNotYetValid,
        28 => DenialCode::LeaseExpired,
        29 => DenialCode::LeaseReplay,
        30 => DenialCode::GrantBudgetExhausted,
        31 => DenialCode::LeaseRateExceeded,
        32 => DenialCode::LeaseConcurrencyExceeded,
        33 => DenialCode::LeaseReservationExceeded,
        34 => DenialCode::LeaseReconciliationRequired,
        35 => DenialCode::LeaseAccountingUnavailable,
        36 => DenialCode::InvalidEgressPlane,
        37 => DenialCode::IpcAuthenticationRequired,
        38 => DenialCode::IpcAuthenticationFailed,
        39 => DenialCode::IpcSessionExpired,
        40 => DenialCode::IpcReplay,
        41 => DenialCode::LeaseRevoked,
        42 => DenialCode::RecoveryCheckpointInvalid,
        43 => DenialCode::RetryAliasInvalid,
        44 => DenialCode::DurabilityUnavailable,
        45 => DenialCode::DurabilityAnchorMismatch,
        46 => DenialCode::PendingResponseUnacknowledged,
        _ => {
            return Err(DecodeError {
                action_id: None,
                reason: DenialCode::MalformedFrame,
            });
        }
    };
    Ok(reason)
}
