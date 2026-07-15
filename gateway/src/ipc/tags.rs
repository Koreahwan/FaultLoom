pub(super) const MAGIC: &[u8; 4] = b"FLGW";
pub(super) const VERSION: u8 = 5;
pub(super) const REQUEST_MESSAGE: u8 = 1;
pub(super) const RESPONSE_MESSAGE: u8 = 2;
pub const MAX_FRAME_BYTES: usize = 65_536;
pub(super) const MAX_ID_BYTES: usize = 256;
pub(super) const MAX_PROOF_BYTES: usize = 4_096;
pub(super) const MAX_PAYLOAD_BYTES: usize = 32_768;
pub(super) const MAX_FEATURES: usize = 16;
pub(super) const MAX_DISPATCH_TTL_MILLIS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ActionClass {
    Observe = 1,
    SafeProbe = 2,
    StateChange = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionKind {
    SemanticHttpV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FlowKind {
    TopLevel = 1,
    DnsResolution = 2,
    Redirect = 3,
    BrowserSubresource = 4,
    BrowserIframe = 5,
    ServiceWorker = 6,
    WebSocket = 7,
    Download = 8,
    ScannerChild = 9,
    GraphQlChild = 10,
    BatchChild = 11,
    Callback = 12,
    Polling = 13,
    RawSchedule = 14,
    PackAction = 15,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RequiredFeature {
    GatewayDispatchV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EgressPlane {
    TargetGateway = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DispatchOutcome {
    Completed = 1,
    Failed = 2,
    UnknownOutcome = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DenialCode {
    MalformedFrame = 1,
    UnknownActionKind = 2,
    UnsupportedActionClass = 3,
    UnknownRequiredFeature = 4,
    InvalidRequest = 5,
    StateChangeContractMissing = 6,
    ScopeVerifierUnavailable = 7,
    ScopeDenied = 8,
    LeaseVerifierUnavailable = 9,
    LeaseDenied = 10,
    CompilerUnavailable = 11,
    CompilerDenied = 12,
    VerificationBindingMismatch = 13,
    ScopeEpochUnavailable = 14,
    ScopeEpochStale = 15,
    ScopeEpochRevoked = 16,
    ScopeEpochExpired = 17,
    ExplicitScopeDeny = 18,
    ScopeTargetDenied = 19,
    ScopeActionDenied = 20,
    ScopeIdentityDenied = 21,
    ScopeTenantDenied = 22,
    ScopeTimeDenied = 23,
    InvalidChildFlow = 24,
    ScopeProofInvalid = 25,
    LeaseBindingMismatch = 26,
    LeaseNotYetValid = 27,
    LeaseExpired = 28,
    LeaseReplay = 29,
    GrantBudgetExhausted = 30,
    LeaseRateExceeded = 31,
    LeaseConcurrencyExceeded = 32,
    LeaseReservationExceeded = 33,
    LeaseReconciliationRequired = 34,
    LeaseAccountingUnavailable = 35,
    InvalidEgressPlane = 36,
    IpcAuthenticationRequired = 37,
    IpcAuthenticationFailed = 38,
    IpcSessionExpired = 39,
    IpcReplay = 40,
    LeaseRevoked = 41,
    RecoveryCheckpointInvalid = 42,
    RetryAliasInvalid = 43,
    DurabilityUnavailable = 44,
    DurabilityAnchorMismatch = 45,
    PendingResponseUnacknowledged = 46,
}
