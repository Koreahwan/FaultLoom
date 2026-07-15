#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopePolicyError {
    InvalidIdentifier,
    DuplicateIdentifier,
    InvalidHostPattern,
    InvalidNetwork,
    InvalidPort,
    InvalidProtocol,
    InvalidMethod,
    InvalidPathPattern,
    InvalidTimeWindow,
    EmptyRequiredAllowlist,
}
