use crate::ipc::ActionClass;

use super::network::IpNetwork;

mod validation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeWindow {
    pub starts_at_millis: u64,
    pub ends_at_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetRule {
    pub target_id: String,
    pub host_patterns: Vec<String>,
    pub networks: Vec<IpNetwork>,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub path_patterns: Vec<String>,
    pub methods: Vec<String>,
    pub supporting_read_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitDenyRule {
    pub deny_id: String,
    pub target_id: Option<String>,
    pub host_pattern: Option<String>,
    pub path_pattern: Option<String>,
    pub methods: Vec<String>,
    pub action_families: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopePolicy {
    pub grant_id: String,
    pub grant_version: u64,
    pub targets: Vec<TargetRule>,
    pub pack_ids: Vec<String>,
    pub allowed_classes: Vec<ActionClass>,
    pub allowed_families: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_path_patterns: Vec<String>,
    pub denied: Vec<ExplicitDenyRule>,
    pub identities: Vec<String>,
    pub tenants: Vec<String>,
    pub execution_windows: Vec<TimeWindow>,
    pub state_change_families: Vec<String>,
}
