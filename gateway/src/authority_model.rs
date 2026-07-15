use serde::{Deserialize, Deserializer};

#[derive(Clone, Copy, Deserialize)]
enum SchemaVersion {
    #[serde(rename = "0.1.0")]
    V0_1_0,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum GrantActionClass {
    Observe,
    SafeProbe,
    StateChange,
    HighLoad,
    Destructive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TimeWindowModel {
    pub(super) starts_at: String,
    pub(super) ends_at: String,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetAssetModel {
    pub(super) target_id: String,
    pub(super) hostnames: Vec<String>,
    pub(super) cidrs: Vec<String>,
    pub(super) ports: Vec<u16>,
    pub(super) protocols: Vec<String>,
    pub(super) paths: Vec<String>,
    pub(super) methods: Vec<String>,
    pub(super) supporting_read_only: bool,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExplicitDenyModel {
    pub(super) deny_id: String,
    #[serde(deserialize_with = "required_option")]
    pub(super) target_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(super) host_pattern: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(super) path_pattern: Option<String>,
    pub(super) methods: Vec<String>,
    pub(super) action_families: Vec<String>,
    pub(super) reason: String,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionPolicyModel {
    pub(super) allowed_classes: Vec<GrantActionClass>,
    pub(super) allowed_families: Vec<String>,
    pub(super) allowed_methods: Vec<String>,
    pub(super) allowed_path_patterns: Vec<String>,
    pub(super) denied: Vec<ExplicitDenyModel>,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionBudgetModel {
    pub(super) total_actions: u64,
    pub(super) rate_per_minute: u64,
    pub(super) max_concurrency: u64,
    pub(super) max_request_bytes: u64,
    pub(super) max_response_bytes: u64,
    pub(super) max_duration_seconds: u64,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallbackPolicyModel {
    pub(super) owned_domains: Vec<String>,
    pub(super) maximum_ttl_seconds: u64,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderPolicyModel {
    pub(super) allowed_providers: Vec<String>,
    pub(super) allowed_model_snapshots: Vec<String>,
    pub(super) data_policy_id: String,
    pub(super) arbitrary_provider_web_tools: bool,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetentionPolicyModel {
    pub(super) policy_id: String,
    pub(super) retain_until: String,
    pub(super) delete_after_seconds: u64,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StateChangePolicyModel {
    pub(super) allowed_families: Vec<String>,
    pub(super) canary_required: bool,
    pub(super) cleanup_plan_required: bool,
    pub(super) external_messages_allowed: bool,
    pub(super) payment_or_real_asset_change_allowed: bool,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityGrantModel {
    pub(super) grant_id: String,
    pub(super) grant_version: u64,
    pub(super) draft_digest: String,
    pub(super) issued_at: String,
    pub(super) not_before: String,
    pub(super) expires_at: String,
    pub(super) issued_to: String,
    pub(super) approved_by: String,
    pub(super) targets: Vec<TargetAssetModel>,
    pub(super) pack_ids: Vec<String>,
    pub(super) adapter_ids: Vec<String>,
    pub(super) action_policy: ActionPolicyModel,
    pub(super) identities: Vec<String>,
    pub(super) roles: Vec<String>,
    pub(super) tenants: Vec<String>,
    pub(super) execution_windows: Vec<TimeWindowModel>,
    pub(super) budget: ActionBudgetModel,
    pub(super) callback_policy: CallbackPolicyModel,
    pub(super) provider_policy: ProviderPolicyModel,
    pub(super) retention_policy: RetentionPolicyModel,
    pub(super) state_change_policy: StateChangePolicyModel,
    pub(super) emergency_contact_ref: String,
    #[serde(rename = "schema_version")]
    _schema_version: SchemaVersion,
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
