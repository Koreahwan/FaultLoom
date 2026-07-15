use std::collections::BTreeSet;

use crate::ipc::valid_identifier;
use crate::protocol_time::ProtocolTime;
use crate::scope::TimeWindow;
use crate::signed_protocol::VerifiedSignedEnvelope;
use crate::signed_protocol_parse::valid_prefixed_hex;

use super::AuthorityError;
use super::model::{AuthorityGrantModel, GrantActionClass};

pub(super) struct ValidatedGrantTimes {
    pub(super) execution_windows: Vec<TimeWindow>,
}

pub(super) fn validate_grant_semantics(
    grant: &AuthorityGrantModel,
    envelope: &VerifiedSignedEnvelope,
    now: ProtocolTime,
) -> Result<ValidatedGrantTimes, AuthorityError> {
    let issued_at = parse_time(&grant.issued_at)?;
    let not_before = parse_time(&grant.not_before)?;
    let expires_at = parse_time(&grant.expires_at)?;
    if not_before < issued_at || expires_at <= not_before {
        return Err(AuthorityError::InvalidValidity);
    }
    if envelope.sequence() != grant.grant_version
        || envelope.signed_at() < issued_at
        || envelope.expires_at() != expires_at
    {
        return Err(AuthorityError::InvalidEnvelope);
    }
    if now < not_before {
        return Err(AuthorityError::NotYetValid);
    }
    if now >= expires_at {
        return Err(AuthorityError::Expired);
    }
    validate_shape(grant)?;
    let execution_windows = intersect_windows(grant, not_before, expires_at)?;
    Ok(ValidatedGrantTimes { execution_windows })
}

fn validate_shape(grant: &AuthorityGrantModel) -> Result<(), AuthorityError> {
    if grant.grant_version == 0
        || !valid_identifier(&grant.grant_id)
        || !valid_prefixed_hex(&grant.draft_digest, "sha256:")
        || !valid_identifier(&grant.issued_to)
        || !valid_identifier(&grant.approved_by)
        || !valid_identifier(&grant.emergency_contact_ref)
        || grant.targets.is_empty()
        || grant.execution_windows.is_empty()
        || !valid_identifiers(&grant.pack_ids, true)
        || !valid_identifiers(&grant.adapter_ids, false)
        || !valid_identifiers(&grant.identities, true)
        || !valid_identifiers(&grant.roles, false)
        || !valid_identifiers(&grant.tenants, false)
        || !valid_budget(grant)
        || grant.callback_policy.maximum_ttl_seconds == 0
        || !valid_short_strings(&grant.callback_policy.owned_domains)
        || !valid_identifiers(&grant.provider_policy.allowed_providers, false)
        || !valid_short_strings(&grant.provider_policy.allowed_model_snapshots)
        || !valid_identifier(&grant.provider_policy.data_policy_id)
        || grant.provider_policy.arbitrary_provider_web_tools
        || !valid_identifier(&grant.retention_policy.policy_id)
        || ProtocolTime::parse_canonical(&grant.retention_policy.retain_until).is_err()
        || grant.retention_policy.delete_after_seconds != 0
        || !valid_identifiers(&grant.state_change_policy.allowed_families, false)
        || !grant.state_change_policy.canary_required
        || !grant.state_change_policy.cleanup_plan_required
        || grant.state_change_policy.external_messages_allowed
        || grant
            .state_change_policy
            .payment_or_real_asset_change_allowed
    {
        return Err(AuthorityError::InvalidProtocol);
    }
    if grant.action_policy.allowed_classes.iter().any(|class| {
        matches!(
            class,
            GrantActionClass::HighLoad | GrantActionClass::Destructive
        )
    }) {
        return Err(AuthorityError::UnsupportedActionClass);
    }
    if grant
        .action_policy
        .denied
        .iter()
        .any(|deny| !non_empty(&deny.reason))
    {
        return Err(AuthorityError::InvalidProtocol);
    }
    Ok(())
}

fn intersect_windows(
    grant: &AuthorityGrantModel,
    not_before: ProtocolTime,
    expires_at: ProtocolTime,
) -> Result<Vec<TimeWindow>, AuthorityError> {
    let windows = grant
        .execution_windows
        .iter()
        .map(|window| {
            let starts_at = parse_time(&window.starts_at)?;
            let ends_at = parse_time(&window.ends_at)?;
            if ends_at <= starts_at {
                return Err(AuthorityError::InvalidValidity);
            }
            let start = starts_at.max(not_before).ceil_millis();
            let end = ends_at.min(expires_at).floor_millis();
            Ok((end > start).then_some(TimeWindow {
                starts_at_millis: start,
                ends_at_millis: end,
            }))
        })
        .collect::<Result<Vec<_>, AuthorityError>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if windows.is_empty() {
        return Err(AuthorityError::InvalidValidity);
    }
    Ok(windows)
}

fn parse_time(value: &str) -> Result<ProtocolTime, AuthorityError> {
    ProtocolTime::parse_canonical(value).map_err(|_| AuthorityError::InvalidProtocol)
}

fn valid_budget(grant: &AuthorityGrantModel) -> bool {
    let budget = &grant.budget;
    budget.total_actions > 0
        && budget.rate_per_minute > 0
        && budget.max_concurrency > 0
        && budget.max_request_bytes > 0
        && budget.max_response_bytes > 0
        && budget.max_duration_seconds > 0
}

fn valid_identifiers(values: &[String], required: bool) -> bool {
    (!required || !values.is_empty())
        && values.iter().all(|value| valid_identifier(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_short_strings(values: &[String]) -> bool {
    values
        .iter()
        .all(|value| !value.is_empty() && value.len() <= 256)
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn non_empty(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4_096
}
