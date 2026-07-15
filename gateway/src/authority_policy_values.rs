use std::net::IpAddr;

use crate::ipc::ActionClass;
use crate::lease::GrantBudget;
use crate::scope::ExplicitDenyRule;

use super::AuthorityError;
use super::model::{AuthorityGrantModel, GrantActionClass};

pub(super) fn intersect_exact(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .filter(|value| right.contains(value))
        .cloned()
        .collect()
}

pub(super) fn intersect_paths(left: &[String], right: &[String]) -> Vec<String> {
    let mut intersection = Vec::new();
    for left_pattern in left {
        for right_pattern in right {
            if let Some(pattern) = intersect_path(left_pattern, right_pattern)
                && !intersection.contains(&pattern)
            {
                intersection.push(pattern);
            }
        }
    }
    intersection
}

fn intersect_path(left: &str, right: &str) -> Option<String> {
    match (left.strip_suffix('*'), right.strip_suffix('*')) {
        (None, None) => (left == right).then(|| left.to_owned()),
        (None, Some(right_prefix)) => left.starts_with(right_prefix).then(|| left.to_owned()),
        (Some(left_prefix), None) => right.starts_with(left_prefix).then(|| right.to_owned()),
        (Some(left_prefix), Some(right_prefix)) if left_prefix.starts_with(right_prefix) => {
            Some(left.to_owned())
        }
        (Some(left_prefix), Some(right_prefix)) if right_prefix.starts_with(left_prefix) => {
            Some(right.to_owned())
        }
        (Some(_), Some(_)) => None,
    }
}

pub(super) fn map_classes(
    classes: &[GrantActionClass],
) -> Result<Vec<ActionClass>, AuthorityError> {
    classes
        .iter()
        .map(|class| match class {
            GrantActionClass::Observe => Ok(ActionClass::Observe),
            GrantActionClass::SafeProbe => Ok(ActionClass::SafeProbe),
            GrantActionClass::StateChange => Ok(ActionClass::StateChange),
            GrantActionClass::HighLoad | GrantActionClass::Destructive => {
                Err(AuthorityError::UnsupportedActionClass)
            }
        })
        .collect()
}

pub(super) fn map_denies(model: &AuthorityGrantModel) -> Vec<ExplicitDenyRule> {
    model
        .action_policy
        .denied
        .iter()
        .map(|deny| ExplicitDenyRule {
            deny_id: deny.deny_id.clone(),
            target_id: deny.target_id.clone(),
            host_pattern: deny.host_pattern.clone(),
            path_pattern: deny.path_pattern.clone(),
            methods: deny.methods.clone(),
            action_families: deny.action_families.clone(),
        })
        .collect()
}

pub(super) fn map_budget(model: &AuthorityGrantModel) -> GrantBudget {
    GrantBudget {
        total_actions: model.budget.total_actions,
        rate_per_minute: model.budget.rate_per_minute,
        max_concurrency: model.budget.max_concurrency,
        max_request_bytes: model.budget.max_request_bytes,
        max_response_bytes: model.budget.max_response_bytes,
        max_duration_seconds: model.budget.max_duration_seconds,
    }
}

pub(super) fn host_matches(pattern: &str, hostname: &str) -> bool {
    pattern.strip_prefix("*.").map_or_else(
        || pattern == hostname,
        |suffix| {
            hostname != suffix
                && hostname
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        },
    )
}

pub(super) fn is_network_address(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(address) & mask == u32::from(address)
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(address) & mask == u128::from(address)
        }
        IpAddr::V4(_) | IpAddr::V6(_) => false,
    }
}
