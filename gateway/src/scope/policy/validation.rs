use std::collections::BTreeSet;

use crate::ipc::valid_identifier;

use super::super::error::ScopePolicyError;
use super::ScopePolicy;

impl ScopePolicy {
    pub(crate) fn validate(&self) -> Result<(), ScopePolicyError> {
        if !valid_identifier(&self.grant_id) || self.grant_version == 0 {
            return Err(ScopePolicyError::InvalidIdentifier);
        }
        validate_identifiers(&self.pack_ids, true)?;
        validate_identifiers(&self.allowed_families, true)?;
        validate_identifiers(&self.identities, true)?;
        validate_identifiers(&self.tenants, false)?;
        validate_identifiers(&self.state_change_families, false)?;
        validate_methods(&self.allowed_methods, true)?;
        validate_paths(&self.allowed_path_patterns, true)?;
        if self.allowed_classes.is_empty() || self.execution_windows.is_empty() {
            return Err(ScopePolicyError::EmptyRequiredAllowlist);
        }
        let class_count = self
            .allowed_classes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len();
        if class_count != self.allowed_classes.len() {
            return Err(ScopePolicyError::DuplicateIdentifier);
        }
        for window in &self.execution_windows {
            if window.ends_at_millis <= window.starts_at_millis {
                return Err(ScopePolicyError::InvalidTimeWindow);
            }
        }
        let mut target_ids = BTreeSet::new();
        if self.targets.is_empty() {
            return Err(ScopePolicyError::EmptyRequiredAllowlist);
        }
        for target in &self.targets {
            if !valid_identifier(&target.target_id) || !target_ids.insert(&target.target_id) {
                return Err(if valid_identifier(&target.target_id) {
                    ScopePolicyError::DuplicateIdentifier
                } else {
                    ScopePolicyError::InvalidIdentifier
                });
            }
            if target.host_patterns.is_empty() && target.networks.is_empty() {
                return Err(ScopePolicyError::EmptyRequiredAllowlist);
            }
            validate_host_patterns(&target.host_patterns)?;
            validate_unique_ports(&target.ports)?;
            validate_protocols(&target.protocols, true)?;
            validate_methods(&target.methods, true)?;
            validate_paths(&target.path_patterns, true)?;
        }
        let mut deny_ids = BTreeSet::new();
        for deny in &self.denied {
            if !valid_identifier(&deny.deny_id) || !deny_ids.insert(&deny.deny_id) {
                return Err(if valid_identifier(&deny.deny_id) {
                    ScopePolicyError::DuplicateIdentifier
                } else {
                    ScopePolicyError::InvalidIdentifier
                });
            }
            if deny
                .target_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            {
                return Err(ScopePolicyError::InvalidIdentifier);
            }
            if let Some(pattern) = &deny.host_pattern {
                validate_host_pattern(pattern)?;
            }
            if let Some(pattern) = &deny.path_pattern {
                validate_path_pattern(pattern)?;
            }
            validate_methods(&deny.methods, false)?;
            validate_identifiers(&deny.action_families, false)?;
        }
        Ok(())
    }
}

fn validate_identifiers(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.iter().any(|value| !valid_identifier(value)) {
        return Err(ScopePolicyError::InvalidIdentifier);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_unique_ports(values: &[u16]) -> Result<(), ScopePolicyError> {
    if values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.contains(&0) {
        return Err(ScopePolicyError::InvalidPort);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_protocols(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.iter().any(|value| {
        value.is_empty()
            || value.len() > 16
            || value != &value.to_ascii_lowercase()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return Err(ScopePolicyError::InvalidProtocol);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_methods(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    if values.iter().any(|value| {
        value.is_empty()
            || value.len() > 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(ScopePolicyError::InvalidMethod);
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_paths(values: &[String], required: bool) -> Result<(), ScopePolicyError> {
    if required && values.is_empty() {
        return Err(ScopePolicyError::EmptyRequiredAllowlist);
    }
    for value in values {
        validate_path_pattern(value)?;
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_path_pattern(value: &str) -> Result<(), ScopePolicyError> {
    let prefix = value.strip_suffix('*').unwrap_or(value);
    if value.is_empty()
        || value.len() > 4_096
        || !value.starts_with('/')
        || prefix.contains('*')
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte == b'#' || byte == b'?')
    {
        return Err(ScopePolicyError::InvalidPathPattern);
    }
    Ok(())
}

fn validate_host_patterns(values: &[String]) -> Result<(), ScopePolicyError> {
    for value in values {
        validate_host_pattern(value)?;
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ScopePolicyError::DuplicateIdentifier);
    }
    Ok(())
}

fn validate_host_pattern(value: &str) -> Result<(), ScopePolicyError> {
    let host = value.strip_prefix("*.").unwrap_or(value);
    if host.is_empty()
        || host.len() > 253
        || host != host.to_ascii_lowercase()
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ScopePolicyError::InvalidHostPattern);
    }
    Ok(())
}
