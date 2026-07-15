use std::net::IpAddr;

use crate::Digest;
use crate::ipc::ActionClass;
use crate::lease::GrantBudget;
use crate::scope::{IpNetwork, ScopePolicy, TargetRule, TimeWindow};

use super::model::{AuthorityGrantModel, TargetAssetModel};
use super::policy_values::{
    host_matches, intersect_exact, intersect_paths, is_network_address, map_budget, map_classes,
    map_denies,
};
use super::{AuthorityError, RequestedSelection, VerifiedAuthorityGrant};

pub(crate) struct AuthorizedRunPolicy {
    selection: RequestedSelection,
    scope_policy: ScopePolicy,
    budget: GrantBudget,
    authority_key_id: String,
    authority_payload_digest: Digest,
    signed_grant_digest: Digest,
    trust_generation: u64,
}

impl AuthorizedRunPolicy {
    pub(crate) const fn selection(&self) -> &RequestedSelection {
        &self.selection
    }

    pub(crate) const fn scope_policy(&self) -> &ScopePolicy {
        &self.scope_policy
    }

    pub(crate) const fn budget(&self) -> &GrantBudget {
        &self.budget
    }

    pub(crate) fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    pub(crate) const fn authority_payload_digest(&self) -> Digest {
        self.authority_payload_digest
    }

    pub(crate) const fn signed_grant_digest(&self) -> Digest {
        self.signed_grant_digest
    }

    pub(crate) const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }
}

pub(crate) fn authorize_selection(
    grant: &VerifiedAuthorityGrant,
    selection: RequestedSelection,
) -> Result<AuthorizedRunPolicy, AuthorityError> {
    let model = &grant.model;
    let target = model
        .targets
        .iter()
        .find(|candidate| candidate.target_id == selection.target_id())
        .ok_or(AuthorityError::SelectionNotAuthorized)?;
    validate_selection(model, target, &selection)?;
    let methods = intersect_exact(&target.methods, &model.action_policy.allowed_methods);
    if methods.is_empty() {
        return Err(AuthorityError::EmptyMethodIntersection);
    }
    let paths = intersect_paths(&target.paths, &model.action_policy.allowed_path_patterns);
    if paths.is_empty() {
        return Err(AuthorityError::EmptyPathIntersection);
    }
    let mut classes = map_classes(&model.action_policy.allowed_classes)?;
    if target.supporting_read_only {
        classes.retain(|class| *class == ActionClass::Observe);
    }
    let state_change_allowed = model
        .state_change_policy
        .allowed_families
        .iter()
        .any(|family| family == selection.action_family());
    if !state_change_allowed {
        classes.retain(|class| *class != ActionClass::StateChange);
    }
    if classes.is_empty() {
        return Err(AuthorityError::SelectionNotAuthorized);
    }
    let exact_network = IpNetwork::new(
        selection.socket().ip(),
        if selection.socket().is_ipv4() {
            32
        } else {
            128
        },
    )
    .map_err(|_| AuthorityError::InvalidProtocol)?;
    let scope_policy = ScopePolicy {
        grant_id: model.grant_id.clone(),
        grant_version: model.grant_version,
        targets: vec![TargetRule {
            target_id: target.target_id.clone(),
            host_patterns: vec![selection.hostname().to_owned()],
            networks: vec![exact_network],
            ports: vec![selection.socket().port()],
            protocols: vec![selection.protocol().to_owned()],
            path_patterns: paths.clone(),
            methods: methods.clone(),
            supporting_read_only: target.supporting_read_only,
        }],
        pack_ids: vec![selection.pack_id().to_owned()],
        allowed_classes: classes.clone(),
        allowed_families: vec![selection.action_family().to_owned()],
        allowed_methods: methods,
        allowed_path_patterns: paths,
        denied: map_denies(model),
        identities: vec![selection.identity_id().to_owned()],
        tenants: selection
            .tenant_id()
            .map(str::to_owned)
            .into_iter()
            .collect(),
        execution_windows: grant.execution_windows.clone(),
        state_change_families: classes
            .contains(&ActionClass::StateChange)
            .then(|| selection.action_family().to_owned())
            .into_iter()
            .collect(),
    };
    scope_policy
        .validate()
        .map_err(|_| AuthorityError::InvalidProtocol)?;
    Ok(AuthorizedRunPolicy {
        selection,
        scope_policy,
        budget: map_budget(model),
        authority_key_id: grant.authority_key_id.clone(),
        authority_payload_digest: grant.payload_digest,
        signed_grant_digest: grant.envelope_digest,
        trust_generation: grant.trust_generation,
    })
}

pub(super) fn validate_grant_scope(
    model: &AuthorityGrantModel,
    windows: &[TimeWindow],
) -> Result<(), AuthorityError> {
    let policy = ScopePolicy {
        grant_id: model.grant_id.clone(),
        grant_version: model.grant_version,
        targets: model
            .targets
            .iter()
            .map(map_target)
            .collect::<Result<Vec<_>, AuthorityError>>()?,
        pack_ids: model.pack_ids.clone(),
        allowed_classes: map_classes(&model.action_policy.allowed_classes)?,
        allowed_families: model.action_policy.allowed_families.clone(),
        allowed_methods: model.action_policy.allowed_methods.clone(),
        allowed_path_patterns: model.action_policy.allowed_path_patterns.clone(),
        denied: map_denies(model),
        identities: model.identities.clone(),
        tenants: model.tenants.clone(),
        execution_windows: windows.to_vec(),
        state_change_families: intersect_exact(
            &model.action_policy.allowed_families,
            &model.state_change_policy.allowed_families,
        ),
    };
    policy
        .validate()
        .map_err(|_| AuthorityError::InvalidProtocol)
}

fn validate_selection(
    model: &AuthorityGrantModel,
    target: &TargetAssetModel,
    selection: &RequestedSelection,
) -> Result<(), AuthorityError> {
    let networks = parse_networks(&target.cidrs)?;
    if networks.is_empty()
        || !networks
            .iter()
            .any(|network| network.contains(selection.socket().ip()))
    {
        return Err(AuthorityError::NetworkNotAuthorized);
    }
    let tenant_allowed = match selection.tenant_id() {
        Some(tenant) => model.tenants.iter().any(|allowed| allowed == tenant),
        None => model.tenants.is_empty(),
    };
    if !target
        .hostnames
        .iter()
        .any(|pattern| host_matches(pattern, selection.hostname()))
        || !target.ports.contains(&selection.socket().port())
        || !target
            .protocols
            .iter()
            .any(|value| value == selection.protocol())
        || !model
            .pack_ids
            .iter()
            .any(|value| value == selection.pack_id())
        || !model
            .action_policy
            .allowed_families
            .iter()
            .any(|value| value == selection.action_family())
        || !model
            .identities
            .iter()
            .any(|value| value == selection.identity_id())
        || !tenant_allowed
    {
        return Err(AuthorityError::SelectionNotAuthorized);
    }
    Ok(())
}

fn map_target(target: &TargetAssetModel) -> Result<TargetRule, AuthorityError> {
    Ok(TargetRule {
        target_id: target.target_id.clone(),
        host_patterns: target.hostnames.clone(),
        networks: parse_networks(&target.cidrs)?,
        ports: target.ports.clone(),
        protocols: target.protocols.clone(),
        path_patterns: target.paths.clone(),
        methods: target.methods.clone(),
        supporting_read_only: target.supporting_read_only,
    })
}

fn parse_networks(cidrs: &[String]) -> Result<Vec<IpNetwork>, AuthorityError> {
    let mut networks = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        let (address_text, prefix_text) = cidr
            .split_once('/')
            .ok_or(AuthorityError::InvalidProtocol)?;
        let address = address_text
            .parse::<IpAddr>()
            .map_err(|_| AuthorityError::InvalidProtocol)?;
        let prefix = prefix_text
            .parse::<u8>()
            .map_err(|_| AuthorityError::InvalidProtocol)?;
        if address_text != address.to_string()
            || prefix_text != prefix.to_string()
            || !is_network_address(address, prefix)
        {
            return Err(AuthorityError::InvalidProtocol);
        }
        let network =
            IpNetwork::new(address, prefix).map_err(|_| AuthorityError::InvalidProtocol)?;
        if networks.contains(&network) {
            return Err(AuthorityError::InvalidProtocol);
        }
        networks.push(network);
    }
    Ok(networks)
}
