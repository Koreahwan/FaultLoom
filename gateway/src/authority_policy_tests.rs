use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::ipc::ActionClass;
use crate::lease::GrantBudget;

use super::test_support::{
    NOT_BEFORE_MILLIS, authority_key, grant_payload, signed_grant, trust_store,
};
use super::{
    AuthorityError, AuthorityVerifier, RequestedSelection, RequestedSelectionParts,
    authorize_selection,
};

fn selection_parts() -> RequestedSelectionParts {
    RequestedSelectionParts {
        target_id: "target-alpha".to_owned(),
        hostname: "loopback.test".to_owned(),
        socket: SocketAddr::from(([127, 0, 0, 1], 8080)),
        protocol: "http".to_owned(),
        pack_id: "web".to_owned(),
        action_family: "semantic-http".to_owned(),
        identity_id: "identity-alpha".to_owned(),
        tenant_id: Some("tenant-alpha".to_owned()),
    }
}

fn selection() -> RequestedSelection {
    RequestedSelection::from_untrusted_parts(selection_parts()).expect("valid selection")
}

fn verified(payload: &serde_json::Value) -> super::VerifiedAuthorityGrant {
    let signer = authority_key(7);
    let trust = trust_store(&[&signer], &signer, 3);
    let raw = signed_grant(payload, &signer);
    AuthorityVerifier::verify(&raw, &trust, NOT_BEFORE_MILLIS, 300_000).expect("verified authority")
}

#[test]
fn selection_rejects_a_socket_not_contained_in_the_signed_cidr() {
    // Given: a signed hostname target whose CIDR list is empty.
    let mut payload = grant_payload();
    payload["targets"][0]["cidrs"] = serde_json::json!([]);
    let grant = verified(&payload);

    // When: loopback is proposed solely from the hostname.
    let result = authorize_selection(&grant, selection());

    // Then: T18 never treats caller-provided hostname resolution as authority.
    assert!(matches!(result, Err(AuthorityError::NetworkNotAuthorized)));
}

#[test]
fn selection_rejects_a_port_wider_than_the_signed_target() {
    // Given: an exact signed target selection.
    let grant = verified(&grant_payload());
    let mut parts = selection_parts();
    parts.socket.set_port(8081);
    let widened = RequestedSelection::from_untrusted_parts(parts).expect("syntactic selection");

    // When: the caller widens only the destination port.
    let result = authorize_selection(&grant, widened);

    // Then: the target port allowlist remains authoritative.
    assert!(matches!(
        result,
        Err(AuthorityError::SelectionNotAuthorized)
    ));
}

#[test]
fn selection_rejects_an_empty_method_intersection() {
    // Given: target and action policies with disjoint methods.
    let mut payload = grant_payload();
    payload["action_policy"]["allowed_methods"] = serde_json::json!(["DELETE"]);
    let grant = verified(&payload);

    // When: the selected target is narrowed into a runtime policy.
    let result = authorize_selection(&grant, selection());

    // Then: no policy with an impossible method intersection is emitted.
    assert!(matches!(
        result,
        Err(AuthorityError::EmptyMethodIntersection)
    ));
}

#[test]
fn selection_rejects_an_empty_path_intersection() {
    // Given: target and action policies with disjoint paths.
    let mut payload = grant_payload();
    payload["action_policy"]["allowed_path_patterns"] = serde_json::json!(["/other/*"]);
    let grant = verified(&payload);

    // When: the selected target is narrowed into a runtime policy.
    let result = authorize_selection(&grant, selection());

    // Then: no policy with an impossible path intersection is emitted.
    assert!(matches!(result, Err(AuthorityError::EmptyPathIntersection)));
}

#[test]
fn selected_policy_preserves_every_overlapping_explicit_deny() {
    // Given: a signed deny that overlaps the exact selected target.
    let payload = grant_payload();
    let grant = verified(&payload);

    // When: the signed grant is narrowed to one runtime target.
    let authorized = authorize_selection(&grant, selection()).expect("authorized selection");

    // Then: the deny survives unchanged and remains ahead of every allow.
    let denies = &authorized.scope_policy().denied;
    assert_eq!(denies.len(), 1);
    assert_eq!(denies[0].deny_id, "deny-admin");
    assert_eq!(denies[0].path_pattern.as_deref(), Some("/api/admin/*"));
    assert_eq!(denies[0].methods, ["POST"]);
}

#[test]
fn state_change_family_requires_both_signed_policies() {
    // Given: action policy allows state change but state-change policy omits the family.
    let mut payload = grant_payload();
    payload["state_change_policy"]["allowed_families"] = serde_json::json!([]);
    let grant = verified(&payload);

    // When: the family is narrowed for execution.
    let authorized = authorize_selection(&grant, selection()).expect("safe classes remain valid");

    // Then: state_change is absent rather than inherited from only one policy.
    assert!(
        !authorized
            .scope_policy()
            .allowed_classes
            .contains(&crate::ipc::ActionClass::StateChange)
    );
    assert!(authorized.scope_policy().state_change_families.is_empty());
}

#[test]
fn selected_policy_narrows_every_runtime_dimension_to_the_exact_selection() {
    // Given: a signed target CIDR and multi-value action allowlists.
    let grant = verified(&grant_payload());

    // When: one concrete target selection is authorized.
    let authorized = authorize_selection(&grant, selection()).expect("authorized selection");

    // Then: the emitted runtime authority contains only that concrete selection.
    let policy = authorized.scope_policy();
    let target = &policy.targets[0];
    assert_eq!(policy.targets.len(), 1);
    assert_eq!(target.target_id, "target-alpha");
    assert_eq!(target.host_patterns, ["loopback.test"]);
    assert_eq!(target.ports, [8080]);
    assert_eq!(target.protocols, ["http"]);
    assert_eq!(policy.pack_ids, ["web"]);
    assert_eq!(policy.allowed_families, ["semantic-http"]);
    assert_eq!(policy.identities, ["identity-alpha"]);
    assert_eq!(policy.tenants, ["tenant-alpha"]);
    assert_eq!(target.networks.len(), 1);
    assert!(target.networks[0].contains(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(!target.networks[0].contains(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
}

#[test]
fn selected_policy_preserves_exact_budget_time_and_action_intersections() {
    // Given: a signed grant whose target and global action policy overlap.
    let grant = verified(&grant_payload());

    // When: the grant is projected into executable authority.
    let authorized = authorize_selection(&grant, selection()).expect("authorized selection");

    // Then: budget, time, methods, paths, and classes are exact signed intersections.
    let policy = authorized.scope_policy();
    assert_eq!(
        authorized.budget(),
        &GrantBudget {
            total_actions: 8,
            rate_per_minute: 8,
            max_concurrency: 2,
            max_request_bytes: 4_096,
            max_response_bytes: 8_192,
            max_duration_seconds: 30,
        }
    );
    assert_eq!(policy.execution_windows.len(), 1);
    assert_eq!(
        policy.execution_windows[0].starts_at_millis,
        1_893_553_500_000
    );
    assert_eq!(
        policy.execution_windows[0].ends_at_millis,
        1_893_557_045_000
    );
    assert_eq!(policy.allowed_methods, ["GET", "POST"]);
    assert_eq!(policy.allowed_path_patterns, ["/api/*"]);
    assert_eq!(
        policy.allowed_classes,
        [
            ActionClass::Observe,
            ActionClass::SafeProbe,
            ActionClass::StateChange,
        ]
    );
}

#[test]
fn nested_path_intersection_keeps_only_the_narrower_pattern() {
    // Given: target scope is broader than the signed global action path.
    let mut payload = grant_payload();
    payload["action_policy"]["allowed_path_patterns"] = serde_json::json!(["/api/v1/*"]);
    let grant = verified(&payload);

    // When: target and action paths are intersected.
    let authorized = authorize_selection(&grant, selection()).expect("authorized selection");

    // Then: the broader target path cannot widen the action policy.
    assert_eq!(
        authorized.scope_policy().allowed_path_patterns,
        ["/api/v1/*"]
    );
    assert_eq!(
        authorized.scope_policy().targets[0].path_patterns,
        ["/api/v1/*"]
    );
}

#[test]
fn exact_path_intersection_does_not_become_a_prefix_allow() {
    // Given: the signed target names one exact path inside a global prefix.
    let mut payload = grant_payload();
    payload["targets"][0]["paths"] = serde_json::json!(["/api/v1/item"]);
    let grant = verified(&payload);

    // When: target and action paths are intersected.
    let authorized = authorize_selection(&grant, selection()).expect("authorized selection");

    // Then: the exact path remains exact.
    assert_eq!(
        authorized.scope_policy().allowed_path_patterns,
        ["/api/v1/item"]
    );
}
