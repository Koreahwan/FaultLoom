from fnmatch import fnmatchcase

from faultloom_protocol import AuthorityGrant, ChainEdge, ExplicitDeny, TargetAsset

from .errors import ChainPolicyError


def validate_scope_policy(
    edge: ChainEdge,
    grant: AuthorityGrant,
    target_asset: TargetAsset,
) -> None:
    """Apply explicit-deny-first scope policy to one already leased edge."""

    intent = edge.action_intent
    policy = grant.action_policy
    if any(_deny_matches(edge, target_asset, deny) for deny in policy.denied):
        raise ChainPolicyError(
            "chain.explicit_deny",
            f"edge {edge.edge_id} matches an explicit deny",
        )
    if intent.action_class not in policy.allowed_classes:
        raise ChainPolicyError(
            "chain.action_class_not_granted",
            f"action class {intent.action_class.value} is absent from the grant",
        )
    if intent.action_kind not in policy.allowed_families:
        raise ChainPolicyError(
            "chain.action_kind_not_granted",
            f"action kind {intent.action_kind} is absent from the grant",
        )
    if policy.allowed_methods and intent.method not in policy.allowed_methods:
        raise ChainPolicyError(
            "chain.method_not_granted",
            "edge method is absent from the grant",
        )
    if policy.allowed_path_patterns and not any(
        fnmatchcase(intent.path or "", pattern)
        for pattern in policy.allowed_path_patterns
    ):
        raise ChainPolicyError(
            "chain.path_not_granted",
            "edge path is absent from the grant",
        )
    if target_asset.methods and intent.method not in target_asset.methods:
        raise ChainPolicyError(
            "chain.target_method_not_granted",
            "edge method is absent from the target asset",
        )
    if target_asset.paths and not any(
        (intent.path or "") == prefix
        or (intent.path or "").startswith(prefix.rstrip("/") + "/")
        for prefix in target_asset.paths
    ):
        raise ChainPolicyError(
            "chain.target_path_not_granted",
            "edge path is absent from the target asset",
        )


def _deny_matches(
    edge: ChainEdge,
    target_asset: TargetAsset,
    deny: ExplicitDeny,
) -> bool:
    intent = edge.action_intent
    return (
        (deny.target_id is None or deny.target_id == intent.target_id)
        and (not deny.action_families or intent.action_kind in deny.action_families)
        and (
            deny.path_pattern is None
            or fnmatchcase(intent.path or "", deny.path_pattern)
        )
        and (not deny.methods or intent.method in deny.methods)
        and (
            deny.host_pattern is None
            or any(
                fnmatchcase(host, deny.host_pattern)
                for host in target_asset.hostnames
            )
        )
    )
