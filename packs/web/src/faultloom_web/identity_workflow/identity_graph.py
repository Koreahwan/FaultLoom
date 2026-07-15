"""Consistent identity graph construction."""

from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator

from faultloom_protocol import (
    IdentityGraph,
    IdentityProfile,
    IdentityRelationship,
    RoleGrant,
    SCHEMA_VERSION,
    TenantRef,
)
from faultloom_protocol.base import Identifier

from ._base import IdentityWorkflowModel
from .errors import IdentityWorkflowError


class IdentityGraphSeed(IdentityWorkflowModel):
    graph_id: Identifier
    run_id: Identifier
    identities: tuple[IdentityProfile, ...] = Field(min_length=1)
    tenants: tuple[TenantRef, ...] = Field(min_length=1)
    role_grants: tuple[RoleGrant, ...]
    relationships: tuple[IdentityRelationship, ...]
    version: int = Field(ge=1)

    @model_validator(mode="after")
    def _references_are_closed(self) -> Self:
        identity_ids = {profile.identity_id for profile in self.identities}
        tenant_ids = {tenant.tenant_id for tenant in self.tenants}
        grant_ids = {grant.role_grant_id for grant in self.role_grants}
        relationship_ids = {
            relationship.relationship_id for relationship in self.relationships
        }
        if len(identity_ids) != len(self.identities):
            raise IdentityWorkflowError(
                code="identity.graph_duplicate_identity",
                detail="identity graph profile IDs must be unique",
            )
        if len(tenant_ids) != len(self.tenants):
            raise IdentityWorkflowError(
                code="identity.graph_duplicate_tenant",
                detail="identity graph tenant IDs must be unique",
            )
        if len(grant_ids) != len(self.role_grants):
            raise IdentityWorkflowError(
                code="identity.graph_duplicate_grant",
                detail="identity graph role grant IDs must be unique",
            )
        if len(relationship_ids) != len(self.relationships):
            raise IdentityWorkflowError(
                code="identity.graph_duplicate_relationship",
                detail="identity relationship IDs must be unique",
            )
        if any(
            not set(profile.tenant_ids).issubset(tenant_ids)
            for profile in self.identities
        ):
            raise IdentityWorkflowError(
                code="identity.graph_profile_tenant_dangling",
                detail="identity profiles must reference graph tenants",
            )
        if any(
            tenant.parent_tenant_id is not None
            and tenant.parent_tenant_id not in tenant_ids
            for tenant in self.tenants
        ):
            raise IdentityWorkflowError(
                code="identity.graph_parent_missing",
                detail="tenant parent references must stay inside the graph",
            )
        if any(
            grant.identity_id not in identity_ids or grant.tenant_id not in tenant_ids
            for grant in self.role_grants
        ):
            raise IdentityWorkflowError(
                code="identity.graph_grant_dangling",
                detail="role grants must reference graph identities and tenants",
            )
        active_roles = {
            (grant.identity_id, grant.role_id)
            for grant in self.role_grants
            if grant.revoked_at is None
        }
        if any(
            (profile.identity_id, role_id) not in active_roles
            for profile in self.identities
            for role_id in profile.role_ids
        ):
            raise IdentityWorkflowError(
                code="identity.graph_profile_role_unbound",
                detail="profile roles require active grants in each profile tenant",
            )
        known_nodes = identity_ids | tenant_ids
        if any(
            relationship.source_id not in known_nodes
            or relationship.target_id not in known_nodes
            for relationship in self.relationships
        ):
            raise IdentityWorkflowError(
                code="identity.graph_relationship_dangling",
                detail="identity relationships must reference graph nodes",
            )
        return self


def build_identity_graph(seed: IdentityGraphSeed) -> IdentityGraph:
    """Build a stable graph independent of discovery ordering."""

    return IdentityGraph(
        schema_version=SCHEMA_VERSION,
        graph_id=seed.graph_id,
        run_id=seed.run_id,
        identities=tuple(sorted(seed.identities, key=lambda item: item.identity_id)),
        tenants=tuple(sorted(seed.tenants, key=lambda item: item.tenant_id)),
        role_grants=tuple(
            sorted(seed.role_grants, key=lambda item: item.role_grant_id)
        ),
        relationships=tuple(
            sorted(seed.relationships, key=lambda item: item.relationship_id)
        ),
        version=seed.version,
    )
