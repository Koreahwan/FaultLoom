"""FaultLoom v0.1 wire contracts.

The models intentionally carry references and digests instead of credentials,
request bodies, model prompts, or raw evidence. Those bytes belong in the
engagement-bound vault/CAS implemented by later tasks.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import AfterValidator, BeforeValidator, Field, model_validator

from .base import (
    AwareDatetime,
    Identifier,
    MAX_INT64,
    NonEmptyStr,
    PROTOCOL_VERSION,
    ProtocolModel,
    SecretRef,
    Sha256Digest,
    ShortStr,
)
from .canonical import sha256_digest
from .compatibility import SemVer, require_protocol_compatible
from .enum_integrity import _install_protocol_enum_catalog
from .evaluation import EVALUATION_ENUM_TYPES, EVALUATION_MODEL_TYPES
from .model_attestation_contracts import MODEL_ATTESTATION_MODEL_TYPES

Port = Annotated[int, Field(ge=1, le=65535)]
PositiveInt = Annotated[int, Field(ge=1, le=MAX_INT64)]
NonNegativeInt = Annotated[int, Field(ge=0, le=MAX_INT64)]
ConfidenceBps = Annotated[int, Field(ge=0, le=10_000)]


def _require_stable_semver(value: str) -> str:
    SemVer.parse(value)
    return value


StableSemVer = Annotated[str, AfterValidator(_require_stable_semver)]
SchemaNamespace = Annotated[
    str,
    Field(
        min_length=5,
        max_length=256,
        pattern=r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+\.v[1-9][0-9]*$",
    ),
]
UpstreamCommit = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]


def _reject_base64url_surrounding_whitespace(value: object) -> object:
    if isinstance(value, str) and value != value.strip():
        raise ValueError("URL-safe base64 cannot contain surrounding whitespace")
    return value


Base64Url = Annotated[
    str,
    BeforeValidator(_reject_base64url_surrounding_whitespace),
    Field(pattern=r"^[A-Za-z0-9_-]+$"),
]
KeyId = Annotated[str, Field(pattern=r"^ed25519:sha256:[0-9a-f]{64}$")]


def _require_nonce_entropy(value: str) -> str:
    if len(set(bytes.fromhex(value))) < 4:
        raise ValueError("nonce must contain at least four distinct bytes")
    return value


Nonce128 = Annotated[
    str,
    Field(pattern=r"^[0-9a-f]{32}$"),
    AfterValidator(_require_nonce_entropy),
]


class ActionClass(str, Enum):
    OBSERVE = "observe"
    SAFE_PROBE = "safe_probe"
    STATE_CHANGE = "state_change"
    HIGH_LOAD = "high_load"
    DESTRUCTIVE = "destructive"


class EgressPlane(str, Enum):
    TARGET_GATEWAY = "target_gateway"


class ProvenanceKind(str, Enum):
    BEHAVIOR = "behavior"
    KNOWLEDGE = "knowledge"
    TOOL = "tool"
    PATCH = "patch"
    SPECIALIST = "specialist"
    OPERATOR = "operator"


class ConfidenceClass(str, Enum):
    EXACT = "EXACT"
    SIMILAR = "SIMILAR"
    SPECULATIVE = "SPECULATIVE"


class FindingClass(str, Enum):
    CVE_REPRODUCTION = "CVE_reproduction"
    ONE_DAY_ADAPTATION = "one_day_adaptation"
    PATCH_VARIANT = "patch_variant"
    ZERO_DAY_LIKE = "zero_day_like"


class KeyValue(ProtocolModel):
    key: Identifier
    value: NonEmptyStr


class TimeWindow(ProtocolModel):
    starts_at: AwareDatetime
    ends_at: AwareDatetime

    @model_validator(mode="after")
    def _ordered(self) -> "TimeWindow":
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be later than starts_at")
        return self


class TargetAsset(ProtocolModel):
    target_id: Identifier
    hostnames: tuple[ShortStr, ...] = ()
    cidrs: tuple[ShortStr, ...] = ()
    ports: tuple[Port, ...] = ()
    protocols: tuple[ShortStr, ...] = ()
    paths: tuple[NonEmptyStr, ...] = ()
    methods: tuple[ShortStr, ...] = ()
    supporting_read_only: bool = False

    @model_validator(mode="after")
    def _has_network_identity(self) -> "TargetAsset":
        if not self.hostnames and not self.cidrs:
            raise ValueError("target must contain at least one hostname or CIDR")
        return self


class ExplicitDeny(ProtocolModel):
    deny_id: Identifier
    target_id: Identifier | None = None
    host_pattern: ShortStr | None = None
    path_pattern: NonEmptyStr | None = None
    methods: tuple[ShortStr, ...] = ()
    action_families: tuple[Identifier, ...] = ()
    reason: NonEmptyStr


class ActionPolicy(ProtocolModel):
    allowed_classes: tuple[ActionClass, ...]
    allowed_families: tuple[Identifier, ...]
    allowed_methods: tuple[ShortStr, ...] = ()
    allowed_path_patterns: tuple[NonEmptyStr, ...] = ()
    denied: tuple[ExplicitDeny, ...] = ()

    @model_validator(mode="after")
    def _v01_classes_only(self) -> "ActionPolicy":
        unsupported = {ActionClass.HIGH_LOAD, ActionClass.DESTRUCTIVE}.intersection(
            self.allowed_classes
        )
        if unsupported:
            names = ", ".join(sorted(item.value for item in unsupported))
            raise ValueError(f"unsupported v0.1 action classes cannot be allowed: {names}")
        return self


class ActionBudget(ProtocolModel):
    total_actions: PositiveInt
    rate_per_minute: PositiveInt
    max_concurrency: PositiveInt
    max_request_bytes: PositiveInt
    max_response_bytes: PositiveInt
    max_duration_seconds: PositiveInt


class CallbackPolicy(ProtocolModel):
    owned_domains: tuple[ShortStr, ...] = ()
    maximum_ttl_seconds: PositiveInt


class ProviderPolicy(ProtocolModel):
    allowed_providers: tuple[Identifier, ...]
    allowed_model_snapshots: tuple[ShortStr, ...]
    data_policy_id: Identifier
    arbitrary_provider_web_tools: Literal[False] = False


class RetentionPolicy(ProtocolModel):
    policy_id: Identifier
    retain_until: AwareDatetime
    delete_after_seconds: NonNegativeInt


class StateChangePolicy(ProtocolModel):
    allowed_families: tuple[Identifier, ...] = ()
    canary_required: Literal[True] = True
    cleanup_plan_required: Literal[True] = True
    external_messages_allowed: bool = False
    payment_or_real_asset_change_allowed: Literal[False] = False


class ScopeContractDraft(ProtocolModel):
    draft_id: Identifier
    revision: PositiveInt
    title: ShortStr
    created_at: AwareDatetime
    created_by: Identifier
    targets: tuple[TargetAsset, ...]
    adapter_ids: tuple[Identifier, ...] = ()
    action_policy: ActionPolicy
    identities: tuple[Identifier, ...]
    tenants: tuple[Identifier, ...] = ()
    execution_windows: tuple[TimeWindow, ...]
    budget: ActionBudget
    callback_policy: CallbackPolicy
    provider_policy: ProviderPolicy
    retention_policy: RetentionPolicy
    state_change_policy: StateChangePolicy
    emergency_contact_ref: Identifier
    notes: tuple[NonEmptyStr, ...] = ()
    status: Literal["draft"] = "draft"


class AuthorityGrant(ProtocolModel):
    grant_id: Identifier
    grant_version: PositiveInt
    draft_digest: Sha256Digest
    issued_at: AwareDatetime
    not_before: AwareDatetime
    expires_at: AwareDatetime
    issued_to: Identifier
    approved_by: Identifier
    targets: tuple[TargetAsset, ...]
    pack_ids: tuple[Identifier, ...]
    adapter_ids: tuple[Identifier, ...] = ()
    action_policy: ActionPolicy
    identities: tuple[Identifier, ...]
    roles: tuple[Identifier, ...] = ()
    tenants: tuple[Identifier, ...] = ()
    execution_windows: tuple[TimeWindow, ...]
    budget: ActionBudget
    callback_policy: CallbackPolicy
    provider_policy: ProviderPolicy
    retention_policy: RetentionPolicy
    state_change_policy: StateChangePolicy
    emergency_contact_ref: Identifier

    @model_validator(mode="after")
    def _validity_is_ordered(self) -> "AuthorityGrant":
        if self.not_before < self.issued_at:
            raise ValueError("not_before cannot precede issued_at")
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must be later than not_before")
        if not self.targets or not self.pack_ids or not self.execution_windows:
            raise ValueError("grant requires targets, packs, and execution windows")
        return self


class ScopeEpoch(ProtocolModel):
    grant_id: Identifier
    epoch: PositiveInt
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    revoked: bool = False
    revocation_reason: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _epoch_validity(self) -> "ScopeEpoch":
        if self.expires_at <= self.issued_at:
            raise ValueError("scope epoch expiry must follow issuance")
        if self.revoked != (self.revocation_reason is not None):
            raise ValueError("revocation_reason must be present exactly when revoked")
        return self


class SignaturePurpose(str, Enum):
    AUTHORITY_GRANT = "authority_grant"
    SCOPE_EPOCH = "scope_epoch"
    ENGAGEMENT_BUNDLE = "engagement_bundle"
    RUN_RESULT_BUNDLE = "run_result_bundle"


class SignatureBlock(ProtocolModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    protocol_version: Literal["0.1.0"] = PROTOCOL_VERSION
    purpose: SignaturePurpose
    key_id: KeyId
    sequence: PositiveInt
    signed_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    payload_digest: Sha256Digest
    signature: Base64Url

    @model_validator(mode="after")
    def _expiry_ordered(self) -> "SignatureBlock":
        if self.expires_at is not None and self.expires_at <= self.signed_at:
            raise ValueError("signature expiry must follow signing time")
        return self


class Ed25519PublicKeyRecord(ProtocolModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: KeyId
    public_key: Base64Url


class SignedAuthorityGrant(ProtocolModel):
    payload: AuthorityGrant
    signature: SignatureBlock


class SignedScopeEpoch(ProtocolModel):
    payload: ScopeEpoch
    signature: SignatureBlock


class SubjectRef(ProtocolModel):
    subject_id: Identifier
    subject_kind: Identifier
    identity_id: Identifier | None = None
    tenant_id: Identifier | None = None


class ResourceRef(ProtocolModel):
    resource_id: Identifier
    resource_kind: Identifier
    target_id: Identifier
    tenant_id: Identifier | None = None


class StateRef(ProtocolModel):
    state_id: Identifier
    state_kind: Identifier
    state_version: NonNegativeInt
    state_digest: Sha256Digest | None = None


class ActionIntent(ProtocolModel):
    action_id: Identifier
    run_id: Identifier
    target_id: Identifier
    pack_id: Identifier
    action_kind: Identifier
    action_class: ActionClass
    subject: SubjectRef
    resource: ResourceRef
    state: StateRef | None = None
    protocol: ShortStr
    method: ShortStr | None = None
    path: NonEmptyStr | None = None
    payload_digest: Sha256Digest | None = None
    requested_at: AwareDatetime
    parent_action_ids: tuple[Identifier, ...] = ()
    canary_ref: Identifier | None = None
    checkpoint_ref: Identifier | None = None
    cleanup_plan_ref: Identifier | None = None

    @model_validator(mode="after")
    def _state_change_contract(self) -> "ActionIntent":
        if self.action_class is ActionClass.STATE_CHANGE:
            if (
                self.canary_ref is None
                or self.checkpoint_ref is None
                or self.cleanup_plan_ref is None
            ):
                raise ValueError(
                    "state_change requires canary_ref, checkpoint_ref, and cleanup_plan_ref"
                )
        return self


class BudgetReservation(ProtocolModel):
    action_count: PositiveInt = 1
    request_bytes: PositiveInt
    response_bytes: NonNegativeInt = 0
    duration_seconds: PositiveInt


class ActionLease(ProtocolModel):
    lease_id: Identifier
    lease_key_id: Identifier
    action_id: Identifier
    correlation_id: Identifier
    intent_digest: Sha256Digest
    decision_digest: Sha256Digest
    grant_id: Identifier
    grant_version: PositiveInt
    scope_epoch: PositiveInt
    authority_key_id: KeyId
    scope_epoch_binding_digest: Sha256Digest
    gateway_boot_id: Identifier
    boot_challenge_digest: Sha256Digest
    target_id: Identifier
    identity_id: Identifier
    tenant_id: Identifier | None = None
    action_kind: Identifier
    semantic_action_digest: Sha256Digest
    request_binding_digest: Sha256Digest
    resolution_digest: Sha256Digest
    egress_plane: EgressPlane
    dispatch_nonce: Nonce128
    retry_of_intent_digest: Sha256Digest | None = None
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    maximum_dispatches: Literal[1] = 1
    reservation: BudgetReservation

    @model_validator(mode="after")
    def _lease_validity(self) -> "ActionLease":
        if self.expires_at <= self.issued_at:
            raise ValueError("lease expiry must follow issuance")
        if (self.expires_at - self.issued_at).total_seconds() > 60:
            raise ValueError("lease TTL cannot exceed sixty seconds")
        if self.retry_of_intent_digest == self.intent_digest:
            raise ValueError("retry alias must use a fresh intent digest")
        if self.reservation.action_count != 1:
            raise ValueError("a v0.1 lease reserves exactly one action")
        return self


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class PolicyDecision(ProtocolModel):
    decision_id: Identifier
    intent_digest: Sha256Digest
    grant_id: Identifier
    grant_version: PositiveInt
    scope_epoch: PositiveInt
    outcome: DecisionOutcome
    reason_codes: tuple[Identifier, ...]
    evaluated_at: AwareDatetime
    lease_id: Identifier | None = None

    @model_validator(mode="after")
    def _lease_only_on_allow(self) -> "PolicyDecision":
        if (self.outcome is DecisionOutcome.ALLOW) != (self.lease_id is not None):
            raise ValueError("an allow decision requires a lease; a deny cannot include one")
        return self


class DispatchOutcome(str, Enum):
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    CANCELLED = "cancelled"


class DispatchReceipt(ProtocolModel):
    receipt_id: Identifier
    receipt_authentication_tag: Sha256Digest
    action_id: Identifier
    correlation_id: Identifier
    lease_id: Identifier
    lease_key_id: Identifier
    grant_id: Identifier
    grant_version: PositiveInt
    authority_key_id: KeyId
    scope_epoch_binding_digest: Sha256Digest
    gateway_boot_id: Identifier
    boot_challenge_digest: Sha256Digest
    intent_digest: Sha256Digest
    decision_digest: Sha256Digest
    scope_epoch: PositiveInt
    target_id: Identifier
    identity_id: Identifier
    tenant_id: Identifier | None = None
    action_kind: Identifier
    semantic_action_digest: Sha256Digest
    request_binding_digest: Sha256Digest
    request_frame_digest: Sha256Digest
    resolution_digest: Sha256Digest
    egress_plane: EgressPlane
    dispatch_nonce: Nonce128
    lease_issued_at: AwareDatetime
    lease_expires_at: AwareDatetime
    retry_of_intent_digest: Sha256Digest | None = None
    reservation: BudgetReservation
    request_digest: Sha256Digest
    response_digest: Sha256Digest | None = None
    outcome: DispatchOutcome
    dispatched_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    response_status: NonNegativeInt | None = None
    bytes_sent: NonNegativeInt
    bytes_received: NonNegativeInt
    reconciliation_required: bool = False

    @model_validator(mode="after")
    def _outcome_contract(self) -> "DispatchReceipt":
        if self.completed_at is not None and self.completed_at < self.dispatched_at:
            raise ValueError("completed_at cannot precede dispatched_at")
        if self.lease_expires_at <= self.lease_issued_at:
            raise ValueError("receipt contains an invalid lease validity interval")
        if (self.lease_expires_at - self.lease_issued_at).total_seconds() > 60:
            raise ValueError("receipt lease TTL cannot exceed sixty seconds")
        if self.retry_of_intent_digest == self.intent_digest:
            raise ValueError("retry alias must use a fresh intent digest")
        if self.reservation.action_count != 1:
            raise ValueError("a v0.1 dispatch receipt reserves exactly one action")
        if self.outcome is DispatchOutcome.UNKNOWN_OUTCOME and not self.reconciliation_required:
            raise ValueError("unknown_outcome requires reconciliation")
        if self.outcome is not DispatchOutcome.UNKNOWN_OUTCOME and self.reconciliation_required:
            raise ValueError("reconciliation flag is reserved for unknown_outcome")
        return self


class ObservationRef(ProtocolModel):
    observation_id: Identifier
    run_id: Identifier
    cas_digest: Sha256Digest
    media_type: ShortStr
    byte_length: NonNegativeInt
    cursor: Identifier | None = None
    created_at: AwareDatetime


class EvidenceRef(ProtocolModel):
    evidence_id: Identifier
    run_id: Identifier
    cas_digest: Sha256Digest
    observation_ids: tuple[Identifier, ...]
    redaction_digest: Sha256Digest | None = None
    created_at: AwareDatetime


class ResearchDelta(ProtocolModel):
    delta_id: Identifier
    run_id: Identifier
    actor_id: Identifier
    sequence: PositiveInt
    created_at: AwareDatetime
    summary: NonEmptyStr
    provenance: tuple[ProvenanceKind, ...]
    evidence_refs: tuple[EvidenceRef, ...] = ()
    introduced_hypothesis_ids: tuple[Identifier, ...] = ()
    updated_hypothesis_ids: tuple[Identifier, ...] = ()
    negative_result_ids: tuple[Identifier, ...] = ()
    previous_delta_digest: Sha256Digest | None = None


class HypothesisStatus(str, Enum):
    ACTIVE = "active"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    SUPERSEDED = "superseded"


class HypothesisRecord(ProtocolModel):
    hypothesis_id: Identifier
    run_id: Identifier
    statement: NonEmptyStr
    provenance: tuple[ProvenanceKind, ...]
    status: HypothesisStatus
    created_at: AwareDatetime
    updated_at: AwareDatetime
    supporting_evidence: tuple[EvidenceRef, ...] = ()
    contradicting_evidence: tuple[EvidenceRef, ...] = ()
    prerequisite_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _timestamps_ordered(self) -> "HypothesisRecord":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        return self


class NegativeResult(ProtocolModel):
    negative_result_id: Identifier
    run_id: Identifier
    hypothesis_id: Identifier
    experiment_digest: Sha256Digest
    conclusion: NonEmptyStr
    evidence_refs: tuple[EvidenceRef, ...]
    recorded_at: AwareDatetime


class PrimitiveRecord(ProtocolModel):
    primitive_id: Identifier
    run_id: Identifier
    primitive_kind: Identifier
    subject: SubjectRef
    resource: ResourceRef
    pre_state: StateRef | None = None
    post_state: StateRef | None = None
    action_intent_digest: Sha256Digest
    dispatch_receipt_digest: Sha256Digest
    evidence_refs: tuple[EvidenceRef, ...]
    verified: bool = False


class EffectRecord(ProtocolModel):
    effect_id: Identifier
    run_id: Identifier
    effect_kind: Identifier
    subject: SubjectRef
    resource: ResourceRef
    state: StateRef | None = None
    observed_at: AwareDatetime
    evidence_refs: tuple[EvidenceRef, ...]
    reversible: bool
    cleanup_receipt_digest: Sha256Digest | None = None


class FindingCandidate(ProtocolModel):
    candidate_id: Identifier
    run_id: Identifier
    finding_class: FindingClass
    title: ShortStr
    hypothesis_ids: tuple[Identifier, ...]
    primitive_ids: tuple[Identifier, ...]
    effect_ids: tuple[Identifier, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    created_at: AwareDatetime
    confidence_bps: ConfidenceBps
    final_effect_observed: bool


class ClaimPacket(ProtocolModel):
    claim_id: Identifier
    candidate_id: Identifier
    run_id: Identifier
    claim: NonEmptyStr
    prerequisites: tuple[NonEmptyStr, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    negative_control_refs: tuple[EvidenceRef, ...]
    replay_plan_id: Identifier
    cleanup_plan_ref: Identifier | None = None
    created_at: AwareDatetime


class VerdictOutcome(str, Enum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class VerificationVerdict(ProtocolModel):
    verdict_id: Identifier
    run_id: Identifier
    claim_id: Identifier
    claim_packet_digest: Sha256Digest
    verifier_run_id: Identifier
    outcome: VerdictOutcome
    independent_replay: bool
    reasons: tuple[NonEmptyStr, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    verified_at: AwareDatetime

    @model_validator(mode="after")
    def _verified_requires_independence(self) -> "VerificationVerdict":
        if self.outcome is VerdictOutcome.VERIFIED and not self.independent_replay:
            raise ValueError("verified verdict requires an independent replay")
        return self


class RemainingBudget(ProtocolModel):
    actions: NonNegativeInt
    duration_seconds: NonNegativeInt
    model_tokens: NonNegativeInt
    cost_microunits: NonNegativeInt


class RetrievalCursor(ProtocolModel):
    index_id: Identifier
    cursor: Identifier
    watermark: PositiveInt


class ContextCheckpoint(ProtocolModel):
    checkpoint_id: Identifier
    run_id: Identifier
    sequence: PositiveInt
    goal_digest: Sha256Digest
    plan_digest: Sha256Digest
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    active_hypothesis_ids: tuple[Identifier, ...]
    important_negative_result_ids: tuple[Identifier, ...]
    identity_graph_id: Identifier | None = None
    workflow_graph_id: Identifier | None = None
    surface_graph_id: Identifier | None = None
    chain_graph_id: Identifier | None = None
    pending_action_ids: tuple[Identifier, ...] = ()
    unknown_outcome_action_ids: tuple[Identifier, ...] = ()
    secret_refs: tuple[SecretRef, ...] = ()
    recent_evidence_refs: tuple[EvidenceRef, ...] = ()
    retrieval_cursors: tuple[RetrievalCursor, ...] = ()
    remaining_budget: RemainingBudget
    stable_watermark: PositiveInt
    created_at: AwareDatetime


class ModelIdentity(ProtocolModel):
    provider_id: Identifier
    requested_alias: ShortStr | None = None
    actual_snapshot: ShortStr
    runtime_version: ShortStr
    context_window: PositiveInt
    prompt_digest: Sha256Digest
    tool_schema_digest: Sha256Digest


class RunManifest(ProtocolModel):
    run_id: Identifier
    engagement_id: Identifier
    target_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    pack_ids: tuple[Identifier, ...]
    adapter_ids: tuple[Identifier, ...] = ()
    model: ModelIdentity
    plan_digest: Sha256Digest
    started_at: AwareDatetime
    live: bool = False


class LicenseClass(str, Enum):
    BUNDLED_OPEN_SOURCE = "bundled_open_source"
    EXTERNAL_USER_MANAGED = "external_user_managed"
    LICENSE_GATED = "license_gated"


class EvidenceCapability(str, Enum):
    CANDIDATE_ONLY = "candidate_only"
    EVIDENCE_CAPABLE = "evidence_capable"


class TelemetryPolicy(str, Enum):
    DISABLED = "disabled"
    LOCAL_RECEIPTS_ONLY = "local_receipts_only"
    EXTERNAL_USER_MANAGED = "external_user_managed"


class AdapterBudget(ProtocolModel):
    rate_per_minute: PositiveInt
    timeout_seconds: PositiveInt
    max_bytes: PositiveInt
    max_concurrency: PositiveInt


class AdapterManifest(ProtocolModel):
    adapter_id: Identifier
    adapter_version: StableSemVer
    upstream_version: ShortStr
    upstream_commit: UpstreamCommit | None = None
    image_digest: Sha256Digest | None = None
    license_class: LicenseClass
    capabilities: tuple[Identifier, ...]
    action_classes: tuple[ActionClass, ...]
    network_mode: Literal["none", "gateway_only", "loopback_policy_proxy"]
    input_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest
    budget: AdapterBudget
    telemetry_policy: TelemetryPolicy
    update_policy: Literal["pinned_no_runtime_updates"] = "pinned_no_runtime_updates"
    evidence_capability: EvidenceCapability

    @model_validator(mode="after")
    def _immutable_v01_contract(self) -> "AdapterManifest":
        if self.upstream_version.casefold() == "latest" or any(
            marker in self.upstream_version for marker in ("*", "@", ">", "<", "=")
        ):
            raise ValueError("upstream_version must identify one pinned release")
        if self.upstream_commit is None and self.image_digest is None:
            raise ValueError("adapter requires an immutable upstream commit or image digest")
        if not self.capabilities or not self.action_classes:
            raise ValueError("adapter requires capabilities and action classes")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("adapter capabilities must be unique")
        if len(self.action_classes) != len(set(self.action_classes)):
            raise ValueError("adapter action classes must be unique")
        unsupported = {ActionClass.HIGH_LOAD, ActionClass.DESTRUCTIVE}.intersection(
            self.action_classes
        )
        if unsupported:
            names = ", ".join(sorted(item.value for item in unsupported))
            raise ValueError(f"unsupported v0.1 adapter action classes: {names}")
        return self


class PackManifest(ProtocolModel):
    pack_id: Identifier
    pack_version: StableSemVer
    protocol_range: ShortStr
    schema_namespace: SchemaNamespace
    capability_descriptors: tuple[Identifier, ...]
    action_compilers: tuple[Identifier, ...]
    observation_normalizers: tuple[Identifier, ...]
    hypothesis_providers: tuple[Identifier, ...]
    verifier_descriptors: tuple[Identifier, ...]
    evaluation_descriptors: tuple[Identifier, ...]
    required_gateway_features: tuple[Identifier, ...]
    required_adapter_capabilities: tuple[Identifier, ...]
    process_isolation: Literal["required"] = "required"

    @model_validator(mode="after")
    def _supports_local_protocol(self) -> "PackManifest":
        require_protocol_compatible("0.1.0", self.protocol_range)
        descriptor_fields = (
            "capability_descriptors",
            "action_compilers",
            "observation_normalizers",
            "hypothesis_providers",
            "verifier_descriptors",
            "evaluation_descriptors",
        )
        fields = (
            *descriptor_fields,
            "required_gateway_features",
            "required_adapter_capabilities",
        )
        if not self.capability_descriptors:
            raise ValueError("pack requires at least one capability descriptor")
        for field in fields:
            values = getattr(self, field)
            if len(values) != len(set(values)):
                raise ValueError(f"pack {field} must contain unique values")
        descriptor_roles: dict[str, str] = {}
        for field in descriptor_fields:
            for descriptor in getattr(self, field):
                previous = descriptor_roles.setdefault(descriptor, field)
                if previous != field:
                    raise ValueError(
                        f"pack descriptor {descriptor!r} cannot be reused across "
                        f"roles {previous!r} and {field!r}"
                    )
        return self


# T32: Web identity and workflow contracts.


class TenantRef(ProtocolModel):
    tenant_id: Identifier
    tenant_kind: Identifier
    target_id: Identifier
    parent_tenant_id: Identifier | None = None


class RoleGrant(ProtocolModel):
    role_grant_id: Identifier
    identity_id: Identifier
    tenant_id: Identifier
    role_id: Identifier
    granted_at: AwareDatetime
    revoked_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _revocation_ordered(self) -> "RoleGrant":
        if self.revoked_at is not None and self.revoked_at < self.granted_at:
            raise ValueError("role revocation cannot precede grant")
        return self


class IdentityProfile(ProtocolModel):
    identity_id: Identifier
    account_ref: Identifier
    display_label: ShortStr
    tenant_ids: tuple[Identifier, ...]
    role_ids: tuple[Identifier, ...]
    credential_ref: SecretRef
    operator_provisioned: Literal[True] = True
    mfa_state: Literal["unknown", "disabled", "enabled", "satisfied"]
    status: Literal["active", "disabled", "revoked"]


class AuthSession(ProtocolModel):
    auth_session_id: Identifier
    identity_id: Identifier
    tenant_id: Identifier
    session_handle_ref: SecretRef
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    mfa_satisfied: bool
    revoked_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _session_ordering(self) -> "AuthSession":
        if self.expires_at <= self.issued_at:
            raise ValueError("session expiry must follow issuance")
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            raise ValueError("session revocation cannot precede issuance")
        return self


class IdentityContext(ProtocolModel):
    identity_context_id: Identifier
    identity_id: Identifier
    tenant_id: Identifier
    role_ids: tuple[Identifier, ...]
    auth_session_id: Identifier
    browser_context_ref: SecretRef | None = None
    api_session_ref: SecretRef | None = None

    @model_validator(mode="after")
    def _has_isolated_session(self) -> "IdentityContext":
        if self.browser_context_ref is None and self.api_session_ref is None:
            raise ValueError("identity context requires a browser or API session reference")
        return self


class IdentityRelationship(ProtocolModel):
    relationship_id: Identifier
    source_id: Identifier
    target_id: Identifier
    relationship_kind: Literal[
        "membership", "delegation", "ownership", "impersonation", "recovery"
    ]
    evidence_refs: tuple[EvidenceRef, ...] = ()


class IdentityGraph(ProtocolModel):
    graph_id: Identifier
    run_id: Identifier
    identities: tuple[IdentityProfile, ...]
    tenants: tuple[TenantRef, ...]
    role_grants: tuple[RoleGrant, ...]
    relationships: tuple[IdentityRelationship, ...]
    version: PositiveInt


class WorkflowState(ProtocolModel):
    workflow_state_id: Identifier
    workflow_id: Identifier
    state_name: Identifier
    tenant_id: Identifier | None = None
    resource: ResourceRef | None = None
    terminal: bool = False


class TransitionRecord(ProtocolModel):
    transition_id: Identifier
    workflow_id: Identifier
    from_state_id: Identifier
    to_state_id: Identifier
    operation_id: Identifier
    identity_context_id: Identifier
    occurred_at: AwareDatetime
    action_intent_digest: Sha256Digest
    dispatch_receipt_digest: Sha256Digest
    evidence_refs: tuple[EvidenceRef, ...]


class WorkflowGraph(ProtocolModel):
    graph_id: Identifier
    run_id: Identifier
    workflow_kind: Literal[
        "invite", "admin", "billing", "workspace", "recovery", "mfa", "approval", "other"
    ]
    states: tuple[WorkflowState, ...]
    transitions: tuple[TransitionRecord, ...]
    invariant_ids: tuple[Identifier, ...]
    version: PositiveInt


class DifferentialCase(ProtocolModel):
    case_id: Identifier
    operation_id: Identifier
    baseline_identity_context_id: Identifier
    comparison_identity_context_id: Identifier
    varied_dimension: Literal["identity", "tenant", "role", "session", "object", "order"]
    expected_invariant_id: Identifier


class DifferentialPlan(ProtocolModel):
    plan_id: Identifier
    run_id: Identifier
    workflow_graph_id: Identifier
    cases: tuple[DifferentialCase, ...]
    negative_control_case_ids: tuple[Identifier, ...]
    created_at: AwareDatetime


# T33: API and asynchronous surface contracts.


class OperationKind(str, Enum):
    REST = "rest"
    GRAPHQL_QUERY = "graphql_query"
    GRAPHQL_MUTATION = "graphql_mutation"
    GRAPHQL_SUBSCRIPTION = "graphql_subscription"
    WEBSOCKET = "websocket"
    WEBHOOK = "webhook"
    BACKGROUND_JOB = "background_job"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    CALLBACK = "callback"


class OperationRef(ProtocolModel):
    operation_id: Identifier
    target_id: Identifier
    operation_kind: OperationKind
    method: ShortStr | None = None
    path: NonEmptyStr
    schema_namespace: Identifier | None = None
    documented: bool


class SchemaEvidence(ProtocolModel):
    schema_evidence_id: Identifier
    source_kind: Literal["openapi", "graphql", "traffic", "javascript", "operator"]
    source_digest: Sha256Digest
    operation_ids: tuple[Identifier, ...]
    observed_at: AwareDatetime
    drift_hypothesis_id: Identifier | None = None


class CorrelationRef(ProtocolModel):
    correlation_id: Identifier
    correlation_kind: Literal[
        "request_id", "job_id", "callback_id", "object_id", "message_id", "timestamp"
    ]
    opaque_value_digest: Sha256Digest


class MessageEnvelope(ProtocolModel):
    message_id: Identifier
    channel_id: Identifier
    direction: Literal["client_to_server", "server_to_client", "callback"]
    message_type: Identifier
    payload_schema_digest: Sha256Digest | None = None
    payload_digest: Sha256Digest
    correlation_refs: tuple[CorrelationRef, ...]
    observed_at: AwareDatetime


class AsyncFlow(ProtocolModel):
    async_flow_id: Identifier
    initiating_operation_id: Identifier
    terminal_operation_id: Identifier | None = None
    operation_ids: tuple[Identifier, ...]
    correlation_refs: tuple[CorrelationRef, ...]
    pending: bool
    initiated_at: AwareDatetime
    completed_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _completion_contract(self) -> "AsyncFlow":
        if self.pending == (self.completed_at is not None):
            raise ValueError("pending flows cannot be completed; completed flows need completed_at")
        if self.completed_at is not None and self.completed_at < self.initiated_at:
            raise ValueError("async completion cannot precede initiation")
        return self


class CallbackLease(ProtocolModel):
    callback_lease_id: Identifier
    engagement_id: Identifier
    grant_id: Identifier
    scope_epoch: PositiveInt
    owned_domain: ShortStr
    callback_path_digest: Sha256Digest
    callback_token_ref: SecretRef
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    revoked: bool = False

    @model_validator(mode="after")
    def _callback_validity(self) -> "CallbackLease":
        if self.expires_at <= self.issued_at:
            raise ValueError("callback expiry must follow issuance")
        return self


class JobObservation(ProtocolModel):
    job_observation_id: Identifier
    async_flow_id: Identifier
    job_id_digest: Sha256Digest
    identity_context_id: Identifier
    status: Identifier
    state: StateRef | None = None
    evidence_refs: tuple[EvidenceRef, ...]
    observed_at: AwareDatetime


class FileStage(ProtocolModel):
    stage_id: Identifier
    stage_kind: Literal["upload", "processing", "storage", "preview", "download"]
    operation_id: Identifier
    artifact_digest: Sha256Digest
    tenant_id: Identifier
    observed_at: AwareDatetime


class FilePipeline(ProtocolModel):
    file_pipeline_id: Identifier
    run_id: Identifier
    canary_id: Identifier
    inert_canary: Literal[True] = True
    media_type: ShortStr
    stages: tuple[FileStage, ...]
    correlation_refs: tuple[CorrelationRef, ...]
    evidence_refs: tuple[EvidenceRef, ...]


class SurfaceEdge(ProtocolModel):
    edge_id: Identifier
    source_operation_id: Identifier
    target_operation_id: Identifier
    edge_kind: Literal["sequence", "callback", "message", "job", "file", "subscription"]
    correlation_refs: tuple[CorrelationRef, ...] = ()


class SurfaceGraph(ProtocolModel):
    graph_id: Identifier
    run_id: Identifier
    operations: tuple[OperationRef, ...]
    schema_evidence: tuple[SchemaEvidence, ...]
    async_flows: tuple[AsyncFlow, ...]
    edges: tuple[SurfaceEdge, ...]
    version: PositiveInt


# T34: Patch and CVE variant contracts.


class ComponentFingerprint(ProtocolModel):
    fingerprint_id: Identifier
    target_id: Identifier
    component_name: ShortStr
    evidence_kinds: tuple[Literal["header", "asset", "behavior", "manifest", "sbom", "source"], ...]
    evidence_refs: tuple[EvidenceRef, ...]
    observed_at: AwareDatetime


class VersionHypothesis(ProtocolModel):
    version_hypothesis_id: Identifier
    fingerprint_id: Identifier
    version_range: ShortStr
    confidence_bps: ConfidenceBps
    backport_possible: bool
    evidence_refs: tuple[EvidenceRef, ...]


class AdvisoryMatch(ProtocolModel):
    advisory_match_id: Identifier
    version_hypothesis_id: Identifier
    advisory_id: Identifier
    advisory_url_digest: Sha256Digest
    vendor_advisory_digest: Sha256Digest | None = None
    security_commit: ShortStr | None = None
    match_confidence_bps: ConfidenceBps


class ReachabilityClaim(ProtocolModel):
    reachability_claim_id: Identifier
    advisory_match_id: Identifier
    component_present: bool
    vulnerable_path_exposed: bool
    prerequisites_satisfied: bool
    patch_or_backport_present: bool | None
    evidence_refs: tuple[EvidenceRef, ...]
    conclusion: Literal["reachable", "not_reachable", "ambiguous"]


class PatchDelta(ProtocolModel):
    patch_delta_id: Identifier
    advisory_match_id: Identifier
    vulnerable_revision: ShortStr
    fixed_revision: ShortStr
    source_diff_digest: Sha256Digest
    test_diff_digest: Sha256Digest | None = None
    config_diff_digest: Sha256Digest | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()


class InvariantChange(ProtocolModel):
    invariant_change_id: Identifier
    patch_delta_id: Identifier
    invariant: NonEmptyStr
    changed_condition: NonEmptyStr
    sink_or_boundary: NonEmptyStr
    evidence_refs: tuple[EvidenceRef, ...]


class VariantHypothesis(ProtocolModel):
    variant_hypothesis_id: Identifier
    invariant_change_id: Identifier
    variant_kind: Literal[
        "sibling_path",
        "alternate_parser",
        "alternate_protocol",
        "similar_helper",
        "role_tenant",
        "canonicalization",
    ]
    statement: NonEmptyStr
    confidence_class: ConfidenceClass
    source_query_digest: Sha256Digest | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()


class DeploymentAdaptation(ProtocolModel):
    adaptation_id: Identifier
    advisory_match_id: Identifier
    target_id: Identifier
    version_hypothesis_id: Identifier
    route_ref: ResourceRef
    identity_context_id: Identifier | None = None
    transport: ShortStr
    prerequisite_ids: tuple[Identifier, ...]
    removed_unsafe_step_digests: tuple[Sha256Digest, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()


class PoCStep(ProtocolModel):
    step_id: Identifier
    action_intent: ActionIntent
    expected_effect: NonEmptyStr
    negative_control: NonEmptyStr


class PoCRecipe(ProtocolModel):
    recipe_id: Identifier
    adaptation_id: Identifier
    prerequisites: tuple[NonEmptyStr, ...]
    steps: tuple[PoCStep, ...]
    expected_observable_effect: NonEmptyStr
    negative_controls: tuple[NonEmptyStr, ...]
    cleanup_plan_ref: Identifier | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()
    forbids_shell_persistence_or_data_dump: Literal[True] = True


# T35: Cross-surface chain contracts.


class CapabilityPrimitive(ProtocolModel):
    capability_id: Identifier
    primitive: PrimitiveRecord
    capability_kind: Identifier
    source_pack_id: Identifier
    verified: bool
    precondition_ids: tuple[Identifier, ...]
    effect_ids: tuple[Identifier, ...]


class ChainEdge(ProtocolModel):
    edge_id: Identifier
    source_capability_id: Identifier
    target_capability_id: Identifier
    preconditions: tuple[NonEmptyStr, ...]
    input_subject: SubjectRef
    input_resource: ResourceRef
    input_state: StateRef | None = None
    action_intent: ActionIntent
    action_lease_id: Identifier
    scope_decision_digest: Sha256Digest
    expected_effect: EffectRecord
    observed_effect: EffectRecord
    identity_transition_id: Identifier | None = None
    session_transition_id: Identifier | None = None
    evidence_refs: tuple[EvidenceRef, ...]
    negative_control_refs: tuple[EvidenceRef, ...]
    reversible: bool
    cleanup_receipt_digest: Sha256Digest | None = None
    action_cost: PositiveInt
    time_cost_seconds: NonNegativeInt
    confidence_bps: ConfidenceBps


class ChainGraph(ProtocolModel):
    graph_id: Identifier
    run_id: Identifier
    capabilities: tuple[CapabilityPrimitive, ...]
    edges: tuple[ChainEdge, ...]
    impact_goal: NonEmptyStr
    action_budget: PositiveInt
    time_budget_seconds: PositiveInt
    version: PositiveInt


class ChainPlan(ProtocolModel):
    chain_plan_id: Identifier
    chain_graph_id: Identifier
    edge_ids: tuple[Identifier, ...]
    search_modes: tuple[Literal["forward", "backward", "bridge"], ...]
    final_effect_id: Identifier
    total_action_cost: NonNegativeInt
    total_time_cost_seconds: NonNegativeInt
    cleanup_plan_ref: Identifier | None = None


class MissingLink(ProtocolModel):
    missing_link_id: Identifier
    chain_graph_id: Identifier
    source_capability_id: Identifier
    target_capability_id: Identifier
    missing_precondition: NonEmptyStr
    minimum_experiment_intent: ActionIntent
    expected_information_gain_bps: ConfidenceBps


class ReplayPlan(ProtocolModel):
    replay_plan_id: Identifier
    chain_plan_id: Identifier
    fresh_identity_context_ids: tuple[Identifier, ...]
    reset_state_refs: tuple[StateRef, ...]
    edge_ids: tuple[Identifier, ...]
    negative_control_edge_ids: tuple[Identifier, ...]
    cleanup_plan_ref: Identifier | None = None


class ChainVerdict(ProtocolModel):
    chain_verdict_id: Identifier
    run_id: Identifier
    replay_plan_id: Identifier
    outcome: VerdictOutcome
    verified_edge_ids: tuple[Identifier, ...]
    longest_verified_prefix: NonNegativeInt
    final_effect_verified: bool
    evidence_refs: tuple[EvidenceRef, ...]
    verified_at: AwareDatetime

    @model_validator(mode="after")
    def _final_effect_gate(self) -> "ChainVerdict":
        if self.outcome is VerdictOutcome.VERIFIED and not self.final_effect_verified:
            raise ValueError("a verified chain requires the final effect")
        if self.longest_verified_prefix > len(self.verified_edge_ids):
            raise ValueError("longest prefix cannot exceed verified edge count")
        return self


# Cross-repository bundles.


class EngagementBundle(ProtocolModel):
    bundle_id: Identifier
    bundle_version: PositiveInt
    engagement_id: Identifier
    authority_grant: SignedAuthorityGrant
    run_manifest: RunManifest
    identity_profiles: tuple[IdentityProfile, ...]
    pack_manifests: tuple[PackManifest, ...]
    adapter_manifests: tuple[AdapterManifest, ...] = ()
    technical_policy_refs: tuple[Identifier, ...] = ()
    created_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def _bundle_consistency(self) -> "EngagementBundle":
        grant = self.authority_grant.payload
        if self.expires_at <= self.created_at:
            raise ValueError("engagement bundle expiry must follow creation")
        if self.created_at < grant.issued_at:
            raise ValueError("engagement bundle cannot predate its authority grant")
        if self.expires_at > grant.expires_at:
            raise ValueError("engagement bundle cannot outlive its authority grant")
        if self.run_manifest.engagement_id != self.engagement_id:
            raise ValueError("run manifest belongs to a different engagement")
        if not self.created_at <= self.run_manifest.started_at < self.expires_at:
            raise ValueError("run start is outside engagement bundle validity")
        if self.authority_grant.signature.signed_at > self.run_manifest.started_at:
            raise ValueError("authority grant was signed after the run started")
        if not grant.not_before <= self.run_manifest.started_at < grant.expires_at:
            raise ValueError("run start is outside authority validity")
        if not any(
            window.starts_at <= self.run_manifest.started_at < window.ends_at
            for window in grant.execution_windows
        ):
            raise ValueError("run start is outside approved execution windows")
        if self.run_manifest.authority_digest != sha256_digest(self.authority_grant):
            raise ValueError("run authority digest does not identify the embedded grant")
        if self.run_manifest.target_id not in {
            target.target_id for target in grant.targets
        }:
            raise ValueError("run target is absent from the authority grant")
        granted_packs = set(grant.pack_ids)
        bundled_packs = {manifest.pack_id for manifest in self.pack_manifests}
        if not bundled_packs.issubset(granted_packs):
            raise ValueError("bundle contains an unauthorized pack")
        if not set(self.run_manifest.pack_ids).issubset(granted_packs & bundled_packs):
            raise ValueError("run references an unauthorized or absent pack")
        granted_adapters = set(grant.adapter_ids)
        bundled_adapters = {manifest.adapter_id for manifest in self.adapter_manifests}
        if not bundled_adapters.issubset(granted_adapters):
            raise ValueError("bundle contains an unauthorized adapter")
        if not set(self.run_manifest.adapter_ids).issubset(
            granted_adapters & bundled_adapters
        ):
            raise ValueError("run references an unauthorized or absent adapter")
        for profile in self.identity_profiles:
            if profile.identity_id not in grant.identities:
                raise ValueError("bundle contains an unauthorized identity")
            if not set(profile.tenant_ids).issubset(grant.tenants):
                raise ValueError("identity profile contains an unauthorized tenant")
            if not set(profile.role_ids).issubset(grant.roles):
                raise ValueError("identity profile contains an unauthorized role")
        return self


class RunResultBundle(ProtocolModel):
    bundle_id: Identifier
    bundle_version: PositiveInt
    engagement_id: Identifier
    run_id: Identifier
    run_manifest_digest: Sha256Digest
    authority_digest: Sha256Digest
    finding_candidates: tuple[FindingCandidate, ...] = ()
    claim_packets: tuple[ClaimPacket, ...] = ()
    verification_verdicts: tuple[VerificationVerdict, ...] = ()
    chain_verdicts: tuple[ChainVerdict, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    final_checkpoint_digest: Sha256Digest
    generated_at: AwareDatetime
    cleanup_receipt_digests: tuple[Sha256Digest, ...] = ()

    @model_validator(mode="after")
    def _nested_records_belong_to_run(self) -> "RunResultBundle":
        run_bound_records = (
            *self.finding_candidates,
            *self.claim_packets,
            *self.verification_verdicts,
            *self.chain_verdicts,
            *self.evidence_refs,
        )
        if any(record.run_id != self.run_id for record in run_bound_records):
            raise ValueError("result contains a record from a different run")

        candidate_ids = {candidate.candidate_id for candidate in self.finding_candidates}
        if len(candidate_ids) != len(self.finding_candidates):
            raise ValueError("result contains duplicate candidate IDs")
        if any(claim.candidate_id not in candidate_ids for claim in self.claim_packets):
            raise ValueError("claim references a candidate absent from the result")

        claim_ids = {claim.claim_id for claim in self.claim_packets}
        if len(claim_ids) != len(self.claim_packets):
            raise ValueError("result contains duplicate claim IDs")
        if any(verdict.claim_id not in claim_ids for verdict in self.verification_verdicts):
            raise ValueError("verdict references a claim absent from the result")
        claims_by_id = {claim.claim_id: claim for claim in self.claim_packets}
        if any(
            verdict.claim_packet_digest != sha256_digest(claims_by_id[verdict.claim_id])
            for verdict in self.verification_verdicts
        ):
            raise ValueError("verdict claim digest does not match the included claim")

        nested_evidence = (
            *(ref for item in self.finding_candidates for ref in item.evidence_refs),
            *(ref for item in self.claim_packets for ref in item.evidence_refs),
            *(ref for item in self.claim_packets for ref in item.negative_control_refs),
            *(ref for item in self.verification_verdicts for ref in item.evidence_refs),
            *(ref for item in self.chain_verdicts for ref in item.evidence_refs),
        )
        if any(ref.run_id != self.run_id for ref in nested_evidence):
            raise ValueError("result contains nested evidence from a different run")
        return self


class SignedEngagementBundle(ProtocolModel):
    payload: EngagementBundle
    signature: SignatureBlock


class SignedRunResultBundle(ProtocolModel):
    payload: RunResultBundle
    signature: SignatureBlock


_install_protocol_enum_catalog(
    (
        ActionClass,
        EgressPlane,
        ProvenanceKind,
        ConfidenceClass,
        FindingClass,
        SignaturePurpose,
        DecisionOutcome,
        DispatchOutcome,
        HypothesisStatus,
        VerdictOutcome,
        LicenseClass,
        EvidenceCapability,
        TelemetryPolicy,
        OperationKind,
        *EVALUATION_ENUM_TYPES,
    )
)


REQUIRED_MODEL_TYPES: tuple[type[ProtocolModel], ...] = (
    ScopeContractDraft,
    AuthorityGrant,
    ScopeEpoch,
    ActionIntent,
    ActionLease,
    PolicyDecision,
    DispatchReceipt,
    ObservationRef,
    EvidenceRef,
    ResearchDelta,
    HypothesisRecord,
    NegativeResult,
    SubjectRef,
    ResourceRef,
    StateRef,
    PrimitiveRecord,
    EffectRecord,
    FindingCandidate,
    ClaimPacket,
    VerificationVerdict,
    ContextCheckpoint,
    RunManifest,
    AdapterManifest,
    PackManifest,
    EngagementBundle,
    RunResultBundle,
    IdentityProfile,
    IdentityContext,
    TenantRef,
    RoleGrant,
    AuthSession,
    IdentityGraph,
    WorkflowGraph,
    WorkflowState,
    TransitionRecord,
    DifferentialPlan,
    SurfaceGraph,
    OperationRef,
    SchemaEvidence,
    AsyncFlow,
    MessageEnvelope,
    CorrelationRef,
    CallbackLease,
    JobObservation,
    FilePipeline,
    ComponentFingerprint,
    VersionHypothesis,
    AdvisoryMatch,
    ReachabilityClaim,
    PatchDelta,
    InvariantChange,
    VariantHypothesis,
    DeploymentAdaptation,
    PoCRecipe,
    CapabilityPrimitive,
    ChainGraph,
    ChainEdge,
    ChainPlan,
    MissingLink,
    ReplayPlan,
    ChainVerdict,
)

WIRE_MODEL_TYPES: tuple[type[ProtocolModel], ...] = (
    SignatureBlock,
    Ed25519PublicKeyRecord,
    SignedAuthorityGrant,
    SignedScopeEpoch,
    SignedEngagementBundle,
    SignedRunResultBundle,
)


def schema_catalog() -> dict[str, dict[str, object]]:
    """Return JSON Schemas for all v0.1 payload and signed wire types."""

    return {
        model.__name__: model.model_json_schema()
        for model in (
            *REQUIRED_MODEL_TYPES,
            *WIRE_MODEL_TYPES,
            *EVALUATION_MODEL_TYPES,
            *MODEL_ATTESTATION_MODEL_TYPES,
        )
    }
