from __future__ import annotations

import re
from enum import Enum
from typing import Annotated, Literal

from faultloom_protocol import ProtocolModel
from faultloom_protocol.base import MAX_INT64
from pydantic import Field

SCHEMA_VERSION = "0.1.0"
Signed64NonNegative = Annotated[int, Field(strict=True, ge=0, le=MAX_INT64)]
Signed64Positive = Annotated[int, Field(strict=True, ge=1, le=MAX_INT64)]
_PROVIDER_CREDENTIAL_PURPOSE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"
)


class ProviderAdapterError(RuntimeError):
    """Base class for provider admission and accounting failures."""


class ProviderPolicyError(ProviderAdapterError):
    """A call conflicts with pinned provider policy."""


class ProviderMetadataError(ProviderAdapterError):
    """Provider identity or runtime metadata is ambiguous or inconsistent."""


class ProviderBudgetError(ProviderAdapterError):
    """A call cannot fit its pinned token, byte, or cost budget."""


class ProviderRetryError(ProviderAdapterError):
    """A retry or failover lacks an admissible prior receipt."""


class ProviderReceiptError(ProviderAdapterError):
    """An immutable call receipt failed validation or journal admission."""


class ProviderPlaneError(ProviderAdapterError):
    """A provider component attempted to use a non-provider egress plane."""


class _RuntimeModel(ProtocolModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION


class ProviderPlane(str, Enum):
    MODEL_PROVIDER = "model_provider"
    TARGET = "target"
    KNOWLEDGE = "knowledge"


class ProviderToolKind(str, Enum):
    FUNCTION = "function"
    WEB = "web"
    COMPUTER = "computer"
    NETWORK = "network"


class MetadataSourceKind(str, Enum):
    PROVIDER_RESPONSE = "provider_response"
    PINNED_REGISTRY = "pinned_registry"
    OPERATOR_PIN = "operator_pin"
    CONSERVATIVE_LAB = "conservative_lab"


class ProxyOutcome(str, Enum):
    COMPLETED = "completed"
    PRE_SEND_FAILED = "pre_send_failed"
    DENIED = "denied"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"


class ProxyEffectDisposition(str, Enum):
    NOT_DISPATCHED = "not_dispatched"
    POSSIBLE = "possible"
    OBSERVED = "observed"


class ProviderCallOutcome(str, Enum):
    COMPLETED = "completed"
    PRE_SEND_FAILED = "pre_send_failed"
    DENIED = "denied"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    REJECTED_RESPONSE = "rejected_response"


class RetryDisposition(str, Enum):
    EXPLICIT_RETRY_ALLOWED = "explicit_retry_allowed"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    BLOCKED_FINAL = "blocked_final"


class FailureCode(str, Enum):
    PROXY_PRE_SEND_FAILED = "proxy_pre_send_failed"
    PROXY_DENIED = "proxy_denied"
    PROXY_FAILED = "proxy_failed"
    PROXY_EXCEPTION_UNKNOWN = "proxy_exception_unknown"
    PROXY_PLANE_MISMATCH = "proxy_plane_mismatch"
    PROXY_IDENTITY_MISMATCH = "proxy_identity_mismatch"
    PROXY_CORRELATION_MISMATCH = "proxy_correlation_mismatch"
    METADATA_MISSING = "metadata_missing"
    METADATA_MISMATCH = "metadata_mismatch"
    PROMPT_DIGEST_MISMATCH = "prompt_digest_mismatch"
    COMPILED_CONTEXT_DRIFT = "compiled_context_drift"
    TOOL_SCHEMA_DRIFT = "tool_schema_drift"
    OUTPUT_SCHEMA_DRIFT = "output_schema_drift"
    CONFIG_DRIFT = "config_drift"
    POLICY_DRIFT = "policy_drift"
    USAGE_INVALID = "usage_invalid"
    TOKEN_BUDGET_EXCEEDED = "token_budget_exceeded"
    COST_BUDGET_EXCEEDED = "cost_budget_exceeded"
    BYTE_BUDGET_EXCEEDED = "byte_budget_exceeded"
