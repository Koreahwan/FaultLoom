from faultloom._provider_constants import OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES
from .chat_payload import OpenAICompatibleChatPayload, OpenAICompatibleMessage
from .common import (
    FailureCode,
    MetadataSourceKind,
    ProviderAdapterError,
    ProviderBudgetError,
    ProviderCallOutcome,
    ProviderMetadataError,
    ProviderPlane,
    ProviderPlaneError,
    ProviderPolicyError,
    ProviderReceiptError,
    ProviderRetryError,
    ProviderToolKind,
    ProxyEffectDisposition,
    ProxyOutcome,
    RetryDisposition,
    provider_canonical_json,
    provider_canonical_json_bytes,
    provider_sha256_digest,
)
from .intent import (
    FailoverProvenance,
    GenerationConfig,
    ProviderCallBudget,
    ProviderCallIntent,
    failover_provenance_attestation_bytes,
)
from .journal_protocol import ProviderReceiptJournal
from .memory_journal import MemoryProviderReceiptJournal
from .metadata import (
    MetadataProvenance,
    ProviderModelProfile,
    ProviderObservedMetadata,
    ProviderToolSpec,
    provider_tool_schema_digest,
)
from .proxy import (
    ProviderProxyPort,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderToolCall,
    ProviderUsage,
    provider_proxy_result_attestation_bytes,
)
from .receipt import ProviderCallReceipt
from .wire_catalog import PROVIDER_WIRE as _PROVIDER_WIRE

_LAZY_EXPORTS = frozenset(
    {
        "AnchoredProviderReceiptJournal",
        "ProviderAdapter",
        "BoundEnvironmentCredentialResolver",
        "OpenAICompatibleCredentialBinding",
        "OpenAICompatibleEndpointConfig",
        "OpenAICompatibleEgressTransport",
        "OpenAICompatibleFunctionSchema",
        "OpenAICompatibleHttpPort",
        "OpenAICompatibleHttpResponse",
        "OpenAICompatiblePayloadStore",
        "OpenAICompatiblePreset",
        "OpenAICompatibleProviderProxy",
        "PinnedHttpsGatewayPort",
        "openai_compatible_preset",
    }
)


def __getattr__(name: str) -> object:
    if name == "ProviderAdapter":
        from .adapter import ProviderAdapter

        value = ProviderAdapter
    elif name == "AnchoredProviderReceiptJournal":
        from .anchored_journal import AnchoredProviderReceiptJournal

        value = AnchoredProviderReceiptJournal
    elif name in _LAZY_EXPORTS:
        from . import openai_compatible

        value = getattr(openai_compatible, name)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value

__all__ = [
    "AnchoredProviderReceiptJournal",
    "FailureCode",
    "FailoverProvenance",
    "GenerationConfig",
    "MemoryProviderReceiptJournal",
    "MetadataProvenance",
    "MetadataSourceKind",
    "BoundEnvironmentCredentialResolver",
    "OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES",
    "OpenAICompatibleChatPayload",
    "OpenAICompatibleCredentialBinding",
    "OpenAICompatibleEndpointConfig",
    "OpenAICompatibleEgressTransport",
    "OpenAICompatibleFunctionSchema",
    "OpenAICompatibleHttpPort",
    "OpenAICompatibleHttpResponse",
    "OpenAICompatibleMessage",
    "OpenAICompatiblePayloadStore",
    "OpenAICompatiblePreset",
    "OpenAICompatibleProviderProxy",
    "PinnedHttpsGatewayPort",
    "ProviderAdapter",
    "ProviderAdapterError",
    "ProviderBudgetError",
    "ProviderCallBudget",
    "ProviderCallIntent",
    "ProviderCallOutcome",
    "ProviderCallReceipt",
    "ProviderMetadataError",
    "ProviderModelProfile",
    "ProviderObservedMetadata",
    "ProviderPlane",
    "ProviderPlaneError",
    "ProviderPolicyError",
    "ProviderProxyPort",
    "ProviderProxyRequest",
    "ProviderProxyResult",
    "ProviderToolCall",
    "ProviderReceiptError",
    "ProviderReceiptJournal",
    "ProviderRetryError",
    "ProviderToolKind",
    "ProviderToolSpec",
    "ProviderUsage",
    "ProxyEffectDisposition",
    "ProxyOutcome",
    "RetryDisposition",
    "failover_provenance_attestation_bytes",
    "provider_proxy_result_attestation_bytes",
    "provider_canonical_json",
    "provider_canonical_json_bytes",
    "provider_sha256_digest",
    "provider_tool_schema_digest",
    "openai_compatible_preset",
]
