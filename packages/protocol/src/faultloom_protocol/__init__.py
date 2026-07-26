"""Public API for the FaultLoom v0.1 protocol."""

from .base import (
    PROTOCOL_VERSION,
    SCHEMA_VERSION,
    SUPPORTED_PROTOCOL_RANGE,
    ProtocolModel,
    SecretRef,
)
from .canonical import canonical_json, canonical_json_bytes, sha256_digest
from .compatibility import (
    SemVer,
    is_protocol_compatible,
    protocol_range_contains,
    require_protocol_compatible,
)
from .gateway_receipt import GatewayEpochReceiptIssuer
from .model_attestation import *  # noqa: F403
from .model_attestation import __all__ as _MODEL_ATTESTATION_PUBLIC_EXPORTS
from .model_utility_admission import *  # noqa: F403
from .model_utility_admission import __all__ as _MODEL_UTILITY_ADMISSION_PUBLIC_EXPORTS
from .evaluation import *  # noqa: F403
from .evaluation import __all__ as _EVALUATION_PUBLIC_EXPORTS
from .models import *  # noqa: F403
from .models import REQUIRED_MODEL_TYPES, WIRE_MODEL_TYPES, schema_catalog
from .signing import (
    AuthorityRevokedError,
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    SignatureBlock,
    SignatureExpiredError,
    SignatureNotYetValidError,
    SignaturePurpose,
    SignatureRollbackError,
    SignatureTamperError,
    SignatureVerificationError,
    SignedAuthorityGrant,
    SignedEngagementBundle,
    SignedRunResultBundle,
    SignedScopeEpoch,
    UnknownKeyError,
    load_public_key,
    sign_authority_grant,
    sign_engagement_bundle,
    sign_run_result_bundle,
    sign_scope_epoch,
    signing_bytes,
    verify_authority_grant,
    verify_engagement_bundle,
    verify_run_result_bundle,
    verify_scope_epoch,
)

__version__ = PROTOCOL_VERSION

__all__ = [
    "PROTOCOL_VERSION",
    "SCHEMA_VERSION",
    "SUPPORTED_PROTOCOL_RANGE",
    "ProtocolModel",
    "SecretRef",
    "canonical_json",
    "canonical_json_bytes",
    "sha256_digest",
    "SemVer",
    "is_protocol_compatible",
    "protocol_range_contains",
    "require_protocol_compatible",
    "REQUIRED_MODEL_TYPES",
    "WIRE_MODEL_TYPES",
    "schema_catalog",
    "GatewayEpochReceiptIssuer",
    *_MODEL_ATTESTATION_PUBLIC_EXPORTS,
    *_MODEL_UTILITY_ADMISSION_PUBLIC_EXPORTS,
    "AuthoritySigner",
    "Ed25519PublicKeyRecord",
    "SignatureBlock",
    "SignaturePurpose",
    "SignedAuthorityGrant",
    "SignedScopeEpoch",
    "SignedEngagementBundle",
    "SignedRunResultBundle",
    "SignatureVerificationError",
    "SignatureTamperError",
    "SignatureExpiredError",
    "SignatureNotYetValidError",
    "SignatureRollbackError",
    "AuthorityRevokedError",
    "UnknownKeyError",
    "load_public_key",
    "sign_authority_grant",
    "sign_scope_epoch",
    "sign_engagement_bundle",
    "sign_run_result_bundle",
    "verify_authority_grant",
    "verify_scope_epoch",
    "verify_engagement_bundle",
    "verify_run_result_bundle",
    "signing_bytes",
    *_EVALUATION_PUBLIC_EXPORTS,
    *[model.__name__ for model in REQUIRED_MODEL_TYPES],
]
