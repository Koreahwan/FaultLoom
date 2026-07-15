"""Application-level OAuth, OIDC, and SAML semantic checks."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self, assert_never

from pydantic import Field, model_validator

from faultloom_protocol.base import Identifier, Sha256Digest

from ._base import IdentityWorkflowModel
from .errors import IdentityWorkflowError


class AuthProtocol(StrEnum):
    OAUTH = "oauth"
    OIDC = "oidc"
    SAML = "saml"


class AuthBinding(StrEnum):
    REDIRECT = "redirect"
    FORM_POST = "form_post"
    ARTIFACT = "artifact"


class AuthCheckKind(StrEnum):
    CORRELATION = "correlation"
    NONCE = "nonce"
    REDIRECT = "redirect"
    AUDIENCE = "audience"
    ISSUER = "issuer"
    SUBJECT_BINDING = "subject_binding"
    TRANSPORT_BINDING = "transport_binding"


class AuthSemanticTrace(IdentityWorkflowModel):
    flow_id: Identifier
    protocol: AuthProtocol
    expected_correlation_digest: Sha256Digest
    observed_correlation_digest: Sha256Digest
    expected_nonce_digest: Sha256Digest | None = None
    observed_nonce_digest: Sha256Digest | None = None
    expected_redirect_digest: Sha256Digest
    observed_redirect_digest: Sha256Digest
    expected_audiences: tuple[Identifier, ...] = Field(min_length=1)
    observed_audiences: tuple[Identifier, ...] = Field(min_length=1)
    expected_issuer: Identifier
    observed_issuer: Identifier
    expected_subject_binding_digest: Sha256Digest
    observed_subject_binding_digest: Sha256Digest
    expected_binding: AuthBinding
    observed_binding: AuthBinding
    analysis_scope: Literal["application_semantics"] = "application_semantics"

    @model_validator(mode="after")
    def _protocol_fields_are_consistent(self) -> Self:
        match self.protocol:
            case AuthProtocol.OAUTH | AuthProtocol.SAML:
                nonce_shape_valid = (
                    self.expected_nonce_digest is None
                    and self.observed_nonce_digest is None
                )
            case AuthProtocol.OIDC:
                nonce_shape_valid = (
                    self.expected_nonce_digest is not None
                    and self.observed_nonce_digest is not None
                )
            case unreachable:
                assert_never(unreachable)
        if not nonce_shape_valid:
            raise IdentityWorkflowError(
                code="auth.nonce_shape_invalid",
                detail="OIDC requires nonce binding while OAuth and SAML use correlation binding",
            )
        if len(set(self.expected_audiences)) != len(self.expected_audiences):
            raise IdentityWorkflowError(
                code="auth.audience_duplicate",
                detail="expected audiences must be unique",
            )
        if len(set(self.observed_audiences)) != len(self.observed_audiences):
            raise IdentityWorkflowError(
                code="auth.audience_duplicate",
                detail="observed audiences must be unique",
            )
        return self


class AuthCheckResult(IdentityWorkflowModel):
    kind: AuthCheckKind
    passed: bool


class AuthSemanticReport(IdentityWorkflowModel):
    flow_id: Identifier
    protocol: AuthProtocol
    checks: tuple[AuthCheckResult, ...]
    accepted: bool
    signature_parser_used: Literal[False] = False


def analyze_auth_semantics(trace: AuthSemanticTrace) -> AuthSemanticReport:
    """Evaluate application bindings without parsing or asserting signatures."""

    checks = [
        AuthCheckResult(
            kind=AuthCheckKind.CORRELATION,
            passed=(
                trace.expected_correlation_digest
                == trace.observed_correlation_digest
            ),
        ),
        AuthCheckResult(
            kind=AuthCheckKind.REDIRECT,
            passed=trace.expected_redirect_digest == trace.observed_redirect_digest,
        ),
        AuthCheckResult(
            kind=AuthCheckKind.AUDIENCE,
            passed=set(trace.expected_audiences) == set(trace.observed_audiences),
        ),
        AuthCheckResult(
            kind=AuthCheckKind.ISSUER,
            passed=trace.expected_issuer == trace.observed_issuer,
        ),
        AuthCheckResult(
            kind=AuthCheckKind.SUBJECT_BINDING,
            passed=(
                trace.expected_subject_binding_digest
                == trace.observed_subject_binding_digest
            ),
        ),
        AuthCheckResult(
            kind=AuthCheckKind.TRANSPORT_BINDING,
            passed=trace.expected_binding is trace.observed_binding,
        ),
    ]
    match trace.protocol:
        case AuthProtocol.OIDC:
            checks.append(
                AuthCheckResult(
                    kind=AuthCheckKind.NONCE,
                    passed=trace.expected_nonce_digest == trace.observed_nonce_digest,
                )
            )
        case AuthProtocol.OAUTH | AuthProtocol.SAML:
            pass
        case unreachable:
            assert_never(unreachable)
    return AuthSemanticReport(
        flow_id=trace.flow_id,
        protocol=trace.protocol,
        checks=tuple(checks),
        accepted=all(check.passed for check in checks),
    )
