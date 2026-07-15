from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from faultloom_protocol import (
    AuthorityGrant,
    Ed25519PublicKeyRecord,
    SignedAuthorityGrant,
    sha256_digest,
    verify_authority_grant,
)


@dataclass(frozen=True, slots=True)
class _AuthorizationProof:
    source_actor_id: str
    verifier_actor_id: str
    verifier_run_id: str
    authority_digest: str
    grant_digest: str


@dataclass(frozen=True, slots=True)
class VerifierAuthorizationError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class VerifierAuthorizationRequest:
    source_actor_id: str
    verifier_actor_id: str
    verifier_run_id: str
    signed_authority: SignedAuthorityGrant
    trusted_authority_key: Ed25519PublicKeyRecord
    verification_time: datetime
    minimum_authority_version: int = 1


@dataclass(frozen=True, slots=True)
class AuthorizedVerifier:
    source_actor_id: str
    verifier_actor_id: str
    verifier_run_id: str
    authority_digest: str
    grant: AuthorityGrant
    _proof: _AuthorizationProof


def authorize_verifier(request: VerifierAuthorizationRequest) -> AuthorizedVerifier:
    if request.source_actor_id == request.verifier_actor_id:
        raise VerifierAuthorizationError(
            reason="the verifier actor must differ from the source research actor"
        )
    try:
        grant = verify_authority_grant(
            request.signed_authority,
            request.trusted_authority_key,
            now=request.verification_time,
            minimum_version=request.minimum_authority_version,
        )
    except ValueError as exc:
        raise VerifierAuthorizationError(
            reason=f"verifier authority verification failed: {exc}"
        ) from exc
    if grant.issued_to != request.verifier_actor_id:
        raise VerifierAuthorizationError(
            reason="the signed verifier authority was issued to a different actor"
        )
    return AuthorizedVerifier(
        source_actor_id=request.source_actor_id,
        verifier_actor_id=request.verifier_actor_id,
        verifier_run_id=request.verifier_run_id,
        authority_digest=sha256_digest(request.signed_authority),
        grant=grant,
        _proof=_AuthorizationProof(
            source_actor_id=request.source_actor_id,
            verifier_actor_id=request.verifier_actor_id,
            verifier_run_id=request.verifier_run_id,
            authority_digest=sha256_digest(request.signed_authority),
            grant_digest=sha256_digest(grant),
        ),
    )


def require_authorized_verifier(verifier: AuthorizedVerifier) -> AuthorizedVerifier:
    proof = verifier._proof
    if (
        verifier.source_actor_id != proof.source_actor_id
        or verifier.verifier_actor_id != proof.verifier_actor_id
        or verifier.verifier_run_id != proof.verifier_run_id
        or verifier.authority_digest != proof.authority_digest
        or sha256_digest(verifier.grant) != proof.grant_digest
        or verifier.grant.issued_to != verifier.verifier_actor_id
        or verifier.source_actor_id == verifier.verifier_actor_id
    ):
        raise VerifierAuthorizationError(reason="verifier authorization proof is invalid")
    return verifier
