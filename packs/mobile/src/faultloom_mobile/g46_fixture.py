"""Pinned, candidate-only contracts for the fully simulated G46 fixture."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .api_binding import MobileApiBindingRun


_FORBIDDEN_MATERIAL = (
    "access_token",
    "authorization",
    "bearer ",
    "password",
    "private_key",
    "refresh_token",
)
_MANIFEST_DOCUMENT: Mapping[str, object] = {
    "fixture_id": "fixture.g46.owned-mobile-api",
    "manifest_version": "1",
    "authority_id": "synthetic.g46.authority",
    "scope_id": "scope.g46.owned-mobile-api",
    "device_id": "synthetic.g46.device.emulator",
    "application_id": "synthetic.g46.application.mobile",
    "api_id": "synthetic.g46.api.binding",
    "api_origin": "fixture://owned-g46-mobile-api",
    "action_budget": 1,
    "command_mode": "inert_preparation_only",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: object) -> str:
    return f"sha256:{hashlib.sha256(_canonical(value)).hexdigest()}"


def _bytes_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


@dataclass(frozen=True, slots=True)
class G46PinnedManifest:
    fixture_id: str
    manifest_version: str
    authority_id: str
    scope_id: str
    device_id: str
    application_id: str
    api_id: str
    api_origin: str
    action_budget: int
    command_mode: Literal["inert_preparation_only"]
    manifest_digest: str

    def validate(self) -> None:
        if self != G46_PINNED_MANIFEST:
            raise ValueError("G46 requires the exact pinned fixture manifest")


G46_PINNED_MANIFEST_DIGEST = "sha256:8ff668797785650b37df19c014aee653a8bc1c271686df721ec4fbc6b32753cd"
if _sha256(_MANIFEST_DOCUMENT) != G46_PINNED_MANIFEST_DIGEST:
    raise RuntimeError("G46 pinned manifest digest does not match its document")
G46_PINNED_MANIFEST = G46PinnedManifest(
    fixture_id="fixture.g46.owned-mobile-api",
    manifest_version="1",
    authority_id="synthetic.g46.authority",
    scope_id="scope.g46.owned-mobile-api",
    device_id="synthetic.g46.device.emulator",
    application_id="synthetic.g46.application.mobile",
    api_id="synthetic.g46.api.binding",
    api_origin="fixture://owned-g46-mobile-api",
    action_budget=1,
    command_mode="inert_preparation_only",
    manifest_digest=G46_PINNED_MANIFEST_DIGEST,
)


@dataclass(frozen=True, slots=True)
class G46SyntheticIdentities:
    device_id: str = "synthetic.g46.device.emulator"
    application_id: str = "synthetic.g46.application.mobile"
    api_id: str = "synthetic.g46.api.binding"

    def validate(self) -> None:
        values = (self.device_id, self.application_id, self.api_id)
        if any(not value.startswith("synthetic.g46.") for value in values):
            raise ValueError("G46 accepts only distinct synthetic mobile/API identities")
        if len(set(values)) != len(values):
            raise ValueError("G46 requires distinct synthetic mobile/API identities")


@dataclass(frozen=True, slots=True)
class G46SignedAuthorityAdmission:
    """Externally signed authority, scope, target, and budget assertion."""

    authority_id: str
    scope_id: str
    device_id: str
    application_id: str
    api_id: str
    action_budget: int
    nonce: str
    issued_at_epoch_seconds: int
    expires_at_epoch_seconds: int
    signature: bytes

    def canonical_authority_scope_budget_bytes(self) -> bytes:
        return canonical_authority_scope_budget_bytes(self)


def canonical_authority_scope_budget_bytes(admission: G46SignedAuthorityAdmission) -> bytes:
    """Return the exact bytes an external Ed25519 authority must sign."""

    return _canonical(
        {
            "authority": {"authority_id": admission.authority_id},
            "scope": {
                "scope_id": admission.scope_id,
                "device_id": admission.device_id,
                "application_id": admission.application_id,
                "api_id": admission.api_id,
            },
            "budget": {"action_budget": admission.action_budget},
            "nonce": admission.nonce,
            "issued_at_epoch_seconds": admission.issued_at_epoch_seconds,
            "expires_at_epoch_seconds": admission.expires_at_epoch_seconds,
        }
    )


@dataclass(frozen=True, slots=True)
class G46AdmissionToken:
    """Signed admission envelope revalidated by every consuming boundary.

    Python-private values cannot establish an authority boundary.  The token
    therefore retains the externally signed envelope and every consumer checks
    it against the caller-supplied pinned authority key before use.
    """

    admission: G46SignedAuthorityAdmission

    @property
    def authority_id(self) -> str:
        return self.admission.authority_id

    @property
    def scope_id(self) -> str:
        return self.admission.scope_id

    @property
    def device_id(self) -> str:
        return self.admission.device_id

    @property
    def application_id(self) -> str:
        return self.admission.application_id

    @property
    def api_id(self) -> str:
        return self.admission.api_id

    @property
    def action_budget(self) -> int:
        return self.admission.action_budget

    @property
    def expires_at_epoch_seconds(self) -> int:
        return self.admission.expires_at_epoch_seconds

    @property
    def admission_id(self) -> str:
        return _bytes_digest(self.admission.canonical_authority_scope_budget_bytes())

    def assert_current(self, now_epoch_seconds: int) -> None:
        if now_epoch_seconds >= self.expires_at_epoch_seconds:
            raise ValueError("G46 admission token has expired")

    def assert_verified(
        self,
        manifest: G46PinnedManifest,
        identities: G46SyntheticIdentities,
        authority_public_key: bytes,
        now_epoch_seconds: int,
    ) -> None:
        """Revalidate the full signed envelope at the point of consumption."""

        manifest.validate()
        identities.validate()
        if len(authority_public_key) != 32:
            raise ValueError("G46 authority public key must be exactly 32 bytes")
        if self.admission.issued_at_epoch_seconds > now_epoch_seconds:
            raise ValueError("G46 authority admission is not yet valid")
        self.assert_current(now_epoch_seconds)
        if not self.admission.nonce.startswith("synthetic.g46."):
            raise ValueError("G46 authority admission nonce must be synthetic")
        try:
            Ed25519PublicKey.from_public_bytes(authority_public_key).verify(
                self.admission.signature,
                self.admission.canonical_authority_scope_budget_bytes(),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("G46 authority admission signature is invalid") from exc
        self.assert_matches(manifest, identities)

    def assert_matches(
        self, manifest: G46PinnedManifest, identities: G46SyntheticIdentities
    ) -> None:
        manifest.validate()
        identities.validate()
        if (
            self.authority_id,
            self.scope_id,
            self.device_id,
            self.application_id,
            self.api_id,
            self.action_budget,
        ) != (
            manifest.authority_id,
            manifest.scope_id,
            identities.device_id,
            identities.application_id,
            identities.api_id,
            manifest.action_budget,
        ):
            raise ValueError("G46 admission token does not match the pinned scope or budget")


@dataclass(slots=True)
class G46AuthorityVerifier:
    """Verify externally supplied Ed25519 admissions and reject nonce replay."""

    manifest: G46PinnedManifest
    authority_public_key: bytes
    now_epoch_seconds: int
    _used_admission_ids: set[str]

    def __init__(
        self,
        manifest: G46PinnedManifest,
        authority_public_key: bytes,
        now_epoch_seconds: int,
    ) -> None:
        manifest.validate()
        if len(authority_public_key) != 32:
            raise ValueError("G46 authority public key must be exactly 32 bytes")
        self.manifest = manifest
        self.authority_public_key = bytes(authority_public_key)
        self.now_epoch_seconds = now_epoch_seconds
        self._used_admission_ids = set()

    def admit(
        self, admission: G46SignedAuthorityAdmission, identities: G46SyntheticIdentities
    ) -> G46AdmissionToken:
        identities.validate()
        token = G46AdmissionToken(admission)
        admission_id = token.admission_id
        if admission_id in self._used_admission_ids:
            raise ValueError("G46 authority admission replay is rejected")
        token.assert_verified(
            self.manifest,
            identities,
            self.authority_public_key,
            self.now_epoch_seconds,
        )
        self._used_admission_ids.add(admission_id)
        return token


@dataclass(frozen=True, slots=True)
class G46PreparedGatewayCommand:
    command_id: str
    command_digest: str
    admission_id: str
    manifest_digest: str
    scope_id: str
    target_origin: str
    action_budget: int
    observation_digest: str
    dispatch_required: Literal[True] = True
    dispatched: Literal[False] = False
    execution_mode: Literal["inert_preparation_only"] = "inert_preparation_only"

    def assert_inert(self) -> None:
        if self.dispatched or self.execution_mode != "inert_preparation_only":
            raise AssertionError("G46 fixture command must remain inert")
        if self.target_origin != "fixture://owned-g46-mobile-api":
            raise AssertionError("G46 fixture command may target only the owned simulation")
        payload = {
            "command_id": self.command_id,
            "admission_id": self.admission_id,
            "manifest_digest": self.manifest_digest,
            "scope_id": self.scope_id,
            "target_origin": self.target_origin,
            "action_budget": self.action_budget,
            "observation_digest": self.observation_digest,
        }
        if self.command_digest != _sha256(payload):
            raise AssertionError("G46 fixture command digest is invalid")


def prepare_g46_gateway_command(
    observation: MobileApiBindingRun,
    manifest: G46PinnedManifest,
    admission_token: G46AdmissionToken,
    authority_public_key: bytes,
    now_epoch_seconds: int,
) -> G46PreparedGatewayCommand:
    """Prepare one non-dispatched command from a verified admission token only."""

    identities = G46SyntheticIdentities(
        device_id=admission_token.device_id,
        application_id=admission_token.application_id,
        api_id=admission_token.api_id,
    )
    admission_token.assert_verified(
        manifest, identities, authority_public_key, now_epoch_seconds
    )
    if observation.evidence.classification != "diagnostic_candidate":
        raise ValueError("G46 prepares a command only for a diagnostic candidate")
    if observation.evidence.app_link_application_id != admission_token.application_id:
        raise ValueError("G46 observation application is outside the admitted scope")
    if observation.evidence.api_binding_id != admission_token.api_id:
        raise ValueError("G46 observation API is outside the admitted scope")
    payload = {
        "command_id": "command.g46.prepare-mobile-api-candidate",
        "admission_id": admission_token.admission_id,
        "manifest_digest": manifest.manifest_digest,
        "scope_id": admission_token.scope_id,
        "target_origin": manifest.api_origin,
        "action_budget": admission_token.action_budget,
        "observation_digest": observation.evidence.normalized_observation.source_digest,
    }
    command = G46PreparedGatewayCommand(
        command_id="command.g46.prepare-mobile-api-candidate",
        command_digest=_sha256(payload),
        admission_id=admission_token.admission_id,
        manifest_digest=manifest.manifest_digest,
        scope_id=admission_token.scope_id,
        target_origin=manifest.api_origin,
        action_budget=admission_token.action_budget,
        observation_digest=observation.evidence.normalized_observation.source_digest,
    )
    command.assert_inert()
    return command


@dataclass(frozen=True, slots=True)
class G46VerifierReceipt:
    receipt_digest: str
    admission_id: str
    manifest_digest: str
    observation_digest: str
    control: Literal["candidate", "matched_negative_control"]
    command_prepared: bool
    command_dispatched: Literal[False]
    fixture_invariants_passed: Literal[True]
    classification: Literal["candidate_only"] = "candidate_only"
    security_verified: Literal[False] = False


def verify_g46_fixture(
    observation: MobileApiBindingRun,
    manifest: G46PinnedManifest,
    admission_token: G46AdmissionToken,
    command: G46PreparedGatewayCommand | None,
    authority_public_key: bytes,
    now_epoch_seconds: int,
) -> G46VerifierReceipt:
    """Return a stable fixture receipt while retaining candidate-only truthfulness."""

    identities = G46SyntheticIdentities(
        device_id=admission_token.device_id,
        application_id=admission_token.application_id,
        api_id=admission_token.api_id,
    )
    admission_token.assert_verified(
        manifest, identities, authority_public_key, now_epoch_seconds
    )
    candidate = observation.evidence.classification == "diagnostic_candidate"
    if candidate:
        if command is None:
            raise ValueError("G46 candidate requires one inert prepared command")
        command.assert_inert()
        if (
            command.admission_id != admission_token.admission_id
            or command.manifest_digest != manifest.manifest_digest
            or command.scope_id != admission_token.scope_id
            or command.action_budget != admission_token.action_budget
            or command.observation_digest != observation.evidence.normalized_observation.source_digest
        ):
            raise ValueError("G46 command exceeds admitted authority")
    elif command is not None:
        raise ValueError("G46 matched negative control must not prepare a command")
    control: Literal["candidate", "matched_negative_control"] = (
        "candidate" if candidate else "matched_negative_control"
    )
    unsigned = {
        "admission_id": admission_token.admission_id,
        "manifest_digest": manifest.manifest_digest,
        "observation_digest": observation.evidence.normalized_observation.source_digest,
        "control": control,
        "command_prepared": command is not None,
        "command_dispatched": False,
        "fixture_invariants_passed": True,
        "classification": "candidate_only",
        "security_verified": False,
    }
    receipt = G46VerifierReceipt(
        receipt_digest=_sha256(unsigned),
        admission_id=admission_token.admission_id,
        manifest_digest=manifest.manifest_digest,
        observation_digest=observation.evidence.normalized_observation.source_digest,
        control=control,
        command_prepared=command is not None,
        command_dispatched=False,
        fixture_invariants_passed=True,
    )
    assert_g46_no_secrets((manifest, admission_token, command, receipt))
    return receipt


def assert_g46_no_secrets(values: object) -> None:
    """Reject credential-shaped material from the fixture's public artifacts."""

    serialized = _canonical(_public_document(values)).decode("utf-8").lower()
    if any(marker in serialized for marker in _FORBIDDEN_MATERIAL):
        raise AssertionError("G46 fixture artifacts must not contain secret material")


def _public_document(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return _bytes_digest(value)
    if isinstance(value, Mapping):
        return {str(key): _public_document(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_public_document(item) for item in value]
    if isinstance(
        value,
        (
            G46PinnedManifest,
            G46SyntheticIdentities,
            G46AdmissionToken,
            G46PreparedGatewayCommand,
            G46VerifierReceipt,
        ),
    ):
        return _public_document(asdict(value))
    raise TypeError(f"G46 cannot serialize {type(value).__name__}")
