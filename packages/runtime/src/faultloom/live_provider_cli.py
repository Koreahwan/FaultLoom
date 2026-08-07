"""Operator-facing composition root for one authorized provider-only turn."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

from cryptography.exceptions import InvalidSignature
from faultloom_protocol import (
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    SignedAuthorityGrant,
    SignedScopeEpoch,
    canonical_json_bytes,
    load_public_key,
    verify_authority_grant,
)
from faultloom_protocol.models import AuthorityGrant, TargetAsset
from faultloom_sdk import AdapterAdmissionRegistry, reference_registry
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from ._provider.adapter import ProviderAdapter
from ._provider.anchored_journal import AnchoredProviderReceiptJournal
from ._provider.intent import ProviderCallIntent
from ._provider.metadata import ProviderModelProfile
from ._provider.openai_compatible import (
    BoundEnvironmentCredentialResolver,
    OpenAICompatibleCredentialBinding,
    OpenAICompatibleEgressTransport,
    OpenAICompatibleEndpointConfig,
    OpenAICompatibleHttpPort,
    OpenAICompatiblePayloadStore,
    OpenAICompatibleProviderProxy,
)
from ._provider.proxy import ProviderProxyPort
from .automation.candidate_outbox import write_automation_result_bundle
from .automation.coordinator import AuthorizedAutomationCoordinator
from .automation.models import AutomationRequest
from .automation.provider_contract import (
    model_turn_openai_function_schema,
    model_turn_provider_tool_spec,
)
from .automation.provider_prompt import OneShotReasoningPromptResolver
from .automation.provider_runner import run_provider_automation_turn
from .egress import (
    DestinationResolution,
    DestinationResolver,
    EgressPlane,
    PinnedDestinationResolver,
    ProviderEndpoint,
    ProviderTool,
    SqliteEgressStateStore,
    TrustedAuthorityState,
)
from .egress import (
    ProviderProxy as EgressProviderProxy,
)
from .egress import (
    ProviderToolKind as EgressProviderToolKind,
)
from .egress import (
    sha256_digest as egress_sha256_digest,
)
from .egress_state import EgressStateCheckpoint
from .state import AnchorCheckpoint, EngagementKey, StateStore
from .tool_planner import ToolPlanner


class LiveProviderTurnError(RuntimeError):
    """Expected fail-closed operator error."""

    def __init__(self, detail: str, *, authority: bool) -> None:
        super().__init__(detail)
        self.authority = authority


class ProviderRuntimeConfig(BaseModel):
    """Serializable public provider facts; no credential value is admitted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: OpenAICompatibleEndpointConfig
    profile: ProviderModelProfile
    destination: PinnedDestinationConfig
    credential_environment_variable: str

    @field_validator("credential_environment_variable")
    @classmethod
    def _environment_name(cls, value: str) -> str:
        if not value or not value.isascii() or not value.replace("_", "A").isalnum():
            raise ValueError("credential environment variable must be an identifier")
        if value != value.upper() or value[0].isdigit():
            raise ValueError("credential environment variable must be uppercase")
        return value


class PinnedDestinationConfig(BaseModel):
    """JSON representation converted to the exact egress resolution type."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plane: Literal[EgressPlane.MODEL_PROVIDER]
    origin: str
    cname_chain: tuple[str, ...] = ()
    addresses: tuple[str, ...]

    def as_resolution(self) -> DestinationResolution:
        return DestinationResolution(
            schema_version="0.1.0",
            plane=self.plane,
            origin=self.origin,
            cname_chain=self.cname_chain,
            addresses=self.addresses,
        )


class SignedProviderRuntimeConfig(BaseModel):
    """Authority-signed envelope for every provider routing and secret selector fact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1.0"] = "0.1.0"
    purpose: Literal["faultloom.provider-runtime-config.v1"] = (
        "faultloom.provider-runtime-config.v1"
    )
    grant_id: str
    grant_version: int
    issuer_key_id: str
    payload_digest: str
    payload: ProviderRuntimeConfig
    signature: str

    @field_validator("grant_id", "issuer_key_id", "payload_digest", "signature")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("signed provider config fields must be non-empty and unpadded")
        return value

    @field_validator("grant_version")
    @classmethod
    def _positive_version(cls, value: int) -> int:
        if type(value) is not int or value < 1:
            raise ValueError("signed provider config grant version must be positive")
        return value


def _provider_config_digest(config: ProviderRuntimeConfig) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(config.model_dump(mode="json"))
    ).hexdigest()


def _provider_config_signing_document(
    *,
    config: ProviderRuntimeConfig,
    grant_id: str,
    grant_version: int,
    issuer_key_id: str,
    payload_digest: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "domain": "faultloom.provider-runtime-config.signature.v1",
            "schema_version": "0.1.0",
            "purpose": "faultloom.provider-runtime-config.v1",
            "grant_id": grant_id,
            "grant_version": grant_version,
            "issuer_key_id": issuer_key_id,
            "payload_digest": payload_digest,
            "payload": config.model_dump(mode="json"),
        }
    )


def sign_provider_runtime_config_value(
    config: ProviderRuntimeConfig,
    authority: SignedAuthorityGrant,
    signer: AuthoritySigner,
) -> SignedProviderRuntimeConfig:
    if signer.key_id != authority.signature.key_id:
        raise LiveProviderTurnError(
            "provider config signer does not match the signed authority key",
            authority=True,
        )
    verification_time = max(authority.signature.signed_at, authority.payload.not_before)
    try:
        verified = verify_authority_grant(
            authority,
            signer.public_key_record,
            now=verification_time,
            minimum_version=authority.payload.grant_version,
            expected_grant_id=authority.payload.grant_id,
        )
    except Exception as exc:
        raise LiveProviderTurnError(
            "signed authority is not valid for provider config signing",
            authority=True,
        ) from exc
    digest = _provider_config_digest(config)
    document = _provider_config_signing_document(
        config=config,
        grant_id=verified.grant_id,
        grant_version=verified.grant_version,
        issuer_key_id=signer.key_id,
        payload_digest=digest,
    )
    return SignedProviderRuntimeConfig(
        grant_id=verified.grant_id,
        grant_version=verified.grant_version,
        issuer_key_id=signer.key_id,
        payload_digest=digest,
        payload=config,
        signature=signer.sign(document),
    )


def _decode_signature(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(canonical, value) or len(decoded) != 64:
            raise ValueError("signature is not canonical Ed25519 material")
        return decoded
    except (ValueError, TypeError) as exc:
        raise LiveProviderTurnError(
            "provider runtime config signature is malformed",
            authority=True,
        ) from exc


def verify_provider_runtime_config(
    envelope: SignedProviderRuntimeConfig,
    *,
    trusted_key: Ed25519PublicKeyRecord,
    signed_authority: SignedAuthorityGrant,
    grant: AuthorityGrant,
) -> ProviderRuntimeConfig:
    if (
        envelope.issuer_key_id != trusted_key.key_id
        or signed_authority.signature.key_id != trusted_key.key_id
        or envelope.grant_id != grant.grant_id
        or envelope.grant_version != grant.grant_version
        or signed_authority.payload != grant
    ):
        raise LiveProviderTurnError(
            "signed provider runtime config is bound to another authority",
            authority=True,
        )
    digest = _provider_config_digest(envelope.payload)
    if not hmac.compare_digest(digest, envelope.payload_digest):
        raise LiveProviderTurnError(
            "signed provider runtime config payload digest mismatch",
            authority=True,
        )
    document = _provider_config_signing_document(
        config=envelope.payload,
        grant_id=envelope.grant_id,
        grant_version=envelope.grant_version,
        issuer_key_id=envelope.issuer_key_id,
        payload_digest=envelope.payload_digest,
    )
    try:
        load_public_key(trusted_key).verify(
            _decode_signature(envelope.signature),
            document,
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise LiveProviderTurnError(
            "signed provider runtime config signature verification failed",
            authority=True,
        ) from exc
    return ProviderRuntimeConfig.model_validate(envelope.payload.model_dump(mode="python"))


@dataclass(frozen=True, slots=True)
class LiveProviderTurnDependencies:
    verify_workspace: Callable[
        [Path, Path], tuple[dict[str, object], AuthorityGrant, TargetAsset, datetime]
    ]
    capture_file: Callable[[Path], bytes]
    emit_json: Callable[[object], None]
    environment: Mapping[str, str]
    http_port: OpenAICompatibleHttpPort | None = None


def sign_provider_runtime_config_file(
    arguments: object,
    *,
    capture_file: Callable[[Path], bytes],
    write_new_file: Callable[[Path, bytes], None],
    emit_json: Callable[[object], None],
) -> int:
    config_path = getattr(arguments, "config", None)
    authority_path = getattr(arguments, "authority", None)
    private_key_path = getattr(arguments, "private_key", None)
    output_path = getattr(arguments, "out", None)
    if any(
        not isinstance(path, Path)
        for path in (config_path, authority_path, private_key_path, output_path)
    ):
        raise LiveProviderTurnError("provider config signing paths are invalid", authority=False)
    config_path, authority_path, private_key_path, output_path = cast(
        tuple[Path, Path, Path, Path],
        (config_path, authority_path, private_key_path, output_path),
    )
    config = _parse_exact(config_path, capture_file(config_path), ProviderRuntimeConfig)
    authority = _parse_exact(
        authority_path,
        capture_file(authority_path),
        SignedAuthorityGrant,
    )
    signer = AuthoritySigner.from_private_bytes(
        _private_seed(private_key_path, capture_file(private_key_path))
    )
    envelope = sign_provider_runtime_config_value(config, authority, signer)
    write_new_file(
        output_path,
        envelope.model_dump_json().encode("utf-8") + b"\n",
    )
    emit_json(
        {
            "grant_id": envelope.grant_id,
            "grant_version": envelope.grant_version,
            "issuer_key_id": envelope.issuer_key_id,
            "out": str(output_path),
            "payload_digest": envelope.payload_digest,
        }
    )
    return 0


def _parse_exact[ModelT: BaseModel](
    path: Path,
    content: bytes,
    model: type[ModelT],
) -> ModelT:
    try:
        text = content.decode("utf-8")
        _ = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        return model.model_validate_json(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise LiveProviderTurnError(f"invalid {path}: {exc}", authority=False) from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _private_seed(path: Path, content: bytes) -> bytes:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("must be a regular non-symlink file")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("must have mode 0600")
        raw = content[:-1] if content.endswith(b"\n") else content
        text = raw.decode("ascii")
        if "\r" in text or "\n" in text or len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
            raise ValueError("expected one lowercase 64-character hex seed")
        return bytes.fromhex(text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise LiveProviderTurnError(f"invalid private key file {path}: {exc}", authority=True) from exc


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LiveProviderTurnError(
            f"runtime directory {path} must be a real directory, not a symlink",
            authority=True,
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid():
        raise LiveProviderTurnError(
            f"runtime directory {path} must be owner-controlled with mode 0700",
            authority=True,
        )


def _runtime_paths(root: Path) -> dict[str, Path]:
    if os.name == "nt" or not hasattr(os, "O_NOFOLLOW"):
        raise LiveProviderTurnError(
            "live provider state requires durable POSIX no-follow and file-lock primitives",
            authority=True,
        )
    if not root.is_absolute() or any(part in {"", ".", ".."} for part in root.parts[1:]):
        raise LiveProviderTurnError("--runtime-dir must be an absolute canonical path", authority=False)
    paths = {
        "egress_state": root / "egress-state",
        "egress_anchor": root / "egress-anchor",
        "provider_state": root / "provider-state",
        "provider_anchor": root / "provider-anchor",
        "checkpoints": root / "checkpoints",
    }
    _mkdir_private(root)
    for path in paths.values():
        _mkdir_private(path)
    return paths


def _load_checkpoint(path: Path, *, kind: str) -> EgressStateCheckpoint | AnchorCheckpoint | None:
    if not path.exists():
        return None
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
        ):
            raise ValueError("checkpoint must be an owner-controlled mode-0600 regular file")
        value = json.loads(path.read_text("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        if type(value) is not dict:
            raise ValueError("checkpoint must be an object")
        if kind == "egress":
            if set(value) != {"sequence", "state_digest", "store_id"}:
                raise ValueError("egress checkpoint keys changed")
            return EgressStateCheckpoint(**value)
        if set(value) != {"engagement_id", "seq", "head"}:
            raise ValueError("provider checkpoint keys changed")
        return AnchorCheckpoint(**value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise LiveProviderTurnError(f"invalid durable checkpoint {path}: {exc}", authority=True) from exc


def _store_checkpoint(path: Path, value: EgressStateCheckpoint | AnchorCheckpoint) -> None:
    document = (
        {"sequence": value.sequence, "state_digest": value.state_digest, "store_id": value.store_id}
        if isinstance(value, EgressStateCheckpoint)
        else {"engagement_id": value.engagement_id, "seq": value.seq, "head": value.head}
    )
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _validate_public_bindings(
    config: ProviderRuntimeConfig,
    intent: ProviderCallIntent,
    request: AutomationRequest,
    scope_epoch: SignedScopeEpoch,
) -> None:
    endpoint = config.endpoint
    profile = config.profile
    destination = config.destination.as_resolution()
    try:
        profile.require_live_safe()
    except Exception as exc:
        raise LiveProviderTurnError("provider profile is not live-safe exact metadata", authority=True) from exc
    if (
        destination.plane is not EgressPlane.MODEL_PROVIDER
        or destination.origin != endpoint.origin
        or profile.endpoint_id != endpoint.endpoint_id
        or profile.provider_id != endpoint.provider_id
        or profile.exact_snapshot != endpoint.model
        or intent.profile_id != profile.profile_id
        or intent.credential_ref != endpoint.credential_ref
        or intent.credential_ref.purpose != f"model-provider:{endpoint.provider_id}"
        or intent.policy_ref != profile.policy_ref
        or intent.data_policy_id != profile.data_policy_id
        or intent.data_consent_ref != profile.data_consent_ref
        or intent.scope_epoch != scope_epoch.payload.epoch
        or scope_epoch.payload.grant_id != request.authority_grant.grant_id
    ):
        raise LiveProviderTurnError("provider runtime binding does not match request, intent, or scope epoch", authority=True)
    observed = endpoint.metadata
    if (
        observed.provider_id != profile.provider_id
        or observed.actual_snapshot != profile.exact_snapshot
        or observed.runtime_version != profile.runtime_version
        or observed.tokenizer_id != profile.tokenizer_id
        or observed.tokenizer_version != profile.tokenizer_version
        or observed.context_window != profile.context_window
        or not all((observed.snapshot_exact, observed.runtime_exact, observed.tokenizer_exact, observed.context_window_exact))
    ):
        raise LiveProviderTurnError("endpoint observations do not match the exact provider profile", authority=True)


def run_live_provider_turn(arguments: object, *, dependencies: LiveProviderTurnDependencies) -> int:
    """Dispatch exactly one provider turn and publish a candidate-only bundle."""

    raw_paths = tuple(
        getattr(arguments, name, None)
        for name in (
            "workspace", "trusted_key", "request", "runtime_config", "base_intent",
            "scope_epoch", "reconciliation_key", "egress_state_key",
            "provider_state_key", "proxy_attestation_key", "runtime_dir",
        )
    )
    if any(not isinstance(value, Path) for value in raw_paths):
        raise LiveProviderTurnError("provider-turn path arguments are invalid", authority=False)
    (
        workspace, trusted_key_path, request_path, runtime_config_path,
        base_intent_path, scope_epoch_path, reconciliation_key_path,
        egress_state_key_path, provider_state_key_path, proxy_attestation_key_path,
        runtime_dir,
    ) = cast(tuple[Path, Path, Path, Path, Path, Path, Path, Path, Path, Path, Path], raw_paths)
    disclosure_paths = getattr(arguments, "trusted_disclosure_key", None)
    if type(disclosure_paths) is not list or not disclosure_paths or any(not isinstance(path, Path) for path in disclosure_paths):
        raise LiveProviderTurnError("provider-turn requires trusted disclosure public keys", authority=False)
    disclosure_paths = cast(list[Path], disclosure_paths)
    minimum_grant_version = getattr(arguments, "minimum_grant_version", None)
    if type(minimum_grant_version) is not int:
        raise LiveProviderTurnError("provider-turn minimum grant version is invalid", authority=False)

    manifest, grant, _target, now = dependencies.verify_workspace(workspace, trusted_key_path)
    if grant.grant_version < minimum_grant_version:
        raise LiveProviderTurnError("signed grant version is below the required minimum", authority=True)

    request = _parse_exact(request_path, dependencies.capture_file(request_path), AutomationRequest)
    signed_config = _parse_exact(
        runtime_config_path,
        dependencies.capture_file(runtime_config_path),
        SignedProviderRuntimeConfig,
    )
    intent = _parse_exact(base_intent_path, dependencies.capture_file(base_intent_path), ProviderCallIntent)
    signed_epoch = _parse_exact(scope_epoch_path, dependencies.capture_file(scope_epoch_path), SignedScopeEpoch)
    signed_authority = _parse_exact(workspace / "authority.json", dependencies.capture_file(workspace / "authority.json"), SignedAuthorityGrant)
    authority_key = _parse_exact(trusted_key_path, dependencies.capture_file(trusted_key_path), Ed25519PublicKeyRecord)
    reconciliation_key = _parse_exact(reconciliation_key_path, dependencies.capture_file(reconciliation_key_path), Ed25519PublicKeyRecord)
    if signed_authority.payload != grant or request.authority_grant != grant or request.observations.run_id != manifest.get("run_id"):
        raise LiveProviderTurnError("provider-turn request is not bound to the signed workspace", authority=True)
    config = verify_provider_runtime_config(
        signed_config,
        trusted_key=authority_key,
        signed_authority=signed_authority,
        grant=grant,
    )
    _validate_public_bindings(config, intent, request, signed_epoch)

    disclosure_keys: dict[str, Ed25519PublicKeyRecord] = {}
    for path in disclosure_paths:
        parsed = _parse_exact(path, dependencies.capture_file(path), Ed25519PublicKeyRecord)
        if parsed.key_id in disclosure_keys:
            raise LiveProviderTurnError("trusted disclosure key ID is duplicated", authority=True)
        disclosure_keys[parsed.key_id] = parsed

    environment_name = config.credential_environment_variable
    credential = dependencies.environment.get(environment_name)
    if type(credential) is not str or not credential:
        raise LiveProviderTurnError(f"credential environment variable {environment_name} is absent", authority=True)

    egress_key = _private_seed(egress_state_key_path, dependencies.capture_file(egress_state_key_path))
    provider_key = _private_seed(provider_state_key_path, dependencies.capture_file(provider_state_key_path))
    proxy_signer = AuthoritySigner.from_private_bytes(
        _private_seed(proxy_attestation_key_path, dependencies.capture_file(proxy_attestation_key_path))
    )
    paths = _runtime_paths(runtime_dir)
    egress_checkpoint_path = paths["checkpoints"] / "egress.json"
    provider_checkpoint_path = paths["checkpoints"] / "provider.json"
    egress_floor = _load_checkpoint(egress_checkpoint_path, kind="egress") or EgressStateCheckpoint.empty()
    loaded_provider_floor = _load_checkpoint(provider_checkpoint_path, kind="provider")
    if loaded_provider_floor is not None and not isinstance(loaded_provider_floor, AnchorCheckpoint):
        raise LiveProviderTurnError("provider checkpoint has the wrong type", authority=True)
    provider_floor = loaded_provider_floor
    assert isinstance(egress_floor, EgressStateCheckpoint)

    egress_store = SqliteEgressStateStore(
        paths["egress_state"] / "state.sqlite3",
        anchor_path=paths["egress_anchor"] / "state.anchor",
        authentication_key=egress_key,
        minimum_anchor=egress_floor,
    )
    provider_store: StateStore | None = None
    try:
        authority_state = TrustedAuthorityState(
            trust_domain="authority.provider-turn",
            trusted_key=authority_key,
            trusted_reconciliation_key=reconciliation_key,
            authority=signed_authority,
            scope_epoch=signed_epoch,
            state_store=egress_store,
        )
        verified_grant, verified_epoch = authority_state.verify(now)
        if verified_grant != grant or verified_epoch.epoch != intent.scope_epoch:
            raise LiveProviderTurnError("signed provider authority state does not match the workspace", authority=True)

        destination = config.destination.as_resolution()
        resolver = PinnedDestinationResolver((destination,))
        resolution_digest = egress_sha256_digest(destination)
        destination_digest = egress_sha256_digest({
            "plane": EgressPlane.MODEL_PROVIDER,
            "endpoint_id": config.endpoint.endpoint_id,
            "origin": config.endpoint.origin,
            "resolution_digest": resolution_digest,
        })
        payload_store = OpenAICompatiblePayloadStore()
        credential_resolver = BoundEnvironmentCredentialResolver(
            bindings=(OpenAICompatibleCredentialBinding(
                credential_ref=config.endpoint.credential_ref,
                endpoint_id=config.endpoint.endpoint_id,
                provider_id=config.endpoint.provider_id,
                origin=config.endpoint.origin,
                resolution_digest=resolution_digest,
                destination_digest=destination_digest,
                environment_variable=environment_name,
            ),),
            environment={environment_name: credential},
        )
        function_schema = model_turn_openai_function_schema()
        if dependencies.http_port is None:
            transport = OpenAICompatibleEgressTransport(
                endpoints=(config.endpoint,), payload_store=payload_store,
                credential_resolver=credential_resolver, tool_schemas=(function_schema,),
            )
            live = True
        else:
            transport = OpenAICompatibleEgressTransport.for_testing(
                endpoints=(config.endpoint,), payload_store=payload_store,
                credential_resolver=credential_resolver, http_port=dependencies.http_port,
                tool_schemas=(function_schema,),
            )
            live = False
        egress_endpoint = ProviderEndpoint(
            schema_version="0.1.0", endpoint_id=config.endpoint.endpoint_id,
            provider_id=config.endpoint.provider_id, origin=config.endpoint.origin,
            tools=(ProviderTool(schema_version="0.1.0", tool_id=model_turn_provider_tool_spec().tool_id, kind=EgressProviderToolKind.LOCAL),),
        )
        egress_proxy = EgressProviderProxy(
            endpoints=(egress_endpoint,), transport=transport,
            resolver=cast(DestinationResolver, cast(object, resolver)),
            authority_state=authority_state, live=live, clock=lambda: now,
        )
        prompt_resolver = OneShotReasoningPromptResolver()
        provider_proxy = OpenAICompatibleProviderProxy(
            proxy_id="provider.openai-compatible.operator", endpoints=(config.endpoint,),
            prompt_resolver=prompt_resolver.resolve, payload_store=payload_store,
            egress_proxy=egress_proxy, transport=transport, attestation_signer=proxy_signer,
        )
        provider_store = StateStore(
            paths["provider_state"], f"provider.{request.observations.run_id}", EngagementKey(provider_key),
            anchor_root=paths["provider_anchor"], minimum_anchor=provider_floor,
        )
        journal = AnchoredProviderReceiptJournal(provider_store, minimum_anchor=provider_store.checkpoint())
        adapter = ProviderAdapter(
            profiles=(config.profile,),
            proxy=cast(ProviderProxyPort, cast(object, provider_proxy)),
            trusted_proxy_attestation_key=proxy_signer.public_key_record,
            journal=journal, live=live, clock=lambda: now,
        )
        registry = reference_registry()
        coordinator = AuthorizedAutomationCoordinator(planner=ToolPlanner(registry, AdapterAdmissionRegistry(registry)))
        result = run_provider_automation_turn(
            request=request, base_intent=intent, resolver=prompt_resolver, adapter=adapter,
            trusted_proxy_attestation_key=proxy_signer.public_key_record,
            trusted_disclosure_keys=disclosure_keys, coordinator=coordinator,
            trusted_clock=lambda: now,
        )
        publication = write_automation_result_bundle(result, workspace / "automation")
        dependencies.emit_json({
            "automatic_submission": False,
            "candidate": None if publication.candidate_path is None else str(publication.candidate_path),
            "digest": publication.result_digest,
            "independent_verification": False,
            "provider_dispatch": True,
            "receipt": str(publication.receipt_path),
            "result": str(publication.result_path),
            "target_dispatch": False,
        })
        return 0
    except LiveProviderTurnError:
        raise
    except Exception as exc:
        raise LiveProviderTurnError(f"provider-turn failed closed: {exc}", authority=True) from exc
    finally:
        try:
            _store_checkpoint(egress_checkpoint_path, egress_store.checkpoint())
            if provider_store is not None:
                _store_checkpoint(provider_checkpoint_path, provider_store.checkpoint())
        finally:
            if provider_store is not None:
                provider_store.close()
            egress_store.close()


__all__ = [
    "LiveProviderTurnDependencies",
    "LiveProviderTurnError",
    "ProviderRuntimeConfig",
    "run_live_provider_turn",
]
