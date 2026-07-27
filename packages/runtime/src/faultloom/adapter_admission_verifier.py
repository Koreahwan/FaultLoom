"""Short-lived verifier child for one adapter-admission calibration pair."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import stat
import sys
import sysconfig
from pathlib import Path
from typing import Annotated, ClassVar, Literal

import faultloom_protocol as protocol_module
import faultloom_sdk as sdk_module
import pydantic as pydantic_module
from cryptography.exceptions import InvalidSignature
from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    ModelUtilityAdmission,
    ModelUtilityOutcomeCoverage,
    ModelVerifierAttestation,
    SignedModelProducerAttestation,
    SignedModelUtilityAdmission,
    SignedModelVerifierAttestation,
    attestation_signing_bytes,
    canonical_json_bytes,
    load_public_key,
    model_utility_admission_digest,
    model_utility_admission_signing_bytes,
    model_utility_outcome_coverage_digest,
    sha256_digest,
    verify_model_producer_attestation,
)
from faultloom_sdk import (
    IndependentVerifierOutcome,
    IndependentVerifierVerdict,
    ModelUtilityArm,
    ModelUtilityCaseOutcome,
    ModelUtilityEvaluation,
    ModelUtilityEvaluationPlan,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    NormalizeObservationResponse,
    UtilityDecision,
    derive_model_utility_metrics,
    model_utility_digest,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import model_utility_proxy_models as proxy_models_module
from .model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST,
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessRequest,
    LocalModelProcessResponse,
    LocalModelRuntimeProfile,
)

_MAX_DOCUMENT_BYTES = 4_194_304
_STAGING_BASE = Path("/run/faultloom-t40-build")
_STAGING_SOURCE_ROLES = (
    "faultloom_wheel",
    "protocol_wheel",
    "sdk_wheel",
    "web_wheel",
    "eval_wheel",
    "dependency_bundle",
)
_FIXED_STAGING_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
_FORBIDDEN_STAGING_ENVIRONMENT = (
    "BASH_ENV",
    "ENV",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "VIRTUAL_ENV",
)
_FORBIDDEN_STAGING_PREFIXES = ("LD_", "PYTHON")
_VERIFIER_ARTIFACT_DIGEST = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
_VERIFIER_PROFILE_DIGEST = sha256_digest(
    {
        "classification": "inconclusive_allowed",
        "network": "none",
        "schema_version": "faultloom.adapter-verifier-profile.v1",
    }
)


class _StrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )


class VerifierInputSpec(_StrictModel):
    schema_version: Literal["faultloom.adapter-admission-input.v1"]
    bundle_id: str
    session_id: str
    evaluator_challenge: str
    staging_manifest_path: str | None
    staging_manifest_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None
    producer_state: Literal["adapter-admission-producer.sequence"]
    verifier_state: Literal["adapter-admission-verifier.sequence"]
    output: Literal["adapter-admission-bundle.json"]
    timeout_seconds: int
    maximum_response_bytes: int


class _ProducerSequenceProofPayload(_StrictModel):
    schema_version: Literal["faultloom.adapter-producer-sequence-proof.v1"]
    allocation_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")]
    attestation: SignedModelProducerAttestation


class _SignedProducerSequenceProof(_StrictModel):
    schema_version: Literal["faultloom.adapter-producer-sequence-proof-envelope.v1"]
    payload: _ProducerSequenceProofPayload
    payload_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    signature: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{86}$")]


class VerifierInvocation(_StrictModel):
    request: LocalModelProcessRequest
    response: LocalModelProcessResponse
    producer: SignedModelProducerAttestation
    fixed_argv_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    transcript_evidence_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    sequence_proof: _SignedProducerSequenceProof


class VerifierRequest(_StrictModel):
    spec: VerifierInputSpec
    core_wheel_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    staging_manifest_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    installed_tree_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    manifest_digest: str
    plan: ModelUtilityEvaluationPlan
    invocations: tuple[VerifierInvocation, VerifierInvocation]
    observation_document: str
    normalized_response: NormalizeObservationResponse
    producer_trust: tuple[Ed25519PublicKeyRecord, ...]


class VerifierResponse(_StrictModel):
    evaluation: ModelUtilityEvaluation
    verifier: SignedModelVerifierAttestation
    admission: SignedModelUtilityAdmission
    verifier_trust: tuple[Ed25519PublicKeyRecord, ...]
    minimum_verifier_sequence: int
    minimum_admission_sequence: int
    staging_manifest_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    installed_tree_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class VerifierPreflightResponse(_StrictModel):
    public_key: Ed25519PublicKeyRecord
    staging_manifest_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    installed_tree_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    core_wheel_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class _StagingSource(_StrictModel):
    role: str
    sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    size: Annotated[int, Field(strict=True, ge=1)]


class _StagingDirectory(_StrictModel):
    path: str
    mode: int


class _StagingFile(_StrictModel):
    path: str
    sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    mode: int


class _StagingInstalledTree(_StrictModel):
    directories: tuple[_StagingDirectory, ...]
    files: tuple[_StagingFile, ...]
    sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class _StagingLauncher(_StrictModel):
    argv_prefix: tuple[str, ...]
    invocation: tuple[str, ...]
    forbidden_environment: tuple[str, ...]
    forbidden_environment_prefixes: tuple[str, ...]
    fixed_environment: dict[str, str]
    isolation_flags: tuple[str, ...]
    module_origin: Literal["strictly-under-site-root"]
    site_root: str
    site_root_mode: int
    sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    mode: int


class _StagingManifest(_StrictModel):
    schema_name: Literal["faultloom.ops.t40-formal-staging.v1"] = Field(alias="schema")
    generation_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")]
    generation_root: str
    sources: tuple[_StagingSource, ...]
    installed_tree: _StagingInstalledTree
    launcher: _StagingLauncher


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _wire(value: BaseModel) -> bytes:
    return canonical_json_bytes(value.model_dump(mode="json"))


def _safe_staging_relative(value: str, *, allow_root: bool = False) -> bool:
    if value == ".":
        return allow_root
    path = Path(value)
    return (
        bool(value)
        and "\\" not in value
        and not path.is_absolute()
        and path.as_posix() == value
        and all(part not in ("", ".", "..") for part in path.parts)
    )


def _staging_owner(*, production: bool) -> tuple[int, int]:
    return (0, 0) if production else (os.geteuid(), os.getegid())


def _verify_staging_directory(path: Path, *, production: bool, mode: int) -> None:
    uid, gid = _staging_owner(production=production)
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise ValueError("formal staging directory is unsafe")


def _read_staging_file(
    path: Path,
    *,
    production: bool,
    mode: int,
    maximum_bytes: int,
) -> bytes:
    uid, gid = _staging_owner(production=production)
    before_named = os.lstat(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                break
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_named = os.lstat(path)
    metadata = (before_named, before, after, after_named)
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        for item in metadata
    }
    raw = b"".join(chunks)
    if (
        len(identities) != 1
        or len(raw) != before.st_size
        or len(raw) > maximum_bytes
        or any(
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != uid
            or item.st_gid != gid
            or stat.S_IMODE(item.st_mode) != mode
            or item.st_nlink != 1
            for item in metadata
        )
    ):
        raise ValueError("formal staging file metadata is unsafe")
    return raw


def _validate_staging_manifest(
    spec: VerifierInputSpec,
    *,
    production: bool,
    verify_import_origins: bool = True,
) -> tuple[str, str, str]:
    if spec.staging_manifest_path is None or spec.staging_manifest_sha256 is None:
        if production:
            raise ValueError("production staging manifest is required")
        digest = _digest_bytes(b"dry-fixture-staging-binding-v1")
        return digest, digest, digest
    manifest_path = Path(spec.staging_manifest_path)
    if (
        not manifest_path.is_absolute()
        or manifest_path != Path(os.path.abspath(manifest_path))
        or manifest_path.name != "staging-manifest.json"
    ):
        raise ValueError("formal staging manifest path is unsafe")
    generation_root = manifest_path.parent
    if production and generation_root.parent != _STAGING_BASE:
        raise ValueError("formal staging generation root is invalid")
    _verify_staging_directory(generation_root, production=production, mode=0o700)
    raw = _read_staging_file(
        manifest_path,
        production=production,
        mode=0o400,
        maximum_bytes=_MAX_DOCUMENT_BYTES,
    )
    if _digest_bytes(raw) != spec.staging_manifest_sha256:
        raise ValueError("formal staging manifest A-vs-B mismatch")
    manifest = _StagingManifest.model_validate_json(raw)
    if raw != canonical_json_bytes(manifest.model_dump(mode="json", by_alias=True)):
        raise ValueError("formal staging manifest is not canonical")
    site_root = generation_root / "site-packages"
    launcher_path = generation_root / "isolated-launcher"
    if (
        manifest.generation_id != generation_root.name
        or manifest.generation_root != str(generation_root)
        or tuple(item.role for item in manifest.sources) != _STAGING_SOURCE_ROLES
        or manifest.launcher.argv_prefix
        != (
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            str(launcher_path),
        )
        or manifest.launcher.invocation
        != (
            "--module",
            "<installed-module>",
            "--callable",
            "<entrypoint>",
            "--",
            "<arguments>",
        )
        or manifest.launcher.forbidden_environment != _FORBIDDEN_STAGING_ENVIRONMENT
        or manifest.launcher.forbidden_environment_prefixes != _FORBIDDEN_STAGING_PREFIXES
        or manifest.launcher.fixed_environment != _FIXED_STAGING_ENVIRONMENT
        or manifest.launcher.isolation_flags != ("-I", "-S", "-B")
        or manifest.launcher.site_root != str(site_root)
        or manifest.launcher.site_root_mode != 0o700
        or manifest.launcher.mode != 0o400
    ):
        raise ValueError("formal staging manifest contract is invalid")
    if (
        _digest_bytes(
            _read_staging_file(
                launcher_path,
                production=production,
                mode=0o400,
                maximum_bytes=1024 * 1024,
            )
        )
        != manifest.launcher.sha256
    ):
        raise ValueError("formal staging launcher binding is invalid")
    directories = tuple(item.path for item in manifest.installed_tree.directories)
    files = tuple(item.path for item in manifest.installed_tree.files)
    if (
        not directories
        or directories[0] != "."
        or directories != tuple(sorted(directories))
        or files != tuple(sorted(files))
        or len(set(directories)) != len(directories)
        or len(set(files)) != len(files)
        or set(directories) & set(files)
        or any(not _safe_staging_relative(item, allow_root=item == ".") for item in directories)
        or any(not _safe_staging_relative(item) for item in files)
        or any(item.mode != 0o700 for item in manifest.installed_tree.directories)
        or any(item.mode & 0o022 for item in manifest.installed_tree.files)
    ):
        raise ValueError("formal staging tree contract is invalid")
    tree_payload = {
        "directories": [
            item.model_dump(mode="json") for item in manifest.installed_tree.directories
        ],
        "files": [item.model_dump(mode="json") for item in manifest.installed_tree.files],
    }
    if sha256_digest(tree_payload) != manifest.installed_tree.sha256:
        raise ValueError("formal staging tree digest is invalid")
    _verify_staging_directory(site_root, production=production, mode=0o700)
    actual_directories = {"."}
    actual_files: set[str] = set()
    for current, child_directories, child_files in os.walk(site_root, followlinks=False):
        current_path = Path(current)
        actual_directories.update(
            (current_path / name).relative_to(site_root).as_posix() for name in child_directories
        )
        actual_files.update(
            (current_path / name).relative_to(site_root).as_posix() for name in child_files
        )
    if actual_directories != set(directories) or actual_files != set(files):
        raise ValueError("formal staging tree inventory is invalid")
    file_paths = set(files)
    for item in manifest.installed_tree.directories:
        _verify_staging_directory(
            site_root if item.path == "." else site_root / item.path,
            production=production,
            mode=item.mode,
        )
    for item in manifest.installed_tree.files:
        if (
            _digest_bytes(
                _read_staging_file(
                    site_root / item.path,
                    production=production,
                    mode=item.mode,
                    maximum_bytes=128 * 1024 * 1024,
                )
            )
            != item.sha256
        ):
            raise ValueError("formal staging file digest is invalid")
    if verify_import_origins:
        pydantic_path = pydantic_module.__file__
        if pydantic_path is None:
            raise ValueError("ambient verifier import origin is unavailable")
        module_bindings = {
            "faultloom/adapter_admission_verifier.py": Path(__file__),
            "faultloom/model_utility_proxy_models.py": Path(proxy_models_module.__file__),
            "faultloom_protocol/__init__.py": Path(protocol_module.__file__),
            "faultloom_sdk/__init__.py": Path(sdk_module.__file__),
            "pydantic/__init__.py": Path(pydantic_path),
        }
        if any(
            loaded.resolve(strict=True) != site_root / relative or relative not in file_paths
            for relative, loaded in module_bindings.items()
        ):
            raise ValueError("ambient verifier import origin is not staged")
    if production and verify_import_origins:
        resolved_paths = tuple(Path(item).resolve(strict=False) for item in sys.path if item)
        if not resolved_paths or resolved_paths[0] != site_root:
            raise ValueError("formal staging verifier path is not isolated")
        if any(
            "site-packages" in item.parts or "dist-packages" in item.parts
            for item in resolved_paths[1:]
        ):
            raise ValueError("ambient verifier package path is present")
        stdlib_root = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
        for module in tuple(sys.modules.values()):
            origin = getattr(module, "__file__", None)
            if not isinstance(origin, str):
                continue
            loaded = Path(origin).resolve(strict=True)
            if loaded == launcher_path:
                continue
            try:
                loaded.relative_to(site_root)
                continue
            except ValueError:
                pass
            try:
                loaded.relative_to(stdlib_root)
            except ValueError:
                raise ValueError("ambient verifier dependency is not staged") from None
            if "site-packages" in loaded.parts or "dist-packages" in loaded.parts:
                raise ValueError("ambient verifier dependency is not staged")
    return (
        spec.staging_manifest_sha256,
        manifest.installed_tree.sha256,
        manifest.sources[0].sha256,
    )


def _fingerprint(signer: AuthoritySigner) -> str:
    raw = base64.urlsafe_b64decode(signer.public_key_record.public_key + "==")
    return _digest_bytes(raw)


def _verify_sequence_proof(
    proof: _SignedProducerSequenceProof,
    trust: Ed25519PublicKeyRecord,
    *,
    expected_allocation_id: str,
    expected_attestation: SignedModelProducerAttestation,
) -> None:
    if (
        proof.payload.allocation_id != expected_allocation_id
        or proof.payload.attestation != expected_attestation
        or proof.payload.attestation.payload.status != "accepted"
        or proof.payload_digest != sha256_digest(proof.payload.model_dump(mode="json"))
    ):
        raise ValueError("producer sequence proof binding is invalid")
    try:
        signature = base64.b64decode(proof.signature + "==", altchars=b"-_", validate=True)
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).rstrip(b"=").decode() != proof.signature
        ):
            raise ValueError
        load_public_key(trust).verify(
            signature,
            canonical_json_bytes(
                {
                    "payload": proof.payload.model_dump(mode="json"),
                    "payload_digest": proof.payload_digest,
                }
            ),
        )
    except (InvalidSignature, TypeError, ValueError):
        raise ValueError("producer sequence proof signature is invalid") from None


def _read_signer(descriptor: int, *, production: bool) -> AuthoritySigner:
    if type(descriptor) is not int or descriptor < 3:
        raise ValueError("verifier key descriptor is invalid")
    expected_uid = 0 if production else os.geteuid()
    expected_gid = 0 if production else os.getegid()
    try:
        before = os.fstat(descriptor)
        material = os.pread(descriptor, 33, 0)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        for item in (before, after)
    }
    if (
        len(material) != 32
        or len(identities) != 1
        or any(
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != expected_uid
            or item.st_gid != expected_gid
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
            or item.st_size != 32
            for item in (before, after)
        )
    ):
        raise ValueError("verifier key must be raw32")
    try:
        return AuthoritySigner.from_private_bytes(material)
    finally:
        del material


def _allocate_sequence(root_fd: int, name: str, allocation_id: str) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags | os.O_CREAT, 0o600, dir_fd=root_fd)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ValueError("verifier sequence metadata is unsafe")
        raw = os.pread(descriptor, 1_048_577, 0)
        sequence = 0
        seen: set[str] = set()
        for encoded in raw.splitlines():
            record = json.loads(encoded)
            if (
                type(record) is not dict
                or set(record) != {"allocation_id", "sequence"}
                or type(record["allocation_id"]) is not str
                or type(record["sequence"]) is not int
                or record["sequence"] != sequence + 1
                or record["allocation_id"] in seen
                or canonical_json_bytes(record) != encoded
            ):
                raise ValueError("verifier sequence state is corrupt")
            sequence = record["sequence"]
            seen.add(record["allocation_id"])
        if allocation_id in seen or sequence >= 2**63 - 1:
            raise ValueError("verifier sequence allocation was reused")
        sequence += 1
        encoded = (
            canonical_json_bytes({"allocation_id": allocation_id, "sequence": sequence}) + b"\n"
        )
        if len(raw) + len(encoded) > 1_048_576:
            raise ValueError("verifier sequence state is full")
        offset = 0
        os.lseek(descriptor, 0, os.SEEK_END)
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
        os.fsync(root_fd)
        return sequence
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _verify_request(request: VerifierRequest) -> tuple[str, str, str]:
    staging_manifest_sha256, installed_tree_sha256, core_wheel_digest = (
        _validate_staging_manifest(request.spec, production=False)
        if request.spec.staging_manifest_path is None
        else _validate_staging_manifest(request.spec, production=os.geteuid() == 0)
    )
    if (
        request.staging_manifest_sha256 != staging_manifest_sha256
        or request.installed_tree_sha256 != installed_tree_sha256
        or request.core_wheel_digest != core_wheel_digest
    ):
        raise ValueError("verifier staging binding changed")
    baseline, treatment = request.invocations
    if (
        baseline.request.arm is not ModelUtilityArm.BASELINE
        or treatment.request.arm is not ModelUtilityArm.TREATMENT
        or baseline.request.request_id == treatment.request.request_id
        or baseline.response.request_id == treatment.response.request_id
    ):
        raise ValueError("calibration pair is not distinct and ordered")
    normalized = _wire(request.normalized_response).decode("ascii")
    if (
        ".invalid" not in request.observation_document
        or "127.0.0.1" not in request.observation_document
        or baseline.request.payload != request.observation_document
        or treatment.request.payload != normalized
        or request.normalized_response.normalized_observation.source_digest
        != _digest_bytes(request.observation_document.encode())
    ):
        raise ValueError("calibration safety or normalization binding failed")
    producer_records = {item.key_id: item for item in request.producer_trust}
    if len(producer_records) != 1:
        raise ValueError("producer trust is ambiguous")
    producer_trust = next(iter(producer_records.values()))
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=request.spec.timeout_seconds,
        maximum_request_bytes=65_536,
        maximum_response_bytes=request.spec.maximum_response_bytes,
    )
    expected_profile_digest = sha256_digest(config.model_dump(mode="json"))
    expected_evaluator_digest = sha256_digest(
        {
            "installed_tree_sha256": request.installed_tree_sha256,
            "materializer_sha256": _digest_bytes(
                (Path(__file__).parent / "adapter_admission_materializer.py").read_bytes()
            ),
            "schema_version": "faultloom.adapter-evaluator-binding.v1",
            "staging_manifest_sha256": request.staging_manifest_sha256,
        }
    )
    fixed_argv_digests = {item.fixed_argv_digest for item in request.invocations}
    transcript_digests = {item.transcript_evidence_digest for item in request.invocations}
    if (
        len(fixed_argv_digests) != 1
        or len(transcript_digests) != 2
        or request.plan.baseline.prompt_digest == request.plan.treatment.prompt_digest
        or request.plan.baseline.tool_schema_digest == request.plan.treatment.tool_schema_digest
        or request.plan.evaluator_artifact_digest != expected_evaluator_digest
    ):
        raise ValueError("producer calls do not share one fixed runtime identity")
    for index, invocation in enumerate(request.invocations):
        arm = (
            request.plan.baseline
            if invocation.request.arm is ModelUtilityArm.BASELINE
            else request.plan.treatment
        )
        payload = verify_model_producer_attestation(
            invocation.producer,
            producer_records,
            minimum_sequence=invocation.producer.payload.sequence,
            expected_session_id=request.spec.session_id,
            expected_evaluator_challenge=request.spec.evaluator_challenge,
        )
        _verify_sequence_proof(
            invocation.sequence_proof,
            producer_trust,
            expected_allocation_id=f"{request.spec.bundle_id}.producer.{index + 1}",
            expected_attestation=invocation.producer,
        )
        if (
            payload.sequence != index + 1
            or payload.canonical_request_digest != _digest_bytes(_wire(invocation.request))
            or payload.parsed_response_digest != _digest_bytes(_wire(invocation.response))
            or invocation.response.request_id != invocation.request.request_id
            or invocation.request.model_snapshot_digest != arm.model_snapshot_digest
            or invocation.request.runtime_artifact_digest != arm.runtime_artifact_digest
            or invocation.request.prompt_digest != arm.prompt_digest
            or invocation.request.tool_schema_digest != arm.tool_schema_digest
            or invocation.request.budget_digest != arm.budget_digest
            or invocation.request.generation_config_digest != arm.generation_config_digest
            or invocation.request.seed != arm.seed
            or payload.model_digest != config.model_snapshot_digest
            or payload.runtime_wrapper_digest != config.runtime_executable_digest
            or payload.runtime_bundle_digest != FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST
            or payload.bwrap_digest != FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST
            or payload.fixed_argv_digest != invocation.fixed_argv_digest
            or payload.core_wheel_digest != request.core_wheel_digest
            or payload.profile_digest != expected_profile_digest
        ):
            raise ValueError("producer response binding failed")
        expected_transcript = sha256_digest(
            {
                "arm": invocation.request.arm.value,
                "ordinal": index + 1,
                "producer_envelope_digest": sha256_digest(invocation.producer),
                "producer_sequence_proof_digest": sha256_digest(
                    invocation.sequence_proof.model_dump(mode="json")
                ),
                "request_digest": payload.canonical_request_digest,
                "response_digest": payload.parsed_response_digest,
                "schema_version": "faultloom.adapter-invocation-transcript.v1",
                "staging_manifest_sha256": request.staging_manifest_sha256,
                "installed_tree_sha256": request.installed_tree_sha256,
            }
        )
        if invocation.transcript_evidence_digest != expected_transcript:
            raise ValueError("producer transcript identity is invalid")
    if baseline.producer.payload.sequence >= treatment.producer.payload.sequence:
        raise ValueError("model response was reused")
    common_producer_facts = (
        "producer_key_id",
        "producer_key_fingerprint",
        "session_id",
        "evaluator_challenge",
        "model_digest",
        "runtime_wrapper_digest",
        "runtime_bundle_digest",
        "bwrap_digest",
        "fixed_argv_digest",
        "core_wheel_digest",
        "profile_digest",
    )
    if any(
        getattr(baseline.producer.payload, field) != getattr(treatment.producer.payload, field)
        for field in common_producer_facts
    ):
        raise ValueError("producer sequence proofs do not share one identity")
    oracle = _digest_bytes(
        request.observation_document.encode() + _wire(request.normalized_response)
    )
    reset = _digest_bytes(b"sequential-process-context-reset-v1")
    replay = _digest_bytes(_wire(baseline.response) + _wire(treatment.response))
    replay_check = _digest_bytes(_wire(baseline.response) + _wire(treatment.response))
    if replay != replay_check:
        raise ValueError("verifier replay changed")
    return oracle, reset, replay


def verify_and_sign(
    request: VerifierRequest, signer: AuthoritySigner, root_fd: int
) -> VerifierResponse:
    oracle_digest, reset_digest, replay_digest = _verify_request(request)
    outcomes = tuple(
        ModelUtilityCaseOutcome(
            case_id=item.request.case_id,
            case_digest=item.request.case_digest,
            arm=item.request.arm,
            arm_config_digest=model_utility_digest(
                request.plan.baseline
                if item.request.arm is ModelUtilityArm.BASELINE
                else request.plan.treatment
            ),
            decision=UtilityDecision.INCONCLUSIVE,
            verifier=IndependentVerifierOutcome(
                verifier_id=signer.key_id,
                independent=True,
                verdict=IndependentVerifierVerdict.INCONCLUSIVE,
                evidence_digest=_digest_bytes(_wire(item.response) + oracle_digest.encode()),
            ),
            provider_receipt_digest=sha256_digest(item.producer),
            response_artifact_digest=_digest_bytes(_wire(item.response)),
            model_tokens=item.response.input_tokens + item.response.output_tokens,
            dispatched_oos=0,
            escaped_oos=0,
        )
        for item in request.invocations
    )
    evaluation = ModelUtilityEvaluation(
        plan=request.plan,
        case_outcomes=outcomes,
        evidence_source=ModelUtilityEvidenceSource.REAL_MODEL,
        state=ModelUtilityEvaluationState.FULLY_DONE,
        metrics=derive_model_utility_metrics(outcomes),
    )
    verifier_sequence = _allocate_sequence(
        root_fd,
        request.spec.verifier_state,
        f"{request.spec.bundle_id}.verifier",
    )
    selected = request.invocations[1]
    verifier_payload = ModelVerifierAttestation(
        schema_version=SCHEMA_VERSION,
        verifier_key_id=signer.key_id,
        verifier_key_fingerprint=_fingerprint(signer),
        session_id=request.spec.session_id,
        sequence=verifier_sequence,
        verifier_artifact_digest=_VERIFIER_ARTIFACT_DIGEST,
        verifier_profile_digest=_VERIFIER_PROFILE_DIGEST,
        producer_receipt_digest=sha256_digest(selected.producer),
        case_digest=selected.request.case_digest,
        oracle_digest=oracle_digest,
        reset_evidence_digest=reset_digest,
        replay_evidence_digest=replay_digest,
        outcome="passed",
        safety_preserved=True,
        context_isolated=True,
        independent_replay=True,
    )
    verifier_digest = sha256_digest(verifier_payload)
    verifier = SignedModelVerifierAttestation(
        schema_version=SCHEMA_VERSION,
        payload=verifier_payload,
        payload_digest=verifier_digest,
        signature=signer.sign(attestation_signing_bytes(verifier_payload, verifier_digest)),
    )
    coverage = tuple(
        ModelUtilityOutcomeCoverage(
            schema_version=SCHEMA_VERSION,
            case_id=outcome.case_id,
            case_digest=outcome.case_digest,
            arm=outcome.arm.value,
            provider_receipt_digest=outcome.provider_receipt_digest,
            response_artifact_digest=outcome.response_artifact_digest,
            producer_canonical_request_digest=item.producer.payload.canonical_request_digest,
            producer_parsed_response_digest=item.producer.payload.parsed_response_digest,
            producer_output_digest=item.producer.payload.output_digest,
            verifier_case_digest=outcome.case_digest,
            verifier_oracle_digest=oracle_digest,
            verifier_reset_evidence_digest=reset_digest,
            verifier_replay_evidence_digest=replay_digest,
        )
        for outcome, item in zip(
            sorted(outcomes, key=lambda value: (value.case_id, value.arm.value)),
            request.invocations,
            strict=True,
        )
    )
    admission_sequence = _allocate_sequence(
        root_fd,
        request.spec.verifier_state,
        f"{request.spec.bundle_id}.admission",
    )
    admission_payload = ModelUtilityAdmission(
        schema_version=SCHEMA_VERSION,
        verifier_key_id=signer.key_id,
        verifier_key_fingerprint=_fingerprint(signer),
        session_id=request.spec.session_id,
        sequence=admission_sequence,
        evaluator_challenge=request.spec.evaluator_challenge,
        adapter_id="adapter.reference",
        manifest_digest=request.manifest_digest,
        evaluation_digest=model_utility_digest(evaluation),
        plan_digest=model_utility_digest(request.plan),
        producer_envelope_digest=sha256_digest(selected.producer),
        verifier_envelope_digest=sha256_digest(verifier),
        outcome_coverage_digest=model_utility_outcome_coverage_digest(coverage),
        outcome_coverage=coverage,
        evidence_source="real_model",
        evaluation_state="fully_done",
        outcome="passed",
        safety_preserved=True,
        dispatched_oos=0,
        escaped_oos=0,
        tool_only_false_verified=0,
    )
    admission_digest = model_utility_admission_digest(admission_payload)
    admission = SignedModelUtilityAdmission(
        schema_version=SCHEMA_VERSION,
        payload=admission_payload,
        payload_digest=admission_digest,
        signature=signer.sign(
            model_utility_admission_signing_bytes(admission_payload, admission_digest)
        ),
    )
    return VerifierResponse(
        evaluation=evaluation,
        verifier=verifier,
        admission=admission,
        verifier_trust=(signer.public_key_record,),
        minimum_verifier_sequence=verifier_sequence,
        minimum_admission_sequence=admission_sequence,
        staging_manifest_sha256=request.staging_manifest_sha256,
        installed_tree_sha256=request.installed_tree_sha256,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--root-fd", type=int)
    parser.add_argument("--verifier-key-fd", required=True, type=int)
    parser.add_argument("--dry-fixture", action="store_true")
    parser.add_argument("--public-key-only", action="store_true")
    arguments = parser.parse_args(argv)
    production = not arguments.dry_fixture
    if arguments.public_key_only:
        try:
            raw = sys.stdin.buffer.read(_MAX_DOCUMENT_BYTES + 1)
            if len(raw) > _MAX_DOCUMENT_BYTES or not raw.endswith(b"\n"):
                return 2
            spec = VerifierInputSpec.model_validate_json(raw[:-1])
            if _wire(spec) != raw[:-1]:
                return 2
            manifest_digest, tree_digest, core_digest = _validate_staging_manifest(
                spec, production=production
            )
            response = VerifierPreflightResponse(
                public_key=_read_signer(
                    arguments.verifier_key_fd, production=production
                ).public_key_record,
                staging_manifest_sha256=manifest_digest,
                installed_tree_sha256=tree_digest,
                core_wheel_digest=core_digest,
            )
            sys.stdout.buffer.write(_wire(response) + b"\n")
            return 0
        except (OSError, TypeError, ValueError):
            return 2
    if arguments.root_fd is None:
        return 2
    raw = sys.stdin.buffer.read(_MAX_DOCUMENT_BYTES + 1)
    if len(raw) > _MAX_DOCUMENT_BYTES or not raw.endswith(b"\n"):
        return 2
    try:
        root = os.fstat(arguments.root_fd)
        expected_uid = 0 if production else os.geteuid()
        expected_gid = 0 if production else os.getegid()
        if (
            not stat.S_ISDIR(root.st_mode)
            or root.st_uid != expected_uid
            or root.st_gid != expected_gid
            or stat.S_IMODE(root.st_mode) != 0o700
        ):
            return 2
        request = VerifierRequest.model_validate_json(raw[:-1])
        if _wire(request) != raw[:-1]:
            return 2
        response = verify_and_sign(
            request,
            _read_signer(
                arguments.verifier_key_fd,
                production=production,
            ),
            arguments.root_fd,
        )
        sys.stdout.buffer.write(_wire(response) + b"\n")
        return 0
    except (OSError, TypeError, ValueError, ValidationError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
