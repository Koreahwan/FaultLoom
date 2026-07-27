"""Root-only, create-once materializer for the formal T40 adapter admission bundle."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import sysconfig
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, ClassVar, Literal

import faultloom_protocol as protocol_module
import faultloom_sdk as sdk_module
import pydantic as pydantic_module
from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    ModelProducerAttestation,
    ObservationRef,
    SignedModelProducerAttestation,
    attestation_signing_bytes,
    canonical_json_bytes,
    sha256_digest,
)
from faultloom_sdk import (
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdmissionGate,
    AdmissionOutcome,
    ModelUtilityArm,
    ModelUtilityArmConfig,
    ModelUtilityCase,
    ModelUtilityEvaluationPlan,
    ModelUtilitySuite,
    NormalizeObservationRequest,
    ReferenceProcessClient,
    RpcMethod,
    UtilityDecision,
    reference_adapter_manifest,
    reference_registry,
    verify_model_utility_admission,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from . import adapter_admission_verifier as verifier_module
from . import model_utility_proxy_models as proxy_models_module
from .adapter_admission_verifier import (
    VerifierInputSpec,
    VerifierInvocation,
    VerifierPreflightResponse,
    VerifierRequest,
    VerifierResponse,
)
from .model_utility_attestor import exchange_with_transcript
from .model_utility_proxy import DigestPinnedLocalProcessProxy
from .model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST,
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessRequest,
    LocalModelProcessResponse,
    LocalModelRuntimeProfile,
)

_SPEC_NAME = "adapter-admission-input.json"
_OUTPUT_NAME = "adapter-admission-bundle.json"
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


class AdapterAdmissionMaterializerError(RuntimeError):
    """The formal bundle could not be created without weakening an invariant."""


class _StrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )


class AdapterAdmissionInput(_StrictModel):
    schema_version: Literal["faultloom.adapter-admission-input.v1"]
    bundle_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")]
    session_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")]
    evaluator_challenge: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    staging_manifest_path: str | None
    staging_manifest_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None
    producer_state: Literal["adapter-admission-producer.sequence"]
    verifier_state: Literal["adapter-admission-verifier.sequence"]
    output: Literal["adapter-admission-bundle.json"]
    timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=300)]
    maximum_response_bytes: Annotated[int, Field(strict=True, ge=1, le=16_777_216)]

    @model_validator(mode="after")
    def _challenge_has_entropy(self) -> AdapterAdmissionInput:
        if len(set(bytes.fromhex(self.evaluator_challenge))) < 8:
            raise ValueError("evaluator challenge lacks diversity")
        return self


class _ProducerSequenceProofPayload(_StrictModel):
    schema_version: Literal["faultloom.adapter-producer-sequence-proof.v1"]
    allocation_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")]
    attestation: SignedModelProducerAttestation


class _SignedProducerSequenceProof(_StrictModel):
    schema_version: Literal["faultloom.adapter-producer-sequence-proof-envelope.v1"]
    payload: _ProducerSequenceProofPayload
    payload_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    signature: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{86}$")]


class _Invocation(_StrictModel):
    request: LocalModelProcessRequest
    response: LocalModelProcessResponse
    producer: SignedModelProducerAttestation
    fixed_argv_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    transcript_evidence_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    sequence_proof: _SignedProducerSequenceProof


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


class _StagingBinding(_StrictModel):
    manifest_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    installed_tree_sha256: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    core_wheel_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    generation_root: Path
    site_root: Path
    launcher_path: Path
    launcher_argv_prefix: tuple[str, ...]


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _wire(value: BaseModel) -> bytes:
    return canonical_json_bytes(value.model_dump(mode="json"))


def _child_environment(*, fixture: bool) -> dict[str, str]:
    """Expose only interpreter discovery state, never caller secrets."""

    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    if fixture:
        environment["PYTHONPATH"] = os.pathsep.join(item for item in sys.path if item)
    return environment


def _fingerprint(signer: AuthoritySigner) -> str:
    raw = base64.urlsafe_b64decode(signer.public_key_record.public_key + "==")
    return _digest_bytes(raw)


def _sequence_proof_signing_bytes(
    payload: _ProducerSequenceProofPayload, payload_digest: str
) -> bytes:
    payload_wire = payload.model_dump(mode="json")
    if payload_digest != sha256_digest(payload_wire):
        raise AdapterAdmissionMaterializerError("producer sequence proof digest is invalid")
    return canonical_json_bytes({"payload": payload_wire, "payload_digest": payload_digest})


def _sign_sequence_proof(
    signer: AuthoritySigner,
    allocation_id: str,
    attestation: SignedModelProducerAttestation,
) -> _SignedProducerSequenceProof:
    payload = _ProducerSequenceProofPayload(
        schema_version="faultloom.adapter-producer-sequence-proof.v1",
        allocation_id=allocation_id,
        attestation=attestation,
    )
    digest = sha256_digest(payload.model_dump(mode="json"))
    return _SignedProducerSequenceProof(
        schema_version="faultloom.adapter-producer-sequence-proof-envelope.v1",
        payload=payload,
        payload_digest=digest,
        signature=signer.sign(_sequence_proof_signing_bytes(payload, digest)),
    )


def _validate_key_descriptor(
    descriptor: int, label: str, *, production: bool
) -> tuple[int, int, int, int, int]:
    if type(descriptor) is not int or descriptor < 3:
        raise AdapterAdmissionMaterializerError(f"{label} key descriptor is invalid")
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        raise AdapterAdmissionMaterializerError(f"{label} key descriptor is unavailable") from None
    expected_uid = 0 if production else os.geteuid()
    expected_gid = 0 if production else os.getegid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != 32
    ):
        raise AdapterAdmissionMaterializerError(f"{label} key descriptor metadata is unsafe")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_exact_key(descriptor: int, label: str, *, production: bool) -> AuthoritySigner:
    before = _validate_key_descriptor(descriptor, label, production=production)
    try:
        material = os.pread(descriptor, 33, 0)
        after = _validate_key_descriptor(descriptor, label, production=production)
    except OSError:
        raise AdapterAdmissionMaterializerError(f"{label} key descriptor is unavailable") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    if len(material) != 32 or before != after:
        raise AdapterAdmissionMaterializerError(f"{label} key must be raw32")
    try:
        return AuthoritySigner.from_private_bytes(material)
    finally:
        del material


def _open_root(path: Path, *, production: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise AdapterAdmissionMaterializerError(
            "admission configuration root is unavailable"
        ) from None
    metadata = os.fstat(descriptor)
    expected_uid = 0 if production else os.geteuid()
    expected_gid = 0 if production else os.getegid()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise AdapterAdmissionMaterializerError("admission configuration root ownership is unsafe")
    return descriptor


def _require_output_absent(root_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise AdapterAdmissionMaterializerError(
            "admission output preflight is unavailable"
        ) from None
    raise AdapterAdmissionMaterializerError("admission bundle already exists")


def _require_sequence_state_absent(root_fd: int, names: tuple[str, str]) -> None:
    for name in names:
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            raise AdapterAdmissionMaterializerError(
                "admission sequence preflight is unavailable"
            ) from None
        raise AdapterAdmissionMaterializerError("admission sequence state already exists")


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
    try:
        metadata = os.lstat(path)
    except OSError:
        raise AdapterAdmissionMaterializerError("formal staging directory is unavailable") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise AdapterAdmissionMaterializerError("formal staging directory is unsafe")


def _read_staging_file(
    path: Path,
    label: str,
    *,
    production: bool,
    mode: int,
    maximum_bytes: int,
) -> bytes:
    uid, gid = _staging_owner(production=production)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_named = os.lstat(path)
        descriptor = os.open(path, flags)
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
    except OSError:
        raise AdapterAdmissionMaterializerError(f"{label} is unavailable") from None
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
        raise AdapterAdmissionMaterializerError(f"{label} metadata is unsafe")
    return raw


def _validate_staging_manifest(
    spec: AdapterAdmissionInput,
    *,
    production: bool,
    verify_import_origins: bool = True,
) -> _StagingBinding:
    if spec.staging_manifest_path is None or spec.staging_manifest_sha256 is None:
        if production:
            raise AdapterAdmissionMaterializerError("production staging manifest is required")
        source = _digest_bytes(b"dry-fixture-staging-binding-v1")
        return _StagingBinding(
            manifest_sha256=source,
            installed_tree_sha256=source,
            core_wheel_digest=source,
            generation_root=Path("/dry-fixture"),
            site_root=Path("/dry-fixture/site-packages"),
            launcher_path=Path("/dry-fixture/isolated-launcher"),
            launcher_argv_prefix=(),
        )
    manifest_path = Path(spec.staging_manifest_path)
    if (
        not manifest_path.is_absolute()
        or manifest_path != Path(os.path.abspath(manifest_path))
        or manifest_path.name != "staging-manifest.json"
    ):
        raise AdapterAdmissionMaterializerError("formal staging manifest path is unsafe")
    generation_root = manifest_path.parent
    if production and generation_root.parent != _STAGING_BASE:
        raise AdapterAdmissionMaterializerError("formal staging generation root is invalid")
    _verify_staging_directory(generation_root, production=production, mode=0o700)
    raw = _read_staging_file(
        manifest_path,
        "formal staging manifest",
        production=production,
        mode=0o400,
        maximum_bytes=_MAX_DOCUMENT_BYTES,
    )
    if _digest_bytes(raw) != spec.staging_manifest_sha256:
        raise AdapterAdmissionMaterializerError("formal staging manifest A-vs-B mismatch")
    try:
        manifest = _StagingManifest.model_validate_json(raw)
    except ValidationError:
        raise AdapterAdmissionMaterializerError("formal staging manifest is malformed") from None
    if raw != canonical_json_bytes(manifest.model_dump(mode="json", by_alias=True)):
        raise AdapterAdmissionMaterializerError("formal staging manifest is not canonical")
    site_root = generation_root / "site-packages"
    launcher_path = generation_root / "isolated-launcher"
    expected_prefix = (
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
    if (
        manifest.generation_id != generation_root.name
        or manifest.generation_root != str(generation_root)
        or tuple(item.role for item in manifest.sources) != _STAGING_SOURCE_ROLES
        or manifest.launcher.argv_prefix != expected_prefix
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
        raise AdapterAdmissionMaterializerError("formal staging manifest contract is invalid")
    launcher = _read_staging_file(
        launcher_path,
        "formal staging launcher",
        production=production,
        mode=0o400,
        maximum_bytes=1024 * 1024,
    )
    if _digest_bytes(launcher) != manifest.launcher.sha256:
        raise AdapterAdmissionMaterializerError("formal staging launcher binding is invalid")
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
        raise AdapterAdmissionMaterializerError("formal staging tree contract is invalid")
    tree_payload = {
        "directories": [
            item.model_dump(mode="json") for item in manifest.installed_tree.directories
        ],
        "files": [item.model_dump(mode="json") for item in manifest.installed_tree.files],
    }
    if sha256_digest(tree_payload) != manifest.installed_tree.sha256:
        raise AdapterAdmissionMaterializerError("formal staging tree digest is invalid")
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
        raise AdapterAdmissionMaterializerError("formal staging tree inventory is invalid")
    for item in manifest.installed_tree.directories:
        path = site_root if item.path == "." else site_root / item.path
        _verify_staging_directory(path, production=production, mode=item.mode)
    file_digests: dict[str, str] = {}
    for item in manifest.installed_tree.files:
        body = _read_staging_file(
            site_root / item.path,
            f"formal staging file {item.path}",
            production=production,
            mode=item.mode,
            maximum_bytes=128 * 1024 * 1024,
        )
        file_digests[item.path] = _digest_bytes(body)
        if file_digests[item.path] != item.sha256:
            raise AdapterAdmissionMaterializerError("formal staging file digest is invalid")
    if verify_import_origins:
        pydantic_path = pydantic_module.__file__
        if pydantic_path is None:
            raise AdapterAdmissionMaterializerError("ambient import origin is unavailable")
        module_bindings = {
            "faultloom/adapter_admission_materializer.py": Path(__file__),
            "faultloom/adapter_admission_verifier.py": Path(verifier_module.__file__),
            "faultloom/model_utility_proxy_models.py": Path(proxy_models_module.__file__),
            "faultloom_protocol/__init__.py": Path(protocol_module.__file__),
            "faultloom_sdk/__init__.py": Path(sdk_module.__file__),
            "pydantic/__init__.py": Path(pydantic_path),
        }
        for relative, loaded in module_bindings.items():
            expected = site_root / relative
            if loaded.resolve(strict=True) != expected or file_digests.get(relative) is None:
                raise AdapterAdmissionMaterializerError("ambient import origin is not staged")
    if production and verify_import_origins:
        resolved_paths = tuple(Path(item).resolve(strict=False) for item in sys.path if item)
        if not resolved_paths or resolved_paths[0] != site_root:
            raise AdapterAdmissionMaterializerError("formal staging import path is not isolated")
        if any(
            "site-packages" in item.parts or "dist-packages" in item.parts
            for item in resolved_paths[1:]
        ):
            raise AdapterAdmissionMaterializerError("ambient package path is present")
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
                raise AdapterAdmissionMaterializerError(
                    "ambient imported dependency is not staged"
                ) from None
            if "site-packages" in loaded.parts or "dist-packages" in loaded.parts:
                raise AdapterAdmissionMaterializerError("ambient imported dependency is not staged")
    core_source = manifest.sources[0]
    return _StagingBinding(
        manifest_sha256=spec.staging_manifest_sha256,
        installed_tree_sha256=manifest.installed_tree.sha256,
        core_wheel_digest=core_source.sha256,
        generation_root=generation_root,
        site_root=site_root,
        launcher_path=launcher_path,
        launcher_argv_prefix=manifest.launcher.argv_prefix,
    )


def _read_private_file(root_fd: int, name: str, *, production: bool) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=root_fd)
    except OSError:
        raise AdapterAdmissionMaterializerError("admission input is unavailable") from None
    try:
        before = os.fstat(descriptor)
        raw = os.read(descriptor, _MAX_DOCUMENT_BYTES + 1)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except OSError:
        raise AdapterAdmissionMaterializerError("admission input is unavailable") from None
    finally:
        os.close(descriptor)
    expected_uid = 0 if production else os.geteuid()
    expected_gid = 0 if production else os.getegid()
    values = (before, after, named)
    identities = {(item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns) for item in values}
    if (
        any(
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != expected_uid
            or item.st_gid != expected_gid
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
            for item in values
        )
        or len(identities) != 1
        or len(raw) != before.st_size
        or len(raw) > _MAX_DOCUMENT_BYTES
    ):
        raise AdapterAdmissionMaterializerError("admission input metadata is unsafe")
    return raw


def _allocate_sequence(root_fd: int, name: str, allocation_id: str) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags | os.O_CREAT, 0o600, dir_fd=root_fd)
    except OSError:
        raise AdapterAdmissionMaterializerError("admission sequence state is unavailable") from None
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
            raise AdapterAdmissionMaterializerError("admission sequence state metadata is unsafe")
        raw = os.pread(descriptor, 1_048_577, 0)
        records = () if not raw else tuple(raw.splitlines())
        sequence = 0
        seen: set[str] = set()
        for encoded in records:
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
                raise AdapterAdmissionMaterializerError("admission sequence state is corrupt")
            sequence = record["sequence"]
            seen.add(record["allocation_id"])
        if allocation_id in seen or sequence >= 2**63 - 1:
            raise AdapterAdmissionMaterializerError("admission sequence allocation was reused")
        sequence += 1
        encoded = (
            canonical_json_bytes({"allocation_id": allocation_id, "sequence": sequence}) + b"\n"
        )
        if len(raw) + len(encoded) > 1_048_576:
            raise AdapterAdmissionMaterializerError("admission sequence state is full")
        os.lseek(descriptor, 0, os.SEEK_END)
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
        os.fsync(root_fd)
        return sequence
    except (json.JSONDecodeError, OSError):
        raise AdapterAdmissionMaterializerError("admission sequence state is corrupt") from None
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _parse_spec(raw: bytes) -> AdapterAdmissionInput:
    try:
        spec = AdapterAdmissionInput.model_validate_json(raw)
    except ValidationError:
        raise AdapterAdmissionMaterializerError("admission input is malformed") from None
    if raw != _wire(spec):
        raise AdapterAdmissionMaterializerError("admission input is not canonical JSON")
    return spec


def _observation(spec: AdapterAdmissionInput) -> tuple[str, ObservationRef]:
    document = canonical_json_bytes(
        {
            "endpoint": "https://adapter-calibration.invalid/status",
            "loopback": "127.0.0.1",
            "mode": "owned-safe-observation",
        }
    ).decode("ascii")
    return document, ObservationRef(
        schema_version=SCHEMA_VERSION,
        observation_id="adapter-admission.case-1.observation",
        run_id=spec.session_id,
        cas_digest=_digest_bytes(document.encode()),
        media_type="application/json",
        byte_length=len(document.encode()),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _plan(
    spec: AdapterAdmissionInput,
    manifest_digest: str,
    baseline_payload: str,
    treatment_payload: str,
    staging_binding: _StagingBinding,
) -> ModelUtilityEvaluationPlan:
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=spec.timeout_seconds,
        maximum_request_bytes=65_536,
        maximum_response_bytes=spec.maximum_response_bytes,
    )
    case = ModelUtilityCase(
        case_id="adapter-admission.case-1",
        case_digest=_digest_bytes(b"adapter-admission.case-1.v1"),
    )
    common = {
        "model_snapshot": "faultloom-model-utility-v1",
        "model_snapshot_digest": config.model_snapshot_digest,
        "runtime_version": "llama.cpp-b10107",
        "runtime_artifact_digest": config.runtime_executable_digest,
        "budget_digest": _digest_bytes(b"adapter-admission-budget-v1"),
        "generation_config_digest": _digest_bytes(b"adapter-admission-generation-v1-seed-42"),
        "seed": 42,
    }
    return ModelUtilityEvaluationPlan(
        adapter_id="adapter.reference",
        manifest_digest=manifest_digest,
        suite=ModelUtilitySuite(
            suite_id="adapter-admission.suite-v1",
            suite_digest=_digest_bytes(b"adapter-admission.suite-v1"),
            cases=(case,),
        ),
        baseline=ModelUtilityArmConfig(
            arm=ModelUtilityArm.BASELINE,
            prompt_digest=_digest_bytes(baseline_payload.encode()),
            tool_schema_digest=_digest_bytes(b"adapter-admission-baseline-no-normalizer"),
            **common,
        ),
        treatment=ModelUtilityArmConfig(
            arm=ModelUtilityArm.TREATMENT,
            prompt_digest=_digest_bytes(treatment_payload.encode()),
            tool_schema_digest=_digest_bytes(b"adapter-admission-treatment-reference-normalizer"),
            **common,
        ),
        evaluator_artifact_digest=sha256_digest(
            {
                "installed_tree_sha256": staging_binding.installed_tree_sha256,
                "materializer_sha256": _digest_bytes(Path(__file__).read_bytes()),
                "schema_version": "faultloom.adapter-evaluator-binding.v1",
                "staging_manifest_sha256": staging_binding.manifest_sha256,
            }
        ),
    )


def _model_request(
    spec: AdapterAdmissionInput,
    case: ModelUtilityCase,
    arm: ModelUtilityArmConfig,
    payload: str,
) -> LocalModelProcessRequest:
    return LocalModelProcessRequest(
        request_id=f"{spec.session_id}.{arm.arm.value}",
        case_id=case.case_id,
        case_digest=case.case_digest,
        arm=arm.arm,
        model_snapshot_digest=arm.model_snapshot_digest,
        runtime_artifact_digest=arm.runtime_artifact_digest,
        prompt_digest=arm.prompt_digest,
        tool_schema_digest=arm.tool_schema_digest,
        budget_digest=arm.budget_digest,
        generation_config_digest=arm.generation_config_digest,
        seed=42,
        payload=payload,
    )


def _fixture_exchange(
    request: LocalModelProcessRequest, timeout: int
) -> tuple[LocalModelProcessResponse, str]:
    completed = subprocess.run(
        (sys.executable, "-m", "faultloom.adapter_admission_materializer", "--fixture-model-child"),
        input=canonical_json_bytes(request.model_dump(mode="json")) + b"\n",
        capture_output=True,
        env=_child_environment(fixture=True),
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr or not completed.stdout.endswith(b"\n"):
        raise AdapterAdmissionMaterializerError("dry fixture model child failed")
    try:
        response = LocalModelProcessResponse.model_validate_json(completed.stdout[:-1])
    except ValidationError:
        raise AdapterAdmissionMaterializerError("dry fixture model response is malformed") from None
    return response, _digest_bytes(b"dry-fixture-model-child-v1")


def _sign_invocation(
    *,
    signer: AuthoritySigner,
    sequence: int,
    spec: AdapterAdmissionInput,
    request: LocalModelProcessRequest,
    response: LocalModelProcessResponse,
    fixed_argv_digest: str,
    config: LocalModelProcessConfig,
    staging_binding: _StagingBinding,
) -> SignedModelProducerAttestation:
    request_bytes = canonical_json_bytes(request.model_dump(mode="json"))
    response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
    payload = ModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        producer_key_id=signer.key_id,
        producer_key_fingerprint=_fingerprint(signer),
        session_id=spec.session_id,
        sequence=sequence,
        evaluator_challenge=spec.evaluator_challenge,
        canonical_request_digest=_digest_bytes(request_bytes),
        parsed_response_digest=_digest_bytes(response_bytes),
        raw_llama_stdout_digest=response.raw_llama_stdout_digest,
        output_digest=response.output_digest,
        model_digest=config.model_snapshot_digest,
        runtime_wrapper_digest=config.runtime_executable_digest,
        runtime_bundle_digest=FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST,
        bwrap_digest=FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
        fixed_argv_digest=fixed_argv_digest,
        core_wheel_digest=staging_binding.core_wheel_digest,
        profile_digest=sha256_digest(config.model_dump(mode="json")),
        status="accepted",
        prompt_tokens=response.input_tokens,
        completion_tokens=response.output_tokens,
        total_tokens=response.input_tokens + response.output_tokens,
    )
    digest = sha256_digest(payload)
    return SignedModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=digest,
        signature=signer.sign(attestation_signing_bytes(payload, digest)),
    )


def _invoke_pair(
    root_fd: int,
    spec: AdapterAdmissionInput,
    signer: AuthoritySigner,
    plan: ModelUtilityEvaluationPlan,
    payloads: tuple[str, str],
    staging_binding: _StagingBinding,
    *,
    fixture: bool,
) -> tuple[_Invocation, _Invocation]:
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=spec.timeout_seconds,
        maximum_request_bytes=65_536,
        maximum_response_bytes=spec.maximum_response_bytes,
    )
    results: list[_Invocation] = []
    for index, (arm, payload) in enumerate(
        zip((plan.baseline, plan.treatment), payloads, strict=True)
    ):
        request = _model_request(spec, plan.suite.cases[0], arm, payload)
        if fixture:
            response, argv_digest = _fixture_exchange(request, spec.timeout_seconds)
        else:
            transcript = exchange_with_transcript(DigestPinnedLocalProcessProxy(config), request)
            response, argv_digest = transcript.response, transcript.fixed_argv_digest
        allocation_id = f"{spec.bundle_id}.producer.{index + 1}"
        sequence = _allocate_sequence(root_fd, spec.producer_state, allocation_id)
        producer = _sign_invocation(
            signer=signer,
            sequence=sequence,
            spec=spec,
            request=request,
            response=response,
            fixed_argv_digest=argv_digest,
            config=config,
            staging_binding=staging_binding,
        )
        sequence_proof = _sign_sequence_proof(signer, allocation_id, producer)
        transcript_evidence_digest = sha256_digest(
            {
                "arm": arm.arm.value,
                "ordinal": index + 1,
                "producer_envelope_digest": sha256_digest(producer),
                "producer_sequence_proof_digest": sha256_digest(
                    sequence_proof.model_dump(mode="json")
                ),
                "request_digest": producer.payload.canonical_request_digest,
                "response_digest": producer.payload.parsed_response_digest,
                "schema_version": "faultloom.adapter-invocation-transcript.v1",
                "staging_manifest_sha256": staging_binding.manifest_sha256,
                "installed_tree_sha256": staging_binding.installed_tree_sha256,
            }
        )
        results.append(
            _Invocation(
                request=request,
                response=response,
                producer=producer,
                fixed_argv_digest=argv_digest,
                transcript_evidence_digest=transcript_evidence_digest,
                sequence_proof=sequence_proof,
            )
        )
    if len(results) != 2 or results[0].request.request_id == results[1].request.request_id:
        raise AdapterAdmissionMaterializerError("model pair was not invoked distinctly")
    return results[0], results[1]


def _verifier_command(
    arguments: list[str], *, fixture: bool, staging_binding: _StagingBinding
) -> list[str]:
    if fixture:
        return [
            sys.executable,
            "-m",
            "faultloom.adapter_admission_verifier",
            *arguments,
            "--dry-fixture",
        ]
    return [
        *staging_binding.launcher_argv_prefix,
        "--module",
        "faultloom.adapter_admission_verifier",
        "--callable",
        "main",
        "--",
        *arguments,
    ]


def _preflight_verifier_public_key(
    verifier_key_fd: int,
    *,
    spec: AdapterAdmissionInput,
    fixture: bool,
    staging_binding: _StagingBinding,
    timeout: int,
) -> VerifierPreflightResponse:
    command = _verifier_command(
        ["--verifier-key-fd", str(verifier_key_fd), "--public-key-only"],
        fixture=fixture,
        staging_binding=staging_binding,
    )
    completed = subprocess.run(
        command,
        input=_wire(VerifierInputSpec.model_validate(spec.model_dump(mode="python"))) + b"\n",
        capture_output=True,
        env=_child_environment(fixture=fixture),
        pass_fds=(verifier_key_fd,),
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr or not completed.stdout.endswith(b"\n"):
        raise AdapterAdmissionMaterializerError("verifier key preflight failed")
    try:
        return VerifierPreflightResponse.model_validate_json(completed.stdout[:-1])
    except ValidationError:
        raise AdapterAdmissionMaterializerError(
            "verifier key preflight response is malformed"
        ) from None


def _run_verifier_child(
    root_fd: int,
    verifier_key_fd: int,
    request: VerifierRequest,
    timeout: int,
    *,
    fixture: bool,
    staging_binding: _StagingBinding,
) -> VerifierResponse:
    command = _verifier_command(
        [
            "--root-fd",
            str(root_fd),
            "--verifier-key-fd",
            str(verifier_key_fd),
        ],
        fixture=fixture,
        staging_binding=staging_binding,
    )
    completed = subprocess.run(
        command,
        input=_wire(request) + b"\n",
        capture_output=True,
        env=_child_environment(fixture=fixture),
        pass_fds=(root_fd, verifier_key_fd),
        timeout=timeout,
        check=False,
    )
    try:
        os.close(verifier_key_fd)
    except OSError:
        pass
    if completed.returncode != 0 or completed.stderr or not completed.stdout.endswith(b"\n"):
        raise AdapterAdmissionMaterializerError("independent verifier failed")
    try:
        return VerifierResponse.model_validate_json(completed.stdout[:-1])
    except ValidationError:
        raise AdapterAdmissionMaterializerError(
            "independent verifier response is malformed"
        ) from None


def _receipt(
    adapter_id: str,
    manifest_digest: str,
    gate: AdmissionGate,
    artifact: BaseModel,
) -> AdapterAdmissionReceipt:
    return AdapterAdmissionReceipt(
        adapter_id=adapter_id,
        manifest_digest=manifest_digest,
        gate=gate,
        outcome=AdmissionOutcome.PASSED,
        artifact_digest=sha256_digest(artifact.model_dump(mode="json")),
    )


def _write_create_once(root_fd: int, name: str, raw: bytes) -> None:
    temporary = f".{name}.{os.getpid()}.partial"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=root_fd,
        )
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=root_fd)
        os.fsync(root_fd)
    except FileExistsError:
        raise AdapterAdmissionMaterializerError("admission bundle already exists") from None
    except OSError:
        raise AdapterAdmissionMaterializerError("admission bundle could not be created") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass


def _materialize(root: Path, producer_key_fd: int, verifier_key_fd: int, *, fixture: bool) -> str:
    production = not fixture
    if production and os.geteuid() != 0:
        raise AdapterAdmissionMaterializerError("production materialization requires root")
    root_fd = _open_root(root, production=production)
    try:
        spec = _parse_spec(_read_private_file(root_fd, _SPEC_NAME, production=production))
        if spec.output != _OUTPUT_NAME:
            raise AdapterAdmissionMaterializerError("admission output name is not canonical")
        _require_output_absent(root_fd, spec.output)
        _require_sequence_state_absent(root_fd, (spec.producer_state, spec.verifier_state))
        _ = _validate_key_descriptor(verifier_key_fd, "verifier", production=production)
        producer_signer = _read_exact_key(producer_key_fd, "producer", production=production)
        producer_record = producer_signer.public_key_record
        staging_binding = _validate_staging_manifest(spec, production=production)
        verifier_preflight = _preflight_verifier_public_key(
            verifier_key_fd,
            spec=spec,
            fixture=fixture,
            staging_binding=staging_binding,
            timeout=spec.timeout_seconds,
        )
        verifier_record = verifier_preflight.public_key
        if (
            verifier_preflight.staging_manifest_sha256 != staging_binding.manifest_sha256
            or verifier_preflight.installed_tree_sha256 != staging_binding.installed_tree_sha256
            or verifier_preflight.core_wheel_digest != staging_binding.core_wheel_digest
        ):
            raise AdapterAdmissionMaterializerError("verifier staging preflight changed")
        if producer_record.key_id == verifier_record.key_id:
            raise AdapterAdmissionMaterializerError("producer and verifier keys must be distinct")
        manifest = reference_adapter_manifest()
        manifest_digest = sha256_digest(manifest)
        client = ReferenceProcessClient(
            expected_adapter_manifest=manifest,
            timeout_seconds=min(30, spec.timeout_seconds),
        )
        described = client.describe(request_id=f"{spec.session_id}.describe")
        observation_document, observation = _observation(spec)
        normalize_request = NormalizeObservationRequest(
            schema_version=SCHEMA_VERSION,
            rpc_version="0.1.0",
            request_id=f"{spec.session_id}.normalize",
            method=RpcMethod.NORMALIZE_OBSERVATION,
            authority_grant_digest=_digest_bytes(b"owned-safe-adapter-admission-grant"),
            adapter_id=manifest.adapter_id,
            capability="reference.digest_normalizer",
            observation=observation,
        )
        normalized = client.normalize(normalize_request)
        if normalized.normalized_observation.source_digest != observation.cas_digest:
            raise AdapterAdmissionMaterializerError("reference normalization lost source binding")
        treatment_payload = canonical_json_bytes(normalized.model_dump(mode="json")).decode("ascii")
        plan = _plan(
            spec,
            manifest_digest,
            observation_document,
            treatment_payload,
            staging_binding,
        )
        invocations = _invoke_pair(
            root_fd,
            spec,
            producer_signer,
            plan,
            (observation_document, treatment_payload),
            staging_binding,
            fixture=fixture,
        )
        verifier_request = VerifierRequest(
            spec=VerifierInputSpec.model_validate(spec.model_dump(mode="python")),
            core_wheel_digest=staging_binding.core_wheel_digest,
            staging_manifest_sha256=staging_binding.manifest_sha256,
            installed_tree_sha256=staging_binding.installed_tree_sha256,
            manifest_digest=manifest_digest,
            plan=plan,
            invocations=(
                VerifierInvocation.model_validate(invocations[0].model_dump(mode="python")),
                VerifierInvocation.model_validate(invocations[1].model_dump(mode="python")),
            ),
            observation_document=observation_document,
            normalized_response=normalized,
            producer_trust=(producer_record,),
        )
        verified = _run_verifier_child(
            root_fd,
            verifier_key_fd,
            verifier_request,
            spec.timeout_seconds,
            fixture=fixture,
            staging_binding=staging_binding,
        )
        if verified.verifier_trust != (verifier_record,):
            raise AdapterAdmissionMaterializerError("verifier identity changed after preflight")
        if (
            verified.staging_manifest_sha256 != staging_binding.manifest_sha256
            or verified.installed_tree_sha256 != staging_binding.installed_tree_sha256
        ):
            raise AdapterAdmissionMaterializerError("verifier staging identity changed")
        producer = invocations[1].producer
        proof = verify_model_utility_admission(
            verified.admission,
            evaluation=verified.evaluation,
            producer=producer,
            verifier=verified.verifier,
            manifest=manifest,
            producer_trust_registry={producer_record.key_id: producer_record},
            verifier_trust_registry={verifier_record.key_id: verifier_record},
            minimum_producer_sequence=producer.payload.sequence,
            minimum_verifier_sequence=verified.minimum_verifier_sequence,
            minimum_admission_sequence=verified.minimum_admission_sequence,
            expected_session_id=spec.session_id,
            expected_evaluator_challenge=spec.evaluator_challenge,
        )
        registry = AdapterAdmissionRegistry(reference_registry())
        contract = _receipt(manifest.adapter_id, manifest_digest, AdmissionGate.CONTRACT, described)
        fidelity = _receipt(
            manifest.adapter_id,
            manifest_digest,
            AdmissionGate.FIDELITY,
            normalized,
        )
        registry.record(contract)
        registry.record(fidelity)
        registry.record_verified_model_utility(
            proof,
            producer_trust_registry={producer_record.key_id: producer_record},
            verifier_trust_registry={verifier_record.key_id: verifier_record},
            minimum_producer_sequence=producer.payload.sequence,
            minimum_verifier_sequence=verified.minimum_verifier_sequence,
            minimum_admission_sequence=verified.minimum_admission_sequence,
            expected_session_id=spec.session_id,
            expected_evaluator_challenge=spec.evaluator_challenge,
        )
        bundle = {
            "schema_version": "faultloom.t40-admission-bundle.v1",
            "bundle_id": spec.bundle_id,
            "manifest": manifest.model_dump(mode="json"),
            "contract_receipt": contract.model_dump(mode="json"),
            "fidelity_receipt": fidelity.model_dump(mode="json"),
            "evaluation": verified.evaluation.model_dump(mode="json"),
            "producer": producer.model_dump(mode="json"),
            "producer_attestations": [
                item.sequence_proof.model_dump(mode="json") for item in invocations
            ],
            "verifier": verified.verifier.model_dump(mode="json"),
            "admission": verified.admission.model_dump(mode="json"),
            "producer_trust": [producer_record.model_dump(mode="json")],
            "verifier_trust": [verifier_record.model_dump(mode="json")],
            "minimum_producer_sequence": producer.payload.sequence,
            "minimum_verifier_sequence": verified.minimum_verifier_sequence,
            "minimum_admission_sequence": verified.minimum_admission_sequence,
            "session_id": spec.session_id,
            "evaluator_challenge": spec.evaluator_challenge,
            "staging_manifest_sha256": staging_binding.manifest_sha256,
            "installed_tree_sha256": staging_binding.installed_tree_sha256,
        }
        raw = canonical_json_bytes(bundle)
        _write_create_once(root_fd, spec.output, raw)
        return _digest_bytes(raw)
    finally:
        for descriptor in (producer_key_fd, verifier_key_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.close(root_fd)


def materialize_adapter_admission(
    *, staging_root: Path, producer_key_fd: int, verifier_key_fd: int
) -> str:
    """Create one staged production bundle without touching the final ``/etc`` root."""

    if (
        not isinstance(staging_root, Path)
        or not staging_root.is_absolute()
        or staging_root != Path(os.path.abspath(staging_root))
        or staging_root == Path("/etc/faultloom")
        or Path("/etc/faultloom") in staging_root.parents
    ):
        raise AdapterAdmissionMaterializerError("production staging root must be an absolute Path")
    return _materialize(staging_root, producer_key_fd, verifier_key_fd, fixture=False)


def _fixture_model_child() -> int:
    raw = sys.stdin.buffer.read(65_537)
    if len(raw) > 65_536 or not raw.endswith(b"\n"):
        return 2
    try:
        request = LocalModelProcessRequest.model_validate_json(raw[:-1])
    except ValidationError:
        return 2
    output = f"dry fixture classification for {request.request_id}"
    response = LocalModelProcessResponse(
        request_id=request.request_id,
        model_snapshot_digest=request.model_snapshot_digest,
        runtime_artifact_digest=request.runtime_artifact_digest,
        decision=UtilityDecision.INCONCLUSIVE,
        output=output,
        output_digest=_digest_bytes(output.encode()),
        raw_llama_stdout_digest=_digest_bytes(("raw:" + request.request_id).encode()),
        input_tokens=17,
        output_tokens=5,
    )
    sys.stdout.buffer.write(_wire(response) + b"\n")
    return 0


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--producer-key-fd", type=int)
    parser.add_argument("--verifier-key-fd", type=int)
    parser.add_argument("--staging-root", type=Path)
    parser.add_argument("--dry-fixture-root", type=Path)
    parser.add_argument("--fixture-model-child", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.fixture_model_child:
        return _fixture_model_child()
    if arguments.producer_key_fd is None or arguments.verifier_key_fd is None:
        return 2
    if (arguments.staging_root is None) == (arguments.dry_fixture_root is None):
        return 2
    try:
        digest = (
            _materialize(
                arguments.dry_fixture_root,
                arguments.producer_key_fd,
                arguments.verifier_key_fd,
                fixture=True,
            )
            if arguments.dry_fixture_root is not None
            else materialize_adapter_admission(
                staging_root=arguments.staging_root,
                producer_key_fd=arguments.producer_key_fd,
                verifier_key_fd=arguments.verifier_key_fd,
            )
        )
    except (AdapterAdmissionMaterializerError, OSError, TypeError, ValueError):
        return 2
    status = {
        "bundle_digest": digest,
        "mode": ("dry_fixture" if arguments.dry_fixture_root is not None else "production"),
    }
    sys.stdout.write(canonical_json_bytes(status).decode("ascii") + "\n")
    return 0


__all__ = [
    "AdapterAdmissionInput",
    "AdapterAdmissionMaterializerError",
    "main",
    "materialize_adapter_admission",
]


if __name__ == "__main__":
    raise SystemExit(main())
