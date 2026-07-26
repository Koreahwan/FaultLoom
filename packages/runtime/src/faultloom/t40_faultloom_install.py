"""Verification of the immutable Task 10 Python installation for the T40 arm."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .t40_arm_runtime import T40ArmRuntimeError, canonical_json_bytes

FORMAL_SITE_ROOT = Path("/opt/faultloom/t40-formal-v1/lib/python3.12/site-packages")
FORMAL_PROFILE_PATH = Path("/etc/faultloom/t40-formal-v1/profile.json")
FORMAL_PYTHON_MANIFEST_PATH = Path("/etc/faultloom/t40-formal-v1/python-install-manifest.json")
FORMAL_WHEEL_ROOT = Path("/opt/faultloom/t40-formal-v1/wheels")
_INSTALLATION_AUTHORITY_PUBLIC_KEY = "vZDj5kYxP815EABkn6MuGY548+AbHs67CMo5L9c40D4="
_INSTALLATION_AUTHORITY_SHA256 = "7d935fb4d2cafda152171d310ab68e3f5ab119731357ad2e645781c52b87d452"
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_WHEEL_BINDINGS = {
    "faultloom_wheel": "faultloom_wheel_sha256",
    "protocol_wheel": "protocol_wheel_sha256",
    "sdk_wheel": "sdk_wheel_sha256",
    "web_wheel": "web_wheel_sha256",
}
_WHEEL_FILES = {
    "faultloom_wheel": "faultloom.whl",
    "protocol_wheel": "faultloom-protocol.whl",
    "sdk_wheel": "faultloom-sdk.whl",
    "web_wheel": "faultloom-web.whl",
}
_REQUIRED_PREFIXES = (
    "cryptography",
    "faultloom",
    "faultloom_protocol",
    "faultloom_sdk",
    "faultloom_web",
    "pydantic",
    "pydantic_core",
)
_REQUIRED_MODULES = (
    "cryptography",
    "faultloom.t40_faultloom_arm",
    "faultloom_protocol",
    "faultloom_sdk",
    "faultloom_web.t40_worker",
    "pydantic",
    "pydantic_core",
)
_PROFILE_FIELDS = {
    "schema",
    "core_commit",
    "core_tree",
    "eval_commit",
    "eval_tree",
    "ops_commit",
    "ops_tree",
    "faultloom_wheel_sha256",
    "protocol_wheel_sha256",
    "sdk_wheel_sha256",
    "web_wheel_sha256",
    "eval_wheel_sha256",
    "router_sha256",
    "legacy_arm_sha256",
    "thin_arm_sha256",
    "faultloom_arm_sha256",
    "model_bundle_sha256",
    "runtime_bundle_sha256",
    "dependency_bundle_sha256",
    "legacy_export_sha256",
    "legacy_manifest_sha256",
    "adapter_admission_bundle_sha256",
    "private_plan_commitment",
    "independent_verifier_sha256",
    "verifier_policy_sha256",
    "expected_calls",
    "lab_key_id",
    "lab_key_sha256",
    "producer_key_id",
    "producer_key_sha256",
    "legacy_arm_key_id",
    "legacy_arm_key_sha256",
    "thin_arm_key_id",
    "thin_arm_key_sha256",
    "faultloom_arm_key_id",
    "faultloom_arm_key_sha256",
    "verifier_key_id",
    "verifier_key_sha256",
    "verifier_root_key_id",
    "verifier_root_key_sha256",
    "sandbox_sha256",
    "argv",
    "environment",
    "network",
    "execution",
    "python_argv",
    "site_packages",
    "python_install_manifest_sha256",
    "cgroup",
    "cgroup_limits",
}


class T40FaultLoomInstallError(T40ArmRuntimeError):
    pass


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _read_owned_file(path: Path, *, uid: int, gid: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise T40FaultLoomInstallError("formal install metadata is unavailable") from None
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 65_536):
            size += len(chunk)
            if size > _MAX_DOCUMENT_BYTES:
                raise T40FaultLoomInstallError("formal install metadata exceeds its limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
    except OSError:
        raise T40FaultLoomInstallError("formal install metadata is unreadable") from None
    finally:
        os.close(descriptor)
    metadata = (before, after, named)
    if any(
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != uid
        or item.st_gid != gid
        or stat.S_IMODE(item.st_mode) != 0o600
        or item.st_nlink != 1
        for item in metadata
    ):
        raise T40FaultLoomInstallError("formal install metadata identity is invalid")
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        for item in metadata
    }
    raw = b"".join(chunks)
    if len(identities) != 1 or len(raw) != before.st_size:
        raise T40FaultLoomInstallError("formal install metadata changed during read")
    return raw


def _verify_envelope(raw: bytes, trusted_root: bytes, label: str) -> dict[str, object]:
    try:
        document: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise T40FaultLoomInstallError(f"{label} is not JSON") from None
    if type(document) is not dict or raw != canonical_json_bytes(document):
        raise T40FaultLoomInstallError(f"{label} is not canonical")
    if set(document) != {"payload", "payload_digest", "signature"}:
        raise T40FaultLoomInstallError(f"{label} envelope is invalid")
    payload = document["payload"]
    payload_digest = document["payload_digest"]
    signature = document["signature"]
    if type(payload) is not dict or type(payload_digest) is not str or type(signature) is not str:
        raise T40FaultLoomInstallError(f"{label} envelope types are invalid")
    if _sha256(canonical_json_bytes(payload)) != payload_digest:
        raise T40FaultLoomInstallError(f"{label} payload digest is invalid")
    try:
        signature_bytes = base64.urlsafe_b64decode(signature + "==")
        if (
            len(signature_bytes) != 64
            or base64.urlsafe_b64encode(signature_bytes).decode().rstrip("=") != signature
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(trusted_root).verify(
            signature_bytes,
            canonical_json_bytes({"payload": payload, "payload_digest": payload_digest}),
        )
    except (InvalidSignature, ValueError):
        raise T40FaultLoomInstallError(f"{label} signature is invalid") from None
    return payload


def _manifest_records(manifest: dict[str, object]) -> dict[str, tuple[str, int]]:
    installed_tree = manifest.get("installed_tree")
    if (
        manifest.get("schema") != "faultloom.ops.t40-formal-python-install-manifest.v1"
        or type(installed_tree) is not list
        or type(manifest.get("wheels")) is not dict
    ):
        raise T40FaultLoomInstallError("formal Python manifest contract is invalid")
    records: dict[str, tuple[str, int]] = {}
    for record in installed_tree:
        if type(record) is not dict or set(record) != {"mode", "path", "sha256"}:
            raise T40FaultLoomInstallError("formal installed-tree record is invalid")
        path = record["path"]
        digest = record["sha256"]
        mode = record["mode"]
        if (
            type(path) is not str
            or type(digest) is not str
            or type(mode) is not int
            or not digest.startswith("sha256:")
            or len(digest) != 71
            or PurePosixPath(path).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
            or path in records
        ):
            raise T40FaultLoomInstallError("formal installed-tree record is unsafe")
        records[path] = (digest, mode)
    return records


def _is_record_file(value: object) -> bool:
    if type(value) is not dict:
        return False
    path = value.get("path")
    return type(path) is str and path.endswith(".dist-info/RECORD")


def _verify_owned_directory(path: Path, *, uid: int, gid: int) -> os.stat_result:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        raise T40FaultLoomInstallError("formal install directory is unavailable") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise T40FaultLoomInstallError("formal install directory identity is invalid")
    return metadata


def _verify_tree(
    site_root: Path, records: dict[str, tuple[str, int]], *, uid: int, gid: int
) -> None:
    root_before = _verify_owned_directory(site_root, uid=uid, gid=gid)
    observed: set[str] = set()
    for directory, names, filenames in os.walk(site_root, followlinks=False):
        base = Path(directory)
        _verify_owned_directory(base, uid=uid, gid=gid)
        for name in names:
            _verify_owned_directory(base / name, uid=uid, gid=gid)
        for name in filenames:
            path = base / name
            relative = path.relative_to(site_root).as_posix()
            expected = records.get(relative)
            if expected is None:
                raise T40FaultLoomInstallError("formal site contains an ambient file")
            _read_installed_file(path, expected[0], expected[1], uid=uid, gid=gid)
            observed.add(relative)
    root_after = os.stat(site_root, follow_symlinks=False)
    if observed != set(records) or (
        root_before.st_dev,
        root_before.st_ino,
        root_before.st_mtime_ns,
        root_before.st_ctime_ns,
    ) != (
        root_after.st_dev,
        root_after.st_ino,
        root_after.st_mtime_ns,
        root_after.st_ctime_ns,
    ):
        raise T40FaultLoomInstallError("formal installed tree changed during validation")


def _read_installed_file(
    path: Path, expected_digest: str, expected_mode: int, *, uid: int, gid: int
) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        visible = os.stat(path, follow_symlinks=False)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        final = os.fstat(descriptor)
    except OSError:
        raise T40FaultLoomInstallError("formal installed file is unreadable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    metadata = (visible, opened, final)
    if any(
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != uid
        or item.st_gid != gid
        or stat.S_IMODE(item.st_mode) != expected_mode
        or item.st_nlink != 1
        for item in metadata
    ):
        raise T40FaultLoomInstallError("formal installed file identity is invalid")
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        for item in metadata
    }
    if (
        len(identities) != 1
        or size != opened.st_size
        or f"sha256:{digest.hexdigest()}" != expected_digest
    ):
        raise T40FaultLoomInstallError("formal installed file digest is invalid")


def _validate_formal_installation_at(
    *,
    site_root: Path,
    profile_path: Path,
    manifest_path: Path,
    wheel_root: Path,
    trusted_root: bytes,
    uid: int,
    gid: int,
) -> None:
    manifest_raw = _read_owned_file(manifest_path, uid=uid, gid=gid)
    manifest = _verify_envelope(manifest_raw, trusted_root, "formal Python manifest")
    profile_raw = _read_owned_file(profile_path, uid=uid, gid=gid)
    profile = _verify_envelope(profile_raw, trusted_root, "formal install profile")
    expected_manifest_root = {
        "gid": gid,
        "mode": 0o700,
        "path": FORMAL_SITE_ROOT.as_posix(),
        "uid": uid,
    }
    if (
        set(manifest)
        != {"dependency_bundle_sha256", "installed_tree", "schema", "site_root", "wheels"}
        or manifest.get("site_root") != expected_manifest_root
        or set(profile) != _PROFILE_FIELDS
        or profile.get("schema") != "faultloom.ops.t40-formal-install-profile.v1"
        or profile.get("site_packages") != FORMAL_SITE_ROOT.as_posix()
        or profile.get("network") != "disabled"
        or profile.get("execution") != "one-shot-no-daemon"
        or profile.get("python_argv") != ["/usr/bin/python3.12", "-I", "-S", "-B"]
        or profile.get("environment")
        != {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        or profile.get("cgroup") != "required-v2"
        or profile.get("cgroup_limits")
        != {
            "cpu.max": "200000 100000",
            "memory.max": "4294967296",
            "memory.oom.group": "1",
            "pids.max": "128",
        }
        or type(profile.get("argv")) is not list
        or profile.get("python_install_manifest_sha256") != _sha256(manifest_raw)
        or manifest.get("dependency_bundle_sha256") != profile.get("dependency_bundle_sha256")
    ):
        raise T40FaultLoomInstallError("formal install profile contract is invalid")
    wheels = manifest.get("wheels")
    if type(wheels) is not dict:
        raise T40FaultLoomInstallError("formal Python wheel bindings are invalid")
    records = _manifest_records(manifest)
    _verify_owned_directory(wheel_root, uid=uid, gid=gid)
    for manifest_role, profile_field in _WHEEL_BINDINGS.items():
        wheel = wheels.get(manifest_role)
        installed_files = wheel.get("installed_files") if type(wheel) is dict else None
        if (
            type(wheel) is not dict
            or wheel.get("artifact_sha256") != profile.get(profile_field)
            or type(installed_files) is not list
            or not any(_is_record_file(item) for item in installed_files)
        ):
            raise T40FaultLoomInstallError("formal Core wheel binding is invalid")
        for item in installed_files:
            if (
                type(item) is not dict
                or set(item) != {"mode", "path", "sha256"}
                or type(item.get("path")) is not str
                or records.get(item["path"]) != (item.get("sha256"), item.get("mode"))
            ):
                raise T40FaultLoomInstallError("formal wheel content binding is invalid")
        expected_wheel_digest = profile.get(profile_field)
        if type(expected_wheel_digest) is not str:
            raise T40FaultLoomInstallError("formal Core wheel digest is invalid")
        _read_installed_file(
            wheel_root / _WHEEL_FILES[manifest_role],
            expected_wheel_digest,
            0o400,
            uid=uid,
            gid=gid,
        )
    _verify_tree(site_root, records, uid=uid, gid=gid)


def validate_formal_installation() -> None:
    trusted_root = base64.b64decode(_INSTALLATION_AUTHORITY_PUBLIC_KEY, validate=True)
    if hashlib.sha256(trusted_root).hexdigest() != _INSTALLATION_AUTHORITY_SHA256:
        raise T40FaultLoomInstallError("compiled installation authority is inconsistent")
    _validate_formal_installation_at(
        site_root=FORMAL_SITE_ROOT,
        profile_path=FORMAL_PROFILE_PATH,
        manifest_path=FORMAL_PYTHON_MANIFEST_PATH,
        wheel_root=FORMAL_WHEEL_ROOT,
        trusted_root=trusted_root,
        uid=0,
        gid=0,
    )
    _validate_required_origins(FORMAL_SITE_ROOT)


def _validate_required_origins(site_root: Path) -> None:
    for name in _REQUIRED_MODULES:
        try:
            module = importlib.import_module(name)
        except (ImportError, OSError):
            raise T40FaultLoomInstallError("required formal module is unavailable") from None
        if getattr(module, "__file__", None) is None:
            raise T40FaultLoomInstallError("required formal module origin is unavailable")
    for name, module in tuple(sys.modules.items()):
        if not any(
            name == prefix or name.startswith(prefix + ".") for prefix in _REQUIRED_PREFIXES
        ):
            continue
        origin = getattr(module, "__file__", None)
        if origin is None:
            continue
        try:
            resolved = Path(origin).resolve(strict=True)
        except OSError:
            raise T40FaultLoomInstallError("required module origin is unavailable") from None
        if not resolved.is_relative_to(site_root):
            raise T40FaultLoomInstallError("required module resolved outside the formal site root")


__all__ = ["T40FaultLoomInstallError", "validate_formal_installation"]
