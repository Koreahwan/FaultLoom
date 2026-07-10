#!/usr/bin/env python3
"""Build deterministic, network-free FaultLoom release-candidate artifacts."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


BUILDER_ID = "faultloom-stdlib-builder/0.1"
MINIMUM_ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z
PINNED_ACTION = re.compile(r"^(?:-\s+)?uses:\s*[^\s@]+@([0-9a-f]{40})\s*$")
EXACT_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.+!-]*)"
    r"(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)\s*$"
)
EXACT_PROJECT_DEPENDENCY = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.+!-]*)$"
)
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+!-]*$")
SAFE_PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class BuildPolicyError(RuntimeError):
    """The repository does not satisfy the deterministic build policy."""


@dataclass(frozen=True)
class Policy:
    python_version: str
    rust_version: str
    release_lock: Path
    package_roots: tuple[Path, ...]
    license_files: tuple[Path, ...]
    sbom_hook: Path
    provenance_hook: Path
    release_enabled: bool


@dataclass(frozen=True)
class Project:
    directory: Path
    name: str
    version: str
    description: str
    requires_python: str
    dependencies: tuple[str, ...]
    build_requirements: tuple[str, ...]
    readme: Path | None


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _wheel_name(value: str) -> str:
    return re.sub(r"[-.]+", "_", value)


def _wheel_version(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]+", "_", value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={digest.decode('ascii')}"


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BuildPolicyError(f"cannot read {path}: {exc}") from exc


def load_policy(root: Path) -> Policy:
    root = root.resolve()
    raw = _read_toml(root / "build-policy.toml")
    if raw.get("schema_version") != 1:
        raise BuildPolicyError("build-policy.toml must use schema_version = 1")
    hooks = raw.get("hooks")
    if not isinstance(hooks, dict):
        raise BuildPolicyError("build-policy.toml must define [hooks]")
    try:
        policy = Policy(
            python_version=str(raw["python_version"]),
            rust_version=str(raw["rust_version"]),
            release_lock=root / str(raw["release_lock"]),
            package_roots=tuple(root / str(item) for item in raw["package_roots"]),
            license_files=tuple(root / str(item) for item in raw["license_files"]),
            sbom_hook=root / str(hooks["sbom"]),
            provenance_hook=root / str(hooks["provenance"]),
            release_enabled=raw["release_enabled"],
        )
    except (KeyError, TypeError) as exc:
        raise BuildPolicyError(f"invalid build policy field: {exc}") from exc
    if not isinstance(policy.release_enabled, bool):
        raise BuildPolicyError("release_enabled must be a boolean")
    return policy


def _single_line(path: Path) -> str:
    try:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    except OSError as exc:
        raise BuildPolicyError(f"cannot read {path}: {exc}") from exc
    values = [line for line in lines if line and not line.startswith("#")]
    if len(values) != 1:
        raise BuildPolicyError(f"{path.name} must contain exactly one value")
    return values[0]


def validate_repository_policy(root: Path, policy: Policy) -> dict[str, str]:
    root = root.resolve()
    if _single_line(root / ".python-version") != policy.python_version:
        raise BuildPolicyError(".python-version does not match build-policy.toml")
    rust = _read_toml(root / "rust-toolchain.toml").get("toolchain", {})
    if rust.get("channel") != policy.rust_version:
        raise BuildPolicyError("rust-toolchain.toml does not match build-policy.toml")
    if rust.get("profile") != "minimal":
        raise BuildPolicyError("the Rust toolchain profile must be minimal")
    policy_paths = (
        policy.release_lock,
        *policy.package_roots,
        *policy.license_files,
        policy.sbom_hook,
        policy.provenance_hook,
    )
    for path in policy_paths:
        try:
            path.resolve().relative_to(root)
        except ValueError as exc:
            raise BuildPolicyError(f"build policy path escapes the repository: {path}") from exc
    for path in (*policy.license_files, policy.sbom_hook, policy.provenance_hook):
        if not path.is_file() or path.is_symlink():
            raise BuildPolicyError(f"required regular file is missing: {path.relative_to(root)}")

    workflows = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    if not workflows:
        raise BuildPolicyError("at least one pinned CI workflow is required")
    action_count = 0
    for workflow in workflows:
        for raw_line in workflow.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line.startswith("uses:") and " uses:" not in raw_line:
                continue
            match = PINNED_ACTION.fullmatch(line)
            if match is None:
                raise BuildPolicyError(
                    f"CI action must use a full lowercase commit SHA: {workflow.relative_to(root)}"
                )
            action_count += 1
    if action_count == 0:
        raise BuildPolicyError("CI workflow has no pinned actions")
    return {"python": policy.python_version, "rust": policy.rust_version}


def parse_release_lock(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BuildPolicyError(f"cannot read release lock {path}: {exc}") from exc
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\") or line.startswith("-"):
            raise BuildPolicyError(f"unsupported release lock syntax at {path}:{number}")
        match = EXACT_REQUIREMENT.fullmatch(line)
        if match is None:
            raise BuildPolicyError(
                f"release requirement must be exact and sha256-hashed at {path}:{number}"
            )
        name = _normalized_name(match.group("name"))
        if name in result:
            raise BuildPolicyError(f"duplicate release requirement: {name}")
        hashes = tuple(
            item.removeprefix("--hash=sha256:")
            for item in match.group("hashes").split()
        )
        result[name] = (match.group("version"), hashes)
    return result


def _validate_exact_requirement(requirement: str, *, context: str) -> tuple[str, str]:
    match = EXACT_PROJECT_DEPENDENCY.fullmatch(requirement)
    if match is None:
        raise BuildPolicyError(f"{context} must be an exact name==version pin: {requirement!r}")
    return _normalized_name(match.group("name")), match.group("version")


def discover_projects(root: Path, policy: Policy) -> tuple[Project, ...]:
    projects: list[Project] = []
    for package_root in policy.package_roots:
        if not package_root.exists():
            continue
        if package_root.is_symlink() or not package_root.is_dir():
            raise BuildPolicyError(f"package root must be a regular directory: {package_root}")
        for pyproject in sorted(package_root.glob("*/pyproject.toml")):
            raw = _read_toml(pyproject)
            project = raw.get("project")
            build = raw.get("build-system")
            if not isinstance(project, dict) or not isinstance(build, dict):
                raise BuildPolicyError(f"missing [project] or [build-system] in {pyproject}")
            name = project.get("name")
            version = project.get("version")
            if not isinstance(name, str) or SAFE_PROJECT_NAME.fullmatch(name) is None:
                raise BuildPolicyError(f"invalid project name in {pyproject}")
            if not isinstance(version, str) or SAFE_VERSION.fullmatch(version) is None:
                raise BuildPolicyError(f"invalid project version in {pyproject}")
            dependencies = project.get("dependencies", [])
            build_requirements = build.get("requires", [])
            if not isinstance(dependencies, list) or not all(
                isinstance(item, str) for item in dependencies
            ):
                raise BuildPolicyError(f"project dependencies must be a string list in {pyproject}")
            if not isinstance(build_requirements, list) or not all(
                isinstance(item, str) for item in build_requirements
            ):
                raise BuildPolicyError(f"build requirements must be a string list in {pyproject}")
            for item in build_requirements:
                _validate_exact_requirement(item, context=f"build requirement in {pyproject}")
            readme_value = project.get("readme")
            readme = pyproject.parent / readme_value if isinstance(readme_value, str) else None
            if readme is not None and (not readme.is_file() or readme.is_symlink()):
                raise BuildPolicyError(f"project readme is missing or unsafe: {readme}")
            projects.append(
                Project(
                    directory=pyproject.parent,
                    name=name,
                    version=version,
                    description=str(project.get("description", "")),
                    requires_python=str(project.get("requires-python", "")),
                    dependencies=tuple(dependencies),
                    build_requirements=tuple(build_requirements),
                    readme=readme,
                )
            )
    names = [_normalized_name(project.name) for project in projects]
    if len(names) != len(set(names)):
        raise BuildPolicyError("discovered package names must be unique")
    return tuple(projects)


def validate_project_dependencies(
    projects: tuple[Project, ...], lock: dict[str, tuple[str, tuple[str, ...]]]
) -> None:
    internal = {_normalized_name(project.name) for project in projects}
    required: dict[str, str] = {}
    for project in projects:
        for item in project.dependencies:
            name, version = _validate_exact_requirement(
                item, context=f"runtime dependency for {project.name}"
            )
            if name in internal:
                continue
            previous = required.setdefault(name, version)
            if previous != version:
                raise BuildPolicyError(
                    f"conflicting runtime pins for {name}: {previous}, {version}"
                )
    for name, version in sorted(required.items()):
        locked = lock.get(name)
        if locked is None:
            raise BuildPolicyError(
                f"external runtime dependency is absent from release lock: {name}"
            )
        if locked[0] != version:
            raise BuildPolicyError(
                f"release lock version mismatch for {name}: expected {version}, found {locked[0]}"
            )
    unexpected = sorted(set(lock) - set(required))
    if unexpected:
        raise BuildPolicyError(
            f"release lock contains dependencies unused by distributable packages: {unexpected}"
        )


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    if epoch < MINIMUM_ZIP_EPOCH:
        raise BuildPolicyError("SOURCE_DATE_EPOCH predates the ZIP format minimum")
    return datetime.fromtimestamp(epoch, UTC).timetuple()[:6]


def _wheel_files(project: Project) -> dict[str, bytes]:
    source = project.directory / "src"
    if not source.is_dir() or source.is_symlink():
        raise BuildPolicyError(
            f"pure-Python project must have a regular src directory: {project.name}"
        )
    files: dict[str, bytes] = {}
    forbidden_suffixes = {".dll", ".dylib", ".exe", ".pyd", ".so"}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise BuildPolicyError(f"package source symlink is forbidden: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(source).as_posix()
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.suffix.lower() in forbidden_suffixes:
            raise BuildPolicyError(f"native or executable wheel content is unsupported: {path}")
        files[relative] = path.read_bytes()
    if not files:
        raise BuildPolicyError(f"project has no source files: {project.name}")
    return files


def build_wheel(project: Project, policy: Policy, epoch: int) -> tuple[str, bytes]:
    files = _wheel_files(project)
    distribution = _wheel_name(project.name)
    version = _wheel_version(project.version)
    dist_info = f"{distribution}-{version}.dist-info"
    metadata = [
        "Metadata-Version: 2.3",
        f"Name: {project.name}",
        f"Version: {project.version}",
    ]
    if project.description:
        metadata.append(f"Summary: {project.description}")
    if project.requires_python:
        metadata.append(f"Requires-Python: {project.requires_python}")
    metadata.append("License: Apache-2.0")
    for dependency in project.dependencies:
        metadata.append(f"Requires-Dist: {dependency}")
    if project.readme is not None:
        metadata.extend(
            [
                "Description-Content-Type: text/markdown",
                "",
                project.readme.read_text(encoding="utf-8"),
            ]
        )
    else:
        metadata.append("")
    files[f"{dist_info}/METADATA"] = ("\n".join(metadata) + "\n").encode()
    files[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        f"Generator: {BUILDER_ID}\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode()
    for license_path in policy.license_files:
        files[f"{dist_info}/licenses/{license_path.name}"] = license_path.read_bytes()

    record_path = f"{dist_info}/RECORD"
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name in sorted(files):
        data = files[name]
        writer.writerow((name, _record_hash(data), len(data)))
    writer.writerow((record_path, "", ""))
    files[record_path] = record.getvalue().encode()

    output = io.BytesIO()
    timestamp = _zip_timestamp(epoch)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as wheel:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            wheel.writestr(info, files[name])
    return f"{distribution}-{version}-py3-none-any.whl", output.getvalue()


def _git(root: Path, *arguments: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-c", "core.quotepath=false", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=not binary,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace") if binary else result.stderr
        raise BuildPolicyError(f"git {' '.join(arguments)} failed: {stderr.strip()}")
    return result.stdout


def git_identity(root: Path) -> dict[str, str]:
    return {
        "commit": str(_git(root, "rev-parse", "HEAD")).strip(),
        "tree": str(_git(root, "rev-parse", "HEAD^{tree}")).strip(),
    }


def require_clean_checkout(root: Path) -> None:
    status = str(_git(root, "status", "--porcelain=v1", "--untracked-files=all"))
    if status:
        raise BuildPolicyError("build requires a clean checkout")


def _tracked_files(root: Path) -> tuple[tuple[str, str], ...]:
    output = bytes(_git(root, "ls-files", "-s", "-z", binary=True))
    entries: list[tuple[str, str]] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, encoded_path = raw.split(b"\t", 1)
            mode = metadata.split(b" ", 1)[0].decode("ascii")
            path = encoded_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise BuildPolicyError("git index contains an unsupported path") from exc
        if mode not in {"100644", "100755"}:
            raise BuildPolicyError(
                f"tracked symlink or gitlink is forbidden in source archive: {path}"
            )
        entries.append((mode, path))
    return tuple(sorted(entries, key=lambda item: item[1]))


def build_source_archive(root: Path, epoch: int) -> tuple[str, bytes]:
    entries = _tracked_files(root)
    raw_tar = io.BytesIO()
    prefix = "faultloom-core"
    directories = {prefix}
    for _, path in entries:
        parts = Path(path).parts[:-1]
        for length in range(1, len(parts) + 1):
            directories.add(f"{prefix}/{'/'.join(parts[:length])}")
    with tarfile.open(fileobj=raw_tar, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for directory in sorted(directories):
            info = tarfile.TarInfo(f"{directory}/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info)
        for mode, relative in entries:
            path = root / relative
            data = path.read_bytes()
            info = tarfile.TarInfo(f"{prefix}/{relative}")
            info.size = len(data)
            info.mode = 0o755 if mode == "100755" else 0o644
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return "faultloom-core-source.tar.gz", _deterministic_gzip(raw_tar.getvalue(), epoch)


def _deterministic_gzip(data: bytes, epoch: int) -> bytes:
    """Encode GZIP with stored DEFLATE blocks, avoiding zlib-version drift."""
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise BuildPolicyError("SOURCE_DATE_EPOCH cannot be represented in a GZIP header")
    output = bytearray(b"\x1f\x8b\x08\x00")
    output.extend(struct.pack("<I", epoch))
    output.extend(b"\x00\xff")  # no compression hint; unknown operating system
    chunks = [data[offset : offset + 65535] for offset in range(0, len(data), 65535)]
    if not chunks:
        chunks = [b""]
    for index, chunk in enumerate(chunks):
        output.append(1 if index == len(chunks) - 1 else 0)
        length = len(chunk)
        output.extend(struct.pack("<HH", length, length ^ 0xFFFF))
        output.extend(chunk)
    output.extend(struct.pack("<II", binascii.crc32(data), len(data) & 0xFFFFFFFF))
    return bytes(output)


def _component(project: Project) -> dict[str, Any]:
    return {
        "name": project.name,
        "version": project.version,
        "dependencies": list(project.dependencies),
        "purl": f"pkg:pypi/{_normalized_name(project.name)}@{project.version}",
    }


def _run_metadata_hook(
    *, root: Path, hook: Path, kind: str, context_path: Path, output_path: Path
) -> None:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1",
        "UV_OFFLINE": "1",
        "CARGO_NET_OFFLINE": "true",
    }
    result = subprocess.run(
        [sys.executable, str(hook), kind, str(context_path), str(output_path)],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BuildPolicyError(f"{kind} hook failed: {result.stderr.strip()}")
    if not output_path.is_file():
        raise BuildPolicyError(f"{kind} hook did not create its output")
    try:
        value = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildPolicyError(f"{kind} hook produced invalid JSON") from exc
    if kind == "sbom" and value.get("bomFormat") != "CycloneDX":
        raise BuildPolicyError("SBOM hook output is not CycloneDX")
    if kind == "provenance" and value.get("_type") != "https://in-toto.io/Statement/v1":
        raise BuildPolicyError("provenance hook output is not an in-toto statement")


def _write_artifact(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def build_once(root: Path, output: Path, epoch: int, *, release: bool = False) -> dict[str, str]:
    root = root.resolve()
    output = output.resolve()
    policy = load_policy(root)
    validate_repository_policy(root, policy)
    if release:
        if not policy.release_enabled:
            raise BuildPolicyError(
                "release mode is disabled until the T41 signed authorization gate is integrated"
            )
        raise BuildPolicyError(
            "release authorization verifier is not implemented; refusing release"
        )
    require_clean_checkout(root)
    lock = parse_release_lock(policy.release_lock)
    projects = discover_projects(root, policy)
    validate_project_dependencies(projects, lock)
    if output.exists() and any(output.iterdir()):
        raise BuildPolicyError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, bytes] = {}
    for project in projects:
        name, data = build_wheel(project, policy, epoch)
        artifacts[name] = data
    source_name, source_data = build_source_archive(root, epoch)
    artifacts[source_name] = source_data
    for name, data in sorted(artifacts.items()):
        _write_artifact(output / name, data)

    identity = git_identity(root)
    context = {
        "schema_version": 1,
        "builder": BUILDER_ID,
        "source_date_epoch": epoch,
        "source": identity,
        "toolchains": {"python": policy.python_version, "rust": policy.rust_version},
        "components": [_component(project) for project in projects],
        "locked_dependencies": [
            {"name": name, "version": version, "sha256": list(hashes)}
            for name, (version, hashes) in sorted(lock.items())
        ],
        "subjects": [
            {"name": name, "sha256": _sha256(data), "size": len(data)}
            for name, data in sorted(artifacts.items())
        ],
    }
    context_path = output / ".build-context.json"
    _write_artifact(context_path, _canonical_json(context))
    sbom = output / "faultloom-core.sbom.cdx.json"
    provenance = output / "faultloom-core.provenance.intoto.json"
    try:
        _run_metadata_hook(
            root=root,
            hook=policy.sbom_hook,
            kind="sbom",
            context_path=context_path,
            output_path=sbom,
        )
        _run_metadata_hook(
            root=root,
            hook=policy.provenance_hook,
            kind="provenance",
            context_path=context_path,
            output_path=provenance,
        )
    finally:
        context_path.unlink(missing_ok=True)

    checksums: dict[str, str] = {}
    for path in sorted(output.iterdir()):
        if path.is_file() and not path.name.startswith("."):
            checksums[path.name] = _sha256(path.read_bytes())
    checksum_text = "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items()))
    _write_artifact(output / "SHA256SUMS", checksum_text.encode())
    checksums["SHA256SUMS"] = _sha256(checksum_text.encode())
    return dict(sorted(checksums.items()))


def _directory_bytes(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def build_reproducibly(
    root: Path, output: Path, epoch: int, *, release: bool = False
) -> dict[str, str]:
    with (
        tempfile.TemporaryDirectory(prefix="faultloom-build-a-") as first_raw,
        tempfile.TemporaryDirectory(prefix="faultloom-build-b-") as second_raw,
    ):
        first = Path(first_raw)
        second = Path(second_raw)
        first_manifest = build_once(root, first, epoch, release=release)
        second_manifest = build_once(root, second, epoch, release=release)
        if _directory_bytes(first) != _directory_bytes(second):
            raise BuildPolicyError("two builds from the same checkout were not byte-identical")
        if output.exists() and any(output.iterdir()):
            raise BuildPolicyError(f"output directory is not empty: {output}")
        output.mkdir(parents=True, exist_ok=True)
        for path in sorted(first.iterdir()):
            if path.is_file():
                shutil.copyfile(path, output / path.name)
        return first_manifest


def _epoch_from_args(value: int | None) -> int:
    if value is None:
        raw = os.environ.get("SOURCE_DATE_EPOCH")
        if raw is None:
            raise BuildPolicyError("SOURCE_DATE_EPOCH is required")
        try:
            value = int(raw)
        except ValueError as exc:
            raise BuildPolicyError("SOURCE_DATE_EPOCH must be an integer") from exc
    if value < MINIMUM_ZIP_EPOCH:
        raise BuildPolicyError("SOURCE_DATE_EPOCH must be at least 1980-01-01")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--verify-reproducible", action="store_true")
    args = parser.parse_args()
    try:
        epoch = _epoch_from_args(args.source_date_epoch)
        if args.verify_reproducible:
            manifest = build_reproducibly(args.root, args.out, epoch, release=args.release)
        else:
            manifest = build_once(args.root, args.out, epoch, release=args.release)
    except BuildPolicyError as exc:
        print(f"build refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "artifacts": manifest}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
