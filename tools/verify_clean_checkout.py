#!/usr/bin/env python3
"""Verify a clean FaultLoom checkout with offline-requested build execution."""

from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_public_tree import Violation, scan_tracked_snapshot
from tools.reproducible_build import (
    BuildPolicyError,
    NETWORK_EXECUTION,
    build_source_archive,
    build_primary_artifacts,
    build_wheel,
    build_reproducibly,
    discover_projects,
    git_commit_epoch,
    git_identity,
    load_policy,
    make_build_context,
    parse_release_dependency_graph,
    parse_release_lock,
    render_metadata_from_head,
    require_clean_checkout,
    rust_toolchain_spec,
    validate_project_dependencies,
    validate_repository_policy,
)
from tools.rust_toolchain import (
    RustToolchainError,
    StagedRustToolchain,
    rustc_closure_sha256,
    stage_verified_toolchain,
)


class VerificationError(RuntimeError):
    """A clean-checkout build invariant failed."""


def _run(command: list[str], *, root: Path, environment: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise VerificationError(
            f"command failed ({' '.join(command)}): {result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


MAX_PORTABLE_ARCHIVE_PATH = 4096
def verify_toolchains(
    root: Path,
    rust_toolchain: str,
    environment: dict[str, str],
    *,
    revision: str = "HEAD",
) -> None:
    with verified_toolchain(
        root,
        rust_toolchain,
        environment,
        revision=revision,
    ):
        pass


@contextlib.contextmanager
def verified_toolchain(
    root: Path,
    rust_toolchain: str,
    environment: dict[str, str],
    *,
    revision: str = "HEAD",
) -> Iterator[StagedRustToolchain]:
    policy = load_policy(root, revision=revision)
    actual_python = ".".join(str(item) for item in sys.version_info[:3])
    if actual_python != policy.python_version:
        raise VerificationError(
            f"Python mismatch: expected {policy.python_version}, found {actual_python}"
        )
    try:
        with stage_verified_toolchain(
            rust_toolchain_spec(policy),
            alias=rust_toolchain,
            environment=environment,
            root=root,
        ) as toolchain:
            yield toolchain
    except RustToolchainError as exc:
        raise VerificationError(str(exc)) from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_checksums(output: Path) -> None:
    checksum_path = output / "SHA256SUMS"
    if not checksum_path.is_file():
        raise VerificationError("SHA256SUMS is missing")
    expected: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        try:
            digest, name = line.split("  ", 1)
        except ValueError as exc:
            raise VerificationError("malformed SHA256SUMS") from exc
        if len(digest) != 64 or name in expected or "/" in name:
            raise VerificationError("unsafe or duplicate SHA256SUMS entry")
        expected[name] = digest
    actual = {
        path.name: _sha256(path.read_bytes())
        for path in output.iterdir()
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if expected != actual:
        raise VerificationError("artifact checksums do not match SHA256SUMS")


def _validate_archive_member_name(name: str) -> PurePosixPath:
    candidate = name[:-1] if name.endswith("/") else name
    if (
        not candidate
        or len(candidate) > MAX_PORTABLE_ARCHIVE_PATH
        or "\\" in candidate
        or candidate.startswith("/")
        or re.match(r"^[A-Za-z]:", candidate)
    ):
        raise VerificationError(f"unsafe archive member path: {name}")
    raw_parts = candidate.split("/")
    if any(
        part in {"", ".", ".."}
        or any(character in '<>"|?*' for character in part)
        or ":" in part
        or part.endswith((" ", "."))
        or len(part) > 255
        or any(
            ord(character) < 32 or ord(character) > 126
            for character in part
        )
        for part in raw_parts
    ):
        raise VerificationError(f"unsafe archive member path: {name}")
    reserved = re.compile(
        r"^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|"
        r"COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)",
        re.IGNORECASE,
    )
    if any(reserved.match(part) for part in raw_parts):
        raise VerificationError(f"Windows-reserved archive member path: {name}")
    dos_alias = re.compile(r"^[^.]*~[0-9]+(?:\.[^.]{0,3})?$", re.IGNORECASE)
    if any(dos_alias.fullmatch(part) for part in raw_parts):
        raise VerificationError(f"Windows 8.3 alias-shaped archive member path: {name}")
    path = PurePosixPath(candidate)
    if path.parts[0] != "faultloom-core":
        raise VerificationError(f"archive member escapes the expected root: {name}")
    return path


def _reject_windows_name_collisions(
    entries: list[tuple[str, bool]], *, artifact: str
) -> None:
    normalized: dict[tuple[str, ...], tuple[str, bool]] = {}
    for name, is_directory in entries:
        candidate = name[:-1] if name.endswith("/") else name
        windows_name = tuple(
            unicodedata.normalize("NFC", part).casefold()
            for part in candidate.split("/")
        )
        previous = normalized.get(windows_name)
        if previous is not None and previous != (name, is_directory):
            raise VerificationError(
                f"{artifact} has Windows-normalized path collision: "
                f"{previous[0]}, {name}"
            )
        for length in range(1, len(windows_name)):
            ancestor = normalized.get(windows_name[:length])
            if ancestor is not None and not ancestor[1]:
                raise VerificationError(
                    f"{artifact} has Windows file/directory collision: "
                    f"{ancestor[0]}, {name}"
                )
        if not is_directory:
            descendant = next(
                (
                    item
                    for path, item in normalized.items()
                    if len(path) > len(windows_name)
                    and path[: len(windows_name)] == windows_name
                ),
                None,
            )
            if descendant is not None:
                raise VerificationError(
                    f"{artifact} has Windows file/directory collision: "
                    f"{name}, {descendant[0]}"
                )
        normalized[windows_name] = (name, is_directory)


def verify_source_archive(output: Path) -> None:
    archive_path = output / "faultloom-core-source.tar.gz"
    if not archive_path.is_file():
        raise VerificationError("tracked-source archive is missing")
    with tarfile.open(archive_path, "r:gz") as archive:
        raw_names = archive.getnames()
        names = set(raw_names)
        if len(names) != len(raw_names):
            raise VerificationError("source archive contains duplicate members")
        members = archive.getmembers()
        _reject_windows_name_collisions(
            [(member.name, member.isdir()) for member in members],
            artifact="source archive",
        )
        if "faultloom-core/LICENSE" not in names or "faultloom-core/NOTICE" not in names:
            raise VerificationError("source archive omits LICENSE or NOTICE")
        for member in members:
            _validate_archive_member_name(member.name)
            if not (member.isfile() or member.isdir()):
                raise VerificationError(f"unsafe source archive member: {member.name}")


@contextlib.contextmanager
def immutable_head_snapshot(
    root: Path, *, revision: str = "HEAD"
) -> Iterator[Path]:
    """Materialize verified Git bytes without consulting worktree file content."""

    _, archive_bytes = build_source_archive(root.resolve(), 0, revision=revision)
    with tempfile.TemporaryDirectory(prefix="faultloom-immutable-head-") as raw_snapshot:
        snapshot = Path(raw_snapshot) / "faultloom-core"
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            raw_names = [member.name for member in members]
            if len(raw_names) != len(set(raw_names)):
                raise VerificationError("immutable source snapshot has duplicate members")
            _reject_windows_name_collisions(
                [(member.name, member.isdir()) for member in members],
                artifact="immutable source snapshot",
            )
            for member in members:
                path = _validate_archive_member_name(member.name)
                relative_parts = path.parts[1:]
                destination = snapshot.joinpath(*relative_parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise VerificationError(
                        f"unsafe immutable source member: {member.name}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise VerificationError(
                        f"cannot read immutable source member: {member.name}"
                    )
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as handle:
                    handle.write(source.read())
        yield snapshot


def scan_immutable_head(root: Path, *, revision: str = "HEAD") -> list[Violation]:
    """Run the public-tree gate over bytes read from the immutable HEAD tree."""

    with immutable_head_snapshot(root, revision=revision) as snapshot:
        return scan_tracked_snapshot(snapshot)


def run_immutable_tests(
    root: Path,
    *,
    revision: str,
    environment: dict[str, str],
) -> None:
    """Run the admitted tests exclusively from a verified HEAD snapshot."""

    with immutable_head_snapshot(root, revision=revision) as snapshot:
        test_environment = {
            key: value
            for key, value in environment.items()
            if not key.startswith("PYTHON")
        }
        test_environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
            }
        )
        bootstrap = (
            "import pathlib, sys, unittest\n"
            "root = pathlib.Path(sys.argv[1]).resolve()\n"
            "sys.path.insert(0, str(root))\n"
            "suite = unittest.defaultTestLoader.discover(\n"
            "    str(root / 'tests'),\n"
            "    pattern='test_reproducible_build.py',\n"
            ")\n"
            "result = unittest.TextTestRunner(verbosity=1).run(suite)\n"
            "raise SystemExit(0 if result.wasSuccessful() and result.testsRun else 1)\n"
        )
        _run(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                bootstrap,
                str(snapshot),
            ],
            root=snapshot,
            environment=test_environment,
        )


def verify_wheels(output: Path) -> None:
    for wheel_path in sorted(output.glob("*.whl")):
        with zipfile.ZipFile(wheel_path) as wheel:
            raw_names = wheel.namelist()
            names = set(raw_names)
            if len(names) != len(raw_names):
                raise VerificationError(f"wheel contains duplicate members: {wheel_path.name}")
            _reject_windows_name_collisions(
                [(item.filename, item.is_dir()) for item in wheel.infolist()],
                artifact=f"wheel {wheel_path.name}",
            )
            for item in wheel.infolist():
                member = _validate_archive_member_name(f"faultloom-core/{item.filename}")
                if len(member.parts) < 2:
                    raise VerificationError(f"unsafe wheel member: {item.filename}")
                mode = item.external_attr >> 16
                if not stat.S_ISREG(mode):
                    raise VerificationError(
                        f"wheel non-regular member is forbidden: {item.filename}"
                    )
            license_names = {
                name for name in names if name.endswith(".dist-info/licenses/LICENSE")
            }
            notice_names = {
                name for name in names if name.endswith(".dist-info/licenses/NOTICE")
            }
            record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
            if not license_names or not notice_names or len(record_names) != 1:
                raise VerificationError(f"wheel policy files or RECORD missing: {wheel_path.name}")
            record_name = record_names[0]
            rows = list(csv.reader(io.StringIO(wheel.read(record_name).decode("utf-8"))))
            if any(len(row) != 3 for row in rows):
                raise VerificationError(f"wheel RECORD is malformed: {wheel_path.name}")
            recorded_paths = [row[0] for row in rows]
            if len(recorded_paths) != len(set(recorded_paths)):
                raise VerificationError(
                    f"wheel RECORD contains duplicate rows: {wheel_path.name}"
                )
            if set(recorded_paths) != names:
                raise VerificationError(f"wheel RECORD is incomplete: {wheel_path.name}")
            for path, digest, size in rows:
                if path == record_name:
                    if digest or size:
                        raise VerificationError(
                            f"wheel RECORD self-row is malformed: {wheel_path.name}"
                        )
                    continue
                data = wheel.read(path)
                encoded = base64.urlsafe_b64encode(
                    hashlib.sha256(data).digest()
                ).rstrip(b"=")
                expected_digest = f"sha256={encoded.decode('ascii')}"
                if digest != expected_digest or size != str(len(data)):
                    raise VerificationError(
                        "wheel RECORD digest or size mismatch: "
                        f"{wheel_path.name}: {path}"
                    )


def verify_metadata(
    output: Path,
    root: Path,
    epoch: int,
    *,
    revision: str = "HEAD",
    toolchain: StagedRustToolchain | None = None,
) -> None:
    root = root.resolve()
    source = git_identity(root, revision=revision)
    revision = source["commit"]
    policy = load_policy(root, revision=revision)
    projects = discover_projects(root, policy, revision=revision)
    lock = parse_release_lock(policy.release_lock, root=root, revision=revision)
    dependency_graph = parse_release_dependency_graph(
        policy.release_dependency_graph, lock, root=root, revision=revision
    )
    validate_project_dependencies(projects, lock, dependency_graph)

    expected_artifacts, expected_modes, native_artifacts = build_primary_artifacts(
        root,
        policy,
        projects,
        epoch,
        revision=revision,
        source=source,
        toolchain=toolchain,
    )
    observed_artifacts = {
        path.name: path.read_bytes()
        for path in output.iterdir()
        if path.is_file()
        and path.name
        not in {
            "SHA256SUMS",
            "faultloom-core.sbom.cdx.json",
            "faultloom-core.provenance.intoto.json",
        }
    }
    if observed_artifacts != expected_artifacts:
        raise VerificationError("built artifacts do not reconcile with immutable Git sources")
    for name, expected_mode in expected_modes.items():
        if stat.S_IMODE((output / name).stat().st_mode) != expected_mode:
            raise VerificationError(f"built artifact mode does not reconcile: {name}")

    context = make_build_context(
        root,
        policy,
        projects,
        lock,
        dependency_graph,
        expected_artifacts,
        epoch,
        source=source,
        native_artifacts=native_artifacts,
    )
    expected_sbom = render_metadata_from_head(
        root=root,
        hook=policy.sbom_hook,
        kind="sbom",
        context=context,
        revision=revision,
    )
    expected_provenance = render_metadata_from_head(
        root=root,
        hook=policy.provenance_hook,
        kind="provenance",
        context=context,
        revision=revision,
    )
    if (output / "faultloom-core.sbom.cdx.json").read_bytes() != expected_sbom:
        raise VerificationError("SBOM does not reconcile with components and dependency graph")
    if (
        output / "faultloom-core.provenance.intoto.json"
    ).read_bytes() != expected_provenance:
        raise VerificationError("provenance does not match the complete expected predicate")


def _offline_environment(rust_toolchain: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "UV_OFFLINE": "1",
            "CARGO_NET_OFFLINE": "true",
            "FAULTLOOM_RUST_TOOLCHAIN": rust_toolchain,
        }
    )
    return environment


def verify(root: Path, *, rust_toolchain: str, run_tests: bool = True) -> dict[str, object]:
    root = root.resolve()
    environment = _offline_environment(rust_toolchain)
    require_clean_checkout(root)
    source = git_identity(root)
    revision = source["commit"]
    policy = load_policy(root, revision=revision)
    validate_repository_policy(root, policy, revision=revision)
    with verified_toolchain(
        root,
        rust_toolchain,
        environment,
        revision=revision,
    ) as toolchain:
        violations = scan_immutable_head(root, revision=revision)
        if violations:
            raise VerificationError(
                f"public tree gate failed with {len(violations)} violation(s)"
            )
        if run_tests:
            run_immutable_tests(
                root,
                revision=revision,
                environment=environment,
            )
        epoch = git_commit_epoch(root, revision=revision)
        with tempfile.TemporaryDirectory(prefix="faultloom-verified-") as raw_output:
            output = Path(raw_output)
            manifest = build_reproducibly(
                root,
                output,
                epoch,
                revision=revision,
                toolchain=toolchain,
            )
            verify_checksums(output)
            verify_source_archive(output)
            verify_wheels(output)
            verify_metadata(
                output,
                root,
                epoch,
                revision=revision,
                toolchain=toolchain,
            )
    require_clean_checkout(root)
    if git_identity(root)["commit"] != revision:
        raise VerificationError("HEAD changed during clean-checkout verification")
    return {
        "ok": True,
        "source": source,
        "source_date_epoch": epoch,
        "artifacts": manifest,
        "network": NETWORK_EXECUTION,
        "toolchain_verification": {
            "rust": "staged_rustc_cargo_closure_digest_probe_and_build_verified",
            "cargo_vendor": (
                "not_used"
                if policy.cargo_vendor is None
                else "lock_vendor_bijection_and_file_checksums_verified"
            ),
            "source_revision": revision,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--rust-toolchain",
        default=os.environ.get("FAULTLOOM_RUST_TOOLCHAIN", "stable"),
        help="preinstalled rustup alias to inspect; reported version must still match the pin",
    )
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    try:
        receipt = verify(
            args.root, rust_toolchain=args.rust_toolchain, run_tests=not args.skip_tests
        )
    except (BuildPolicyError, VerificationError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
