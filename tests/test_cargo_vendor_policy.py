from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from tools.reproducible_build import BuildPolicyError, load_policy, validate_repository_policy


ROOT = Path(__file__).resolve().parents[1]
BASE64_CHECKSUM = "72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6"


def _run_git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _commit(root: Path, message: str) -> None:
    _run_git(root, "add", "-A")
    _run_git(root, "commit", "-qm", message)


def _replace_vendor_file(root: Path, relative: str, content: bytes) -> None:
    crate = root / "vendor/base64-0.22.1"
    target = crate / relative
    old_digest = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    checksum_path = crate / ".cargo-checksum.json"
    checksum = checksum_path.read_text(encoding="utf-8")
    if old_digest is None:
        checksum = checksum.replace('"files":{', f'"files":{{"{relative}":"{digest}",', 1)
    else:
        checksum = checksum.replace(f'"{relative}":"{old_digest}"', f'"{relative}":"{digest}"')
    checksum_path.write_text(checksum, encoding="utf-8")


def _repository(root: Path) -> None:
    for relative in (
        ".python-version",
        "rust-toolchain.toml",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "ETHICAL_USE.md",
        "requirements-release.lock",
        "requirements-release.graph.json",
        "tools/__init__.py",
        "tools/build_metadata_hook.py",
        "tools/cargo_sbom.py",
        "tools/cargo_vendor_graph.py",
        "tools/cargo_vendor_policy.py",
        ".github/workflows/ci.yml",
    ):
        source = ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    _write(root / "packages/demo/pyproject.toml", """[build-system]
requires = ["setuptools==81.0.0", "wheel==0.42.0"]
build-backend = "setuptools.build_meta"

[project]
name = "faultloom-demo"
version = "0.1.0"
description = "fixture"
readme = "README.md"
license = "Apache-2.0"
license-files = ["LICENSE", "NOTICE"]
requires-python = ">=3.12,<3.13"
dependencies = []
""")
    for name in ("README.md", "LICENSE", "NOTICE"):
        _write(root / "packages/demo" / name, f"fixture {name}\n")
    _write(root / "packages/demo/src/faultloom_demo/__init__.py", "VALUE = 1\n")
    _write(root / "Cargo.toml", (ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    _write(
        root / "gateway/Cargo.toml",
        (ROOT / "gateway/Cargo.toml")
        .read_text(encoding="utf-8")
        .replace(
            '[dependencies]\nbase64 = { version = "=0.22.1", default-features = false }\n'
            'ed25519-dalek = { version = "=2.2.0", default-features = false }\n'
            'serde = { version = "=1.0.228", default-features = false, '
            'features = ["derive", "std"] }\n'
            'serde_json = { version = "=1.0.150", default-features = false, features = ["std"] }',
            '[dependencies]\nbase64 = { version = "=0.22.1", default-features = false }',
        ),
    )
    _write(root / "gateway/src/lib.rs", "#![forbid(unsafe_code)]\npub fn status() {}\n")
    _write(root / "gateway/src/main.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")
    _write(
        root / "Cargo.lock",
        f'''version = 4

[[package]]
name = "base64"
version = "0.22.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{BASE64_CHECKSUM}"

[[package]]
name = "faultloom-gateway"
version = "0.1.0"
dependencies = ["base64"]
''',
    )
    _write(root / ".cargo/config.toml", (ROOT / ".cargo/config.toml").read_text(encoding="utf-8"))
    shutil.copytree(ROOT / "vendor/base64-0.22.1", root / "vendor/base64-0.22.1")
    policy = (ROOT / "build-policy.toml").read_text(encoding="utf-8")
    before_vendor, after_vendor = policy.split("[cargo_vendor]", 1)
    _, hooks = after_vendor.split("[hooks]", 1)
    policy = before_vendor + """[cargo_vendor]

config = ".cargo/config.toml"
directory = "vendor"
registry_source = "registry+https://github.com/rust-lang/crates.io-index"
maximum_rust_version = "1.96.1"
direct_dependencies = [
  { name = "base64", version = "0.22.1", default_features = false, features = [] },
]
approved_build_scripts = []
approved_licenses = ["MIT OR Apache-2.0"]
\n[hooks]""" + hooks
    _write(root / "build-policy.toml", policy)
    _run_git(root, "init", "-q")
    _run_git(root, "config", "user.email", "fixture@faultloom.invalid")
    _run_git(root, "config", "user.name", "FaultLoom fixture")
    _run_git(root, "add", ".")
    _run_git(root, "commit", "-qm", "Synthetic vendored Gateway")


def test_checksum_bound_vendor_graph_is_admitted() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)

        validate_repository_policy(root, load_policy(root))


def test_tampered_missing_and_extra_vendor_files_are_rejected() -> None:
    variants = ("tampered", "missing", "extra")
    for variant in variants:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _repository(root)
            crate = root / "vendor/base64-0.22.1"
            if variant == "tampered":
                (crate / "src/lib.rs").write_bytes(b"tampered\n")
            elif variant == "missing":
                (crate / "README.md").unlink()
            else:
                _write(crate / "unlisted.txt", "extra\n")
            _commit(root, f"Inject {variant} vendor file")

            with pytest.raises(BuildPolicyError, match="checksum"):
                validate_repository_policy(root, load_policy(root))


def test_lock_checksum_and_cargo_config_drift_are_rejected() -> None:
    variants = ("lock", "config")
    for variant in variants:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _repository(root)
            if variant == "lock":
                lock = (root / "Cargo.lock").read_text(encoding="utf-8")
                _write(root / "Cargo.lock", lock.replace(BASE64_CHECKSUM, "0" * 64))
            else:
                _write(root / ".cargo/config.toml", '[source.crates-io]\nreplace-with = "other"\n')
            _commit(root, f"Inject {variant} drift")

            with pytest.raises(BuildPolicyError, match="checksum|configuration"):
                validate_repository_policy(root, load_policy(root))


def test_first_party_and_unapproved_vendor_build_scripts_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)
        _write(root / "gateway/build.rs", "fn main() {}\n")
        _commit(root, "Inject first-party build script")

        with pytest.raises(BuildPolicyError, match="build scripts"):
            validate_repository_policy(root, load_policy(root))

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)
        _replace_vendor_file(root, "build.rs", b"fn main() {}\n")
        _commit(root, "Inject checksum-reconciled unapproved vendor build script")

        with pytest.raises(BuildPolicyError, match="build script"):
            validate_repository_policy(root, load_policy(root))


def test_checksum_bound_vendor_build_script_is_admitted_and_recorded() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)
        _replace_vendor_file(root, "build.rs", b"fn main() {}\n")
        policy = (root / "build-policy.toml").read_text(encoding="utf-8")
        _write(
            root / "build-policy.toml",
            policy.replace(
                "approved_build_scripts = []",
                'approved_build_scripts = ["base64=0.22.1"]',
            ),
        )
        _commit(root, "Add checksum-bound vendor build script")

        validate_repository_policy(root, load_policy(root))


def test_missing_approved_vendor_build_script_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)
        policy = (root / "build-policy.toml").read_text(encoding="utf-8")
        _write(
            root / "build-policy.toml",
            policy.replace(
                "approved_build_scripts = []",
                'approved_build_scripts = ["base64=0.22.1"]',
            ),
        )
        _commit(root, "Approve a missing vendor build script")

        with pytest.raises(BuildPolicyError, match="build script"):
            validate_repository_policy(root, load_policy(root))


def test_direct_dependency_features_and_sources_are_exact() -> None:
    variants = (
        (
            'default_features = false, features = []',
            'default_features = true, features = []',
        ),
        (
            'default_features = false, features = []',
            'default_features = false, features = ["alloc"]',
        ),
        (
            'default-features = false }',
            'default-features = false, path = "../base64" }',
        ),
        (
            'default-features = false }',
            'default-features = false, git = "https://example.invalid/base64" }',
        ),
    )
    for old, new in variants:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _repository(root)
            policy_target = root / "build-policy.toml"
            manifest_target = root / "gateway/Cargo.toml"
            target = policy_target if "default_features" in old else manifest_target
            _write(target, target.read_text(encoding="utf-8").replace(old, new, 1))
            _commit(root, "Inject direct dependency configuration drift")

            with pytest.raises(BuildPolicyError, match="dependency|source|option"):
                validate_repository_policy(root, load_policy(root))


def test_unapproved_license_and_excessive_msrv_are_rejected_after_hash_reconciliation() -> None:
    variants = ("license", "msrv")
    for variant in variants:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _repository(root)
            manifest = root / "vendor/base64-0.22.1/Cargo.toml"
            content = manifest.read_text(encoding="utf-8")
            if variant == "license":
                content = content.replace(
                    'license = "MIT OR Apache-2.0"',
                    'license = "GPL-3.0-only"',
                )
            else:
                content = content.replace('rust-version = "1.48.0"', 'rust-version = "9.0.0"')
            _replace_vendor_file(root, "Cargo.toml", content.encode("utf-8"))
            _commit(root, f"Inject {variant} policy violation")

            with pytest.raises(BuildPolicyError, match="license|MSRV"):
                validate_repository_policy(root, load_policy(root))


def test_missing_retained_license_text_is_rejected_after_hash_reconciliation() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)
        crate = root / "vendor/base64-0.22.1"
        checksum_path = crate / ".cargo-checksum.json"
        checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
        for name in ("LICENSE-APACHE", "LICENSE-MIT"):
            (crate / name).unlink()
            del checksum["files"][name]
        checksum_path.write_text(
            json.dumps(checksum, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        _commit(root, "Remove checksum-reconciled vendor license texts")

        with pytest.raises(BuildPolicyError, match="license text"):
            validate_repository_policy(root, load_policy(root))


def test_symlink_and_non_registry_lock_source_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)
        (root / "vendor/base64-0.22.1/link").symlink_to("README.md")
        _commit(root, "Add vendor symlink")

        with pytest.raises(BuildPolicyError, match="tracked symlink|unsafe Cargo vendor entry"):
            validate_repository_policy(root, load_policy(root))

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        _repository(root)
        lock = (root / "Cargo.lock").read_text(encoding="utf-8")
        _write(
            root / "Cargo.lock",
            lock.replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                "git+https://example.invalid/base64#deadbeef",
                1,
            ),
        )
        _commit(root, "Replace registry package with Git source")

        with pytest.raises(BuildPolicyError, match="source"):
            validate_repository_policy(root, load_policy(root))


def test_actual_graph_resolves_with_empty_cargo_home_frozen_locked_and_offline(
    tmp_path: Path,
) -> None:
    cargo_home = tmp_path / "cargo-home"
    cargo_home.mkdir()
    environment = os.environ.copy()
    environment.update(
        {
            "CARGO_HOME": str(cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "HOME": str(tmp_path / "home"),
        }
    )

    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(ROOT / "Cargo.toml"),
            "--format-version",
            "1",
            "--frozen",
            "--locked",
            "--offline",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    metadata = json.loads(result.stdout)
    assert len(metadata["packages"]) == 32
    assert metadata["resolve"] is not None
