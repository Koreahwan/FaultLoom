from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.reproducible_build import (
    BuildPolicyError,
    build_once,
    build_reproducibly,
    discover_projects,
    load_policy,
    parse_release_lock,
    validate_project_dependencies,
    validate_repository_policy,
)


EPOCH = 1_700_000_000
ACTION_SHA = "1" * 40


def write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def run_git(root: Path, *arguments: str, environment: dict[str, str] | None = None) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


def make_repository(root: Path, *, dependency: str | None = None) -> None:
    source_root = Path(__file__).resolve().parents[1]
    write(root / ".python-version", "3.12.3\n")
    write(
        root / "rust-toolchain.toml",
        '[toolchain]\nchannel = "1.96.1"\nprofile = "minimal"\n'
        'components = ["clippy", "rustfmt"]\n',
    )
    write(
        root / "build-policy.toml",
        """schema_version = 1
python_version = "3.12.3"
rust_version = "1.96.1"
release_lock = "requirements-release.lock"
package_roots = ["packages", "packs"]
license_files = ["LICENSE", "NOTICE"]
release_enabled = false

[hooks]
sbom = "tools/build_metadata_hook.py"
provenance = "tools/build_metadata_hook.py"
""",
    )
    write(root / "requirements-release.lock", "# intentionally empty\n")
    write(root / "LICENSE", "synthetic Apache-2.0 license fixture\n")
    write(root / "NOTICE", "synthetic notice fixture\n")
    write(
        root / ".github/workflows/ci.yml",
        f"name: test\njobs:\n  test:\n    steps:\n      - uses: example/action@{ACTION_SHA}\n",
    )
    (root / "tools").mkdir(parents=True)
    shutil.copyfile(
        source_root / "tools/build_metadata_hook.py", root / "tools/build_metadata_hook.py"
    )
    dependencies = f'  "{dependency}",\n' if dependency else ""
    write(
        root / "packages/demo/pyproject.toml",
        f"""[build-system]
requires = ["setuptools==81.0.0", "wheel==0.42.0"]
build-backend = "setuptools.build_meta"

[project]
name = "faultloom-demo"
version = "0.1.0"
description = "Synthetic package"
readme = "README.md"
requires-python = ">=3.12,<3.13"
dependencies = [
{dependencies}]
""",
    )
    write(root / "packages/demo/README.md", "# Demo\n")
    write(root / "packages/demo/src/faultloom_demo/__init__.py", 'VALUE = "fixture"\n')
    run_git(root, "init", "-q")
    run_git(root, "config", "user.email", "fixture@faultloom.invalid")
    run_git(root, "config", "user.name", "FaultLoom fixture")
    run_git(root, "add", ".")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": f"@{EPOCH} +0000",
            "GIT_COMMITTER_DATE": f"@{EPOCH} +0000",
        }
    )
    run_git(root, "commit", "-q", "-m", "Synthetic build fixture", environment=environment)


class ReproducibleBuildTests(unittest.TestCase):
    def test_synthetic_package_build_is_byte_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            first = base / "first"
            second = base / "second"
            first_manifest = build_once(root, first, EPOCH)
            second_manifest = build_once(root, second, EPOCH)
            self.assertEqual(first_manifest, second_manifest)
            first_files = {
                path.name: path.read_bytes() for path in first.iterdir() if path.is_file()
            }
            second_files = {
                path.name: path.read_bytes() for path in second.iterdir() if path.is_file()
            }
            self.assertEqual(first_files, second_files)
            wheel_path = next(first.glob("*.whl"))
            with zipfile.ZipFile(wheel_path) as wheel:
                names = set(wheel.namelist())
                self.assertIn("faultloom_demo/__init__.py", names)
                self.assertIn(
                    "faultloom_demo-0.1.0.dist-info/licenses/LICENSE", names
                )
                self.assertIn("faultloom_demo-0.1.0.dist-info/licenses/NOTICE", names)
                timestamps = {item.date_time for item in wheel.infolist()}
                self.assertEqual(len(timestamps), 1)
            provenance = json.loads(
                (first / "faultloom-core.provenance.intoto.json").read_text(encoding="utf-8")
            )
            self.assertEqual(provenance["_type"], "https://in-toto.io/Statement/v1")
            self.assertIn("SHA256SUMS", first_manifest)

    def test_reproducible_driver_copies_only_identical_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            manifest = build_reproducibly(root, base / "output", EPOCH)
            self.assertEqual(set(manifest), {path.name for path in (base / "output").iterdir()})

    def test_external_dependency_requires_matching_hashed_lock(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root, dependency="example-dependency==2.4.1")
            policy = load_policy(root)
            projects = discover_projects(root, policy)
            with self.assertRaisesRegex(BuildPolicyError, "absent from release lock"):
                validate_project_dependencies(projects, parse_release_lock(policy.release_lock))
            digest = "a" * 64
            write(
                root / "requirements-release.lock",
                f"example-dependency==2.4.1 --hash=sha256:{digest}\n",
            )
            lock = parse_release_lock(policy.release_lock)
            validate_project_dependencies(projects, lock)

    def test_unhashed_or_non_exact_release_lock_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "requirements-release.lock"
            write(lock, "example-dependency==2.4.1\n")
            with self.assertRaisesRegex(BuildPolicyError, "exact and sha256-hashed"):
                parse_release_lock(lock)
            write(lock, "example-dependency>=2.4.1 --hash=sha256:" + "b" * 64 + "\n")
            with self.assertRaisesRegex(BuildPolicyError, "exact and sha256-hashed"):
                parse_release_lock(lock)

    def test_release_mode_is_disabled_before_artifact_creation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            output = base / "release"
            with self.assertRaisesRegex(BuildPolicyError, "release mode is disabled"):
                build_once(root, output, EPOCH, release=True)
            self.assertFalse(output.exists())

    def test_missing_metadata_hook_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            (root / "tools/build_metadata_hook.py").unlink()
            with self.assertRaisesRegex(BuildPolicyError, "required regular file is missing"):
                validate_repository_policy(root, load_policy(root))

    def test_ci_action_reference_must_be_full_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            workflow = root / ".github/workflows/ci.yml"
            write(
                workflow,
                "name: test\njobs:\n  test:\n    steps:\n      - uses: example/action@"
                + "v"
                + "4\n",
            )
            with self.assertRaisesRegex(BuildPolicyError, "full lowercase commit SHA"):
                validate_repository_policy(root, load_policy(root))


if __name__ == "__main__":
    unittest.main()
