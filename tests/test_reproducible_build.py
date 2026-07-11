from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from tools.check_public_tree import scan
from tools.reproducible_build import (
    BuildPolicyError,
    build_once,
    build_reproducibly,
    build_source_archive,
    canonical_ci_workflow,
    discover_projects,
    git_commit_epoch,
    git_identity,
    load_policy,
    parse_release_dependency_graph,
    parse_release_lock,
    require_clean_checkout,
    validate_project_dependencies,
    validate_repository_policy,
)
from tools.verify_clean_checkout import (
    VerificationError,
    run_immutable_tests,
    rustc_closure_sha256,
    scan_immutable_head,
    verify_metadata,
    verify_source_archive,
    verify_toolchains,
    verify_wheels,
)


EPOCH = 1_700_000_000
ACTION_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


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


def commit_all(root: Path, message: str = "Update synthetic fixture") -> None:
    run_git(root, "add", ".")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": f"@{EPOCH} +0000",
            "GIT_COMMITTER_DATE": f"@{EPOCH} +0000",
        }
    )
    run_git(root, "commit", "-q", "-m", message, environment=environment)


def pin_synthetic_rustc(root: Path, rustc: Path) -> None:
    toolchain = rustc.parent.parent
    write(toolchain / "lib/librustc_driver-fixture.so", "synthetic driver\n")
    write(toolchain / "lib/libLLVM-fixture.so", "synthetic LLVM\n")
    write(
        toolchain
        / "lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-fixture.rlib",
        "synthetic sysroot\n",
    )
    policy = root / "build-policy.toml"
    digest = hashlib.sha256(rustc.read_bytes()).hexdigest()
    closure_digest = rustc_closure_sha256(rustc, "x86_64-unknown-linux-gnu")
    contents = policy.read_text(encoding="utf-8")
    contents = contents.replace(
        f'rustc_sha256 = "{"0" * 64}"', f'rustc_sha256 = "{digest}"'
    )
    contents = contents.replace(
        f'rustc_closure_sha256 = "{"0" * 64}"',
        f'rustc_closure_sha256 = "{closure_digest}"',
    )
    write(
        policy,
        contents,
    )
    commit_all(root, "Pin synthetic rustc digest")


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
python_runtime_verification = "version_only_unverified"
rust_version = "1.96.1"
rustc_host = "x86_64-unknown-linux-gnu"
rustc_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
rustc_closure_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
release_lock = "requirements-release.lock"
release_dependency_graph = "requirements-release.graph.json"
package_roots = ["packages", "packs"]
license_files = ["LICENSE", "NOTICE"]
release_enabled = false
ci_external_trust_anchor = false

[hooks]
sbom = "tools/build_metadata_hook.py"
provenance = "tools/build_metadata_hook.py"
""",
    )
    write(root / "requirements-release.lock", "# intentionally empty\n")
    write(
        root / "requirements-release.graph.json",
        '{\n  "packages": {},\n  "schema_version": 1\n}\n',
    )
    write(root / "LICENSE", "synthetic Apache-2.0 license fixture\n")
    write(root / "NOTICE", "synthetic notice fixture\n")
    write(root / "SECURITY.md", "synthetic security policy fixture\n")
    write(root / "ETHICAL_USE.md", "synthetic ethical-use policy fixture\n")
    workflow = root / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_bytes(canonical_ci_workflow("1.96.1"))
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
license = "Apache-2.0"
license-files = ["LICENSE", "NOTICE"]
requires-python = ">=3.12,<3.13"
dependencies = [
{dependencies}]
""",
    )
    write(root / "packages/demo/README.md", "# Demo\n")
    write(root / "packages/demo/LICENSE", "project license\n")
    write(root / "packages/demo/NOTICE", "project notice\n")
    write(root / "packages/demo/src/faultloom_demo/__init__.py", 'VALUE = "fixture"\n')
    run_git(root, "init", "-q")
    run_git(root, "config", "user.email", "fixture@faultloom.invalid")
    run_git(root, "config", "user.name", "FaultLoom fixture")
    commit_all(root, "Synthetic build fixture")


def add_gateway_fixture(root: Path, *, add_policy: bool = True) -> None:
    write(
        root / "Cargo.toml",
        """[workspace]
members = ["gateway"]
resolver = "3"

[profile.release]
codegen-units = 1
debug = 0
incremental = false
lto = "fat"
opt-level = 3
panic = "abort"
strip = "symbols"
""",
    )
    write(
        root / "Cargo.lock",
        """version = 4

[[package]]
name = "faultloom-gateway"
version = "0.1.0"
""",
    )
    write(
        root / "gateway/Cargo.toml",
        """[package]
name = "faultloom-gateway"
version = "0.1.0"
edition = "2024"
rust-version = "1.96.1"
description = "Fail-closed target egress kernel for FaultLoom"
license = "Apache-2.0"
publish = false

[lib]
name = "faultloom_gateway"
path = "src/lib.rs"

[[bin]]
name = "faultloom-gateway"
path = "src/main.rs"

[dependencies]

[lints.rust]
unsafe_code = "forbid"
""",
    )
    write(root / "gateway/src/lib.rs", "#![forbid(unsafe_code)]\npub fn status() {}\n")
    write(root / "gateway/src/main.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")
    if add_policy:
        policy = root / "build-policy.toml"
        contents = policy.read_text(encoding="utf-8")
        contents += """

[gateway]
workspace_manifest = "Cargo.toml"
manifest = "gateway/Cargo.toml"
lock = "Cargo.lock"
package = "faultloom-gateway"
binary = "faultloom-gateway"
version = "0.1.0"
target = "x86_64-unknown-linux-gnu"
cargo_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
"""
        write(policy, contents)
    commit_all(root, "Add synthetic Gateway fixture")


class ReproducibleBuildTests(unittest.TestCase):
    def test_tracked_cargo_requires_explicit_gateway_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            add_gateway_fixture(root, add_policy=False)
            with self.assertRaisesRegex(BuildPolicyError, "explicit.*gateway"):
                validate_repository_policy(root, load_policy(root))

    def test_gateway_cannot_be_silently_omitted_without_staged_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            add_gateway_fixture(root)
            with self.assertRaisesRegex(BuildPolicyError, "staged Rust and Cargo"):
                build_once(root, root / "output", EPOCH)

    def test_gateway_manifest_lock_and_build_controls_fail_closed(self) -> None:
        variants = (
            (
                "dependency",
                "gateway/Cargo.toml",
                lambda value: value.replace(
                    "[dependencies]\n", '[dependencies]\nserde = "1"\n'
                ),
                "unsupported field or dependency",
            ),
            (
                "lock dependency",
                "Cargo.lock",
                lambda value: value + 'dependencies = ["serde"]\n',
                "exactly one source-less package",
            ),
            (
                "build script",
                "gateway/build.rs",
                lambda _value: "fn main() {}\n",
                "build scripts.*forbidden",
            ),
            (
                "Cargo config",
                ".cargo/config.toml",
                lambda _value: "[build]\nrustc-wrapper = \"marker\"\n",
                "Cargo configuration.*forbidden",
            ),
        )
        for label, relative, mutate, message in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                make_repository(root)
                add_gateway_fixture(root)
                path = root / relative
                current = path.read_text(encoding="utf-8") if path.exists() else ""
                write(path, mutate(current))
                commit_all(root, f"Inject {label}")
                with self.assertRaisesRegex(BuildPolicyError, message):
                    validate_repository_policy(root, load_policy(root))

    def test_exact_project_license_files_are_packaged_from_the_project(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)

            output = root / "output"
            build_once(root, output, EPOCH)
            with zipfile.ZipFile(next(output.glob("*.whl"))) as wheel:
                metadata = wheel.read(
                    "faultloom_demo-0.1.0.dist-info/METADATA"
                ).decode("utf-8")
                self.assertIn("Metadata-Version: 2.4\n", metadata)
                self.assertIn("License-Expression: Apache-2.0\n", metadata)
                self.assertEqual(metadata.count("License-File: LICENSE\n"), 1)
                self.assertEqual(metadata.count("License-File: NOTICE\n"), 1)
                self.assertNotIn("\nLicense: Apache-2.0\n", metadata)
                self.assertEqual(
                    wheel.read("faultloom_demo-0.1.0.dist-info/licenses/LICENSE"),
                    b"project license\n",
                )
                self.assertEqual(
                    wheel.read("faultloom_demo-0.1.0.dist-info/licenses/NOTICE"),
                    b"project notice\n",
                )

    def test_project_license_files_fail_closed(self) -> None:
        variants = (
            (None, "must be a non-empty string list"),
            ('license-files = ["../LICENSE", "NOTICE"]', "escapes the repository"),
            ('license-files = ["/LICENSE", "NOTICE"]', "escapes the repository"),
            ('license-files = ["//LICENSE", "NOTICE"]', "escapes the repository"),
            ('license-files = ["./LICENSE", "NOTICE"]', "not a canonical repository path"),
            ('license-files = ["LICENSE/", "NOTICE"]', "not a canonical repository path"),
            ('license-files = ["LICENSE", "./NOTICE"]', "not a canonical repository path"),
            ('license-files = ["LICEN*", "NOTICE"]', "must use exact paths"),
            ('license-files = []', "must be a non-empty string list"),
            (
                'license-files = ["legal/LICENSE", "NOTICE"]',
                "must name direct project files",
            ),
            ('license-files = ["LICENSE"]', "must contain LICENSE and NOTICE"),
            ('license-files = ["license", "NOTICE"]', "may contain only LICENSE and NOTICE"),
            ('license-files = ["LICENSE", "notice"]', "may contain only LICENSE and NOTICE"),
            ('license-files = ["LICENSE", "LICENSE", "NOTICE"]', "duplicate name"),
            ('license-files = ["LICENSE", "MISSING"]', "may contain only LICENSE and NOTICE"),
        )
        for declaration, error in variants:
            with self.subTest(declaration=declaration):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    project = root / "packages/demo/pyproject.toml"
                    contents = project.read_text(encoding="utf-8")
                    if declaration is None:
                        contents = contents.replace(
                            'license-files = ["LICENSE", "NOTICE"]\n', ""
                        )
                    else:
                        contents = contents.replace(
                            'license-files = ["LICENSE", "NOTICE"]', declaration
                        )
                    write(project, contents)
                    write(root / "packages/demo/LICENSE", "project license\n")
                    write(root / "packages/demo/NOTICE", "project notice\n")
                    write(root / "packages/demo/license", "duplicate project license\n")
                    commit_all(root, "Declare invalid project license files")
                    with self.assertRaisesRegex(BuildPolicyError, error):
                        discover_projects(root, load_policy(root))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            (root / "packages/demo/NOTICE").unlink()
            commit_all(root, "Remove a declared project license file")
            with self.assertRaisesRegex(BuildPolicyError, "missing or unsafe"):
                discover_projects(root, load_policy(root))

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
            lock = parse_release_lock(policy.release_lock)
            graph = parse_release_dependency_graph(policy.release_dependency_graph, lock)
            with self.assertRaisesRegex(BuildPolicyError, "absent from release lock"):
                validate_project_dependencies(projects, lock, graph)
            digest = "a" * 64
            write(
                root / "requirements-release.lock",
                f"example-dependency==2.4.1 --hash=sha256:{digest}\n",
            )
            write(
                root / "requirements-release.graph.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "packages": {"example-dependency==2.4.1": []},
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            lock = parse_release_lock(policy.release_lock)
            graph = parse_release_dependency_graph(policy.release_dependency_graph, lock)
            validate_project_dependencies(projects, lock, graph)

    def test_unhashed_or_non_exact_release_lock_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "requirements-release.lock"
            write(lock, "example-dependency==2.4.1\n")
            with self.assertRaisesRegex(BuildPolicyError, "exact and sha256-hashed"):
                parse_release_lock(lock)

    def test_numeric_two_component_release_version_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "requirements-release.lock"
            digest = "b" * 64
            write(lock, f"pycparser==3.0 --hash=sha256:{digest}\n")
            self.assertEqual(
                parse_release_lock(lock),
                {"pycparser": ("3.0", (digest,))},
            )
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

    def test_release_enabled_policy_still_requires_enforced_network_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            policy_path = root / "build-policy.toml"
            write(
                policy_path,
                policy_path.read_text(encoding="utf-8").replace(
                    "release_enabled = false", "release_enabled = true"
                ),
            )
            commit_all(root, "Enable synthetic release policy")
            output = base / "release"
            with self.assertRaisesRegex(BuildPolicyError, "enforced network isolation"):
                build_once(root, output, EPOCH, release=True)
            self.assertFalse(output.exists())

    def test_missing_metadata_hook_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            (root / "tools/build_metadata_hook.py").unlink()
            commit_all(root, "Remove required metadata hook")
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
                + "4\n      - run: python3 tools/verify_clean_checkout.py\n",
            )
            commit_all(root, "Add mutable CI action")
            with self.assertRaisesRegex(BuildPolicyError, "full lowercase commit SHA"):
                validate_repository_policy(root, load_policy(root))

    def test_local_action_path_cannot_masquerade_as_a_commit_pin(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    steps:
      - uses: ./.github/actions/evil@{ACTION_SHA}
      - run: python3 tools/verify_clean_checkout.py
""",
            )
            commit_all(root, "Add a local action with a SHA-looking suffix")
            with self.assertRaisesRegex(BuildPolicyError, "full lowercase commit SHA"):
                validate_repository_policy(root, load_policy(root))

    def test_unreviewed_action_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    steps:
      - uses: attacker/action@{ACTION_SHA}
      - run: python3 tools/verify_clean_checkout.py
""",
            )
            commit_all(root, "Add an unreviewed action digest")
            with self.assertRaisesRegex(BuildPolicyError, "reviewed digest allowlist"):
                validate_repository_policy(root, load_policy(root))

    def test_ci_requires_clean_checkout_gate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                "name: test\njobs:\n  test:\n    steps:\n"
                f"      - uses: actions/checkout@{ACTION_SHA}\n",
            )
            commit_all(root, "Remove clean checkout gate")
            with self.assertRaisesRegex(BuildPolicyError, "clean-checkout gate"):
                validate_repository_policy(root, load_policy(root))

    def test_ci_gate_must_be_a_job_step(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
run: python3 tools/verify_clean_checkout.py
""",
            )
            commit_all(root, "Move gate outside job steps")
            with self.assertRaisesRegex(BuildPolicyError, "clean-checkout gate"):
                validate_repository_policy(root, load_policy(root))

    def test_ci_gate_cannot_be_conditional_or_non_blocking(self) -> None:
        variants = (
            "        if: false\n",
            "        continue-on-error: true\n",
            "        shell: bash\n",
        )
        for addition in variants:
            with self.subTest(addition=addition.strip()):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    write(
                        root / ".github/workflows/ci.yml",
                        f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - name: Gate
{addition}        run: python3 tools/verify_clean_checkout.py
""",
                    )
                    commit_all(root, "Make synthetic gate non-enforcing")
                    with self.assertRaisesRegex(BuildPolicyError, "clean-checkout gate"):
                        validate_repository_policy(root, load_policy(root))

    def test_ci_gate_job_cannot_be_conditional(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    if: false
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - run: python3 tools/verify_clean_checkout.py
""",
            )
            commit_all(root, "Make synthetic gate job conditional")
            with self.assertRaisesRegex(BuildPolicyError, "clean-checkout gate"):
                validate_repository_policy(root, load_policy(root))

    def test_quoted_yaml_action_keys_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            workflow = root / ".github/workflows/ci.yml"
            write(
                workflow,
                """name: test
jobs:
  test:
    steps:
      - "uses": "example/action@v4"
      - 'run': 'python3 tools/verify_clean_checkout.py'
""",
            )
            commit_all(root, "Add quoted mutable CI action")
            with self.assertRaisesRegex(BuildPolicyError, "full lowercase commit SHA"):
                validate_repository_policy(root, load_policy(root))

    def test_ci_gate_requires_the_canonical_action_and_execution_contract(self) -> None:
        variants = (
            (
                "          repository: \"${{ github.repository }}\"\n",
                "          repository: attacker/public-repo\n",
            ),
            (
                "          path: .\n",
                "          path: decoy\n",
            ),
            (
                "        run: python3 tools/verify_clean_checkout.py\n",
                "        working-directory: decoy\n"
                "        run: python3 tools/verify_clean_checkout.py\n",
            ),
            (
                "        run: python3 tools/verify_clean_checkout.py\n",
                "        run: python3 tools/verify_clean_checkout.py\n"
                "          || true\n",
            ),
            (
                "          FAULTLOOM_RUST_TOOLCHAIN: \"1.96.1\"\n",
                "          BASH_FUNC_python3%%: hostile\n",
            ),
            (
                "          FAULTLOOM_RUST_TOOLCHAIN: \"1.96.1\"\n",
                "          SHELLOPTS: xtrace\n"
                "          PS4: hostile\n",
            ),
        )
        for old, new in variants:
            with self.subTest(replacement=new.strip()):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    workflow = root / ".github/workflows/ci.yml"
                    contents = workflow.read_text(encoding="utf-8")
                    self.assertIn(old, contents)
                    write(workflow, contents.replace(old, new, 1))
                    commit_all(root, "Break the canonical CI execution contract")
                    with self.assertRaises(BuildPolicyError):
                        validate_repository_policy(root, load_policy(root))

    def test_toolchain_policy_cannot_inject_ci_or_toolchain_paths(self) -> None:
        variants = (
            (
                'rust_version = "1.96.1"',
                'rust_version = "1.96.1\\nmalicious"',
                "exact numeric release",
            ),
            (
                'rustc_host = "x86_64-unknown-linux-gnu"',
                'rustc_host = "../../host"',
                "canonical Rust target triple",
            ),
            (
                'python_runtime_verification = "version_only_unverified"',
                'python_runtime_verification = "content_verified"',
                "must remain version_only_unverified",
            ),
            (
                "ci_external_trust_anchor = false",
                "ci_external_trust_anchor = true",
                "cannot be asserted by the repository itself",
            ),
        )
        for old, new, error in variants:
            with self.subTest(policy_value=new):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    policy = root / "build-policy.toml"
                    contents = policy.read_text(encoding="utf-8")
                    self.assertIn(old, contents)
                    write(policy, contents.replace(old, new, 1))
                    commit_all(root, "Inject an unsafe toolchain policy value")
                    with self.assertRaisesRegex(BuildPolicyError, error):
                        load_policy(root)

    def test_license_files_cannot_collide_after_wheel_flattening(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(root / "legal/LICENSE", "second license fixture\n")
            policy = root / "build-policy.toml"
            contents = policy.read_text(encoding="utf-8").replace(
                'license_files = ["LICENSE", "NOTICE"]',
                'license_files = ["LICENSE", "legal/LICENSE", "NOTICE"]',
            )
            write(policy, contents)
            commit_all(root, "Add colliding license basenames")
            with self.assertRaisesRegex(BuildPolicyError, "basename flattening"):
                load_policy(root)

    def test_inline_yaml_action_mapping_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - {{ uses: example/other@v4 }}
      - run: python3 tools/verify_clean_checkout.py
""",
            )
            commit_all(root, "Add inline CI action mapping")
            with self.assertRaisesRegex(BuildPolicyError, "flow collections"):
                validate_repository_policy(root, load_policy(root))

    def test_explicit_yaml_action_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - ? uses
        : example/other@v4
      - run: python3 tools/verify_clean_checkout.py
""",
            )
            commit_all(root, "Add explicit CI action key")
            with self.assertRaisesRegex(BuildPolicyError, "explicit mapping keys"):
                validate_repository_policy(root, load_policy(root))

    def test_yaml_block_scalar_cannot_embed_a_fake_gate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - run: |
          echo this is inert text
          run: python3 tools/verify_clean_checkout.py
""",
            )
            commit_all(root, "Embed a fake gate in a YAML block scalar")
            with self.assertRaisesRegex(BuildPolicyError, "block scalars"):
                validate_repository_policy(root, load_policy(root))

    def test_nested_mapping_text_cannot_satisfy_the_ci_gate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / ".github/workflows/ci.yml",
                f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - name: Decoy
        env:
          run: python3 tools/verify_clean_checkout.py
        run: echo harmless
""",
            )
            commit_all(root, "Nest inert gate text below an environment mapping")
            with self.assertRaisesRegex(BuildPolicyError, "clean-checkout gate"):
                validate_repository_policy(root, load_policy(root))

    def test_mutable_predecessor_or_skipped_dependency_cannot_guard_the_gate(self) -> None:
        variants = (
            f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - run: printf hostile > tools/verify_clean_checkout.py
      - run: python3 tools/verify_clean_checkout.py
""",
            f"""name: test
jobs:
  skipped:
    if: false
    steps:
      - run: echo skipped
  test:
    needs: skipped
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - run: python3 tools/verify_clean_checkout.py
""",
        )
        for workflow in variants:
            with self.subTest(workflow=workflow):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    write(root / ".github/workflows/ci.yml", workflow)
                    commit_all(root, "Make the gate depend on mutable predecessor state")
                    with self.assertRaisesRegex(BuildPolicyError, "clean-checkout gate"):
                        validate_repository_policy(root, load_policy(root))

    def test_ci_gate_rejects_path_poisoning_tags_and_multiline_decoys(self) -> None:
        variants = (
            (
                "        env:\n          PATH: /tmp/hostile\n"
                "        run: python3 tools/verify_clean_checkout.py\n",
                "unsafe execution variable",
            ),
            (
                "        if: !unsafe false\n"
                "        run: python3 tools/verify_clean_checkout.py\n",
                "YAML tags",
            ),
            (
                '        run: "echo harmless\n'
                "          run: python3 tools/verify_clean_checkout.py\n"
                '          "\n',
                "multiline quoted scalars",
            ),
            (
                '        run: echo /tmp/hostile >> "$GITHUB_PATH"\n',
                "mutate later-step environments",
            ),
        )
        for step, error in variants:
            with self.subTest(error=error):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    write(
                        root / ".github/workflows/ci.yml",
                        f"""name: test
jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - name: Gate
{step}""",
                    )
                    commit_all(root, "Add an unsafe CI gate representation")
                    with self.assertRaisesRegex(BuildPolicyError, error):
                        validate_repository_policy(root, load_policy(root))

    def test_yaml_alias_cannot_hide_action_or_gate_control_keys(self) -> None:
        variants = (
            "x-key: &hidden uses\n",
            "x-key: &hidden if\n",
        )
        for declaration in variants:
            with self.subTest(declaration=declaration.strip()):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    write(
                        root / ".github/workflows/ci.yml",
                        f"""name: test
{declaration}jobs:
  test:
    steps:
      - uses: actions/checkout@{ACTION_SHA}
      - *hidden: example/other@v4
        run: python3 tools/verify_clean_checkout.py
""",
                    )
                    commit_all(root, "Hide a CI control key behind a YAML alias")
                    with self.assertRaisesRegex(BuildPolicyError, "aliases and anchors"):
                        validate_repository_policy(root, load_policy(root))

    def test_nested_package_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            write(
                root / "packages/nested/deeper/pyproject.toml",
                (root / "packages/demo/pyproject.toml").read_text(encoding="utf-8"),
            )
            commit_all(root, "Add unsupported nested package")
            with self.assertRaisesRegex(BuildPolicyError, "exactly one directory"):
                discover_projects(root, load_policy(root))

    def test_internal_dependency_version_must_match_project(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            demo = root / "packages/demo/pyproject.toml"
            write(
                demo,
                demo.read_text(encoding="utf-8").replace(
                    "dependencies = [\n]\n",
                    'dependencies = [\n  "faultloom-other==9.9.9",\n]\n',
                ),
            )
            write(
                root / "packages/other/pyproject.toml",
                """[build-system]
requires = ["setuptools==81.0.0", "wheel==0.42.0"]
build-backend = "setuptools.build_meta"

[project]
name = "faultloom-other"
version = "0.2.0"
license = "Apache-2.0"
license-files = ["LICENSE", "NOTICE"]
requires-python = ">=3.12,<3.13"
dependencies = []
""",
            )
            write(root / "packages/other/LICENSE", "project license\n")
            write(root / "packages/other/NOTICE", "project notice\n")
            write(root / "packages/other/src/faultloom_other/__init__.py", "VALUE = 2\n")
            commit_all(root, "Add mismatched internal dependency")
            policy = load_policy(root)
            projects = discover_projects(root, policy)
            lock = parse_release_lock(policy.release_lock)
            graph = parse_release_dependency_graph(policy.release_dependency_graph, lock)
            with self.assertRaisesRegex(BuildPolicyError, "internal dependency version mismatch"):
                validate_project_dependencies(projects, lock, graph)

    def test_internal_build_dependency_version_must_match_project(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            demo = root / "packages/demo/pyproject.toml"
            write(
                demo,
                demo.read_text(encoding="utf-8").replace(
                    'requires = ["setuptools==81.0.0", "wheel==0.42.0"]',
                    'requires = ["faultloom-build-tool==9.9.9"]',
                ),
            )
            write(
                root / "packages/build-tool/pyproject.toml",
                """[build-system]
requires = ["setuptools==81.0.0"]
build-backend = "setuptools.build_meta"

[project]
name = "faultloom-build-tool"
version = "0.2.0"
license = "Apache-2.0"
license-files = ["LICENSE", "NOTICE"]
requires-python = ">=3.12,<3.13"
dependencies = []
""",
            )
            write(root / "packages/build-tool/LICENSE", "project license\n")
            write(root / "packages/build-tool/NOTICE", "project notice\n")
            write(
                root / "packages/build-tool/src/faultloom_build_tool/__init__.py",
                "VALUE = 2\n",
            )
            commit_all(root, "Add mismatched internal build dependency")
            policy = load_policy(root)
            projects = discover_projects(root, policy)
            lock = parse_release_lock(policy.release_lock)
            graph = parse_release_dependency_graph(policy.release_dependency_graph, lock)
            with self.assertRaisesRegex(
                BuildPolicyError, "internal build dependency version mismatch"
            ):
                validate_project_dependencies(projects, lock, graph)

    def test_optional_dependencies_are_rejected_until_graph_semantics_exist(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            project = root / "packages/demo/pyproject.toml"
            write(
                project,
                project.read_text(encoding="utf-8")
                + '\n[project.optional-dependencies]\ntest = ["pytest==9.0.2"]\n',
            )
            commit_all(root, "Add unsupported optional dependency")
            with self.assertRaisesRegex(BuildPolicyError, "optional project dependencies"):
                discover_projects(root, load_policy(root))

    def test_project_headers_cannot_inject_untracked_wheel_dependencies(self) -> None:
        fields = ("description", "requires-python")
        for field in fields:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    project = root / "packages/demo/pyproject.toml"
                    contents = project.read_text(encoding="utf-8")
                    original = (
                        'description = "Synthetic package"'
                        if field == "description"
                        else 'requires-python = ">=3.12,<3.13"'
                    )
                    injected = (
                        f'{field} = """allowed\n'
                        'Requires-Dist: undeclared-dependency==9.9.9"""'
                    )
                    write(project, contents.replace(original, injected))
                    commit_all(root, "Inject a wheel metadata header")
                    with self.assertRaisesRegex(BuildPolicyError, "control character"):
                        discover_projects(root, load_policy(root))

    def test_unicode_metadata_controls_fail_before_full_build(self) -> None:
        escapes = (r"\u0085", r"\u2028", r"\u2029", r"\u202e")
        for escape in escapes:
            with self.subTest(escape=escape):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    project = root / "packages/demo/pyproject.toml"
                    contents = project.read_text(encoding="utf-8").replace(
                        'description = "Synthetic package"',
                        f'description = "safe{escape}Requires-Dist: injected==9.9.9"',
                    )
                    write(project, contents)
                    commit_all(root, "Inject a Unicode metadata control")
                    with self.assertRaisesRegex(BuildPolicyError, "control character"):
                        build_once(root, root / "output", EPOCH)

    def test_project_metadata_must_use_the_supported_packaging_subset(self) -> None:
        variants = (
            ('name = "faultloom-demo"', 'name = "faultloom-demo-"', "project name"),
            ('version = "0.1.0"', 'version = "1..2"', "project version"),
            (
                'requires-python = ">=3.12,<3.13"',
                'requires-python = "definitely-not-a-specifier"',
                "unsupported specifier",
            ),
        )
        for old, new, error in variants:
            with self.subTest(value=new):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    project = root / "packages/demo/pyproject.toml"
                    contents = project.read_text(encoding="utf-8")
                    self.assertIn(old, contents)
                    write(project, contents.replace(old, new, 1))
                    commit_all(root, "Add invalid package metadata")
                    with self.assertRaisesRegex(BuildPolicyError, error):
                        discover_projects(root, load_policy(root))

    def test_project_readme_forms_and_content_types_are_explicit(self) -> None:
        invalid = (
            ('readme = "README.md"', 'readme = "README.txt"', "must be a .md or .rst"),
            ('readme = "README.md"', 'readme = "/README.md"', "escapes the repository"),
            (
                'readme = "README.md"',
                'readme = "./README.md"',
                "not a canonical repository path",
            ),
            (
                'readme = "README.md"',
                'readme = "README.md/"',
                "not a canonical repository path",
            ),
            (
                'readme = "README.md"',
                'readme = "docs/README.md"',
                "must name a direct project file",
            ),
            (
                'readme = "README.md"',
                'readme = "[README].md"',
                "must use an exact path",
            ),
            (
                'readme = "README.md"',
                'readme = {file = "README.md", content-type = "text/markdown"}',
                "table forms are unsupported",
            ),
        )
        for old, new, error in invalid:
            with self.subTest(value=new):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    project = root / "packages/demo/pyproject.toml"
                    contents = project.read_text(encoding="utf-8")
                    write(project, contents.replace(old, new, 1))
                    commit_all(root, "Use an unsupported readme form")
                    with self.assertRaisesRegex(BuildPolicyError, error):
                        discover_projects(root, load_policy(root))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            project = root / "packages/demo/pyproject.toml"
            contents = project.read_text(encoding="utf-8").replace(
                'readme = "README.md"', 'readme = "README.rst"'
            )
            write(project, contents)
            (root / "packages/demo/README.md").unlink()
            write(root / "packages/demo/README.rst", "Demo\n====\n")
            commit_all(root, "Use a reStructuredText readme")
            output = root / "output"
            build_once(root, output, EPOCH)
            with zipfile.ZipFile(next(output.glob("*.whl"))) as wheel:
                metadata_name = next(
                    name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
                )
                metadata = wheel.read(metadata_name).decode("utf-8")
            self.assertIn("Description-Content-Type: text/x-rst\n", metadata)

    def test_unsupported_entry_points_and_conflicting_license_fail_closed(self) -> None:
        additions = (
            ('\n[project.scripts]\nfaultloom-demo = "faultloom_demo:main"\n', "unsupported"),
            (
                '\n[project.entry-points."faultloom.plugins"]\n'
                'demo = "faultloom_demo:plugin"\n',
                "unsupported",
            ),
        )
        for addition, error in additions:
            with self.subTest(addition=addition):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    project = root / "packages/demo/pyproject.toml"
                    write(project, project.read_text(encoding="utf-8") + addition)
                    commit_all(root, "Declare unsupported entry-point metadata")
                    with self.assertRaisesRegex(BuildPolicyError, error):
                        discover_projects(root, load_policy(root))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            project = root / "packages/demo/pyproject.toml"
            contents = project.read_text(encoding="utf-8").replace(
                'license = "Apache-2.0"',
                'license = {text = "Proprietary"}',
            )
            write(project, contents)
            commit_all(root, "Contradict the repository license")
            with self.assertRaisesRegex(BuildPolicyError, "license must be"):
                discover_projects(root, load_policy(root))

    def test_duplicate_normalized_project_requirements_are_rejected(self) -> None:
        variants = (
            (
                'dependencies = [\n]\n',
                'dependencies = [\n  "example-dep==1.0.0",\n'
                '  "example_dep==1.0.0",\n]\n',
                "duplicate runtime dependency",
            ),
            (
                'requires = ["setuptools==81.0.0", "wheel==0.42.0"]',
                'requires = ["setuptools==81.0.0", "setuptools==81.0.0"]',
                "duplicate build requirement",
            ),
        )
        for old, new, error in variants:
            with self.subTest(error=error):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    project = root / "packages/demo/pyproject.toml"
                    contents = project.read_text(encoding="utf-8")
                    self.assertIn(old, contents)
                    write(project, contents.replace(old, new, 1))
                    if "runtime" in error:
                        digest = "a" * 64
                        write(
                            root / "requirements-release.lock",
                            f"example-dep==1.0.0 --hash=sha256:{digest}\n",
                        )
                        write(
                            root / "requirements-release.graph.json",
                            '{"packages":{"example-dep==1.0.0":[]},'
                            '"schema_version":1}\n',
                        )
                    commit_all(root, "Duplicate a normalized project requirement")
                    policy = load_policy(root)
                    lock = parse_release_lock(policy.release_lock, root=root)
                    graph = parse_release_dependency_graph(
                        policy.release_dependency_graph, lock, root=root
                    )
                    with self.assertRaisesRegex(BuildPolicyError, error):
                        validate_project_dependencies(
                            discover_projects(root, policy), lock, graph
                        )

    def test_dependency_pins_use_supported_names_and_versions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root, dependency="example-dependency-==1..2")
            policy = load_policy(root)
            with self.assertRaisesRegex(BuildPolicyError, "exact name==version pin"):
                validate_project_dependencies(
                    discover_projects(root, policy), {}, {}
                )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            digest = "a" * 64
            lock_path = root / "requirements-release.lock"
            write(
                lock_path,
                f"example-dependency-==1..2 --hash=sha256:{digest}\n",
            )
            with self.assertRaisesRegex(BuildPolicyError, "unsupported name or version"):
                parse_release_lock(lock_path)

    def test_wheel_installer_control_namespaces_are_rejected(self) -> None:
        relative_paths = (
            "faultloom_demo-0.1.0.dist-info/RECORD",
            "faultloom_demo-0.1.0.data/scripts/undeclared-tool",
            "faultloom_demo-0.1.0.data/purelib/evil.pth",
            "shadow.egg-info/entry_points.txt",
            "shadow.egg/EGG-INFO/entry_points.txt",
            "evil.pth",
            "sitecustomize.py",
            "sitecustomize/__init__.py",
            "usercustomize.py",
            "usercustomize/__init__.py",
        )
        for relative in relative_paths:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    write(root / "packages/demo/src" / relative, "fixture\n")
                    commit_all(root, "Add installer-control wheel content")
                    with self.assertRaisesRegex(
                        BuildPolicyError, "installer-control wheel paths"
                    ):
                        build_once(root, Path(raw) / "output", EPOCH)

    def test_native_wheel_payloads_are_rejected_by_name_and_magic(self) -> None:
        payloads = (
            ("faultloom_demo/libfaultloom.so.1", b"not actually native\n"),
            ("faultloom_demo/payload.a", b"not actually native\n"),
            ("faultloom_demo/payload.bc", b"not actually native\n"),
            ("faultloom_demo/payload.lib", b"not actually native\n"),
            ("faultloom_demo/payload.o", b"not actually native\n"),
            ("faultloom_demo/payload.obj", b"not actually native\n"),
            ("faultloom_demo/extensionless-elf", b"\x7fELF\x02fixture"),
            ("faultloom_demo/extensionless-pe", b"MZfixture"),
            ("faultloom_demo/extensionless-macho", b"\xcf\xfa\xed\xfefixture"),
            ("faultloom_demo/extensionless-archive", b"!<arch>\nfixture"),
            (
                "faultloom_demo/extensionless-wrapped-bitcode",
                b"\xde\xc0\x17\x0bfixture",
            ),
            (
                "faultloom_demo/extensionless-coff",
                b"\x64\x86" + b"\x00" * 18,
            ),
        )
        for relative, data in payloads:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    make_repository(root)
                    path = root / "packages/demo/src" / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    commit_all(root, "Add native wheel payload")
                    with self.assertRaisesRegex(
                        BuildPolicyError, "native or executable wheel content"
                    ):
                        build_once(root, Path(raw) / "output", EPOCH)

    def test_transitive_dependency_graph_is_complete_and_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root, dependency="direct-dependency==1.0.0")
            direct_hash = "a" * 64
            transitive_hash = "b" * 64
            write(
                root / "requirements-release.lock",
                "direct-dependency==1.0.0 --hash=sha256:"
                + direct_hash
                + "\ntransitive-dependency==2.0.0 --hash=sha256:"
                + transitive_hash
                + "\n",
            )
            write(
                root / "requirements-release.graph.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "packages": {
                            "direct-dependency==1.0.0": [
                                "transitive-dependency==2.0.0"
                            ],
                            "transitive-dependency==2.0.0": [],
                        },
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            commit_all(root, "Add complete transitive dependency graph")
            output = base / "output"
            build_once(root, output, EPOCH)
            sbom = json.loads(
                (output / "faultloom-core.sbom.cdx.json").read_text(encoding="utf-8")
            )
            edges = {item["ref"]: item["dependsOn"] for item in sbom["dependencies"]}
            self.assertEqual(
                edges["pkg:pypi/direct-dependency@1.0.0"],
                ["pkg:pypi/transitive-dependency@2.0.0"],
            )
            self.assertEqual(edges["pkg:pypi/transitive-dependency@2.0.0"], [])
            verify_metadata(output, root, EPOCH)

            graph_path = root / "requirements-release.graph.json"
            write(
                graph_path,
                json.dumps(
                    {
                        "schema_version": 1,
                        "packages": {
                            "direct-dependency==1.0.0": [],
                            "transitive-dependency==2.0.0": [],
                        },
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            policy = load_policy(root)
            lock = parse_release_lock(policy.release_lock)
            graph = parse_release_dependency_graph(policy.release_dependency_graph, lock)
            with self.assertRaisesRegex(BuildPolicyError, "unused by distributable packages"):
                validate_project_dependencies(discover_projects(root, policy), lock, graph)

    def test_dependency_graph_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            graph_path = root / "requirements-release.graph.json"
            write(
                graph_path,
                '{"schema_version":1,"packages":{},"packages":{}}\n',
            )
            with self.assertRaisesRegex(BuildPolicyError, "duplicate JSON object key"):
                parse_release_dependency_graph(graph_path, {})

    def test_transitive_lock_cannot_collide_with_an_internal_project(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root, dependency="direct-dependency==1.0.0")
            digest = "a" * 64
            write(
                root / "requirements-release.lock",
                f"direct-dependency==1.0.0 --hash=sha256:{digest}\n"
                f"faultloom-demo==0.1.0 --hash=sha256:{digest}\n",
            )
            write(
                root / "requirements-release.graph.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "packages": {
                            "direct-dependency==1.0.0": ["faultloom-demo==0.1.0"],
                            "faultloom-demo==0.1.0": [],
                        },
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            commit_all(root, "Collide a transitive lock with an internal project")
            policy = load_policy(root)
            lock = parse_release_lock(policy.release_lock, root=root)
            graph = parse_release_dependency_graph(
                policy.release_dependency_graph, lock, root=root
            )
            with self.assertRaisesRegex(
                BuildPolicyError, "release lock collides with internal project names"
            ):
                validate_project_dependencies(discover_projects(root, policy), lock, graph)

    def test_ignored_files_do_not_enter_wheel_or_source_archive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            ignored = root / "packages/demo/src/faultloom_demo/ignored.py"
            write(root / ".git/info/exclude", f"/{ignored.relative_to(root).as_posix()}\n")
            write(ignored, 'VALUE = "ignored"\n')
            output = base / "output"
            build_once(root, output, EPOCH)
            with zipfile.ZipFile(next(output.glob("*.whl"))) as wheel:
                self.assertNotIn("faultloom_demo/ignored.py", wheel.namelist())
            with tarfile.open(output / "faultloom-core-source.tar.gz", "r:gz") as archive:
                self.assertNotIn(
                    "faultloom-core/packages/demo/src/faultloom_demo/ignored.py",
                    archive.getnames(),
                )

    def test_index_visibility_flags_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            tracked = "packages/demo/src/faultloom_demo/__init__.py"
            for enable, disable in (
                ("--assume-unchanged", "--no-assume-unchanged"),
                ("--skip-worktree", "--no-skip-worktree"),
            ):
                with self.subTest(flag=enable):
                    run_git(root, "update-index", enable, tracked)
                    try:
                        with self.assertRaisesRegex(BuildPolicyError, "index flag"):
                            require_clean_checkout(root)
                    finally:
                        run_git(root, "update-index", disable, tracked)

    def test_source_archive_reads_head_blob_not_hidden_worktree_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            relative = "packages/demo/src/faultloom_demo/__init__.py"
            source = root / relative
            original = source.read_text(encoding="utf-8")
            write(source, 'VALUE = "hidden mutation"\n')
            run_git(root, "update-index", "--assume-unchanged", relative)
            try:
                _, archive_bytes = build_source_archive(root, EPOCH)
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
                    archived = archive.extractfile(f"faultloom-core/{relative}")
                    self.assertIsNotNone(archived)
                    assert archived is not None
                    self.assertEqual(archived.read().decode("utf-8"), original)
            finally:
                run_git(root, "update-index", "--no-assume-unchanged", relative)
                write(source, original)

    def test_git_replace_refs_are_ignored_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            relative = "packages/demo/src/faultloom_demo/__init__.py"
            original_object = subprocess.run(
                ["git", "rev-parse", f"HEAD:{relative}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            replacement_path = root / ".git/replacement-blob"
            write(replacement_path, 'VALUE = "replace-ref mutation"\n')
            replacement_object = subprocess.run(
                ["git", "hash-object", "-w", str(replacement_path)],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            run_git(root, "replace", original_object, replacement_object)
            try:
                _, archive_bytes = build_source_archive(root, EPOCH)
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
                    archived = archive.extractfile(f"faultloom-core/{relative}")
                    self.assertIsNotNone(archived)
                    assert archived is not None
                    self.assertEqual(archived.read().decode("utf-8"), 'VALUE = "fixture"\n')
                with self.assertRaisesRegex(BuildPolicyError, "replace refs"):
                    require_clean_checkout(root)
            finally:
                run_git(root, "replace", "-d", original_object)

    def test_corrupted_loose_git_object_is_rejected_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            relative = "packages/demo/src/faultloom_demo/__init__.py"
            object_id = subprocess.run(
                ["git", "rev-parse", f"HEAD:{relative}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            git_directory = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            object_path = root / git_directory / "objects" / object_id[:2] / object_id[2:]
            original = (root / relative).read_bytes()
            replacement = original.replace(b"fixture", b"corrupt")
            self.assertEqual(len(original), len(replacement))
            payload = f"blob {len(replacement)}\0".encode("ascii") + replacement
            object_path.chmod(0o600)
            object_path.write_bytes(zlib.compress(payload))
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )
            with self.assertRaisesRegex(BuildPolicyError, "does not match its ID"):
                require_clean_checkout(root)

    def test_malformed_git_tree_cannot_create_duplicate_logical_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            blob_id = subprocess.run(
                [
                    "git",
                    "rev-parse",
                    "HEAD:packages/demo/src/faultloom_demo/__init__.py",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            def write_literal_tree(data: bytes) -> str:
                return subprocess.run(
                    [
                        "git",
                        "hash-object",
                        "--literally",
                        "-t",
                        "tree",
                        "-w",
                        "--stdin",
                    ],
                    cwd=root,
                    check=True,
                    input=data,
                    capture_output=True,
                ).stdout.decode("ascii").strip()

            child_tree = write_literal_tree(
                b"100644 b\0" + bytes.fromhex(blob_id)
            )
            malformed_root = write_literal_tree(
                b"40000 a\0"
                + bytes.fromhex(child_tree)
                + b"100644 a/b\0"
                + bytes.fromhex(blob_id)
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_AUTHOR_NAME": "Fixture",
                    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Fixture",
                    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                    "GIT_AUTHOR_DATE": f"@{EPOCH} +0000",
                    "GIT_COMMITTER_DATE": f"@{EPOCH} +0000",
                }
            )
            revision = subprocess.run(
                ["git", "commit-tree", malformed_root],
                cwd=root,
                env=environment,
                check=True,
                input="Malformed tree fixture\n",
                capture_output=True,
                text=True,
            ).stdout.strip()
            with self.assertRaisesRegex(BuildPolicyError, "basename-only"):
                build_source_archive(root, EPOCH, revision=revision)

    def test_git_epoch_uses_the_pinned_revision_not_moving_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            revision = git_identity(root)["commit"]
            write(root / "later.txt", "later revision\n")
            run_git(root, "add", "later.txt")
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_AUTHOR_DATE": f"@{EPOCH + 120} +0000",
                    "GIT_COMMITTER_DATE": f"@{EPOCH + 120} +0000",
                }
            )
            run_git(root, "commit", "-q", "-m", "Move synthetic HEAD", environment=environment)
            self.assertNotEqual(git_identity(root)["commit"], revision)
            self.assertEqual(git_commit_epoch(root, revision=revision), EPOCH)

    def test_clean_filter_cannot_replace_immutable_metadata_hook(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            hook = "tools/build_metadata_hook.py"
            run_git(
                root,
                "config",
                "filter.hide-hook.clean",
                f"git show HEAD:{hook}",
            )
            run_git(root, "config", "filter.hide-hook.smudge", "cat")
            write(root / ".git/info/attributes", f"/{hook} filter=hide-hook\n")
            write(
                root / hook,
                "#!/usr/bin/env python3\nraise SystemExit('worktree hook executed')\n",
            )
            # The clean filter preserves the HEAD blob in the index while Git
            # records the hostile worktree file's stat data as clean.
            run_git(root, "add", "--", hook)
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )
            output = base / "output"
            build_once(root, output, EPOCH)
            verify_metadata(output, root, EPOCH)

    def test_clean_filter_cannot_replace_executed_test_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            test_path = "tests/test_reproducible_build.py"
            head_marker = base / "immutable-head-test-executed"
            site_marker = base / "sitecustomize-executed"
            unittest_marker = base / "shadow-unittest-executed"
            write(
                root / test_path,
                "import unittest\n"
                "from pathlib import Path\n\n"
                "class ImmutableTest(unittest.TestCase):\n"
                "    def test_head_bytes(self):\n"
                f"        Path({str(head_marker)!r}).write_text('executed')\n",
            )
            write(
                root / "sitecustomize.py",
                "from pathlib import Path\n"
                f"Path({str(site_marker)!r}).write_text('executed')\n",
            )
            write(
                root / "unittest.py",
                "from pathlib import Path\n"
                f"Path({str(unittest_marker)!r}).write_text('executed')\n"
                "raise SystemExit(0)\n",
            )
            run_git(root, "init", "-q")
            run_git(root, "config", "user.email", "fixture@faultloom.invalid")
            run_git(root, "config", "user.name", "FaultLoom fixture")
            commit_all(root, "Add immutable test fixture")
            marker = base / "hostile-test-executed"
            run_git(
                root,
                "config",
                "filter.hide-test.clean",
                f"git show HEAD:{test_path}",
            )
            run_git(root, "config", "filter.hide-test.smudge", "cat")
            write(root / ".git/info/attributes", f"/{test_path} filter=hide-test\n")
            write(
                root / test_path,
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "raise RuntimeError('hostile worktree test executed')\n",
            )
            run_git(root, "add", "--", test_path)
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )
            run_immutable_tests(
                root,
                revision=git_identity(root)["commit"],
                environment=os.environ.copy(),
            )
            self.assertTrue(head_marker.is_file())
            self.assertFalse(site_marker.exists())
            self.assertFalse(unittest_marker.exists())
            self.assertFalse(marker.exists())

    def test_public_tree_gate_scans_head_not_clean_filtered_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            leak = "leak.txt"
            write(root / leak, "/mnt/" + "c/users/example/private\n")
            commit_all(root, "Add forbidden immutable source fixture")
            run_git(
                root,
                "config",
                "filter.hide-leak.clean",
                f"git show HEAD:{leak}",
            )
            run_git(root, "config", "filter.hide-leak.smudge", "cat")
            write(root / ".git/info/attributes", f"/{leak} filter=hide-leak\n")
            write(root / leak, "safe worktree replacement\n")
            run_git(root, "add", "--", leak)
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )
            self.assertEqual(scan(root), [])
            violations = scan_immutable_head(root)
            self.assertIn("absolute_user_path", {item.rule for item in violations})

    def test_public_tree_gate_scans_tracked_generated_directories(self) -> None:
        for relative in ("dist/customer.json", "target/.env"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                make_repository(root)
                write(root / relative, "tracked private fixture\n")
                commit_all(root, f"Add tracked private fixture at {relative}")
                self.assertEqual(scan(root), [])
                violations = scan_immutable_head(root)
                self.assertIn(
                    (relative, "private_name"),
                    {(item.path, item.rule) for item in violations},
                )

    def test_tracked_package_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            make_repository(root)
            link = root / "packages/demo/src/faultloom_demo/escape.py"
            try:
                link.symlink_to("../../../../LICENSE")
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            commit_all(root, "Add unsafe package symlink")
            with self.assertRaisesRegex(BuildPolicyError, "symlink or gitlink"):
                build_source_archive(root, EPOCH)

    def test_windows_style_archive_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)
            archive_path = output / "faultloom-core-source.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, data in (
                    ("faultloom-core/LICENSE", b"license"),
                    ("faultloom-core/NOTICE", b"notice"),
                    (r"faultloom-core\..\outside", b"escape"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(VerificationError, "unsafe archive member path"):
                verify_source_archive(output)

    def test_windows_archive_aliases_and_reserved_names_are_rejected(self) -> None:
        variants = (
            (("faultloom-core/Foo.txt", "faultloom-core/foo.txt"), "collision"),
            (
                ("faultloom-core/Foo", "faultloom-core/foo/bar.py"),
                "file/directory collision",
            ),
            (("faultloom-core/file.txt:stream",), "unsafe archive member path"),
            (("faultloom-core/CON.txt",), "Windows-reserved"),
            (("faultloom-core/bad?.txt",), "unsafe archive member path"),
            (("faultloom-core/bad*.txt",), "unsafe archive member path"),
            (("faultloom-core/bad|.txt",), "unsafe archive member path"),
            (("faultloom-core/bad<.txt",), "unsafe archive member path"),
            (("faultloom-core/bad>.txt",), "unsafe archive member path"),
            (("faultloom-core/bad\".txt",), "unsafe archive member path"),
            (("faultloom-core/CONIN$",), "Windows-reserved"),
            (("faultloom-core/CONOUT$",), "Windows-reserved"),
            (("faultloom-core/FOOBAR~1.TXT",), "Windows 8.3 alias-shaped"),
            (
                (
                    "faultloom-core/AAAA~BBBBCCCC.TXT",
                    "faultloom-core/AAAA~B~1.TXT",
                ),
                "Windows 8.3 alias-shaped",
            ),
            ((f"faultloom-core/{'A' * 256}",), "unsafe archive member path"),
            (
                (f"faultloom-core/{'/'.join(['A' * 240] * 18)}",),
                "unsafe archive member path",
            ),
            (("faultloom-core/COM¹.txt",), "unsafe archive member path"),
            (("faultloom-core/LPT².txt",), "unsafe archive member path"),
            (
                ("faultloom-core/I.txt", "faultloom-core/ı.txt"),
                "unsafe archive member path",
            ),
        )
        for malicious_names, error in variants:
            with self.subTest(names=malicious_names):
                with tempfile.TemporaryDirectory() as raw:
                    output = Path(raw)
                    archive_path = output / "faultloom-core-source.tar.gz"
                    with tarfile.open(archive_path, "w:gz") as archive:
                        for name in (
                            "faultloom-core/LICENSE",
                            "faultloom-core/NOTICE",
                            *malicious_names,
                        ):
                            data = b"fixture"
                            info = tarfile.TarInfo(name)
                            info.size = len(data)
                            archive.addfile(info, io.BytesIO(data))
                    with self.assertRaisesRegex(VerificationError, error):
                        verify_source_archive(output)

    def test_windows_invalid_wheel_members_are_rejected(self) -> None:
        variants = (
            ("FOOBAR~1.TXT", "Windows 8.3 alias-shaped"),
            ("AAAA~B~1.TXT", "Windows 8.3 alias-shaped"),
            ("A" * 256, "unsafe archive member path"),
            ("/".join(["A" * 240] * 18), "unsafe archive member path"),
        )
        for member_name, error in variants:
            with self.subTest(member_name=member_name):
                with tempfile.TemporaryDirectory() as raw:
                    base = Path(raw)
                    root = base / "source"
                    root.mkdir()
                    make_repository(root)
                    output = base / "output"
                    build_once(root, output, EPOCH)
                    wheel_path = next(output.glob("*.whl"))
                    with zipfile.ZipFile(
                        wheel_path, "a", compression=zipfile.ZIP_STORED
                    ) as wheel:
                        wheel.writestr(member_name, b"invalid member fixture")
                    with self.assertRaisesRegex(VerificationError, error):
                        verify_wheels(output)

    def test_wheel_record_rows_are_unique_and_content_verified(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            output = base / "output"
            build_once(root, output, EPOCH)
            wheel_path = next(output.glob("*.whl"))
            original = wheel_path.read_bytes()

            def rewrite_record(transform) -> None:
                with zipfile.ZipFile(io.BytesIO(original)) as archive:
                    entries = [
                        (item, archive.read(item.filename))
                        for item in archive.infolist()
                    ]
                record_name = next(
                    item.filename
                    for item, _ in entries
                    if item.filename.endswith(".dist-info/RECORD")
                )
                rebuilt = io.BytesIO()
                with zipfile.ZipFile(rebuilt, "w", compression=zipfile.ZIP_STORED) as archive:
                    for item, data in entries:
                        if item.filename == record_name:
                            data = transform(data)
                        archive.writestr(item, data)
                wheel_path.write_bytes(rebuilt.getvalue())

            def duplicate_first_row(data: bytes) -> bytes:
                first = data.splitlines(keepends=True)[0]
                return first + data

            rewrite_record(duplicate_first_row)
            with self.assertRaisesRegex(VerificationError, "duplicate rows"):
                verify_wheels(output)

            wheel_path.write_bytes(original)

            def corrupt_first_digest(data: bytes) -> bytes:
                rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
                rows[0][1] = "sha256=" + "A" * 43
                rendered = io.StringIO(newline="")
                writer = csv.writer(rendered, lineterminator="\n")
                writer.writerows(rows)
                return rendered.getvalue().encode("utf-8")

            rewrite_record(corrupt_first_digest)
            with self.assertRaisesRegex(VerificationError, "digest or size mismatch"):
                verify_wheels(output)

    def test_metadata_must_exactly_reconcile_with_repository(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            output = base / "output"
            build_once(root, output, EPOCH)
            verify_metadata(output, root, EPOCH)

            sbom_path = output / "faultloom-core.sbom.cdx.json"
            original_sbom = sbom_path.read_bytes()
            sbom = json.loads(original_sbom)
            duplicate_key_sbom = original_sbom.decode("utf-8").replace(
                '"bomFormat":"CycloneDX"',
                '"bomFormat":"CycloneDX","bomFormat":"CycloneDX"',
                1,
            )
            write(sbom_path, duplicate_key_sbom)
            with self.assertRaisesRegex(VerificationError, "SBOM does not reconcile"):
                verify_metadata(output, root, EPOCH)
            sbom_path.write_bytes(original_sbom)
            for key in ("components", "dependencies"):
                with self.subTest(sbom_field=key):
                    mutated = dict(sbom)
                    mutated[key] = []
                    write(sbom_path, json.dumps(mutated, sort_keys=True) + "\n")
                    with self.assertRaisesRegex(VerificationError, "SBOM does not reconcile"):
                        verify_metadata(output, root, EPOCH)
                    sbom_path.write_bytes(original_sbom)

            provenance_path = output / "faultloom-core.provenance.intoto.json"
            original_provenance = provenance_path.read_bytes()
            provenance = json.loads(original_provenance)
            del provenance["predicate"]["buildDefinition"]["internalParameters"]["network"]
            write(provenance_path, json.dumps(provenance, sort_keys=True) + "\n")
            with self.assertRaisesRegex(VerificationError, "complete expected predicate"):
                verify_metadata(output, root, EPOCH)
            provenance_path.write_bytes(original_provenance)

    def test_lock_hashes_are_declared_unverified_without_wheelhouse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root, dependency="example-dependency==2.4.1")
            digest = "a" * 64
            write(
                root / "requirements-release.lock",
                f"example-dependency==2.4.1 --hash=sha256:{digest}\n",
            )
            write(
                root / "requirements-release.graph.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "packages": {"example-dependency==2.4.1": []},
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            commit_all(root, "Lock synthetic external dependency")
            output = base / "output"
            build_once(root, output, EPOCH)
            sbom = json.loads(
                (output / "faultloom-core.sbom.cdx.json").read_text(encoding="utf-8")
            )
            external = next(
                component
                for component in sbom["components"]
                if component["name"] == "example-dependency"
            )
            properties = {item["name"]: item["value"] for item in external["properties"]}
            self.assertEqual(properties["faultloom:hashVerification"], "declared_unverified")
            self.assertEqual(properties["faultloom:declaredSha256"], digest)
            self.assertNotIn("hashes", external)
            metadata_properties = {
                item["name"]: item["value"] for item in sbom["metadata"]["properties"]
            }
            self.assertEqual(
                metadata_properties["faultloom:dependencyGraphVerification"],
                "declared_unverified",
            )
            self.assertEqual(
                metadata_properties["faultloom:pythonRuntimeVerification"],
                "version_only_unverified",
            )
            self.assertEqual(
                metadata_properties["faultloom:ciExternalTrustAnchor"], "false"
            )
            self.assertRegex(
                metadata_properties["faultloom:ciWorkflowSha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(
                metadata_properties["faultloom:rustRuntimeVerification"],
                "policy_declared_unverified",
            )
            graph_refs = {edge["ref"] for edge in sbom["dependencies"]}
            component_refs = {component["bom-ref"] for component in sbom["components"]}
            root_ref = sbom["metadata"]["component"]["bom-ref"]
            component_refs.add(root_ref)
            self.assertEqual(graph_refs, component_refs)
            root_edge = next(
                edge for edge in sbom["dependencies"] if edge["ref"] == root_ref
            )
            self.assertEqual(root_edge["dependsOn"], ["pkg:pypi/faultloom-demo@0.1.0"])

            provenance = json.loads(
                (output / "faultloom-core.provenance.intoto.json").read_text(encoding="utf-8")
            )
            internal = provenance["predicate"]["buildDefinition"]["internalParameters"]
            self.assertEqual(internal["network"]["mode"], "offline_requested")
            self.assertFalse(internal["network"]["enforced"])
            self.assertEqual(
                internal["dependencyGraph"]["verification"], "declared_unverified"
            )
            self.assertEqual(
                internal["toolchains"]["python_runtime_verification"],
                "version_only_unverified",
            )
            self.assertEqual(
                internal["toolchains"]["rust_runtime_verification"],
                "policy_declared_unverified",
            )
            self.assertFalse(internal["ciPolicy"]["external_trust_anchor"])
            self.assertRegex(
                internal["ciPolicy"]["workflow_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(provenance["predicate"]["runDetails"]["metadata"], {})
            dependency = next(
                item
                for item in provenance["predicate"]["buildDefinition"][
                    "resolvedDependencies"
                ]
                if item["uri"].startswith("pkg:pypi/example-dependency@")
            )
            self.assertNotIn("digest", dependency)
            self.assertEqual(
                dependency["annotations"]["faultloom:hashVerification"],
                "declared_unverified",
            )
            verify_metadata(output, root, EPOCH)

    def test_version_only_fake_rustc_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            marker = base / "executed-rustc-path"
            binary = base / "bin/rustc"
            write(
                binary,
                f"#!/bin/sh\nprintf '%s\\n' \"$0\" > '{marker}'\n"
                "printf 'rustc 1.96.1\\n'\n",
            )
            binary.chmod(0o755)
            pin_synthetic_rustc(root, binary)
            environment = os.environ.copy()
            environment["FAULTLOOM_RUSTC"] = str(binary)
            with self.assertRaisesRegex(VerificationError, "complete verbose version"):
                verify_toolchains(root, "fixture", environment)
            executed = marker.read_text(encoding="utf-8").strip()
            self.assertNotEqual(executed, str(binary))
            self.assertIn("faultloom-rustc-stage-", executed)

    def test_unpinned_rustc_binary_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            marker = base / "executed"
            binary = base / "bin/rustc"
            write(binary, f"#!/bin/sh\ntouch '{marker}'\n")
            binary.chmod(0o755)
            environment = os.environ.copy()
            environment["FAULTLOOM_RUSTC"] = str(binary)
            with self.assertRaisesRegex(VerificationError, "binary digest mismatch"):
                verify_toolchains(root, "fixture", environment)
            self.assertFalse(marker.exists())

    def test_unpinned_cargo_binary_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            add_gateway_fixture(root)
            rustc = base / "toolchain/bin/rustc"
            cargo = base / "toolchain/bin/cargo"
            cargo_marker = base / "executed-cargo"
            write(rustc, "#!/bin/sh\nexit 1\n")
            write(cargo, f"#!/bin/sh\ntouch '{cargo_marker}'\n")
            rustc.chmod(0o755)
            cargo.chmod(0o755)
            pin_synthetic_rustc(root, rustc)
            environment = os.environ.copy()
            environment["FAULTLOOM_RUSTC"] = str(rustc)
            environment["FAULTLOOM_CARGO"] = str(cargo)
            with self.assertRaisesRegex(VerificationError, "cargo binary digest mismatch"):
                verify_toolchains(root, "fixture", environment)
            self.assertFalse(cargo_marker.exists())

    def test_non_compiling_fake_rustc_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            commit = "a" * 40
            binary = base / "bin/rustc"
            write(
                binary,
                f"""#!/bin/sh
case "$*" in
  *-vV*)
    printf '%s\\n' \\
      'rustc 1.96.1 ({commit[:9]} 2026-03-25)' \\
      'binary: rustc' \\
      'commit-hash: {commit}' \\
      'commit-date: 2026-03-25' \\
      'host: x86_64-unknown-linux-gnu' \\
      'release: 1.96.1' \\
      'LLVM version: 21.1.2'
    ;;
esac
exit 0
""",
            )
            binary.chmod(0o755)
            pin_synthetic_rustc(root, binary)
            environment = os.environ.copy()
            environment["FAULTLOOM_RUSTC"] = str(binary)
            with self.assertRaisesRegex(VerificationError, "probe executable"):
                verify_toolchains(root, "fixture", environment)

    def test_script_producing_fake_rustc_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "source"
            root.mkdir()
            make_repository(root)
            commit = "a" * 40
            binary = base / "bin/rustc"
            write(
                binary,
                f"""#!/bin/sh
case "$*" in
  *-vV*)
    printf '%s\\n' \\
      'rustc 1.96.1 ({commit[:9]} 2026-03-25)' \\
      'binary: rustc' \\
      'commit-hash: {commit}' \\
      'commit-date: 2026-03-25' \\
      'host: x86_64-unknown-linux-gnu' \\
      'release: 1.96.1' \\
      'LLVM version: 21.1.2'
    exit 0
    ;;
esac
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then
    shift
    output="$1"
  fi
  shift
done
printf '#!/bin/sh\\nprintf faultloom-rustc-probe-v1\\n' > "$output"
chmod 755 "$output"
""",
            )
            binary.chmod(0o755)
            pin_synthetic_rustc(root, binary)
            environment = os.environ.copy()
            environment["FAULTLOOM_RUSTC"] = str(binary)
            with self.assertRaisesRegex(VerificationError, "not a native executable"):
                verify_toolchains(root, "fixture", environment)


if __name__ == "__main__":
    unittest.main()
