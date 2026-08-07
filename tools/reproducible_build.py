#!/usr/bin/env python3
"""Build deterministic, network-free FaultLoom release-candidate artifacts."""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, overload

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.rust_toolchain import (
    RustToolchainError,
    RustToolchainSpec,
    StagedRustToolchain,
    rustc_closure_sha256,
    sha256_file,
    stage_verified_toolchain,
)
from tools.cargo_vendor_graph import validate_vendor_graph
from tools.cargo_vendor_policy import (
    CargoVendorError,
    CargoVendorGraph,
    CargoVendorPolicy,
    SnapshotFile,
    parse_vendor_policy,
)


BUILDER_ID = "faultloom-core-builder/0.3"
MINIMUM_ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z
PINNED_ACTION_REFERENCE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)*@[0-9a-f]{40}$"
)
CHECKOUT_ACTION = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
SETUP_PYTHON_ACTION = (
    "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
)
GITLEAKS_ACTION = (
    "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e"
)
APPROVED_CI_ACTIONS = {CHECKOUT_ACTION, SETUP_PYTHON_ACTION, GITLEAKS_ACTION}
APPROVED_PRE_GATE_RUNS = {
    'rustup toolchain install "$RUST_VERSION" --profile minimal '
    "--component clippy --component rustfmt --no-self-update",
}
SENSITIVE_USES_HINT = re.compile(r'''(?:"uses"|'uses'|(?<![A-Za-z0-9_-])uses)\s*:''')
EXPLICIT_USES_HINT = re.compile(
    r'''^\s*(?:-\s*)?\?\s*(?:"uses"|'uses'|uses)(?:\s|$)'''
)
YAML_REFERENCE_HINT = re.compile(
    r"(?:^|[\s:\[{},-])[&*][A-Za-z0-9_-]+(?=$|[\s:\[\]{},])"
)
YAML_EXPLICIT_KEY_HINT = re.compile(r"^\s*(?:-\s*)?\?(?:\s|$)")
YAML_BLOCK_SCALAR = re.compile(r"^[|>][0-9+-]*$")
YAML_TAG_HINT = re.compile(r"(?:^|[\s:\[{},-])!")
UNSAFE_CI_ENVIRONMENT_KEYS = {
    "BASH_ENV",
    "PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "VIRTUAL_ENV",
}
CI_GATE_COMMAND = "python3 tools/verify_clean_checkout.py"
REQUIRED_RUNTIME_TESTS = (
    "tests/runtime/test_personal_campaign.py",
    "tests/runtime/test_personal_campaign_bridge.py",
    "tests/runtime/test_personal_campaign_supervise.py",
    "tests/runtime/test_model_http1_poc_supervisor.py",
    "tests/runtime/test_campaign_verification_handoff.py",
    "tests/runtime/test_independent_http1_verification.py",
)
NETWORK_EXECUTION: dict[str, Any] = {
    "mode": "offline_requested",
    "enforced": False,
    "controls": [
        "PIP_NO_INDEX",
        "UV_OFFLINE",
        "CARGO_NET_OFFLINE",
        "CARGO_FROZEN_LOCKED_OFFLINE",
        "CARGO_HOME_PRIVATE_EMPTY",
        "CARGO_VENDOR_FILE_CHECKSUMS",
        "GIT_NO_LAZY_FETCH",
    ],
}
EXACT_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.+!-]*)"
    r"(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)\s*$"
)
EXACT_PROJECT_DEPENDENCY = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.+!-]*)$"
)
# Stable PEP 440 release segments may contain two or more numeric components
# (for example, pycparser 3.0).  Pre/dev/local versions stay outside the
# admitted release-lock grammar.
SAFE_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
SAFE_PROJECT_NAME = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$"
)
SAFE_SCRIPT_NAME = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$"
)
SAFE_SCRIPT_TARGET = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:"
    r"[A-Za-z_][A-Za-z0-9_]*$"
)
SAFE_REQUIRES_PYTHON = re.compile(
    r"^(?:(?:~=|==|!=|<=|>=|<|>)[0-9]+\.[0-9]+(?:\.[0-9]+)?)"
    r"(?:,(?:~=|==|!=|<=|>=|<|>)[0-9]+\.[0-9]+(?:\.[0-9]+)?)*$"
)


class BuildPolicyError(RuntimeError):
    """The repository does not satisfy the deterministic build policy."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def canonical_ci_workflow(rust_version: str) -> bytes:
    """Return the only admitted CI workflow, including exact action inputs."""

    required_runtime_command = "python3 -m pytest " + " ".join(
        REQUIRED_RUNTIME_TESTS
    )
    return f'''name: core-ci

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read

env:
  PYTHONDONTWRITEBYTECODE: "1"
  PIP_DISABLE_PIP_VERSION_CHECK: "1"
  PIP_NO_INDEX: "1"
  UV_OFFLINE: "1"
  CARGO_NET_OFFLINE: "true"

jobs:
  offline-build-verification:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - name: Check out the exact revision
        uses: {CHECKOUT_ACTION}
        with:
          repository: "${{{{ github.repository }}}}"
          ref: "${{{{ github.sha }}}}"
          path: .
          clean: true
          fetch-depth: 1
          persist-credentials: false
          lfs: false
          submodules: false

      - name: Provision the pinned Python runtime
        uses: {SETUP_PYTHON_ACTION}
        env:
          PIP_NO_INDEX: "0"
        with:
          python-version-file: .python-version
          cache: ""
          check-latest: false

      - name: Provision the pinned Rust runtime
        env:
          RUST_VERSION: "{rust_version}"
        run: rustup toolchain install "$RUST_VERSION" --profile minimal --component clippy --component rustfmt --no-self-update

      - name: Verify policy and reproduce artifacts without package downloads
        env:
          FAULTLOOM_RUST_TOOLCHAIN: "{rust_version}"
        run: python3 tools/verify_clean_checkout.py

  required-runtime-tests:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - name: Check out the exact revision
        uses: {CHECKOUT_ACTION}
        with:
          repository: "${{{{ github.repository }}}}"
          ref: "${{{{ github.sha }}}}"
          path: .
          clean: true
          fetch-depth: 1
          persist-credentials: false
          lfs: false
          submodules: false

      - name: Provision the pinned Python runtime
        uses: {SETUP_PYTHON_ACTION}
        env:
          PIP_NO_INDEX: "0"
        with:
          python-version-file: .python-version
          cache: ""
          check-latest: false

      - name: Install pinned test dependencies (network-enabled)
        env:
          PIP_NO_INDEX: "0"
          PIP_INDEX_URL: https://pypi.org/simple
          UV_OFFLINE: "0"
        run: python3 -m pip install --requirement requirements-dev.lock

      - name: Run the required runtime tests
        run: {required_runtime_command}

  public-history-secret-gate:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - name: Check out the exact revision and complete history
        uses: {CHECKOUT_ACTION}
        with:
          repository: "${{{{ github.repository }}}}"
          ref: "${{{{ github.sha }}}}"
          path: .
          clean: true
          fetch-depth: 0
          persist-credentials: false
          lfs: false
          submodules: false

      - name: Verify the current public tree
        run: python3 tools/check_public_tree.py .

      - name: Scan complete public history for secrets
        uses: {GITLEAKS_ACTION}
        env:
          GITHUB_TOKEN: "${{{{ secrets.GITHUB_TOKEN }}}}"
          GITLEAKS_CONFIG: ".gitleaks.toml"
          GITLEAKS_VERSION: "8.21.2"
'''.encode("utf-8")


@dataclass(frozen=True)
class GatewayPolicy:
    workspace_manifest: Path
    manifest: Path
    lock: Path
    package: str
    binary: str
    version: str
    target: str
    cargo_sha256: str


@dataclass(frozen=True)
class Policy:
    python_version: str
    python_runtime_verification: str
    rust_version: str
    rustc_host: str
    rustc_sha256: str
    rustc_closure_sha256: str
    release_lock: Path
    release_dependency_graph: Path
    package_roots: tuple[Path, ...]
    license_files: tuple[Path, ...]
    sbom_hook: Path
    provenance_hook: Path
    release_enabled: bool
    ci_external_trust_anchor: bool
    gateway: GatewayPolicy | None
    cargo_vendor: CargoVendorPolicy | None


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
    readme_content_type: str | None
    license_files: tuple[Path, ...]
    scripts: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class TrackedFile:
    mode: str
    path: str
    object_id: str


@dataclass(frozen=True)
class NativeArtifact:
    artifact_name: str
    component_name: str
    version: str
    target: str
    purl: str
    sha256: str
    size: int
    source_commit: str
    source_tree: str
    cargo_lock_sha256: str
    recipe_sha256: str
    rustc_sha256: str
    rustc_closure_sha256: str
    cargo_sha256: str
    host_environment_verification: str


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


def _read_toml_bytes(data: bytes, display: str) -> dict[str, Any]:
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BuildPolicyError(f"cannot read {display}: {exc}") from exc


def load_policy(root: Path, *, revision: str = "HEAD") -> Policy:
    root = root.resolve()
    policy_bytes = _head_blob_for_path(root, "build-policy.toml", revision=revision)
    raw = _read_toml_bytes(policy_bytes, f"build-policy.toml at {revision}")
    if raw.get("schema_version") != 2:
        raise BuildPolicyError("build-policy.toml must use schema_version = 2")
    hooks = raw.get("hooks")
    if not isinstance(hooks, dict):
        raise BuildPolicyError("build-policy.toml must define [hooks]")
    try:
        path_fields = {
            key: _safe_repository_path(raw[key], context=f"build policy {key}")
            for key in ("release_lock", "release_dependency_graph")
        }
        package_roots = tuple(
            _safe_repository_path(item, context="build policy package root")
            for item in raw["package_roots"]
        )
        license_files = tuple(
            _safe_repository_path(item, context="build policy license file")
            for item in raw["license_files"]
        )
        sbom_hook = _safe_repository_path(hooks["sbom"], context="build policy SBOM hook")
        provenance_hook = _safe_repository_path(
            hooks["provenance"], context="build policy provenance hook"
        )
        gateway_raw = raw.get("gateway")
        gateway = None
        if gateway_raw is not None:
            if not isinstance(gateway_raw, dict) or set(gateway_raw) != {
                "workspace_manifest",
                "manifest",
                "lock",
                "package",
                "binary",
                "version",
                "target",
                "cargo_sha256",
            }:
                raise BuildPolicyError(
                    "[gateway] must contain the exact deterministic build fields"
                )
            gateway = GatewayPolicy(
                workspace_manifest=(
                    root
                    / _safe_repository_path(
                        gateway_raw["workspace_manifest"],
                        context="Gateway workspace manifest",
                    ).as_posix()
                ),
                manifest=(
                    root
                    / _safe_repository_path(
                        gateway_raw["manifest"], context="Gateway manifest"
                    ).as_posix()
                ),
                lock=(
                    root
                    / _safe_repository_path(
                        gateway_raw["lock"], context="Gateway lock"
                    ).as_posix()
                ),
                package=gateway_raw["package"],
                binary=gateway_raw["binary"],
                version=gateway_raw["version"],
                target=gateway_raw["target"],
                cargo_sha256=gateway_raw["cargo_sha256"],
            )
        try:
            cargo_vendor = parse_vendor_policy(policy_bytes, raw["rust_version"])
        except CargoVendorError as exc:
            raise BuildPolicyError(str(exc)) from exc
        policy = Policy(
            python_version=raw["python_version"],
            python_runtime_verification=raw["python_runtime_verification"],
            rust_version=raw["rust_version"],
            rustc_host=raw["rustc_host"],
            rustc_sha256=raw["rustc_sha256"],
            rustc_closure_sha256=raw["rustc_closure_sha256"],
            release_lock=root / path_fields["release_lock"].as_posix(),
            release_dependency_graph=(
                root / path_fields["release_dependency_graph"].as_posix()
            ),
            package_roots=tuple(root / item.as_posix() for item in package_roots),
            license_files=tuple(root / item.as_posix() for item in license_files),
            sbom_hook=root / sbom_hook.as_posix(),
            provenance_hook=root / provenance_hook.as_posix(),
            release_enabled=raw["release_enabled"],
            ci_external_trust_anchor=raw["ci_external_trust_anchor"],
            gateway=gateway,
            cargo_vendor=cargo_vendor,
        )
    except (KeyError, TypeError) as exc:
        raise BuildPolicyError(f"invalid build policy field: {exc}") from exc
    if not isinstance(policy.release_enabled, bool) or not isinstance(
        policy.ci_external_trust_anchor, bool
    ):
        raise BuildPolicyError("release and CI trust-anchor policy values must be booleans")
    if not all(
        isinstance(item, str)
        for item in (
            policy.python_version,
            policy.rust_version,
            policy.rustc_host,
            policy.rustc_sha256,
            policy.rustc_closure_sha256,
        )
    ):
        raise BuildPolicyError("toolchain policy values must be strings")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", policy.python_version) is None:
        raise BuildPolicyError("python_version must be an exact numeric release")
    if policy.python_runtime_verification != "version_only_unverified":
        raise BuildPolicyError(
            "Python runtime verification must remain version_only_unverified "
            "until a content verifier is implemented"
        )
    if policy.ci_external_trust_anchor:
        raise BuildPolicyError(
            "ci_external_trust_anchor cannot be asserted by the repository itself"
        )
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", policy.rust_version) is None:
        raise BuildPolicyError("rust_version must be an exact numeric release")
    if (
        re.fullmatch(
            r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+", policy.rustc_host
        )
        is None
    ):
        raise BuildPolicyError("rustc_host must be a canonical Rust target triple")
    if re.fullmatch(r"[0-9a-f]{64}", policy.rustc_sha256) is None:
        raise BuildPolicyError("rustc_sha256 must be a lowercase SHA-256 digest")
    if re.fullmatch(r"[0-9a-f]{64}", policy.rustc_closure_sha256) is None:
        raise BuildPolicyError(
            "rustc_closure_sha256 must be a lowercase SHA-256 digest"
        )
    if policy.gateway is not None:
        gateway_strings = (
            policy.gateway.package,
            policy.gateway.binary,
            policy.gateway.version,
            policy.gateway.target,
            policy.gateway.cargo_sha256,
        )
        if not all(isinstance(item, str) for item in gateway_strings):
            raise BuildPolicyError("Gateway policy values must be strings")
        if policy.gateway.workspace_manifest.relative_to(root) != Path("Cargo.toml"):
            raise BuildPolicyError("Gateway workspace_manifest must be Cargo.toml")
        if policy.gateway.manifest.relative_to(root) != Path("gateway/Cargo.toml"):
            raise BuildPolicyError("Gateway manifest must be gateway/Cargo.toml")
        if policy.gateway.lock.relative_to(root) != Path("Cargo.lock"):
            raise BuildPolicyError("Gateway lock must be Cargo.lock")
        if policy.gateway.package != "faultloom-gateway":
            raise BuildPolicyError("Gateway package must be faultloom-gateway")
        if policy.gateway.binary != "faultloom-gateway":
            raise BuildPolicyError("Gateway binary must be faultloom-gateway")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", policy.gateway.version) is None:
            raise BuildPolicyError("Gateway version must be an exact numeric release")
        if policy.gateway.target != policy.rustc_host:
            raise BuildPolicyError("Gateway target must equal the pinned Rust host")
        if re.fullmatch(r"[0-9a-f]{64}", policy.gateway.cargo_sha256) is None:
            raise BuildPolicyError("Gateway cargo_sha256 must be a lowercase SHA-256 digest")
    license_keys: dict[str, str] = {}
    for license_path in policy.license_files:
        basename = license_path.name
        if (
            not basename
            or basename.endswith((" ", "."))
            or any(
                ord(character) < 32
                or ord(character) > 126
                or character in '<>:"/\\|?*'
                for character in basename
            )
        ):
            raise BuildPolicyError(f"license filename is not portable: {basename!r}")
        key = unicodedata.normalize("NFC", basename).casefold()
        previous = license_keys.setdefault(key, license_path.as_posix())
        if previous != license_path.as_posix():
            raise BuildPolicyError(
                "license files collide after basename flattening: "
                f"{previous}, {license_path.as_posix()}"
            )
    return policy


def _single_line_bytes(data: bytes, display: str) -> str:
    try:
        lines = [line.strip() for line in data.decode("utf-8").splitlines()]
    except UnicodeDecodeError as exc:
        raise BuildPolicyError(f"cannot decode {display} as UTF-8") from exc
    values = [line for line in lines if line and not line.startswith("#")]
    if len(values) != 1:
        raise BuildPolicyError(f"{display} must contain exactly one value")
    return values[0]


def _yaml_scalar_mapping_entry(raw_line: str) -> tuple[str, str] | None:
    """Parse one scalar YAML mapping entry without accepting opaque syntax.

    The CI policy only needs the security-sensitive ``uses`` and ``run`` keys.
    Supporting quoted keys and values here avoids bypasses in a raw line regex
    without adding a mutable YAML parser dependency to the release builder.
    """

    line = raw_line.strip()
    if line.startswith("- "):
        line = line[2:].lstrip()
    quote: str | None = None
    escaped = False
    separator = -1
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == ":":
            separator = index
            break
    if separator < 0:
        return None
    raw_key = line[:separator].strip()
    raw_value = line[separator + 1 :].strip()
    try:
        key = ast.literal_eval(raw_key) if raw_key[:1] in {"'", '"'} else raw_key
    except (SyntaxError, ValueError):
        return None
    if not isinstance(key, str):
        return None

    quote = None
    escaped = False
    comment = len(raw_value)
    for index, character in enumerate(raw_value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "#" and (index == 0 or raw_value[index - 1].isspace()):
            comment = index
            break
    raw_value = raw_value[:comment].strip()
    try:
        value = ast.literal_eval(raw_value) if raw_value[:1] in {"'", '"'} else raw_value
    except (SyntaxError, ValueError):
        return None
    return (key, value) if isinstance(value, str) else None


def _yaml_without_comment(raw_line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(raw_line):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "#" and (index == 0 or raw_line[index - 1].isspace()):
            return raw_line[:index]
    return raw_line


def _yaml_unquoted_text(raw_line: str) -> str:
    """Return YAML punctuation while masking quoted strings and comments."""

    output: list[str] = []
    quote: str | None = None
    escaped = False
    for index, character in enumerate(raw_line):
        if escaped:
            escaped = False
            output.append(" ")
            continue
        if character == "\\" and quote == '"':
            escaped = True
            output.append(" ")
            continue
        if quote is not None:
            if character == quote:
                quote = None
            output.append(" ")
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(" ")
        elif character == "#" and (index == 0 or raw_line[index - 1].isspace()):
            break
        else:
            output.append(character)
    if quote is not None:
        raise BuildPolicyError("CI workflow multiline quoted scalars are unsupported")
    return "".join(output)


def _yaml_indent(raw_line: str) -> int:
    prefix = raw_line[: len(raw_line) - len(raw_line.lstrip())]
    if "\t" in prefix:
        raise BuildPolicyError("CI workflow indentation must use spaces")
    return len(prefix)


def _yaml_ancestor(
    lines: list[str], before_index: int, child_indent: int, target: str
) -> tuple[int, int] | None:
    boundary = child_indent
    for index in range(before_index - 1, -1, -1):
        raw_line = lines[index]
        if not _yaml_without_comment(raw_line).strip():
            continue
        indent = _yaml_indent(raw_line)
        if indent >= boundary:
            continue
        entry = _yaml_scalar_mapping_entry(raw_line)
        if entry == (target, ""):
            return index, indent
        boundary = indent
    return None


def _yaml_block_end(lines: list[str], start: int, indent: int) -> int:
    for index in range(start + 1, len(lines)):
        if not _yaml_without_comment(lines[index]).strip():
            continue
        if _yaml_indent(lines[index]) <= indent:
            return index
    return len(lines)


def _is_enforced_job_step_run(lines: list[str], index: int) -> bool:
    raw_line = lines[index]
    run_indent = _yaml_indent(raw_line)
    steps = _yaml_ancestor(lines, index, run_indent, "steps")
    if steps is None:
        return False
    steps_index, steps_indent = steps
    jobs = _yaml_ancestor(lines, steps_index, steps_indent, "jobs")
    if jobs is None:
        return False
    jobs_index, jobs_indent = jobs

    job_start: tuple[int, int] | None = None
    boundary = steps_indent
    for candidate_index in range(steps_index - 1, jobs_index, -1):
        candidate = lines[candidate_index]
        if not _yaml_without_comment(candidate).strip():
            continue
        indent = _yaml_indent(candidate)
        if indent >= boundary:
            continue
        if indent > jobs_indent:
            job_start = (candidate_index, indent)
            break
        boundary = indent
    if job_start is None:
        return False

    step_start: tuple[int, int] | None = None
    if raw_line.lstrip().startswith("- "):
        step_start = (index, run_indent)
    for candidate_index in range(index - 1, steps_index, -1):
        if step_start is not None:
            break
        candidate = lines[candidate_index]
        if not _yaml_without_comment(candidate).strip():
            continue
        indent = _yaml_indent(candidate)
        if steps_indent < indent < run_indent and candidate.lstrip().startswith("- "):
            step_start = (candidate_index, indent)
    if step_start is None:
        return False
    step_index, step_indent = step_start
    if not (
        (step_index == index and run_indent == step_indent)
        or (step_index != index and run_indent == step_indent + 2)
    ):
        return False

    forbidden = {
        "container",
        "continue-on-error",
        "defaults",
        "if",
        "needs",
        "services",
        "shell",
        "working-directory",
    }
    for candidate in lines[step_index : _yaml_block_end(lines, step_index, step_indent)]:
        entry = _yaml_scalar_mapping_entry(candidate)
        if entry is not None and entry[0] in forbidden:
            return False
    job_index, job_indent = job_start
    for candidate in lines[job_index : _yaml_block_end(lines, job_index, job_indent)]:
        entry = _yaml_scalar_mapping_entry(candidate)
        if entry is not None and entry[0] in forbidden:
            return False
    for candidate in lines:
        entry = _yaml_scalar_mapping_entry(candidate)
        if entry is not None and entry[0] == "shell":
            return False
    for candidate in lines[job_index:index]:
        entry = _yaml_scalar_mapping_entry(candidate)
        if entry is not None and entry[0] == "run" and entry[1] not in APPROVED_PRE_GATE_RUNS:
            return False
    return True


def validate_repository_policy(
    root: Path, policy: Policy, *, revision: str = "HEAD"
) -> dict[str, str]:
    root = root.resolve()
    entries = {entry.path: entry for entry in _head_entries(root, revision=revision)}

    def head_bytes(path: str) -> bytes:
        entry = entries.get(path)
        if entry is None:
            raise BuildPolicyError(f"required regular file is missing from HEAD: {path}")
        return _head_blob(root, entry.object_id)

    python_version = _single_line_bytes(head_bytes(".python-version"), ".python-version")
    if python_version != policy.python_version:
        raise BuildPolicyError(".python-version does not match build-policy.toml")
    rust = _read_toml_bytes(
        head_bytes("rust-toolchain.toml"), "rust-toolchain.toml at HEAD"
    ).get("toolchain", {})
    if rust.get("channel") != policy.rust_version:
        raise BuildPolicyError("rust-toolchain.toml does not match build-policy.toml")
    if rust.get("profile") != "minimal":
        raise BuildPolicyError("the Rust toolchain profile must be minimal")
    required_paths = (
        policy.release_lock,
        policy.release_dependency_graph,
        *policy.license_files,
        policy.sbom_hook,
        policy.provenance_hook,
        root / "tools/__init__.py",
        root / "tools/cargo_sbom.py",
        root / "tools/cargo_vendor_graph.py",
        root / "tools/cargo_vendor_policy.py",
    )
    for path in required_paths:
        head_bytes(path.relative_to(root).as_posix())

    workflows = sorted(
        path
        for path in entries
        if PurePosixPath(path).parent == PurePosixPath(".github/workflows")
        and PurePosixPath(path).suffix in {".yml", ".yaml"}
    )
    if not workflows:
        raise BuildPolicyError("at least one pinned CI workflow is required")
    action_count = 0
    gate_count = 0
    for workflow in workflows:
        try:
            lines = head_bytes(workflow).decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise BuildPolicyError(f"CI workflow is not UTF-8: {workflow}") from exc
        for index, raw_line in enumerate(lines):
            _yaml_indent(raw_line)
            unquoted = _yaml_unquoted_text(raw_line)
            if re.search(r"\bGITHUB_(?:ENV|PATH)\b", _yaml_without_comment(raw_line)):
                raise BuildPolicyError(
                    f"CI workflow may not mutate later-step environments: {workflow}"
                )
            if YAML_REFERENCE_HINT.search(unquoted):
                raise BuildPolicyError(
                    f"CI workflow aliases and anchors are unsupported: {workflow}"
                )
            if YAML_EXPLICIT_KEY_HINT.search(unquoted):
                raise BuildPolicyError(
                    f"CI workflow explicit mapping keys are unsupported: {workflow}"
                )
            if YAML_TAG_HINT.search(unquoted):
                raise BuildPolicyError(
                    f"CI workflow YAML tags are unsupported: {workflow}"
                )
            if any(character in unquoted for character in "[]{}"):
                raise BuildPolicyError(
                    f"CI workflow flow collections are unsupported: {workflow}"
                )
            uncommented = _yaml_without_comment(raw_line)
            entry = _yaml_scalar_mapping_entry(raw_line)
            if entry is not None and YAML_BLOCK_SCALAR.fullmatch(entry[1]):
                raise BuildPolicyError(
                    f"CI workflow block scalars are unsupported: {workflow}"
                )
            suspicious_uses = SENSITIVE_USES_HINT.search(
                uncommented
            ) or EXPLICIT_USES_HINT.search(uncommented)
            if suspicious_uses and (entry is None or entry[0] != "uses"):
                raise BuildPolicyError(
                    "CI action uses unsupported YAML syntax; only scalar mapping "
                    f"entries are allowed: {workflow}"
                )
            if entry is None:
                continue
            key, value = entry
            if (
                key in UNSAFE_CI_ENVIRONMENT_KEYS
                or key.startswith("BASH_FUNC_")
                or key.startswith("LD_")
                or key.startswith("DYLD_")
            ):
                raise BuildPolicyError(
                    f"CI workflow overrides an unsafe execution variable: {workflow}"
                )
            if key == "uses" and PINNED_ACTION_REFERENCE.fullmatch(value) is None:
                raise BuildPolicyError(
                    f"CI action must use a full lowercase commit SHA: {workflow}"
                )
            if key == "uses":
                if value not in APPROVED_CI_ACTIONS:
                    raise BuildPolicyError(
                        f"CI action is not in the reviewed digest allowlist: {workflow}"
                    )
                action_count += 1
            elif (
                key == "run"
                and value == CI_GATE_COMMAND
                and _is_enforced_job_step_run(lines, index)
            ):
                gate_count += 1
    if action_count == 0:
        raise BuildPolicyError("CI workflow has no pinned actions")
    if gate_count == 0:
        raise BuildPolicyError(
            f"CI workflow must execute the clean-checkout gate: {CI_GATE_COMMAND}"
        )
    if workflows != [".github/workflows/ci.yml"]:
        raise BuildPolicyError("CI must contain only the canonical clean-checkout workflow")
    if head_bytes(workflows[0]) != canonical_ci_workflow(policy.rust_version):
        raise BuildPolicyError(
            "CI workflow must match the canonical clean-checkout gate template"
        )
    _validate_gateway_repository(
        root,
        policy,
        entries=entries,
        head_bytes=head_bytes,
    )
    return {"python": policy.python_version, "rust": policy.rust_version}


def _validate_gateway_repository(
    root: Path,
    policy: Policy,
    *,
    entries: dict[str, TrackedFile],
    head_bytes: Any,
) -> None:
    vendor_prefix = (
        "" if policy.cargo_vendor is None else f"{policy.cargo_vendor.directory}/"
    )
    manifests = {
        path
        for path in entries
        if PurePosixPath(path).name == "Cargo.toml"
        and (not vendor_prefix or not path.startswith(vendor_prefix))
    }
    locks = {
        path
        for path in entries
        if PurePosixPath(path).name == "Cargo.lock"
        and (not vendor_prefix or not path.startswith(vendor_prefix))
    }
    unsafe_controls = sorted(
        path
        for path in entries
        if (
            PurePosixPath(path).name == "build.rs"
            and (not vendor_prefix or not path.startswith(vendor_prefix))
        )
        or (
            ".cargo" in PurePosixPath(path).parts
            and PurePosixPath(path).name in {"config", "config.toml"}
            and policy.cargo_vendor is None
        )
    )
    gateway = policy.gateway
    if gateway is None:
        if manifests or locks or unsafe_controls:
            raise BuildPolicyError(
                "tracked Cargo inputs require an explicit [gateway] build policy"
            )
        return
    if unsafe_controls:
        raise BuildPolicyError(
            f"Gateway build scripts and Cargo configuration are forbidden: {unsafe_controls}"
        )
    expected_manifests = {
        gateway.workspace_manifest.relative_to(root).as_posix(),
        gateway.manifest.relative_to(root).as_posix(),
    }
    expected_locks = {gateway.lock.relative_to(root).as_posix()}
    if manifests != expected_manifests or locks != expected_locks:
        raise BuildPolicyError(
            "Gateway Cargo manifests and lock must exactly match the admitted policy"
        )

    workspace = _read_toml_bytes(
        head_bytes("Cargo.toml"), "Gateway workspace Cargo.toml at HEAD"
    )
    expected_workspace = {
        "workspace": {"members": ["gateway"], "resolver": "3"},
        "profile": {
            "release": {
                "codegen-units": 1,
                "debug": 0,
                "incremental": False,
                "lto": "fat",
                "opt-level": 3,
                "panic": "abort",
                "strip": "symbols",
            }
        },
    }
    if workspace != expected_workspace:
        raise BuildPolicyError(
            "Gateway workspace manifest must use the exact deterministic release profile"
        )

    manifest = _read_toml_bytes(
        head_bytes("gateway/Cargo.toml"), "Gateway package Cargo.toml at HEAD"
    )
    expected_manifest = {
        "package": {
            "name": gateway.package,
            "version": gateway.version,
            "edition": "2024",
            "rust-version": policy.rust_version,
            "description": "Fail-closed target egress kernel for FaultLoom",
            "license": "Apache-2.0",
            "publish": False,
        },
        "lib": {"name": "faultloom_gateway", "path": "src/lib.rs"},
        "bin": [{"name": gateway.binary, "path": "src/main.rs"}],
        "dependencies": (
            manifest.get("dependencies") if policy.cargo_vendor is not None else {}
        ),
        "lints": {"rust": {"unsafe_code": "forbid"}},
    }
    if manifest != expected_manifest:
        raise BuildPolicyError(
            "Gateway package manifest contains an unsupported field or dependency"
        )

    if policy.cargo_vendor is None:
        lock = _read_toml_bytes(head_bytes("Cargo.lock"), "Gateway Cargo.lock at HEAD")
        if lock != {
            "version": 4,
            "package": [{"name": gateway.package, "version": gateway.version}],
        }:
            raise BuildPolicyError(
                "Gateway lock must contain exactly one source-less package and no dependencies"
            )
    else:
        _cargo_graph_from_snapshot(policy, entries=entries, head_bytes=head_bytes)
    required_sources = {"gateway/src/lib.rs", "gateway/src/main.rs"}
    if not required_sources <= entries.keys():
        raise BuildPolicyError("Gateway library or binary source is missing from HEAD")


def _cargo_graph_from_snapshot(
    policy: Policy,
    *,
    entries: dict[str, TrackedFile],
    head_bytes: Any,
) -> CargoVendorGraph:
    cargo_vendor = policy.cargo_vendor
    if cargo_vendor is None:
        raise BuildPolicyError("internal error: Cargo vendor graph requested without policy")
    paths = sorted(
        path
        for path in entries
        if path.startswith(".cargo/") or path.startswith(f"{cargo_vendor.directory}/")
    )
    snapshot = tuple(
        SnapshotFile(path=path, mode=entries[path].mode, content=head_bytes(path))
        for path in paths
    )
    try:
        return validate_vendor_graph(
            cargo_vendor,
            head_bytes("gateway/Cargo.toml"),
            head_bytes("Cargo.lock"),
            snapshot,
        )
    except CargoVendorError as exc:
        raise BuildPolicyError(str(exc)) from exc


def rust_toolchain_spec(policy: Policy) -> RustToolchainSpec:
    return RustToolchainSpec(
        version=policy.rust_version,
        host=policy.rustc_host,
        rustc_sha256=policy.rustc_sha256,
        rustc_closure_sha256=policy.rustc_closure_sha256,
        cargo_sha256=(None if policy.gateway is None else policy.gateway.cargo_sha256),
    )


def parse_release_lock(
    path: Path, *, root: Path | None = None, revision: str = "HEAD"
) -> dict[str, tuple[str, tuple[str, ...]]]:
    try:
        if root is None:
            data = path.read_bytes()
        else:
            relative = path.relative_to(root.resolve()).as_posix()
            data = _head_blob_for_path(root.resolve(), relative, revision=revision)
        lines = data.decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
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
        raw_name = match.group("name")
        version = match.group("version")
        if (
            SAFE_PROJECT_NAME.fullmatch(raw_name) is None
            or SAFE_VERSION.fullmatch(version) is None
        ):
            raise BuildPolicyError(
                f"release requirement uses an unsupported name or version "
                f"at {path}:{number}"
            )
        name = _normalized_name(raw_name)
        if name in result:
            raise BuildPolicyError(f"duplicate release requirement: {name}")
        hashes = tuple(
            item.removeprefix("--hash=sha256:")
            for item in match.group("hashes").split()
        )
        result[name] = (version, hashes)
    return result


def _validate_exact_requirement(requirement: str, *, context: str) -> tuple[str, str]:
    match = EXACT_PROJECT_DEPENDENCY.fullmatch(requirement)
    if (
        match is None
        or SAFE_PROJECT_NAME.fullmatch(match.group("name")) is None
        or SAFE_VERSION.fullmatch(match.group("version")) is None
    ):
        raise BuildPolicyError(f"{context} must be an exact name==version pin: {requirement!r}")
    return _normalized_name(match.group("name")), match.group("version")


def _safe_repository_path(value: str, *, context: str) -> PurePosixPath:
    if "\\" in value or re.match(r"^[A-Za-z]:", value):
        raise BuildPolicyError(f"{context} uses a Windows-style or ambiguous path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BuildPolicyError(f"{context} escapes the repository: {value!r}")
    if path.as_posix() != value:
        raise BuildPolicyError(f"{context} is not a canonical repository path: {value!r}")
    return path


def _metadata_header_value(value: Any, *, context: str) -> str:
    if not isinstance(value, str):
        raise BuildPolicyError(f"{context} must be a string")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        raise BuildPolicyError(
            f"{context} contains a forbidden control character or Unicode separator"
        )
    return value


def discover_projects(
    root: Path, policy: Policy, *, revision: str = "HEAD"
) -> tuple[Project, ...]:
    root = root.resolve()
    entries = _head_entries(root, revision=revision)
    by_path = {entry.path: entry for entry in entries}
    projects: list[Project] = []
    for package_root in policy.package_roots:
        relative_root = package_root.relative_to(root).as_posix()
        prefix = f"{relative_root}/"
        manifests = [
            entry
            for entry in entries
            if entry.path.startswith(prefix) and PurePosixPath(entry.path).name == "pyproject.toml"
        ]
        for manifest in manifests:
            relative_manifest = PurePosixPath(manifest.path).relative_to(relative_root)
            if len(relative_manifest.parts) != 2:
                raise BuildPolicyError(
                    "package manifest must be exactly one directory below its package root: "
                    f"{manifest.path}"
                )
            raw = _read_toml_bytes(_head_blob(root, manifest.object_id), manifest.path)
            project = raw.get("project")
            build = raw.get("build-system")
            if not isinstance(project, dict) or not isinstance(build, dict):
                raise BuildPolicyError(f"missing [project] or [build-system] in {manifest.path}")
            supported_project_fields = {
                "dependencies",
                "description",
                "dynamic",
                "license",
                "license-files",
                "name",
                "optional-dependencies",
                "readme",
                "requires-python",
                "scripts",
                "version",
            }
            unsupported_fields = sorted(set(project) - supported_project_fields)
            if unsupported_fields:
                raise BuildPolicyError(
                    f"unsupported project metadata fields in {manifest.path}: "
                    f"{unsupported_fields}"
                )
            license_value = project.get("license")
            if license_value is not None and license_value != "Apache-2.0":
                raise BuildPolicyError(
                    f"project license must be the string Apache-2.0 in {manifest.path}"
                )
            name = project.get("name")
            version = project.get("version")
            if not isinstance(name, str) or SAFE_PROJECT_NAME.fullmatch(name) is None:
                raise BuildPolicyError(f"invalid project name in {manifest.path}")
            if not isinstance(version, str) or SAFE_VERSION.fullmatch(version) is None:
                raise BuildPolicyError(f"invalid project version in {manifest.path}")
            description = _metadata_header_value(
                project.get("description", ""),
                context=f"project description in {manifest.path}",
            )
            requires_python = _metadata_header_value(
                project.get("requires-python", ""),
                context=f"requires-python in {manifest.path}",
            )
            if requires_python and SAFE_REQUIRES_PYTHON.fullmatch(requires_python) is None:
                raise BuildPolicyError(
                    f"requires-python uses an unsupported specifier in {manifest.path}"
                )
            dependencies = project.get("dependencies", [])
            raw_scripts = project.get("scripts", {})
            optional_dependencies = project.get("optional-dependencies", {})
            dynamic = project.get("dynamic", [])
            build_requirements = build.get("requires", [])
            if not isinstance(dependencies, list) or not all(
                isinstance(item, str) for item in dependencies
            ):
                raise BuildPolicyError(
                    f"project dependencies must be a string list in {manifest.path}"
                )
            if not isinstance(raw_scripts, dict):
                raise BuildPolicyError(
                    f"project scripts must be a string table in {manifest.path}"
                )
            scripts: list[tuple[str, str]] = []
            normalized_script_names: set[str] = set()
            for script_name, script_target in sorted(raw_scripts.items()):
                if (
                    not isinstance(script_name, str)
                    or SAFE_SCRIPT_NAME.fullmatch(script_name) is None
                ):
                    raise BuildPolicyError(
                        f"invalid project script name in {manifest.path}: {script_name!r}"
                    )
                normalized_script_name = script_name.casefold()
                if normalized_script_name in normalized_script_names:
                    raise BuildPolicyError(
                        f"duplicate normalized project script name in {manifest.path}: "
                        f"{script_name!r}"
                    )
                if (
                    not isinstance(script_target, str)
                    or SAFE_SCRIPT_TARGET.fullmatch(script_target) is None
                ):
                    raise BuildPolicyError(
                        f"invalid project script target in {manifest.path}: "
                        f"{script_target!r}"
                    )
                normalized_script_names.add(normalized_script_name)
                scripts.append((script_name, script_target))
            if optional_dependencies not in ({}, None):
                raise BuildPolicyError(
                    f"optional project dependencies are unsupported in {manifest.path}"
                )
            if not isinstance(dynamic, list) or dynamic:
                raise BuildPolicyError(
                    f"dynamic project metadata is unsupported in {manifest.path}"
                )
            if not isinstance(build_requirements, list) or not all(
                isinstance(item, str) for item in build_requirements
            ):
                raise BuildPolicyError(
                    f"build requirements must be a string list in {manifest.path}"
                )
            for item in build_requirements:
                _validate_exact_requirement(item, context=f"build requirement in {manifest.path}")
            project_directory = PurePosixPath(manifest.path).parent
            raw_license_files = project.get("license-files")
            license_files: list[Path] = []
            if not isinstance(raw_license_files, list) or not raw_license_files:
                raise BuildPolicyError(
                    f"project license-files must be a non-empty string list in {manifest.path}"
                )
            else:
                seen_license_names: set[str] = set()
                for raw_license_file in raw_license_files:
                    if not isinstance(raw_license_file, str) or any(
                        token in raw_license_file for token in ("*", "?", "[")
                    ):
                        raise BuildPolicyError(
                            f"project license-files must use exact paths in {manifest.path}"
                        )
                    project_relative_license = _safe_repository_path(
                        raw_license_file,
                        context=f"project-relative license file in {manifest.path}",
                    )
                    if len(project_relative_license.parts) != 1:
                        raise BuildPolicyError(
                            "project license-files must name direct project files in "
                            f"{manifest.path}"
                        )
                    relative_license = _safe_repository_path(
                        f"{project_directory.as_posix()}/"
                        f"{project_relative_license.as_posix()}",
                        context=f"project license file in {manifest.path}",
                    )
                    license_name = relative_license.name
                    if license_name not in {"LICENSE", "NOTICE"}:
                        raise BuildPolicyError(
                            f"project license-files may contain only LICENSE and NOTICE in {manifest.path}"
                        )
                    if relative_license.as_posix() not in by_path:
                        raise BuildPolicyError(
                            f"project license file is missing or unsafe: {relative_license}"
                        )
                    if license_name in seen_license_names:
                        raise BuildPolicyError(
                            f"project license-files contain a duplicate name in {manifest.path}"
                        )
                    seen_license_names.add(license_name)
                    license_files.append(root / relative_license.as_posix())
                if seen_license_names != {"LICENSE", "NOTICE"}:
                    raise BuildPolicyError(
                        f"project license-files must contain LICENSE and NOTICE in {manifest.path}"
                    )
            readme_value = project.get("readme")
            readme: Path | None = None
            readme_content_type: str | None = None
            if isinstance(readme_value, str):
                if any(token in readme_value for token in ("*", "?", "[")):
                    raise BuildPolicyError(
                        f"project readme must use an exact path in {manifest.path}"
                    )
                project_relative_readme = _safe_repository_path(
                    readme_value,
                    context=f"project-relative readme in {manifest.path}",
                )
                if len(project_relative_readme.parts) != 1:
                    raise BuildPolicyError(
                        f"project readme must name a direct project file in {manifest.path}"
                    )
                readme_suffix = PurePosixPath(readme_value).suffix.casefold()
                if readme_suffix == ".md":
                    readme_content_type = "text/markdown"
                elif readme_suffix == ".rst":
                    readme_content_type = "text/x-rst"
                else:
                    raise BuildPolicyError(
                        f"project readme must be a .md or .rst file in {manifest.path}"
                    )
                readme_path = _safe_repository_path(
                    f"{project_directory.as_posix()}/"
                    f"{project_relative_readme.as_posix()}",
                    context=f"project readme in {manifest.path}",
                )
                if readme_path.as_posix() not in by_path:
                    raise BuildPolicyError(f"project readme is missing or unsafe: {readme_path}")
                readme = root / readme_path.as_posix()
            elif readme_value is not None:
                raise BuildPolicyError(
                    f"project readme table forms are unsupported in {manifest.path}"
                )
            projects.append(
                Project(
                    directory=root / project_directory.as_posix(),
                    name=name,
                    version=version,
                    description=description,
                    requires_python=requires_python,
                    dependencies=tuple(dependencies),
                    build_requirements=tuple(build_requirements),
                    readme=readme,
                    readme_content_type=readme_content_type,
                    license_files=tuple(license_files),
                    scripts=tuple(scripts),
                )
            )
    names = [_normalized_name(project.name) for project in projects]
    if len(names) != len(set(names)):
        raise BuildPolicyError("discovered package names must be unique")
    script_owners: dict[str, str] = {}
    for project in projects:
        for script_name, _ in project.scripts:
            normalized_script_name = script_name.casefold()
            previous = script_owners.setdefault(normalized_script_name, project.name)
            if previous != project.name:
                raise BuildPolicyError(
                    "console script names must be unique across projects: "
                    f"{script_name!r} is declared by {previous!r} and {project.name!r}"
                )
    return tuple(projects)


def parse_release_dependency_graph(
    path: Path,
    lock: dict[str, tuple[str, tuple[str, ...]]],
    *,
    root: Path | None = None,
    revision: str = "HEAD",
) -> dict[str, tuple[str, ...]]:
    try:
        if root is None:
            data = path.read_bytes()
        else:
            relative = path.relative_to(root.resolve()).as_posix()
            data = _head_blob_for_path(root.resolve(), relative, revision=revision)
        raw = json.loads(data, object_pairs_hook=_unique_json_object)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise BuildPolicyError(f"cannot read release dependency graph {path}: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "packages"}:
        raise BuildPolicyError("release dependency graph has unexpected top-level fields")
    if raw["schema_version"] != 1 or not isinstance(raw["packages"], dict):
        raise BuildPolicyError("release dependency graph must use schema_version = 1")

    graph: dict[str, tuple[str, ...]] = {}
    for raw_requirement, raw_dependencies in raw["packages"].items():
        if not isinstance(raw_requirement, str) or not isinstance(raw_dependencies, list):
            raise BuildPolicyError("release dependency graph entries must map pins to lists")
        name, version = _validate_exact_requirement(
            raw_requirement, context="release dependency graph package"
        )
        if name in graph:
            raise BuildPolicyError(f"duplicate release dependency graph package: {name}")
        if lock.get(name, (None, ()))[0] != version:
            raise BuildPolicyError(
                f"release dependency graph package does not match lock: {raw_requirement}"
            )
        dependencies: list[str] = []
        for raw_dependency in raw_dependencies:
            if not isinstance(raw_dependency, str):
                raise BuildPolicyError("release dependency graph pins must be strings")
            dependency_name, dependency_version = _validate_exact_requirement(
                raw_dependency,
                context=f"dependency of {raw_requirement}",
            )
            if lock.get(dependency_name, (None, ()))[0] != dependency_version:
                raise BuildPolicyError(
                    "release dependency graph edge does not match lock: "
                    f"{raw_requirement} -> {raw_dependency}"
                )
            dependencies.append(dependency_name)
        if len(dependencies) != len(set(dependencies)):
            raise BuildPolicyError(
                f"release dependency graph has duplicate edges for {raw_requirement}"
            )
        graph[name] = tuple(sorted(dependencies))
    if set(graph) != set(lock):
        raise BuildPolicyError(
            "release dependency graph packages do not exactly match the release lock"
        )
    return graph


def validate_project_dependencies(
    projects: tuple[Project, ...],
    lock: dict[str, tuple[str, tuple[str, ...]]],
    dependency_graph: dict[str, tuple[str, ...]],
) -> None:
    internal = {_normalized_name(project.name): project.version for project in projects}
    collisions = sorted(set(internal) & set(lock))
    if collisions:
        raise BuildPolicyError(
            "release lock collides with internal project names: "
            f"{collisions}"
        )
    required: dict[str, str] = {}
    for project in projects:
        runtime_names: set[str] = set()
        for item in project.dependencies:
            name, version = _validate_exact_requirement(
                item, context=f"runtime dependency for {project.name}"
            )
            if name in runtime_names:
                raise BuildPolicyError(
                    f"duplicate runtime dependency for {project.name}: {name}"
                )
            runtime_names.add(name)
            if name in internal:
                if version != internal[name]:
                    raise BuildPolicyError(
                        f"internal dependency version mismatch for {name}: "
                        f"expected {internal[name]}, found {version}"
                    )
                continue
            previous = required.setdefault(name, version)
            if previous != version:
                raise BuildPolicyError(
                    f"conflicting runtime pins for {name}: {previous}, {version}"
                )
        build_names: set[str] = set()
        for item in project.build_requirements:
            name, version = _validate_exact_requirement(
                item, context=f"build requirement for {project.name}"
            )
            if name in build_names:
                raise BuildPolicyError(
                    f"duplicate build requirement for {project.name}: {name}"
                )
            build_names.add(name)
            if name in internal and version != internal[name]:
                raise BuildPolicyError(
                    f"internal build dependency version mismatch for {name}: "
                    f"expected {internal[name]}, found {version}"
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
    reachable = set(required)
    pending = list(required)
    while pending:
        current = pending.pop()
        for dependency in dependency_graph.get(current, ()):
            if dependency not in reachable:
                reachable.add(dependency)
                pending.append(dependency)
    unexpected = sorted(set(lock) - reachable)
    if unexpected:
        raise BuildPolicyError(
            f"release lock contains dependencies unused by distributable packages: {unexpected}"
        )


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    if epoch < MINIMUM_ZIP_EPOCH:
        raise BuildPolicyError("SOURCE_DATE_EPOCH predates the ZIP format minimum")
    return datetime.fromtimestamp(epoch, UTC).timetuple()[:6]


def _wheel_files(
    root: Path, project: Project, *, revision: str = "HEAD"
) -> dict[str, bytes]:
    source = project.directory.relative_to(root) / "src"
    prefix = f"{source.as_posix()}/"
    files: dict[str, bytes] = {}
    forbidden_suffixes = {
        ".a",
        ".bc",
        ".dll",
        ".dylib",
        ".exe",
        ".lib",
        ".o",
        ".obj",
        ".pyd",
        ".so",
    }
    native_magic = (
        b"\x7fELF",
        b"MZ",
        b"!<arch>\n",
        b"!<thin>\n",
        b"BC\xc0\xde",
        b"\xde\xc0\x17\x0b",
        b"\x00\x00\xff\xff",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    )
    coff_machines = {
        0x014C,
        0x0166,
        0x0169,
        0x01A2,
        0x01A3,
        0x01A6,
        0x01A8,
        0x01C0,
        0x01C2,
        0x01C4,
        0x01D3,
        0x01F0,
        0x01F1,
        0x0200,
        0x0266,
        0x0366,
        0x0466,
        0x0EBC,
        0x5032,
        0x5064,
        0x5128,
        0x6232,
        0x6264,
        0x8664,
        0x9041,
        0xAA64,
    }
    for entry in _head_entries(root, revision=revision):
        if not entry.path.startswith(prefix):
            continue
        relative = entry.path.removeprefix(prefix)
        relative_path = PurePosixPath(relative)
        if "__pycache__" in relative_path.parts or relative_path.suffix in {".pyc", ".pyo"}:
            continue
        data = _head_blob(root, entry.object_id)
        filename = relative_path.name.casefold()
        if (
            relative_path.suffix.casefold() in forbidden_suffixes
            or re.fullmatch(r".+\.so(?:\..+)?", filename) is not None
            or data.startswith(native_magic)
            or (
                len(data) >= 20
                and int.from_bytes(data[:2], byteorder="little") in coff_machines
            )
        ):
            raise BuildPolicyError(
                f"native or executable wheel content is unsupported: {entry.path}"
            )
        files[relative] = data
    if not files:
        raise BuildPolicyError(f"project has no source files: {project.name}")
    return files


def build_wheel(
    root: Path,
    project: Project,
    policy: Policy,
    epoch: int,
    *,
    revision: str = "HEAD",
) -> tuple[str, bytes]:
    files = _wheel_files(root, project, revision=revision)
    for script_name, script_target in project.scripts:
        module_name, _ = script_target.split(":", 1)
        module_path = module_name.replace(".", "/")
        if (
            f"{module_path}.py" not in files
            and f"{module_path}/__init__.py" not in files
        ):
            raise BuildPolicyError(
                f"console script {script_name!r} targets a module outside its wheel: "
                f"{module_name!r}"
            )
    distribution = _wheel_name(project.name)
    version = _wheel_version(project.version)
    dist_info = f"{distribution}-{version}.dist-info"
    installer_control_paths: list[str] = []
    for name in files:
        parts = PurePosixPath(name).parts
        folded = tuple(part.casefold() for part in parts)
        top_level = folded[0]
        if (
            any(
                part.endswith((".dist-info", ".egg-info"))
                for part in folded
            )
            or top_level.endswith((".data", ".egg"))
            or top_level.endswith((".pth", ".egg-link"))
            or top_level
            in {
                "sitecustomize",
                "sitecustomize.py",
                "usercustomize",
                "usercustomize.py",
            }
        ):
            installer_control_paths.append(name)
    if installer_control_paths:
        raise BuildPolicyError(
            "tracked source may not provide installer-control wheel paths: "
            f"{sorted(installer_control_paths)}"
        )
    wheel_license_files = project.license_files or policy.license_files
    if project.license_files:
        license_metadata_paths = tuple(
            license_path.relative_to(project.directory).as_posix()
            for license_path in wheel_license_files
        )
    else:
        license_metadata_paths = tuple(
            license_path.name for license_path in wheel_license_files
        )
    metadata = [
        "Metadata-Version: 2.4",
        f"Name: {project.name}",
        f"Version: {project.version}",
    ]
    if project.description:
        metadata.append(f"Summary: {project.description}")
    if project.requires_python:
        metadata.append(f"Requires-Python: {project.requires_python}")
    metadata.append("License-Expression: Apache-2.0")
    metadata.extend(f"License-File: {path}" for path in license_metadata_paths)
    for dependency in project.dependencies:
        metadata.append(f"Requires-Dist: {dependency}")
    if project.readme is not None:
        try:
            readme = _head_blob_for_path(
                root,
                project.readme.relative_to(root).as_posix(),
                revision=revision,
            ).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BuildPolicyError(f"project readme is not UTF-8: {project.readme}") from exc
        metadata.extend(
            [
                f"Description-Content-Type: {project.readme_content_type}",
                "",
                readme,
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
    if project.scripts:
        entry_points = ["[console_scripts]"]
        entry_points.extend(
            f"{script_name} = {script_target}"
            for script_name, script_target in project.scripts
        )
        files[f"{dist_info}/entry_points.txt"] = (
            "\n".join(entry_points) + "\n"
        ).encode()
    for license_path, metadata_path in zip(
        wheel_license_files, license_metadata_paths, strict=True
    ):
        relative_license = license_path.relative_to(root).as_posix()
        files[f"{dist_info}/licenses/{metadata_path}"] = _head_blob_for_path(
            root, relative_license, revision=revision
        )

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


@overload
def _git(
    root: Path, *arguments: str, binary: Literal[True]
) -> bytes: ...


@overload
def _git(
    root: Path, *arguments: str, binary: Literal[False] = False
) -> str: ...


def _git(root: Path, *arguments: str, binary: bool = False) -> bytes | str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment["GIT_NO_LAZY_FETCH"] = "1"
    result = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-c",
            "core.quotepath=false",
            "-c",
            "core.fsmonitor=false",
            *arguments,
        ],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=not binary,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace") if binary else result.stderr
        raise BuildPolicyError(f"git {' '.join(arguments)} failed: {stderr.strip()}")
    return result.stdout


def _git_object_bytes(root: Path, object_id: str, expected_type: str) -> bytes:
    if re.fullmatch(r"[0-9a-f]{40}", object_id) is None:
        raise BuildPolicyError("Git object ID must be a full lowercase SHA-1 digest")
    actual_type = str(_git(root, "cat-file", "-t", object_id)).strip()
    if actual_type != expected_type:
        raise BuildPolicyError(
            f"Git object type mismatch for {object_id}: "
            f"expected {expected_type}, found {actual_type}"
        )
    data = bytes(_git(root, "cat-file", expected_type, object_id, binary=True))
    header = f"{expected_type} {len(data)}\0".encode("ascii")
    actual_id = hashlib.sha1(header + data, usedforsecurity=False).hexdigest()
    if actual_id != object_id:
        raise BuildPolicyError(
            f"Git {expected_type} object content does not match its ID: {object_id}"
        )
    return data


def git_identity(root: Path, *, revision: str = "HEAD") -> dict[str, str]:
    commit = str(_git(root, "rev-parse", "--verify", f"{revision}^{{commit}}")).strip()
    commit_data = _git_object_bytes(root, commit, "commit")
    tree_match = re.match(rb"tree ([0-9a-f]{40})\n", commit_data)
    if tree_match is None:
        raise BuildPolicyError("Git commit has no canonical root tree header")
    tree = tree_match.group(1).decode("ascii")
    _git_object_bytes(root, tree, "tree")
    return {"commit": commit, "tree": tree}


def git_commit_epoch(root: Path, *, revision: str) -> int:
    commit = git_identity(root, revision=revision)["commit"]
    commit_data = _git_object_bytes(root, commit, "commit")
    committer = next(
        (line for line in commit_data.splitlines() if line.startswith(b"committer ")),
        None,
    )
    if committer is None:
        raise BuildPolicyError("Git commit has no committer header")
    fields = committer.rsplit(b" ", 2)
    if len(fields) != 3 or re.fullmatch(rb"[0-9]+", fields[1]) is None:
        raise BuildPolicyError("Git commit time is not an unsigned integer")
    return int(fields[1])


def require_clean_checkout(root: Path) -> None:
    replace_refs = str(
        _git(root, "for-each-ref", "--format=%(refname)", "refs/replace/")
    ).strip()
    if replace_refs:
        raise BuildPolicyError("Git replace refs are forbidden in a build checkout")
    common_directory = Path(str(_git(root, "rev-parse", "--git-common-dir")).strip())
    if not common_directory.is_absolute():
        common_directory = (root / common_directory).resolve()
    if (common_directory / "info/grafts").exists():
        raise BuildPolicyError("legacy Git grafts are forbidden in a build checkout")
    flags = bytes(_git(root, "ls-files", "-v", "-z", binary=True))
    for raw in flags.split(b"\0"):
        if raw and not raw.startswith(b"H "):
            display = raw.decode("utf-8", errors="replace")
            raise BuildPolicyError(f"tracked index flag is forbidden: {display}")
    status = str(_git(root, "status", "--porcelain=v1", "--untracked-files=all"))
    if status:
        raise BuildPolicyError("build requires a clean checkout")
    _head_entries(root)


def _head_entries(root: Path, *, revision: str = "HEAD") -> tuple[TrackedFile, ...]:
    source = git_identity(root, revision=revision)
    entries: list[TrackedFile] = []
    pending: list[tuple[str, tuple[str, ...]]] = [(source["tree"], ())]
    logical_paths: set[str] = set()
    while pending:
        tree_id, prefix = pending.pop()
        data = _git_object_bytes(root, tree_id, "tree")
        offset = 0
        previous_sort_key: bytes | None = None
        local_names: set[bytes] = set()
        while offset < len(data):
            separator = data.find(b" ", offset)
            terminator = data.find(b"\0", separator + 1)
            if (
                separator <= offset
                or terminator <= separator + 1
                or terminator + 21 > len(data)
            ):
                raise BuildPolicyError("Git tree object has malformed binary framing")
            mode_raw = data[offset:separator]
            name_raw = data[separator + 1 : terminator]
            object_id = data[terminator + 1 : terminator + 21].hex()
            offset = terminator + 21
            is_tree = mode_raw == b"40000"
            if mode_raw not in {b"40000", b"100644", b"100755"}:
                display = name_raw.decode("utf-8", errors="replace")
                raise BuildPolicyError(
                    "tracked symlink or gitlink is forbidden in source archive: "
                    f"{'/'.join((*prefix, display))}"
                )
            if (
                not name_raw
                or name_raw in {b".", b".."}
                or b"/" in name_raw
                or b"\\" in name_raw
            ):
                raise BuildPolicyError("Git tree entries must use basename-only names")
            sort_key = name_raw + (b"/" if is_tree else b"\0")
            if previous_sort_key is not None and sort_key <= previous_sort_key:
                raise BuildPolicyError("Git tree entries are not canonically ordered")
            previous_sort_key = sort_key
            if name_raw in local_names:
                raise BuildPolicyError("Git tree contains duplicate logical paths")
            local_names.add(name_raw)
            try:
                name = name_raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BuildPolicyError("Git tree path is not valid UTF-8") from exc
            path = "/".join((*prefix, name))
            _safe_repository_path(path, context="tracked source path")
            if path in logical_paths:
                raise BuildPolicyError(f"Git tree contains duplicate logical path: {path}")
            logical_paths.add(path)
            if is_tree:
                pending.append((object_id, (*prefix, name)))
                continue
            _git_object_bytes(root, object_id, "blob")
            entries.append(
                TrackedFile(
                    mode=mode_raw.decode("ascii"),
                    path=path,
                    object_id=object_id,
                )
            )
    return tuple(sorted(entries, key=lambda item: item.path))


def _head_blob(root: Path, object_id: str) -> bytes:
    return _git_object_bytes(root, object_id, "blob")


def _head_blob_for_path(root: Path, path: str, *, revision: str = "HEAD") -> bytes:
    for entry in _head_entries(root, revision=revision):
        if entry.path == path:
            return _head_blob(root, entry.object_id)
    raise BuildPolicyError(f"tracked source file is missing from HEAD: {path}")


def build_source_archive(
    root: Path, epoch: int, *, revision: str = "HEAD"
) -> tuple[str, bytes]:
    entries = _head_entries(root, revision=revision)
    raw_tar = io.BytesIO()
    prefix = "faultloom-core"
    directories = {prefix}
    for entry in entries:
        parts = PurePosixPath(entry.path).parts[:-1]
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
        for entry in entries:
            data = _head_blob(root, entry.object_id)
            info = tarfile.TarInfo(f"{prefix}/{entry.path}")
            info.size = len(data)
            info.mode = 0o755 if entry.mode == "100755" else 0o644
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


def _gateway_recipe(gateway: GatewayPolicy) -> dict[str, Any]:
    return {
        "builder": "cargo",
        "command": [
            "build",
            "--manifest-path",
            "<immutable-source>/Cargo.toml",
            "--package",
            gateway.package,
            "--bin",
            gateway.binary,
            "--release",
            "--frozen",
            "--locked",
            "--offline",
            "--target",
            gateway.target,
        ],
        "environment": {
            "CARGO_HOME": "<private-empty-directory>",
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": "<private-target-directory>",
            "HOME": "<private-empty-directory>",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "RUSTC": "<content-verified-staged-rustc>",
            "RUSTFLAGS": "--remap-path-prefix=<immutable-source>=/faultloom-core",
            "SOURCE_DATE_EPOCH": "<git-commit-epoch>",
            "TZ": "UTC",
        },
        "network": "offline_requested_not_os_enforced",
        "source": "verified_immutable_git_tree",
        "working_directory": "/",
    }


def _materialize_source_archive(source_archive: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if (
                not path.parts
                or path.parts[0] != "faultloom-core"
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise BuildPolicyError("source archive has an unsafe Gateway build path")
            relative = path.parts[1:]
            target = destination.joinpath(*relative)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise BuildPolicyError("source archive has a non-regular Gateway build input")
            source = archive.extractfile(member)
            if source is None:
                raise BuildPolicyError("cannot read a Gateway build input from source archive")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(source.read())
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def _read_gateway_elf(path: Path, *, target: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BuildPolicyError(f"cannot open the Gateway build output safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size == 0:
            raise BuildPolicyError("Gateway build output is not a non-empty regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise BuildPolicyError("Gateway build output changed while it was being read")
    if stat.S_IMODE(before.st_mode) & 0o111 == 0:
        raise BuildPolicyError("Gateway build output is not executable")
    data = b"".join(chunks)
    if target != "x86_64-unknown-linux-gnu":
        raise BuildPolicyError("Gateway ELF validation supports only the admitted Linux target")
    if (
        len(data) < 64
        or data[:4] != b"\x7fELF"
        or data[4] != 2
        or data[5] != 1
        or int.from_bytes(data[16:18], "little") not in {2, 3}
        or int.from_bytes(data[18:20], "little") != 0x3E
        or int.from_bytes(data[20:24], "little") != 1
    ):
        raise BuildPolicyError("Gateway build output is not an x86-64 little-endian ELF")
    return data


def _require_gateway_toolchain(
    policy: Policy, toolchain: StagedRustToolchain | None
) -> StagedRustToolchain:
    if policy.gateway is None:
        raise BuildPolicyError("internal error: Gateway toolchain requested without policy")
    if toolchain is None or toolchain.cargo is None:
        raise BuildPolicyError(
            "Gateway artifacts require the content-verified staged Rust and Cargo toolchain"
        )
    expected = rust_toolchain_spec(policy)
    if toolchain.spec != expected:
        raise BuildPolicyError("Gateway toolchain does not match the immutable build policy")
    for name, path, digest in (
        ("rustc", toolchain.rustc, expected.rustc_sha256),
        ("cargo", toolchain.cargo, expected.cargo_sha256),
    ):
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            raise BuildPolicyError(f"Gateway {name} is not a regular absolute staged file")
        if digest is None or sha256_file(path) != digest:
            raise BuildPolicyError(f"Gateway {name} digest changed before the build")
    if toolchain.cargo.parent.parent != toolchain.rustc.parent.parent:
        raise BuildPolicyError("Gateway Cargo and rustc do not share one staged toolchain")
    if rustc_closure_sha256(toolchain.rustc, expected.host) != expected.rustc_closure_sha256:
        raise BuildPolicyError("Gateway staged Rust closure changed before the build")
    return toolchain


def build_gateway_release(
    root: Path,
    policy: Policy,
    epoch: int,
    *,
    revision: str,
    source: dict[str, str],
    source_archive: bytes,
    toolchain: StagedRustToolchain | None,
) -> tuple[str, bytes, NativeArtifact]:
    gateway = policy.gateway
    if gateway is None:
        raise BuildPolicyError("internal error: Gateway build requested without policy")
    admitted = _require_gateway_toolchain(policy, toolchain)
    cargo = admitted.cargo
    if cargo is None:
        raise BuildPolicyError("internal error: admitted Gateway toolchain lacks Cargo")
    for ambient in (Path("/.cargo/config"), Path("/.cargo/config.toml")):
        if ambient.exists():
            raise BuildPolicyError(
                f"ambient root Cargo configuration prevents an isolated build: {ambient}"
            )
    with tempfile.TemporaryDirectory(prefix="faultloom-gateway-build-") as raw:
        build_root = Path(raw)
        snapshot = build_root / "immutable-source"
        snapshot.mkdir()
        _materialize_source_archive(source_archive, snapshot)
        cargo_home = build_root / "cargo-home"
        target_dir = build_root / "target"
        home = build_root / "home"
        cargo_home.mkdir()
        target_dir.mkdir()
        home.mkdir()
        environment = {
            "CARGO_HOME": str(cargo_home),
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(target_dir),
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "RUSTC": str(admitted.rustc),
            "RUSTFLAGS": f"--remap-path-prefix={snapshot}=/faultloom-core",
            "SOURCE_DATE_EPOCH": str(epoch),
            "TZ": "UTC",
        }
        command = [
            str(cargo),
            "build",
            "--manifest-path",
            str(snapshot / "Cargo.toml"),
            "--package",
            gateway.package,
            "--bin",
            gateway.binary,
            "--release",
            "--frozen",
            "--locked",
            "--offline",
            "--target",
            gateway.target,
        ]
        result = subprocess.run(
            command,
            cwd=snapshot,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise BuildPolicyError(
                "locked offline Gateway build failed: "
                f"{result.stdout}{result.stderr}"
            )
        binary = target_dir / gateway.target / "release" / gateway.binary
        data = _read_gateway_elf(binary, target=gateway.target)
        lock_sha256 = _sha256((snapshot / "Cargo.lock").read_bytes())
    if sha256_file(admitted.rustc) != policy.rustc_sha256:
        raise BuildPolicyError("Gateway staged rustc changed during the build")
    if sha256_file(cargo) != gateway.cargo_sha256:
        raise BuildPolicyError("Gateway staged Cargo changed during the build")
    if rustc_closure_sha256(admitted.rustc, policy.rustc_host) != policy.rustc_closure_sha256:
        raise BuildPolicyError("Gateway staged Rust closure changed during the build")

    artifact_name = f"{gateway.binary}-{gateway.version}-{gateway.target}"
    recipe_sha256 = _sha256(_canonical_json(_gateway_recipe(gateway)))
    native = NativeArtifact(
        artifact_name=artifact_name,
        component_name=gateway.package,
        version=gateway.version,
        target=gateway.target,
        purl=f"pkg:cargo/{gateway.package}@{gateway.version}",
        sha256=_sha256(data),
        size=len(data),
        source_commit=source["commit"],
        source_tree=source["tree"],
        cargo_lock_sha256=lock_sha256,
        recipe_sha256=recipe_sha256,
        rustc_sha256=policy.rustc_sha256,
        rustc_closure_sha256=policy.rustc_closure_sha256,
        cargo_sha256=gateway.cargo_sha256,
        host_environment_verification="linker_libc_kernel_unverified",
    )
    return artifact_name, data, native


def _component(project: Project) -> dict[str, Any]:
    return {
        "name": project.name,
        "version": project.version,
        "dependencies": list(project.dependencies),
        "purl": f"pkg:pypi/{_normalized_name(project.name)}@{project.version}",
    }


def _native_component(artifact: NativeArtifact) -> dict[str, Any]:
    return {
        "artifact_name": artifact.artifact_name,
        "component_name": artifact.component_name,
        "version": artifact.version,
        "target": artifact.target,
        "purl": artifact.purl,
        "sha256": artifact.sha256,
        "size": artifact.size,
        "source_commit": artifact.source_commit,
        "source_tree": artifact.source_tree,
        "cargo_lock_sha256": artifact.cargo_lock_sha256,
        "recipe_sha256": artifact.recipe_sha256,
        "rustc_sha256": artifact.rustc_sha256,
        "rustc_closure_sha256": artifact.rustc_closure_sha256,
        "cargo_sha256": artifact.cargo_sha256,
        "host_environment_verification": artifact.host_environment_verification,
    }


def make_build_context(
    root: Path,
    policy: Policy,
    projects: tuple[Project, ...],
    lock: dict[str, tuple[str, tuple[str, ...]]],
    dependency_graph: dict[str, tuple[str, ...]],
    artifacts: dict[str, bytes],
    epoch: int,
    *,
    source: dict[str, str] | None = None,
    native_artifacts: tuple[NativeArtifact, ...] = (),
) -> dict[str, Any]:
    source_identity = git_identity(root) if source is None else dict(source)
    native_context = [_native_component(item) for item in native_artifacts]
    cargo_graph = None
    if policy.cargo_vendor is not None:
        revision = source_identity["commit"]
        entries = {
            entry.path: entry for entry in _head_entries(root.resolve(), revision=revision)
        }

        def head_bytes(path: str) -> bytes:
            entry = entries.get(path)
            if entry is None:
                raise BuildPolicyError(f"required Cargo vendor file is missing: {path}")
            return _head_blob(root.resolve(), entry.object_id)

        cargo_graph = _cargo_graph_from_snapshot(
            policy,
            entries=entries,
            head_bytes=head_bytes,
        )
    return {
        "schema_version": 3,
        "builder": BUILDER_ID,
        "source_date_epoch": epoch,
        "source": source_identity,
        "toolchains": {
            "python": policy.python_version,
            "python_runtime_verification": policy.python_runtime_verification,
            "rust": policy.rust_version,
            "rustc_host": policy.rustc_host,
            "rustc_sha256": policy.rustc_sha256,
            "rustc_closure_sha256": policy.rustc_closure_sha256,
            "cargo_sha256": (
                None if policy.gateway is None else policy.gateway.cargo_sha256
            ),
            "rust_runtime_verification": (
                "rustc_cargo_closure_digests_and_locked_offline_build_verified"
                if native_artifacts
                else "policy_declared_unverified"
            ),
            "host_environment_verification": (
                "linker_libc_kernel_unverified" if native_artifacts else "not_used"
            ),
        },
        "ci_policy": {
            "workflow": ".github/workflows/ci.yml",
            "workflow_sha256": _sha256(canonical_ci_workflow(policy.rust_version)),
            "validation": "byte_exact_repository_self_check",
            "external_trust_anchor": policy.ci_external_trust_anchor,
        },
        "network": {
            "mode": NETWORK_EXECUTION["mode"],
            "enforced": NETWORK_EXECUTION["enforced"],
            "controls": list(NETWORK_EXECUTION["controls"]),
        },
        "dependency_graph": {
            "source": policy.release_dependency_graph.relative_to(root).as_posix(),
            "verification": (
                "declared_unverified" if lock else "complete_no_external_dependencies"
            ),
        },
        "components": [_component(project) for project in projects],
        "native_artifacts": native_context,
        "cargo_vendor": None if cargo_graph is None else cargo_graph.context(),
        "locked_dependencies": [
            {
                "name": name,
                "version": version,
                "sha256": list(hashes),
                "hash_verification": "declared_unverified",
                "dependencies": [
                    f"{dependency}=={lock[dependency][0]}"
                    for dependency in dependency_graph[name]
                ],
            }
            for name, (version, hashes) in sorted(lock.items())
        ],
        "subjects": [
            {"name": name, "sha256": _sha256(data), "size": len(data)}
            for name, data in sorted(artifacts.items())
        ],
    }


def _set_and_verify_artifact_mode(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
        actual_mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise BuildPolicyError(
            f"cannot enforce artifact mode for {path.name}: {exc}"
        ) from exc
    if actual_mode != mode:
        raise BuildPolicyError(
            f"artifact mode mismatch for {path.name}: "
            f"expected {mode:04o}, found {actual_mode:04o}"
        )


def _run_metadata_hook(
    *,
    root: Path,
    hook: Path,
    kind: str,
    context_path: Path,
    output_path: Path,
    revision: str = "HEAD",
) -> None:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1",
        "UV_OFFLINE": "1",
        "CARGO_NET_OFFLINE": "true",
    }
    with tempfile.TemporaryDirectory(prefix=f"faultloom-{kind}-hook-") as raw_hook:
        hook_root = Path(raw_hook)
        immutable_hook = hook_root / "tools/build_metadata_hook.py"
        immutable_hook.parent.mkdir()
        immutable_hook.write_bytes(
            _head_blob_for_path(root, hook.relative_to(root).as_posix(), revision=revision)
        )
        for helper in ("tools/cargo_sbom.py", "tools/cargo_vendor_policy.py"):
            helper_path = hook_root / helper
            helper_path.write_bytes(_head_blob_for_path(root, helper, revision=revision))
        immutable_hook.chmod(0o700)
        result = subprocess.run(
            [
                sys.executable,
                str(immutable_hook),
                kind,
                str(context_path),
                str(output_path),
            ],
            cwd=hook_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        raise BuildPolicyError(f"{kind} hook failed: {result.stderr.strip()}")
    if not output_path.is_file():
        raise BuildPolicyError(f"{kind} hook did not create its output")
    _set_and_verify_artifact_mode(output_path, 0o644)
    try:
        value = json.loads(
            output_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, ValueError) as exc:
        raise BuildPolicyError(f"{kind} hook produced invalid JSON") from exc
    if kind == "sbom" and value.get("bomFormat") != "CycloneDX":
        raise BuildPolicyError("SBOM hook output is not CycloneDX")
    if kind == "provenance" and value.get("_type") != "https://in-toto.io/Statement/v1":
        raise BuildPolicyError("provenance hook output is not an in-toto statement")


def render_metadata_from_head(
    *,
    root: Path,
    hook: Path,
    kind: str,
    context: dict[str, Any],
    revision: str,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix=f"faultloom-{kind}-render-") as raw:
        directory = Path(raw)
        context_path = directory / "context.json"
        output_path = directory / f"{kind}.json"
        context_path.write_bytes(_canonical_json(context))
        _run_metadata_hook(
            root=root,
            hook=hook,
            kind=kind,
            context_path=context_path,
            output_path=output_path,
            revision=revision,
        )
        return output_path.read_bytes()


def _write_artifact(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    _set_and_verify_artifact_mode(path, mode)


def build_primary_artifacts(
    root: Path,
    policy: Policy,
    projects: tuple[Project, ...],
    epoch: int,
    *,
    revision: str,
    source: dict[str, str],
    toolchain: StagedRustToolchain | None,
) -> tuple[dict[str, bytes], dict[str, int], tuple[NativeArtifact, ...]]:
    artifacts: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    for project in projects:
        name, data = build_wheel(root, project, policy, epoch, revision=revision)
        artifacts[name] = data
        modes[name] = 0o644
    source_name, source_data = build_source_archive(root, epoch, revision=revision)
    artifacts[source_name] = source_data
    modes[source_name] = 0o644
    native: tuple[NativeArtifact, ...] = ()
    if policy.gateway is not None:
        name, data, descriptor = build_gateway_release(
            root,
            policy,
            epoch,
            revision=revision,
            source=source,
            source_archive=source_data,
            toolchain=toolchain,
        )
        if name in artifacts:
            raise BuildPolicyError(f"duplicate primary artifact name: {name}")
        artifacts[name] = data
        modes[name] = 0o755
        native = (descriptor,)
    return artifacts, modes, native


def build_once(
    root: Path,
    output: Path,
    epoch: int,
    *,
    release: bool = False,
    revision: str | None = None,
    toolchain: StagedRustToolchain | None = None,
) -> dict[str, str]:
    root = root.resolve()
    output = output.resolve()
    require_clean_checkout(root)
    source = git_identity(root, revision="HEAD" if revision is None else revision)
    revision = source["commit"]
    policy = load_policy(root, revision=revision)
    validate_repository_policy(root, policy, revision=revision)
    if release:
        if not policy.release_enabled:
            raise BuildPolicyError(
                "release mode is disabled until the T41 signed authorization gate is integrated"
            )
        if not NETWORK_EXECUTION["enforced"]:
            raise BuildPolicyError(
                "release requires enforced network isolation; offline flags are insufficient"
            )
        raise BuildPolicyError(
            "release authorization verifier is not implemented; refusing release"
        )
    lock = parse_release_lock(policy.release_lock, root=root, revision=revision)
    dependency_graph = parse_release_dependency_graph(
        policy.release_dependency_graph, lock, root=root, revision=revision
    )
    projects = discover_projects(root, policy, revision=revision)
    validate_project_dependencies(projects, lock, dependency_graph)
    if output.exists() and any(output.iterdir()):
        raise BuildPolicyError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    artifacts, artifact_modes, native_artifacts = build_primary_artifacts(
        root,
        policy,
        projects,
        epoch,
        revision=revision,
        source=source,
        toolchain=toolchain,
    )
    for name, data in sorted(artifacts.items()):
        _write_artifact(output / name, data, mode=artifact_modes[name])

    context = make_build_context(
        root,
        policy,
        projects,
        lock,
        dependency_graph,
        artifacts,
        epoch,
        source=source,
        native_artifacts=native_artifacts,
    )
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
            revision=revision,
        )
        _run_metadata_hook(
            root=root,
            hook=policy.provenance_hook,
            kind="provenance",
            context_path=context_path,
            output_path=provenance,
            revision=revision,
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


def _directory_bytes(directory: Path) -> dict[str, tuple[int, bytes]]:
    return {
        path.relative_to(directory).as_posix(): (
            stat.S_IMODE(path.stat().st_mode),
            path.read_bytes(),
        )
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def build_reproducibly(
    root: Path,
    output: Path,
    epoch: int,
    *,
    release: bool = False,
    revision: str | None = None,
    toolchain: StagedRustToolchain | None = None,
) -> dict[str, str]:
    root = root.resolve()
    require_clean_checkout(root)
    source = git_identity(root, revision="HEAD" if revision is None else revision)
    revision = source["commit"]
    with (
        tempfile.TemporaryDirectory(prefix="faultloom-build-a-") as first_raw,
        tempfile.TemporaryDirectory(prefix="faultloom-build-b-") as second_raw,
    ):
        first = Path(first_raw)
        second = Path(second_raw)
        first_manifest = build_once(
            root,
            first,
            epoch,
            release=release,
            revision=revision,
            toolchain=toolchain,
        )
        second_manifest = build_once(
            root,
            second,
            epoch,
            release=release,
            revision=revision,
            toolchain=toolchain,
        )
        if _directory_bytes(first) != _directory_bytes(second):
            raise BuildPolicyError("two builds from the same checkout were not byte-identical")
        if output.exists() and any(output.iterdir()):
            raise BuildPolicyError(f"output directory is not empty: {output}")
        output.mkdir(parents=True, exist_ok=True)
        for path in sorted(first.iterdir()):
            if path.is_file():
                target = output / path.name
                expected_mode = stat.S_IMODE(path.stat().st_mode)
                shutil.copyfile(path, target)
                _set_and_verify_artifact_mode(target, expected_mode)
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
    parser.add_argument(
        "--rust-toolchain",
        default=os.environ.get("FAULTLOOM_RUST_TOOLCHAIN", "stable"),
        help="preinstalled rustup alias; content must match build-policy.toml",
    )
    args = parser.parse_args()
    try:
        epoch = _epoch_from_args(args.source_date_epoch)
        root = args.root.resolve()
        require_clean_checkout(root)
        source = git_identity(root)
        policy = load_policy(root, revision=source["commit"])
        validate_repository_policy(root, policy, revision=source["commit"])

        def run(toolchain: StagedRustToolchain | None) -> dict[str, str]:
            if args.verify_reproducible:
                return build_reproducibly(
                    root,
                    args.out,
                    epoch,
                    release=args.release,
                    revision=source["commit"],
                    toolchain=toolchain,
                )
            return build_once(
                root,
                args.out,
                epoch,
                release=args.release,
                revision=source["commit"],
                toolchain=toolchain,
            )

        if policy.gateway is None:
            manifest = run(None)
        else:
            environment = os.environ.copy()
            environment["CARGO_NET_OFFLINE"] = "true"
            with stage_verified_toolchain(
                rust_toolchain_spec(policy),
                alias=args.rust_toolchain,
                environment=environment,
                root=root,
            ) as toolchain:
                manifest = run(toolchain)
    except (BuildPolicyError, RustToolchainError) as exc:
        print(f"build refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "artifacts": manifest}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
