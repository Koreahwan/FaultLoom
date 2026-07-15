from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol


REGISTRY_SOURCE: Final = "registry+https://github.com/rust-lang/crates.io-index"
CONFIG_BYTES: Final = (
    b"[source.crates-io]\n"
    b'replace-with = "vendored-sources"\n'
    b"\n"
    b"[source.vendored-sources]\n"
    b'directory = "vendor"\n'
)
IDENTITY = re.compile(r"(?P<name>[a-z0-9][a-z0-9_-]*)=(?P<version>[0-9]+(?:\.[0-9]+){1,3})")
DIGEST = re.compile(r"[0-9a-f]{64}")
type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class JsonLoader(Protocol):
    def __call__(
        self,
        s: bytes,
        *,
        object_pairs_hook: Callable[
            [list[tuple[str, JsonValue]]], dict[str, JsonValue]
        ],
    ) -> JsonValue: ...


def _typed_loader(loader: JsonLoader) -> JsonLoader:
    return loader


JSON_LOADS: Final = _typed_loader(json.loads)
SUPPORTED_SPDX_EXPRESSIONS: Final = frozenset(
    {
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        "Apache-2.0 OR MIT",
        "BSD-3-Clause",
        "MIT",
        "MIT OR Apache-2.0",
        "MIT OR Apache-2.0 OR BSD-1-Clause",
        "Unlicense OR MIT",
    }
)


class CargoVendorError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, order=True)
class CargoIdentity:
    name: str
    version: str

    @property
    def purl(self) -> str:
        return f"pkg:cargo/{self.name}@{self.version}"


@dataclass(frozen=True, slots=True, order=True)
class CargoDirectDependency:
    identity: CargoIdentity
    default_features: bool
    features: tuple[str, ...]

    @property
    def purl(self) -> str:
        return self.identity.purl


@dataclass(frozen=True, slots=True)
class CargoVendorPolicy:
    config: str
    directory: str
    registry_source: str
    maximum_rust_version: str
    direct_dependencies: tuple[CargoDirectDependency, ...]
    approved_build_scripts: frozenset[CargoIdentity]
    approved_licenses: frozenset[str]


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    path: str
    mode: str
    content: bytes


@dataclass(frozen=True, slots=True)
class CargoPackage:
    identity: CargoIdentity
    checksum: str
    license: str
    license_files: tuple[str, ...]
    rust_version: str | None
    dependencies: tuple[str, ...]
    build_script: bool

    def context(self) -> dict[str, JsonValue]:
        return {
            "name": self.identity.name,
            "version": self.identity.version,
            "purl": self.identity.purl,
            "checksum": self.checksum,
            "license": self.license,
            "license_files": list(self.license_files),
            "rust_version": self.rust_version,
            "rust_version_verification": (
                "declared_within_policy" if self.rust_version is not None else "undeclared"
            ),
            "build_script": self.build_script,
            "dependencies": list(self.dependencies),
        }


@dataclass(frozen=True, slots=True)
class CargoVendorGraph:
    policy: CargoVendorPolicy
    packages: tuple[CargoPackage, ...]

    def context(self) -> dict[str, JsonValue]:
        packages: list[JsonValue] = [item.context() for item in self.packages]
        return {
            "verification": "lock_vendor_bijection_and_file_checksums_verified",
            "config_sha256": hashlib.sha256(CONFIG_BYTES).hexdigest(),
            "registry_source": self.policy.registry_source,
            "maximum_rust_version": self.policy.maximum_rust_version,
            "direct_dependencies": [item.purl for item in self.policy.direct_dependencies],
            "packages": packages,
        }


def mapping(value: JsonValue, context: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise CargoVendorError(f"{context} must be a string-keyed table")
    return value


def _strings(value: JsonValue, context: str) -> tuple[str, ...]:
    values = _string_list(value, context)
    if not values:
        raise CargoVendorError(f"{context} must be a non-empty string list")
    return values


def _string_list(value: JsonValue, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CargoVendorError(f"{context} must be a string list")
    return tuple(item for item in value if isinstance(item, str))


def _identity(value: str, context: str) -> CargoIdentity:
    match = IDENTITY.fullmatch(value)
    if match is None:
        raise CargoVendorError(f"invalid {context}: {value}")
    return CargoIdentity(match["name"], match["version"])


def parse_vendor_policy(data: bytes, expected_rust: str) -> CargoVendorPolicy | None:
    try:
        raw: dict[str, JsonValue] = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise CargoVendorError(f"cannot parse build policy: {exc}") from exc
    value = raw.get("cargo_vendor")
    if value is None:
        return None
    table = mapping(value, "[cargo_vendor]")
    required = {
        "config",
        "directory",
        "registry_source",
        "maximum_rust_version",
        "direct_dependencies",
        "approved_build_scripts",
        "approved_licenses",
    }
    if set(table) != required:
        raise CargoVendorError("[cargo_vendor] must contain only the admitted fields")
    scalar_fields = tuple(
        required
        - {"direct_dependencies", "approved_build_scripts", "approved_licenses"}
    )
    if not all(isinstance(table[field], str) for field in scalar_fields):
        raise CargoVendorError("cargo vendor scalar policy fields must be strings")
    raw_dependencies = table["direct_dependencies"]
    if not isinstance(raw_dependencies, list) or not raw_dependencies:
        raise CargoVendorError("direct_dependencies must be a non-empty table list")
    dependencies: list[CargoDirectDependency] = []
    for value in raw_dependencies:
        dependency = mapping(value, "direct Cargo dependency")
        if set(dependency) != {"name", "version", "default_features", "features"}:
            raise CargoVendorError("direct Cargo dependency has unknown or missing fields")
        name, version = dependency["name"], dependency["version"]
        default_features = dependency["default_features"]
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(default_features, bool)
        ):
            raise CargoVendorError("direct Cargo dependency identity or feature policy is invalid")
        features = _string_list(dependency["features"], f"{name} direct features")
        if default_features or features != tuple(sorted(set(features))):
            raise CargoVendorError("direct Cargo dependency feature policy is non-canonical")
        identity = _identity(f"{name}={version}", "direct Cargo pin")
        dependencies.append(CargoDirectDependency(identity, default_features, features))
    approved_scripts = tuple(
        _identity(item, "approved Cargo build script")
        for item in _string_list(table["approved_build_scripts"], "approved_build_scripts")
    )
    licenses = frozenset(_strings(table["approved_licenses"], "approved_licenses"))
    policy = CargoVendorPolicy(
        config=str(table["config"]),
        directory=str(table["directory"]),
        registry_source=str(table["registry_source"]),
        maximum_rust_version=str(table["maximum_rust_version"]),
        direct_dependencies=tuple(dependencies),
        approved_build_scripts=frozenset(approved_scripts),
        approved_licenses=licenses,
    )
    if (
        policy.config != ".cargo/config.toml"
        or policy.directory != "vendor"
        or policy.registry_source != REGISTRY_SOURCE
        or policy.maximum_rust_version != expected_rust
        or tuple(dependencies) != tuple(sorted(set(dependencies)))
        or len({dependency.identity for dependency in dependencies}) != len(dependencies)
        or tuple(approved_scripts) != tuple(sorted(set(approved_scripts)))
        or len(licenses) != len(_strings(table["approved_licenses"], "approved_licenses"))
        or not licenses <= SUPPORTED_SPDX_EXPRESSIONS
    ):
        raise CargoVendorError("cargo vendor policy is non-canonical or conflicts with Rust policy")
    return policy


def rust_version_tuple(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) not in {2, 3} or not all(part.isdigit() for part in parts):
        raise CargoVendorError(f"invalid declared Rust version: {value}")
    major, minor, patch = (*parts, "0")[:3]
    return int(major), int(minor), int(patch)


def canonical_license(value: str) -> str:
    return "MIT OR Apache-2.0" if value == "MIT/Apache-2.0" else value


def _unique_json(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise CargoVendorError(f"duplicate checksum JSON key: {key}")
        result[key] = value
    return result


def checksum_manifest(crate: CargoIdentity, files: dict[str, SnapshotFile]) -> str:
    path = f"vendor/{crate.name}-{crate.version}/.cargo-checksum.json"
    checksum_file = files.get(path)
    if checksum_file is None:
        raise CargoVendorError(f"missing Cargo checksum manifest: {path}")
    try:
        raw = JSON_LOADS(checksum_file.content, object_pairs_hook=_unique_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CargoVendorError(f"invalid Cargo checksum manifest: {path}") from exc
    table = mapping(raw, path)
    if set(table) != {"files", "package"} or not isinstance(table["package"], str):
        raise CargoVendorError(f"malformed Cargo checksum manifest: {path}")
    declared = mapping(table["files"], f"{path} files")
    if not all(isinstance(digest, str) for digest in declared.values()):
        raise CargoVendorError(f"malformed file hashes in {path}")
    prefix = f"vendor/{crate.name}-{crate.version}/"
    actual = {
        name.removeprefix(prefix): item
        for name, item in files.items()
        if name.startswith(prefix)
    }
    _ = actual.pop(".cargo-checksum.json", None)
    if set(declared) != set(actual):
        raise CargoVendorError(f"Cargo checksum file set mismatch: {crate.name}")
    for name, item in actual.items():
        if (
            not DIGEST.fullmatch(str(declared[name]))
            or hashlib.sha256(item.content).hexdigest() != declared[name]
        ):
            raise CargoVendorError(f"Cargo vendor file checksum mismatch: {crate.name}/{name}")
    return str(table["package"])
