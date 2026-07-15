from __future__ import annotations

import re
import tomllib
from pathlib import PurePosixPath

from tools.cargo_vendor_policy import (
    CONFIG_BYTES,
    DIGEST,
    CargoIdentity,
    CargoPackage,
    CargoVendorError,
    CargoVendorGraph,
    CargoVendorPolicy,
    JsonValue,
    SnapshotFile,
    canonical_license,
    checksum_manifest,
    mapping,
    rust_version_tuple,
)


def _toml(data: bytes, context: str) -> dict[str, JsonValue]:
    try:
        raw: dict[str, JsonValue] = tomllib.loads(data.decode("utf-8"))
        return mapping(raw, context)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise CargoVendorError(f"cannot parse {context}: {exc}") from exc


def _dependency_names(value: JsonValue, context: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CargoVendorError(f"{context} dependencies must be strings")
    names = tuple(item for item in value if isinstance(item, str))
    if any(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", item) is None for item in names):
        raise CargoVendorError(f"{context} has ambiguous or non-registry dependency syntax")
    return names


def _direct_manifest(data: bytes, policy: CargoVendorPolicy) -> None:
    manifest = _toml(data, "Gateway Cargo manifest")
    dependencies = mapping(manifest.get("dependencies"), "Gateway dependencies")
    expected: dict[str, JsonValue] = {}
    for dependency in policy.direct_dependencies:
        table: dict[str, JsonValue] = {
            "version": f"={dependency.identity.version}",
            "default-features": dependency.default_features,
        }
        if dependency.features:
            table["features"] = list(dependency.features)
        expected[dependency.identity.name] = table
    if dependencies != expected:
        raise CargoVendorError(
            "Gateway direct dependency pins, features, or sources differ from policy"
        )


def _lock_packages(
    data: bytes, policy: CargoVendorPolicy
) -> tuple[dict[CargoIdentity, dict[str, JsonValue]], tuple[str, ...]]:
    lock = _toml(data, "Cargo.lock")
    if set(lock) != {"version", "package"} or lock.get("version") != 4:
        raise CargoVendorError("Cargo.lock must use the exact version 4 package schema")
    raw_packages = lock.get("package")
    if not isinstance(raw_packages, list):
        raise CargoVendorError("Cargo.lock package list is missing")
    registry: dict[CargoIdentity, dict[str, JsonValue]] = {}
    root_dependencies: tuple[str, ...] | None = None
    for raw in raw_packages:
        package = mapping(raw, "Cargo.lock package")
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise CargoVendorError("Cargo.lock package identity is malformed")
        source = package.get("source")
        if source is None:
            if name != "faultloom-gateway" or version != "0.1.0" or root_dependencies is not None:
                raise CargoVendorError("Cargo.lock has an unlisted path package")
            root_dependencies = _dependency_names(package.get("dependencies"), name)
            continue
        allowed_fields = {"name", "version", "source", "checksum", "dependencies"}
        if source != policy.registry_source or set(package) - allowed_fields:
            raise CargoVendorError(f"Cargo.lock package {name} has an unapproved source or field")
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or DIGEST.fullmatch(checksum) is None:
            raise CargoVendorError(f"Cargo.lock package {name} lacks an exact checksum")
        identity = CargoIdentity(name, version)
        if identity in registry:
            raise CargoVendorError(f"duplicate Cargo.lock package: {name} {version}")
        registry[identity] = package
    if root_dependencies is None:
        raise CargoVendorError("Cargo.lock omits the Gateway root package")
    direct_names = tuple(
        sorted(item.identity.name for item in policy.direct_dependencies)
    )
    if tuple(sorted(root_dependencies)) != direct_names:
        raise CargoVendorError("Cargo.lock root edges differ from direct dependency policy")
    return registry, root_dependencies


def _snapshot_files(snapshot: tuple[SnapshotFile, ...]) -> dict[str, SnapshotFile]:
    files: dict[str, SnapshotFile] = {}
    for item in snapshot:
        path = PurePosixPath(item.path)
        if (
            item.path != path.as_posix()
            or item.mode not in {"100644", "100755"}
            or item.path in files
        ):
            raise CargoVendorError(f"unsafe Cargo vendor entry: {item.path}")
        files[item.path] = item
    config_paths = {path for path in files if path.startswith(".cargo/")}
    if (
        config_paths != {".cargo/config.toml"}
        or files[".cargo/config.toml"].content != CONFIG_BYTES
    ):
        raise CargoVendorError("Cargo source replacement configuration drifted")
    return files


def validate_vendor_graph(
    policy: CargoVendorPolicy,
    gateway_manifest: bytes,
    cargo_lock: bytes,
    snapshot: tuple[SnapshotFile, ...],
) -> CargoVendorGraph:
    _direct_manifest(gateway_manifest, policy)
    registry, direct = _lock_packages(cargo_lock, policy)
    files = _snapshot_files(snapshot)
    expected_direct = {item.identity for item in policy.direct_dependencies}
    if not expected_direct <= set(registry):
        raise CargoVendorError("direct Cargo policy pin is absent from Cargo.lock")
    by_name = {identity.name: identity for identity in registry}
    if len(by_name) != len(registry):
        raise CargoVendorError("multiple versions of one Cargo package are not admitted")
    edges: dict[CargoIdentity, tuple[CargoIdentity, ...]] = {}
    for identity, package in registry.items():
        dependencies = _dependency_names(package.get("dependencies"), identity.name)
        if any(name not in by_name for name in dependencies):
            raise CargoVendorError(f"Cargo.lock edge from {identity.name} is unresolved")
        edges[identity] = tuple(by_name[name] for name in dependencies)
    reachable: set[CargoIdentity] = set()
    pending = [by_name[name] for name in direct]
    while pending:
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            pending.extend(edges[current])
    if reachable != set(registry):
        raise CargoVendorError("Cargo.lock contains an unreachable registry package")
    expected_directories = {f"vendor/{item.name}-{item.version}" for item in registry}
    actual_directories = {
        "/".join(path.split("/")[:2])
        for path in files
        if path.startswith("vendor/")
    }
    if actual_directories != expected_directories:
        raise CargoVendorError("Cargo.lock and versioned vendor directories are not bijective")
    actual_build_scripts = {
        identity
        for identity in registry
        if f"vendor/{identity.name}-{identity.version}/build.rs" in files
    }
    if actual_build_scripts != set(policy.approved_build_scripts):
        raise CargoVendorError("vendored Cargo build script set differs from policy")
    packages: list[CargoPackage] = []
    for identity, package in sorted(registry.items()):
        checksum = checksum_manifest(identity, files)
        if checksum != package["checksum"]:
            raise CargoVendorError(
                f"vendor package checksum differs from Cargo.lock: {identity.name}"
            )
        manifest_path = f"vendor/{identity.name}-{identity.version}/Cargo.toml"
        crate = _toml(files[manifest_path].content, manifest_path)
        metadata = mapping(crate.get("package"), f"{manifest_path} package")
        license_value, rust_version = metadata.get("license"), metadata.get("rust-version")
        if (
            metadata.get("name") != identity.name
            or metadata.get("version") != identity.version
            or not isinstance(license_value, str)
        ):
            raise CargoVendorError(f"vendored manifest identity/license drift: {identity.name}")
        license_expression = canonical_license(license_value)
        if license_expression not in policy.approved_licenses:
            raise CargoVendorError(
                f"unapproved Cargo license: {identity.name}: {license_expression}"
            )
        if rust_version is not None and (
            not isinstance(rust_version, str)
            or rust_version_tuple(rust_version)
            > rust_version_tuple(policy.maximum_rust_version)
        ):
            raise CargoVendorError(f"Cargo package MSRV exceeds policy: {identity.name}")
        prefix = f"vendor/{identity.name}-{identity.version}/"
        license_files = tuple(
            sorted(
                name.removeprefix(prefix)
                for name, item in files.items()
                if name.startswith(prefix)
                and "/" not in name.removeprefix(prefix)
                and re.fullmatch(
                    r"(?i:LICENSE(?:[-.].*)?|COPYING(?:[-.].*)?|COPYRIGHT(?:[-.].*)?)",
                    name.removeprefix(prefix),
                )
                is not None
                and item.content.strip()
            )
        )
        if not license_files:
            raise CargoVendorError(f"vendored Cargo package lacks a license text: {identity.name}")
        packages.append(
            CargoPackage(
                identity=identity,
                checksum=checksum,
                license=license_expression,
                license_files=license_files,
                rust_version=rust_version,
                dependencies=tuple(sorted(item.purl for item in edges[identity])),
                build_script=f"vendor/{identity.name}-{identity.version}/build.rs" in files,
            )
        )
    return CargoVendorGraph(policy=policy, packages=tuple(packages))
