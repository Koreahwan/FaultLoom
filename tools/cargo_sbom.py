from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from tools.cargo_vendor_policy import (
    CONFIG_BYTES,
    REGISTRY_SOURCE,
    SUPPORTED_SPDX_EXPRESSIONS,
    JsonValue,
)


class CargoSbomError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CargoSbomPackage:
    name: str
    version: str
    purl: str
    checksum: str
    license: str
    license_files: tuple[str, ...]
    rust_version: str | None
    rust_version_verification: str
    build_script: bool
    dependencies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CargoSbomGraph:
    direct_dependencies: tuple[str, ...]
    packages: tuple[CargoSbomPackage, ...]


def _mapping(value: JsonValue, context: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise CargoSbomError(f"{context} must be an object")
    return value


def _strings(value: JsonValue, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CargoSbomError(f"{context} must be a string list")
    return tuple(item for item in value if isinstance(item, str))


def parse_cargo_context(value: JsonValue) -> CargoSbomGraph | None:
    if value is None:
        return None
    table = _mapping(value, "cargo_vendor")
    required = {
        "verification",
        "config_sha256",
        "registry_source",
        "maximum_rust_version",
        "direct_dependencies",
        "packages",
    }
    if set(table) != required:
        raise CargoSbomError("cargo_vendor context has missing or unknown fields")
    expected_config = hashlib.sha256(CONFIG_BYTES).hexdigest()
    if (
        table["verification"] != "lock_vendor_bijection_and_file_checksums_verified"
        or table["config_sha256"] != expected_config
        or table["registry_source"] != REGISTRY_SOURCE
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(table["maximum_rust_version"])) is None
    ):
        raise CargoSbomError("cargo_vendor verification or source identity is invalid")
    direct = _strings(table["direct_dependencies"], "cargo direct dependencies")
    raw_packages = table["packages"]
    if not isinstance(raw_packages, list) or not raw_packages:
        raise CargoSbomError("cargo_vendor packages must be non-empty")
    packages: list[CargoSbomPackage] = []
    expected_package_fields = {
        "name",
        "version",
        "purl",
        "checksum",
        "license",
        "license_files",
        "rust_version",
        "rust_version_verification",
        "build_script",
        "dependencies",
    }
    for raw_package in raw_packages:
        package = _mapping(raw_package, "cargo package")
        if set(package) != expected_package_fields:
            raise CargoSbomError("cargo package has missing or unknown fields")
        name, version = package["name"], package["version"]
        checksum, license_value = package["checksum"], package["license"]
        license_files = _strings(package["license_files"], f"{name} license files")
        rust_version = package["rust_version"]
        verification = package["rust_version_verification"]
        build_script = package["build_script"]
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or package["purl"] != f"pkg:cargo/{name}@{version}"
            or not isinstance(checksum, str)
            or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
            or not isinstance(license_value, str)
            or license_value not in SUPPORTED_SPDX_EXPRESSIONS
            or not license_files
            or any(
                "/" in path
                or re.fullmatch(
                    r"(?i:LICENSE(?:[-.].*)?|COPYING(?:[-.].*)?|COPYRIGHT(?:[-.].*)?)",
                    path,
                )
                is None
                for path in license_files
            )
            or not (rust_version is None or isinstance(rust_version, str))
            or verification
            != ("declared_within_policy" if rust_version is not None else "undeclared")
            or not isinstance(build_script, bool)
        ):
            raise CargoSbomError("cargo package identity, checksum, license, or MSRV is invalid")
        packages.append(
            CargoSbomPackage(
                name=name,
                version=version,
                purl=str(package["purl"]),
                checksum=checksum,
                license=license_value,
                license_files=license_files,
                rust_version=rust_version,
                rust_version_verification=str(verification),
                build_script=build_script,
                dependencies=_strings(package["dependencies"], f"{name} dependencies"),
            )
        )
    by_purl = {package.purl: package for package in packages}
    if len(by_purl) != len(packages) or not set(direct) <= set(by_purl):
        raise CargoSbomError("cargo package or direct dependency identity is invalid")
    if any(not set(package.dependencies) <= set(by_purl) for package in packages):
        raise CargoSbomError("cargo dependency edge is unresolved")
    reachable: set[str] = set()
    pending = list(direct)
    while pending:
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            pending.extend(by_purl[current].dependencies)
    if reachable != set(by_purl):
        raise CargoSbomError("cargo context contains an unreachable package")
    return CargoSbomGraph(direct_dependencies=direct, packages=tuple(packages))


def sbom_fragments(
    graph: CargoSbomGraph,
) -> tuple[list[dict[str, JsonValue]], list[dict[str, JsonValue]]]:
    components: list[dict[str, JsonValue]] = []
    edges: list[dict[str, JsonValue]] = []
    for package in graph.packages:
        properties: list[JsonValue] = [
            {"name": "faultloom:cargoPackageChecksum", "value": package.checksum},
            {
                "name": "faultloom:retainedLicenseFiles",
                "value": ",".join(package.license_files),
            },
            {
                "name": "faultloom:rustVersionVerification",
                "value": package.rust_version_verification,
            },
            {"name": "faultloom:vendoredBuildScript", "value": str(package.build_script).lower()},
        ]
        if package.rust_version is not None:
            properties.append(
                {"name": "faultloom:declaredRustVersion", "value": package.rust_version}
            )
        components.append(
            {
                "type": "library",
                "name": package.name,
                "version": package.version,
                "purl": package.purl,
                "bom-ref": package.purl,
                "hashes": [{"alg": "SHA-256", "content": package.checksum}],
                "licenses": [{"expression": package.license}],
                "properties": properties,
            }
        )
        edges.append({"ref": package.purl, "dependsOn": list(package.dependencies)})
    return components, edges
