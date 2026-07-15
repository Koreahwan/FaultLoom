from __future__ import annotations

import copy
import functools
import json
from pathlib import Path

import pytest

from tools.build_metadata_hook import make_provenance, make_sbom
from tools.cargo_sbom import CargoSbomError, parse_cargo_context, sbom_fragments
from tools.cargo_vendor_graph import validate_vendor_graph
from tools.cargo_vendor_policy import (
    CargoVendorGraph,
    JsonValue,
    SnapshotFile,
    parse_vendor_policy,
)


ROOT = Path(__file__).resolve().parents[1]


def _string(table: dict[str, JsonValue], key: str) -> str:
    value = table[key]
    assert isinstance(value, str)
    return value


def _packages(context: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    value = context["packages"]
    assert isinstance(value, list)
    packages: list[dict[str, JsonValue]] = []
    for item in value:
        assert isinstance(item, dict)
        packages.append(item)
    return packages


@functools.cache
def _admitted_graph() -> CargoVendorGraph:
    policy = parse_vendor_policy((ROOT / "build-policy.toml").read_bytes(), "1.96.1")
    assert policy is not None
    snapshot: list[SnapshotFile] = []
    for directory in (ROOT / ".cargo", ROOT / "vendor"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() or path.is_symlink():
                mode = "120000" if path.is_symlink() else (
                    "100755" if path.stat().st_mode & 0o111 else "100644"
                )
                snapshot.append(
                    SnapshotFile(path.relative_to(ROOT).as_posix(), mode, path.read_bytes())
                )
    return validate_vendor_graph(
        policy,
        (ROOT / "gateway/Cargo.toml").read_bytes(),
        (ROOT / "Cargo.lock").read_bytes(),
        tuple(snapshot),
    )


def test_actual_cargo_graph_has_complete_sbom_nodes_and_edges() -> None:
    graph = _admitted_graph()
    context = graph.context()
    parsed = parse_cargo_context(context)
    assert parsed is not None

    components, edges = sbom_fragments(parsed)

    assert len(parsed.packages) == 31
    assert sum(len(package.dependencies) for package in parsed.packages) == 43
    assert sum(package.rust_version is None for package in parsed.packages) == 10
    assert sum(package.build_script for package in parsed.packages) == 9
    assert {package.name for package in parsed.packages if package.build_script} == {
        "curve25519-dalek",
        "generic-array",
        "libc",
        "proc-macro2",
        "quote",
        "serde",
        "serde_core",
        "serde_json",
        "zmij",
    }
    assert all(package.license_files for package in parsed.packages)
    assert {_string(component, "bom-ref") for component in components} == {
        package.purl for package in parsed.packages
    }
    assert {_string(edge, "ref") for edge in edges} == {
        package.purl for package in parsed.packages
    }
    assert all("hashes" in component and "licenses" in component for component in components)
    inventory = (ROOT / "docs/THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
    for package in parsed.packages:
        assert (
            f"| {package.name} | {package.version} | {package.license} | "
            f"{', '.join(package.license_files)} |"
        ) in inventory


def test_cargo_context_rejects_missing_nodes_edges_and_invalid_policy_fields() -> None:
    original = _admitted_graph().context()
    variants: list[dict[str, JsonValue]] = []
    missing_node = copy.deepcopy(original)
    raw_packages = missing_node["packages"]
    assert isinstance(raw_packages, list)
    _ = raw_packages.pop()
    variants.append(missing_node)
    missing_edge = copy.deepcopy(original)
    serde_json = next(
        item for item in _packages(missing_edge) if _string(item, "name") == "serde_json"
    )
    serde_json["dependencies"] = []
    variants.append(missing_edge)
    bad_license = copy.deepcopy(original)
    _packages(bad_license)[0]["license"] = "GPL-3.0-only"
    variants.append(bad_license)
    bad_config = copy.deepcopy(original)
    bad_config["config_sha256"] = "0" * 64
    variants.append(bad_config)
    missing_license_text = copy.deepcopy(original)
    _packages(missing_license_text)[0]["license_files"] = []
    variants.append(missing_license_text)

    for context in variants:
        with pytest.raises(CargoSbomError):
            parse_cargo_context(context)


def test_gateway_sbom_edge_names_every_exact_direct_cargo_pin() -> None:
    graph = _admitted_graph()
    context = {
        "source": {"commit": "a" * 40, "tree": "b" * 40},
        "source_date_epoch": 0,
        "builder": "fixture",
        "subjects": [
            {
                "name": "faultloom-gateway",
                "sha256": "c" * 64,
                "size": 1,
            }
        ],
        "components": [],
        "locked_dependencies": [],
        "cargo_vendor": graph.context(),
        "native_artifacts": [
            {
                "artifact_name": "faultloom-gateway",
                "component_name": "faultloom-gateway",
                "version": "0.1.0",
                "target": "x86_64-unknown-linux-gnu",
                "purl": "pkg:cargo/faultloom-gateway@0.1.0",
                "sha256": "c" * 64,
                "source_commit": "a" * 40,
                "source_tree": "b" * 40,
                "recipe_sha256": "d" * 64,
                "cargo_lock_sha256": "e" * 64,
                "rustc_sha256": "f" * 64,
                "rustc_closure_sha256": "0" * 64,
                "cargo_sha256": "1" * 64,
                "host_environment_verification": "linker_libc_kernel_unverified",
            }
        ],
        "dependency_graph": {"verification": "complete", "source": "fixture"},
        "network": {"mode": "offline_requested", "enforced": False, "controls": []},
        "toolchains": {
            "rust": "1.96.1",
            "python_runtime_verification": "version_only_unverified",
            "rust_runtime_verification": "verified",
            "host_environment_verification": "linker_libc_kernel_unverified",
        },
        "ci_policy": {"external_trust_anchor": False, "workflow_sha256": "2" * 64},
    }

    sbom = make_sbom(context)
    repeated = make_sbom(copy.deepcopy(context))
    provenance = make_provenance(context)

    assert json.dumps(sbom, sort_keys=True, separators=(",", ":")) == json.dumps(
        repeated,
        sort_keys=True,
        separators=(",", ":"),
    )

    gateway_edge = next(
        edge
        for edge in sbom["dependencies"]
        if edge["ref"] == "pkg:cargo/faultloom-gateway@0.1.0"
    )
    assert gateway_edge["dependsOn"] == [
        identity.purl for identity in graph.policy.direct_dependencies
    ]
    resolved = provenance["predicate"]["buildDefinition"]["resolvedDependencies"]
    cargo_package = graph.packages[0]
    cargo_dependency = next(
        item for item in resolved if item["uri"] == cargo_package.identity.purl
    )
    assert cargo_dependency["annotations"]["faultloom:retainedLicenseFiles"] == list(
        cargo_package.license_files
    )
