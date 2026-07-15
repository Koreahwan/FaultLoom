#!/usr/bin/env python3
"""Generate deterministic SBOM or provenance metadata for the build driver."""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.cargo_sbom import CargoSbomError, parse_cargo_context, sbom_fragments


class HookError(RuntimeError):
    """The supplied build context is incomplete or malformed."""


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def _load_context(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HookError(f"cannot read build context: {exc}") from exc
    required = {
        "builder",
        "cargo_vendor",
        "ci_policy",
        "components",
        "dependency_graph",
        "locked_dependencies",
        "native_artifacts",
        "network",
        "source",
        "source_date_epoch",
        "subjects",
        "toolchains",
    }
    if value.get("schema_version") != 3 or not required <= value.keys():
        raise HookError("unsupported or incomplete build context")
    if not isinstance(value["subjects"], list) or not value["subjects"]:
        raise HookError("build context must contain at least one subject")
    network = value["network"]
    if (
        not isinstance(network, dict)
        or network.get("mode") not in {"offline_requested", "isolated"}
        or not isinstance(network.get("enforced"), bool)
        or network.get("enforced") != (network.get("mode") == "isolated")
    ):
        raise HookError("build context has an invalid network enforcement claim")
    dependency_graph = value["dependency_graph"]
    if (
        not isinstance(dependency_graph, dict)
        or dependency_graph.get("verification")
        not in {"declared_unverified", "complete_no_external_dependencies"}
        or not isinstance(dependency_graph.get("source"), str)
    ):
        raise HookError("build context has an invalid dependency graph claim")
    ci_policy = value["ci_policy"]
    if (
        not isinstance(ci_policy, dict)
        or ci_policy.get("workflow") != ".github/workflows/ci.yml"
        or re.fullmatch(r"[0-9a-f]{64}", ci_policy.get("workflow_sha256", ""))
        is None
        or ci_policy.get("validation") != "byte_exact_repository_self_check"
        or ci_policy.get("external_trust_anchor") is not False
    ):
        raise HookError("build context has an invalid CI trust-anchor claim")
    toolchains = value["toolchains"]
    native_artifacts = value["native_artifacts"]
    if not isinstance(native_artifacts, list):
        raise HookError("build context native_artifacts must be a list")
    try:
        cargo_graph = parse_cargo_context(value["cargo_vendor"])
    except CargoSbomError as exc:
        raise HookError(str(exc)) from exc
    if cargo_graph is not None and not native_artifacts:
        raise HookError("Cargo vendor graph requires a native artifact")
    expected_rust_verification = (
        "rustc_cargo_closure_digests_and_locked_offline_build_verified"
        if native_artifacts
        else "policy_declared_unverified"
    )
    expected_host_verification = (
        "linker_libc_kernel_unverified" if native_artifacts else "not_used"
    )
    if (
        not isinstance(toolchains, dict)
        or toolchains.get("python_runtime_verification")
        != "version_only_unverified"
        or toolchains.get("rust_runtime_verification")
        != expected_rust_verification
        or toolchains.get("host_environment_verification")
        != expected_host_verification
        or re.fullmatch(r"[0-9a-f]{64}", toolchains.get("rustc_sha256", ""))
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", toolchains.get("rustc_closure_sha256", "")
        )
        is None
    ):
        raise HookError("build context has an invalid toolchain verification claim")
    if native_artifacts:
        if re.fullmatch(r"[0-9a-f]{64}", toolchains.get("cargo_sha256", "")) is None:
            raise HookError("native artifacts require a pinned Cargo digest")
    elif toolchains.get("cargo_sha256") is not None:
        raise HookError("Cargo may not be claimed when no native artifact was built")

    source = value["source"]
    if (
        not isinstance(source, dict)
        or re.fullmatch(r"[0-9a-f]{40}", source.get("commit", "")) is None
        or re.fullmatch(r"[0-9a-f]{40}", source.get("tree", "")) is None
    ):
        raise HookError("build context has an invalid source identity")
    subjects: dict[str, dict[str, Any]] = {}
    for subject in value["subjects"]:
        if (
            not isinstance(subject, dict)
            or set(subject) != {"name", "sha256", "size"}
            or not isinstance(subject["name"], str)
            or not subject["name"]
            or re.fullmatch(r"[0-9a-f]{64}", subject["sha256"]) is None
            or not isinstance(subject["size"], int)
            or isinstance(subject["size"], bool)
            or subject["size"] <= 0
            or subject["name"] in subjects
        ):
            raise HookError("build context has an invalid or duplicate subject")
        subjects[subject["name"]] = subject
    native_names: set[str] = set()
    native_purls: set[str] = set()
    required_native = {
        "artifact_name",
        "component_name",
        "version",
        "target",
        "purl",
        "sha256",
        "size",
        "source_commit",
        "source_tree",
        "cargo_lock_sha256",
        "recipe_sha256",
        "rustc_sha256",
        "rustc_closure_sha256",
        "cargo_sha256",
        "host_environment_verification",
    }
    for native in native_artifacts:
        if not isinstance(native, dict) or set(native) != required_native:
            raise HookError("native artifact descriptor is incomplete or has unknown fields")
        subject = subjects.get(native["artifact_name"])
        digest_fields = (
            "sha256",
            "cargo_lock_sha256",
            "recipe_sha256",
            "rustc_sha256",
            "rustc_closure_sha256",
            "cargo_sha256",
        )
        if (
            subject is None
            or subject["sha256"] != native["sha256"]
            or subject["size"] != native["size"]
            or native["source_commit"] != source["commit"]
            or native["source_tree"] != source["tree"]
            or native["rustc_sha256"] != toolchains["rustc_sha256"]
            or native["rustc_closure_sha256"]
            != toolchains["rustc_closure_sha256"]
            or native["cargo_sha256"] != toolchains["cargo_sha256"]
            or native["host_environment_verification"]
            != "linker_libc_kernel_unverified"
            or any(
                re.fullmatch(r"[0-9a-f]{64}", native[field]) is None
                for field in digest_fields
            )
            or native["artifact_name"] in native_names
            or native["purl"] in native_purls
            or not isinstance(native["component_name"], str)
            or not isinstance(native["version"], str)
            or not isinstance(native["target"], str)
            or native["purl"]
            != f"pkg:cargo/{native['component_name']}@{native['version']}"
        ):
            raise HookError("native artifact is not bound to its subject, source, and toolchain")
        native_names.add(native["artifact_name"])
        native_purls.add(native["purl"])
    return value


def make_sbom(context: dict[str, Any]) -> dict[str, Any]:
    commit = context["source"].get("commit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise HookError("source commit must be a full Git object ID")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://faultloom.invalid/core/{commit}")
    root_ref = f"urn:faultloom:core:{commit}"
    components = []
    dependency_edges = []
    internal_purls = {component["purl"] for component in context["components"]}
    root_dependencies = set(internal_purls)
    cargo_graph = parse_cargo_context(context["cargo_vendor"])
    cargo_direct: list[str] = []
    if cargo_graph is not None:
        cargo_components, cargo_edges = sbom_fragments(cargo_graph)
        components.extend(cargo_components)
        dependency_edges.extend(cargo_edges)
        cargo_direct = list(cargo_graph.direct_dependencies)
    for component in context["components"]:
        components.append(
            {
                "type": "library",
                "name": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "bom-ref": component["purl"],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        )
        depends_on = []
        for requirement in component["dependencies"]:
            name, version = requirement.split("==", 1)
            purl = f"pkg:pypi/{_normalized_name(name)}@{version}"
            depends_on.append(purl)
        dependency_edges.append({"ref": component["purl"], "dependsOn": sorted(depends_on)})
    for dependency in context["locked_dependencies"]:
        purl = f"pkg:pypi/{dependency['name']}@{dependency['version']}"
        if purl in internal_purls:
            continue
        components.append(
            {
                "type": "library",
                "name": dependency["name"],
                "version": dependency["version"],
                "purl": purl,
                "bom-ref": purl,
                "properties": [
                    {
                        "name": "faultloom:hashVerification",
                        "value": dependency["hash_verification"],
                    },
                    {
                        "name": "faultloom:declaredSha256",
                        "value": ",".join(dependency["sha256"]),
                    },
                ],
            }
        )
        depends_on = []
        for requirement in dependency["dependencies"]:
            name, version = requirement.split("==", 1)
            depends_on.append(f"pkg:pypi/{_normalized_name(name)}@{version}")
        dependency_edges.append({"ref": purl, "dependsOn": sorted(depends_on)})
    for native in context["native_artifacts"]:
        root_dependencies.add(native["purl"])
        components.append(
            {
                "type": "application",
                "name": native["component_name"],
                "version": native["version"],
                "purl": native["purl"],
                "bom-ref": native["purl"],
                "hashes": [{"alg": "SHA-256", "content": native["sha256"]}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "properties": [
                    {"name": "faultloom:artifactName", "value": native["artifact_name"]},
                    {"name": "faultloom:target", "value": native["target"]},
                    {
                        "name": "faultloom:sourceCommit",
                        "value": native["source_commit"],
                    },
                    {"name": "faultloom:sourceTree", "value": native["source_tree"]},
                    {
                        "name": "faultloom:buildRecipeSha256",
                        "value": native["recipe_sha256"],
                    },
                    {
                        "name": "faultloom:cargoLockSha256",
                        "value": native["cargo_lock_sha256"],
                    },
                    {"name": "faultloom:rustcSha256", "value": native["rustc_sha256"]},
                    {"name": "faultloom:cargoSha256", "value": native["cargo_sha256"]},
                    {
                        "name": "faultloom:hostEnvironmentVerification",
                        "value": native["host_environment_verification"],
                    },
                ],
            }
        )
        dependency_edges.append({"ref": native["purl"], "dependsOn": cargo_direct})
    dependency_edges.append({"ref": root_ref, "dependsOn": sorted(root_dependencies)})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": context["builder"]}]},
            "properties": [
                {
                    "name": "faultloom:dependencyGraphVerification",
                    "value": context["dependency_graph"]["verification"],
                },
                {
                    "name": "faultloom:dependencyGraphSource",
                    "value": context["dependency_graph"]["source"],
                },
                {
                    "name": "faultloom:pythonRuntimeVerification",
                    "value": context["toolchains"]["python_runtime_verification"],
                },
                {
                    "name": "faultloom:ciExternalTrustAnchor",
                    "value": str(context["ci_policy"]["external_trust_anchor"]).lower(),
                },
                {
                    "name": "faultloom:ciWorkflowSha256",
                    "value": context["ci_policy"]["workflow_sha256"],
                },
                {
                    "name": "faultloom:rustRuntimeVerification",
                    "value": context["toolchains"]["rust_runtime_verification"],
                },
                {
                    "name": "faultloom:hostEnvironmentVerification",
                    "value": context["toolchains"]["host_environment_verification"],
                },
                {
                    "name": "faultloom:cargoVendorVerification",
                    "value": (
                        "not_used"
                        if context["cargo_vendor"] is None
                        else context["cargo_vendor"]["verification"]
                    ),
                },
            ],
            "component": {
                "type": "application",
                "name": "faultloom-core",
                "version": commit,
                "bom-ref": root_ref,
                "hashes": [{"alg": "SHA-1", "content": context["source"]["tree"]}],
            },
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "dependencies": sorted(dependency_edges, key=lambda item: item["ref"]),
    }


def make_provenance(context: dict[str, Any]) -> dict[str, Any]:
    subjects = [
        {"name": item["name"], "digest": {"sha256": item["sha256"]}}
        for item in context["subjects"]
    ]
    resolved_dependencies = [
        {
            "uri": "git+https://faultloom.invalid/core",
            "digest": {
                "sha1": context["source"]["commit"],
                "gitTree": context["source"]["tree"],
            },
        }
    ]
    for item in context["locked_dependencies"]:
        resolved_dependencies.append(
            {
                "uri": f"pkg:pypi/{item['name']}@{item['version']}",
                "annotations": {
                    "faultloom:hashVerification": item["hash_verification"],
                    "faultloom:declaredSha256": ",".join(item["sha256"]),
                },
            }
        )
    cargo_graph = parse_cargo_context(context["cargo_vendor"])
    if cargo_graph is not None:
        for package in cargo_graph.packages:
            resolved_dependencies.append(
                {
                    "uri": package.purl,
                    "digest": {"sha256": package.checksum},
                    "annotations": {
                        "faultloom:licenseExpression": package.license,
                        "faultloom:retainedLicenseFiles": list(package.license_files),
                        "faultloom:rustVersionVerification": package.rust_version_verification,
                        "faultloom:declaredRustVersion": package.rust_version,
                        "faultloom:vendoredBuildScript": package.build_script,
                        "faultloom:dependencies": list(package.dependencies),
                    },
                }
            )
    for native in context["native_artifacts"]:
        resolved_dependencies.extend(
            [
                {
                    "uri": (
                        "urn:faultloom:rust-toolchain:"
                        f"{context['toolchains']['rust']}:{native['target']}"
                    ),
                    "digest": {"sha256": native["rustc_closure_sha256"]},
                    "annotations": {
                        "faultloom:rustcSha256": native["rustc_sha256"],
                        "faultloom:cargoSha256": native["cargo_sha256"],
                        "faultloom:hostEnvironmentVerification": native[
                            "host_environment_verification"
                        ],
                    },
                },
                {
                    "uri": "git+https://faultloom.invalid/core#path=Cargo.lock",
                    "digest": {"sha256": native["cargo_lock_sha256"]},
                },
            ]
        )
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://faultloom.invalid/build-types/core-artifacts/v2",
                "externalParameters": {"sourceDateEpoch": context["source_date_epoch"]},
                "internalParameters": {
                    "toolchains": context["toolchains"],
                    "ciPolicy": context["ci_policy"],
                    "network": context["network"],
                    "dependencyGraph": context["dependency_graph"],
                    "nativeArtifacts": context["native_artifacts"],
                },
                "resolvedDependencies": resolved_dependencies,
            },
            "runDetails": {
                "builder": {"id": context["builder"]},
                "metadata": {},
                "byproducts": [],
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("sbom", "provenance"))
    parser.add_argument("context", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        context = _load_context(args.context)
        value = make_sbom(context) if args.kind == "sbom" else make_provenance(context)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical_json(value))
            handle.flush()
    except (HookError, FileExistsError, OSError) as exc:
        print(f"metadata hook refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
