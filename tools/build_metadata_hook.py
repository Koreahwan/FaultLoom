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
        "ci_policy",
        "components",
        "dependency_graph",
        "locked_dependencies",
        "network",
        "source",
        "source_date_epoch",
        "subjects",
        "toolchains",
    }
    if value.get("schema_version") != 1 or not required <= value.keys():
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
    if (
        not isinstance(toolchains, dict)
        or toolchains.get("python_runtime_verification")
        != "version_only_unverified"
        or toolchains.get("rust_runtime_verification")
        != "policy_declared_unverified"
    ):
        raise HookError("build context has an invalid Python runtime verification claim")
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
    dependency_edges.append({"ref": root_ref, "dependsOn": sorted(internal_purls)})
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
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://faultloom.invalid/build-types/stdlib-wheel/v1",
                "externalParameters": {"sourceDateEpoch": context["source_date_epoch"]},
                "internalParameters": {
                    "toolchains": context["toolchains"],
                    "ciPolicy": context["ci_policy"],
                    "network": context["network"],
                    "dependencyGraph": context["dependency_graph"],
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
