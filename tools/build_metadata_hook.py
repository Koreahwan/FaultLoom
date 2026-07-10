#!/usr/bin/env python3
"""Generate deterministic SBOM or provenance metadata for the build driver."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from datetime import UTC, datetime
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
        "components",
        "locked_dependencies",
        "source",
        "source_date_epoch",
        "subjects",
        "toolchains",
    }
    if value.get("schema_version") != 1 or not required <= value.keys():
        raise HookError("unsupported or incomplete build context")
    if not isinstance(value["subjects"], list) or not value["subjects"]:
        raise HookError("build context must contain at least one subject")
    return value


def _timestamp(epoch: int) -> str:
    try:
        value = datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds")
        return value.replace("+00:00", "Z")
    except (OverflowError, OSError, TypeError, ValueError) as exc:
        raise HookError("invalid source date epoch") from exc


def make_sbom(context: dict[str, Any]) -> dict[str, Any]:
    commit = context["source"].get("commit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise HookError("source commit must be a full Git object ID")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://faultloom.invalid/core/{commit}")
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
                "hashes": [
                    {"alg": "SHA-256", "content": digest}
                    for digest in dependency["sha256"]
                ],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(context["source_date_epoch"]),
            "tools": {"components": [{"type": "application", "name": context["builder"]}]},
            "component": {
                "type": "application",
                "name": "faultloom-core",
                "version": commit,
                "hashes": [{"alg": "SHA-1", "content": context["source"]["tree"]}],
            },
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "dependencies": sorted(dependency_edges, key=lambda item: item["ref"]),
    }


def make_provenance(context: dict[str, Any]) -> dict[str, Any]:
    timestamp = _timestamp(context["source_date_epoch"])
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
        for digest in item["sha256"]:
            resolved_dependencies.append(
                {
                    "uri": f"pkg:pypi/{item['name']}@{item['version']}",
                    "digest": {"sha256": digest},
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
                    "network": "disabled",
                },
                "resolvedDependencies": resolved_dependencies,
            },
            "runDetails": {
                "builder": {"id": context["builder"]},
                "metadata": {
                    "invocationId": hashlib.sha256(
                        _canonical_json(context).encode("utf-8")
                    ).hexdigest(),
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
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
