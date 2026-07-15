#!/usr/bin/env python3
"""Fail closed on public-tree leakage and repository-boundary violations."""

from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


REQUIRED_POLICY_FILES = {"LICENSE", "NOTICE", "SECURITY.md", "ETHICAL_USE.md"}
PRIVATE_NAMES = {
    ".env",
    "labels.private.json",
    "oracle.private.json",
    "customer.json",
    "submission-outbox",
}
GENERATED_PARTS = {".pytest_cache", "__pycache__", "target", "dist", "build"}
IGNORED_PARTS = {".git", *GENERATED_PARTS}
RULE_FIXTURE_PATHS = {"tools/check_public_tree.py", "tests/test_public_tree_gate.py"}
ABSOLUTE_PATH_PATTERNS = (
    re.compile(r"/mnt/[a-z]/users/", re.IGNORECASE),
    re.compile(r"[a-z]:\\\\users\\\\", re.IGNORECASE),
)
MUTABLE_REFERENCE_PATTERNS = (
    re.compile(r"@latest\b", re.IGNORECASE),
    re.compile(r"\b(?:image|from)\s*[:=]?\s*[^\s]+:latest\b", re.IGNORECASE),
)
SIBLING_DEPENDENCY_PATTERNS = (
    re.compile(r"(?:^|[\s\"'])\.\./(?:core|ops|eval|legacy)(?:[/\s\"']|$)"),
    re.compile(r"\b(?:path|file)\s*=\s*[\"'][^\"']*(?:core|ops|eval|legacy)[^\"']*[\"']"),
    re.compile(r"\b-e\s+[^\s]+"),
)
DIRECT_NETWORK_IMPORTS = {
    "aiohttp",
    "http.client",
    "httpx",
    "requests",
    "socket",
    "urllib.request",
    "websockets",
}


@dataclass(frozen=True)
class Violation:
    path: str
    rule: str
    detail: str


def _iter_files(root: Path, *, ignored_parts: set[str]):
    for path in sorted(root.rglob("*")):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in ignored_parts for part in relative.parts):
            continue
        yield path, relative


def _python_imports(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return set()
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def _scan(root: Path, *, ignored_parts: set[str]) -> list[Violation]:
    root = root.resolve()
    violations: list[Violation] = []
    missing = REQUIRED_POLICY_FILES - {path.name for path in root.iterdir() if path.is_file()}
    for name in sorted(missing):
        violations.append(Violation(name, "missing_policy_file", "required public policy file"))

    for path, relative in _iter_files(root, ignored_parts=ignored_parts):
        display = relative.as_posix()
        if path.is_symlink():
            violations.append(Violation(display, "symlink_forbidden", "public repositories are self-contained"))
            continue
        if not path.is_file():
            continue
        if path.name.lower() in {name.lower() for name in PRIVATE_NAMES}:
            violations.append(Violation(display, "private_name", path.name))
        if path.stat().st_size > 5 * 1024 * 1024:
            violations.append(Violation(display, "unexpected_large_file", str(path.stat().st_size)))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if display not in RULE_FIXTURE_PATHS:
            for pattern in ABSOLUTE_PATH_PATTERNS:
                if pattern.search(text):
                    violations.append(Violation(display, "absolute_user_path", pattern.pattern))
            for pattern in MUTABLE_REFERENCE_PATTERNS:
                if pattern.search(text):
                    violations.append(Violation(display, "mutable_dependency", pattern.pattern))
            if not display.startswith("vendor/"):
                for pattern in SIBLING_DEPENDENCY_PATTERNS:
                    if pattern.search(text):
                        violations.append(
                            Violation(display, "sibling_dependency", pattern.pattern)
                        )

        pack_or_sdk = (
            display.startswith("packs/")
            or display.startswith("packages/sdk/")
            or display.startswith("packages/protocol/")
        )
        if pack_or_sdk and path.suffix == ".py":
            for imported in sorted(_python_imports(path)):
                if any(
                    imported == denied or imported.startswith(f"{denied}.")
                    for denied in DIRECT_NETWORK_IMPORTS
                ):
                    violations.append(
                        Violation(display, "direct_target_network_import", imported)
                    )
    return violations


def scan(root: Path) -> list[Violation]:
    """Scan a worktree while ignoring untracked generated output."""

    return _scan(root, ignored_parts=IGNORED_PARTS)


def scan_tracked_snapshot(root: Path) -> list[Violation]:
    """Scan every file materialized from an immutable tracked tree."""

    return _scan(root, ignored_parts={".git"})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path.cwd())
    args = parser.parse_args()
    violations = scan(args.root)
    print(
        json.dumps(
            {"ok": not violations, "violations": [asdict(item) for item in violations]},
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
