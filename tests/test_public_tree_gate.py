from __future__ import annotations

from pathlib import Path

from tools.check_public_tree import scan


def make_policies(root: Path) -> None:
    for name in ("LICENSE", "NOTICE", "SECURITY.md", "ETHICAL_USE.md"):
        (root / name).write_text("policy\n", encoding="utf-8")


def test_clean_self_contained_tree_passes(tmp_path: Path) -> None:
    make_policies(tmp_path)
    package = tmp_path / "packs" / "web"
    package.mkdir(parents=True)
    (package / "pack.py").write_text("from dataclasses import dataclass\n", encoding="utf-8")
    assert scan(tmp_path) == []


def test_private_absolute_mutable_and_sibling_inputs_fail(tmp_path: Path) -> None:
    make_policies(tmp_path)
    package = tmp_path / "packs" / "web"
    package.mkdir(parents=True)
    (package / ".env").write_text("TOKEN=redacted\n", encoding="utf-8")
    (package / "pack.py").write_text(
        'import socket\nPATH = "/mnt/c/users/example/private"\nIMAGE = "tool:latest"\n',
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        'dependency = { path = "../ops" }\n', encoding="utf-8"
    )
    rules = {item.rule for item in scan(tmp_path)}
    assert {
        "private_name",
        "absolute_user_path",
        "mutable_dependency",
        "sibling_dependency",
        "direct_target_network_import",
    } <= rules


def test_symlink_is_rejected_without_following(tmp_path: Path) -> None:
    make_policies(tmp_path)
    outside = tmp_path.parent / "outside-secret"
    outside.write_text("secret that must not be read", encoding="utf-8")
    (tmp_path / "linked").symlink_to(outside)
    violations = scan(tmp_path)
    assert [(item.path, item.rule) for item in violations] == [
        ("linked", "symlink_forbidden")
    ]


def test_untracked_generated_output_is_ignored(tmp_path: Path) -> None:
    make_policies(tmp_path)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "customer.json").write_text("generated\n", encoding="utf-8")
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / ".env").write_text("generated\n", encoding="utf-8")
    assert scan(tmp_path) == []


def test_vendored_source_skips_only_first_party_sibling_heuristic(tmp_path: Path) -> None:
    make_policies(tmp_path)
    crate = tmp_path / "vendor/example-1.0.0"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text('path = "../core"\n', encoding="utf-8")
    assert scan(tmp_path) == []
    (crate / "README.md").write_text('image = "tool:latest"\n', encoding="utf-8")
    assert {item.rule for item in scan(tmp_path)} == {"mutable_dependency"}


def test_current_public_tree_passes() -> None:
    root = Path(__file__).resolve().parents[1]
    assert scan(root) == []
