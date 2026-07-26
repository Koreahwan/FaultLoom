from __future__ import annotations

from pathlib import Path

from tools.check_public_tree import scan


def make_policies(root: Path) -> None:
    (root / "LICENSE").write_text("Apache License\nVersion 2.0\n", encoding="utf-8")
    (root / "NOTICE").write_text(
        "MIT License\nCopyright Terminator Project Contributors\n",
        encoding="utf-8",
    )
    for name in ("SECURITY.md", "ETHICAL_USE.md"):
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
    for directory in (".omo", ".venv", "dist", "out", "target"):
        generated = tmp_path / directory
        generated.mkdir()
        (generated / "customer.json").write_text("generated\n", encoding="utf-8")
    (tmp_path / "nul").write_text("generated\n", encoding="utf-8")
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


def test_private_repository_root_is_rejected(tmp_path: Path) -> None:
    make_policies(tmp_path)
    private = tmp_path / "ops"
    private.mkdir()
    (private / "engagement.json").write_text("{}\n", encoding="utf-8")
    assert {item.rule for item in scan(tmp_path)} == {"private_root"}


def test_secret_and_personal_data_are_rejected_but_placeholders_pass(tmp_path: Path) -> None:
    make_policies(tmp_path)
    (tmp_path / "safe.toml").write_text(
        'api_key = "redacted"\ncontact = "fixture@example.invalid"\n',
        encoding="utf-8",
    )
    assert scan(tmp_path) == []
    (tmp_path / "unsafe.yaml").write_text(
        "access_token: live-value-123\n"
        "owner: person@corp.example.edu\n"
        "phone: +1-212-555-0199\n",
        encoding="utf-8",
    )
    assert {item.rule for item in scan(tmp_path)} == {
        "pii_email",
        "pii_phone",
        "secret_assignment",
    }


def test_high_confidence_secret_material_is_rejected(tmp_path: Path) -> None:
    make_policies(tmp_path)
    (tmp_path / "leak.txt").write_text(
        "-----BEGIN PRIVATE KEY-----\nnot-real\n",
        encoding="utf-8",
    )
    assert {item.rule for item in scan(tmp_path)} == {"secret_material"}


def test_legal_and_package_metadata_are_required(tmp_path: Path) -> None:
    make_policies(tmp_path)
    package = tmp_path / "packages" / "runtime"
    package.mkdir(parents=True)
    (package / "pyproject.toml").write_text(
        '[project]\nname = "example"\nlicense = "MIT"\nlicense-files = ["LICENSE"]\n',
        encoding="utf-8",
    )
    rules = {item.rule for item in scan(tmp_path)}
    assert {"invalid_package_license", "missing_package_notice"} <= rules
