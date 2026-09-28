from __future__ import annotations

import copy
import hashlib
import html
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from faultloom import knowledge as kb
from faultloom import knowledge_cli
from faultloom.knowledge_view import render_overview


def fixture_catalog(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "templates").mkdir()
    (source / "templates" / "summary.md").write_text(
        "# Example summary\nOnly documented observations belong here.\n", encoding="utf-8"
    )
    (source / "role.md").write_text("Untrusted archived instructions, not executed.\n", encoding="utf-8")
    selection = {
        "schema": kb.SELECTION_SCHEMA,
        "origin": {"id": "archive", "label": "보존 자료"},
        "entries": [
            {"path": "templates/summary.md", "kind": "report_template", "title": "고객 요약 양식"},
            {"path": "role.md", "kind": "role_prompt", "title": "기존 역할 정의"},
        ],
    }
    spec = tmp_path / "selection.json"
    spec.write_text(json.dumps(selection, ensure_ascii=False), encoding="utf-8")
    catalog = kb.build_catalog(source, spec)
    return source, spec, catalog


def write_selection(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def test_build_records_hashes_and_keeps_all_references_inert(tmp_path: Path) -> None:
    source, _, catalog = fixture_catalog(tmp_path)
    assert catalog["schema"] == kb.CATALOG_SCHEMA
    assert len(catalog["entries"]) == 2
    assert catalog["content_status"] == "not_evaluated"
    assert catalog["use"] == "human_reference_only"
    assert str(source) not in json.dumps(catalog)
    for entry in catalog["entries"]:
        original = source / entry["path"]
        assert entry["sha256"] == hashlib.sha256(original.read_bytes()).hexdigest()
        assert entry["review"] == "unreviewed"
        assert "body" not in entry


def test_catalog_roundtrip_and_case_stable_ids(tmp_path: Path) -> None:
    source, spec, catalog = fixture_catalog(tmp_path)
    out = tmp_path / "catalog.json"
    kb.write_new(out, kb.json_bytes(catalog), source_root=source)
    assert kb.load_catalog(out) == catalog
    first_id = catalog["entries"][0]["id"]
    (source / "templates" / "summary.md").write_text("Updated wording", encoding="utf-8")
    rebuilt = kb.build_catalog(source, spec)
    assert rebuilt["entries"][0]["id"] == first_id
    assert rebuilt["entries"][0]["sha256"] != catalog["entries"][0]["sha256"]


def test_search_uses_all_terms_and_category_labels(tmp_path: Path) -> None:
    _, _, catalog = fixture_catalog(tmp_path)
    assert len(kb.search_catalog(catalog, "고객 요약")) == 1
    assert kb.search_catalog(catalog, "고객 역할") == []
    assert len(kb.search_catalog(catalog, "프롬프트")) == 1
    assert kb.search_catalog(catalog, "고객", kind="role_prompt") == []
    assert len(kb.search_catalog(catalog, "", limit=1)) == 1


def test_check_distinguishes_changed_missing_and_unchanged(tmp_path: Path) -> None:
    source, _, catalog = fixture_catalog(tmp_path)
    assert {row["status"] for row in kb.check_catalog(catalog, source)["entries"]} == {"unchanged"}
    (source / "templates" / "summary.md").write_text("Changed", encoding="utf-8")
    (source / "role.md").unlink()
    statuses = {row["path"]: row["status"] for row in kb.check_catalog(catalog, source)["entries"]}
    assert statuses == {"templates/summary.md": "changed", "role.md": "missing"}


def test_packet_has_exact_citations_and_no_source_bodies(tmp_path: Path) -> None:
    source, _, catalog = fixture_catalog(tmp_path)
    entry = catalog["entries"][0]
    packet = kb.make_packet(catalog, source, [entry["id"]], "고객 보고서 검토")
    assert entry["path"] in packet and entry["sha256"] in packet
    assert catalog["digest"] in packet
    assert "Only documented observations" not in packet
    assert "내용 검토 전" in packet
    assert "고객 보고서 검토" in packet


def test_packet_rejects_stale_and_retired_references(tmp_path: Path) -> None:
    source, spec, catalog = fixture_catalog(tmp_path)
    entry = catalog["entries"][0]
    (source / entry["path"]).write_text("Changed", encoding="utf-8")
    with pytest.raises(kb.CatalogError, match="changed"):
        kb.make_packet(catalog, source, [entry["id"]], "Review")
    selection = json.loads(spec.read_text(encoding="utf-8"))
    selection["entries"][0]["review"] = "retired"
    write_selection(spec, selection)
    current = kb.build_catalog(source, spec)
    with pytest.raises(kb.CatalogError, match="retired"):
        kb.make_packet(current, source, [entry["id"]], "Review")


def test_ids_must_be_known_unique_and_nonempty(tmp_path: Path) -> None:
    source, _, catalog = fixture_catalog(tmp_path)
    entry_id = catalog["entries"][0]["id"]
    for ids in ([], ["ref_unknown"], [entry_id, entry_id]):
        with pytest.raises(kb.CatalogError):
            kb.make_packet(catalog, source, ids, "Review")


@pytest.mark.parametrize("path", ["../outside.md", "/outside.md", "C:/outside.md", "a\\b.md", "a/../b.md", "./role.md", "NUL.md", "a:stream.md", "a./b.md", "//server/share.md", "role.md/"])
def test_selection_paths_are_portable_and_confined(tmp_path: Path, path: str) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    selection = json.loads(spec.read_text(encoding="utf-8"))
    selection["entries"][0]["path"] = path
    write_selection(spec, selection)
    with pytest.raises(kb.CatalogError):
        kb.build_catalog(source, spec)


def test_known_secret_files_are_not_catalogued(tmp_path: Path) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    (source / "credentials.json").write_text('{"fake":"example"}', encoding="utf-8")
    selection = json.loads(spec.read_text(encoding="utf-8"))
    selection["entries"][0]["path"] = "credentials.json"
    write_selection(spec, selection)
    with pytest.raises(kb.CatalogError):
        kb.build_catalog(source, spec)


def test_expected_hash_prevents_silent_change_since_selection(tmp_path: Path) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    selection = json.loads(spec.read_text(encoding="utf-8"))
    selection["entries"][0]["expected_sha256"] = "0" * 64
    write_selection(spec, selection)
    with pytest.raises(kb.CatalogError, match="selected digest"):
        kb.build_catalog(source, spec)


def test_duplicate_paths_and_unknown_fields_are_rejected(tmp_path: Path) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    selection = json.loads(spec.read_text(encoding="utf-8"))
    selection["entries"].append(copy.deepcopy(selection["entries"][0]))
    write_selection(spec, selection)
    with pytest.raises(kb.CatalogError):
        kb.build_catalog(source, spec)
    selection["entries"].pop()
    selection["execute"] = True
    write_selection(spec, selection)
    with pytest.raises(kb.CatalogError):
        kb.build_catalog(source, spec)


@pytest.mark.parametrize("raw", [b'{"schema":1,"schema":2}', b'{"schema":NaN}', b'[' * 1000 + b']' * 1000, b'\xff'], ids=["duplicate", "nonfinite", "deep", "encoding"])
def test_malformed_input_has_controlled_error(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(kb.CatalogError):
        kb.load_catalog(path)


def test_catalog_digest_and_types_are_checked(tmp_path: Path) -> None:
    source, _, catalog = fixture_catalog(tmp_path)
    path = tmp_path / "catalog.json"
    changed = copy.deepcopy(catalog)
    changed["entries"][0]["title"] = "Tampered"
    path.write_bytes(kb.json_bytes(changed))
    with pytest.raises(kb.CatalogError, match="digest"):
        kb.load_catalog(path)
    changed["entries"][0]["bytes"] = True
    changed["digest"] = kb.catalog_digest(changed)
    path.write_bytes(kb.json_bytes(changed))
    with pytest.raises(kb.CatalogError):
        kb.load_catalog(path)


def test_limits_apply_before_body_reads(tmp_path: Path, monkeypatch) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    monkeypatch.setattr(kb, "MAX_SOURCE_BYTES", 4)
    with pytest.raises(kb.CatalogError, match="limit"):
        kb.build_catalog(source, spec)


def test_symlink_sources_are_not_followed(tmp_path: Path) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    (source / "role.md").unlink()
    try:
        (source / "role.md").symlink_to(source / "templates" / "summary.md")
    except OSError:
        pytest.skip("OS does not permit user symlinks")
    with pytest.raises(kb.CatalogError):
        kb.build_catalog(source, spec)


def test_read_only_hardlinks_are_preserved(tmp_path: Path) -> None:
    source, spec, catalog = fixture_catalog(tmp_path)
    os.link(source / "role.md", tmp_path / "preserved.md")
    assert kb.build_catalog(source, spec)["entries"][1]["sha256"] == catalog["entries"][1]["sha256"]
    assert (source / "role.md").stat().st_nlink == 2


def test_path_and_handle_ctime_can_differ_without_a_false_change(tmp_path: Path, monkeypatch) -> None:
    source, spec, catalog = fixture_catalog(tmp_path)
    actual = os.fstat

    def handle_stat(descriptor):
        item = actual(descriptor)
        values = {key: getattr(item, key) for key in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
        values["st_ctime_ns"] += 1_000_000
        return SimpleNamespace(**values)

    monkeypatch.setattr(os, "fstat", handle_stat)
    assert kb.build_catalog(source, spec)["entries"] == catalog["entries"]


def test_outputs_never_replace_files_or_write_into_source(tmp_path: Path) -> None:
    source, _, _ = fixture_catalog(tmp_path)
    original = (source / "role.md").read_bytes()
    with pytest.raises(kb.CatalogError):
        kb.write_new(source / "new" / "output.md", b"output", source_root=source)
    assert not (source / "new").exists()
    destination = tmp_path / "result.md"
    kb.write_new(destination, b"first", source_root=source)
    with pytest.raises(kb.CatalogError):
        kb.write_new(destination, b"second", source_root=source)
    assert destination.read_bytes() == b"first"
    assert (source / "role.md").read_bytes() == original


def test_html_embeds_only_escaped_metadata(tmp_path: Path) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    selection = json.loads(spec.read_text(encoding="utf-8"))
    selection["entries"][0]["title"] = '</script><img src="https://invalid.example/tracker">'
    write_selection(spec, selection)
    catalog = kb.build_catalog(source, spec)
    page = render_overview(catalog, kb.check_catalog(catalog, source))
    assert '<img src="https://invalid.example/tracker">' not in page
    assert "Only documented observations" not in page
    assert "Untrusted archived instructions" not in page
    assert "connect-src 'none'" in html.unescape(page)
    assert "textContent" in page
    assert max(map(len, page.splitlines())) < 2000


def test_cli_works_without_network_and_verifies_before_packet_write(tmp_path: Path, monkeypatch, capsys) -> None:
    source, spec, _ = fixture_catalog(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("offline reference tools attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    destination = tmp_path / "catalog.json"
    assert knowledge_cli.main(["build", "--source-root", str(source), "--selection", str(spec), "--out", str(destination)]) == 0
    capsys.readouterr()
    assert knowledge_cli.main(["search", "--catalog", str(destination), "고객", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result["entries"]) == 1
    entry_id = result["entries"][0]["id"]
    (source / "templates" / "summary.md").write_text("Changed", encoding="utf-8")
    packet = tmp_path / "packet.md"
    assert knowledge_cli.main(["packet", "--catalog", str(destination), "--source-root", str(source), "--id", entry_id, "--purpose", "Review", "--out", str(packet)]) == 2
    assert not packet.exists()
    assert knowledge_cli.main(["check", "--catalog", str(destination), "--source-root", str(source)]) == 3


def test_integrated_cli_registers_knowledge_commands(tmp_path: Path, capsys) -> None:
    from faultloom import cli

    source, _, catalog = fixture_catalog(tmp_path)
    destination = tmp_path / "catalog.json"
    kb.write_new(destination, kb.json_bytes(catalog), source_root=source)
    assert cli.main(["knowledge", "search", "--catalog", str(destination), "프롬프트", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["entries"]) == 1


@pytest.mark.parametrize(("key", "value"), [("kind", []), ("review", {}), ("title", 3), ("tags", "tag")])
def test_bad_annotation_types_fail_cleanly(tmp_path: Path, key: str, value: object) -> None:
    source, spec, _ = fixture_catalog(tmp_path)
    selection = json.loads(spec.read_text(encoding="utf-8"))
    selection["entries"][0][key] = value
    write_selection(spec, selection)
    with pytest.raises(kb.CatalogError):
        kb.build_catalog(source, spec)


def test_aggregate_read_budget_is_enforced(tmp_path: Path, monkeypatch) -> None:
    source, spec, catalog = fixture_catalog(tmp_path)
    largest = max(item["bytes"] for item in catalog["entries"])
    monkeypatch.setattr(kb, "MAX_TOTAL_BYTES", largest)
    with pytest.raises(kb.CatalogError, match="limit"):
        kb.build_catalog(source, spec)


def test_output_parent_links_are_rejected(tmp_path: Path) -> None:
    source, _, _ = fixture_catalog(tmp_path)
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(source, target_is_directory=True)
    except OSError:
        pytest.skip("OS does not permit user symlinks")
    with pytest.raises(kb.CatalogError):
        kb.write_new(alias / "new.md", b"example", source_root=source)
    assert not (source / "new.md").exists()
