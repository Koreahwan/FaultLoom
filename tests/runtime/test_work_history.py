from __future__ import annotations

import hashlib
import json
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from faultloom import work_history as wh
from faultloom.history_legacy import import_tracker, preview_tracker


def case_data(title="Private client name"):
    return {"title": title, "track": "client", "domains": ["web_api", "ai"],
            "state": "active", "subject": "Private engagement", "origin": "faultloom"}


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "private-history"
    wh.initialize(root)
    return wh.WorkHistory(root)


def test_roundtrip_preserves_notes_and_corrections(store):
    case_id = store.create(case_data(), occurred_at="2026-09-26")
    first = store.record(case_id, "decision", "Original decision", "Evidence still incomplete.")
    store.record(case_id, "correction", "Correction", "Later review changes the decision.", corrects=first)
    reopened = wh.WorkHistory(store.root).snapshot()
    assert reopened["event_count"] == 3
    case = reopened["cases"][0]
    assert case["domains"] == ["web_api", "ai"]
    assert case["events"][0]["occurred_at"] == "2026-09-26"
    assert case["events"][1]["data"]["summary"] == "Original decision"
    assert case["events"][2]["data"]["corrects"] == first


def test_database_contains_no_plaintext_records(store):
    case_id = store.create(case_data("Private customer UNIQUE987654"))
    store.record(case_id, "note", "PRIVATE TITLE ABCDEFG", "PRIVATE BODY 987654321")
    for path in store.root.glob("history.sqlite3*"):
        raw = path.read_bytes()
        assert b"UNIQUE987654" not in raw
        assert b"PRIVATE TITLE" not in raw
        assert b"PRIVATE BODY" not in raw


def test_wrong_key_rejected_before_writes(store):
    store.create(case_data())
    before = (store.root / "history.sqlite3").read_bytes()
    (store.root / "history.key").write_bytes(b"0" * 32)
    with pytest.raises(wh.HistoryError):
        store.create(case_data("Should not exist"))
    assert (store.root / "history.sqlite3").read_bytes() == before


@pytest.mark.parametrize("damage", ["ciphertext", "gap", "previous", "tail"])
def test_corrupt_history_is_not_replayed(store, damage):
    case_id = store.create(case_data())
    store.record(case_id, "note", "Second event")
    with sqlite3.connect(store.root / "history.sqlite3") as connection:
        if damage == "gap":
            connection.execute("DELETE FROM events WHERE sequence = 1")
        elif damage == "tail":
            connection.execute("DELETE FROM events WHERE sequence = 2")
        else:
            outer = json.loads(connection.execute("SELECT envelope FROM events WHERE sequence=2").fetchone()[0])
            if damage == "previous":
                outer["previous"] = wh.ZERO
            else:
                outer["ciphertext"] = "AAAA"
            connection.execute("UPDATE events SET envelope=? WHERE sequence=2", (wh._canonical(outer),))
    with pytest.raises(wh.HistoryError):
        store.snapshot()


def test_batch_failure_rolls_back_earlier_insert(store, monkeypatch):
    case_id = store.create(case_data())
    before = store.snapshot()
    events = [wh.new_event(case_id, "note", {"summary": "one", "detail": ""}),
              wh.new_event(case_id, "note", {"summary": "two", "detail": "longer " * 150})]
    with sqlite3.connect(store.root / "history.sqlite3") as connection:
        total = connection.execute("SELECT SUM(LENGTH(envelope)) FROM events").fetchone()[0]
    monkeypatch.setattr(wh, "MAX_BYTES", total + 850)
    with pytest.raises(wh.HistoryError, match="byte limit"):
        store.append_batch(events)
    after = store.snapshot()
    assert after["head"] == before["head"]
    assert after["cases"] == before["cases"]


def test_concurrent_writers_keep_all_events(store):
    case_id = store.create(case_data())
    def add(index):
        return wh.WorkHistory(store.root).record(case_id, "note", f"Concurrent note {index}")
    with ThreadPoolExecutor(max_workers=4) as pool:
        identifiers = list(pool.map(add, range(12)))
    snapshot = store.snapshot()
    assert snapshot["event_count"] == 13
    assert {event["id"] for event in snapshot["cases"][0]["events"][1:]} == set(identifiers)


def test_journal_can_disappear_between_metadata_checks(store, monkeypatch):
    case_id = store.create(case_data())
    original_exists, original_lstat = Path.exists, Path.lstat

    def exists(path):
        return True if path.name == "history.sqlite3-journal" else original_exists(path)

    def lstat(path):
        if path.name == "history.sqlite3-journal":
            raise FileNotFoundError("Another transaction already removed the sidecar")
        return original_lstat(path)

    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(Path, "lstat", lstat)
    store.record(case_id, "note", "Write survives normal journal removal")
    assert store.snapshot()["event_count"] == 2


def test_stale_edits_do_not_overwrite_new_records(store):
    case_id = store.create(case_data())
    before = store.snapshot()
    store.record(case_id, "note", "Other writer's work")
    with pytest.raises(wh.HistoryError, match="concurrently"):
        store.append_batch([wh.new_event(case_id, "case_updated", case_data("Lost update"))], expected_head=before["head"])
    assert store.snapshot()["cases"][0]["title"] == "Private client name"
    store.update(case_id, {"state": "waiting"})
    assert store.snapshot()["cases"][0]["state"] == "waiting"


def test_corrections_cannot_cross_cases(store):
    first = store.create(case_data())
    second = store.create(case_data("Another case"))
    target = store.record(first, "note", "First case")
    with pytest.raises(wh.HistoryError, match="same case"):
        store.record(second, "correction", "Wrong case", corrects=target)
    assert store.snapshot()["event_count"] == 3


def test_duplicate_event_is_idempotent_but_conflict_fails(store):
    case_id = store.create(case_data())
    event = wh.new_event(case_id, "note", {"summary": "Idempotent", "detail": ""})
    assert store.append_batch([event])["appended"] == 1
    repeated = {**event, "recorded_at": "2026-09-29T01:00:00+09:00"}
    assert store.append_batch([repeated])["appended"] == 0
    with pytest.raises(wh.HistoryError, match="conflicts"):
        store.append_batch([{**event, "data": {"summary": "Different", "detail": ""}}])


@pytest.mark.parametrize("change", [{"track": "illegal"}, {"domains": []}, {"domains": ["ai", "unknown"]},
                                    {"title": "x\x00y"}, {"state": "vendor_verified"}])
def test_invalid_case_inputs_do_not_write(store, change):
    with pytest.raises(wh.HistoryError):
        store.create({**case_data(), **change})
    assert store.snapshot()["event_count"] == 0


def test_private_directory_is_create_only_and_not_in_git(tmp_path):
    (tmp_path / ".git").mkdir()
    root = tmp_path / "history"
    wh.initialize(root)
    before = (root / "history.key").read_bytes()
    with pytest.raises(wh.HistoryError):
        wh.initialize(root)
    assert (root / "history.key").read_bytes() == before
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").write_text("gitdir: elsewhere")
    with pytest.raises(wh.HistoryError, match="Git"):
        wh.initialize(repository / "history")
    with pytest.raises(wh.HistoryError, match="Git"):
        wh.write_export(repository / "leak.json", b"private", history_root=root)


def tracker(tmp_path):
    root = tmp_path / "legacy"
    (root / "coordination").mkdir(parents=True)
    path = root / "coordination/SUBMISSIONS.md"
    path.write_text("""# Historical tracker
## Active (Pending / Triage)
| Platform | Target | Title | Sev | Bounty | Status | Submitted | Last Check | Note |
|---|---|---|---|---|---|---|---|---|
| Platform A | Example | Earlier record | High | est $900 | Hold (submission unverified) | — | 2026-06-30 | PRIVATE TECHNICAL BODY |
## Resolved (Accepted / Rejected / Closed)
| Platform | Target | Title | Sev | Bounty | Status | Submitted | Resolved | Memory Lesson |
|---|---|---|---|---|---|---|---|---|
| Platform B | Other | Closed record | Low | — | Duplicate | 2026-04-03 | 2026-06-26 | INSTRUCTION DO NOT EXECUTE |
""", encoding="utf-8")
    return root, path


def test_import_keeps_historical_status_and_dates_without_notes(store, tmp_path):
    root, path = tracker(tmp_path)
    before = path.read_bytes()
    preview = preview_tracker(root)
    result = import_tracker(store, root, expected_sha256=preview["source"]["sha256"])
    assert result["new_cases"] == 2
    assert result["appended"] == 4
    repeated = import_tracker(store, root, expected_sha256=preview["source"]["sha256"])
    assert repeated["appended"] == 0
    snapshot = store.snapshot()
    encoded = json.dumps(snapshot)
    assert "PRIVATE TECHNICAL BODY" not in encoded
    assert "INSTRUCTION DO NOT EXECUTE" not in encoded
    case = next(case for case in snapshot["cases"] if case["title"] == "Earlier record")
    original = case["events"][-1]
    assert case["state"] == "historical"
    assert original["occurred_at"] == "2026-06-30"
    assert original["data"]["submitted"] is None
    assert original["data"]["status"] == "Hold (submission unverified)"
    assert original["data"]["bounty_text"] == "est $900"
    assert path.read_bytes() == before


def test_changed_snapshot_appends_without_rewriting_prior_status(store, tmp_path):
    root, path = tracker(tmp_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    import_tracker(store, root, expected_sha256=digest)
    path.write_text(path.read_text(encoding="utf-8").replace("Duplicate", "Closed"), encoding="utf-8")
    with pytest.raises(wh.HistoryError, match="reviewed snapshot"):
        import_tracker(store, root, expected_sha256=digest)
    result = import_tracker(store, root, expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    assert result["new_cases"] == 0
    assert result["appended"] == 2
    case = next(case for case in store.snapshot()["cases"] if case["title"] == "Closed record")
    assert [event["data"]["status"] for event in case["events"][1:]] == ["Duplicate", "Closed"]


def test_import_rejects_table_drift(tmp_path):
    root, path = tracker(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace("Last Check", "Changed Header"), encoding="utf-8")
    with pytest.raises(wh.HistoryError, match="headers"):
        preview_tracker(root)


def test_history_storage_opens_no_network(store, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("history attempted a network operation")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    case_id = store.create(case_data())
    store.record(case_id, "negative_result", "Expected behavior observed")
    assert store.snapshot()["event_count"] == 2


def test_cli_create_record_edit_and_export(tmp_path, capsys):
    from faultloom.history_cli import main
    root = tmp_path / "cli-history"
    assert main(["init", "--directory", str(root)]) == 0
    capsys.readouterr()
    creation = tmp_path / "create.json"
    creation.write_text(json.dumps({"title": "Local research", "track": "research", "domains": ["ai"]}), encoding="utf-8")
    assert main(["create", "--directory", str(root), "--input", str(creation)]) == 0
    case_id = json.loads(capsys.readouterr().out)["case_id"]
    note = tmp_path / "note.json"
    note.write_text(json.dumps({"kind": "negative_result", "summary": "No issue observed", "detail": "The control behaved as expected."}), encoding="utf-8")
    assert main(["record", "--directory", str(root), "--case", case_id, "--input", str(note)]) == 0
    capsys.readouterr()
    note.write_text('{"state":"closed"}', encoding="utf-8")
    assert main(["update", "--directory", str(root), "--case", case_id, "--input", str(note)]) == 0
    capsys.readouterr()
    assert main(["verify", "--directory", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["events"] == 3
    wh.WorkHistory(root).create(case_data("Other client must stay excluded"))
    for format, suffix in (("html", "html"), ("json", "json"), ("markdown", "md")):
        output = tmp_path / ("export." + suffix)
        assert main(["export", "--directory", str(root), "--format", format, "--out", str(output), "--case", case_id]) == 0
        assert output.is_file()
        assert "Other client must stay excluded" not in output.read_text(encoding="utf-8")
        if format == "json":
            exported = json.loads(output.read_text(encoding="utf-8"))
            assert exported["event_count"] == 3
            assert exported["export_scope"] == "selected_cases"
        assert main(["export", "--directory", str(root), "--format", format, "--out", str(output)]) == 2


def test_html_escapes_metadata_and_note_bodies(store):
    from faultloom.history_view import render_history, render_markdown
    case_id = store.create(case_data('</script><img src="https://invalid.example">'))
    store.record(case_id, "note", "A note", '<script>alert("untrusted")</script>')
    snapshot = store.snapshot()
    page = render_history(snapshot)
    assert '<img src="https://invalid.example">' not in page
    assert '<script>alert("untrusted")</script>' not in page
    assert "\\u003c/script\\u003e" in page
    assert "innerHTML" not in page
    assert "&lt;script&gt;" in render_markdown(snapshot)
    assert 'href="references.html"' in render_history(snapshot, reference_page="references.html")
    with pytest.raises(ValueError, match="local HTML"):
        render_history(snapshot, reference_page="https://example.com/private")


def test_integrated_cli_registers_history(tmp_path, capsys):
    from faultloom.cli import main
    root = tmp_path / "registered-history"
    wh.initialize(root)
    assert main(["history", "verify", "--directory", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["events"] == 0


def test_backup_can_be_opened_independently_without_touching_original(store, tmp_path):
    case_id = store.create(case_data())
    store.record(case_id, "report", "Report prepared")
    before = store.snapshot()
    destination = tmp_path / "private-backup"
    result = store.backup(destination)
    assert result["head"] == before["head"]
    copy = wh.WorkHistory(destination)
    assert copy.snapshot()["cases"] == before["cases"]
    copy.record(case_id, "note", "Backup-only note")
    assert store.snapshot()["event_count"] == 2
    assert copy.snapshot()["event_count"] == 3
    with pytest.raises(wh.HistoryError, match="new private directory"):
        store.backup(destination)
