from __future__ import annotations

import hashlib
import secrets
import sqlite3
from pathlib import Path

import pytest

from faultloom import history_files as hf
from faultloom import work_history as wh


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / 'history'
    wh.initialize(directory)
    store = wh.WorkHistory(directory)
    case_id = store.create({'title': 'Archive test', 'track': 'client', 'domains': ['other'],
                            'state': 'active', 'subject': 'Synthetic fixture', 'origin': 'faultloom'})
    source = tmp_path / 'source'
    source.mkdir()
    content = b'Original report bytes\r\n\x00\xff'
    (source / 'report.pdf').write_bytes(content)
    return store, case_id, source, content


def archive(setup, **kwargs):
    store, case_id, root, content = setup
    return hf.archive_source(store, case_id, root, 'report.pdf', origin='test', label='Archived report',
                             expected_sha256=hashlib.sha256(content).hexdigest(), **kwargs)


def test_archive_is_exact_encrypted_and_survives_deleted_source(setup):
    store, case_id, root, content = setup
    result = archive(setup)
    assert (root / 'report.pdf').read_bytes() == content
    assert content not in (store.root / 'history.sqlite3').read_bytes()
    (root / 'report.pdf').unlink()
    data, observed = hf.read_attachment(store, case_id, result['event_id'])
    assert observed == content
    assert data['sha256'] == hashlib.sha256(content).hexdigest()
    assert hf.verify_archives(store)['verified_attachments'] == 1


def test_retry_after_source_disappears_is_idempotent(setup):
    store, case_id, root, _ = setup
    event_id = 'evt_' + secrets.token_hex(16)
    first = archive(setup, event_id=event_id)
    (root / 'report.pdf').unlink()
    repeated = archive(setup, event_id=event_id)
    assert repeated['appended'] == 0
    assert repeated['attachment'] == first['attachment']
    assert store.snapshot()['event_count'] == 2


def test_duplicate_content_reuses_blob_only_within_same_case(setup):
    store, case_id, root, content = setup
    first, second = archive(setup), archive(setup)
    assert first['attachment']['blob_id'] == second['attachment']['blob_id']
    other = store.create({'title': 'Other client', 'track': 'client', 'domains': ['other'],
                           'state': 'active', 'subject': 'Other fixture', 'origin': 'faultloom'})
    third = hf.archive_source(store, other, root, 'report.pdf', origin='test', label='Other copy',
                              expected_sha256=hashlib.sha256(content).hexdigest())
    assert third['attachment']['blob_id'] != first['attachment']['blob_id']
    with pytest.raises(wh.HistoryError, match='belong'):
        hf.read_attachment(store, other, first['event_id'])
    assert hf.verify_archives(store)['verified_attachments'] == 2


def test_blob_and_record_roll_back_together(setup, monkeypatch):
    store, _, _, _ = setup
    monkeypatch.setattr(wh, 'MAX_EVENTS', 1)
    with pytest.raises(wh.HistoryError, match='event limit'):
        archive(setup)
    with sqlite3.connect(store.root / 'history.sqlite3') as connection:
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE name='attachments'").fetchone()
        assert not exists or connection.execute('SELECT COUNT(*) FROM attachments').fetchone()[0] == 0
    assert store.snapshot()['event_count'] == 1


def test_changed_source_rejected_before_archive_mutation(setup):
    store, _, root, _ = setup
    (root / 'report.pdf').write_bytes(b'Later version')
    with pytest.raises(wh.HistoryError, match='source changed'):
        archive(setup)
    assert store.snapshot()['event_count'] == 1


def test_corrupt_ciphertext_fails_download_and_backup(setup, tmp_path):
    store, case_id, _, _ = setup
    result = archive(setup)
    with sqlite3.connect(store.root / 'history.sqlite3') as connection:
        encoded = connection.execute('SELECT envelope FROM attachments').fetchone()[0]
        damaged = encoded[:-1] + bytes([encoded[-1] ^ 1])
        connection.execute('UPDATE attachments SET envelope=?', (damaged,))
    with pytest.raises(wh.HistoryError):
        hf.read_attachment(store, case_id, result['event_id'])
    with pytest.raises(wh.HistoryError):
        store.backup(tmp_path / 'bad-backup')


def test_verified_backup_includes_attachments_without_original_source(setup, tmp_path):
    store, case_id, root, content = setup
    result = archive(setup)
    (root / 'report.pdf').unlink()
    backup = store.backup(tmp_path / 'backup')
    assert backup['verified_attachments'] == 1
    restored = wh.WorkHistory(tmp_path / 'backup')
    assert hf.read_attachment(restored, case_id, result['event_id'])[1] == content


def test_attachment_record_requires_matching_stored_blob(setup):
    store, case_id, _, _ = setup
    original = archive(setup)['attachment']
    fake = {**original, 'blob_id': 'a' * 64}
    with pytest.raises(wh.HistoryError, match='missing'):
        store.append_batch([wh.new_event(case_id, 'attachment', fake)])
    assert store.snapshot()['event_count'] == 2


def test_sources_distinguish_change_missing_unmapped_and_record_receipt(setup):
    store, case_id, root, _ = setup
    refs = []
    for name in ('unchanged.txt', 'changed.txt', 'missing.txt'):
        (root / name).write_text(name, encoding='utf-8')
        reference, _ = hf.capture_reference(root, name, origin='test', label=name)
        event = wh.new_event(case_id, 'file_reference', reference)
        refs.append(event)
    reference, _ = hf.capture_reference(root, 'unchanged.txt', origin='unmapped', label='Unmapped')
    refs.append(wh.new_event(case_id, 'file_reference', reference))
    store.append_batch(refs)
    (root / 'changed.txt').write_text('Changed content', encoding='utf-8')
    (root / 'missing.txt').unlink()
    operation = 'evt_' + secrets.token_hex(16)
    result = hf.check_sources(store, case_id, {'test': root}, event_id=operation)
    assert [row['status'] for row in result['checks']['results']] == ['unchanged', 'changed', 'missing', 'unmapped']
    assert hf.check_sources(store, case_id, {'test': root}, event_id=operation)['appended'] == 0
    assert store.snapshot()['cases'][0]['events'][-1]['kind'] == 'reference_check'


def test_check_budget_does_not_claim_unread_sources_unchanged(setup, monkeypatch):
    store, case_id, root, _ = setup
    ref, _ = hf.capture_reference(root, 'report.pdf', origin='test', label='Report')
    store.append_batch([wh.new_event(case_id, 'file_reference', ref)])
    monkeypatch.setattr(hf, 'MAX_CHECK_BYTES', 1)
    results = hf.check_sources(store, case_id, {'test': root})['checks']['results']
    assert results[0]['status'] == 'budget_exhausted'
    assert results[0]['observed_sha256'] is None


@pytest.mark.parametrize('path', ['../outside.pdf', '/absolute.pdf', 'C:/file.pdf', 'history.key', 'editor.access', 'CON.txt', '.env.json'])
def test_non_reference_paths_rejected(path):
    with pytest.raises(ValueError):
        hf.relative_file(path)


def test_archive_size_limit_and_foreign_case_receipt(setup, monkeypatch):
    store, case_id, root, _ = setup
    monkeypatch.setattr(hf, 'MAX_ARCHIVE_BYTES', 1)
    with pytest.raises(wh.HistoryError, match='archive limit'):
        archive(setup)
    other = store.create({'title': 'Other', 'track': 'research', 'domains': ['other'],
                           'state': 'active', 'subject': '', 'origin': 'faultloom'})
    ref, _ = hf.capture_reference(root, 'report.pdf', origin='test', label='Report')
    event = wh.new_event(case_id, 'file_reference', ref)
    store.append_batch([event])
    checks = hf.check_sources(store, case_id, {'test': root})['checks']
    with pytest.raises(wh.HistoryError, match='same case'):
        store.append_batch([wh.new_event(other, 'reference_check', checks)])


def test_cli_links_archives_extracts_and_verifies(setup, tmp_path, capsys):
    import json
    from faultloom.history_cli import main
    store, case_id, root, content = setup
    shared = ['--directory', str(store.root), '--case', case_id]
    file_args = ['--source-root', str(root), '--path', 'report.pdf', '--origin', 'test', '--label', 'Report']
    assert main(['link-file', *shared, *file_args]) == 0
    capsys.readouterr()
    assert main(['archive', *shared, *file_args, '--expected-sha256', hashlib.sha256(content).hexdigest()]) == 0
    result = json.loads(capsys.readouterr().out)
    output = tmp_path / 'restored.pdf'
    assert main(['extract', *shared, '--event', result['event_id'], '--out', str(output)]) == 0
    assert output.read_bytes() == content
    capsys.readouterr()
    assert main(['check-sources', *shared, '--reference-root', 'test=' + str(root), '--record']) == 0
    assert {row['status'] for row in json.loads(capsys.readouterr().out)['checks']['results']} == {'unchanged'}
    assert main(['verify', '--directory', str(store.root)]) == 0
    assert json.loads(capsys.readouterr().out)['verified_attachments'] == 1
