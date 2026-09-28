from __future__ import annotations

import hashlib
import runpy
import socket
from pathlib import Path

import pytest

from faultloom import knowledge
from faultloom.history_files import read_attachment, verify_archives
from faultloom.work_history import HistoryError, WorkHistory


DEMO = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'tools/history_demo.py'))


def test_demo_is_self_contained_synthetic_and_offline(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('demo attempted network access')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    destination = tmp_path / 'demo'
    result = DEMO['build_demo'](destination)
    store = WorkHistory(destination / 'history')
    snapshot = store.snapshot()
    assert result['synthetic_only'] is True
    assert result['cases'] == 3 and result['events'] == 15
    assert {case['track'] for case in snapshot['cases']} == {'research', 'bug_bounty', 'client'}
    assert all(case['subject'] == 'Synthetic example; no real engagement' for case in snapshot['cases'])
    for case in snapshot['cases']:
        archived = next(event for event in case['events'] if event['kind'] == 'attachment')
        data, raw = read_attachment(store, case['id'], archived['id'])
        assert raw == (destination / 'sources' / data['source']['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == data['sha256']
        check = next(event for event in case['events'] if event['kind'] == 'reference_check')
        assert all(row['status'] == 'unchanged' for row in check['data']['results'])
    assert verify_archives(WorkHistory(destination / 'backup'))['head'] == snapshot['head']
    catalogue = knowledge.load_catalog(destination / 'catalog.json')
    assert len(catalogue['entries']) == 3
    assert all(item['status'] == 'unchanged' for item in knowledge.check_catalog(catalogue, destination / 'sources')['entries'])
    assert 'references.html' in (destination / 'site/index.html').read_text(encoding='utf-8')
    assert 'index.html' in (destination / 'site/references.html').read_text(encoding='utf-8')


def test_demo_preserves_an_existing_destination(tmp_path):
    destination = tmp_path / 'existing'
    destination.mkdir()
    marker = destination / 'original.txt'
    marker.write_bytes(b'Keep the original')
    with pytest.raises(HistoryError, match='already exists'):
        DEMO['build_demo'](destination)
    assert list(destination.iterdir()) == [marker]
    assert marker.read_bytes() == b'Keep the original'


def test_demo_rejects_a_git_destination_before_writing(tmp_path):
    repository = tmp_path / 'repo'
    (repository / '.git').mkdir(parents=True)
    (repository / '.git/HEAD').write_text('ref: refs/heads/main\n', encoding='utf-8')
    destination = repository / 'demo'
    with pytest.raises(HistoryError, match='outside Git'):
        DEMO['build_demo'](destination)
    assert not destination.exists()


def test_demo_cli_reports_invalid_relative_path(capsys):
    assert DEMO['main'](['--out', 'relative-demo']) == 2
    assert 'absolute' in capsys.readouterr().out
