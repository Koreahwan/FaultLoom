#!/usr/bin/env python3
"""Create a local, synthetic demonstration of the research notebook."""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packages/runtime/src'))
from faultloom import knowledge
from faultloom.history_files import archive_source, capture_reference, check_sources, verify_archives
from faultloom.history_view import render_history
from faultloom.knowledge_view import render_overview
from faultloom.work_history import HistoryError, WorkHistory, _inside_git, _safe_path, initialize, new_event, write_export


SAMPLES = (
    ('research', ['ai'], 'Synthetic research notes', 'method.md', 'research_note',
     '# Synthetic research method\nRecord input versions, observations, missing context, and uncertainty.\n'),
    ('bug_bounty', ['web_api'], 'Synthetic bounty notes', 'report-template.md', 'report_template',
     '# Synthetic report template\nSummary, evidence, limitations, and reviewer notes. No real finding.\n'),
    ('client', ['web3'], 'Synthetic client notes', 'review-checklist.md', 'guide',
     '# Synthetic review checklist\nKeep source versions and delivery records. No real customer.\n'),
)


def build_demo(destination: Path) -> dict:
    root = _safe_path(destination)
    if _inside_git(root):
        raise HistoryError('create demo data outside Git worktrees')
    if root.exists():
        raise HistoryError('demo destination already exists; choose a new directory')
    root.mkdir(parents=True, mode=0o700)
    sources = root / 'sources'
    sources.mkdir(mode=0o700)
    initialize(root / 'history')
    store = WorkHistory(root / 'history')
    entries = []
    for track, domains, title, filename, kind, content in SAMPLES:
        with (sources / filename).open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
        entries.append({'path': filename, 'kind': kind, 'title': title})
        case_id = store.create({'title': title, 'track': track, 'domains': domains,
                               'subject': 'Synthetic example; no real engagement',
                               'state': 'planned', 'origin': 'faultloom'})
        store.record(case_id, 'note', 'Synthetic example only',
                     'This record demonstrates provenance and storage. It records no real research result.')
        reference, _ = capture_reference(sources, filename, origin='demo', label=title)
        store.append_batch([new_event(case_id, 'file_reference', reference)])
        archive_source(store, case_id, sources, filename, origin='demo', label=title,
                       expected_sha256=reference['sha256'])
        check_sources(store, case_id, {'demo': sources}, event_id='evt_' + secrets.token_hex(16))
    selection = {'schema': knowledge.SELECTION_SCHEMA,
                 'origin': {'id': 'demo', 'label': 'Synthetic examples'}, 'entries': entries}
    selection_path = root / 'selection.json'
    knowledge.write_new(selection_path, knowledge.json_bytes(selection), source_root=sources)
    catalogue = knowledge.build_catalog(sources, selection_path)
    knowledge.write_new(root / 'catalog.json', knowledge.json_bytes(catalogue), source_root=sources)
    checks = knowledge.check_catalog(catalogue, sources)
    snapshot = store.snapshot()
    write_export(root / 'site/index.html', render_history(snapshot, reference_page='references.html').encode('utf-8'),
                 history_root=store.root)
    write_export(root / 'site/references.html', render_overview(catalogue, checks, history_page='index.html').encode('utf-8'),
                 history_root=store.root)
    verified = verify_archives(store)
    backup = store.backup(root / 'backup')
    if backup['head'] != verified['head']:
        raise HistoryError('demo backup differs from the source history')
    result = {'schema': 'faultloom.synthetic-notebook-demo.v1', 'synthetic_only': True,
              **verified, 'references': len(catalogue['entries']), 'backup_head': backup['head'],
              'site': 'site/index.html', 'public_research_result': False}
    knowledge.write_new(root / 'demo.json', knowledge.json_bytes(result), source_root=sources)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='new absolute directory outside Git')
    args = parser.parse_args(argv)
    try:
        result = build_demo(args.out)
    except (OSError, HistoryError, knowledge.CatalogError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({'ok': True, **result}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
