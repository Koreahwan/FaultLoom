"""Bounded, read-only import of historical submission-table metadata."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from . import knowledge as files
from .work_history import HistoryError, WorkHistory, _canonical, _date, new_event

HEADERS = {
    "Active (Pending / Triage)": ["Platform", "Target", "Title", "Sev", "Bounty", "Status", "Submitted", "Last Check", "Note"],
    "Resolved (Accepted / Rejected / Closed)": ["Platform", "Target", "Title", "Sev", "Bounty", "Status", "Submitted", "Resolved", "Memory Lesson"],
}


def _cells(line: str) -> list[str]:
    if not line.startswith("|") or not line.endswith("|"):
        raise HistoryError("unsupported tracker table row")
    return [cell.strip().replace(r"\|", "|") for cell in re.split(r"(?<!\\)\|", line[1:-1])]


def _historical_date(value: str) -> str | None:
    return None if value in {"", "—", "-", "N/A"} else _date(value)


def preview_tracker(source_root: Path, relative: str = "coordination/SUBMISSIONS.md") -> dict:
    root = files._root(source_root)
    relative = files._relative(relative)
    raw = files._capture(root / relative, files.MAX_SOURCE_BYTES)
    source = {"origin": "terminator", "path": relative, "sha256": hashlib.sha256(raw).hexdigest(),
              "bytes": len(raw), "label": "Terminator 과거 제출표"}
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeError as exc:
        raise HistoryError("tracker must be UTF-8 text") from exc
    section, header, separator = None, None, False
    records, identities, sections = [], set(), set()
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if line.startswith("## "):
            section = line[3:]
            header, separator = None, False
            continue
        if section not in HEADERS or not line.startswith("|"):
            continue
        cells = _cells(line)
        if header is None:
            if cells != HEADERS[section]:
                raise HistoryError("tracker table headers differ; review the importer before proceeding")
            header = cells
            sections.add(section)
            continue
        if not separator:
            if len(cells) != len(header) or not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                raise HistoryError("invalid tracker table separator")
            separator = True
            continue
        if len(cells) != len(header):
            raise HistoryError(f"tracker row {line_number} has unexpected columns")
        row = dict(zip(header, cells, strict=True))
        # Notes/Memory Lesson can contain private technical details or old action
        # instructions. Keep only their source pointer, not their contents.
        identity = hashlib.sha256(_canonical({"origin": "terminator", "path": relative,
                                               "platform": row["Platform"], "subject": row["Target"],
                                               "title": row["Title"]})).hexdigest()[:24]
        if identity in identities:
            raise HistoryError("ambiguous duplicate row identity")
        identities.add(identity)
        records.append({"case_id": "case_" + identity,
                        "case": {"title": row["Title"], "subject": row["Target"], "track": "bug_bounty",
                                 "domains": ["unknown"], "state": "historical", "origin": "terminator"},
                        "snapshot": {"source": source, "line": line_number, "section": section,
                                     "platform": row["Platform"], "status": row["Status"],
                                     "severity": row["Sev"], "bounty_text": row["Bounty"],
                                     "submitted": _historical_date(row["Submitted"]),
                                     "checked": _historical_date(row.get("Last Check", "")),
                                     "resolved": _historical_date(row.get("Resolved", ""))}})
        if len(records) > 1000:
            raise HistoryError("tracker exceeds the row limit")
    if sections != set(HEADERS) or not records:
        raise HistoryError("expected historical tracker tables were not found")
    return {"schema": "faultloom.legacy-history-preview.v1", "source": source, "records": records,
            "excluded_columns": ["Note", "Memory Lesson"], "status_freshness": "historical_not_live_checked"}


def import_tracker(store: WorkHistory, source_root: Path, relative: str = "coordination/SUBMISSIONS.md",
                   *, expected_sha256: str) -> dict:
    files._sha(expected_sha256)
    preview = preview_tracker(source_root, relative)
    if preview["source"]["sha256"] != expected_sha256:
        raise HistoryError("tracker differs from the reviewed snapshot")
    current = store.snapshot()
    known = {case["id"] for case in current["cases"]}
    additions = []
    for row in preview["records"]:
        case_id = row["case_id"]
        if case_id not in known:
            event_id = "evt_" + hashlib.sha256((case_id + ":create").encode()).hexdigest()[:32]
            additions.append(new_event(case_id, "case_created", row["case"], event_id=event_id))
        data = row["snapshot"]
        event_id = "evt_" + hashlib.sha256((case_id + ":" + preview["source"]["sha256"]).encode()).hexdigest()[:32]
        additions.append(new_event(case_id, "legacy_snapshot", data,
                                   occurred_at=data["checked"] or data["resolved"], event_id=event_id))
    result = store.append_batch(additions, expected_head=current["head"])
    return {**result, "rows": len(preview["records"]), "new_cases": len(preview["records"]) - len(known.intersection(row["case_id"] for row in preview["records"])),
            "source_sha256": preview["source"]["sha256"], "status_freshness": preview["status_freshness"]}
