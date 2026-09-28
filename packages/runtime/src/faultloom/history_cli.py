"""Local work-history CLI: operator notes, historical metadata, and private exports."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import knowledge as files
from .history_legacy import import_tracker, preview_tracker
from .work_history import TRACKS, HistoryError, WorkHistory, initialize, new_event, source_reference, write_export


def _emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _handle(args):
    try:
        command = args.history_command
        if command == "init":
            _emit(initialize(args.directory))
            return 0
        if command == "preview-legacy":
            _emit(preview_tracker(args.source_root, args.path))
            return 0
        if command == "serve":
            from .history_server import serve
            serve(args.directory, args.session_file, port=args.port, catalog=args.catalog,
                  source_root=args.source_root, reference_roots=_roots(args.reference_root))
            return 0
        store = WorkHistory(args.directory)
        if command == "create":
            data = files._read_json(args.input)
            files._object(data, {"title", "track", "domains"}, {"subject", "state", "occurred_at"})
            occurred = data.pop("occurred_at", None)
            data = {"subject": "", "state": "active", **data, "origin": "faultloom"}
            _emit({"case_id": store.create(data, occurred_at=occurred)})
        elif command == "update":
            _emit({"event_id": store.update(args.case, files._read_json(args.input))})
        elif command == "record":
            data = files._read_json(args.input)
            files._object(data, {"kind", "summary"}, {"detail", "occurred_at", "corrects"})
            _emit({"event_id": store.record(args.case, data["kind"], data["summary"], data.get("detail", ""),
                                           occurred_at=data.get("occurred_at"), corrects=data.get("corrects"))})
        elif command == "link":
            reference = source_reference(args.source_root, args.path, origin=args.origin, label=args.label)
            event = new_event(args.case, "reference", reference)
            _emit({**store.append_batch([event]), "event_id": event["id"], "source_sha256": reference["sha256"]})
        elif command == "import-legacy":
            _emit(import_tracker(store, args.source_root, args.path, expected_sha256=args.expected_sha256))
        elif command == "backup":
            _emit(store.backup(args.out))
        elif command in {"link-file", "archive", "extract", "check-sources"}:
            from . import history_files
            if command == "link-file":
                reference, _ = history_files.capture_reference(args.source_root, args.path, origin=args.origin, label=args.label)
                event = new_event(args.case, "file_reference", reference)
                _emit({**store.append_batch([event]), "event_id": event["id"], "source_sha256": reference["sha256"]})
            elif command == "archive":
                _emit(history_files.archive_source(store, args.case, args.source_root, args.path,
                                                  origin=args.origin, label=args.label, expected_sha256=args.expected_sha256))
            elif command == "extract":
                metadata, raw = history_files.read_attachment(store, args.case, args.event)
                write_export(args.out, raw, history_root=store.root)
                _emit({"output": str(args.out), "sha256": metadata["sha256"], "bytes": len(raw)})
            else:
                import secrets
                event_id = "evt_" + secrets.token_hex(16) if args.record else None
                _emit(history_files.check_sources(store, args.case, _roots(args.reference_root), event_id=event_id))
        else:
            snapshot = store.snapshot()
            if command == "verify":
                from .history_files import verify_archives
                verified = verify_archives(store)
                _emit({"ok": True, "cases": len(snapshot["cases"]), "events": snapshot["event_count"],
                       "head": snapshot["head"], "attestation": snapshot["attestation"], **verified})
            elif command == "list":
                words = args.query.casefold().split()
                cases = [case for case in snapshot["cases"] if (not args.track or case["track"] == args.track)
                         and all(word in " ".join([case["title"], case["subject"], case["origin"], *case["domains"]]).casefold() for word in words)]
                _emit({"cases": [{key: value for key, value in case.items() if key != "events"} for case in cases]})
            elif command == "show":
                case = next((case for case in snapshot["cases"] if case["id"] == args.case), None)
                if case is None:
                    raise HistoryError("unknown case")
                _emit(case)
            elif command == "export":
                from .history_view import render_history, render_markdown
                if args.case:
                    selected = [case for case in snapshot["cases"] if case["id"] in args.case]
                    if len(selected) != len(set(args.case)) or len(args.case) != len(set(args.case)):
                        raise HistoryError("export case ids must be known and unique")
                    snapshot = {**snapshot, "cases": selected}
                snapshot["exported_case_count"] = len(snapshot["cases"])
                snapshot["event_count"] = sum(len(case["events"]) for case in snapshot["cases"])
                snapshot["export_scope"] = "selected_cases" if args.case else "all_cases"
                if args.format == "json":
                    content = files.json_bytes(snapshot)
                elif args.format == "markdown":
                    content = render_markdown(snapshot).encode("utf-8")
                else:
                    content = render_history(snapshot, reference_page=args.reference_page).encode("utf-8")
                write_export(args.out, content, history_root=store.root)
                _emit({"export": str(args.out), "cases": len(snapshot["cases"]), "privacy": "private_plaintext_export"})
        return 0
    except (HistoryError, files.CatalogError, OSError) as exc:
        print(f"faultloom history: {exc}", file=sys.stderr)
        return 2


def _roots(values):
    result = {}
    for value in values or []:
        origin, separator, path = value.partition("=")
        if not separator or not origin or origin in result:
            raise HistoryError("reference roots must be unique origin=absolute-directory mappings")
        result[origin] = files._root(Path(path))
    return result


def configure_history_parser(parser):
    commands = parser.add_subparsers(dest="history_command", required=True)
    init = commands.add_parser("init", help="create a private encrypted work-history directory")
    init.add_argument("--directory", type=Path, required=True)
    init.set_defaults(handler=_handle)
    server = commands.add_parser("serve", help="start an owner-local browser editor on 127.0.0.1")
    server.add_argument("--directory", type=Path, required=True)
    server.add_argument("--session-file", type=Path, required=True)
    server.add_argument("--port", type=int, default=0)
    server.add_argument("--catalog", type=Path)
    server.add_argument("--source-root", type=Path)
    server.add_argument("--reference-root", action="append", default=[], help="origin=absolute-directory source mapping")
    server.set_defaults(handler=_handle)
    for command in ("create", "update", "record", "link", "import-legacy", "list", "show", "verify", "export", "backup",
                    "link-file", "archive", "extract", "check-sources"):
        item = commands.add_parser(command)
        item.add_argument("--directory", type=Path, required=True)
        if command in {"create", "update", "record"}:
            item.add_argument("--input", type=Path, required=True)
        if command in {"update", "record", "link", "show", "link-file", "archive", "extract", "check-sources"}:
            item.add_argument("--case", required=True)
        if command in {"link", "import-legacy", "link-file", "archive"}:
            item.add_argument("--source-root", type=Path, required=True)
            item.add_argument("--path", default="coordination/SUBMISSIONS.md" if command == "import-legacy" else None,
                              required=command != "import-legacy")
        if command in {"link", "link-file", "archive"}:
            item.add_argument("--origin", required=True)
            item.add_argument("--label", required=True)
        if command in {"import-legacy", "archive"}:
            item.add_argument("--expected-sha256", required=True)
        if command == "list":
            item.add_argument("--track", choices=tuple(TRACKS))
            item.add_argument("--query", default="")
        if command == "export":
            item.add_argument("--format", choices=("html", "json", "markdown"), default="html")
            item.add_argument("--out", type=Path, required=True)
            item.add_argument("--case", action="append")
            item.add_argument("--reference-page", help="optional sibling HTML reference page")
        if command == "backup":
            item.add_argument("--out", type=Path, required=True)
        if command == "extract":
            item.add_argument("--event", required=True)
            item.add_argument("--out", type=Path, required=True)
        if command == "check-sources":
            item.add_argument("--reference-root", action="append", required=True)
            item.add_argument("--record", action="store_true")
        item.set_defaults(handler=_handle)
    preview = commands.add_parser("preview-legacy", help="read only the historical tracker metadata")
    preview.add_argument("--source-root", type=Path, required=True)
    preview.add_argument("--path", default="coordination/SUBMISSIONS.md")
    preview.set_defaults(handler=_handle)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="faultloom history")
    configure_history_parser(parser)
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
