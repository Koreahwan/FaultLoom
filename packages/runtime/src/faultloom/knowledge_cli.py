"""Cross-platform offline reference commands; also usable without runtime dependencies."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import knowledge as kb
from .knowledge_view import render_overview


def _emit(document: dict) -> None:
    print(json.dumps(document, ensure_ascii=False, indent=2))


def _handle(arguments: argparse.Namespace) -> int:
    try:
        operation = arguments.knowledge_command
        if operation == "build":
            catalog = kb.build_catalog(arguments.source_root, arguments.selection)
            kb.write_new(arguments.out, kb.json_bytes(catalog), source_root=arguments.source_root)
            _emit({"catalog": str(arguments.out), "entries": len(catalog["entries"]),
                   "digest": catalog["digest"], "use": catalog["use"]})
            return 0
        catalog = kb.load_catalog(arguments.catalog)
        if operation == "search":
            entries = kb.search_catalog(catalog, arguments.query, kind=arguments.kind, limit=arguments.limit)
            if arguments.json:
                _emit({"catalog_digest": catalog["digest"], "entries": entries})
            else:
                print(f"{len(entries)} reference(s)")
                for entry in entries:
                    print(f"{entry['id']}  {entry['title']} [{kb.KINDS[entry['kind']]}]")
                    print(f"  {entry['path']} | {kb.REVIEWS[entry['review']]}")
            return 0
        if operation == "packet":
            content = kb.make_packet(catalog, arguments.source_root, arguments.ids, arguments.purpose)
            kb.write_new(arguments.out, content.encode("utf-8"), source_root=arguments.source_root)
            _emit({"packet": str(arguments.out), "references": len(arguments.ids),
                   "content_status": "requires_human_review"})
            return 0
        checks = kb.check_catalog(catalog, arguments.source_root)
        if operation == "view":
            page = render_overview(catalog, checks, history_page=arguments.history_page)
            kb.write_new(arguments.out, page.encode("utf-8"), source_root=arguments.source_root)
            _emit({"overview": str(arguments.out), "entries": len(catalog["entries"]),
                   "source_status": dict(Counter(item["status"] for item in checks["entries"]))})
            return 0
        counts = dict(Counter(item["status"] for item in checks["entries"]))
        if arguments.json:
            _emit(checks)
        else:
            _emit({"catalog_digest": catalog["digest"], "checked_at": checks["checked_at"],
                   "source_status": counts})
        return 0 if counts.get("unchanged", 0) == len(catalog["entries"]) else 3
    except (kb.CatalogError, OSError) as exc:
        print(f"faultloom knowledge: {exc}", file=sys.stderr)
        return 2


def configure_knowledge_parser(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="knowledge_command", required=True)
    build = commands.add_parser("build", help="catalogue explicitly selected local references")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--selection", type=Path, required=True)
    build.add_argument("--out", type=Path, required=True)
    build.set_defaults(handler=_handle)

    search = commands.add_parser("search", help="search catalogue metadata without reading bodies")
    search.add_argument("--catalog", type=Path, required=True)
    search.add_argument("query", nargs="?", default="")
    search.add_argument("--kind", choices=tuple(kb.KINDS))
    search.add_argument("--limit", type=int, default=50)
    search.add_argument("--json", action="store_true")
    search.set_defaults(handler=_handle)

    check = commands.add_parser("check", help="check current source hashes without changing sources")
    check.add_argument("--catalog", type=Path, required=True)
    check.add_argument("--source-root", type=Path, required=True)
    check.add_argument("--json", action="store_true")
    check.set_defaults(handler=_handle)

    packet = commands.add_parser("packet", help="create a citation list after checking selected sources")
    packet.add_argument("--catalog", type=Path, required=True)
    packet.add_argument("--source-root", type=Path, required=True)
    packet.add_argument("--id", dest="ids", action="append", required=True)
    packet.add_argument("--purpose", required=True)
    packet.add_argument("--out", type=Path, required=True)
    packet.set_defaults(handler=_handle)

    view = commands.add_parser("view", help="create a local read-only HTML reference workspace")
    view.add_argument("--catalog", type=Path, required=True)
    view.add_argument("--source-root", type=Path, required=True)
    view.add_argument("--out", type=Path, required=True)
    view.add_argument("--history-page", help="optional sibling HTML work-history page")
    view.set_defaults(handler=_handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="faultloom knowledge")
    configure_knowledge_parser(parser)
    arguments = parser.parse_args(argv)
    return int(arguments.handler(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
