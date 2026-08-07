"""PyInstaller entry point for the personal Windows CLI bundle."""

from __future__ import annotations

import sys


def _configure_utf8_streams(*streams: object) -> None:
    for stream in streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict")


def _main() -> int:
    _configure_utf8_streams(sys.stdout, sys.stderr)
    from faultloom.cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_main())
