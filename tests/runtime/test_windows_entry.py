from __future__ import annotations

import io

from tools.faultloom_windows_entry import _configure_utf8_streams


class _Stream:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def reconfigure(self, **values: str) -> None:
        self.calls.append(values)


def test_windows_entry_configures_utf8_stdout_and_stderr() -> None:
    stdout = _Stream()
    stderr = _Stream()

    _configure_utf8_streams(stdout, stderr)

    assert stdout.calls == [{"encoding": "utf-8", "errors": "strict"}]
    assert stderr.calls == [{"encoding": "utf-8", "errors": "strict"}]


def test_windows_entry_accepts_non_reconfigurable_stream() -> None:
    _configure_utf8_streams(object())


def test_windows_entry_can_emit_unicode_after_cp949_default() -> None:
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp949", errors="strict")

    _configure_utf8_streams(stream)
    stream.write("—")
    stream.flush()

    assert buffer.getvalue() == "—".encode("utf-8")
