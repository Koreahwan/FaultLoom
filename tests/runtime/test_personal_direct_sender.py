from __future__ import annotations

import json
import socket
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from faultloom import cli

from tests.runtime.test_cli import _authority_files, _run_arguments


def _workspace(tmp_path: Path, port: int, *, response_limit: int = 4096) -> tuple[Path, Path]:
    authority, key = _authority_files(
        tmp_path / "grant",
        hostnames=("127.0.0.1",),
        ports=(port,),
        paths=("/api/*",),
        methods=("GET", "HEAD", "OPTIONS"),
        protocols=("http",),
        budget_updates={"max_response_bytes": response_limit},
        now=datetime.now(UTC) - timedelta(minutes=1),
    )
    workspace = tmp_path / "workspace"
    assert cli.main(_run_arguments(authority, key) + ["--workspace", str(workspace)]) == 0
    return workspace, key


def _request_arguments(
    workspace: Path,
    key: Path,
    port: int,
    request: Path,
    *,
    response_bytes: int,
    timeout_seconds: int = 5,
    body_preview_chars: int = 0,
) -> list[str]:
    return [
        "scope", "send-request", "--workspace", str(workspace), "--trusted-key", str(key),
        "--hostname", "127.0.0.1", "--port", str(port), "--scheme", "http", "--method", "GET",
        "--path", "/api/items", "--request-file", str(request), "--response-bytes", str(response_bytes),
        "--timeout-seconds", str(timeout_seconds), "--body-preview-chars", str(body_preview_chars),
    ]


def _serve_once(listener: socket.socket, response: bytes, captured: list[bytes]) -> threading.Thread:
    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(3)
            raw = bytearray()
            while b"\r\n\r\n" not in raw:
                raw.extend(connection.recv(4096))
            captured.append(bytes(raw))
            connection.sendall(response)

    thread = threading.Thread(target=serve)
    thread.start()
    return thread


def test_personal_direct_sender_owned_loopback_is_exact_completes_and_ignores_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    request = workspace / "request.raw"
    expected = b"GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:" + str(port).encode() + b"\r\nConnection: Close\r\n\r\n"
    request.write_bytes(expected)
    captured: list[bytes] = []
    thread = _serve_once(listener, b"HTTP/1.1 200 OK\r\nX-Secret: value\r\nContent-Length: 6\r\n\r\nSECRET", captured)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")

    assert cli.main(_request_arguments(workspace, key, port, request, response_bytes=256)) == 0
    thread.join(timeout=3)
    listener.close()
    result = json.loads(capsys.readouterr().out)
    assert captured == [expected]
    assert result["schema"] == "faultloom.personal-http1-send.v1"
    assert result["dispatchPerformed"] is True
    assert result["networkAccess"] == "direct_owner_local"
    assert result["statusCode"] == 200
    assert result["headerNames"] == ["X-Secret", "Content-Length"]
    assert "bodyPreview" not in result
    assert "previewTruncated" not in result
    assert "value" not in json.dumps(result)
    assert "SECRET" not in json.dumps(result)
    response = Path(result["responseFile"])
    assert response.parent == workspace / "responses"
    assert response.read_bytes().endswith(b"\r\n\r\nSECRET")
    connection = sqlite3.connect(workspace / cli.REQUEST_ACCOUNTING_FILENAME)
    try:
        assert connection.execute("SELECT completed_at FROM reservations").fetchone()[0] is not None
    finally:
        connection.close()


def test_personal_direct_sender_does_not_follow_redirect_or_retry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    request = workspace / "request.raw"
    request.write_bytes(
        f"GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    captured: list[bytes] = []
    thread = _serve_once(listener, b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n", captured)

    assert cli.main(_request_arguments(workspace, key, port, request, response_bytes=256)) == 0
    thread.join(timeout=3)
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert json.loads(capsys.readouterr().out)["statusCode"] == 302
    assert len(captured) == 1


def test_personal_direct_sender_opt_in_preview_is_bounded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    request = workspace / "request.raw"
    request.write_bytes(
        f"GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    captured: list[bytes] = []
    thread = _serve_once(
        listener,
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nSECRET",
        captured,
    )

    assert cli.main(
        _request_arguments(
            workspace, key, port, request, response_bytes=256, body_preview_chars=3
        )
    ) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    result = json.loads(capsys.readouterr().out)
    assert result["bodyPreview"] == "SEC"
    assert result["previewTruncated"] is True


@pytest.mark.parametrize("response", [b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", b"x" * 100])
def test_personal_direct_sender_overflow_or_partial_response_is_unresolved_without_retry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], response: bytes
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    workspace, key = _workspace(tmp_path, port, response_limit=64)
    capsys.readouterr()
    request = workspace / "request.raw"
    request.write_bytes(
        f"GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    captured: list[bytes] = []
    thread = _serve_once(listener, response, captured)

    assert cli.main(_request_arguments(workspace, key, port, request, response_bytes=64)) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    listener.close()
    result = json.loads(capsys.readouterr().out)
    assert result["dispatchPerformed"] is True
    assert result["error"] == "response_incomplete_or_ambiguous"
    assert not list((workspace / "responses").glob("*"))
    connection = sqlite3.connect(workspace / cli.REQUEST_ACCOUNTING_FILENAME)
    try:
        assert connection.execute("SELECT completed_at FROM reservations").fetchone()[0] is None
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("method", "response"),
    [
        ("GET", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc"),
        ("GET", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc"),
        ("GET", b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"),
        ("HEAD", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"),
        ("GET", b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx"),
    ],
)
def test_personal_direct_sender_rejects_ambiguous_or_no_body_extra_responses(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    method: str,
    response: bytes,
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    request = workspace / "request.raw"
    request.write_bytes(
        f"{method} /api/items HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    captured: list[bytes] = []
    thread = _serve_once(listener, response, captured)
    arguments = _request_arguments(workspace, key, port, request, response_bytes=256)
    arguments[arguments.index("--method") + 1] = method

    assert cli.main(arguments) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    listener.close()
    result = json.loads(capsys.readouterr().out)
    assert result["reservationState"] == "unresolved_no_retry"
    assert not (workspace / "responses").exists()


def test_direct_http11_deadline_bounds_slow_drip_after_one_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowSocket:
        sent = 0

        def settimeout(self, value: float) -> None:
            assert 0 < value <= 1

        def connect(self, address: tuple[object, ...]) -> None:
            return None

        def sendall(self, content: bytes) -> None:
            self.sent += 1

        def recv(self, size: int) -> bytes:
            return b"x"

        def close(self) -> None:
            return None

    clock = iter((0.0, 0.0, 0.1, 0.2, 0.4, 0.5, 1.1))
    fake = SlowSocket()
    monkeypatch.setattr(
        cli, "_resolve_direct_address", lambda *args, **kwargs: (socket.AF_INET, ("127.0.0.1", 80))
    )
    monkeypatch.setattr(cli.socket, "socket", lambda *args: fake)
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(clock))

    with pytest.raises(TimeoutError):
        cli._send_direct_http11_once(
            hostname="127.0.0.1",
            port=80,
            scheme="http",
            target=object(),
            request_content=b"GET / HTTP/1.1\r\n\r\n",
            response_limit=64,
            deadline=1,
        )
    assert fake.sent == 1


def test_direct_http11_deadline_bounds_blocked_dns_without_opening_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    release = threading.Event()
    sockets_opened = 0

    def blocked_resolution(*_args: object, **_kwargs: object) -> list[object]:
        started.set()
        release.wait(1)
        return []

    def unexpected_socket(*_args: object, **_kwargs: object) -> object:
        nonlocal sockets_opened
        sockets_opened += 1
        raise AssertionError("DNS timeout must not open a socket")

    monkeypatch.setattr(cli.socket, "getaddrinfo", blocked_resolution)
    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    deadline = cli.time.monotonic() + 0.05
    try:
        with pytest.raises(cli._PersonalPreDispatchError, match="resolution timed out"):
            cli._send_direct_http11_once(
                hostname="example.invalid",
                port=80,
                scheme="http",
                target=object(),
                request_content=b"GET / HTTP/1.1\r\n\r\n",
                response_limit=64,
                deadline=deadline,
            )
    finally:
        release.set()
    assert started.is_set()
    assert sockets_opened == 0


def test_direct_http11_rechecks_deadline_before_opening_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sockets_opened = 0

    def unexpected_socket(*_args: object, **_kwargs: object) -> object:
        nonlocal sockets_opened
        sockets_opened += 1
        raise AssertionError("elapsed deadline must not open a socket")

    monkeypatch.setattr(
        cli, "_resolve_direct_address", lambda *_args, **_kwargs: (socket.AF_INET, ("127.0.0.1", 80))
    )
    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 2.0)

    with pytest.raises(cli._PersonalPreDispatchError, match="deadline elapsed"):
        cli._send_direct_http11_once(
            hostname="127.0.0.1",
            port=80,
            scheme="http",
            target=object(),
            request_content=b"GET / HTTP/1.1\r\n\r\n",
            response_limit=64,
            deadline=1.0,
        )
    assert sockets_opened == 0


def test_direct_http11_rejects_hostname_only_plaintext_dns_answer_without_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sockets_opened = 0

    def unexpected_socket(*_args: object, **_kwargs: object) -> object:
        nonlocal sockets_opened
        sockets_opened += 1
        raise AssertionError("unsigned plaintext DNS must not open a socket")

    monkeypatch.setattr(
        cli.socket, "getaddrinfo", lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
    )
    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    target = SimpleNamespace(hostnames=("example.test",), cidrs=())

    with pytest.raises(cli._PersonalPreDispatchError, match="plaintext resolution selected an unsigned"):
        cli._send_direct_http11_once(
            hostname="example.test",
            port=80,
            scheme="http",
            target=target,
            request_content=b"GET / HTTP/1.1\r\n\r\n",
            response_limit=64,
            deadline=cli.time.monotonic() + 1,
        )
    assert sockets_opened == 0


def test_plaintext_resolution_allows_address_in_signed_cidr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli.socket, "getaddrinfo", lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
    )
    target = SimpleNamespace(hostnames=("example.test",), cidrs=("93.184.216.0/24",))

    assert cli._resolve_direct_address(
        "example.test", 80, target, scheme="http", deadline=cli.time.monotonic() + 1
    ) == (socket.AF_INET, ("93.184.216.34", 80))


def test_personal_response_storage_rejects_symlink_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = tmp_path / "elsewhere"
    target.mkdir()
    responses = workspace / "responses"
    try:
        responses.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")

    with pytest.raises(cli.CliError, match="directory is unsafe"):
        cli._write_personal_response_file(workspace, "reservation.test", b"HTTP/1.1 200 OK\r\n\r\n")


def test_windows_response_directory_guard_uses_non_deletable_reparse_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ctypes

    class Call:
        def __init__(self, result: int = 1) -> None:
            self.argtypes: object | None = None
            self.restype: object | None = None
            self.calls: list[tuple[object, ...]] = []
            self.result = result

        def __call__(self, *args: object) -> int:
            self.calls.append(args)
            return self.result

    class AttributeCall(Call):
        def __call__(self, *args: object) -> int:
            self.calls.append(args)
            args[2]._obj.file_attributes = 0
            return 1

    class Kernel32:
        def __init__(self) -> None:
            self.CreateFileW = Call(0x100000001)
            self.GetFileInformationByHandleEx = AttributeCall()
            self.CloseHandle = Call()

    kernel32 = Kernel32()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    handle = cli._open_windows_response_directory_guard(tmp_path)
    cli._close_windows_response_directory_guard(handle)

    assert handle == 0x100000001
    assert kernel32.CreateFileW.calls[0][1:6] == (0x80, 0x3, None, 3, 0x02200000)
    assert kernel32.GetFileInformationByHandleEx.calls[0][1] == 9
    assert kernel32.CloseHandle.calls[-1][0].value == 0x100000001


def test_personal_direct_sender_rejects_unsafely_resolved_address_without_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _workspace(tmp_path, 8080)
    capsys.readouterr()
    request = workspace / "request.raw"
    request.write_bytes(b"GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.2", 8080))])
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: pytest.fail("socket opened"))

    assert cli.main(_request_arguments(workspace, key, 8080, request, response_bytes=256)) == cli.EXIT_UNAVAILABLE
    result = json.loads(capsys.readouterr().out)
    assert result["dispatchPerformed"] is False
    assert result["reservationState"] == "unresolved_no_retry"


def test_personal_direct_sender_unsafe_method_never_opens_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, key = _workspace(tmp_path, 8080)
    request = workspace / "request.raw"
    request.write_bytes(b"GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n")
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: pytest.fail("socket opened"))
    arguments = _request_arguments(workspace, key, 8080, request, response_bytes=256)
    arguments[arguments.index("--method") + 1] = "POST"
    assert cli.main(arguments) == cli.EXIT_AUTHORITY


def test_personal_direct_sender_out_of_scope_and_changed_digest_never_open_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _workspace(tmp_path, 8080)
    capsys.readouterr()
    request = workspace / "request.raw"
    request.write_bytes(
        b"GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\nX-Token: a\r\n\r\n"
    )
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: pytest.fail("socket opened"))
    original_admit = cli._admit_raw_request

    def admit_then_change(*args: object, **kwargs: object) -> cli._AdmittedRawRequest:
        admitted = original_admit(*args, **kwargs)
        request.write_bytes(request.read_bytes().replace(b"X-Token: a", b"X-Token: b"))
        return admitted

    monkeypatch.setattr(cli, "_admit_raw_request", admit_then_change)
    assert cli.main(_request_arguments(workspace, key, 8080, request, response_bytes=256)) == cli.EXIT_UNAVAILABLE
    assert json.loads(capsys.readouterr().out)["reservationState"] == "unresolved_no_retry"

    request.write_bytes(b"GET /api/items HTTP/1.1\r\nHost: 127.0.0.2:8080\r\nConnection: close\r\n\r\n")
    arguments = _request_arguments(workspace, key, 8080, request, response_bytes=256)
    arguments[arguments.index("--hostname") + 1] = "127.0.0.2"
    assert cli.main(arguments) == cli.EXIT_AUTHORITY


def test_scope_draft_explicitly_records_owned_http_scheme(tmp_path: Path) -> None:
    draft = tmp_path / "scope-draft.json"
    assert cli.main(
        [
            "scope", "draft", "--template", "lab", "--target-id", "target.loopback",
            "--hostname", "127.0.0.1", "--port", "8080", "--scheme", "http",
            "--out", str(draft),
        ]
    ) == cli.EXIT_OK
    assert json.loads(draft.read_text(encoding="utf-8"))["targets"][0]["protocols"] == ["http"]
