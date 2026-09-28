from __future__ import annotations

import http.client
import json
import secrets
import threading

import pytest

from faultloom.history_server import HistoryApplication, HistoryHTTPServer, MAX_BODY, SESSION_SECONDS
from faultloom.work_history import HistoryError, WorkHistory, initialize


@pytest.fixture
def running(tmp_path):
    directory = tmp_path / "history"
    initialize(directory)
    app = HistoryApplication(directory)
    server = HistoryHTTPServer(app)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def call(server, method, path, body=None, headers=None):
    supplied = {"Origin": server.origin, "Content-Type": "application/json", **(headers or {})}
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    raw = None if body is None else json.dumps(body).encode()
    try:
        connection.request(method, path, body=raw, headers=supplied)
        response = connection.getresponse()
        content = response.read()
        return response.status, dict(response.getheaders()), content
    finally:
        connection.close()


def login(server):
    token = server.app._launch_token
    status, headers, _ = call(server, "POST", "/api/session", {}, {"Authorization": "Bearer " + token})
    assert status == 200
    value = headers["Set-Cookie"]
    assert "HttpOnly" in value and "SameSite=Strict" in value
    assert "Max-Age=" in value and "Path=/" in value
    return value.split(";", 1)[0]


def creation(server, title="Browser-created case"):
    return {"operation": "create", "operation_id": secrets.token_hex(16),
            "expected_head": server.app.store.snapshot()["head"], "occurred_at": "2026-09-28",
            "data": {"title": title, "track": "client", "domains": ["web_api"],
                     "state": "active", "subject": "Disposable test client"}}


def test_public_shell_has_no_private_data_or_launch_capability(running):
    running.app.store.create({"title": "PRIVATE-UNIQUE-CLIENT", "track": "client", "domains": ["ai"],
                              "state": "active", "subject": "Private subject", "origin": "faultloom"})
    status, headers, content = call(running, "GET", "/")
    assert status == 200
    assert b"PRIVATE-UNIQUE-CLIENT" not in content
    assert running.app._launch_token.encode() not in content
    assert b"/api/session" in content
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Frame-Options"] == "DENY"
    assert "Access-Control-Allow-Origin" not in headers
    assert call(running, "GET", "/api/history")[0] == 401
    assert call(running, "GET", "/references.html")[0] == 401


def test_launch_link_is_single_use_and_session_survives_reload(running):
    token = running.app._launch_token
    cookie = login(running)
    assert call(running, "GET", "/api/history", headers={"Cookie": cookie})[0] == 200
    assert call(running, "POST", "/api/session", {}, {"Authorization": "Bearer " + token})[0] == 401
    assert call(running, "GET", "/index.html", headers={"Cookie": cookie})[0] == 200
    assert call(running, "GET", "/api/history", headers={"Cookie": cookie})[0] == 200


def test_host_and_origin_are_checked_before_authorization_or_mutation(running):
    token = running.app._launch_token
    assert call(running, "POST", "/api/session", {},
                {"Authorization": "Bearer " + token, "Origin": "https://unrelated.example"})[0] == 403
    assert call(running, "GET", "/", headers={"Host": "unrelated.example"})[0] == 421
    cookie = login(running)
    request = creation(running)
    assert call(running, "POST", "/api/mutate", request,
                {"Cookie": cookie, "Origin": "http://127.0.0.1:1"})[0] == 403
    assert call(running, "POST", "/api/mutate", request)[0] == 401
    assert running.app.store.snapshot()["event_count"] == 0


def test_same_operation_replayed_after_lost_response_is_not_duplicated(running):
    cookie = login(running)
    request = creation(running)
    first = call(running, "POST", "/api/mutate", request, {"Cookie": cookie})
    repeated = call(running, "POST", "/api/mutate", request, {"Cookie": cookie})
    assert first[0] == repeated[0] == 200
    assert json.loads(first[2])["appended"] == 1
    assert json.loads(repeated[2])["appended"] == 0
    assert running.app.store.snapshot()["event_count"] == 1
    assert json.loads(first[2])["case_id"] == json.loads(repeated[2])["case_id"]


def test_stale_edits_fail_and_corrections_keep_original_records(running):
    cookie = login(running)
    status, _, response = call(running, "POST", "/api/mutate", creation(running), {"Cookie": cookie})
    assert status == 200
    case_id = json.loads(response)["case_id"]
    head = running.app.store.snapshot()["head"]
    note = {"operation": "record", "operation_id": secrets.token_hex(16), "expected_head": head,
            "case_id": case_id, "data": {"kind": "decision", "summary": "Original decision", "detail": "First view"}}
    status, _, response = call(running, "POST", "/api/mutate", note, {"Cookie": cookie})
    assert status == 200
    note_id = json.loads(response)["event_id"]
    edit = {"operation": "update", "operation_id": secrets.token_hex(16), "expected_head": head,
            "case_id": case_id, "data": {**creation(running)["data"], "title": "Stale title"}}
    assert call(running, "POST", "/api/mutate", edit, {"Cookie": cookie})[0] == 409
    assert running.app.store.snapshot()["cases"][0]["title"] == "Browser-created case"
    correction = {"operation": "record", "operation_id": secrets.token_hex(16),
                  "expected_head": running.app.store.snapshot()["head"], "case_id": case_id,
                  "data": {"kind": "correction", "summary": "Revised decision", "detail": "Later evidence", "corrects": note_id}}
    assert call(running, "POST", "/api/mutate", correction, {"Cookie": cookie})[0] == 200
    case = running.app.store.snapshot()["cases"][0]
    assert case["events"][1]["data"]["summary"] == "Original decision"
    assert case["events"][2]["data"]["corrects"] == note_id
    assert WorkHistory(running.app.store.root).snapshot()["event_count"] == 3


@pytest.mark.parametrize("mutation", [{"operation": []}, {"operation_id": "invalid"}, {"data": {"title": "incomplete"}},
                                      {"unknown": "extra"}, {"expected_head": "invalid"}])
def test_invalid_write_inputs_leave_history_unchanged(running, mutation):
    cookie = login(running)
    request = {**creation(running), **mutation}
    assert call(running, "POST", "/api/mutate", request, {"Cookie": cookie})[0] == 400
    assert running.app.store.snapshot()["event_count"] == 0


def test_request_limits_and_no_arbitrary_file_routes(running):
    cookie = login(running)
    assert call(running, "POST", "/api/mutate", {}, {"Cookie": cookie, "Content-Length": str(MAX_BODY + 1)})[0] == 413
    assert call(running, "POST", "/api/mutate", {}, {"Cookie": cookie, "Content-Type": "text/plain"})[0] == 415
    assert call(running, "GET", "/history.key", headers={"Cookie": cookie})[0] == 404
    assert call(running, "OPTIONS", "/api/history")[0] == 403
    assert running.app.store.snapshot()["event_count"] == 0


def test_expired_launch_and_session_are_rejected(tmp_path):
    directory = tmp_path / "history"
    initialize(directory)
    clock = [10]
    app = HistoryApplication(directory, clock=lambda: clock[0])
    token = app._launch_token
    clock[0] += 301
    assert app.exchange(token) is None
    app = HistoryApplication(directory, clock=lambda: clock[0])
    cookie = app.exchange(app._launch_token).split(";", 1)[0]
    assert app.authenticated(cookie)
    clock[0] += SESSION_SECONDS
    assert not app.authenticated(cookie)
    assert app.exchange("not ascii \u00ff") is None


def test_invalid_port_has_controlled_error(running):
    with pytest.raises(HistoryError, match="port"):
        HistoryHTTPServer(running.app, -1)


def test_link_archive_check_and_download_use_configured_sources(running, tmp_path):
    import hashlib
    root = tmp_path / 'reports'
    root.mkdir()
    raw = b'Exact archived report\r\n\x00\xff'
    source = root / 'report.txt'
    source.write_bytes(raw)
    running.app.reference_roots = {'test': root}
    cookie = login(running)
    status, _, result = call(running, 'POST', '/api/mutate', creation(running), {'Cookie': cookie})
    assert status == 200
    case_id = json.loads(result)['case_id']

    def operation(kind, data):
        return {'operation': kind, 'operation_id': secrets.token_hex(16), 'case_id': case_id,
                'expected_head': running.app.store.snapshot()['head'], 'data': data}

    link = operation('link_file', {'origin': 'test', 'path': 'report.txt', 'label': 'Test report'})
    status, _, result = call(running, 'POST', '/api/mutate', link, {'Cookie': cookie})
    assert status == 200
    reference_id = json.loads(result)['event_id']
    assert call(running, 'POST', '/api/mutate', link, {'Cookie': cookie})[0] == 200
    archive = operation('archive_reference', {'reference_event_id': reference_id})
    status, _, result = call(running, 'POST', '/api/mutate', archive, {'Cookie': cookie})
    assert status == 200
    attachment_id = json.loads(result)['event_id']
    source.unlink()
    repeated = call(running, 'POST', '/api/mutate', archive, {'Cookie': cookie})
    assert repeated[0] == 200 and json.loads(repeated[2])['appended'] == 0
    download = f'/api/attachment/{case_id}/{attachment_id}'
    assert call(running, 'GET', download)[0] == 401
    status, headers, downloaded = call(running, 'GET', download, headers={'Cookie': cookie})
    assert status == 200 and downloaded == raw
    assert headers['Content-Type'] == 'application/octet-stream'
    assert headers['Content-Disposition'].startswith('attachment;')
    assert headers['X-Content-SHA256'] == hashlib.sha256(raw).hexdigest()
    check = operation('check_sources', {})
    status, _, result = call(running, 'POST', '/api/mutate', check, {'Cookie': cookie})
    assert status == 200
    assert {row['status'] for row in json.loads(result)['checks']['results']} == {'missing'}
    assert call(running, 'POST', '/api/mutate', check, {'Cookie': cookie})[0] == 200
    assert running.app.store.snapshot()['event_count'] == 4


def test_file_link_rejects_unconfigured_origin_and_path_escape(running, tmp_path):
    root = tmp_path / 'reports'
    root.mkdir()
    running.app.reference_roots = {'test': root}
    cookie = login(running)
    created = call(running, 'POST', '/api/mutate', creation(running), {'Cookie': cookie})
    case_id = json.loads(created[2])['case_id']
    for origin, path in [('unknown', 'report.txt'), ('test', '../outside.txt')]:
        request = {'operation': 'link_file', 'operation_id': secrets.token_hex(16), 'case_id': case_id,
                   'expected_head': running.app.store.snapshot()['head'], 'data': {'origin': origin, 'path': path, 'label': 'Test'}}
        assert call(running, 'POST', '/api/mutate', request, {'Cookie': cookie})[0] == 400
    assert running.app.store.snapshot()['event_count'] == 1


def test_missing_link_source_is_an_input_error_without_mutation(running, tmp_path):
    root = tmp_path / 'empty-sources'
    root.mkdir()
    running.app.reference_roots = {'test': root}
    cookie = login(running)
    created = call(running, 'POST', '/api/mutate', creation(running), {'Cookie': cookie})
    case_id = json.loads(created[2])['case_id']
    request = {'operation': 'link_file', 'operation_id': secrets.token_hex(16), 'case_id': case_id,
               'expected_head': running.app.store.snapshot()['head'],
               'data': {'origin': 'test', 'path': 'missing.txt', 'label': 'Missing source'}}
    status, _, body = call(running, 'POST', '/api/mutate', request, {'Cookie': cookie})
    assert status == 400
    assert json.loads(body)['error'] == 'source_not_found'
    assert running.app.store.snapshot()['event_count'] == 1
