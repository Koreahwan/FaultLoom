"""Owner-local history editor with a launch capability and same-origin sessions."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

from . import knowledge as files
from .history_view import render_history
from .knowledge_view import render_overview
from .work_history import NOTES, SCHEMA, ZERO, HistoryError, WorkHistory, _exact, _identifier, new_event, write_export

MAX_BODY = 64 * 1024
SESSION_SECONDS = 8 * 60 * 60


class HistoryApplication:
    def __init__(self, directory: Path, *, catalog: Path | None = None, source_root: Path | None = None,
                 reference_roots: dict[str, Path] | None = None, clock=time.monotonic):
        self.store = WorkHistory(directory)
        self.store.snapshot()
        self.clock = clock
        self.lock = threading.Lock()
        self._launch_token = secrets.token_urlsafe(32)
        self._launch_until = clock() + 300
        self._session_token = secrets.token_urlsafe(32)
        self._session_until = 0
        self.cookie_name = "fl_history_" + secrets.token_hex(6)
        self.reference_roots = {}
        for origin, root in (reference_roots or {}).items():
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", origin):
                raise HistoryError("source origins must use simple lowercase identifiers")
            self.reference_roots[origin] = files._root(root)
        self.references = None
        if (catalog is None) != (source_root is None):
            raise HistoryError("catalog and source root must be provided together")
        if catalog is not None:
            content = files.load_catalog(catalog)
            self.references = render_overview(content, files.check_catalog(content, source_root), history_page="index.html")

    def exchange(self, token: str) -> str | None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        with self.lock:
            if self._launch_token is None or self.clock() >= self._launch_until:
                return None
            if not secrets.compare_digest(token, self._launch_token):
                return None
            self._launch_token = None
            self._session_until = self.clock() + SESSION_SECONDS
            return f"{self.cookie_name}={self._session_token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"

    def authenticated(self, header: str | None) -> bool:
        if not header or len(header) > 4096 or self.clock() >= self._session_until:
            return False
        cookie = SimpleCookie()
        try:
            cookie.load(header)
            value = cookie.get(self.cookie_name)
            return value is not None and secrets.compare_digest(value.value, self._session_token)
        except (CookieError, TypeError):
            return False

    def mutate(self, request: dict) -> dict:
        _exact(request, {"operation", "operation_id", "expected_head", "data"}, {"case_id", "occurred_at"})
        operation = request["operation"]
        if not isinstance(operation, str):
            raise HistoryError("invalid editor operation")
        operation_id = request["operation_id"]
        if not isinstance(operation_id, str) or not re.fullmatch(r"[a-f0-9]{32}", operation_id):
            raise HistoryError("invalid operation id")
        files._sha(request["expected_head"])
        event_id = "evt_" + operation_id
        value = request["data"]
        if operation in {"link_file", "archive_reference", "check_sources"}:
            from . import history_files
            case_id = _identifier(request.get("case_id"), "case", 24)
            snapshot = self.store.snapshot()
            case = next((case for case in snapshot["cases"] if case["id"] == case_id), None)
            if case is None:
                raise HistoryError("unknown case")
            if operation == "check_sources":
                _exact(value, set())
                return history_files.check_sources(self.store, case_id, self.reference_roots,
                                                   event_id=event_id, expected_head=request["expected_head"])
            if operation == "archive_reference":
                _exact(value, {"reference_event_id"})
                prior = next((event for event in case["events"] if event["id"] == value["reference_event_id"]), None)
                reference = history_files._source(prior) if prior else None
                if reference is None:
                    raise HistoryError("source reference does not belong to this case")
            else:
                _exact(value, {"origin", "path", "label"})
                known = next((event for event in case["events"] if event["id"] == event_id), None)
                if known:
                    if known["kind"] != "file_reference" or any(known["data"].get(key) != value[key] for key in value):
                        raise HistoryError("event id conflicts with an existing record")
                    return {"appended": 0, "case_id": case_id, "event_id": event_id, "head": snapshot["head"]}
                reference = value
            origin = reference.get("origin")
            if not isinstance(origin, str) or origin not in self.reference_roots:
                raise HistoryError("source origin is not configured in this local editor")
            root = self.reference_roots[origin]
            if operation == "archive_reference":
                return history_files.archive_source(self.store, case_id, root, reference["path"], origin=origin,
                                                     label=reference["label"], expected_sha256=reference["sha256"],
                                                     event_id=event_id, expected_head=request["expected_head"])
            reference, _ = history_files.capture_reference(root, reference["path"], origin=origin, label=reference["label"])
            event = new_event(case_id, "file_reference", reference, event_id=event_id)
            return {**self.store.append_batch([event], expected_head=request["expected_head"]), "case_id": case_id, "event_id": event_id}
        if operation in {"create", "update"}:
            _exact(value, {"title", "track", "domains", "state", "subject"})
            if operation == "create":
                if "case_id" in request:
                    raise HistoryError("new case id is assigned by the editor")
                case_id = "case_" + hashlib.sha256(("ui:" + operation_id).encode()).hexdigest()[:24]
                event_data = {**value, "origin": "faultloom"}
            else:
                case_id = _identifier(request.get("case_id"), "case", 24)
                snapshot = self.store.snapshot()
                case = next((case for case in snapshot["cases"] if case["id"] == case_id), None)
                if case is None:
                    raise HistoryError("unknown case")
                event_data = {**value, "origin": case["origin"]}
            kind = "case_created" if operation == "create" else "case_updated"
        elif operation == "record":
            case_id = _identifier(request.get("case_id"), "case", 24)
            _exact(value, {"kind", "summary", "detail"}, {"corrects"})
            kind = value["kind"]
            if not isinstance(kind, str) or kind not in NOTES:
                raise HistoryError("invalid note kind")
            event_data = {name: item for name, item in value.items() if name != "kind"}
        else:
            raise HistoryError("unknown editor operation")
        event = new_event(case_id, kind, event_data, occurred_at=request.get("occurred_at"), event_id=event_id)
        result = self.store.append_batch([event], expected_head=request["expected_head"])
        return {**result, "case_id": case_id, "event_id": event_id}


class HistoryHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, app: HistoryApplication, port: int = 0):
        if type(port) is not int or not 0 <= port <= 65535:
            raise HistoryError("port must be between 0 and 65535")
        self.app = app
        super().__init__(("127.0.0.1", port), HistoryHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.host_header = f"127.0.0.1:{self.server_port}"


class HistoryHandler(BaseHTTPRequestHandler):
    server: HistoryHTTPServer

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        # Do not log capabilities, cookies, record bodies, or request targets.
        pass

    def _reply(self, status: int, value, *, html: bool = False, cookie: str | None = None,
               attachment: dict | None = None):
        raw = value if attachment is not None else value.encode("utf-8") if html else files.json_bytes(value)
        self.send_response(status)
        content_type = "application/octet-stream" if attachment is not None else "text/html; charset=utf-8" if html else "application/json; charset=utf-8"
        self.send_header("Content-Type", content_type)
        if attachment is not None:
            self.send_header("Content-Disposition", "attachment; filename=download; filename*=UTF-8''" + quote(attachment["name"], safe=""))
            self.send_header("X-Content-SHA256", attachment["sha256"])
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Connection", "close")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        try:
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        self.close_connection = True

    def _host_ok(self):
        if self.headers.get_all("Host") != [self.server.host_header]:
            self._reply(421, {"error": "invalid_host"})
            return False
        return True

    def _authorized(self):
        cookies = self.headers.get_all("Cookie") or []
        if len(cookies) != 1 or not self.server.app.authenticated(cookies[0]):
            self._reply(401, {"error": "session_required"})
            return False
        return True

    def do_GET(self):
        if not self._host_ok():
            return
        try:
            if self.path in {"/", "/index.html"}:
                empty = {"schema": SCHEMA, "cases": [], "event_count": 0, "head": ZERO, "generated_at": ""}
                self._reply(200, render_history(empty, live=True,
                            reference_page="references.html" if self.server.app.references is not None else None), html=True)
                return
            attachment_route = re.fullmatch(r"/api/attachment/(case_[a-f0-9]{24})/(evt_[a-f0-9]{32})", self.path)
            if self.path not in {"/api/history", "/references.html"} and attachment_route is None:
                self._reply(404, {"error": "not_found"})
                return
            if not self._authorized():
                return
            if self.path == "/api/history":
                self._reply(200, {**self.server.app.store.snapshot(), "source_origins": list(self.server.app.reference_roots)})
            elif attachment_route is not None:
                from .history_files import read_attachment
                metadata, raw = read_attachment(self.server.app.store, attachment_route[1], attachment_route[2])
                self._reply(200, raw, attachment=metadata)
            elif self.server.app.references is not None:
                self._reply(200, self.server.app.references, html=True)
            else:
                self._reply(404, {"error": "references_not_configured"})
        except (HistoryError, files.CatalogError, OSError):
            self._reply(503, {"error": "history_unavailable"})

    def do_POST(self):
        if not self._host_ok():
            return
        if self.headers.get_all("Origin") != [self.server.origin]:
            self._reply(403, {"error": "same_origin_required"})
            return
        if self.path not in {"/api/session", "/api/mutate"}:
            self._reply(404, {"error": "not_found"})
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._reply(400, {"error": "unsupported_body_encoding"})
            return
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0]) or int(lengths[0]) > MAX_BODY:
            self._reply(413, {"error": "invalid_body_length"})
            return
        if self.headers.get("Content-Type", "").lower() != "application/json":
            self._reply(415, {"error": "json_required"})
            return
        if self.path == "/api/mutate" and not self._authorized():
            return
        try:
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise HistoryError("incomplete request body")
            request = json.loads(raw.decode("utf-8"), object_pairs_hook=files._pairs, parse_constant=files._constant)
            files._depth(request)
            if self.path == "/api/session":
                _exact(request, set())
                header = self.headers.get_all("Authorization") or []
                if len(header) != 1 or not header[0].startswith("Bearer "):
                    self._reply(401, {"error": "launch_link_required"})
                    return
                cookie = self.server.app.exchange(header[0][7:])
                if cookie is None:
                    self._reply(401, {"error": "launch_link_expired_or_used"})
                else:
                    self._reply(200, {"ok": True}, cookie=cookie)
            else:
                result = self.server.app.mutate(request)
                self._reply(200, result)
        except (HistoryError, files.CatalogError, ValueError, RecursionError) as exc:
            message = str(exc)
            conflict = "concurrently" in message or "conflicts" in message
            self._reply(409 if conflict else 400, {"error": "conflict" if conflict else "invalid_record", "message": message})
        except FileNotFoundError:
            self._reply(400, {"error": "source_not_found", "message": "Selected source file is missing; check its configured location and path."})
        except OSError:
            self._reply(503, {"error": "history_unavailable"})

    def do_OPTIONS(self):
        self._reply(403, {"error": "cross_origin_access_disabled"})


def serve(directory: Path, session_file: Path, *, port: int = 0, catalog: Path | None = None,
          source_root: Path | None = None, reference_roots: dict[str, Path] | None = None):
    if session_file.suffix != ".access":
        raise HistoryError("session file must use the private .access extension")
    app = HistoryApplication(directory, catalog=catalog, source_root=source_root, reference_roots=reference_roots)
    server = HistoryHTTPServer(app, port)
    try:
        launch = {"url": server.origin + "/#access=" + app._launch_token, "pid": os.getpid(),
                  "expires_after_seconds": 300, "privacy": "private_launch_capability"}
        write_export(session_file, files.json_bytes(launch), history_root=directory)
        print(json.dumps({"url": server.origin + "/", "pid": os.getpid(), "session_file": str(session_file)}), flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
