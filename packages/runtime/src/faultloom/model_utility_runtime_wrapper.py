#!/usr/bin/python3
"""Standalone, stdlib-only wrapper for the pinned llama.cpp utility profile."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath

_BUNDLE_PATH = "/opt/faultloom/llama-b10107-bin-ubuntu-x64.tar.gz"
_MODEL_PATH = "/opt/faultloom/model-snapshot"
_ARCHIVE_ROOT = "llama-b10107"
_MAX_REQUEST_BYTES = 16 * 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_EXTRACTED_BYTES = 64 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 128
_MAX_CHILD_STDOUT_BYTES = 64 * 1024
_MAX_CHILD_STDERR_BYTES = 64 * 1024
_MAX_INPUT_PAYLOAD_CHARS = 10 * 1024
_MAX_OUTPUT_CHARS = 4096
_CONTEXT_TOKENS = 4096
_MAX_OUTPUT_TOKENS = 256
_CHILD_TIMEOUT_SECONDS = 180
_PR_SET_CHILD_SUBREAPER = 36
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECISIONS = frozenset(("positive", "negative", "inconclusive"))
_DECISION_GRAMMAR = """root ::= \"{\\\"decision\\\":\" decision \",\\\"output\\\":\\\"\" characters \"\\\"}\"
decision ::= \"\\\"positive\\\"\" | \"\\\"negative\\\"\" | \"\\\"inconclusive\\\"\"
characters ::= character*
character ::= [^\"\\\\\\n\\r]
"""
_PROMPT_PREFIX = (
    "Return exactly one JSON object with keys decision and output. "
    "decision must be positive, negative, or inconclusive.\n"
)
_REQUEST_KEYS = frozenset(
    (
        "request_id",
        "case_id",
        "case_digest",
        "arm",
        "model_snapshot_digest",
        "runtime_artifact_digest",
        "prompt_digest",
        "tool_schema_digest",
        "budget_digest",
        "generation_config_digest",
        "seed",
        "payload",
    )
)


class WrapperError(RuntimeError):
    """One bounded wrapper precondition failed."""


def _read_request() -> dict[str, object]:
    raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise WrapperError("request framing is invalid")
    try:
        document = json.loads(raw[:-1])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WrapperError("request JSON is invalid") from None
    if type(document) is not dict or frozenset(document) != _REQUEST_KEYS:
        raise WrapperError("request shape is invalid")
    request = document
    if not all(
        type(request[key]) is str and _IDENTIFIER.fullmatch(request[key])
        for key in ("request_id", "case_id")
    ):
        raise WrapperError("request identity is invalid")
    if not all(
        type(request[key]) is str and _DIGEST.fullmatch(request[key])
        for key in (
            "case_digest",
            "model_snapshot_digest",
            "runtime_artifact_digest",
            "prompt_digest",
            "tool_schema_digest",
            "budget_digest",
            "generation_config_digest",
        )
    ):
        raise WrapperError("request digest is invalid")
    if request["arm"] not in ("baseline", "treatment"):
        raise WrapperError("request arm is invalid")
    if type(request["seed"]) is not int or request["seed"] != 42:
        raise WrapperError("request seed is invalid")
    if (
        type(request["payload"]) is not str
        or not request["payload"]
        or len(request["payload"]) > _MAX_INPUT_PAYLOAD_CHARS
    ):
        raise WrapperError("request payload is invalid")
    return request


def _safe_member_path(name: str) -> PurePosixPath:
    if not name or name.startswith("/") or "\\" in name:
        raise WrapperError("archive member path is unsafe")
    path = PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise WrapperError("archive member path is unsafe")
    if path.parts[0] != _ARCHIVE_ROOT or len(path.parts) > 2:
        raise WrapperError("archive topology is unexpected")
    return path


def _validated_members(archive: tarfile.TarFile) -> tuple[tarfile.TarInfo, ...]:
    members = archive.getmembers()
    if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
        raise WrapperError("archive member count is invalid")
    names: set[str] = set()
    regular_names: set[str] = set()
    total = 0
    symlinks: list[tarfile.TarInfo] = []
    for member in members:
        path = _safe_member_path(member.name)
        normalized = str(path)
        if normalized in names:
            raise WrapperError("archive contains duplicate paths")
        names.add(normalized)
        if member.isdir():
            if normalized != _ARCHIVE_ROOT:
                raise WrapperError("archive topology is unexpected")
        elif member.isreg():
            if len(path.parts) != 2 or member.size < 0 or member.size > _MAX_MEMBER_BYTES:
                raise WrapperError("archive member size is invalid")
            total += member.size
            if total > _MAX_EXTRACTED_BYTES:
                raise WrapperError("archive extracted size is invalid")
            regular_names.add(normalized)
        elif member.issym():
            if len(path.parts) != 2:
                raise WrapperError("archive topology is unexpected")
            target = PurePosixPath(member.linkname)
            if target.is_absolute() or len(target.parts) != 1 or target.name in ("", ".", ".."):
                raise WrapperError("archive symlink is unsafe")
            symlinks.append(member)
        else:
            raise WrapperError("archive member type is unsafe")
    required = {
        f"{_ARCHIVE_ROOT}/LICENSE",
        f"{_ARCHIVE_ROOT}/llama-cli",
        f"{_ARCHIVE_ROOT}/llama-tokenize",
    }
    if not required.issubset(regular_names):
        raise WrapperError("archive is missing required runtime files")
    for member in symlinks:
        current = f"{_ARCHIVE_ROOT}/{member.linkname}"
        visited: set[str] = set()
        while current not in regular_names:
            if current in visited:
                raise WrapperError("archive symlink cycle is unsafe")
            visited.add(current)
            linked = next(
                (item for item in symlinks if item.name.rstrip("/") == current), None
            )
            if linked is None:
                raise WrapperError("archive symlink target is missing")
            current = f"{_ARCHIVE_ROOT}/{linked.linkname}"
    return tuple(members)


def _extract_bundle(bundle: Path, destination: Path) -> Path:
    with tarfile.open(bundle, mode="r:gz") as archive:
        members = _validated_members(archive)
        runtime_root = destination / _ARCHIVE_ROOT
        runtime_root.mkdir(mode=0o700)
        symlinks: list[tarfile.TarInfo] = []
        for member in members:
            path = _safe_member_path(member.name)
            if member.isdir():
                continue
            target = destination.joinpath(*path.parts)
            if member.issym():
                symlinks.append(member)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise WrapperError("archive member is unreadable")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            written = 0
            try:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    if written > member.size:
                        raise WrapperError("archive member grew during extraction")
                    pending = memoryview(chunk)
                    offset = 0
                    while offset < len(pending):
                        offset += os.write(descriptor, pending[offset:])
                if written != member.size:
                    raise WrapperError("archive member was truncated")
                os.fchmod(descriptor, 0o500 if member.mode & 0o111 else 0o400)
            finally:
                os.close(descriptor)
                source.close()
        for member in symlinks:
            path = _safe_member_path(member.name)
            os.symlink(member.linkname, destination.joinpath(*path.parts))
    return runtime_root


def _run_bounded(argv: tuple[str, ...], stdin: bytes = b"") -> bytes:
    _set_subreaper()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C.UTF-8", "LD_LIBRARY_PATH": str(Path(argv[0]).parent)},
        close_fds=True,
        start_new_session=True,
    )
    target_start: int | None = None
    try:
        target_record = _process_record(process.pid)
        target_start = None if target_record is None else target_record[1]
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise WrapperError("child pipes are unavailable")
        process.stdin.write(stdin)
        process.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = bytearray()
        stderr_size = 0
        deadline = time.monotonic() + _CHILD_TIMEOUT_SECONDS
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WrapperError("child timed out")
                events = selector.select(remaining)
                if not events:
                    raise WrapperError("child timed out")
                for key, _mask in events:
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        output.extend(chunk)
                        if len(output) > _MAX_CHILD_STDOUT_BYTES:
                            raise WrapperError("child stdout exceeded its limit")
                    else:
                        stderr_size += len(chunk)
                        if stderr_size > _MAX_CHILD_STDERR_BYTES:
                            raise WrapperError("child stderr exceeded its limit")
        finally:
            selector.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise WrapperError("child returned nonzero status")
        return bytes(output)
    finally:
        cleanup_ok = _cleanup_descendants(process.pid, target_start)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        if not cleanup_ok:
            raise WrapperError("child process cleanup failed")


def _set_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise WrapperError("child subreaper is unavailable")


def _process_record(pid: int) -> tuple[int, int] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise WrapperError("child process identity is unavailable") from error
    end = raw.rfind(")")
    fields = raw[end + 2 :].split() if end >= 0 else []
    if len(fields) < 20:
        raise WrapperError("child process identity is invalid")
    try:
        return int(fields[1]), int(fields[19])
    except ValueError as error:
        raise WrapperError("child process identity is invalid") from error


def _children_of(pid: int, start_time: int) -> tuple[int, ...]:
    current = _process_record(pid)
    if current is None or current[1] != start_time:
        return ()
    try:
        tasks = tuple(
            entry for entry in Path(f"/proc/{pid}/task").iterdir() if entry.name.isdigit()
        )
    except FileNotFoundError:
        return ()
    except OSError as error:
        raise WrapperError("known child inventory is unavailable") from error
    values: list[str] = []
    for task in tasks:
        try:
            values.extend((task / "children").read_text().split())
        except FileNotFoundError:
            continue
        except OSError as error:
            raise WrapperError("known child inventory is unavailable") from error
    after = _process_record(pid)
    if after is None or after[1] != start_time:
        return ()
    try:
        children = tuple(int(value) for value in values)
    except ValueError as error:
        raise WrapperError("known child inventory is invalid") from error
    if any(child <= 0 for child in children) or len(set(children)) != len(children):
        raise WrapperError("known child inventory is invalid")
    return children


def _descendants() -> dict[int, int]:
    root = _process_record(os.getpid())
    if root is None:
        raise WrapperError("wrapper identity is unavailable")
    pending = [(os.getpid(), root[1])]
    descendants: dict[int, int] = {}
    while pending:
        parent_pid, parent_start = pending.pop()
        for child in _children_of(parent_pid, parent_start):
            if child == os.getpid() or child in descendants:
                continue
            record = _process_record(child)
            if record is None:
                continue
            descendants[child] = record[1]
            pending.append((child, record[1]))
    return descendants


def _signal_identity(pid: int, start_time: int, sent_signal: int) -> bool:
    current = _process_record(pid)
    if current is None or current[1] != start_time:
        return True
    try:
        os.kill(pid, sent_signal)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def _signal_target_group(pid: int, start_time: int | None, sent_signal: int) -> bool:
    if start_time is None:
        return True
    current = _process_record(pid)
    if current is None or current[1] != start_time:
        return True
    try:
        process_group = os.getpgid(pid)
        if process_group != pid or process_group == os.getpgrp():
            return False
        os.killpg(process_group, sent_signal)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def _reap_exited() -> tuple[bool, bool]:
    """Return (operation_succeeded, no_children_remain)."""
    while True:
        try:
            waited, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True, True
        except OSError:
            return False, False
        if waited == 0:
            return True, False


def _cleanup_descendants(target_pid: int, target_start: int | None) -> bool:
    for sent_signal, duration in ((signal.SIGTERM, 0.2), (signal.SIGKILL, 1.5)):
        try:
            if not _signal_target_group(target_pid, target_start, sent_signal):
                return False
        except WrapperError:
            return False
        deadline = time.monotonic() + duration
        while True:
            try:
                descendants = _descendants()
                signaled = all(
                    _signal_identity(pid, start_time, sent_signal)
                    for pid, start_time in descendants.items()
                )
            except WrapperError:
                return False
            if descendants and not signaled:
                return False
            reaped, no_children = _reap_exited()
            if not reaped:
                return False
            if not descendants and no_children:
                return True
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
    try:
        descendants = _descendants()
    except WrapperError:
        return False
    reaped, no_children = _reap_exited()
    return not descendants and reaped and no_children


def _llama_argv(runtime_root: Path, prompt_file: Path) -> tuple[str, ...]:
    return (
        str(runtime_root / "llama-cli"),
        "--model",
        _MODEL_PATH,
        "--file",
        str(prompt_file),
        "--threads",
        "1",
        "--threads-batch",
        "1",
        "--ctx-size",
        str(_CONTEXT_TOKENS),
        "--predict",
        str(_MAX_OUTPUT_TOKENS),
        "--seed",
        "42",
        "--temp",
        "0",
        "--gpu-layers",
        "0",
        "--device",
        "none",
        "--offline",
        "--no-display-prompt",
        "--no-perf",
        "--no-show-timings",
        "--no-warmup",
        "--no-context-shift",
        "--single-turn",
        "--simple-io",
        "--grammar",
        _DECISION_GRAMMAR,
        "--no-conversation",
        "--log-disable",
    )


def _token_count(runtime_root: Path, value: str) -> int:
    argv = (
        str(runtime_root / "llama-tokenize"),
        "--model",
        _MODEL_PATH,
        "--stdin",
        "--ids",
        "--no-bos",
        "--offline",
        "--log-disable",
    )
    encoded = _run_bounded(argv, value.encode())
    try:
        ids = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WrapperError("tokenizer output is invalid") from None
    if type(ids) is not list or not all(type(item) is int and item >= 0 for item in ids):
        raise WrapperError("tokenizer output is invalid")
    return len(ids)


def _parse_decision(raw: bytes, prompt: str) -> tuple[str, str]:
    try:
        text = raw.decode()
    except UnicodeDecodeError:
        return "inconclusive", ""
    prompt_marker = "> " + prompt + "\n"
    exit_marker = "\n\n\nExiting...\n"
    if not text.endswith(exit_marker):
        raise WrapperError("model generation markers are invalid")
    if not prompt.startswith(_PROMPT_PREFIX):
        raise WrapperError("model prompt is invalid")
    payload = prompt.removeprefix(_PROMPT_PREFIX)
    try:
        payload_object = json.loads(payload)
    except json.JSONDecodeError:
        payload_object = None
    payload_is_decision = (
        type(payload_object) is dict
        and frozenset(payload_object) == frozenset(("decision", "output"))
        and payload_object.get("decision") in _DECISIONS
        and type(payload_object.get("output")) is str
        and len(payload_object["output"]) <= _MAX_OUTPUT_CHARS
    )
    generated = text[: -len(exit_marker)]
    decoder = json.JSONDecoder()
    marker_count = generated.count(prompt_marker)
    if marker_count:
        if marker_count != 1:
            raise WrapperError("model prompt was echoed")
        preamble, framed = generated.split(prompt_marker)
        if prompt in preamble or prompt in framed or prompt_marker in framed:
            raise WrapperError("model prompt was echoed")
        if payload_is_decision and payload in framed:
            raise WrapperError("model prompt was echoed")
        for offset, character in enumerate(preamble):
            if character != "{":
                continue
            try:
                value, _end = decoder.raw_decode(preamble, offset)
            except json.JSONDecodeError:
                continue
            if (
                type(value) is dict
                and frozenset(value) == frozenset(("decision", "output"))
                and value.get("decision") in _DECISIONS
                and type(value.get("output")) is str
                and len(value["output"]) <= _MAX_OUTPUT_CHARS
            ):
                raise WrapperError("model prompt was echoed")
        try:
            value, end = decoder.raw_decode(framed)
        except json.JSONDecodeError:
            raise WrapperError("model prompt was echoed") from None
        if (
            end != len(framed)
            or type(value) is not dict
            or frozenset(value) != frozenset(("decision", "output"))
            or value.get("decision") not in _DECISIONS
            or type(value.get("output")) is not str
            or len(value["output"]) > _MAX_OUTPUT_CHARS
        ):
            raise WrapperError("model prompt was echoed")
        return value["decision"], value["output"]
    if prompt in generated:
        raise WrapperError("model prompt was echoed")
    if payload_is_decision and payload in generated:
        raise WrapperError("model prompt was echoed")
    matches: list[tuple[str, str]] = []
    for offset, character in enumerate(generated):
        if character != "{":
            continue
        try:
            value, _end = decoder.raw_decode(generated, offset)
        except json.JSONDecodeError:
            continue
        if (
            type(value) is dict
            and frozenset(value) == frozenset(("decision", "output"))
            and value.get("decision") in _DECISIONS
            and type(value.get("output")) is str
            and len(value["output"]) <= _MAX_OUTPUT_CHARS
        ):
            matches.append((value["decision"], value["output"]))
    if len(matches) == 1:
        return matches[0]
    return "inconclusive", ""


def _main() -> int:
    if sys.argv != [sys.argv[0], "--bundle", _BUNDLE_PATH, "--model", _MODEL_PATH]:
        raise WrapperError("runtime arguments are invalid")
    request = _read_request()
    with tempfile.TemporaryDirectory(prefix="faultloom-model-") as temporary:
        temporary_root = Path(temporary)
        runtime_root = _extract_bundle(Path(_BUNDLE_PATH), temporary_root)
        prompt = _PROMPT_PREFIX + str(request["payload"])
        input_tokens = _token_count(runtime_root, prompt)
        if input_tokens + _MAX_OUTPUT_TOKENS > _CONTEXT_TOKENS:
            raise WrapperError("prompt exceeds context limit")
        prompt_file = temporary_root / "prompt.txt"
        descriptor = os.open(
            prompt_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            os.write(descriptor, prompt.encode())
        finally:
            os.close(descriptor)
        raw_output = _run_bounded(_llama_argv(runtime_root, prompt_file))
        raw_llama_stdout_digest = "sha256:" + hashlib.sha256(raw_output).hexdigest()
        decision, output = _parse_decision(raw_output, prompt)
        response = {
            "decision": decision,
            "input_tokens": input_tokens,
            "model_snapshot_digest": request["model_snapshot_digest"],
            "output": output,
            "output_digest": "sha256:" + hashlib.sha256(output.encode()).hexdigest(),
            "output_tokens": _token_count(runtime_root, output) if output else 0,
            "raw_llama_stdout_digest": raw_llama_stdout_digest,
            "request_id": request["request_id"],
            "runtime_artifact_digest": request["runtime_artifact_digest"],
        }
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except (OSError, tarfile.TarError, subprocess.SubprocessError, WrapperError):
        sys.stderr.write("faultloom model runtime failed closed\n")
        raise SystemExit(2) from None
