#!/usr/bin/python3
"""Standalone, stdlib-only wrapper for the pinned llama.cpp utility profile."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
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
_MAX_OUTPUT_CHARS = 4096
_CHILD_TIMEOUT_SECONDS = 180
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECISIONS = frozenset(("positive", "negative", "inconclusive"))
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
        or len(request["payload"]) > _MAX_OUTPUT_CHARS
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
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C.UTF-8", "LD_LIBRARY_PATH": str(Path(argv[0]).parent)},
        close_fds=True,
        start_new_session=True,
    )
    try:
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
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


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
        "1024",
        "--predict",
        "256",
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
        "--conversation",
        "--single-turn",
        "--simple-io",
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
    if "Error:" in text or "Failed to" in text:
        raise WrapperError("model runtime reported an error")
    prompt_marker = "> " + prompt + "\n"
    exit_marker = "\n\n\nExiting...\n"
    if text.count(prompt_marker) != 1 or not text.endswith(exit_marker):
        raise WrapperError("model generation markers are invalid")
    generated = text.split(prompt_marker, 1)[1][: -len(exit_marker)]
    decoder = json.JSONDecoder()
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
        prompt = (
            "Return exactly one JSON object with keys decision and output. "
            "decision must be positive, negative, or inconclusive.\n" + str(request["payload"])
        )
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
        decision, output = _parse_decision(raw_output, prompt)
        response = {
            "decision": decision,
            "input_tokens": _token_count(runtime_root, prompt),
            "model_snapshot_digest": request["model_snapshot_digest"],
            "output": output,
            "output_digest": "sha256:" + hashlib.sha256(output.encode()).hexdigest(),
            "output_tokens": _token_count(runtime_root, output) if output else 0,
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
