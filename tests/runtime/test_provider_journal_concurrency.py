from __future__ import annotations

import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from faultloom.state import ProviderJournalEntry, StateStore, StorageError
from tests.runtime.provider_journal_support import reservation, store


def test_same_attempt_concurrency_has_one_durable_winner(tmp_path: Path) -> None:
    first = reservation(label="first", attempt_id="attempt-first")
    second = reservation(label="second", attempt_id="attempt-second")
    left = store(tmp_path, "eng.provider-concurrent")
    right = store(tmp_path, "eng.provider-concurrent")
    try:
        def reserve_one(
            state: StateStore, entry: ProviderJournalEntry
        ) -> tuple[str, str]:
            try:
                record = state.reserve_provider_receipt(entry)
                return "won", record.entry.receipt_digest
            except StorageError:
                return "lost", entry.receipt_digest

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(reserve_one, left, first),
                pool.submit(reserve_one, right, second),
            )
            results = [future.result(timeout=10) for future in futures]
        assert sorted(result[0] for result in results) == ["lost", "won"]
        winner = next(result[1] for result in results if result[0] == "won")
        record = left.provider_receipt_by_attempt(first.call_id, first.attempt)
        assert record is not None
        assert record.entry.receipt_digest == winner
        assert left.checkpoint().seq == 1
    finally:
        left.close()
        right.close()


def test_same_attempt_across_processes_has_one_durable_winner(tmp_path: Path) -> None:
    script = r'''
import hashlib
import sys
import time
from pathlib import Path

source_root, base_value, label, ready_value, release_value, result_value = sys.argv[1:]
sys.path.insert(0, source_root)
from faultloom.state import (
    EngagementKey,
    ProviderCanonicalReceipt,
    ProviderJournalEntry,
    ProviderReceiptMetadata,
    StateStore,
    StorageError,
)

def digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()

base = Path(base_value)
metadata = ProviderReceiptMetadata(
    call_id="call/process",
    attempt=1,
    attempt_id="attempt-process-shared",
    provider_id="provider.test",
    endpoint_id="endpoint.test",
    profile_digest=digest("profile:process-shared"),
    requested_alias="model-alias-process-shared",
    exact_snapshot="model-test-2026-07-14",
    runtime_version="runtime-1.0",
    tokenizer_id="tokenizer.test",
    tokenizer_version="1.0",
    context_window=4096,
    prompt_digest=digest("prompt:process-shared"),
    compiled_context_digest=digest("context:process-shared"),
    tool_schema_digest=digest("tools:process-shared"),
    credential_ref_uri="secret://provider/test-credential",
    credential_ref_purpose="provider.credential",
)
entry = ProviderJournalEntry.from_receipt(ProviderCanonicalReceipt.reserved(metadata))
receipt_digest = entry.receipt_digest
state = StateStore(
    base / "state",
    "eng.provider-process",
    EngagementKey(bytes(range(32))),
    anchor_root=base / "anchor",
)
Path(ready_value).write_text("ready")
release = Path(release_value)
deadline = time.monotonic() + 15
while not release.exists():
    if time.monotonic() > deadline:
        raise RuntimeError("process barrier timed out")
    time.sleep(0.01)
try:
    state.reserve_provider_receipt(entry)
except StorageError:
    outcome = "lost"
else:
    outcome = "won"
Path(result_value).write_text(outcome + ":" + receipt_digest)
state.close()
'''
    source_root = Path(__file__).parents[2] / "packages" / "runtime" / "src"
    release = tmp_path / "release"
    processes: list[subprocess.Popen[str]] = []
    ready_paths: list[Path] = []
    result_paths: list[Path] = []
    for label in ("left", "right"):
        ready = tmp_path / f"ready-{label}"
        result = tmp_path / f"result-{label}"
        ready_paths.append(ready)
        result_paths.append(result)
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    script,
                    str(source_root),
                    str(tmp_path),
                    label,
                    str(ready),
                    str(release),
                    str(result),
                ],
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
    deadline = time.monotonic() + 15
    while not all(path.exists() for path in ready_paths):
        if time.monotonic() > deadline:
            for process in processes:
                process.kill()
            raise AssertionError("provider subprocesses did not reach the barrier")
        time.sleep(0.01)
    release.touch()
    for process in processes:
        _, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr
    results = [path.read_text().split(":", 1) for path in result_paths]
    assert sorted(result[0] for result in results) == ["lost", "won"]
    winner = next(result[1] for result in results if result[0] == "won")
    with store(tmp_path, "eng.provider-process") as state:
        record = state.provider_receipt_by_attempt("call/process", 1)
        assert record is not None
        assert record.entry.receipt_digest == winner
        assert state.checkpoint().seq == 1


def test_provider_reservation_holds_engagement_lock_through_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement_id = "eng.provider-close-race"
    reserved = reservation(label="close-race")
    state = store(tmp_path, engagement_id)
    ledger_module = sys.modules[type(state.ledger).__module__]
    original_insert = ledger_module.insert_provider_entry
    insertion_started = threading.Event()
    allow_insert = threading.Event()
    close_finished = threading.Event()

    def insert_then_wait(connection, event_seq, entry) -> None:
        insertion_started.set()
        if not allow_insert.wait(timeout=10):
            raise AssertionError("close-race barrier timed out")
        original_insert(connection, event_seq, entry)

    monkeypatch.setattr(ledger_module, "insert_provider_entry", insert_then_wait)

    def reserve_in_thread() -> None:
        state.reserve_provider_receipt(reserved)

    def close_in_thread() -> None:
        try:
            state.close()
        finally:
            close_finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        reserve_future = pool.submit(reserve_in_thread)
        assert insertion_started.wait(timeout=10)
        close_future = pool.submit(close_in_thread)
        assert not close_finished.wait(timeout=0.25)
        allow_insert.set()
        reserve_future.result(timeout=15)
        close_future.result(timeout=15)

    with store(tmp_path, engagement_id) as reopened:
        record = reopened.provider_receipt_by_attempt(
            reserved.call_id, reserved.attempt
        )
        assert record is not None
        assert record.entry == reserved
        assert record.anchor.seq == 1
