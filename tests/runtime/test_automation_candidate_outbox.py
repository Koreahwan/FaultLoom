from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any, cast

import pytest

from faultloom.automation.candidate_outbox import (
    CandidateOutboxError,
    write_automation_result_bundle,
    write_candidate_outbox,
)
from faultloom.automation.models import (
    AuthorizedAutomationResult,
    CandidateFindingDraft,
)
from faultloom_protocol import canonical_json


def _result(*, draft: CandidateFindingDraft | None = None) -> AuthorizedAutomationResult:
    finding = draft or CandidateFindingDraft(
        hypothesis_id="hypothesis.candidate-1",
        title="Owned route normalization candidate",
        severity="low",
        summary="The observation needs an independent replay.",
        impact="No impact is verified yet.",
        reproduction_steps=("Replay the admitted safe probe only.",),
        remediation="Confirm independently before changing the service.",
    )
    return AuthorizedAutomationResult(
        run_id="run.candidate-1",
        authority_grant_id="grant.candidate-1",
        authority_grant_version=1,
        authority_grant_digest="sha256:" + "1" * 64,
        observation_bundle_digest="sha256:" + "2" * 64,
        action_context_digest="sha256:" + "3" * 64,
        hypotheses=(),
        negative_results=(),
        admitted_plans=(),
        finding_draft=finding,
        stop_reason="Await independent verification.",
        provider_network_access="none",
    )


def test_candidate_outbox_publishes_canonical_manual_review_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("candidate outbox opened a network socket")

    monkeypatch.setattr(socket, "socket", reject_network)
    publication = write_candidate_outbox(_result(), tmp_path / "outbox")

    assert publication.entry_dir.is_dir()
    assert sorted(path.name for path in publication.entry_dir.iterdir()) == [
        "candidate.md",
        "receipt.json",
    ]
    candidate = publication.candidate_path.read_text(encoding="utf-8")
    assert "Status: `draft_unverified`" in candidate
    assert "Review: `manual_review`" in candidate
    assert "Independent verification: `false`" in candidate
    assert "Automatic submission: `false`" in candidate
    assert "Network access: `none`" in candidate

    receipt_text = publication.receipt_path.read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)
    assert canonical_json(receipt) == receipt_text
    assert receipt == {
        "action_context_digest": "sha256:" + "3" * 64,
        "automatic_submission": False,
        "authority_grant_digest": "sha256:" + "1" * 64,
        "candidate_digest": publication.candidate_digest,
        "candidate_format": "md",
        "entry_id": publication.entry_id,
        "hypothesis_id": "hypothesis.candidate-1",
        "independent_verification": False,
        "network_access": "none",
        "observation_bundle_digest": "sha256:" + "2" * 64,
        "poc_context_digest": None,
        "review_status": "manual_review",
        "run_id": "run.candidate-1",
        "schema": "faultloom.candidate_outbox.receipt.v1",
        "source_result_digest": publication.source_result_digest,
        "status": "draft_unverified",
        "target_dispatch": False,
    }


def test_candidate_outbox_scrubs_secret_shaped_model_text(tmp_path: Path) -> None:
    bearer = "candidate-bearer-marker-1234567890"
    api_key = "sk-candidateApiKeyMarker1234567890"
    github_token = "gh" + "p_CandidateGithubTokenMarker1234567890"
    private_body = "candidate-private-body-marker"
    draft = CandidateFindingDraft(
        hypothesis_id="hypothesis.secret-shaped",
        title=f"Authorization: Bearer {bearer}",
        severity="low",
        summary=f"Provider token {api_key}",
        impact=f"client_secret={github_token}",
        reproduction_steps=(
            "-----BEGIN " + "PRIVATE KEY-----\n"
            f"{private_body}\n"
            "-----END PRIVATE KEY-----",
        ),
        remediation=f"Remove secret://run/{github_token} and {github_token}.",
    )

    publication = write_candidate_outbox(
        _result(draft=draft),
        tmp_path / "outbox",
    )
    persisted = b"".join(
        path.read_bytes() for path in sorted(publication.entry_dir.iterdir())
    )

    for secret in (bearer, api_key, github_token, private_body):
        assert secret.encode() not in persisted
    assert b"secret-ref" in persisted
    assert b"private-key-ref" in persisted


def test_candidate_outbox_requires_a_finding_draft(tmp_path: Path) -> None:
    result = _result().model_copy(update={"finding_draft": None})

    with pytest.raises(CandidateOutboxError, match="no candidate finding draft"):
        write_candidate_outbox(result, tmp_path / "outbox")

    assert not (tmp_path / "outbox").exists()


def test_candidate_outbox_rejects_secret_shaped_binding_metadata(
    tmp_path: Path,
) -> None:
    draft = _result().finding_draft
    assert draft is not None
    secret_shaped = "sk-candidateBindingMarker1234567890"
    result = _result(
        draft=draft.model_copy(update={"hypothesis_id": secret_shaped})
    )

    with pytest.raises(CandidateOutboxError, match="hypothesis ID"):
        write_candidate_outbox(result, tmp_path / "outbox")

    assert not (tmp_path / "outbox").exists()


def test_candidate_outbox_refuses_overwrite_and_preserves_first_entry(
    tmp_path: Path,
) -> None:
    result = _result()
    publication = write_candidate_outbox(result, tmp_path / "outbox")
    first = {
        path.name: path.read_bytes() for path in publication.entry_dir.iterdir()
    }

    with pytest.raises(CandidateOutboxError, match="already exists"):
        write_candidate_outbox(result, tmp_path / "outbox")

    assert {
        path.name: path.read_bytes() for path in publication.entry_dir.iterdir()
    } == first


def test_candidate_outbox_interruption_has_no_visible_entry_and_can_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    result = _result()
    out_dir = tmp_path / "outbox"
    original = outbox_module._create_file_once
    calls = 0

    def interrupt_second_write(path: Path, content: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        original(path, content)

    monkeypatch.setattr(outbox_module, "_create_file_once", interrupt_second_write)
    with pytest.raises(KeyboardInterrupt):
        write_candidate_outbox(result, out_dir)

    assert list(out_dir.iterdir()) == []
    monkeypatch.setattr(outbox_module, "_create_file_once", original)
    publication = write_candidate_outbox(result, out_dir)
    assert publication.candidate_path.is_file()
    assert publication.receipt_path.is_file()


def test_result_bundle_refuses_output_root_replacement_without_external_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    out_dir = tmp_path / "outbox"
    external = tmp_path / "external"
    external.mkdir()
    moved = tmp_path / "outbox-original"
    original_mkdir = outbox_module.os.mkdir
    replacement_done = False
    external_stage: Path | None = None

    def replace_output_root_after_staging(
        path: str | Path,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal replacement_done, external_stage
        original_mkdir(path, mode, dir_fd=dir_fd)
        name = Path(path).name
        if (
            not replacement_done
            and dir_fd is not None
            and name.startswith(".result.")
            and name.endswith(".tmp")
        ):
            replacement_done = True
            out_dir.rename(moved)
            out_dir.symlink_to(external, target_is_directory=True)
            external_stage = external / name
            original_mkdir(external_stage, 0o700)
            (external_stage / "sentinel.txt").write_text("untouched", encoding="utf-8")

    monkeypatch.setattr(outbox_module.os, "mkdir", replace_output_root_after_staging)
    with pytest.raises(CandidateOutboxError, match="outbox path changed"):
        write_automation_result_bundle(_result(), out_dir)

    assert replacement_done
    assert external_stage is not None
    assert (external_stage / "sentinel.txt").read_text(encoding="utf-8") == "untouched"
    assert sorted(path.name for path in external_stage.iterdir()) == ["sentinel.txt"]


def test_result_bundle_posix_commit_never_replaces_raced_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    out_dir = tmp_path / "outbox"
    original_rename_no_replace = outbox_module._rename_no_replace_at
    original_mkdir = outbox_module.os.mkdir
    raced_destination: Path | None = None

    def create_destination_at_commit(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal raced_destination
        original_mkdir(destination_name, 0o700, dir_fd=destination_directory_fd)
        raced_destination = out_dir / destination_name
        original_rename_no_replace(
            source_directory_fd,
            source_name,
            destination_directory_fd,
            destination_name,
        )

    monkeypatch.setattr(
        outbox_module, "_rename_no_replace_at", create_destination_at_commit
    )
    with pytest.raises(CandidateOutboxError, match="File exists"):
        write_automation_result_bundle(_result(), out_dir)

    assert raced_destination is not None
    assert raced_destination.is_dir()
    assert list(raced_destination.iterdir()) == []


def test_result_bundle_windows_path_holds_directory_lock_through_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    out_dir = tmp_path / "outbox"

    class FakeLock:
        def __init__(self, directory: Path) -> None:
            self.directory = directory
            self.stat = directory.lstat()
            self.closed = False

        def close(self) -> None:
            self.closed = True

    out_dir.mkdir()
    lock = FakeLock(out_dir)
    staging_locks: list[FakeLock] = []
    original = outbox_module._create_file_once

    def require_lock(path: Path, content: str) -> None:
        assert not lock.closed
        original(path, content)

    def lock_staging(directory: Path, *, access: int) -> FakeLock:
        assert access == 0x00010080
        staging_lock = FakeLock(directory)
        staging_locks.append(staging_lock)
        return staging_lock

    def move_no_replace(staging_lock: FakeLock, destination: Path) -> None:
        assert not lock.closed
        assert not staging_lock.closed
        os.rename(staging_lock.directory, destination)

    monkeypatch.setattr(outbox_module, "_lock_windows_output_directory", lambda _: lock)
    monkeypatch.setattr(outbox_module, "_lock_windows_directory", lock_staging)
    monkeypatch.setattr(outbox_module, "_windows_move_no_replace", move_no_replace)
    monkeypatch.setattr(outbox_module, "_create_file_once", require_lock)
    entry_dir = outbox_module._publish_windows_create_once_bundle(
        out_dir=out_dir,
        entry_id="result.windows-lock-test",
        files=(("result.json", "{}"), ("receipt.json", "{}")),
        error_label="automation result bundle",
    )

    assert lock.closed
    assert len(staging_locks) == 1
    assert staging_locks[0].closed
    assert (entry_dir / "result.json").is_file()


def test_result_bundle_windows_staging_lock_blocks_junction_swap_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    out_dir = tmp_path / "outbox"
    out_dir.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_text("untouched", encoding="utf-8")

    class FakeLock:
        def __init__(self, directory: Path) -> None:
            self.directory = directory
            self.stat = directory.lstat()
            self.closed = False

        def close(self) -> None:
            self.closed = True

    root_lock = FakeLock(out_dir)
    staging_locks: list[FakeLock] = []
    junction_swap_attempted = False

    def lock_staging(directory: Path, *, access: int) -> FakeLock:
        assert access == 0x00010080
        staging_lock = FakeLock(directory)
        staging_locks.append(staging_lock)
        return staging_lock

    def reject_junction_swap(staging_lock: FakeLock, _destination: Path) -> None:
        nonlocal junction_swap_attempted
        junction_swap_attempted = True
        # Windows denies delete/rename while this handle omits FILE_SHARE_DELETE;
        # model the attacker's attempted staging-to-junction replacement here.
        if not staging_lock.closed:
            raise PermissionError("staging directory is handle-locked")
        raise AssertionError("staging handle was released before commit")

    monkeypatch.setattr(
        outbox_module, "_lock_windows_output_directory", lambda _: root_lock
    )
    monkeypatch.setattr(outbox_module, "_lock_windows_directory", lock_staging)
    monkeypatch.setattr(outbox_module, "_windows_move_no_replace", reject_junction_swap)
    monkeypatch.setattr(outbox_module, "_windows_mark_directory_for_delete", lambda _: None)

    with pytest.raises(CandidateOutboxError, match="handle-locked"):
        outbox_module._publish_windows_create_once_bundle(
            out_dir=out_dir,
            entry_id="result.windows-junction-race",
            files=(("result.json", "{}"), ("receipt.json", "{}")),
            error_label="automation result bundle",
        )

    assert junction_swap_attempted
    assert len(staging_locks) == 1
    assert staging_locks[0].closed
    assert root_lock.closed
    assert sentinel.read_text(encoding="utf-8") == "untouched"
    assert not (out_dir / "result.windows-junction-race").exists()


def test_result_bundle_windows_commit_failure_cleans_staging_sensitive_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    out_dir = tmp_path / "outbox"
    out_dir.mkdir()
    sensitive = "sensitive-staging-marker-1234567890"
    real_rmdir = os.rmdir

    class FakeLock:
        def __init__(self, directory: Path) -> None:
            self.directory = directory
            self.stat = directory.lstat()
            self.handle = 0x100000001
            self.closed = False
            self.delete_on_close = False

        def close(self) -> None:
            if self.delete_on_close:
                real_rmdir(self.directory)
            self.closed = True

    root_lock = FakeLock(out_dir)
    staging_locks: list[FakeLock] = []

    def lock_staging(directory: Path, *, access: int) -> FakeLock:
        assert access == 0x00010080
        staging_lock = FakeLock(directory)
        staging_locks.append(staging_lock)
        return staging_lock

    def reject_commit(_staging_lock: FakeLock, _destination: Path) -> None:
        raise PermissionError("commit denied")

    disposition_handles: list[int] = []

    def mark_for_delete(staging_lock: FakeLock) -> None:
        disposition_handles.append(staging_lock.handle)
        staging_lock.delete_on_close = True

    def reject_path_rmdir(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Windows cleanup must not call path rmdir")

    monkeypatch.setattr(
        outbox_module, "_lock_windows_output_directory", lambda _: root_lock
    )
    monkeypatch.setattr(outbox_module, "_lock_windows_directory", lock_staging)
    monkeypatch.setattr(outbox_module, "_windows_move_no_replace", reject_commit)
    monkeypatch.setattr(outbox_module, "_windows_mark_directory_for_delete", mark_for_delete)
    monkeypatch.setattr(outbox_module.os, "rmdir", reject_path_rmdir)

    with pytest.raises(CandidateOutboxError, match="commit denied"):
        outbox_module._publish_windows_create_once_bundle(
            out_dir=out_dir,
            entry_id="result.windows-cleanup",
            files=(("result.json", sensitive), ("receipt.json", "{}")),
            error_label="automation result bundle",
        )

    assert root_lock.closed
    assert len(staging_locks) == 1
    assert staging_locks[0].closed
    assert disposition_handles == [0x100000001]
    assert list(out_dir.iterdir()) == []
    assert not any(
        sensitive in path.read_text(encoding="utf-8")
        for path in out_dir.rglob("*")
        if path.is_file()
    )


def test_windows_move_uses_handle_no_replace_rename_information(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctypes
    import faultloom.automation.candidate_outbox as outbox_module

    class FakeSetFileInformationByHandle:
        def __init__(self) -> None:
            self.argtypes: object | None = None
            self.restype: object | None = None
            self.call: tuple[object, ...] | None = None

        def __call__(self, *args: object) -> int:
            self.call = args
            return 1

    class FakeKernel32:
        def __init__(self) -> None:
            self.SetFileInformationByHandle = FakeSetFileInformationByHandle()

    kernel32 = FakeKernel32()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    destination = tmp_path / "result.native-handle-rename"
    staging_lock = outbox_module._WindowsDirectoryLock(
        handle=0x100000001,
        stat=tmp_path.stat(),
    )

    outbox_module._windows_move_no_replace(staging_lock, destination)

    call = kernel32.SetFileInformationByHandle.call
    assert call is not None
    handle, information_class, rename_info, buffer_size = cast(
        tuple[Any, Any, Any, int], call
    )
    assert isinstance(handle, ctypes.c_void_p)
    assert handle.value == 0x100000001
    assert information_class == 22
    assert isinstance(buffer_size, int)
    info_value = cast(Any, rename_info)._obj
    assert info_value.flags == 0
    assert info_value.filename_length == len(
        str(destination.absolute()).encode("utf-16-le")
    )
    raw_info = ctypes.string_at(ctypes.addressof(info_value), buffer_size)
    destination_bytes = str(destination.absolute()).encode("utf-16-le")
    filename_offset = type(info_value).filename.offset
    filename_end = filename_offset + len(destination_bytes)
    assert buffer_size == filename_end + 2
    assert raw_info[filename_offset:filename_end] == destination_bytes
    assert raw_info[filename_end:] == b"\x00\x00"


def test_windows_cleanup_marks_full_width_staging_handle_for_disposition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctypes
    import faultloom.automation.candidate_outbox as outbox_module

    class FakeSetFileInformationByHandle:
        def __init__(self) -> None:
            self.argtypes: object | None = None
            self.restype: object | None = None
            self.call: tuple[object, ...] | None = None

        def __call__(self, *args: object) -> int:
            self.call = args
            return 1

    class FakeKernel32:
        def __init__(self) -> None:
            self.SetFileInformationByHandle = FakeSetFileInformationByHandle()

    kernel32 = FakeKernel32()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    staging_lock = outbox_module._WindowsDirectoryLock(
        handle=0x100000001,
        stat=tmp_path.stat(),
    )

    outbox_module._windows_mark_directory_for_delete(staging_lock)

    call = kernel32.SetFileInformationByHandle.call
    assert call is not None
    handle, information_class, disposition_info, buffer_size = cast(
        tuple[Any, Any, Any, int], call
    )
    assert isinstance(handle, ctypes.c_void_p)
    assert handle.value == 0x100000001
    assert information_class == 4
    assert buffer_size == 1
    assert cast(Any, disposition_info)._obj.delete_file == 1


def test_windows_cleanup_reports_disposition_failure_without_path_rmdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import faultloom.automation.candidate_outbox as outbox_module

    staging_dir = tmp_path / "staging"
    staging_dir.mkdir()
    (staging_dir / "result.json").write_text("sensitive", encoding="utf-8")
    staging_lock = outbox_module._WindowsDirectoryLock(
        handle=0x100000001,
        stat=staging_dir.stat(),
    )

    def reject_disposition(_staging_lock: object) -> None:
        raise OSError("delete disposition denied")

    def reject_path_rmdir(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Windows cleanup must not call path rmdir")

    monkeypatch.setattr(
        outbox_module, "_windows_mark_directory_for_delete", reject_disposition
    )
    monkeypatch.setattr(outbox_module.os, "rmdir", reject_path_rmdir)

    with pytest.raises(CandidateOutboxError, match="mark empty directory for deletion"):
        outbox_module._cleanup_windows_staging_directory(
            staging_dir,
            staging_lock,
            ("result.json",),
        )

    assert not (staging_dir / "result.json").exists()
    assert staging_dir.is_dir()
