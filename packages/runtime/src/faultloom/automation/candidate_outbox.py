from __future__ import annotations

import errno
import hashlib
import os
import re
import secrets
import stat
import tempfile
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, final, override

from pydantic import ValidationError

from faultloom.verification.reporting import (
    _scrub as _verified_report_scrub,  # pyright: ignore[reportPrivateUsage]
)
from faultloom_protocol import canonical_json, sha256_digest

from .models import AuthorizedAutomationResult, CandidateFindingDraft


_PRIVATE_KEY_BLOCK = re.compile(
    "".join(
        (
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?",
            r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
        )
    ),
    re.IGNORECASE | re.DOTALL,
)
_SECRET_FIELD = re.compile(
    "".join(
        (
            r"(?i)\b(client[_-]?secret|private[_-]?key|refresh[_-]?token|",
            r"auth[_-]?token|credential|secret)\s*[:=]\s*[^\s,;]+",
        )
    )
)
_COMMON_TOKEN = re.compile(
    "".join(
        (
            r"(?<![A-Za-z0-9])(?:",
            r"sk-[A-Za-z0-9_-]{16,}|",
            r"gh[opusr]_[A-Za-z0-9]{20,}|",
            r"AKIA[0-9A-Z]{16}|",
            r"AIza[0-9A-Za-z_-]{20,}|",
            r"xox[baprs]-[A-Za-z0-9-]{10,}|",
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            r")(?![A-Za-z0-9])",
        )
    )
)
_ACTIVE_DIRECTORY_FD: ContextVar[int | None] = ContextVar(
    "candidate_outbox_active_directory_fd", default=None
)


@final
class CandidateOutboxError(RuntimeError):
    __slots__: ClassVar[tuple[str, ...]] = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason: str = reason

    @override
    def __str__(self) -> str:
        return self.reason


@final
class _CandidateBundleAlreadyExists(CandidateOutboxError):
    """Typed create-once collision used only by exact-verify publication."""


@dataclass(frozen=True, slots=True)
class CandidateOutboxPublication:
    entry_id: str
    entry_dir: Path
    candidate_path: Path
    receipt_path: Path
    candidate_digest: str
    source_result_digest: str


@dataclass(frozen=True, slots=True)
class AutomationResultBundlePublication:
    """One create-once, offline-only automation compilation bundle."""

    entry_id: str
    entry_dir: Path
    result_path: Path
    receipt_path: Path
    candidate_path: Path | None
    result_digest: str
    candidate_digest: str | None


@dataclass(slots=True)
class _WindowsDirectoryLock:
    handle: int
    stat: os.stat_result
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL
        # This is cleanup after the write/commit decision. A failed close cannot
        # make another path safe, so do not mask the original publication result.
        _ = kernel32.CloseHandle(ctypes.c_void_p(self.handle))


def _scrub_candidate_text(value: str) -> str:
    scrubbed = _verified_report_scrub(value)
    scrubbed = _PRIVATE_KEY_BLOCK.sub("<private-key-ref>", scrubbed)
    scrubbed = _SECRET_FIELD.sub(
        lambda match: f"{match.group(1)}: <secret-ref>", scrubbed
    )
    scrubbed = _COMMON_TOKEN.sub("<secret-ref>", scrubbed)
    if (
        _PRIVATE_KEY_BLOCK.search(scrubbed) is not None
        or _COMMON_TOKEN.search(scrubbed) is not None
    ):
        raise CandidateOutboxError("candidate report contains unredacted secret material")
    return scrubbed


def _markdown(value: str) -> str:
    escaped = _scrub_candidate_text(value).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "<", ">", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _require_secret_free_metadata(label: str, value: str) -> str:
    if _scrub_candidate_text(value) != value:
        raise CandidateOutboxError(f"candidate {label} contains secret-shaped material")
    return value


def _candidate_markdown(
    result: AuthorizedAutomationResult,
    draft: CandidateFindingDraft,
) -> str:
    steps = "\n".join(
        f"{index}. {_markdown(step)}"
        for index, step in enumerate(draft.reproduction_steps, start=1)
    )
    run_id = _require_secret_free_metadata("run ID", result.run_id)
    hypothesis_id = _require_secret_free_metadata(
        "hypothesis ID", draft.hypothesis_id
    )
    poc_recipe = (
        "none"
        if draft.poc_recipe_id is None
        else _require_secret_free_metadata("PoC recipe ID", draft.poc_recipe_id)
    )
    return (
        f"# {_markdown(draft.title)}\n\n"
        "- Status: `draft_unverified`\n"
        "- Review: `manual_review`\n"
        "- Independent verification: `false`\n"
        "- Automatic submission: `false`\n"
        "- Network access: `none`\n"
        "- Target dispatch: `false`\n"
        f"- Run: `{run_id}`\n"
        f"- Hypothesis: `{hypothesis_id}`\n"
        f"- PoC recipe: `{poc_recipe}`\n"
        f"- Severity: `{draft.severity}`\n\n"
        "## Summary\n\n"
        f"{_markdown(draft.summary)}\n\n"
        "## Unverified impact\n\n"
        f"{_markdown(draft.impact)}\n\n"
        "## Candidate reproduction steps\n\n"
        f"{steps}\n\n"
        "## Candidate remediation\n\n"
        f"{_markdown(draft.remediation)}\n"
    )


def _content_digest(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def automation_result_candidate_digest(
    result: AuthorizedAutomationResult,
) -> str | None:
    """Return the exact optional candidate artifact digest used by result bundles."""
    if type(result) is not AuthorizedAutomationResult:
        raise CandidateOutboxError(
            "automation result candidate digest requires an exact automation result"
        )
    try:
        validated = AuthorizedAutomationResult.model_validate(result)
    except ValidationError as exc:
        raise CandidateOutboxError(
            "automation result candidate digest received an invalid result"
        ) from exc
    if validated.finding_draft is None:
        return None
    return _content_digest(_candidate_markdown(validated, validated.finding_draft))


def _create_file_once(path: Path, content: str | bytes) -> None:
    directory_fd = _ACTIVE_DIRECTORY_FD.get()
    if directory_fd is not None:
        if path.name != str(path):
            raise CandidateOutboxError("candidate bundle filename is not a leaf")
        _create_file_once_at(directory_fd, path.name, content)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    data = content.encode("utf-8") if isinstance(content, str) else content
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            _ = output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o600)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _create_file_once_at(directory_fd: int, name: str, content: str | bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    data = content.encode("utf-8") if isinstance(content, str) else content
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            _ = output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, 0o600, dir_fd=directory_fd, follow_symlinks=False)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_descriptor(descriptor: int) -> None:
    os.fsync(descriptor)


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(left.st_mode)
        and stat.S_ISDIR(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISREG(left.st_mode)
        and stat.S_ISREG(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
    )


def _open_output_directory(out_dir: Path) -> tuple[int, os.stat_result]:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        expected = out_dir.lstat()
        if stat.S_ISLNK(expected.st_mode) or not stat.S_ISDIR(expected.st_mode):
            raise OSError("outbox path is not a directory")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(out_dir, flags)
        opened = os.fstat(descriptor)
        current = out_dir.lstat()
        if not _same_directory(expected, opened) or not _same_directory(expected, current):
            os.close(descriptor)
            raise OSError("outbox path changed while opening")
        return descriptor, opened
    except CandidateOutboxError:
        raise
    except OSError as exc:
        raise CandidateOutboxError(f"unable to create automation result bundle: {exc}") from exc


def _lock_windows_directory(
    directory: Path,
    *,
    access: int,
) -> _WindowsDirectoryLock:
    """Open a non-reparse directory without sharing delete access."""

    import ctypes
    from ctypes import wintypes

    file_share_read_write = 0x00000003
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    file_attribute_reparse_point = 0x00000400
    invalid_handle_value = ctypes.c_void_p(-1).value
    kernel32: object | None = None
    handle: int | None = None
    try:
        expected = directory.lstat()
        if (
            not stat.S_ISDIR(expected.st_mode)
            or getattr(expected, "st_file_attributes", 0) & file_attribute_reparse_point
        ):
            raise OSError("outbox path is not a non-reparse directory")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL
        raw_handle = kernel32.CreateFileW(
            str(directory.absolute()),
            access,
            file_share_read_write,
            None,
            open_existing,
            file_flag_backup_semantics | file_flag_open_reparse_point,
            None,
        )
        if raw_handle is None or raw_handle == invalid_handle_value:
            raise OSError(ctypes.get_last_error(), "CreateFileW failed")
        handle = int(raw_handle)
        opened = directory.lstat()
        if (
            not _same_directory(expected, opened)
            or getattr(opened, "st_file_attributes", 0) & file_attribute_reparse_point
        ):
            raise OSError("outbox path changed while opening")
        lock = _WindowsDirectoryLock(handle=handle, stat=opened)
        handle = None
        return lock
    except CandidateOutboxError:
        raise
    except OSError as exc:
        if handle is not None and kernel32 is not None:
            _ = kernel32.CloseHandle(ctypes.c_void_p(handle))  # type: ignore[union-attr]
        raise CandidateOutboxError(f"unable to create automation result bundle: {exc}") from exc


def _lock_windows_output_directory(out_dir: Path) -> _WindowsDirectoryLock:
    """Lock the output root against delete/rename through the commit window."""

    out_dir.mkdir(parents=True, exist_ok=True)
    return _lock_windows_directory(out_dir, access=0x00000080)


def _output_directory_is_current(out_dir: Path, expected: os.stat_result) -> bool:
    try:
        current = out_dir.lstat()
    except OSError:
        return False
    return not stat.S_ISLNK(current.st_mode) and _same_directory(expected, current)


def _windows_directory_is_current(directory: Path, expected: os.stat_result) -> bool:
    file_attribute_reparse_point = 0x00000400
    try:
        current = directory.lstat()
    except OSError:
        return False
    return (
        _output_directory_is_current(directory, expected)
        and not getattr(current, "st_file_attributes", 0) & file_attribute_reparse_point
    )


def _windows_move_no_replace(
    staging_lock: _WindowsDirectoryLock,
    destination: Path,
) -> None:
    """Rename an opened staging directory without replacing an existing entry."""

    import ctypes
    from ctypes import wintypes

    file_rename_info_ex = 22

    class FileRenameInfoEx(ctypes.Structure):
        _fields_ = [
            ("flags", wintypes.DWORD),
            ("root_directory", ctypes.c_void_p),
            ("filename_length", wintypes.DWORD),
            ("filename", wintypes.WCHAR * 1),
        ]

    destination_bytes = str(destination.absolute()).encode("utf-16-le")
    # FileNameLength deliberately excludes the required trailing UTF-16 NUL.
    # Native Windows otherwise can read one uninitialized WCHAR past the name.
    buffer_size = FileRenameInfoEx.filename.offset + len(destination_bytes) + 2
    buffer = ctypes.create_string_buffer(buffer_size)
    rename_info = ctypes.cast(buffer, ctypes.POINTER(FileRenameInfoEx)).contents
    rename_info.flags = 0  # Deliberately omit FILE_RENAME_FLAG_REPLACE_IF_EXISTS.
    rename_info.root_directory = None
    rename_info.filename_length = len(destination_bytes)
    ctypes.memmove(
        ctypes.addressof(rename_info) + FileRenameInfoEx.filename.offset,
        destination_bytes,
        len(destination_bytes),
    )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    if not kernel32.SetFileInformationByHandle(
        ctypes.c_void_p(staging_lock.handle),
        file_rename_info_ex,
        ctypes.byref(rename_info),
        buffer_size,
    ):
        error_number = ctypes.get_last_error()
        if error_number in {80, 183}:  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
            raise _CandidateBundleAlreadyExists("Windows no-replace destination already exists")
        raise OSError(error_number, "SetFileInformationByHandle failed")


def _windows_mark_directory_for_delete(staging_lock: _WindowsDirectoryLock) -> None:
    """Delete the exact opened staging directory when its handle closes."""

    import ctypes
    from ctypes import wintypes

    file_disposition_info = 4

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("delete_file", ctypes.c_ubyte)]

    disposition_info = FileDispositionInfo(delete_file=1)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    if not kernel32.SetFileInformationByHandle(
        ctypes.c_void_p(staging_lock.handle),
        file_disposition_info,
        ctypes.byref(disposition_info),
        ctypes.sizeof(disposition_info),
    ):
        raise OSError(ctypes.get_last_error(), "SetFileInformationByHandle failed")


def _rename_no_replace_at(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    """Use Linux renameat2(RENAME_NOREPLACE); never emulate it unsafely."""

    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise CandidateOutboxError("atomic no-replace rename is unavailable") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        source_directory_fd,
        os.fsencode(source_name),
        destination_directory_fd,
        os.fsencode(destination_name),
        1,  # RENAME_NOREPLACE
    ) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number or errno.EIO, os.strerror(error_number or errno.EIO))


def _remove_staging_directory(
    output_fd: int,
    staging_name: str,
    staging_fd: int,
) -> None:
    try:
        current = os.stat(staging_name, dir_fd=output_fd, follow_symlinks=False)
        if not _same_directory(os.fstat(staging_fd), current):
            return
        for name in os.listdir(staging_fd):
            os.unlink(name, dir_fd=staging_fd)
        _fsync_descriptor(staging_fd)
        os.rmdir(staging_name, dir_fd=output_fd)
    except OSError:
        pass


def _cleanup_windows_staging_directory(
    staging_dir: Path,
    staging_lock: _WindowsDirectoryLock,
    written_filenames: tuple[str, ...],
) -> None:
    """Remove known staged content without trusting a path after lock failure."""

    if not _windows_directory_is_current(staging_dir, staging_lock.stat):
        raise CandidateOutboxError("staging cleanup could not verify directory identity")
    for filename in written_filenames:
        if Path(filename).name != filename:
            raise CandidateOutboxError("staging cleanup received a non-leaf filename")
        try:
            # unlink removes a reparse-point file itself; it never follows it.
            os.unlink(staging_dir / filename)
        except OSError as exc:
            raise CandidateOutboxError(
                f"staging cleanup could not remove {filename}: {exc}"
            ) from exc
    try:
        if os.listdir(staging_dir):
            raise CandidateOutboxError("staging cleanup found unexpected entries")
    except CandidateOutboxError:
        raise
    except OSError as exc:
        raise CandidateOutboxError(
            f"staging cleanup could not inspect directory: {exc}"
        ) from exc

    try:
        # FILE_DISPOSITION_INFO binds deletion to the opened DELETE-access
        # staging handle. Closing that handle in the caller deletes this exact
        # directory; no post-close path resolution occurs.
        _windows_mark_directory_for_delete(staging_lock)
    except OSError as exc:
        raise CandidateOutboxError(
            f"staging cleanup could not mark empty directory for deletion: {exc}"
        ) from exc


def _publish_windows_create_once_bundle(
    *,
    out_dir: Path,
    entry_id: str,
    files: tuple[tuple[str, str | bytes], ...],
    error_label: str,
) -> Path:
    entry_dir = out_dir / entry_id
    root_lock = _lock_windows_output_directory(out_dir)
    staging_dir: Path | None = None
    staging_lock: _WindowsDirectoryLock | None = None
    written_filenames: list[str] = []
    committed = False
    try:
        if os.path.lexists(entry_dir):
            raise _CandidateBundleAlreadyExists(f"{error_label} entry already exists")
        staging_dir = Path(
            tempfile.mkdtemp(prefix=f".{entry_id}.", suffix=".tmp", dir=out_dir)
        )
        # DELETE access plus no FILE_SHARE_DELETE means the staging directory
        # cannot be replaced by a junction while its paths are used below.
        staging_lock = _lock_windows_directory(
            staging_dir,
            access=0x00010080,  # DELETE | FILE_READ_ATTRIBUTES
        )
        for filename, content in files:
            _create_file_once(staging_dir / filename, content)
            written_filenames.append(filename)
        _fsync_directory(staging_dir)
        if not _windows_directory_is_current(out_dir, root_lock.stat):
            raise CandidateOutboxError("outbox path changed during publication")
        if not _windows_directory_is_current(staging_dir, staging_lock.stat):
            raise CandidateOutboxError("staging path changed during publication")
        _windows_move_no_replace(staging_lock, entry_dir)
        committed = True
        _fsync_directory(out_dir)
        if not _windows_directory_is_current(out_dir, root_lock.stat):
            raise CandidateOutboxError("outbox path changed during publication")
    except BaseException as exc:
        if not committed and staging_dir is not None and staging_lock is not None:
            try:
                _cleanup_windows_staging_directory(
                    staging_dir,
                    staging_lock,
                    tuple(written_filenames),
                )
            except CandidateOutboxError as cleanup_error:
                raise CandidateOutboxError(
                    f"unable to clean failed {error_label} staging: {cleanup_error}"
                ) from cleanup_error
        if isinstance(exc, FileExistsError):
            raise _CandidateBundleAlreadyExists(f"{error_label} entry already exists") from exc
        if isinstance(exc, OSError):
            raise CandidateOutboxError(
                f"unable to create {error_label}: {exc}"
            ) from exc
        raise
    finally:
        if staging_lock is not None and not staging_lock.closed:
            staging_lock.close()
        root_lock.close()
    return entry_dir


def _publish_posix_create_once_bundle(
    *,
    out_dir: Path,
    entry_id: str,
    files: tuple[tuple[str, str | bytes], ...],
    error_label: str,
) -> Path:
    entry_dir = out_dir / entry_id
    output_fd, output_stat = _open_output_directory(out_dir)
    staging_fd: int | None = None
    staging_name = ""
    committed = False
    try:
        try:
            os.stat(entry_id, dir_fd=output_fd, follow_symlinks=False)
            raise _CandidateBundleAlreadyExists(f"{error_label} entry already exists")
        except FileNotFoundError:
            pass
        for _ in range(32):
            staging_name = f".{entry_id}.{secrets.token_hex(8)}.tmp"
            try:
                os.mkdir(staging_name, mode=0o700, dir_fd=output_fd)
                break
            except FileExistsError:
                continue
        else:
            raise OSError("unable to allocate a unique staging directory")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        staging_fd = os.open(staging_name, directory_flags, dir_fd=output_fd)
        token = _ACTIVE_DIRECTORY_FD.set(staging_fd)
        try:
            for filename, content in files:
                _create_file_once(Path(filename), content)
        finally:
            _ACTIVE_DIRECTORY_FD.reset(token)
        _fsync_descriptor(staging_fd)
        try:
            os.stat(entry_id, dir_fd=output_fd, follow_symlinks=False)
            raise _CandidateBundleAlreadyExists(f"{error_label} entry already exists")
        except FileNotFoundError:
            pass
        _rename_no_replace_at(
            output_fd,
            staging_name,
            output_fd,
            entry_id,
        )
        committed = True
        _fsync_descriptor(output_fd)
        if not _output_directory_is_current(out_dir, output_stat):
            raise CandidateOutboxError("outbox path changed during publication")
    except BaseException as exc:
        if not committed and staging_fd is not None:
            _remove_staging_directory(output_fd, staging_name, staging_fd)
        if isinstance(exc, FileExistsError):
            raise _CandidateBundleAlreadyExists(f"{error_label} entry already exists") from exc
        if isinstance(exc, OSError):
            raise CandidateOutboxError(
                f"unable to create {error_label}: {exc}"
            ) from exc
        raise
    finally:
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(output_fd)
    return entry_dir


def _publish_create_once_bundle(
    *,
    out_dir: Path,
    entry_id: str,
    files: tuple[tuple[str, str | bytes], ...],
    error_label: str,
) -> Path:
    if os.name == "nt":
        return _publish_windows_create_once_bundle(
            out_dir=out_dir,
            entry_id=entry_id,
            files=files,
            error_label=error_label,
        )
    return _publish_posix_create_once_bundle(
        out_dir=out_dir,
        entry_id=entry_id,
        files=files,
        error_label=error_label,
    )


def ensure_private_content_bundle(
    out_dir: Path,
    *,
    entry_id: str,
    files: tuple[tuple[str, str | bytes], ...],
    error_label: str,
    permitted_extra_files: frozenset[str] = frozenset(),
) -> Path:
    """Create one private content-addressed bundle or verify its exact bytes.

    Existing entries are never repaired in place: a partial, symlinked, or
    different entry is an authority failure for callers rather than a reason to
    republish possibly changed material.
    """

    if (
        not entry_id
        or Path(entry_id).name != entry_id
        or len(files) == 0
        or len({name for name, _ in files}) != len(files)
        or any(not name or Path(name).name != name for name, _ in files)
        or any(not name or Path(name).name != name for name in permitted_extra_files)
        or set(permitted_extra_files).intersection(name for name, _ in files)
    ):
        raise CandidateOutboxError("private bundle layout is invalid")
    expected = {
        name: content.encode("utf-8") if isinstance(content, str) else content
        for name, content in files
    }
    entry_dir = out_dir / entry_id

    def verify_posix() -> None:
        root_fd, root_stat = _open_output_directory(out_dir)
        entry_fd: int | None = None
        try:
            entry_stat = os.stat(entry_id, dir_fd=root_fd, follow_symlinks=False)
            if not stat.S_ISDIR(entry_stat.st_mode):
                raise CandidateOutboxError(f"existing {error_label} is not a regular directory")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            entry_fd = os.open(entry_id, flags, dir_fd=root_fd)
            if not _same_directory(entry_stat, os.fstat(entry_fd)):
                raise CandidateOutboxError(f"existing {error_label} changed while opening")
            observed = os.listdir(entry_fd)
            if set(observed) != set(expected).union(permitted_extra_files):
                raise CandidateOutboxError(f"existing {error_label} has an incomplete or different layout")
            for name, wanted in expected.items():
                flags = os.O_RDONLY | os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                file_fd = os.open(name, flags, dir_fd=entry_fd)
                try:
                    metadata = os.fstat(file_fd)
                    listed = os.stat(name, dir_fd=entry_fd, follow_symlinks=False)
                    if not stat.S_ISREG(metadata.st_mode) or not _same_file(metadata, listed):
                        raise CandidateOutboxError(f"existing {error_label} contains a changed artifact")
                    actual = bytearray()
                    while len(actual) <= len(wanted):
                        block = os.read(file_fd, min(65_536, len(wanted) + 1 - len(actual)))
                        if not block:
                            break
                        actual.extend(block)
                    if bytes(actual) != wanted:
                        raise CandidateOutboxError(f"existing {error_label} artifact differs")
                finally:
                    os.close(file_fd)
            for name in permitted_extra_files:
                metadata = os.stat(name, dir_fd=entry_fd, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    raise CandidateOutboxError(f"existing {error_label} contains a non-regular artifact")
            if not _output_directory_is_current(out_dir, root_stat):
                raise CandidateOutboxError(f"existing {error_label} parent changed during verification")
            current = os.stat(entry_id, dir_fd=root_fd, follow_symlinks=False)
            if not _same_directory(entry_stat, current):
                raise CandidateOutboxError(f"existing {error_label} changed during verification")
        except CandidateOutboxError:
            raise
        except OSError as exc:
            raise CandidateOutboxError(f"cannot inspect existing {error_label}: {exc}") from exc
        finally:
            if entry_fd is not None:
                os.close(entry_fd)
            os.close(root_fd)

    def verify_windows() -> None:
        root_lock = _lock_windows_output_directory(out_dir)
        entry_lock: _WindowsDirectoryLock | None = None
        try:
            entry_lock = _lock_windows_directory(entry_dir, access=0x00010080)
            observed = list(entry_dir.iterdir())
            if {item.name for item in observed} != set(expected).union(permitted_extra_files):
                raise CandidateOutboxError(f"existing {error_label} has an incomplete or different layout")
            for item in observed:
                metadata = item.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise CandidateOutboxError(f"existing {error_label} contains a non-regular artifact")
                descriptor = os.open(item, os.O_RDONLY | getattr(os, "O_BINARY", 0))
                try:
                    opened = os.fstat(descriptor)
                    current = item.lstat()
                    if not _same_file(opened, current):
                        raise CandidateOutboxError(f"existing {error_label} artifact changed while opening")
                    wanted = expected.get(item.name)
                    actual = os.read(descriptor, (len(wanted) + 1) if wanted is not None else 1)
                    if wanted is not None and actual != wanted:
                        raise CandidateOutboxError(f"existing {error_label} artifact differs")
                finally:
                    os.close(descriptor)
            if not _windows_directory_is_current(out_dir, root_lock.stat) or not _windows_directory_is_current(entry_dir, entry_lock.stat):
                raise CandidateOutboxError(f"existing {error_label} changed during verification")
        except CandidateOutboxError:
            raise
        except OSError as exc:
            raise CandidateOutboxError(f"cannot inspect existing {error_label}: {exc}") from exc
        finally:
            if entry_lock is not None:
                entry_lock.close()
            root_lock.close()

    def verify() -> None:
        if os.name == "nt":
            verify_windows()
        else:
            verify_posix()

    try:
        _ = entry_dir.lstat()
    except FileNotFoundError:
        try:
            return _publish_create_once_bundle(
                out_dir=out_dir,
                entry_id=entry_id,
                files=files,
                error_label=error_label,
            )
        except _CandidateBundleAlreadyExists:
            verify()
            return entry_dir
    except OSError as exc:
        raise CandidateOutboxError(f"cannot inspect existing {error_label}: {exc}") from exc
    verify()
    return entry_dir


def write_automation_result_bundle(
    result: AuthorizedAutomationResult,
    out_dir: Path,
) -> AutomationResultBundlePublication:
    """Atomically publish one offline candidate-only compilation result bundle."""

    if type(result) is not AuthorizedAutomationResult:
        raise CandidateOutboxError("automation result bundle requires an exact automation result")
    try:
        validated = AuthorizedAutomationResult.model_validate(result)
    except ValidationError as exc:
        raise CandidateOutboxError("automation result bundle received an invalid result") from exc

    result_value = validated.model_dump(mode="json")
    result_content = canonical_json(result_value)
    result_digest = sha256_digest(result_value)
    entry_id = f"result.{result_digest.removeprefix('sha256:')[:32]}"
    candidate_content: str | None = None
    candidate_digest = automation_result_candidate_digest(validated)
    if validated.finding_draft is not None:
        candidate_content = _candidate_markdown(validated, validated.finding_draft)

    receipt_content = canonical_json(
        {
            "automatic_submission": False,
            "candidate_digest": candidate_digest,
            "candidate_only": True,
            "entry_id": entry_id,
            "evidence_existence_independently_verified": False,
            "independent_verification": False,
            "network_access": "none",
            "result_digest": result_digest,
            "schema": "faultloom.automation.result.receipt.v1",
            "target_dispatch": False,
        }
    )
    files: list[tuple[str, str]] = [("result.json", result_content)]
    if candidate_content is not None:
        files.append(("candidate.md", candidate_content))
    files.append(("receipt.json", receipt_content))
    try:
        entry_dir = _publish_create_once_bundle(
            out_dir=out_dir,
            entry_id=entry_id,
            files=tuple(files),
            error_label="automation result bundle",
        )
    except _CandidateBundleAlreadyExists as exc:
        raise CandidateOutboxError("automation result bundle entry already exists: File exists") from exc
    return AutomationResultBundlePublication(
        entry_id=entry_id,
        entry_dir=entry_dir,
        result_path=entry_dir / "result.json",
        receipt_path=entry_dir / "receipt.json",
        candidate_path=(entry_dir / "candidate.md") if candidate_content is not None else None,
        result_digest=result_digest,
        candidate_digest=candidate_digest,
    )


def write_candidate_outbox(
    result: AuthorizedAutomationResult,
    out_dir: Path,
) -> CandidateOutboxPublication:
    """Publish one secret-scrubbed, candidate-only report without network I/O."""

    if type(result) is not AuthorizedAutomationResult:
        raise CandidateOutboxError("candidate outbox requires an exact automation result")
    try:
        validated = AuthorizedAutomationResult.model_validate(result)
    except ValidationError as exc:
        raise CandidateOutboxError("candidate outbox received an invalid automation result") from exc
    draft = validated.finding_draft
    if draft is None:
        raise CandidateOutboxError("automation result has no candidate finding draft")
    run_id = _require_secret_free_metadata("run ID", validated.run_id)
    hypothesis_id = _require_secret_free_metadata(
        "hypothesis ID", draft.hypothesis_id
    )

    candidate_content = _candidate_markdown(validated, draft)
    candidate_digest = _content_digest(candidate_content)
    source_result_digest = sha256_digest(validated.model_dump(mode="json"))
    entry_id = f"candidate.{candidate_digest.removeprefix('sha256:')[:32]}"
    entry_dir = out_dir / entry_id
    candidate_path = entry_dir / "candidate.md"
    receipt_path = entry_dir / "receipt.json"
    receipt_content = canonical_json(
        {
            "action_context_digest": validated.action_context_digest,
            "automatic_submission": False,
            "authority_grant_digest": validated.authority_grant_digest,
            "candidate_digest": candidate_digest,
            "candidate_format": "md",
            "entry_id": entry_id,
            "hypothesis_id": hypothesis_id,
            "independent_verification": False,
            "network_access": "none",
            "observation_bundle_digest": validated.observation_bundle_digest,
            "poc_context_digest": validated.poc_context_digest,
            "review_status": "manual_review",
            "run_id": run_id,
            "schema": "faultloom.candidate_outbox.receipt.v1",
            "source_result_digest": source_result_digest,
            "status": "draft_unverified",
            "target_dispatch": False,
        }
    )

    try:
        _ = _publish_create_once_bundle(
            out_dir=out_dir,
            entry_id=entry_id,
            files=(("candidate.md", candidate_content), ("receipt.json", receipt_content)),
            error_label="candidate outbox",
        )
    except _CandidateBundleAlreadyExists as exc:
        raise CandidateOutboxError("candidate outbox entry already exists: File exists") from exc

    return CandidateOutboxPublication(
        entry_id=entry_id,
        entry_dir=entry_dir,
        candidate_path=candidate_path,
        receipt_path=receipt_path,
        candidate_digest=candidate_digest,
        source_result_digest=source_result_digest,
    )
