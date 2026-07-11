#!/usr/bin/env python3
"""Content-verify and privately stage the Rust tools used by Core builds."""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path


class RustToolchainError(RuntimeError):
    """The selected Rust distribution is incomplete, mutable, or not pinned."""


RUSTC_HEADER = re.compile(
    r"^rustc (?P<release>\S+) \((?P<commit>[0-9a-f]{7,40}) "
    r"(?P<date>\d{4}-\d{2}-\d{2})\)$"
)
CARGO_HEADER = re.compile(
    r"^cargo (?P<release>\S+) \((?P<commit>[0-9a-f]{7,40}) "
    r"(?P<date>\d{4}-\d{2}-\d{2})\)$"
)
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUSTC_REQUIRED_FIELDS = {
    "binary",
    "commit-hash",
    "commit-date",
    "host",
    "release",
    "LLVM version",
}
CARGO_REQUIRED_FIELDS = {"release", "commit-hash", "commit-date", "host"}


@dataclass(frozen=True)
class RustToolchainSpec:
    version: str
    host: str
    rustc_sha256: str
    rustc_closure_sha256: str
    cargo_sha256: str | None = None


@dataclass(frozen=True)
class StagedRustToolchain:
    rustc: Path
    cargo: Path | None
    spec: RustToolchainSpec


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], *, root: Path, environment: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RustToolchainError(
            f"command failed ({' '.join(command)}): {result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


def _parse_verbose_identity(
    output: str,
    *,
    binary: str,
    header_pattern: re.Pattern[str],
    required_fields: set[str],
) -> dict[str, str]:
    lines = output.splitlines()
    if not lines:
        raise RustToolchainError(f"{binary} -vV produced no output")
    header = header_pattern.fullmatch(lines[0])
    if header is None:
        raise RustToolchainError(
            f"{binary} must provide a complete verbose version identity"
        )
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if ": " not in line:
            raise RustToolchainError(
                f"malformed {binary} verbose version field: {line!r}"
            )
        key, value = line.split(": ", 1)
        if key in fields or not value:
            raise RustToolchainError(
                f"duplicate or empty {binary} version field: {key!r}"
            )
        fields[key] = value
    missing = sorted(required_fields - fields.keys())
    if missing:
        raise RustToolchainError(
            f"{binary} verbose version is missing fields: {missing}"
        )
    commit = fields["commit-hash"]
    if FULL_COMMIT.fullmatch(commit) is None or set(commit) == {"0"}:
        raise RustToolchainError(
            f"{binary} verbose identity has an invalid commit hash"
        )
    try:
        datetime.date.fromisoformat(fields["commit-date"])
    except ValueError as exc:
        raise RustToolchainError(
            f"{binary} verbose identity has an invalid commit date"
        ) from exc
    if (
        header.group("release") != fields["release"]
        or not commit.startswith(header.group("commit"))
        or header.group("date") != fields["commit-date"]
    ):
        raise RustToolchainError(f"{binary} verbose identity fields disagree")
    return fields


def _parse_rustc_verbose(output: str) -> dict[str, str]:
    fields = _parse_verbose_identity(
        output,
        binary="rustc",
        header_pattern=RUSTC_HEADER,
        required_fields=RUSTC_REQUIRED_FIELDS,
    )
    if fields["binary"] != "rustc":
        raise RustToolchainError("rustc verbose identity has an unexpected binary name")
    return fields


def _parse_cargo_verbose(output: str) -> dict[str, str]:
    return _parse_verbose_identity(
        output,
        binary="cargo",
        header_pattern=CARGO_HEADER,
        required_fields=CARGO_REQUIRED_FIELDS,
    )


def _rustc_closure_files(rustc: Path, host: str) -> tuple[Path, tuple[Path, ...]]:
    toolchain = rustc.parent.parent
    driver_files = sorted((toolchain / "lib").glob("librustc_driver-*"))
    llvm_files = sorted((toolchain / "lib").glob("libLLVM*"))
    host_root = toolchain / "lib/rustlib" / host
    host_files = sorted(path for path in host_root.rglob("*") if path.is_file())
    if len(driver_files) != 1 or not llvm_files or not host_files:
        raise RustToolchainError("Rust distribution closure is incomplete")
    files = [rustc, *driver_files, *llvm_files, *host_files]
    if len(files) != len(set(files)):
        raise RustToolchainError("Rust distribution closure contains duplicate paths")
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise RustToolchainError(
                f"Rust distribution closure has an unsafe file: {path}"
            )
    return toolchain, tuple(files)


def rustc_closure_sha256(rustc: Path, host: str) -> str:
    """Hash rustc, its dynamic driver/LLVM, and the selected host sysroot."""

    toolchain, files = _rustc_closure_files(rustc, host)
    closure = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(toolchain).as_posix()):
        relative = path.relative_to(toolchain).as_posix().encode("utf-8")
        file_hash = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                file_hash.update(chunk)
        closure.update(
            len(relative).to_bytes(4, "big")
            + relative
            + size.to_bytes(8, "big")
            + file_hash.digest()
        )
    return closure.hexdigest()


def _compiler_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": "/tmp",
    }


def _copy_and_lock_toolchain(
    rustc: Path,
    cargo: Path | None,
    host: str,
    destination: Path,
) -> tuple[Path, Path | None]:
    toolchain, closure_files = _rustc_closure_files(rustc, host)
    extra_files: tuple[Path, ...] = () if cargo is None else (cargo,)
    for source in (*closure_files, *extra_files):
        if source.parent.parent != toolchain and source == cargo:
            raise RustToolchainError("cargo must come from the selected rustc toolchain")
        relative = source.relative_to(toolchain)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        source_mode = stat.S_IMODE(source.stat().st_mode)
        target.chmod(0o500 if source_mode & 0o111 else 0o400)
    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        directory.chmod(0o500)
    destination.chmod(0o500)
    staged_rustc = destination / rustc.relative_to(toolchain)
    staged_cargo = None if cargo is None else destination / cargo.relative_to(toolchain)
    return staged_rustc, staged_cargo


def _restore_staged_directories(destination: Path) -> None:
    for path in destination.rglob("*"):
        if path.is_file():
            path.chmod(0o600)
    destination.chmod(0o700)
    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda item: len(item.parts),
    ):
        directory.chmod(0o700)


def _probe_rustc(rustc: Path, *, host: str, version: str, root: Path) -> None:
    compiler_environment = _compiler_environment()
    fields = _parse_rustc_verbose(
        _run([str(rustc), "-vV"], root=root, environment=compiler_environment)
    )
    if fields["release"] != version:
        raise RustToolchainError(
            f"Rust mismatch: expected {version}, found {fields['release']}"
        )
    if fields["host"] != host:
        raise RustToolchainError(
            f"Rust host mismatch: expected {host}, found {fields['host']}"
        )
    challenge = os.urandom(32)
    expected = f"{sum((index + 1) * value for index, value in enumerate(challenge)):016x}"
    values = ", ".join(str(value) for value in challenge)
    with tempfile.TemporaryDirectory(prefix="faultloom-rustc-probe-") as raw_probe:
        probe = Path(raw_probe)
        source = probe / "probe.rs"
        executable = probe / ("probe.exe" if os.name == "nt" else "probe")
        source.write_text(
            "fn main() {\n"
            f"    let data: [u8; {len(challenge)}] = [{values}];\n"
            "    let value = data.iter().enumerate().fold(0u64, |acc, (index, item)| {\n"
            "        acc.wrapping_add((index as u64 + 1) * *item as u64)\n"
            "    });\n"
            '    print!("{value:016x}");\n'
            "}\n",
            encoding="utf-8",
            newline="\n",
        )
        _run(
            [str(rustc), "--edition=2021", str(source), "-o", str(executable)],
            root=root,
            environment=compiler_environment,
        )
        if (
            not executable.is_file()
            or executable.is_symlink()
            or executable.stat().st_size == 0
        ):
            raise RustToolchainError("rustc did not produce a regular probe executable")
        magic = executable.read_bytes()[:4]
        if not (
            magic == b"\x7fELF"
            or magic[:2] == b"MZ"
            or magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}
        ):
            raise RustToolchainError("rustc probe output is not a native executable")
        if _run([str(executable)], root=root, environment=compiler_environment) != expected:
            raise RustToolchainError(
                "the compiled Rust probe produced an unexpected result"
            )


def _probe_cargo(cargo: Path, *, host: str, version: str, root: Path) -> None:
    fields = _parse_cargo_verbose(
        _run([str(cargo), "-vV"], root=root, environment=_compiler_environment())
    )
    if fields["release"] != version:
        raise RustToolchainError(
            f"Cargo mismatch: expected {version}, found {fields['release']}"
        )
    if fields["host"] != host:
        raise RustToolchainError(
            f"Cargo host mismatch: expected {host}, found {fields['host']}"
        )


def _resolve_tools(
    spec: RustToolchainSpec,
    *,
    alias: str,
    environment: Mapping[str, str],
) -> tuple[Path, Path | None]:
    configured_rustc = environment.get("FAULTLOOM_RUSTC")
    if configured_rustc:
        rustc = Path(configured_rustc)
    else:
        rustup_home = Path(
            environment.get("RUSTUP_HOME", str(Path.home() / ".rustup"))
        )
        executable_name = "rustc.exe" if os.name == "nt" else "rustc"
        rustc = (
            rustup_home
            / "toolchains"
            / f"{alias}-{spec.host}"
            / "bin"
            / executable_name
        )
    cargo: Path | None = None
    if spec.cargo_sha256 is not None:
        configured_cargo = environment.get("FAULTLOOM_CARGO")
        cargo = (
            Path(configured_cargo)
            if configured_cargo
            else rustc.parent / ("cargo.exe" if os.name == "nt" else "cargo")
        )
    return rustc, cargo


def _require_regular_absolute(path: Path, *, name: str) -> None:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise RustToolchainError(
            f"rustup did not resolve a regular absolute {name} path"
        )


@contextlib.contextmanager
def stage_verified_toolchain(
    spec: RustToolchainSpec,
    *,
    alias: str,
    environment: Mapping[str, str],
    root: Path,
) -> Iterator[StagedRustToolchain]:
    """Yield a read-only staged toolchain and re-hash it after all use."""

    rustc, cargo = _resolve_tools(spec, alias=alias, environment=environment)
    _require_regular_absolute(rustc, name="rustc")
    if sha256_file(rustc) != spec.rustc_sha256:
        raise RustToolchainError(
            "rustc binary digest mismatch: "
            f"expected {spec.rustc_sha256}, found {sha256_file(rustc)}"
        )
    closure_digest = rustc_closure_sha256(rustc, spec.host)
    if closure_digest != spec.rustc_closure_sha256:
        raise RustToolchainError(
            "Rust distribution closure digest mismatch: "
            f"expected {spec.rustc_closure_sha256}, found {closure_digest}"
        )
    if cargo is not None:
        _require_regular_absolute(cargo, name="cargo")
        if cargo.parent.parent != rustc.parent.parent:
            raise RustToolchainError("cargo must come from the selected rustc toolchain")
        cargo_digest = sha256_file(cargo)
        if cargo_digest != spec.cargo_sha256:
            raise RustToolchainError(
                "cargo binary digest mismatch: "
                f"expected {spec.cargo_sha256}, found {cargo_digest}"
            )

    with tempfile.TemporaryDirectory(prefix="faultloom-rustc-stage-") as raw_stage:
        stage_root = Path(raw_stage) / "toolchain"
        try:
            staged_rustc, staged_cargo = _copy_and_lock_toolchain(
                rustc, cargo, spec.host, stage_root
            )
            if sha256_file(staged_rustc) != spec.rustc_sha256:
                raise RustToolchainError("staged rustc binary digest mismatch")
            if (
                rustc_closure_sha256(staged_rustc, spec.host)
                != spec.rustc_closure_sha256
            ):
                raise RustToolchainError("staged Rust distribution closure digest mismatch")
            if staged_cargo is not None:
                if sha256_file(staged_cargo) != spec.cargo_sha256:
                    raise RustToolchainError("staged cargo binary digest mismatch")
                _probe_cargo(
                    staged_cargo, host=spec.host, version=spec.version, root=root
                )
            _probe_rustc(staged_rustc, host=spec.host, version=spec.version, root=root)
            yield StagedRustToolchain(staged_rustc, staged_cargo, spec)
            if sha256_file(staged_rustc) != spec.rustc_sha256:
                raise RustToolchainError("the staged rustc changed during use")
            if (
                rustc_closure_sha256(staged_rustc, spec.host)
                != spec.rustc_closure_sha256
            ):
                raise RustToolchainError("the staged Rust closure changed during use")
            if staged_cargo is not None and sha256_file(staged_cargo) != spec.cargo_sha256:
                raise RustToolchainError("the staged cargo changed during use")
        finally:
            if stage_root.exists():
                _restore_staged_directories(stage_root)
