#!/usr/bin/env python3
"""Create a deterministic, mode-preserving xctest transport archive."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

PAYLOAD_ROOT = "xctest"
FIXED_SOURCE = ".ci/xctest"
FIXED_ARCHIVE = ".ci/xctest-transport/xctest-payload.tar"
FIXED_SIDECAR = ".ci/xctest-transport/xctest-payload.tar.sha256"
COPY_BUFFER_SIZE = 1024 * 1024
MAX_MEMBER_COUNT = 100_000
MAX_MEMBER_SIZE = 8 * 1024 * 1024 * 1024
MAX_TOTAL_SIZE = 32 * 1024 * 1024 * 1024


class PayloadError(Exception):
    pass


@dataclass(frozen=True)
class TreeEntry:
    archive_name: str
    path: Path
    status: os.stat_result
    is_directory: bool


def fail(message: str) -> None:
    raise PayloadError(message)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    if not root.is_dir():
        fail("repository root is unavailable")
    return root


def parse_repo_relative(value: str, label: str) -> PurePosixPath:
    if not value or "\\" in value or any(ord(character) < 32 for character in value):
        fail(f"{label} must be a safe repository-relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        fail(f"{label} must be a safe repository-relative path")
    return relative


def repo_path(root: Path, value: str, label: str) -> tuple[PurePosixPath, Path]:
    relative = parse_repo_relative(value, label)
    return relative, root.joinpath(*relative.parts)


def require_safe_existing_path(root: Path, relative: PurePosixPath, label: str) -> os.stat_result:
    current = root
    status: os.stat_result | None = None
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            status = os.lstat(current)
        except OSError as error:
            fail(f"{label} is missing or unreadable: {error}")
        if stat.S_ISLNK(status.st_mode):
            fail(f"{label} contains a symlink: {current.relative_to(root)}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(status.st_mode):
            fail(f"{label} has a non-directory ancestor: {current.relative_to(root)}")
    if status is None:
        fail(f"{label} is missing")
    return status


def ensure_safe_output_parent(root: Path, relative: PurePosixPath, label: str) -> Path:
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except OSError as error:
                fail(f"cannot create {label} parent: {error}")
            continue
        except OSError as error:
            fail(f"cannot inspect {label} parent: {error}")
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            fail(f"{label} parent is not a safe directory: {current.relative_to(root)}")
    return root.joinpath(*relative.parts)


def reject_existing_output(path: Path, label: str) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    fail(f"duplicate {label}")


def is_below(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_source_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 for character in name)
    ):
        fail(f"source tree contains an unsafe name: {name!r}")


def tree_entry(path: Path, archive_name: str) -> TreeEntry:
    try:
        status = os.lstat(path)
    except OSError as error:
        fail(f"cannot inspect source entry {path}: {error}")
    if stat.S_ISLNK(status.st_mode):
        fail(f"source tree contains a symlink: {path}")
    if stat.S_ISDIR(status.st_mode):
        return TreeEntry(archive_name, path, status, True)
    if stat.S_ISREG(status.st_mode):
        return TreeEntry(archive_name, path, status, False)
    fail(f"source tree contains an unsupported file type: {path}")


def collect_tree(source: Path) -> list[TreeEntry]:
    entries = [tree_entry(source, PAYLOAD_ROOT)]
    total_size = 0

    def append_entry(entry: TreeEntry) -> None:
        nonlocal total_size
        if len(entries) >= MAX_MEMBER_COUNT:
            fail("source tree exceeds the maximum member count")
        if not entry.is_directory:
            if entry.status.st_size < 0 or entry.status.st_size > MAX_MEMBER_SIZE:
                fail(f"source file exceeds the maximum size: {entry.path}")
            total_size += entry.status.st_size
            if total_size > MAX_TOTAL_SIZE:
                fail("source tree exceeds the maximum total size")
        entries.append(entry)

    def walk(directory: Path, archive_directory: str) -> None:
        try:
            with os.scandir(directory) as scanner:
                children = sorted(scanner, key=lambda child: child.name)
        except OSError as error:
            fail(f"cannot enumerate source directory {directory}: {error}")
        for child in children:
            validate_source_name(child.name)
            archive_name = f"{archive_directory}/{child.name}"
            entry = tree_entry(directory / child.name, archive_name)
            append_entry(entry)
            if entry.is_directory:
                walk(entry.path, archive_name)

    walk(source, PAYLOAD_ROOT)
    return entries


def same_entry(expected: os.stat_result, actual: os.stat_result) -> bool:
    return (
        expected.st_dev == actual.st_dev
        and expected.st_ino == actual.st_ino
        and stat.S_IFMT(expected.st_mode) == stat.S_IFMT(actual.st_mode)
        and stat.S_IMODE(expected.st_mode) == stat.S_IMODE(actual.st_mode)
        and expected.st_size == actual.st_size
    )


def tar_info(entry: TreeEntry) -> tarfile.TarInfo:
    info = tarfile.TarInfo(entry.archive_name)
    info.type = tarfile.DIRTYPE if entry.is_directory else tarfile.REGTYPE
    info.mode = stat.S_IMODE(entry.status.st_mode)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = 0 if entry.is_directory else entry.status.st_size
    return info


def open_unchanged_regular_file(entry: TreeEntry) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(entry.path, flags)
    except OSError as error:
        fail(f"cannot open source file without following symlinks: {entry.path}: {error}")
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode) or not same_entry(entry.status, current):
            fail(f"source file changed while packaging: {entry.path}")
        return os.fdopen(descriptor, "rb", closefd=True)
    except Exception:
        os.close(descriptor)
        raise


def write_archive(temporary_path: Path, entries: list[TreeEntry]) -> None:
    try:
        flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(temporary_path, flags), "wb") as output:
            with tarfile.open(
                fileobj=output,
                mode="w",
                format=tarfile.GNU_FORMAT,
                dereference=False,
            ) as archive:
                for entry in entries:
                    try:
                        current = os.lstat(entry.path)
                    except OSError as error:
                        fail(f"cannot recheck source entry {entry.path}: {error}")
                    if not same_entry(entry.status, current):
                        fail(f"source tree changed while packaging: {entry.path}")
                    info = tar_info(entry)
                    if entry.is_directory:
                        archive.addfile(info)
                    else:
                        with open_unchanged_regular_file(entry) as source_file:
                            archive.addfile(info, source_file)
            output.flush()
            os.fsync(output.fileno())
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot create payload archive: {error}")


def publish_new_file(temporary_path: Path, destination: Path, label: str) -> tuple[int, int]:
    try:
        identity = os.lstat(temporary_path)
        if not stat.S_ISREG(identity.st_mode):
            fail(f"temporary {label} is not a regular file")
        os.link(temporary_path, destination, follow_symlinks=False)
    except FileExistsError:
        fail(f"duplicate {label}")
    except OSError as error:
        fail(f"cannot publish {label}: {error}")
    try:
        os.unlink(temporary_path)
    except OSError as error:
        fail(f"cannot finalize {label}: {error}")
    return identity.st_dev, identity.st_ino


def make_temporary(parent: Path, prefix: str) -> tuple[int, Path]:
    try:
        descriptor, raw_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=parent)
    except OSError as error:
        fail(f"cannot create temporary output: {error}")
    return descriptor, Path(raw_path)


def write_sidecar(temporary_path: Path, digest: str, archive_name: str) -> None:
    content = f"{digest}  {archive_name}\n".encode("utf-8")
    try:
        flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(temporary_path, flags), "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        fail(f"cannot write payload sidecar: {error}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as source:
            while chunk := source.read(COPY_BUFFER_SIZE):
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash payload archive: {error}")
    return digest.hexdigest()


def remove_if_identity(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = os.lstat(path)
    except OSError:
        return
    if (current.st_dev, current.st_ino) == identity:
        try:
            os.unlink(path)
        except OSError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a deterministic xctest archive without following symlinks."
    )
    parser.add_argument("--source", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--sidecar", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    archive_identity: tuple[int, int] | None = None
    archive_temporary: Path | None = None
    sidecar_temporary: Path | None = None
    try:
        root = repository_root()
        source_relative, source = repo_path(root, arguments.source, "source")
        archive_relative = parse_repo_relative(arguments.archive, "archive output")
        sidecar_relative = parse_repo_relative(arguments.sidecar, "sidecar output")
        if source_relative.as_posix() != FIXED_SOURCE:
            fail(f"source must be {FIXED_SOURCE}")
        if archive_relative.as_posix() != FIXED_ARCHIVE:
            fail(f"archive output must be {FIXED_ARCHIVE}")
        if sidecar_relative.as_posix() != FIXED_SIDECAR:
            fail(f"sidecar output must be {FIXED_SIDECAR}")
        source_status = require_safe_existing_path(root, source_relative, "source")
        if not stat.S_ISDIR(source_status.st_mode):
            fail("source must be a directory")
        archive_path = ensure_safe_output_parent(root, archive_relative, "archive output")
        sidecar_path = ensure_safe_output_parent(root, sidecar_relative, "sidecar output")
        if is_below(archive_path, source) or is_below(sidecar_path, source):
            fail("archive and sidecar outputs must be outside the source tree")
        reject_existing_output(archive_path, "archive output")
        reject_existing_output(sidecar_path, "sidecar output")

        entries = collect_tree(source)
        archive_descriptor, archive_temporary = make_temporary(
            archive_path.parent, f".{archive_path.name}."
        )
        os.close(archive_descriptor)
        write_archive(archive_temporary, entries)
        digest = sha256_file(archive_temporary)
        archive_identity = publish_new_file(archive_temporary, archive_path, "archive output")
        archive_temporary = None
        sidecar_descriptor, sidecar_temporary = make_temporary(
            sidecar_path.parent, f".{sidecar_path.name}."
        )
        os.close(sidecar_descriptor)
        write_sidecar(sidecar_temporary, digest, archive_path.name)
        publish_new_file(sidecar_temporary, sidecar_path, "sidecar output")
        sidecar_temporary = None
    except PayloadError as error:
        remove_if_identity(archive_path, archive_identity) if "archive_path" in locals() else None
        print(f"xctest payload packaging failed: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        remove_if_identity(archive_path, archive_identity) if "archive_path" in locals() else None
        print(f"xctest payload packaging failed: {error}", file=sys.stderr)
        return 1
    finally:
        for temporary_path in (archive_temporary, sidecar_temporary):
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass
    print(f"created xctest payload archive: {arguments.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
