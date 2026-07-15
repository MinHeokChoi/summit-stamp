#!/usr/bin/env python3
"""Verify and safely restore a mode-preserving xctest transport archive."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

PAYLOAD_ROOT = "xctest"
FIXED_ARCHIVE = ".ci/xctest-transport/xctest-payload.tar"
FIXED_SIDECAR = ".ci/xctest-transport/xctest-payload.tar.sha256"
FIXED_DESTINATION = ".ci/xctest"
COPY_BUFFER_SIZE = 1024 * 1024
MAX_ARCHIVE_SIZE = 32 * 1024 * 1024 * 1024
MAX_MEMBER_COUNT = 100_000
MAX_MEMBER_SIZE = 8 * 1024 * 1024 * 1024
MAX_TOTAL_SIZE = 32 * 1024 * 1024 * 1024
MAX_MEMBER_NAME_BYTES = 4_096


class PayloadError(Exception):
    pass


@dataclass(frozen=True)
class MemberRecord:
    name: str
    is_directory: bool
    mode: int
    size: int


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


def ensure_safe_destination_parent(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except OSError as error:
                fail(f"cannot create destination parent: {error}")
            continue
        except OSError as error:
            fail(f"cannot inspect destination parent: {error}")
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            fail(f"destination parent is not a safe directory: {current.relative_to(root)}")
    return root.joinpath(*relative.parts)


def reject_existing_destination(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        fail(f"cannot inspect destination: {error}")
    fail("destination already exists")




def open_unchanged_regular_file(
    root: Path, relative: PurePosixPath, label: str
) -> tuple[BinaryIO, os.stat_result]:
    expected = require_safe_existing_path(root, relative, label)
    if not stat.S_ISREG(expected.st_mode):
        fail(f"{label} must be a regular file")
    if label == "archive" and expected.st_size > MAX_ARCHIVE_SIZE:
        fail("archive exceeds the maximum allowed size")
    if label == "sidecar" and expected.st_size > 4_096:
        fail("sidecar exceeds the maximum allowed size")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(root.joinpath(*relative.parts), flags)
    except OSError as error:
        fail(f"cannot open {label} without following symlinks: {error}")
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != expected.st_dev
            or current.st_ino != expected.st_ino
            or current.st_size != expected.st_size
        ):
            fail(f"{label} changed while opening")
        return os.fdopen(descriptor, "rb", closefd=True), current
    except Exception:
        os.close(descriptor)
        raise


def sidecar_digest(sidecar: BinaryIO, archive_name: str) -> str:
    try:
        sidecar.seek(0)
        content = sidecar.read()
        archive_name_bytes = archive_name.encode("utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read sidecar: {error}")
    expected_length = 64 + 2 + len(archive_name_bytes) + 1
    if (
        len(content) != expected_length
        or content[64:66] != b"  "
        or content[66:] != archive_name_bytes + b"\n"
        or any(character not in b"0123456789abcdef" for character in content[:64])
    ):
        fail("sidecar has invalid syntax")
    return content[:64].decode("ascii")


def sha256_open_file(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    try:
        source.seek(0)
        while chunk := source.read(COPY_BUFFER_SIZE):
            digest.update(chunk)
        source.seek(0)
    except OSError as error:
        fail(f"cannot hash archive: {error}")
    return digest.hexdigest()


def validate_member_name(name: str) -> PurePosixPath:
    if not name or "\\" in name or any(ord(character) < 32 for character in name):
        fail("archive contains an unsafe member name")
    try:
        encoded_name = name.encode("utf-8")
    except UnicodeError:
        fail("archive contains a non-UTF-8 member name")
    relative = PurePosixPath(name)
    if (
        len(encoded_name) > MAX_MEMBER_NAME_BYTES
        or relative.is_absolute()
        or relative.as_posix() != name
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        fail("archive contains an unsafe member name")
    if relative.parts[0] != PAYLOAD_ROOT:
        fail("archive member is outside the xctest payload root")
    return relative


def record_for_member(member: tarfile.TarInfo) -> MemberRecord:
    relative = validate_member_name(member.name)
    if member.type == tarfile.DIRTYPE:
        is_directory = True
        if member.size != 0:
            fail(f"directory member has content: {member.name}")
    elif member.type == tarfile.REGTYPE:
        is_directory = False
    else:
        fail(f"archive contains an unsupported member type: {member.name}")
    if member.linkname:
        fail(f"archive contains a link member: {member.name}")
    if getattr(member, "sparse", None):
        fail(f"archive contains a sparse member: {member.name}")
    if member.pax_headers and set(member.pax_headers) != {"path"}:
        fail(f"archive contains unsupported extended metadata: {member.name}")
    if member.pax_headers and member.pax_headers.get("path") != member.name:
        fail(f"archive contains inconsistent extended metadata: {member.name}")
    if (
        member.uid != 0
        or member.gid != 0
        or member.uname != ""
        or member.gname != ""
        or member.mtime != 0
        or not isinstance(member.mode, int)
        or member.mode < 0
        or member.mode & ~0o7777
    ):
        fail(f"archive member has invalid metadata: {member.name}")
    if not is_directory:
        if not isinstance(member.size, int) or member.size < 0 or member.size > MAX_MEMBER_SIZE:
            fail(f"archive member has an invalid size: {member.name}")
    if relative.parts == (PAYLOAD_ROOT,) and not is_directory:
        fail("payload root must be a directory")
    return MemberRecord(member.name, is_directory, member.mode, member.size)


def validate_archive(archive_file: BinaryIO) -> list[MemberRecord]:
    records: list[MemberRecord] = []
    names: set[str] = set()
    total_size = 0
    try:
        archive_file.seek(0)
        with tarfile.open(fileobj=archive_file, mode="r:") as archive:
            for member in archive:
                if len(records) >= MAX_MEMBER_COUNT:
                    fail("archive exceeds the maximum member count")
                record = record_for_member(member)
                if record.name in names:
                    fail(f"archive contains a duplicate member: {record.name}")
                names.add(record.name)
                if not record.is_directory:
                    total_size += record.size
                    if total_size > MAX_TOTAL_SIZE:
                        fail("archive exceeds the maximum uncompressed size")
                records.append(record)
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot validate archive: {error}")
    if not records or records[0] != MemberRecord(PAYLOAD_ROOT, True, records[0].mode, 0):
        fail("archive must begin with the xctest payload root")
    if [record.name for record in records] != sorted(record.name for record in records):
        fail("archive members are not in deterministic order")
    records_by_name = {record.name: record for record in records}
    for record in records:
        parts = PurePosixPath(record.name).parts
        for parent_length in range(1, len(parts)):
            parent_name = "/".join(parts[:parent_length])
            parent = records_by_name.get(parent_name)
            if parent is None or not parent.is_directory:
                fail(f"archive member has an invalid parent: {record.name}")
    return records


def output_path(destination: Path, record: MemberRecord) -> Path:
    parts = PurePosixPath(record.name).parts
    if parts == (PAYLOAD_ROOT,):
        return destination
    return destination.joinpath(*parts[1:])


def extract_regular_file(
    archive: tarfile.TarFile, member: tarfile.TarInfo, destination: Path, mode: int
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags, 0o600)
    except OSError as error:
        fail(f"cannot create archive member {member.name}: {error}")
    try:
        source = archive.extractfile(member)
        if source is None:
            fail(f"cannot read archive member {member.name}")
        try:
            remaining = member.size
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                descriptor = -1
                while remaining:
                    chunk = source.read(min(COPY_BUFFER_SIZE, remaining))
                    if not chunk:
                        fail(f"archive member is truncated: {member.name}")
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), mode)
        finally:
            source.close()
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot extract archive member {member.name}: {error}")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass


def extract_archive(
    archive_file: BinaryIO, records: list[MemberRecord], staging: Path
) -> None:
    directory_modes: list[tuple[Path, int]] = []
    try:
        status = os.lstat(staging)
    except OSError as error:
        fail(f"cannot inspect staging destination: {error}")
    if not stat.S_ISDIR(status.st_mode):
        fail("staging destination is not a directory")
    try:
        archive_file.seek(0)
        with tarfile.open(fileobj=archive_file, mode="r:") as archive:
            iterator = iter(archive)
            for expected in records:
                try:
                    member = next(iterator)
                except StopIteration:
                    fail("archive changed during extraction")
                actual = record_for_member(member)
                if actual != expected:
                    fail("archive changed during extraction")
                member_destination = output_path(staging, expected)
                if expected.is_directory:
                    if member_destination != staging:
                        try:
                            os.mkdir(member_destination, 0o700)
                        except OSError as error:
                            fail(f"cannot create archive directory {member.name}: {error}")
                    directory_modes.append((member_destination, expected.mode))
                else:
                    extract_regular_file(archive, member, member_destination, expected.mode)
            try:
                next(iterator)
            except StopIteration:
                pass
            else:
                fail("archive changed during extraction")
        for directory, mode in reversed(directory_modes):
            try:
                status = os.lstat(directory)
            except OSError as error:
                fail(f"cannot inspect extracted directory: {error}")
            if not stat.S_ISDIR(status.st_mode):
                fail(f"extracted directory changed unexpectedly: {directory}")
            try:
                os.chmod(directory, mode)
            except OSError as error:
                fail(f"cannot preserve directory mode: {error}")
    except PayloadError:
        remove_destination(staging)
        raise
    except (OSError, tarfile.TarError) as error:
        remove_destination(staging)
        fail(f"cannot extract archive: {error}")


def make_staging_destination(parent: Path) -> Path:
    try:
        return Path(tempfile.mkdtemp(prefix=".xctest-payload.", dir=parent))
    except OSError as error:
        fail(f"cannot create staging destination: {error}")


def publish_destination(staging: Path, destination: Path) -> None:
    try:
        os.rename(staging, destination)
    except OSError as error:
        fail(f"cannot publish extracted payload: {error}")


def remove_destination(destination: Path) -> None:
    try:
        shutil.rmtree(destination)
    except OSError:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify and safely extract a deterministic xctest payload archive."
    )
    parser.add_argument("--archive", required=True)
    parser.add_argument("--sidecar", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    destination_created = False
    staging_path: Path | None = None
    try:
        root = repository_root()
        archive_relative, archive_path = repo_path(root, arguments.archive, "archive")
        sidecar_relative, _sidecar_path = repo_path(root, arguments.sidecar, "sidecar")
        if archive_relative.as_posix() != FIXED_ARCHIVE:
            fail(f"archive must be {FIXED_ARCHIVE}")
        if sidecar_relative.as_posix() != FIXED_SIDECAR:
            fail(f"sidecar must be {FIXED_SIDECAR}")
        destination_relative = parse_repo_relative(FIXED_DESTINATION, "destination")
        destination_path = ensure_safe_destination_parent(root, destination_relative)
        reject_existing_destination(destination_path)
        with open_unchanged_regular_file(root, sidecar_relative, "sidecar")[0] as sidecar_file:
            expected_digest = sidecar_digest(sidecar_file, archive_path.name)

        with open_unchanged_regular_file(root, archive_relative, "archive")[0] as archive_file:
            actual_digest = sha256_open_file(archive_file)
            if not hmac.compare_digest(expected_digest, actual_digest):
                fail("archive digest does not match sidecar")
            records = validate_archive(archive_file)
            staging_path = make_staging_destination(destination_path.parent)
            extract_archive(archive_file, records, staging_path)
            if not hmac.compare_digest(expected_digest, sha256_open_file(archive_file)):
                fail("archive changed during extraction")
            publish_destination(staging_path, destination_path)
            staging_path = None
            destination_created = True
    except PayloadError as error:
        if staging_path is not None:
            remove_destination(staging_path)
        if destination_created and "destination_path" in locals():
            remove_destination(destination_path)
        print(f"xctest payload unpacking failed: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        if staging_path is not None:
            remove_destination(staging_path)
        if destination_created and "destination_path" in locals():
            remove_destination(destination_path)
        print(f"xctest payload unpacking failed: {error}", file=sys.stderr)
        return 1
    print(f"restored xctest payload: {FIXED_DESTINATION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
