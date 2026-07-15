#!/usr/bin/env python3
"""Atomically write one verified M0 evidence record."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import NoReturn, Optional
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SECRET_PATTERNS = (
    re.compile(rb"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(rb"(?i)(?:supabase_)?(?:service[_-]?role|anon)[_-]?(?:key|token)\s*[:=]\s*['\"]?\S+"),
    re.compile(rb"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(rb"(?:postgres|postgresql)://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE),
    re.compile(rb"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
    re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk_[A-Za-z0-9]{16,}|sbp_[A-Za-z0-9_-]{16,})\b", re.IGNORECASE),
)
SKIPPED_TEST_RE = re.compile(
    rb"(?i)(?:#\s*skip\b|\bTest Case\b.*\bskipped\b|\btests?\s+skipped\b)"
)
WARNING_RE = re.compile(rb"(?i)\bwarning\s*:")
NO_APPINTENTS_METADATA_RE = re.compile(
    rb"(?i).*warning:\s*Metadata extraction skipped\. No AppIntents\.framework dependency found\.\s*(?:\(in target .+\))?\s*$"
)


class EvidenceError(Exception):
    pass


def fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def repository_root() -> Path:
    script_dir = Path(__file__).resolve().parent
    result = subprocess.run(
        ["git", "-C", str(script_dir), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail("unable to determine repository root")
    root = Path(result.stdout.strip()).resolve()
    if not root.is_dir():
        fail("invalid repository root")
    return root


def repo_relative_path(root: Path, raw_path: str, label: str) -> tuple[Path, str]:
    if not raw_path or "\\" in raw_path or any(ord(character) < 32 for character in raw_path):
        fail(f"invalid {label} path")
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or relative.as_posix() != raw_path or not relative.parts or any(part in (".", "..") for part in relative.parts):
        fail(f"invalid {label} path")
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            fail(f"{label} path contains a symlinked directory")
    try:
        candidate.parent.resolve(strict=False).relative_to(root)
    except ValueError:
        fail(f"{label} path is outside repository")
    return candidate, relative.as_posix()


def contains_secret(data: bytes) -> bool:
    return any(pattern.search(data) for pattern in SECRET_PATTERNS)


def require_safe_log(
    root: Path,
    raw_path: str,
    expected_id: Optional[str] = None,
) -> tuple[Path, str, bytes]:
    path, relative = repo_relative_path(root, raw_path, "log")
    if expected_id is None:
        allowed = re.fullmatch(
            r"\.ci/logs/(?:[A-Za-z0-9][A-Za-z0-9._-]*\.log|\.[A-Za-z0-9][A-Za-z0-9._-]*\.log\.[A-Za-z0-9._-]+)",
            relative,
        )
        if not allowed:
            fail("invalid log path")
    elif relative != f".ci/logs/{expected_id}.log":
        fail("mismatched evidence ID")
    if path.is_symlink() or not path.is_file():
        fail("missing log")
    data = path.read_bytes()
    if not data:
        fail("missing log")
    if contains_secret(data):
        fail("secret detected in log")
    return path, relative, data


def test_log_counts(data: bytes) -> tuple[int, int]:
    skipped_tests = 0
    warnings = 0
    for line in data.splitlines():
        if NO_APPINTENTS_METADATA_RE.fullmatch(line):
            continue
        if SKIPPED_TEST_RE.search(line):
            skipped_tests += 1
        if WARNING_RE.search(line):
            warnings += 1
    return skipped_tests, warnings




def parse_timestamp(raw: str, label: str) -> datetime:
    if not TIMESTAMP_RE.fullmatch(raw):
        fail(f"invalid {label} timestamp")
    try:
        value = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail(f"invalid {label} timestamp")
    return value


def require_nonnegative_integer(raw: str, label: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", raw):
        fail(f"invalid {label}")
    return int(raw)


def git_sha(root: Path) -> str:
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        check=False,
        capture_output=True,
        text=True,
    )
    value = head.stdout.strip().lower()
    if head.returncode != 0 or status.returncode != 0 or status.stdout or not SHA_RE.fullmatch(value):
        return "uncommitted"
    return value


def parse_command(raw: str) -> list[str]:
    try:
        command = json.loads(raw)
    except json.JSONDecodeError:
        fail("invalid command JSON")
    if not isinstance(command, list) or not command:
        fail("invalid command JSON")
    for argument in command:
        if not isinstance(argument, str) or not argument or any(ord(char) < 32 for char in argument):
            fail("invalid command JSON")
        try:
            encoded = argument.encode("utf-8")
        except UnicodeError:
            fail("invalid command JSON")
        if contains_secret(encoded):
            fail("secret detected in command")
    return command


def add_evidence_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True)
    parser.add_argument("--status", required=True, choices=("passed", "failed"))
    parser.add_argument(
        "--runner",
        required=True,
        choices=("swift", "xcode", "xctest", "pgtap", "ui-build", "bijection-negative"),
    )
    parser.add_argument("--command-json", required=True)
    parser.add_argument("--exit-code", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--skipped-tests", required=True)
    parser.add_argument("--warnings", required=True)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    add_evidence_arguments(parser)
    return parser


def atomic_link_write(path: Path, data: bytes) -> None:
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    except OSError:
        fail("unable to write evidence output")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            fail("duplicate evidence output")
        except OSError:
            fail("unable to write evidence output")
    except OSError:
        fail("unable to write evidence output")
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def write_evidence(arguments: argparse.Namespace) -> None:
    if not ID_RE.fullmatch(arguments.id):
        fail("invalid evidence ID")
    if arguments.status != "passed":
        fail("only passed evidence can be written")

    exit_code = require_nonnegative_integer(arguments.exit_code, "exit code")
    skipped_tests = require_nonnegative_integer(arguments.skipped_tests, "skipped tests")
    warnings = require_nonnegative_integer(arguments.warnings, "warnings")
    if exit_code != 0:
        fail("nonzero evidence run")
    if skipped_tests != 0:
        fail("skipped tests are not valid evidence")
    if warnings != 0:
        fail("warnings are not valid evidence")

    root = repository_root()
    log_path, log_relative, log_data = require_safe_log(root, arguments.log, arguments.id)
    observed_skipped_tests, observed_warnings = test_log_counts(log_data)
    if observed_skipped_tests != skipped_tests or observed_warnings != warnings:
        fail("mismatched evidence log counts")
    expected_output = f"Evidence/tests/{arguments.id}.json"
    if arguments.output != expected_output:
        fail("mismatched evidence output")
    output_path, output_relative = repo_relative_path(root, arguments.output, "output")
    if output_relative != expected_output:
        fail("mismatched evidence output")
    sidecar_path = Path(f"{output_path}.sha256")
    if output_path.exists() or output_path.is_symlink() or sidecar_path.exists() or sidecar_path.is_symlink():
        fail("duplicate evidence output")

    started_at = parse_timestamp(arguments.started_at, "start")
    finished_at = parse_timestamp(arguments.finished_at, "finish")
    if finished_at < started_at:
        fail("invalid evidence timestamps")
    command = parse_command(arguments.command_json)

    output_parent = output_path.parent
    output_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved_parent = output_parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(root)
    except ValueError:
        fail("output path is outside repository")
    if output_path.exists() or output_path.is_symlink() or sidecar_path.exists() or sidecar_path.is_symlink():
        fail("duplicate evidence output")

    record = {
        "schemaVersion": 1,
        "id": arguments.id,
        "status": "passed",
        "runner": arguments.runner,
        "command": command,
        "exitCode": exit_code,
        "gitSHA": git_sha(root),
        "logSHA": hashlib.sha256(log_data).hexdigest(),
        "timestamps": {
            "startedAt": arguments.started_at,
            "finishedAt": arguments.finished_at,
        },
        "output": {"path": output_relative},
        "skippedTests": skipped_tests,
        "warnings": warnings,
    }
    evidence_bytes = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    sidecar_bytes = f"{hashlib.sha256(evidence_bytes).hexdigest()}  {output_relative}\n".encode("ascii")

    # Create the sidecar first. If the evidence path races, remove only the sidecar
    # linked by this process and leave the competing evidence untouched.
    atomic_link_write(sidecar_path, sidecar_bytes)
    try:
        atomic_link_write(output_path, evidence_bytes)
    except EvidenceError:
        sidecar_path.unlink(missing_ok=True)
        raise


def validate_log(raw_path: str) -> None:
    root = repository_root()
    require_safe_log(root, raw_path)


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 2 and argv[0] == "--validate-log":
            validate_log(argv[1])
            return 0
        parser = make_parser()
        arguments = parser.parse_args(argv)
        write_evidence(arguments)
        return 0
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
