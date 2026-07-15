#!/usr/bin/env python3
"""Verify an xctestrun manifest against the current build and source inputs."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
ENTRY_GROUPS = ("artifacts", "sourceMetadata", "projectMetadata", "lockMetadata")
ENTRY_KINDS = {"file", "directory", "symlink"}


class VerificationError(Exception):
    pass


def fail(classification: str, message: str) -> None:
    raise VerificationError(f"{classification}: {message}")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail("missing", f"cannot read manifest {path}: {error}")
    if not isinstance(document, dict) or document.get("schemaVersion") != SCHEMA_VERSION:
        fail("altered", "manifest has an unsupported schemaVersion")
    expected_keys = {
        "schemaVersion",
        "inputs",
        "artifacts",
        "sourceMetadata",
        "projectMetadata",
        "lockMetadata",
    }
    if set(document) != expected_keys:
        fail("extra", "manifest has missing or unexpected top-level fields")
    inputs = document["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "xctestrun",
        "project",
        "sourcePaths",
        "lockfiles",
    }:
        fail("altered", "manifest inputs are malformed")
    for field in ("xctestrun", "project"):
        if not isinstance(inputs[field], str):
            fail("altered", f"manifest input {field} is not a string")
        validate_relative(inputs[field], f"input {field}")
    for field in ("sourcePaths", "lockfiles"):
        if not isinstance(inputs[field], list) or not all(isinstance(value, str) for value in inputs[field]):
            fail("altered", f"manifest input {field} is not a string list")
        for value in inputs[field]:
            validate_relative(value, f"input {field}")
        if len(set(inputs[field])) != len(inputs[field]):
            fail("altered", f"manifest input {field} contains duplicates")
    for group in ENTRY_GROUPS:
        entries = document[group]
        if not isinstance(entries, list):
            fail("altered", f"manifest {group} is not a list")
        paths: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                fail("altered", f"manifest {group} contains a non-object entry")
            validate_entry(entry, group)
            if entry["path"] in paths:
                fail("altered", f"manifest {group} contains duplicate path {entry['path']}")
            paths.add(entry["path"])
    return document


def validate_relative(value: str, label: str) -> None:
    path = Path(value)
    if not value or path.is_absolute() or "\\" in value or any(part in {"", ".", ".."} for part in path.parts):
        fail("out_of_root", f"{label} is not a safe relative path: {value!r}")


def validate_entry(entry: dict[str, Any], group: str) -> None:
    required = {"path", "kind", "mode"}
    if not required.issubset(entry):
        fail("altered", f"manifest {group} entry lacks required fields")
    allowed = set(required)
    if entry.get("kind") in {"file", "symlink"}:
        allowed.add("sha256")
    if entry.get("kind") == "symlink":
        allowed.add("target")
    if set(entry) != allowed:
        fail("extra", f"manifest {group} entry has unexpected fields")
    if not isinstance(entry["path"], str):
        fail("altered", f"manifest {group} entry path is not a string")
    validate_relative(entry["path"], f"{group} entry")
    if entry["kind"] not in ENTRY_KINDS:
        fail("altered", f"manifest {group} entry has invalid kind")
    if not isinstance(entry["mode"], str) or len(entry["mode"]) != 4 or any(
        character not in "01234567" for character in entry["mode"]
    ):
        fail("altered", f"manifest {group} entry has invalid mode")
    if entry["kind"] in {"file", "symlink"}:
        digest = entry.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            fail("altered", f"manifest {group} entry has invalid sha256")
    if entry["kind"] == "symlink" and not isinstance(entry.get("target"), str):
        fail("altered", f"manifest {group} symlink lacks a target")


def manifest_builder() -> Path:
    builder = Path(__file__).with_name("build-xctest-manifest.py")
    if not builder.is_file():
        fail("missing", f"manifest builder is missing: {builder}")
    return builder


def build_current(
    expected: dict[str, Any], arguments: argparse.Namespace, output: Path
) -> dict[str, Any]:
    inputs = expected["inputs"]
    project = arguments.project or inputs["project"]
    if arguments.project is not None:
        source_root = Path(arguments.source_root).resolve()
        provided = Path(arguments.project)
        if not provided.is_absolute():
            provided = source_root / provided
        try:
            provided_relative = provided.resolve().relative_to(source_root).as_posix()
        except ValueError:
            fail("out_of_root", "--project is outside --source-root")
        if provided_relative != inputs["project"]:
            fail("altered", "--project does not match the manifest project input")
    command = [
        sys.executable,
        str(manifest_builder()),
        "--derived-data",
        arguments.derived_data,
        "--source-root",
        arguments.source_root,
        "--project",
        project,
        "--xctestrun",
        inputs["xctestrun"],
        "--output",
        str(output),
    ]
    for path in inputs["sourcePaths"]:
        command.extend(("--source-path", path))
    for lockfile in inputs["lockfiles"]:
        command.extend(("--lockfile", lockfile))
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "manifest builder failed"
        if "out-of-root" in message or "out of root" in message:
            fail("out_of_root", message)
        if "missing" in message or "does not exist" in message:
            fail("missing", message)
        fail("altered", message)
    return load_manifest(output)


def compare_group(name: str, expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> None:
    expected_by_path = {entry["path"]: entry for entry in expected}
    actual_by_path = {entry["path"]: entry for entry in actual}
    missing = sorted(set(expected_by_path) - set(actual_by_path))
    if missing:
        fail("missing", f"{name} entries are missing: {', '.join(missing)}")
    extra = sorted(set(actual_by_path) - set(expected_by_path))
    if extra:
        fail("extra", f"{name} has unmanifested entries: {', '.join(extra)}")
    altered = sorted(
        path
        for path in expected_by_path
        if expected_by_path[path] != actual_by_path[path]
    )
    if altered:
        fail("altered", f"{name} entries changed: {', '.join(altered)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail closed when an xctestrun manifest differs from its inputs."
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--derived-data", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--project")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        expected = load_manifest(Path(arguments.manifest))
        with tempfile.TemporaryDirectory(prefix="verify-xctest-manifest-") as temporary_directory:
            actual = build_current(expected, arguments, Path(temporary_directory) / "actual.json")
        if expected["inputs"] != actual["inputs"]:
            fail("altered", "manifest inputs changed")
        for group in ENTRY_GROUPS:
            compare_group(group, expected[group], actual[group])
    except VerificationError as error:
        print(f"xctest manifest verification failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"xctest manifest verification failed: altered: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
