#!/usr/bin/env python3
"""Build a deterministic inventory for an xcodebuild build-for-testing product."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
SOURCE_DIRECTORIES = ("App", "Config", "Features", "Packages", "Tests")
LOCKFILE_NAMES = {"Package.resolved", "Podfile.lock", "Cartfile.resolved"}
EXCLUDED_TOP_LEVEL = {".git", ".gjc", ".ci", "Evidence", "Pods", "Carthage"}
PROVENANCE_EXCLUDED_DIRECTORIES = {".build", ".cache", ".swiftpm", "DerivedData", "cache", "Caches"}
REFERENCE_KEYS = {"TestBundlePath", "TestHostPath", "UITargetAppPath", "DependentProductPaths"}
BUNDLE_SUFFIXES = (".xctest", ".app", ".framework", ".appex", ".bundle")


class ManifestError(Exception):
    pass


def fail(message: str) -> None:
    raise ManifestError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def mode_string(path: Path) -> str:
    return f"{stat.S_IMODE(os.lstat(path).st_mode):04o}"


def is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def resolved_existing(path: Path, root: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"missing {label}: {path} ({error})")
    if not is_inside(resolved, root):
        fail(f"out-of-root {label}: {path}")
    return resolved


def relative_existing(path: Path, root: Path, label: str) -> str:
    lexical = Path(os.path.abspath(path))
    if not is_inside(lexical, root):
        fail(f"out-of-root {label}: {path}")
    resolved_existing(lexical, root, label)
    return lexical.relative_to(root).as_posix()


def entry_for(path: Path, root: Path, category: str) -> dict[str, str]:
    relative = relative_existing(path, root, f"{category} entry")
    file_mode = os.lstat(path).st_mode
    entry: dict[str, str] = {
        "path": relative,
        "mode": mode_string(path),
    }
    if stat.S_ISREG(file_mode):
        entry["kind"] = "file"
        entry["sha256"] = sha256_file(path)
    elif stat.S_ISLNK(file_mode):
        target = os.readlink(path)
        resolved_existing(path, root, f"{category} symlink")
        entry["kind"] = "symlink"
        entry["sha256"] = sha256_bytes(target.encode("utf-8", "surrogateescape"))
        entry["target"] = target
    elif stat.S_ISDIR(file_mode):
        entry["kind"] = "directory"
    else:
        fail(f"unsupported {category} entry type: {path}")
    return entry


def is_excluded_provenance_directory(path: Path) -> bool:
    return path.name in PROVENANCE_EXCLUDED_DIRECTORIES


def collect_tree(path: Path, root: Path, category: str) -> list[dict[str, str]]:
    """Collect path, children, modes, and hashes without following symlinks."""
    entries: list[dict[str, str]] = []

    def visit(current: Path) -> None:
        if category != "artifact" and is_excluded_provenance_directory(current):
            return
        entry = entry_for(current, root, category)
        entries.append(entry)
        if entry["kind"] != "directory":
            return
        try:
            children = sorted(os.scandir(current), key=lambda child: child.name)
        except OSError as error:
            fail(f"cannot enumerate {category} directory {current}: {error}")
        for child in children:
            child_path = Path(child.path)
            if category != "artifact" and is_excluded_provenance_directory(child_path):
                continue
            visit(child_path)

    visit(path)
    return entries


def merge_entries(entries: Iterable[dict[str, str]], category: str) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for entry in entries:
        previous = merged.get(entry["path"])
        if previous is not None and previous != entry:
            fail(f"conflicting {category} entry: {entry['path']}")
        merged[entry["path"]] = entry
    return [merged[path] for path in sorted(merged)]


def parse_xctestrun(path: Path, derived_data: Path) -> tuple[dict[str, Any], list[Path]]:
    try:
        content = path.read_bytes()
        document = plistlib.loads(content)
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        fail(f"invalid xctestrun {path}: {error}")
    if not isinstance(document, dict):
        fail(f"xctestrun root must be a dictionary: {path}")

    references: list[Path] = []

    def expand_test_root(raw: str) -> str:
        return raw.replace("__TESTROOT__", str(path.parent))

    def resolve_reference(raw: str, test_host: Path | None = None) -> Path:
        expanded = expand_test_root(raw)
        if "__TESTHOST__" in expanded:
            if test_host is None:
                fail(f"xctestrun reference requires a TestHostPath: {raw}")
            expanded = expanded.replace("__TESTHOST__", str(test_host))
        if "__" in expanded or "$" in expanded:
            fail(f"unresolved xctestrun path placeholder: {raw}")
        candidate = Path(expanded)
        if not candidate.is_absolute():
            candidate = path.parent / candidate
        resolved_existing(candidate, derived_data, "xctestrun reference")
        bundle_parts: list[str] = []
        for part in candidate.parts:
            bundle_parts.append(part)
            if part.endswith(BUNDLE_SUFFIXES):
                bundle = Path(*bundle_parts)
                resolved_existing(bundle, derived_data, "xctestrun bundle")
                return bundle
        fail(f"xctestrun reference is not inside a bundle: {raw}")

    def visit(
        value: Any,
        key: str | None = None,
        test_host: Path | None = None,
    ) -> None:
        if isinstance(value, dict):
            local_test_host = test_host
            raw_test_host = value.get("TestHostPath")
            if isinstance(raw_test_host, str):
                expanded_test_host = expand_test_root(raw_test_host)
                if "__" in expanded_test_host or "$" in expanded_test_host:
                    fail(f"unresolved xctestrun TestHostPath placeholder: {raw_test_host}")
                local_test_host = Path(expanded_test_host)
                if not local_test_host.is_absolute():
                    local_test_host = path.parent / local_test_host
                resolved_existing(local_test_host, derived_data, "xctestrun test host")
            for child_key, child_value in value.items():
                if not isinstance(child_key, str):
                    fail("xctestrun contains a non-string key")
                visit(child_value, child_key, local_test_host)
            return
        if isinstance(value, list):
            for child in value:
                if key in REFERENCE_KEYS:
                    if not isinstance(child, str):
                        fail(f"xctestrun {key} must contain only strings")
                    references.append(resolve_reference(child, test_host))
                else:
                    visit(child, key, test_host)
            return
        if key in REFERENCE_KEYS:
            if not isinstance(value, str):
                fail(f"xctestrun {key} must be a string or string list")
            references.append(resolve_reference(value, test_host))

    visit(document)
    if not references:
        fail(f"xctestrun has no bundle references: {path}")
    return document, references


def find_xctestrun(derived_data: Path, requested: str | None) -> Path:
    if requested is not None:
        candidate = Path(requested)
        if not candidate.is_absolute():
            candidate = derived_data / candidate
        resolved_existing(candidate, derived_data, "xctestrun")
        if candidate.suffix != ".xctestrun":
            fail(f"xctestrun must end in .xctestrun: {candidate}")
        return candidate
    matches = sorted(
        path for path in derived_data.glob("Build/Products/**/*.xctestrun") if path.is_file()
    )
    if len(matches) != 1:
        fail(
            "expected exactly one xctestrun below "
            f"{derived_data / 'Build/Products'}, found {len(matches)}"
        )
    resolved_existing(matches[0], derived_data, "xctestrun")
    return matches[0]


def resolve_source_path(source_root: Path, raw: str, label: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = source_root / candidate
    resolved_existing(candidate, source_root, label)
    return candidate


def discover_lockfiles(source_root: Path) -> list[Path]:
    lockfiles: list[Path] = []
    for current, directories, filenames in os.walk(source_root, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source_root)
        directories[:] = sorted(
            directory
            for directory in directories
            if not (
                (relative == Path(".") and directory in EXCLUDED_TOP_LEVEL)
                or directory in PROVENANCE_EXCLUDED_DIRECTORIES
            )
        )
        for filename in sorted(filenames):
            if filename in LOCKFILE_NAMES:
                candidate = current_path / filename
                resolved_existing(candidate, source_root, "lockfile")
                lockfiles.append(candidate)
    return sorted(lockfiles)


def collect_metadata(
    source_root: Path,
    project: Path,
    source_paths: list[str],
    lockfile_values: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], dict[str, Any]]:
    selected_source_paths = source_paths or [
        directory for directory in SOURCE_DIRECTORIES if (source_root / directory).exists()
    ]
    if not selected_source_paths:
        fail(f"no source directories found below {source_root}")

    source_entries: list[dict[str, str]] = []
    source_inputs: list[str] = []
    for value in selected_source_paths:
        path = resolve_source_path(source_root, value, "source path")
        source_inputs.append(relative_existing(path, source_root, "source path"))
        source_entries.extend(collect_tree(path, source_root, "source"))

    project_entries = collect_tree(project, source_root, "project")
    project_yml = source_root / "project.yml"
    if project_yml.exists() and project_yml != project:
        project_entries.extend(collect_tree(project_yml, source_root, "project"))

    if lockfile_values:
        lockfiles = [resolve_source_path(source_root, value, "lockfile") for value in lockfile_values]
    else:
        lockfiles = discover_lockfiles(source_root)
    lock_entries: list[dict[str, str]] = []
    lock_inputs: list[str] = []
    for lockfile in lockfiles:
        lock_inputs.append(relative_existing(lockfile, source_root, "lockfile"))
        lock_entries.extend(collect_tree(lockfile, source_root, "lockfile"))

    inputs = {
        "project": relative_existing(project, source_root, "project"),
        "sourcePaths": sorted(set(source_inputs)),
        "lockfiles": sorted(set(lock_inputs)),
    }
    return (
        merge_entries(source_entries, "source"),
        merge_entries(project_entries, "project"),
        merge_entries(lock_entries, "lockfile"),
        inputs,
    )


def build_manifest(arguments: argparse.Namespace) -> dict[str, Any]:
    derived_data = Path(arguments.derived_data).resolve()
    source_root = Path(arguments.source_root).resolve()
    if not derived_data.is_dir():
        fail(f"derived data directory does not exist: {derived_data}")
    if not source_root.is_dir():
        fail(f"source root directory does not exist: {source_root}")

    project = resolve_source_path(source_root, arguments.project, "project")
    xctestrun = find_xctestrun(derived_data, arguments.xctestrun)
    _, bundles = parse_xctestrun(xctestrun, derived_data)

    artifact_entries: list[dict[str, str]] = [
        entry_for(xctestrun, derived_data, "xctestrun")
    ]
    for bundle in bundles:
        artifact_entries.extend(collect_tree(bundle, derived_data, "artifact"))

    source_entries, project_entries, lock_entries, input_metadata = collect_metadata(
        source_root,
        project,
        arguments.source_path,
        arguments.lockfile,
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "inputs": {
            "xctestrun": relative_existing(xctestrun, derived_data, "xctestrun"),
            **input_metadata,
        },
        "artifacts": merge_entries(artifact_entries, "artifact"),
        "sourceMetadata": source_entries,
        "projectMetadata": project_entries,
        "lockMetadata": lock_entries,
    }


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a fail-closed xctestrun artifact manifest."
    )
    parser.add_argument("--derived-data", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--xctestrun")
    parser.add_argument("--source-path", action="append", default=[])
    parser.add_argument("--lockfile", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        manifest = build_manifest(arguments)
        content = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        output = Path(arguments.output)
        atomic_write(output, content)
        atomic_write(
            output.with_name(output.name + ".sha256"),
            f"{sha256_bytes(content)}  {output.name}\n".encode("ascii"),
        )
    except ManifestError as error:
        print(f"xctest manifest error: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"xctest manifest error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
