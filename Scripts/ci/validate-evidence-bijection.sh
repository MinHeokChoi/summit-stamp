#!/usr/bin/env bash
# Validate that evidence declarations, their producer registry, and generated outputs agree.
set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: validate-evidence-bijection.sh --profiles <evidence-profiles.yml> --registry <evidence-registry.json> [--outputs <Evidence-directory>]'
}

profiles=''
registry=''
outputs=''
while (($#)); do
  case "$1" in
    --profiles)
      (($# >= 2)) || { usage >&2; exit 64; }
      profiles=$2
      shift 2
      ;;
    --registry)
      (($# >= 2)) || { usage >&2; exit 64; }
      registry=$2
      shift 2
      ;;
    --outputs)
      (($# >= 2)) || { usage >&2; exit 64; }
      outputs=$2
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
done

[[ -n "$profiles" && -n "$registry" ]] || { usage >&2; exit 64; }

python3 - "$profiles" "$registry" "$outputs" <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any


class BijectionError(Exception):
    def __init__(self, classification: str, message: str) -> None:
        super().__init__(message)
        self.classification = classification


def fail(classification: str, message: str) -> None:
    raise BijectionError(classification, message)
def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail("duplicate_id", f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def reject_json_constant(value: str) -> None:
    fail("invalid_schema", f"invalid JSON constant {value!r}")


def load_json_document(path: Path, label: str) -> Any:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        fail("invalid_schema", f"cannot read {label} {path}: {error}")
    try:
        return json.loads(
            source,
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
        )
    except json.JSONDecodeError as error:
        fail("invalid_schema", f"cannot parse {label} {path}: {error}")


def strip_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if character == "#" and quote is None:
            return value[:index].rstrip()
    if quote is not None:
        fail("invalid_schema", "unterminated quoted YAML scalar")
    return value.rstrip()


def parse_scalar(value: str, line_number: int) -> str:
    value = value.strip()
    if not value:
        fail("invalid_schema", f"empty scalar on line {line_number}")
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as error:
            fail("invalid_schema", f"invalid double-quoted scalar on line {line_number}: {error}")
        if not isinstance(decoded, str):
            fail("invalid_schema", f"non-string scalar on line {line_number}")
        return decoded
    if value.startswith("'"):
        if not value.endswith("'") or len(value) == 1:
            fail("invalid_schema", f"invalid single-quoted scalar on line {line_number}")
        return value[1:-1].replace("''", "'")
    if value[0] in "[{":
        fail("invalid_schema", f"YAML collections are not accepted on line {line_number}")
    return value


def normalize_profiles(profiles: dict[str, Any]) -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    for evidence_id, profile in profiles.items():
        if not isinstance(evidence_id, str) or not evidence_id:
            fail("invalid_schema", "profile IDs must be non-empty strings")
        if not isinstance(profile, dict):
            fail("invalid_schema", f"profile {evidence_id!r} must be a mapping")
        normalized_profile: dict[str, str] = {}
        for field, value in profile.items():
            if not isinstance(field, str) or not field:
                fail("invalid_schema", f"profile {evidence_id!r} has an invalid field name")
            if not isinstance(value, str):
                fail("invalid_schema", f"profile {evidence_id!r} field {field!r} is not a string")
            normalized_profile[field] = value
        normalized[evidence_id] = normalized_profile
    return normalized


def parse_json_profiles(source: str) -> dict[str, dict[str, str]]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail("duplicate_id", f"duplicate JSON key {key!r}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        fail("invalid_schema", f"invalid JSON constant {value!r}")

    try:
        document = json.loads(
            source,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        fail("invalid_schema", f"invalid JSON profiles: {error}")
    if not isinstance(document, dict) or set(document) != {"schemaVersion", "profiles"}:
        fail("invalid_schema", "profiles must contain only schemaVersion and profiles")
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1:
        fail("invalid_schema", "profiles schemaVersion must be 1")
    source_profiles = document["profiles"]
    if not isinstance(source_profiles, dict):
        fail("invalid_schema", "profiles must be a mapping")
    if not source_profiles:
        fail("missing_profile", "profiles mapping is missing or empty")
    return normalize_profiles(source_profiles)


def parse_yaml_profiles(lines: list[str]) -> dict[str, dict[str, str]]:
    top_level: dict[str, str | None] = {}
    profiles: dict[str, dict[str, str]] = {}
    current_id: str | None = None
    profiles_seen = False
    key_pattern = re.compile(r"^([^:\s][^:]*?):(?:[ \t]*(.*))?$")
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line.startswith("\t") or "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip(" "))]:
            fail("invalid_schema", f"tabs are not permitted for YAML indentation on line {line_number}")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent not in {0, 2, 4}:
            fail("invalid_schema", f"unsupported YAML indentation on line {line_number}")
        text = strip_comment(raw_line[indent:])
        if not text:
            continue
        match = key_pattern.match(text)
        if match is None:
            fail("invalid_schema", f"unsupported YAML syntax on line {line_number}")
        key = match.group(1).strip()
        raw_value = match.group(2)
        if indent == 0:
            if key in top_level:
                fail("duplicate_id", f"duplicate top-level key {key!r}")
            if key == "profiles":
                if raw_value not in {None, ""}:
                    fail("invalid_schema", "profiles must be a mapping")
                profiles_seen = True
                top_level[key] = None
            else:
                if raw_value is None:
                    fail("invalid_schema", f"top-level mapping {key!r} is not supported")
                top_level[key] = parse_scalar(raw_value, line_number)
            current_id = None
        elif indent == 2:
            if not profiles_seen:
                fail("invalid_schema", f"profile outside profiles mapping on line {line_number}")
            if raw_value not in {None, ""}:
                fail("invalid_schema", f"profile {key!r} must be a mapping")
            if key in profiles:
                fail("duplicate_id", f"duplicate profile ID {key!r}")
            profiles[key] = {}
            current_id = key
        else:
            if current_id is None:
                fail("invalid_schema", f"profile field without an ID on line {line_number}")
            if raw_value is None:
                fail("invalid_schema", f"nested profile mapping is not supported on line {line_number}")
            if key in profiles[current_id]:
                fail("duplicate_id", f"duplicate field {key!r} in profile {current_id!r}")
            profiles[current_id][key] = parse_scalar(raw_value, line_number)

    if set(top_level) != {"schemaVersion", "profiles"}:
        fail("invalid_schema", "profiles must contain only schemaVersion and profiles")
    if top_level.get("schemaVersion") != "1":
        fail("invalid_schema", "profiles schemaVersion must be 1")
    if not profiles_seen or not profiles:
        fail("missing_profile", "profiles mapping is missing or empty")
    return normalize_profiles(profiles)


def parse_profiles(path: Path) -> dict[str, dict[str, str]]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        fail("invalid_schema", f"cannot read profiles file {path}: {error}")
    if source.lstrip().startswith("{"):
        return parse_json_profiles(source)
    return parse_yaml_profiles(source.splitlines())


def load_registry(path: Path) -> tuple[list[str], dict[str, dict[str, str]]]:
    registry = load_json_document(path, "registry")
    if not isinstance(registry, dict) or set(registry) != {
        "schemaVersion",
        "requiredIds",
        "allowedProducers",
    }:
        fail("invalid_schema", "registry must contain only schemaVersion, requiredIds, and allowedProducers")
    if type(registry["schemaVersion"]) is not int or registry["schemaVersion"] != 1:
        fail("invalid_schema", "registry schemaVersion must be 1")
    required_ids = registry["requiredIds"]
    producers = registry["allowedProducers"]
    if not isinstance(required_ids, list) or not required_ids or not all(
        isinstance(value, str) and value for value in required_ids
    ):
        fail("invalid_schema", "registry requiredIds must be a non-empty string list")
    if len(set(required_ids)) != len(required_ids):
        fail("duplicate_id", "registry requiredIds contains duplicates")
    if not isinstance(producers, dict):
        fail("missing_producer_dependency", "registry allowedProducers must be an object")
    if set(producers) != set(required_ids):
        missing = sorted(set(required_ids) - set(producers))
        extra = sorted(set(producers) - set(required_ids))
        fail(
            "missing_producer_dependency",
            f"registry producer mapping does not match required IDs (missing={missing}, extra={extra})",
        )
    normalized: dict[str, dict[str, str]] = {}
    for evidence_id, producer in producers.items():
        if not isinstance(producer, dict):
            fail("missing_producer_dependency", f"producer for {evidence_id} is not an object")
        required_fields = {"runner", "job", "output"}
        if not required_fields.issubset(producer):
            fail("missing_producer_dependency", f"producer for {evidence_id} lacks runner, job, or output")
        if not set(producer).issubset(required_fields | {"scheme"}):
            fail("invalid_schema", f"producer for {evidence_id} has unsupported fields")
        for key, value in producer.items():
            if not isinstance(value, str) or not value:
                fail("missing_producer_dependency", f"producer {key} for {evidence_id} is not a non-empty string")
        normalized[evidence_id] = producer
    return required_ids, normalized


def validate_destination(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(character) < 32 for character in value):
        fail("wrong_destination", f"{label} must be a safe Evidence/*.json destination: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {".", ".."} for part in path.parts)
        or not path.parts
        or path.parts[0] != "Evidence"
        or path.suffix != ".json"
    ):
        fail("wrong_destination", f"{label} must be a safe Evidence/*.json destination: {value!r}")
    return path.as_posix()


def requires_hiker_ui_scheme(profile: dict[str, str]) -> bool:
    return profile.get("runner", "").lower() in {"xctest", "ui-build"}


def validate_declarations(
    profiles: dict[str, dict[str, str]], required_ids: list[str], producers: dict[str, dict[str, str]]
) -> dict[str, str]:
    required_set = set(required_ids)
    for evidence_id in required_ids:
        if evidence_id not in profiles:
            fail("missing_profile", f"required evidence ID has no profile: {evidence_id}")
    extras = sorted(set(profiles) - required_set)
    if extras:
        fail("undeclared_output", f"profiles declare IDs absent from registry: {', '.join(extras)}")

    destinations: dict[str, str] = {}
    destination_ids: dict[str, str] = {}
    for evidence_id in required_ids:
        profile = profiles[evidence_id]
        producer = producers[evidence_id]
        for field in ("runner", "job", "output"):
            value = profile.get(field)
            if not isinstance(value, str) or not value:
                fail("missing_producer_dependency", f"profile {evidence_id} lacks a non-empty {field}")
        for field in ("runner", "job"):
            if profile[field] != producer[field]:
                fail("missing_producer_dependency", f"profile {evidence_id} {field} does not match its registered producer")
        profile_output = validate_destination(profile["output"], f"profile {evidence_id} output")
        registered_output = validate_destination(producer["output"], f"registered output for {evidence_id}")
        if profile_output != registered_output:
            fail("wrong_destination", f"profile {evidence_id} output does not match its registered destination")
        existing_id = destination_ids.get(profile_output)
        if existing_id is not None:
            fail("duplicate_id", f"profiles {existing_id} and {evidence_id} share output {profile_output}")
        destination_ids[profile_output] = evidence_id
        destinations[evidence_id] = profile_output

        profile_scheme = profile.get("scheme")
        producer_scheme = producer.get("scheme")
        if requires_hiker_ui_scheme(profile):
            if profile_scheme != "HikerUITests":
                fail("wrong_scheme", f"profile {evidence_id} must use scheme HikerUITests")
        if producer_scheme is not None and profile_scheme != producer_scheme:
            fail("wrong_scheme", f"profile {evidence_id} scheme does not match its registered producer")
        if profile_scheme is not None and not isinstance(profile_scheme, str):
            fail("wrong_scheme", f"profile {evidence_id} scheme is invalid")
    return destinations


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
FIXTURE_RE = re.compile(
    r"^Docs/evidence/fixtures/(?:bijection-valid\.json|bijection-invalid/[A-Za-z0-9][A-Za-z0-9._-]*\.json)$"
)
NEGATIVE_CLASSES = frozenset(
    {
        "wrong_destination",
        "wrong_scheme",
        "missing_producer_dependency",
        "undeclared_output",
        "duplicate_id",
        "missing_profile",
    }
)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail("invalid_schema", f"{label} has an invalid shape")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        fail("invalid_schema", f"{label} must be a SHA-256 digest")
    return value


def require_repo_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(character) < 32 for character in value):
        fail("invalid_schema", f"{label} must be a safe repository-relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
    ):
        fail("invalid_schema", f"{label} must be a safe repository-relative path")
    return path.as_posix()


def require_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        fail("invalid_schema", f"{label} must be a UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail("invalid_schema", f"{label} must be a valid UTC timestamp")


def require_git_sha(value: Any, label: str) -> None:
    if not isinstance(value, str) or (value != "uncommitted" and GIT_SHA_RE.fullmatch(value) is None):
        fail("invalid_schema", f"{label} must be a commit SHA or uncommitted")


def require_zero_integer(value: Any, label: str) -> None:
    if type(value) is not int or value != 0:
        fail("invalid_schema", f"{label} must be zero")


def require_nonnegative_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        fail("invalid_schema", f"{label} must be a non-negative integer")
    return value

REPO_ROOT = Path.cwd().resolve()


def tree_sha256(path: Path) -> str:
    digest = hashlib.sha256()

    def record(value: str) -> None:
        digest.update(value.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")

    def visit(current: Path, relative: str) -> None:
        metadata = os.lstat(current)
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if stat.S_ISREG(metadata.st_mode):
            record(f"F:{relative}:{mode}")
            with current.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            digest.update(b"\0")
        elif stat.S_ISLNK(metadata.st_mode):
            record(f"L:{relative}:{mode}:{os.readlink(current)}")
        elif stat.S_ISDIR(metadata.st_mode):
            record(f"D:{relative}:{mode}")
            for child in sorted(os.scandir(current), key=lambda item: item.name):
                child_relative = child.name if not relative else f"{relative}/{child.name}"
                visit(Path(child.path), child_relative)
        else:
            fail("invalid_schema", f"unsupported artifact entry: {current}")

    visit(path, "")
    return digest.hexdigest()


def require_current_hash(path_value: str, expected_hash: str, label: str, directory: bool = False) -> None:
    relative = require_repo_relative_path(path_value, f"{label} path")
    candidate = REPO_ROOT.joinpath(*PurePosixPath(relative).parts)
    if candidate.is_symlink() or (not candidate.is_dir() if directory else not candidate.is_file()):
        fail("missing_output", f"{label} is missing: {relative}")
    observed = tree_sha256(candidate) if directory else hash_file(candidate)
    if observed != expected_hash:
        fail("altered_output", f"{label} hash does not match current artifact")


def require_promotion_commit(document: dict[str, Any], label: str) -> None:
    expected = os.environ.get("GITHUB_SHA")
    if expected:
        expected = expected.strip().lower()
        if GIT_SHA_RE.fullmatch(expected) is None or document["gitSHA"] != expected:
            fail("invalid_schema", f"{label} is not bound to GITHUB_SHA")


def output_path(outputs_root: Path, destination: str) -> Path:
    destination_path = PurePosixPath(destination)
    if not destination_path.parts or destination_path.parts[0] != "Evidence":
        fail("wrong_destination", f"invalid evidence destination {destination}")
    return outputs_root.joinpath(*destination_path.parts[1:])


def ensure_no_symlink_components(outputs_root: Path, path: Path, label: str) -> None:
    try:
        relative = path.relative_to(outputs_root)
    except ValueError:
        fail("wrong_destination", f"{label} escapes outputs root: {path}")
    current = outputs_root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            fail("invalid_schema", f"{label} contains a symlink: {path}")


def check_sidecar(path: Path, destination: str, outputs_root: Path) -> None:
    sidecar = path.with_name(path.name + ".sha256")
    ensure_no_symlink_components(outputs_root, sidecar, "checksum sidecar")
    if sidecar.is_symlink() or not sidecar.is_file():
        fail("missing_output", f"missing checksum sidecar for {path}")
    try:
        content = sidecar.read_bytes().decode("ascii")
    except (OSError, UnicodeDecodeError) as error:
        fail("invalid_schema", f"invalid checksum sidecar for {path}: {error}")
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\n]+)\n", content)
    if match is None:
        fail("invalid_schema", f"invalid checksum sidecar for {path}")
    named_path = match.group(2)
    if named_path not in {destination, path.name}:
        fail("invalid_schema", f"checksum sidecar names the wrong output for {path}")
    if match.group(1) != hash_file(path):
        fail("altered_output", f"checksum mismatch for {path}")


def validate_output_reference(document: dict[str, Any], destination: str, label: str) -> None:
    output = require_exact_keys(document["output"], {"path"}, f"{label} output")
    if output["path"] != destination:
        fail("wrong_destination", f"{label} declares the wrong output destination")


def validate_common_command_fields(document: dict[str, Any], label: str) -> None:
    if document["status"] != "passed":
        fail("invalid_schema", f"{label} is not passed")
    require_zero_integer(document["exitCode"], f"{label} exitCode")
    require_git_sha(document["gitSHA"], f"{label} gitSHA")
    command = document["command"]
    if not isinstance(command, list) or not command or any(
        not isinstance(token, str) or not token or any(ord(character) < 32 for character in token)
        for token in command
    ):
        fail("invalid_schema", f"{label} command is invalid")
    timestamps = require_exact_keys(document["timestamps"], {"startedAt", "finishedAt"}, f"{label} timestamps")
    started_at = require_timestamp(timestamps["startedAt"], f"{label} startedAt")
    finished_at = require_timestamp(timestamps["finishedAt"], f"{label} finishedAt")
    if finished_at < started_at:
        fail("invalid_schema", f"{label} timestamps are out of order")
    require_promotion_commit(document, label)


def validate_command_evidence(
    document: dict[str, Any],
    evidence_id: str,
    destination: str,
    profile: dict[str, str],
) -> None:
    runner = profile["runner"]
    keys = {
        "schemaVersion",
        "id",
        "status",
        "runner",
        "command",
        "exitCode",
        "gitSHA",
        "logSHA",
        "timestamps",
        "output",
        "skippedTests",
        "warnings",
    }
    if runner == "xctest":
        keys |= {"manifestSHA", "result"}
    require_exact_keys(document, keys, f"evidence {evidence_id}")
    if document["runner"] != runner:
        fail("invalid_schema", f"evidence {evidence_id} runner does not match its profile")
    validate_common_command_fields(document, f"evidence {evidence_id}")
    require_sha256(document["logSHA"], f"evidence {evidence_id} logSHA")
    require_zero_integer(document["skippedTests"], f"evidence {evidence_id} skippedTests")
    require_zero_integer(document["warnings"], f"evidence {evidence_id} warnings")
    validate_output_reference(document, destination, f"evidence {evidence_id}")
    log_path = f".ci/logs/{evidence_id}.log"
    require_current_hash(log_path, document["logSHA"], f"evidence {evidence_id} log")
    if runner == "xcode":
        expected_command = [
            "xcodebuild",
            "test",
            "-workspace",
            profile["workspace"],
            "-scheme",
            profile["scheme"],
            "-destination",
            profile["destination"],
            f"-only-testing:{profile['filter']}",
            "-resultBundlePath",
            profile["result"],
        ]
        if document["command"] != expected_command:
            fail("invalid_schema", f"evidence {evidence_id} command does not match its profile")
    if runner == "xctest":
        require_sha256(document["manifestSHA"], f"evidence {evidence_id} manifestSHA")
        result = require_exact_keys(document["result"], {"path"}, f"evidence {evidence_id} result")
        expected_result = require_repo_relative_path(profile.get("result"), f"profile {evidence_id} result")
        if result["path"] != expected_result:
            fail("invalid_schema", f"evidence {evidence_id} result does not match its profile")


def require_hashed_artifact(value: Any, expected_path: str, label: str) -> None:
    artifact = require_exact_keys(value, {"path", "sha256"}, label)
    if require_repo_relative_path(artifact["path"], f"{label} path") != expected_path:
        fail("invalid_schema", f"{label} path is invalid")
    require_sha256(artifact["sha256"], f"{label} sha256")


def validate_ui_build_evidence(
    document: dict[str, Any],
    evidence_id: str,
    destination: str,
    profile: dict[str, str],
) -> None:
    require_exact_keys(
        document,
        {
            "schemaVersion",
            "id",
            "status",
            "runner",
            "command",
            "exitCode",
            "gitSHA",
            "log",
            "manifest",
            "result",
            "timestamps",
            "output",
            "warningSummary",
        },
        f"evidence {evidence_id}",
    )
    if document["runner"] != "ui-build":
        fail("invalid_schema", f"evidence {evidence_id} runner does not match its profile")
    validate_common_command_fields(document, f"evidence {evidence_id}")
    require_hashed_artifact(document["log"], f".ci/logs/{evidence_id}.log", f"evidence {evidence_id} log")
    require_hashed_artifact(document["manifest"], ".ci/xctest/manifest.json", f"evidence {evidence_id} manifest")
    expected_result = require_repo_relative_path(profile.get("result"), f"profile {evidence_id} result")
    require_hashed_artifact(document["result"], expected_result, f"evidence {evidence_id} result")
    warning_summary = require_exact_keys(
        document["warningSummary"],
        {"compilerOrTestWarnings", "skippedTests", "nonTestToolWarnings"},
        f"evidence {evidence_id} warningSummary",
    )
    require_zero_integer(
        warning_summary["compilerOrTestWarnings"],
        f"evidence {evidence_id} compilerOrTestWarnings",
    )
    require_zero_integer(warning_summary["skippedTests"], f"evidence {evidence_id} skippedTests")
    non_test_warnings = require_exact_keys(
        warning_summary["nonTestToolWarnings"],
        {"xcodeNoAppIntentsMetadata"},
        f"evidence {evidence_id} nonTestToolWarnings",
    )
    require_nonnegative_integer(
        non_test_warnings["xcodeNoAppIntentsMetadata"],
        f"evidence {evidence_id} xcodeNoAppIntentsMetadata",
    )
    validate_output_reference(document, destination, f"evidence {evidence_id}")
    require_current_hash(
        document["log"]["path"],
        document["log"]["sha256"],
        f"evidence {evidence_id} log",
    )
    require_current_hash(
        document["manifest"]["path"],
        document["manifest"]["sha256"],
        f"evidence {evidence_id} manifest",
    )
    require_current_hash(
        document["result"]["path"],
        document["result"]["sha256"],
        f"evidence {evidence_id} result",
        directory=True,
    )


def validate_bijection_negative_evidence(
    document: dict[str, Any],
    evidence_id: str,
    destination: str,
) -> None:
    require_exact_keys(
        document,
        {
            "schemaVersion",
            "id",
            "status",
            "command",
            "exitCode",
            "gitSHA",
            "startedAt",
            "finishedAt",
            "output",
            "evidenceTreeBefore",
            "evidenceTreeAfterValidation",
            "fixtures",
        },
        f"evidence {evidence_id}",
    )
    if document["status"] != "passed":
        fail("invalid_schema", f"evidence {evidence_id} is not passed")
    if document["command"] != "test-evidence-bijection-negative.sh":
        fail("invalid_schema", f"evidence {evidence_id} command is invalid")
    require_zero_integer(document["exitCode"], f"evidence {evidence_id} exitCode")
    require_git_sha(document["gitSHA"], f"evidence {evidence_id} gitSHA")
    require_promotion_commit(document, f"evidence {evidence_id}")
    started_at = require_timestamp(document["startedAt"], f"evidence {evidence_id} startedAt")
    finished_at = require_timestamp(document["finishedAt"], f"evidence {evidence_id} finishedAt")
    if finished_at < started_at:
        fail("invalid_schema", f"evidence {evidence_id} timestamps are out of order")
    if document["output"] != destination:
        fail("wrong_destination", f"evidence {evidence_id} declares the wrong output destination")
    before = require_sha256(document["evidenceTreeBefore"], f"evidence {evidence_id} evidenceTreeBefore")
    after = require_sha256(
        document["evidenceTreeAfterValidation"],
        f"evidence {evidence_id} evidenceTreeAfterValidation",
    )
    if before != after:
        fail("invalid_schema", f"evidence {evidence_id} mutated the evidence tree")
    fixtures = document["fixtures"]
    if not isinstance(fixtures, list) or len(fixtures) < len(NEGATIVE_CLASSES) + 1:
        fail("invalid_schema", f"evidence {evidence_id} fixtures are incomplete")
    seen_fixtures: set[str] = set()
    invalid_classes: set[str] = set()
    valid_count = 0
    for index, fixture in enumerate(fixtures, start=1):
        fixture = require_exact_keys(
            fixture,
            {"fixture", "kind", "classification", "exitCode", "evidenceTreeBefore", "evidenceTreeAfter"},
            f"evidence {evidence_id} fixture {index}",
        )
        fixture_path = fixture["fixture"]
        if not isinstance(fixture_path, str) or FIXTURE_RE.fullmatch(fixture_path) is None:
            fail("invalid_schema", f"evidence {evidence_id} fixture {index} path is invalid")
        if fixture_path in seen_fixtures:
            fail("duplicate_id", f"evidence {evidence_id} repeats fixture {fixture_path}")
        seen_fixtures.add(fixture_path)
        fixture_before = require_sha256(
            fixture["evidenceTreeBefore"],
            f"evidence {evidence_id} fixture {index} evidenceTreeBefore",
        )
        fixture_after = require_sha256(
            fixture["evidenceTreeAfter"],
            f"evidence {evidence_id} fixture {index} evidenceTreeAfter",
        )
        if fixture_before != before or fixture_after != after:
            fail("invalid_schema", f"evidence {evidence_id} fixture {index} mutated the evidence tree")
        exit_code = fixture["exitCode"]
        if type(exit_code) is not int or exit_code < 0:
            fail("invalid_schema", f"evidence {evidence_id} fixture {index} exitCode is invalid")
        kind = fixture["kind"]
        classification = fixture["classification"]
        if kind == "valid" and classification == "success" and exit_code == 0:
            valid_count += 1
        elif kind == "invalid" and classification in NEGATIVE_CLASSES and exit_code > 0:
            invalid_classes.add(classification)
        else:
            fail("invalid_schema", f"evidence {evidence_id} fixture {index} result is invalid")
    if valid_count != 1 or invalid_classes != NEGATIVE_CLASSES:
        fail("invalid_schema", f"evidence {evidence_id} fixture classifications are incomplete")


def validate_synthetic_fixture(
    document: dict[str, Any],
    evidence_id: str,
    destination: str,
) -> None:
    require_exact_keys(document, {"schemaVersion", "id", "output"}, f"fixture evidence {evidence_id}")
    if document["output"] != destination:
        fail("wrong_destination", f"fixture evidence {evidence_id} declares the wrong output destination")


def validate_output_document(
    document: dict[str, Any],
    evidence_id: str,
    destination: str,
    profile: dict[str, str],
) -> None:
    runner = profile["runner"]
    if destination.startswith("Evidence/fixture-output/"):
        validate_synthetic_fixture(document, evidence_id, destination)
    elif runner == "bijection-negative":
        validate_bijection_negative_evidence(document, evidence_id, destination)
    elif runner == "ui-build":
        validate_ui_build_evidence(document, evidence_id, destination, profile)
    elif runner in {"swift", "xcode", "xctest", "pgtap"}:
        validate_command_evidence(document, evidence_id, destination, profile)
    else:
        fail("invalid_schema", f"profile {evidence_id} has an unsupported runner {runner!r}")


def validate_sidecar_inventory(
    outputs_root: Path,
    expected_paths: dict[str, Path],
) -> None:
    expected_set = set(expected_paths.values())
    for sidecar in sorted(outputs_root.rglob("*.sha256")):
        ensure_no_symlink_components(outputs_root, sidecar, "checksum sidecar")
        if sidecar.is_symlink() or not sidecar.is_file():
            fail("invalid_schema", f"checksum sidecar is not a regular file: {sidecar}")
        if not sidecar.name.endswith(".json.sha256"):
            fail("invalid_schema", f"checksum sidecar has an invalid name: {sidecar}")
        source = sidecar.with_name(sidecar.name[: -len(".sha256")])
        if source.suffix != ".json" or source not in expected_set:
            fail("invalid_schema", f"checksum sidecar has no matching declared output: {sidecar}")


def validate_outputs(
    outputs_value: str,
    destinations: dict[str, str],
    profiles: dict[str, dict[str, str]],
) -> None:
    outputs_root = Path(outputs_value)
    if outputs_root.is_symlink():
        fail("invalid_schema", f"outputs directory is a symlink: {outputs_root}")
    if not outputs_root.is_dir():
        fail("missing_output", f"outputs directory does not exist: {outputs_root}")
    outputs_root = outputs_root.resolve()
    expected_paths = {
        evidence_id: output_path(outputs_root, destination)
        for evidence_id, destination in destinations.items()
    }
    seen_ids: dict[str, Path] = {}
    for candidate in sorted(outputs_root.rglob("*.json")):
        ensure_no_symlink_components(outputs_root, candidate, "evidence output")
        if candidate.is_symlink() or not candidate.is_file():
            fail("invalid_schema", f"evidence output is not a regular file: {candidate}")
        document = load_json_document(candidate, "evidence JSON")
        if (
            not isinstance(document, dict)
            or type(document.get("schemaVersion")) is not int
            or document["schemaVersion"] != 1
        ):
            fail("invalid_schema", f"evidence JSON has invalid schemaVersion: {candidate}")
        evidence_id = document.get("id")
        if not isinstance(evidence_id, str) or not evidence_id:
            fail("invalid_schema", f"evidence JSON lacks a string id: {candidate}")
        if evidence_id not in destinations:
            fail("undeclared_output", f"evidence output has undeclared ID {evidence_id}: {candidate}")
        if evidence_id in seen_ids:
            fail("duplicate_id", f"evidence ID {evidence_id} appears in {seen_ids[evidence_id]} and {candidate}")
        expected = expected_paths[evidence_id]
        if candidate != expected:
            fail("wrong_destination", f"evidence ID {evidence_id} is at {candidate}, not {expected}")
        validate_output_document(document, evidence_id, destinations[evidence_id], profiles[evidence_id])
        check_sidecar(candidate, destinations[evidence_id], outputs_root)
        seen_ids[evidence_id] = candidate
    missing = sorted(set(destinations) - set(seen_ids))
    if missing:
        fail("missing_output", f"missing evidence outputs for IDs: {', '.join(missing)}")
    validate_sidecar_inventory(outputs_root, expected_paths)


def main() -> int:
    profiles = parse_profiles(Path(sys.argv[1]))
    required_ids, producers = load_registry(Path(sys.argv[2]))
    destinations = validate_declarations(profiles, required_ids, producers)
    if sys.argv[3]:
        validate_outputs(sys.argv[3], destinations, profiles)
    return 0


try:
    raise SystemExit(main())
except BijectionError as error:
    print(f"EVIDENCE_BIJECTION_CLASS={error.classification}: {error}", file=sys.stderr)
    raise SystemExit(1)
except (OSError, ValueError) as error:
    print(f"EVIDENCE_BIJECTION_CLASS=invalid_schema: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
