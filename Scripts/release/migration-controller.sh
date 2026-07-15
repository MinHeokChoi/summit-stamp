#!/usr/bin/env bash
# Invoke the single protected release-transition RPC after local fail-closed validation.
set -euo pipefail

exec python3 - "$@" <<'PY'
from __future__ import annotations

import hashlib
import math
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, NoReturn


class ControllerError(Exception):
    pass


def fail() -> NoReturn:
    raise ControllerError


SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
ACTOR_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVIDENCE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
SENSITIVE_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b|"
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    r"(?:authorization|bearer|password|secret|token|cookie|credential)\s*[:=])"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<![0-9])\+[1-9][0-9]{7,14}(?![0-9])")
ROLES = ("Product", "Security", "Ops")

# This is the sole executable the controller may invoke. It is a separately
# deployed, root-owned helper that has one fixed transport target.
RPC_HELPER = "/usr/local/bin/hiker-release-rpc"
STATES: dict[str, dict[str, Any]] = {
    "predeploy-disabled": {
        "sequence": 0,
        "approval": "Evidence/runtime/approvals/predeploy.json",
        "gate": "predeploy",
        "switch": "disabled",
        "output": "Evidence/runtime/REL-002.json",
    },
    "compatibility": {
        "sequence": 1,
        "approval": "Evidence/runtime/approvals/compatibility.json",
        "gate": "compatibility",
        "switch": "disabled",
        "output": "Evidence/runtime/REL-003.json",
    },
    "pitr-proof": {
        "sequence": 2,
        "approval": "Evidence/runtime/approvals/pitr-proof.json",
        "gate": "pitr-proof",
        "switch": "disabled",
        "output": "Evidence/runtime/REL-008.json",
    },
    "activate-1pct": {
        "sequence": 3,
        "approval": "Evidence/runtime/approvals/activate-1pct.json",
        "gate": "activate-1pct",
        "switch": "enabled",
        "output": "Evidence/runtime/REL-010.json",
    },
    "phase-5": {
        "sequence": 4,
        "approval": "Evidence/runtime/approvals/phase-05.json",
        "gate": "phase-05",
        "switch": "enabled",
        "output": "Evidence/runtime/REL-PHASE-05.json",
    },
    "phase-25": {
        "sequence": 5,
        "approval": "Evidence/runtime/approvals/phase-25.json",
        "gate": "phase-25",
        "switch": "enabled",
        "output": "Evidence/runtime/REL-PHASE-25.json",
    },
    "phase-50": {
        "sequence": 6,
        "approval": "Evidence/runtime/approvals/phase-50.json",
        "gate": "phase-50",
        "switch": "enabled",
        "output": "Evidence/runtime/REL-PHASE-50.json",
    },
    "phase-100": {
        "sequence": 7,
        "approval": "Evidence/runtime/approvals/phase-100.json",
        "gate": "phase-100",
        "switch": "enabled",
        "output": "Evidence/runtime/REL-PHASE-100.json",
    },
    "contract-remove-old": {
        "sequence": 8,
        "approval": "Evidence/runtime/approvals/contract.json",
        "gate": "contract",
        "switch": "enabled",
        "output": "Evidence/runtime/REL-CONTRACT.json",
    },
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(value: bytes | Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical_bytes(value)).hexdigest()

def genesis_sentinel(values: dict[str, str]) -> str:
    # Keep this byte-for-byte aligned with
    # m6_private.release_transition_sentinel_sha. SQL controls both field order
    # and the schema-version string; this is deliberately not generic JSON
    # canonicalization.
    payload = (
        '{"commit":'
        + json.dumps(values["commit"], ensure_ascii=True, separators=(",", ":"))
        + ',"datasetSHA":'
        + json.dumps(values["data_sha"], ensure_ascii=True, separators=(",", ":"))
        + ',"migrationSHA":'
        + json.dumps(values["migration_sha"], ensure_ascii=True, separators=(",", ":"))
        + ',"releaseID":'
        + json.dumps(values["release_id"], ensure_ascii=True, separators=(",", ":"))
        + ',"schemaVersion":"m6-release-transition-v1","tag":'
        + json.dumps(values["tag"], ensure_ascii=True, separators=(",", ":"))
        + "}"
    )
    return sha256(payload.encode("utf-8"))


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            fail()
        document[key] = value
    return document


def reject_constant(_value: str) -> None:
    fail()


def reject_nonfinite(value: Any) -> None:
    if type(value) is float:
        if not math.isfinite(value):
            fail()
    elif isinstance(value, list):
        for item in value:
            reject_nonfinite(item)
    elif isinstance(value, dict):
        for item in value.values():
            reject_nonfinite(item)


def parse_json(raw: bytes) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()
    reject_nonfinite(value)
    return value


def parse_arguments(arguments: list[str]) -> dict[str, str]:
    core_options = {
        "--release-id": "release_id",
        "--state": "state",
        "--tag": "tag",
        "--commit": "commit",
        "--switch-state": "switch_state",
        "--expected-sequence": "expected_sequence",
        "--expected-event-sha": "expected_event_sha",
        "--approval": "approval",
        "--approval-sha": "approval_sha",
        "--observed-input-manifest": "observed_input_manifest",
        "--observed-input-sha": "observed_input_sha",
        "--data-sha": "data_sha",
        "--migration-sha": "migration_sha",
        "--actor": "actor",
        "--output": "output",
    }
    m7_options = {
        "--rc-manifest": "rc_manifest",
        "--rc-manifest-sha": "rc_manifest_sha",
        "--m6-exit": "m6_exit",
        "--m6-exit-sha": "m6_exit_sha",
    }
    phase_options = {
        "--phase-floor": "phase_floor",
        "--phase-floor-sha": "phase_floor_sha",
    }
    options = core_options | m7_options | phase_options
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option not in options or index + 1 >= len(arguments):
            fail()
        value = arguments[index + 1]
        name = options[option]
        if name in values or not value or value.startswith("--"):
            fail()
        values[name] = value
        index += 2
    if not set(core_options.values()).issubset(values):
        fail()
    state = values["state"]
    expected = set(core_options.values())
    if state in {"activate-1pct", "phase-5", "phase-25", "phase-50", "phase-100", "contract-remove-old"}:
        expected |= set(m7_options.values())
    if state in {"phase-5", "phase-25", "phase-50", "phase-100"}:
        expected |= set(phase_options.values())
    if set(values) != expected:
        fail()
    return values


def reject_sensitive_text(value: str) -> None:
    if (
        not value
        or len(value) > 4096
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
        or SENSITIVE_RE.search(value) is not None
        or EMAIL_RE.search(value) is not None
        or PHONE_RE.search(value) is not None
    ):
        fail()


def reject_sensitive_data(value: Any) -> None:
    if isinstance(value, str):
        reject_sensitive_text(value)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive_data(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_sensitive_text(key)
            reject_sensitive_data(item)
    elif value is None or type(value) in {bool, int, float}:
        return
    else:
        fail()


def relative_parts(value: str) -> tuple[str, ...]:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
    ):
        fail()
    return path.parts


def repository_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], check=False, capture_output=True, stdin=subprocess.DEVNULL
    )
    try:
        root = Path(result.stdout.decode("utf-8", "strict").strip()).resolve(strict=True)
    except (OSError, UnicodeError):
        fail()
    if result.returncode != 0 or not root.is_dir():
        fail()
    return root


def git_output(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], check=False, capture_output=True, stdin=subprocess.DEVNULL
    )
    try:
        output = result.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        fail()
    if result.returncode != 0:
        fail()
    return output


def require_protected_context(root: Path, values: dict[str, str]) -> str:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_WORKFLOW") != "Release Evidence"
        or os.environ.get("RELEASE_PROTECTED_ENVIRONMENT") != "production"
        or os.environ.get("RELEASE_PROTECTED_INPUTS_CONFIRMED") != "approved"
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
        or os.environ.get("GITHUB_REF_NAME") != values["tag"]
        or os.environ.get("GITHUB_SHA") != values["commit"]
        or os.environ.get("GITHUB_ACTOR") != values["actor"]
    ):
        fail()
    build_digest = os.environ.get("HIKER_RELEASE_BUILD_DIGEST")
    if SHA256_RE.fullmatch(build_digest or "") is None:
        fail()
    repository = os.environ.get("GITHUB_REPOSITORY")
    if repository is None or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        fail()
    if git_output(root, "rev-parse", "--verify", "HEAD") != values["commit"]:
        fail()
    if git_output(root, "rev-parse", "--verify", f"{values['tag']}^{{commit}}") != values["commit"]:
        fail()
    return build_digest


def read_regular(root: Path, relative: str, limit: int = 1024 * 1024) -> bytes:
    parts = relative_parts(relative)
    directory = -1
    descriptor = -1
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        for part in parts[:-1]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > limit:
            fail()
        result = bytearray()
        while len(result) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) == 0 or len(result) > limit:
            fail()
        return bytes(result)
    except OSError:
        fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)


def canonical_document(root: Path, relative: str) -> tuple[dict[str, Any], bytes, str]:
    raw = read_regular(root, relative)
    document = parse_json(raw)
    if not isinstance(document, dict):
        fail()
    canonical = canonical_bytes(document) + b"\n"
    if raw != canonical:
        fail()
    reject_sensitive_data(document)
    return document, canonical, sha256(canonical)


def require_sha(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail()
    return value


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        fail()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail()

def require_fresh_timestamp(value: Any, now: datetime) -> datetime:
    timestamp = parse_timestamp(value)
    if timestamp < now - timedelta(hours=24) or timestamp > now + timedelta(minutes=5):
        fail()
    return timestamp


def verify_sidecar(root: Path, path: str, digest: str) -> None:
    expected = f"{digest}  {path}\n".encode("ascii")
    if read_regular(root, f"{path}.sha256", 256) != expected:
        fail()


def validate_membership_attestations(value: Any, role: str) -> None:
    if not isinstance(value, list) or len(value) != len(ROLES):
        fail()
    roles: set[str] = set()
    active: list[str] = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"role", "teamSlug", "state", "responseSHA256"}:
            fail()
        current_role = entry.get("role")
        if current_role not in ROLES or current_role in roles or not isinstance(entry.get("teamSlug"), str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", entry["teamSlug"]) is None:
            fail()
        if entry.get("state") not in {"active", "inactive"}:
            fail()
        require_sha(entry.get("responseSHA256"))
        roles.add(current_role)
        if entry["state"] == "active":
            active.append(current_role)
    if roles != set(ROLES) or active != [role]:
        fail()


def is_m7_state(values: dict[str, str]) -> bool:
    return values["state"] in {
        "activate-1pct",
        "phase-5",
        "phase-25",
        "phase-50",
        "phase-100",
        "contract-remove-old",
    }


def phase_floor_id(state: str) -> str:
    identifiers = {
        "phase-5": "REL-011-05",
        "phase-25": "REL-011-25",
        "phase-50": "REL-011-50",
        "phase-100": "REL-011-100",
    }
    try:
        return identifiers[state]
    except KeyError:
        fail()


def validate_approval(
    document: dict[str, Any],
    values: dict[str, str],
    state: dict[str, Any],
    observed_sha: str,
    build_digest: str,
    rc_digest: str | None,
    m6_exit_digest: str | None,
    phase_floor_digest: str | None,
) -> None:
    expected_fields = {
        "schemaVersion",
        "artifactType",
        "gate",
        "issueURL",
        "releaseTag",
        "commitSHA",
        "buildDigest",
        "observedInputSHA256",
        "transition",
        "predecessorEventSHA256",
        "githubRunId",
        "createdAt",
        "issueSnapshotSHA256",
        "teamSnapshotSHA256",
        "teamSnapshots",
        "approvals",
    }
    if is_m7_state(values):
        expected_fields |= {"rcManifestSHA256", "m6ExitSHA256"}
    if values["state"] in {"phase-5", "phase-25", "phase-50", "phase-100"}:
        expected_fields.add("phaseFloorSHA256")
    if set(document) != expected_fields:
        fail()
    if (
        document.get("schemaVersion") != 1
        or document.get("artifactType") != "release-role-approvals"
        or document.get("gate") != state["gate"]
        or document.get("releaseTag") != values["tag"]
        or document.get("commitSHA") != values["commit"]
        or document.get("buildDigest") != build_digest
        or document.get("observedInputSHA256") != observed_sha
        or document.get("transition") != values["state"]
        or document.get("predecessorEventSHA256") != values["expected_event_sha"]
        or not isinstance(document.get("issueURL"), str)
        or re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*", document["issueURL"]) is None
        or not isinstance(document.get("githubRunId"), str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", document["githubRunId"]) is None
        or document["githubRunId"] != os.environ.get("GITHUB_RUN_ID")
    ):
        fail()
    for field in (
        "buildDigest",
        "observedInputSHA256",
        "predecessorEventSHA256",
        "issueSnapshotSHA256",
        "teamSnapshotSHA256",
    ):
        require_sha(document.get(field))
    if is_m7_state(values):
        if (
            rc_digest is None
            or m6_exit_digest is None
            or document.get("rcManifestSHA256") != rc_digest
            or document.get("m6ExitSHA256") != m6_exit_digest
        ):
            fail()
        require_sha(document.get("rcManifestSHA256"))
        require_sha(document.get("m6ExitSHA256"))
    if values["state"] in {"phase-5", "phase-25", "phase-50", "phase-100"}:
        if phase_floor_digest is None or document.get("phaseFloorSHA256") != phase_floor_digest:
            fail()
        require_sha(document.get("phaseFloorSHA256"))
    now = datetime.now(timezone.utc)
    document_created_at = require_fresh_timestamp(document.get("createdAt"), now)
    teams = document.get("teamSnapshots")
    if not isinstance(teams, list) or len(teams) != len(ROLES):
        fail()
    team_roles: set[str] = set()
    for team in teams:
        if not isinstance(team, dict) or set(team) != {"role", "teamSlug", "responseSHA256"}:
            fail()
        if team.get("role") not in ROLES or team["role"] in team_roles or not isinstance(team.get("teamSlug"), str):
            fail()
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", team["teamSlug"]) is None:
            fail()
        require_sha(team.get("responseSHA256"))
        team_roles.add(team["role"])
    if team_roles != set(ROLES):
        fail()
    approvals = document.get("approvals")
    if not isinstance(approvals, list) or len(approvals) != len(ROLES):
        fail()
    roles: set[str] = set()
    logins: set[str] = set()
    comment_ids: set[int] = set()
    approval_digests: set[str] = set()
    comment_digests: set[str] = set()
    for approval in approvals:
        expected = {"role", "status", "commentId", "login", "createdAt", "approvedAt", "approvalDigest", "commentSHA256", "membershipAttestations"}
        if not isinstance(approval, dict) or set(approval) != expected:
            fail()
        role = approval.get("role")
        login = approval.get("login")
        comment_id = approval.get("commentId")
        if (
            role not in ROLES
            or role in roles
            or approval.get("status") != "active"
            or not isinstance(login, str)
            or ACTOR_RE.fullmatch(login) is None
            or login.lower() in logins
            or type(comment_id) is not int
            or comment_id <= 0
            or comment_id in comment_ids
        ):
            fail()
        comment_created_at = require_fresh_timestamp(approval.get("createdAt"), now)
        approved_at = require_fresh_timestamp(approval.get("approvedAt"), now)
        if approved_at < comment_created_at or document_created_at < approved_at:
            fail()
        approval_digest = require_sha(approval.get("approvalDigest"))
        comment_digest = require_sha(approval.get("commentSHA256"))
        if approval_digest in approval_digests or comment_digest in comment_digests:
            fail()
        validate_membership_attestations(approval.get("membershipAttestations"), role)
        roles.add(role)
        logins.add(login.lower())
        comment_ids.add(comment_id)
        approval_digests.add(approval_digest)
        comment_digests.add(comment_digest)
    if roles != set(ROLES):
        fail()


def validate_observed_manifest(
    document: dict[str, Any],
    values: dict[str, str],
    build_digest: str,
    m6_exit_digest: str | None,
) -> None:
    expected_fields = {
        "schemaVersion",
        "artifactType",
        "releaseID",
        "state",
        "tag",
        "commit",
        "buildDigest",
        "dataSHA256",
        "migrationSHA256",
        "expectedSequence",
        "expectedEventSHA256",
        "observedAt",
        "evidence",
        "repository",
        "inputSHA256",
        "workflowRunId",
        "job",
        "sourceDocumentSHA256",
        "sourceSignatureSHA256",
        "sourcePublicKeySHA256",
        "sourceInputSHA256",
        "sourceObservedAt",
        "sourceObservation",
    }
    if set(document) != expected_fields:
        fail()
    if (
        document.get("schemaVersion") != 1
        or document.get("artifactType") != "release-transition-observed-input"
        or document.get("releaseID") != values["release_id"]
        or document.get("state") != values["state"]
        or document.get("tag") != values["tag"]
        or document.get("commit") != values["commit"]
        or document.get("buildDigest") != build_digest
        or document.get("dataSHA256") != values["data_sha"]
        or document.get("migrationSHA256") != values["migration_sha"]
        or document.get("expectedSequence") != int(values["expected_sequence"])
        or document.get("expectedEventSHA256") != values["expected_event_sha"]
        or document.get("repository") != os.environ.get("GITHUB_REPOSITORY")
        or document.get("inputSHA256") != require_sha(os.environ.get("HIKER_RELEASE_INPUT_SHA256"))
        or document.get("workflowRunId") != os.environ.get("GITHUB_RUN_ID")
        or document.get("job") != os.environ.get("GITHUB_JOB")
    ):
        fail()
    require_sha(document.get("buildDigest"))
    for field in (
        "buildDigest",
        "sourceDocumentSHA256",
        "sourceSignatureSHA256",
        "sourcePublicKeySHA256",
        "sourceInputSHA256",
    ):
        require_sha(document.get(field))
    parse_timestamp(document.get("sourceObservedAt"))
    if not isinstance(document.get("sourceObservation"), dict) or not document["sourceObservation"]:
        fail()
    parse_timestamp(document.get("observedAt"))
    evidence = document.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        fail()
    ids: set[str] = set()
    m6_entries: list[dict[str, Any]] = []
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"id", "sha256"} or not isinstance(item.get("id"), str):
            fail()
        if EVIDENCE_ID_RE.fullmatch(item["id"]) is None or item["id"] in ids:
            fail()
        require_sha(item.get("sha256"))
        ids.add(item["id"])
        if item["id"] == "M6-EXIT":
            m6_entries.append(item)
    if m6_exit_digest is None:
        if m6_entries:
            fail()
    elif len(m6_entries) != 1 or m6_entries[0]["sha256"] != m6_exit_digest:
        fail()


def validate_rc_manifest(document: dict[str, Any], values: dict[str, str]) -> None:
    expected_fields = {
        "schemaVersion",
        "artifactType",
        "id",
        "tag",
        "commit",
        "buildDigest",
        "previousManifestSHA256",
        "inputs",
        "thresholdApproval",
    }
    if (
        set(document) != expected_fields
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "release-candidate-manifest"
        or document.get("id") != "REL-007"
        or document.get("tag") != values["tag"]
        or document.get("commit") != values["commit"]
        or document.get("buildDigest") != require_sha(os.environ.get("HIKER_RELEASE_BUILD_DIGEST"))
    ):
        fail()
    require_sha(document.get("previousManifestSHA256"))
    inputs = document.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        fail()
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"id", "path", "sha256"} or not isinstance(item.get("id"), str) or not isinstance(item.get("path"), str):
            fail()
        if EVIDENCE_ID_RE.fullmatch(item["id"]) is None:
            fail()
        relative_parts(item["path"])
        require_sha(item.get("sha256"))
    threshold_approval = document.get("thresholdApproval")
    if not isinstance(threshold_approval, dict) or set(threshold_approval) != {"path", "sha256"}:
        fail()
    if threshold_approval.get("path") != "Evidence/runtime/approvals/threshold.json":
        fail()
    require_sha(threshold_approval.get("sha256"))


def validate_m6_exit(document: dict[str, Any], values: dict[str, str], rc_digest: str) -> None:
    expected_fields = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "tag",
        "commit",
        "buildDigest",
        "previousManifestSHA256",
        "inputs",
        "approval",
        "output",
    }
    if (
        set(document) != expected_fields
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "m6-exit-admission"
        or document.get("id") != "M6-EXIT"
        or document.get("status") != "passed"
        or document.get("tag") != values["tag"]
        or document.get("commit") != values["commit"]
        or document.get("buildDigest") != require_sha(os.environ.get("HIKER_RELEASE_BUILD_DIGEST"))
        or document.get("previousManifestSHA256") != rc_digest
    ):
        fail()
    require_sha(document.get("previousManifestSHA256"))
    inputs = document.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        fail()
    rc_inputs: list[dict[str, Any]] = []
    input_ids: set[str] = set()
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"id", "path", "sha256"} or not isinstance(item.get("id"), str) or not isinstance(item.get("path"), str):
            fail()
        if EVIDENCE_ID_RE.fullmatch(item["id"]) is None or item["id"] in input_ids:
            fail()
        relative_parts(item["path"])
        require_sha(item.get("sha256"))
        input_ids.add(item["id"])
        if item["id"] == "REL-007":
            rc_inputs.append(item)
    if len(rc_inputs) != 1 or rc_inputs[0]["path"] != "Evidence/manifests/rc.json" or rc_inputs[0]["sha256"] != rc_digest:
        fail()
    approval = document.get("approval")
    output = document.get("output")
    if (
        not isinstance(approval, dict)
        or set(approval) != {"path", "sha256"}
        or approval.get("path") != "Evidence/runtime/approvals/m6-exit.json"
        or not isinstance(output, dict)
        or set(output) != {"path"}
        or output.get("path") != "Evidence/runtime/M6-EXIT.json"
    ):
        fail()
    require_sha(approval.get("sha256"))


def validate_phase_floor(
    document: dict[str, Any],
    values: dict[str, str],
    observed_sha: str,
) -> None:
    expected_fields = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "tag",
        "commit",
        "sourceManifestSHA256",
        "thresholdSHA256",
        "schemaSHA256",
        "windowStartedAt",
        "windowEndedAt",
        "windowHours",
        "validatedAt",
    }
    if (
        set(document) != expected_fields
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "runtime-floor-validation"
        or document.get("id") != phase_floor_id(values["state"])
        or document.get("status") != "passed"
        or document.get("tag") != values["tag"]
        or document.get("commit") != values["commit"]
        or document.get("sourceManifestSHA256") != observed_sha
    ):
        fail()
    for field in ("sourceManifestSHA256", "thresholdSHA256", "schemaSHA256"):
        require_sha(document.get(field))
    started_at = parse_timestamp(document.get("windowStartedAt"))
    ended_at = parse_timestamp(document.get("windowEndedAt"))
    validated_at = parse_timestamp(document.get("validatedAt"))
    window_hours = document.get("windowHours")
    elapsed_hours = (ended_at - started_at).total_seconds() / 3600
    if (
        type(window_hours) not in {int, float}
        or not math.isfinite(float(window_hours))
        or ended_at <= started_at
        or validated_at < ended_at
        or elapsed_hours < 24
        or not math.isclose(float(window_hours), elapsed_hours, rel_tol=0, abs_tol=1e-9)
    ):
        fail()


def rpc_command() -> str:
    if os.environ.get("MIGRATION_APPROVED_RPC_COMMAND") is not None:
        fail()
    try:
        metadata = os.stat(RPC_HELPER, follow_symlinks=False)
    except OSError:
        fail()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not os.access(RPC_HELPER, os.X_OK)
    ):
        fail()
    return RPC_HELPER


def operation_key(values: dict[str, str], build_digest: str) -> str:
    # This is intentionally derived from every accepted controller argument and
    # the protected build context. The fixed helper receives the resulting
    # opaque key with the exact transition arguments for append/read-back.
    return sha256(
        {
            "schemaVersion": 1,
            "buildDigest": build_digest,
            "transition": values,
        }
    )


def rpc_invocation(command: str, operation: str, key: str, values: dict[str, str]) -> list[str]:
    if operation not in {"append", "read-back"} or SHA256_RE.fullmatch(key) is None:
        fail()
    return [
        command,
        "--operation", operation,
        "--operation-key", key,
        "--release-id", values["release_id"],
        "--state", values["state"],
        "--tag", values["tag"],
        "--commit", values["commit"],
        "--switch-state", values["switch_state"],
        "--expected-sequence", values["expected_sequence"],
        "--expected-event-sha", values["expected_event_sha"],
        "--approval-sha", values["approval_sha"],
        "--observed-input-sha", values["observed_input_sha"],
        "--data-sha", values["data_sha"],
        "--migration-sha", values["migration_sha"],
        "--actor", values["actor"],
    ]


def run_rpc(command: str, operation: str, key: str, values: dict[str, str]) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(
            rpc_invocation(command, operation, key, values),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def receipt_from_result(
    result: subprocess.CompletedProcess[bytes],
    values: dict[str, str],
    key: str,
) -> tuple[dict[str, Any], str]:
    if len(result.stdout) == 0 or len(result.stdout) > 65536 or len(result.stderr) > 65536:
        fail()
    receipt = parse_json(result.stdout)
    if not isinstance(receipt, dict) or result.stdout != canonical_bytes(receipt) + b"\n":
        fail()
    reject_sensitive_data(receipt)
    expected_fields = {
        "schemaVersion", "artifactType", "operationKey", "releaseID", "state", "tag", "commit", "sequence", "previousEventSHA256",
        "eventSHA256", "auditEventId", "createdAt",
    }
    if set(receipt) != expected_fields or (
        receipt.get("schemaVersion") != 1
        or receipt.get("artifactType") != "release-transition-rpc-receipt"
        or receipt.get("operationKey") != key
        or receipt.get("releaseID") != values["release_id"]
        or receipt.get("state") != values["state"]
        or receipt.get("tag") != values["tag"]
        or receipt.get("commit") != values["commit"]
        or receipt.get("sequence") != int(values["expected_sequence"]) + 1
        or receipt.get("previousEventSHA256") != values["expected_event_sha"]
        or not isinstance(receipt.get("auditEventId"), str)
        or AUDIT_ID_RE.fullmatch(receipt["auditEventId"]) is None
    ):
        fail()
    require_sha(receipt.get("eventSHA256"))
    parse_timestamp(receipt.get("createdAt"))
    return receipt, sha256(result.stdout)


def reconcile_rpc(command: str, values: dict[str, str], key: str) -> tuple[dict[str, Any], str] | None:
    result = run_rpc(command, "read-back", key, values)
    if result is None or len(result.stdout) > 65536 or len(result.stderr) > 65536:
        fail()
    if result.returncode == 3:
        if result.stdout:
            fail()
        return None
    if result.returncode != 0:
        fail()
    return receipt_from_result(result, values, key)


def append_or_reconcile_rpc(
    command: str,
    values: dict[str, str],
    key: str,
    root: Path,
) -> tuple[dict[str, Any], str]:
    result = run_rpc(command, "append", key, values)
    if result is not None and result.returncode == 0:
        try:
            return receipt_from_result(result, values, key)
        except ControllerError:
            pass
    receipt = reconcile_rpc(command, values, key)
    if receipt is None:
        if result is not None and result.returncode != 0:
            remove_publication_intent(root, values["output"], key)
        fail()
    return receipt


def open_existing_directory(root: Path, parts: tuple[str, ...]) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError:
        fail()
    try:
        for part in parts:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        os.close(descriptor)
        fail()




def read_component(directory: int, name: str) -> bytes | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        return None
    except OSError:
        fail()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > 131072:
            fail()
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                fail()
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def preflight_pair(root: Path, output: str, key: str) -> None:
    parts = relative_parts(output)
    directory = open_existing_directory(root, parts[:-1])
    temporary = f".{parts[-1]}.{secrets.token_hex(16)}.probe"
    marker_name = f"{parts[-1]}.publication-intent"
    marker = canonical_bytes(
        {
            "schemaVersion": 1,
            "artifactType": "release-transition-publication-intent",
            "operationKey": key,
            "output": output,
        }
    ) + b"\n"
    descriptor = -1
    created = False
    marker_temporary: str | None = None
    try:
        existing_marker = read_component(directory, marker_name)
        existing_output = read_component(directory, parts[-1])
        existing_sidecar = read_component(directory, f"{parts[-1]}.sha256")
        if existing_marker is None:
            if existing_output is not None or existing_sidecar is not None:
                fail()
            marker_temporary = write_file_once(directory, marker_name, marker)
            os.fsync(directory)
        elif existing_marker != marker or (existing_output is not None and existing_sidecar is not None):
            fail()
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        created = True
        if os.write(descriptor, b"\0" * 65536) != 65536:
            fail()
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.unlink(temporary, dir_fd=directory)
        created = False
        os.fsync(directory)
    except OSError:
        fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            unlink_name(directory, temporary)
        if marker_temporary is not None:
            unlink_name(directory, marker_temporary)
        os.close(directory)




def unlink_name(directory: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory)
    except OSError:
        pass


def write_file_once(directory: int, name: str, data: bytes) -> str:
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            descriptor = -1
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        return temporary
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        fail()



def remove_publication_intent(root: Path, output: str, key: str) -> None:
    parts = relative_parts(output)
    directory = open_existing_directory(root, parts[:-1])
    marker_name = f"{parts[-1]}.publication-intent"
    expected = canonical_bytes(
        {
            "schemaVersion": 1,
            "artifactType": "release-transition-publication-intent",
            "operationKey": key,
            "output": output,
        }
    ) + b"\n"
    try:
        if read_component(directory, marker_name) != expected:
            fail()
        os.unlink(marker_name, dir_fd=directory)
        os.fsync(directory)
    except OSError:
        fail()
    finally:
        os.close(directory)

def write_pair(root: Path, output: str, record: dict[str, Any]) -> None:
    parts = relative_parts(output)
    directory = open_existing_directory(root, parts[:-1])
    evidence = canonical_bytes(record) + b"\n"
    sidecar = f"{sha256(evidence)}  {output}\n".encode("ascii")
    names = (parts[-1], f"{parts[-1]}.sha256")
    temporary: list[str] = []
    try:
        for name, data in zip(names, (evidence, sidecar)):
            existing = read_component(directory, name)
            if existing is None:
                temporary.append(write_file_once(directory, name, data))
            elif existing != data:
                fail()
        os.fsync(directory)
    except (ControllerError, OSError):
        fail()
    finally:
        for name in temporary:
            unlink_name(directory, name)
        os.close(directory)


def run() -> None:
    values = parse_arguments(sys.argv[1:])
    for value in values.values():
        reject_sensitive_text(value)
    if (
        RELEASE_ID_RE.fullmatch(values["release_id"]) is None
        or values["state"] not in STATES
        or TAG_RE.fullmatch(values["tag"]) is None
        or COMMIT_RE.fullmatch(values["commit"]) is None
        or values["switch_state"] not in {"enabled", "disabled"}
        or re.fullmatch(r"(?:0|[1-9][0-9]{0,8})", values["expected_sequence"]) is None
        or SHA256_RE.fullmatch(values["expected_event_sha"]) is None
        or SHA256_RE.fullmatch(values["approval_sha"]) is None
        or SHA256_RE.fullmatch(values["observed_input_sha"]) is None
        or SHA256_RE.fullmatch(values["data_sha"]) is None
        or SHA256_RE.fullmatch(values["migration_sha"]) is None
        or ACTOR_RE.fullmatch(values["actor"]) is None
    ):
        fail()
    if is_m7_state(values) and (
        SHA256_RE.fullmatch(values["rc_manifest_sha"]) is None
        or SHA256_RE.fullmatch(values["m6_exit_sha"]) is None
    ):
        fail()
    if values["state"] in {"phase-5", "phase-25", "phase-50", "phase-100"} and SHA256_RE.fullmatch(values["phase_floor_sha"]) is None:
        fail()
    state = STATES[values["state"]]
    if (
        int(values["expected_sequence"]) != state["sequence"]
        or values["switch_state"] != state["switch"]
        or values["approval"] != state["approval"]
        or values["output"] != state["output"]
    ):
        fail()
    relative_parts(values["approval"])
    relative_parts(values["observed_input_manifest"])
    relative_parts(values["output"])
    if not values["observed_input_manifest"].startswith("Evidence/manifests/") or not values["observed_input_manifest"].endswith(".json"):
        fail()
    if is_m7_state(values):
        relative_parts(values["rc_manifest"])
        relative_parts(values["m6_exit"])
        if (
            values["rc_manifest"] != "Evidence/manifests/rc.json"
            or values["m6_exit"] != "Evidence/runtime/M6-EXIT.json"
        ):
            fail()
    if values["state"] in {"phase-5", "phase-25", "phase-50", "phase-100"}:
        relative_parts(values["phase_floor"])
        if values["phase_floor"] != f"Evidence/runtime/{phase_floor_id(values['state'])}.json":
            fail()
    root = repository_root()
    build_digest = require_protected_context(root, values)
    sentinel = genesis_sentinel(values)
    if (
        values["state"] == "predeploy-disabled" and values["expected_event_sha"] != sentinel
    ) or (
        values["state"] != "predeploy-disabled" and values["expected_event_sha"] == sentinel
    ):
        fail()
    approval, _approval_raw, approval_digest = canonical_document(root, values["approval"])
    observed, _observed_raw, observed_digest = canonical_document(root, values["observed_input_manifest"])
    if approval_digest != values["approval_sha"] or observed_digest != values["observed_input_sha"]:
        fail()
    verify_sidecar(root, values["approval"], approval_digest)
    verify_sidecar(root, values["observed_input_manifest"], observed_digest)
    rc_digest: str | None = None
    m6_exit_digest: str | None = None
    phase_floor_digest: str | None = None
    if is_m7_state(values):
        rc_manifest, _rc_raw, rc_digest = canonical_document(root, values["rc_manifest"])
        m6_exit, _m6_raw, m6_exit_digest = canonical_document(root, values["m6_exit"])
        if rc_digest != values["rc_manifest_sha"] or m6_exit_digest != values["m6_exit_sha"]:
            fail()
        verify_sidecar(root, values["rc_manifest"], rc_digest)
        verify_sidecar(root, values["m6_exit"], m6_exit_digest)
        validate_rc_manifest(rc_manifest, values)
        validate_m6_exit(m6_exit, values, rc_digest)
    if values["state"] in {"phase-5", "phase-25", "phase-50", "phase-100"}:
        phase_floor, _phase_floor_raw, phase_floor_digest = canonical_document(root, values["phase_floor"])
        if phase_floor_digest != values["phase_floor_sha"]:
            fail()
        verify_sidecar(root, values["phase_floor"], phase_floor_digest)
        validate_phase_floor(phase_floor, values, observed_digest)
    validate_observed_manifest(observed, values, build_digest, m6_exit_digest)
    validate_approval(
        approval,
        values,
        state,
        observed_digest,
        build_digest,
        rc_digest,
        m6_exit_digest,
        phase_floor_digest,
    )
    command = rpc_command()
    key = operation_key(values, build_digest)
    preflight_pair(root, values["output"], key)
    receipt = reconcile_rpc(command, values, key)
    if receipt is None:
        receipt = append_or_reconcile_rpc(command, values, key, root)
    receipt, receipt_digest = receipt
    record = {
        "schemaVersion": 1,
        "artifactType": "release-transition-controller",
        "releaseID": values["release_id"],
        "state": values["state"],
        "tag": values["tag"],
        "commit": values["commit"],
        "buildDigest": build_digest,
        "switchState": values["switch_state"],
        "expectedSequence": int(values["expected_sequence"]),
        "expectedEventSHA256": values["expected_event_sha"],
        "approvalSHA256": values["approval_sha"],
        "observedInputSHA256": values["observed_input_sha"],
        "dataSHA256": values["data_sha"],
        "migrationSHA256": values["migration_sha"],
        "actorSHA256": sha256(values["actor"].encode("ascii")),
        "eventSHA256": receipt["eventSHA256"],
        "auditEventId": receipt["auditEventId"],
        "rpcReceiptSHA256": receipt_digest,
        "createdAt": receipt["createdAt"],
    }
    if rc_digest is not None and m6_exit_digest is not None:
        record["rcManifestSHA256"] = rc_digest
        record["m6ExitSHA256"] = m6_exit_digest
    if phase_floor_digest is not None:
        record["phaseFloorSHA256"] = phase_floor_digest
    write_pair(root, values["output"], record)


def main() -> int:
    try:
        run()
        return 0
    except ControllerError:
        print("migration controller error: protected release transition was not invoked", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
PY
