#!/usr/bin/env python3
"""Fail-closed writers and validator for the immutable M6/M7 release lineage.

The shell entrypoints in this directory only select a subcommand.  Keeping the
JSON parsing, checksum validation, safe repository paths, and create-once
publication here prevents the release gates from drifting apart.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, NoReturn


class ReleaseError(Exception):
    """An invalid or incomplete release evidence set."""


SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ISSUE_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_APPROVAL_AGE = timedelta(hours=24)
ROLES = ("Product", "Security", "Ops")

READINESS_TEST_IDS = (
    "ARCH-001",
    "DATA-001",
    "UI-BUILD-PRODUCER",
    "EVIDENCE-BIJECTION-NEGATIVE",
    "MAP-001",
    "MAP-002",
    "A11Y-001",
    "PASS-001",
    "PASS-002",
    "PASS-003",
    "PASS-004",
    "PASS-005",
    "PASS-006",
    "PASS-007",
    "PASS-008",
    "OUT-001",
    "OUT-002",
    "OUT-003",
    "OUT-004",
    "OUT-005",
    "MAP-003",
    "AUTH-001",
    "AUTH-002",
    "AUTH-003",
    "AUTH-004",
    "OUT-006",
    "SYNC-001",
    "SYNC-002",
    "SYNC-003",
    "SYNC-004",
    "SYNC-005",
    "SYNC-006",
    "SYNC-007",
    "SYNC-008",
    "HIST-001",
    "HIST-002",
    "HIST-003",
    "HIST-004",
    "HIST-005",
    "HIST-006",
    "HIST-007",
    "HIST-008",
    "MIG-001",
    "MIG-002",
    "MIG-003",
    "MIG-004",
    "MIG-005",
    "GPS-001",
    "GPS-002",
    "GPS-003",
    "GPS-004",
    "GPS-005",
    "GPS-006",
    "GPS-007",
    "PRIV-001",
    "SOC-001",
    "SOC-002",
    "SOC-003",
    "SOC-004",
    "SOC-005",
    "SOC-006",
    "SOC-007",
    "SOC-008",
    "SOC-009",
    "SOC-010",
    "PRIV-002",
    "E2E-001",
    "E2E-002",
    "E2E-003",
)
READINESS_RUNTIME_IDS = (
    "OPS-001",
    "OPS-002",
    "AUTH-APPLE-STAGING",
    "AUTH-005-PREFLIGHT-SERVER",
    "AUTH-005-PREFLIGHT-ARCHIVE",
    "AUTH-005-PREFLIGHT",
)

READINESS_OUTPUT = "Evidence/manifests/m6-readiness.json"
RC_OUTPUT = "Evidence/manifests/rc.json"
RC_PUBLICATION_MARKER = "Evidence/manifests/.rc-publication.json"
REL007_OUTPUT = "Evidence/runtime/REL-007.json"
M6_EXIT_OUTPUT = "Evidence/runtime/M6-EXIT.json"
REL009_OUTPUT = "Evidence/runtime/REL-009.json"
SWITCH_OBSERVATION = "Evidence/runtime/observed-switch-drill.json"
M2A_APPROVAL = "Evidence/runtime/approvals/m2a.json"


def fail(message: str) -> NoReturn:
    raise ReleaseError(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON object contains a duplicate key")
        result[key] = value
    return result


def reject_non_standard_number(value: str) -> NoReturn:
    fail(f"JSON contains a non-standard number: {value}")


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    try:
        root_stat = root.stat()
    except OSError as error:
        fail(f"could not inspect repository root: {error}")
    if not stat.S_ISDIR(root_stat.st_mode):
        fail("repository root is not a directory")
    return root
def verify_tag_commit(root: Path, tag: str, commit: str) -> None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", f"{tag}^{{commit}}"],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=10,
        )
        resolved = result.stdout.decode("ascii", "strict").strip().lower()
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as error:
        fail(f"could not resolve release tag: {error}")
    if result.returncode != 0 or resolved != commit:
        fail("release tag does not resolve to the supplied commit")


def valid_relative_path(raw: str) -> tuple[str, ...]:
    path = PurePosixPath(raw)
    if (
        not raw
        or "\\" in raw
        or path.is_absolute()
        or path.as_posix() != raw
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        fail(f"unsafe repository-relative path: {raw!r}")
    return path.parts


def root_path(root: Path, raw: str) -> Path:
    return root.joinpath(*valid_relative_path(raw))


def assert_exact_path(actual: str, expected: str, argument: str) -> None:
    if actual != expected:
        fail(f"{argument} must be exactly {expected}")


def ensure_regular_file(root: Path, raw: str) -> Path:
    parts = valid_relative_path(raw)
    current = root
    for part in parts:
        current = current / part
        try:
            information = os.lstat(current)
        except OSError as error:
            fail(f"missing required input {raw}: {error}")
        if stat.S_ISLNK(information.st_mode):
            fail(f"symlinked input is forbidden: {raw}")
    if not stat.S_ISREG(information.st_mode):
        fail(f"input is not a regular file: {raw}")
    return current


def read_bytes(root: Path, raw: str, *, limit: int = MAX_JSON_BYTES) -> bytes:
    path = ensure_regular_file(root, raw)
    try:
        size = path.stat().st_size
        if size <= 0 or size > limit:
            fail(f"input size is invalid: {raw}")
        with path.open("rb") as source:
            content = source.read(limit + 1)
    except OSError as error:
        fail(f"could not read {raw}: {error}")
    if not content or len(content) > limit:
        fail(f"input size is invalid: {raw}")
    return content


def parse_json(raw: bytes, name: str) -> Any:
    try:
        text = raw.decode("utf-8", "strict")
        document = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_standard_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, ReleaseError) as error:
        if isinstance(error, ReleaseError):
            raise
        fail(f"invalid JSON in {name}: {error}")
    if canonical_bytes(document) + b"\n" != raw:
        fail(f"JSON input is not canonical: {name}")
    return document


def read_json(root: Path, raw: str) -> tuple[dict[str, Any], bytes, str]:
    content = read_bytes(root, raw)
    document = parse_json(content, raw)
    if type(document) is not dict:
        fail(f"JSON document must be an object: {raw}")
    verify_sidecar(root, raw, content)
    return document, content, sha256_bytes(content)


def verify_sidecar(root: Path, raw: str, content: bytes) -> None:
    sidecar_path = f"{raw}.sha256"
    sidecar = read_bytes(root, sidecar_path, limit=512)
    expected = f"{sha256_bytes(content)}  {raw}\n".encode("ascii")
    if sidecar != expected:
        fail(f"invalid SHA-256 sidecar for {raw}")


def require_string(value: Any, name: str, expression: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{name} must be a non-empty string")
    if expression is not None and expression.fullmatch(value) is None:
        fail(f"{name} has an invalid format")
    return value


def require_sha(value: Any, name: str) -> str:
    return require_string(value, name, SHA256_RE)


def require_commit(value: Any, name: str) -> str:
    return require_string(value, name, COMMIT_RE)


def require_tag(value: Any, name: str) -> str:
    return require_string(value, name, TAG_RE)


def parse_timestamp(value: Any, name: str) -> datetime:
    text = require_string(value, name, TIMESTAMP_RE)
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail(f"{name} is not a valid UTC timestamp")


def output_path(record: dict[str, Any], expected: str, name: str) -> None:
    output = record.get("output")
    if not isinstance(output, dict) or set(output) != {"path"} or output.get("path") != expected:
        fail(f"{name} has the wrong output path")


def finite_number(value: Any, name: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        fail(f"{name} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        fail(f"{name} must be a finite number")
    return number


def verify_threshold_ratification(record: dict[str, Any], name: str) -> None:
    expected = {
        "schemaVersion",
        "artifactType",
        "id",
        "tag",
        "commit",
        "approvalSHA256",
        "createdAt",
        "thresholds",
    }
    if (
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "threshold-ratification"
        or record.get("id") != "OPS-005"
    ):
        fail(f"{name} has an invalid threshold-ratification schema")
    require_tag(record.get("tag"), f"{name} tag")
    require_commit(record.get("commit"), f"{name} commit")
    require_sha(record.get("approvalSHA256"), f"{name} approval SHA-256")
    parse_timestamp(record.get("createdAt"), f"{name} createdAt")
    thresholds = record.get("thresholds")
    if not isinstance(thresholds, dict) or set(thresholds) != {"beta", "production"}:
        fail(f"{name} has incomplete thresholds")
    beta = thresholds.get("beta")
    production = thresholds.get("production")
    beta_minimums = {
        "minimumWindowHours": 168.0,
        "crashFreeSessionsPercent": 99.5,
        "authSuccessPercent": 99.0,
        "bootstrapSuccessPercent": 99.0,
        "manualMutationSuccessPercent": 99.0,
    }
    beta_maximums = {"mapP95Seconds": 2.5, "bootstrapP95Seconds": 3.0}
    beta_zero = {"p0Count", "unresolvedP1Count", "authBypassCount", "rawGPSPersistenceCount"}
    production_minimums = {
        "minimumWindowHours": 24.0,
        "crashFreeSessionsPercent": 99.7,
        "crashFreeUsersPercent": 99.5,
        "mutationSuccessPercent": 99.5,
    }
    production_maximums = {
        "server5xxPercent": 0.5,
        "manualOnlineAckP95Seconds": 2.0,
        "revokeEventP95Seconds": 5.0,
        "failClosedLeaseSeconds": 30.0,
    }
    production_zero = {
        "p0Count",
        "unresolvedP1Count",
        "directDMLExposureCount",
        "privacyExposureCount",
        "authBypassCount",
        "revocationExposureCount",
        "rawGPSPersistenceCount",
    }
    for scope, values, minimums, maximums, zeroes in (
        ("beta", beta, beta_minimums, beta_maximums, beta_zero),
        ("production", production, production_minimums, production_maximums, production_zero),
    ):
        expected_fields = set(minimums) | set(maximums) | zeroes
        if not isinstance(values, dict) or set(values) != expected_fields:
            fail(f"{name} has incomplete {scope} thresholds")
        for field, minimum in minimums.items():
            if finite_number(values[field], f"{name} {scope}.{field}") < minimum:
                fail(f"{name} weakens {scope}.{field}")
        for field, maximum in maximums.items():
            value = finite_number(values[field], f"{name} {scope}.{field}")
            if value <= 0 or value > maximum:
                fail(f"{name} weakens {scope}.{field}")
        for field in zeroes:
            if type(values[field]) is not int or values[field] != 0:
                fail(f"{name} weakens {scope}.{field}")


def verify_runtime_floor_validation(record: dict[str, Any], name: str, evidence_id: str) -> None:
    expected = {
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
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "runtime-floor-validation"
        or record.get("id") != evidence_id
        or record.get("status") != "passed"
    ):
        fail(f"{name} has an invalid runtime-floor-validation schema")
    require_tag(record.get("tag"), f"{name} tag")
    require_commit(record.get("commit"), f"{name} commit")
    for field in ("sourceManifestSHA256", "thresholdSHA256", "schemaSHA256"):
        require_sha(record.get(field), f"{name} {field}")
    started = parse_timestamp(record.get("windowStartedAt"), f"{name} windowStartedAt")
    ended = parse_timestamp(record.get("windowEndedAt"), f"{name} windowEndedAt")
    if ended <= started or parse_timestamp(record.get("validatedAt"), f"{name} validatedAt") < ended:
        fail(f"{name} has an invalid runtime-floor window")
    duration_hours = (ended - started).total_seconds() / 3600.0
    declared_hours = finite_number(record.get("windowHours"), f"{name} windowHours")
    if not math.isclose(declared_hours, duration_hours, rel_tol=0.0, abs_tol=1e-9):
        fail(f"{name} windowHours does not match its timestamps")
    minimum = 168.0 if evidence_id == "REL-005" else 24.0
    if duration_hours < minimum:
        fail(f"{name} has a too-short runtime-floor window")
TRANSITION_EVIDENCE = {
    "REL-002": ("predeploy-disabled", 0, "disabled"),
    "REL-003": ("compatibility", 1, "disabled"),
    "REL-008": ("pitr-proof", 2, "disabled"),
    "REL-010": ("activate-1pct", 3, "enabled"),
    "REL-PHASE-05": ("phase-5", 4, "enabled"),
    "REL-PHASE-25": ("phase-25", 5, "enabled"),
    "REL-PHASE-50": ("phase-50", 6, "enabled"),
    "REL-PHASE-100": ("phase-100", 7, "enabled"),
    "REL-CONTRACT": ("contract-remove-old", 8, "enabled"),
}


def verify_transition_controller(record: dict[str, Any], name: str, evidence_id: str) -> None:
    expected = {
        "schemaVersion",
        "artifactType",
        "releaseID",
        "state",
        "tag",
        "commit",
        "buildDigest",
        "switchState",
        "expectedSequence",
        "expectedEventSHA256",
        "approvalSHA256",
        "observedInputSHA256",
        "dataSHA256",
        "migrationSHA256",
        "actorSHA256",
        "eventSHA256",
        "auditEventId",
        "rpcReceiptSHA256",
        "createdAt",
    }
    if evidence_id in {"REL-010", "REL-PHASE-05", "REL-PHASE-25", "REL-PHASE-50", "REL-PHASE-100", "REL-CONTRACT"}:
        expected.update({"rcManifestSHA256", "m6ExitSHA256"})
    if evidence_id in {"REL-PHASE-05", "REL-PHASE-25", "REL-PHASE-50", "REL-PHASE-100"}:
        expected.add("phaseFloorSHA256")
    state = TRANSITION_EVIDENCE.get(evidence_id)
    if (
        state is None
        or set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "release-transition-controller"
        or record.get("state") != state[0]
        or record.get("switchState") != state[2]
        or record.get("expectedSequence") != state[1]
    ):
        fail(f"{name} has an invalid release-transition-controller schema")
    if not isinstance(record.get("releaseID"), str) or RELEASE_ID_RE.fullmatch(record["releaseID"]) is None:
        fail(f"{name} has an invalid release ID")
    require_tag(record.get("tag"), f"{name} tag")
    require_commit(record.get("commit"), f"{name} commit")
    require_sha(record.get("buildDigest"), f"{name} buildDigest")
    for field in (
        "expectedEventSHA256",
        "approvalSHA256",
        "observedInputSHA256",
        "dataSHA256",
        "migrationSHA256",
        "actorSHA256",
        "eventSHA256",
        "rpcReceiptSHA256",
    ):
        require_sha(record.get(field), f"{name} {field}")
    if evidence_id in {"REL-010", "REL-PHASE-05", "REL-PHASE-25", "REL-PHASE-50", "REL-PHASE-100", "REL-CONTRACT"}:
        require_sha(record.get("rcManifestSHA256"), f"{name} rcManifestSHA256")
        require_sha(record.get("m6ExitSHA256"), f"{name} m6ExitSHA256")
    if evidence_id in {"REL-PHASE-05", "REL-PHASE-25", "REL-PHASE-50", "REL-PHASE-100"}:
        require_sha(record.get("phaseFloorSHA256"), f"{name} phaseFloorSHA256")
    if record["eventSHA256"] == record["expectedEventSHA256"]:
        fail(f"{name} self-references its event predecessor")
    if not isinstance(record.get("auditEventId"), str) or not record["auditEventId"]:
        fail(f"{name} has no audit event ID")
    parse_timestamp(record.get("createdAt"), f"{name} createdAt")


def transition_genesis_sentinel(record: dict[str, Any]) -> str:
    payload = (
        '{"commit":'
        + json.dumps(record["commit"], ensure_ascii=True, separators=(",", ":"))
        + ',"datasetSHA":' + json.dumps(record["dataSHA256"], ensure_ascii=True, separators=(",", ":"))
        + ',"migrationSHA":' + json.dumps(record["migrationSHA256"], ensure_ascii=True, separators=(",", ":"))
        + ',"releaseID":' + json.dumps(record["releaseID"], ensure_ascii=True, separators=(",", ":"))
        + ',"schemaVersion":"m6-release-transition-v1","tag":'
        + json.dumps(record["tag"], ensure_ascii=True, separators=(",", ":"))
        + "}"
    )
    return sha256_bytes(payload.encode("utf-8"))


def verify_transition_context(
    records: Iterable[tuple[str, dict[str, Any]]],
    *,
    tag: str,
    commit: str,
) -> None:
    baseline: dict[str, Any] | None = None
    for label, record in records:
        if record.get("tag") != tag or record.get("commit") != commit:
            fail(f"{label} is cross-release")
        if baseline is None:
            baseline = record
            continue
        for field in ("releaseID", "buildDigest", "dataSHA256", "migrationSHA256"):
            if record.get(field) != baseline.get(field):
                fail(f"{label} is bound to a different release context")
    if baseline is None:
        fail("release transition context is empty")


def verify_pre_rc_transition_lineage(
    rel002: dict[str, Any],
    rel003: dict[str, Any],
    rel008: dict[str, Any],
    *,
    tag: str,
    commit: str,
) -> None:
    verify_transition_context(
        (("REL-002", rel002), ("REL-003", rel003), ("REL-008", rel008)),
        tag=tag,
        commit=commit,
    )
    if rel002.get("expectedEventSHA256") != transition_genesis_sentinel(rel002):
        fail("REL-002 does not bind the canonical genesis sentinel")
    if rel003.get("expectedEventSHA256") != rel002.get("eventSHA256"):
        fail("REL-003 does not bind the exact REL-002 predecessor event")
    if rel008.get("expectedEventSHA256") != rel003.get("eventSHA256"):
        fail("REL-008 does not bind the exact REL-003 predecessor event")


def protected_build_digest(record: dict[str, Any], name: str) -> str:
    correlation = record.get("correlation")
    if not isinstance(correlation, dict):
        fail(f"{name} has no protected build provenance")
    return require_sha(correlation.get("buildDigest"), f"{name} buildDigest")


def require_stable_build_bindings(records: Iterable[tuple[str, dict[str, Any]]]) -> None:
    binding: str | None = None
    for name, record in records:
        build_digest = protected_build_digest(record, name)
        if binding is None:
            binding = build_digest
        elif build_digest != binding:
            fail(f"{name} is bound to a different release build")
PROTECTED_RELEASE_RECORDS = {
    "REL-004": ("protected-release-observation-evidence", "internal-alpha", "staging", "signed"),
    "REL-006": ("protected-release-observation-evidence", "metadata-review", "production", "signed"),
    "OPS-003": ("protected-release-observation-evidence", "alert-drill", "production", "signed"),
    "OPS-004": ("protected-release-observation-evidence", "evidence-disposition", "production", "signed"),
    "AUTH-005-RC": ("protected-rc-auth-aggregate-evidence", "rc-auth-aggregate", "production", "aggregate"),
    "REL-014": ("protected-release-observation-evidence", "postrelease-review", "production", "signed"),
}


def require_sha_object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{name} has an invalid schema")
    for key in keys:
        require_sha(value.get(key), f"{name} {key}")
    return value


def require_runtime_checks(value: Any, name: str) -> None:
    if not isinstance(value, list) or not value:
        fail(f"{name} has no runtime checks")
    codes: set[str] = set()
    for check in value:
        if not isinstance(check, dict) or set(check) != {"code", "outcome", "evidenceSHA256"}:
            fail(f"{name} has a malformed runtime check")
        code = require_string(check.get("code"), f"{name} check code", re.compile(r"^[A-Z][A-Z0-9_]{0,63}$"))
        if code in codes or check.get("outcome") != "passed":
            fail(f"{name} has a failed or duplicate runtime check")
        require_sha(check.get("evidenceSHA256"), f"{name} {code} evidence SHA-256")
        codes.add(code)


def verify_standard_runtime_evidence(record: dict[str, Any], name: str, evidence_id: str) -> None:
    expected = {"schemaVersion", "artifactType", "id", "status", "collectedAt", "gitSHA", "output", "inputHashes", "checks"}
    if (
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "runtime-evidence"
        or record.get("id") != evidence_id
        or record.get("status") != "passed"
    ):
        fail(f"{name} has an invalid runtime-evidence schema")
    require_commit(record.get("gitSHA"), f"{name} gitSHA")
    parse_timestamp(record.get("collectedAt"), f"{name} collectedAt")
    output_path(record, name, name)
    bindings = record.get("inputHashes")
    if not isinstance(bindings, dict) or not bindings:
        fail(f"{name} has no runtime input hashes")
    for key, digest in bindings.items():
        require_string(key, f"{name} input hash name", re.compile(r"^[A-Za-z][A-Za-z0-9]*SHA256$"))
        require_sha(digest, f"{name} {key}")
    require_runtime_checks(record.get("checks"), name)


def verify_protected_release_record(record: dict[str, Any], name: str, evidence_id: str) -> None:
    contract = PROTECTED_RELEASE_RECORDS[evidence_id]
    expected = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "tag",
        "commit",
        "collectedAt",
        "output",
        "correlation",
        "inputHashes",
        "attestations",
        "observation",
    }
    if evidence_id == "REL-014":
        expected.add("previousArtifactSHA256")
    if (
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != contract[0]
        or record.get("id") != evidence_id
        or record.get("status") != "passed"
    ):
        fail(f"{name} has an invalid protected runtime-evidence schema")
    require_tag(record.get("tag"), f"{name} tag")
    require_commit(record.get("commit"), f"{name} commit")
    parse_timestamp(record.get("collectedAt"), f"{name} collectedAt")
    output_path(record, name, name)
    if evidence_id == "REL-014":
        require_sha(record.get("previousArtifactSHA256"), f"{name} previousArtifactSHA256")
    correlation = record.get("correlation")
    correlation_keys = {"repository", "workflowRunId", "job", "environment", "buildDigest", "inputSHA256"}
    if not isinstance(correlation, dict) or set(correlation) != correlation_keys:
        fail(f"{name} has incomplete protected provenance")
    require_string(correlation.get("repository"), f"{name} repository", REPOSITORY_RE)
    require_string(correlation.get("workflowRunId"), f"{name} workflowRunId", RUN_ID_RE)
    if correlation.get("job") != contract[1] or correlation.get("environment") != contract[2]:
        fail(f"{name} has the wrong protected workflow provenance")
    require_sha(correlation.get("buildDigest"), f"{name} buildDigest")
    require_sha(correlation.get("inputSHA256"), f"{name} inputSHA256")
    attestations = record.get("attestations")
    if not isinstance(attestations, dict) or set(attestations) != {
        "protectedGithubContextVerified",
        "sourceSignatureVerified",
        "sourceRedactionVerified",
    } or any(value is not True for value in attestations.values()):
        fail(f"{name} has invalid protected attestations")
    if contract[3] == "signed":
        require_sha_object(
            record.get("inputHashes"),
            {
                "sourceDocumentSHA256",
                "sourceSignatureSHA256",
                "sourcePublicKeySHA256",
                "buildDigestSHA256",
                "inputSHA256",
                "sourceProducerReceiptSHA256",
            },
            f"{name} input hashes",
        )
        observation = record.get("observation")
        if not isinstance(observation, dict) or set(observation) != {"sourceObservedAt", "observationSHA256"}:
            fail(f"{name} has invalid protected observation")
        parse_timestamp(observation.get("sourceObservedAt"), f"{name} sourceObservedAt")
        require_sha(observation.get("observationSHA256"), f"{name} observationSHA256")
    else:
        require_sha_object(
            record.get("inputHashes"),
            {"serverEvidenceSHA256", "archiveEvidenceSHA256", "buildDigestSHA256", "inputSHA256"},
            f"{name} input hashes",
        )
        require_sha_object(
            record.get("observation"),
            {
                "serverEvidenceSHA256",
                "archiveEvidenceSHA256",
                "serverObservationSHA256",
                "archiveObservationSHA256",
            },
            f"{name} observation",
        )
    hashes = record["inputHashes"]
    if hashes["buildDigestSHA256"] != correlation["buildDigest"] or hashes["inputSHA256"] != correlation["inputSHA256"]:
        fail(f"{name} protected provenance hashes are inconsistent")


def verify_auth_apple_staging(record: dict[str, Any], name: str) -> None:
    expected = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "correlation",
        "inputHashes",
        "redactedCorrelation",
        "validations",
        "checkpoint",
        "collectedAt",
        "output",
    }
    if (
        set(record) != expected
        or record.get("schemaVersion") != 2
        or record.get("artifactType") != "runtime-evidence"
        or record.get("id") != "AUTH-APPLE-STAGING"
        or record.get("status") != "passed"
    ):
        fail(f"{name} has an invalid AUTH-APPLE-STAGING schema")
    correlation = record.get("correlation")
    correlation_keys = {"runId", "commitSHA", "buildDigest", "testFlightBuildDigest", "checkpointReceiptId"}
    if not isinstance(correlation, dict) or set(correlation) != correlation_keys:
        fail(f"{name} has incomplete AUTH-APPLE-STAGING provenance")
    require_string(correlation.get("runId"), f"{name} runId", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
    require_commit(correlation.get("commitSHA"), f"{name} commitSHA")
    require_sha(correlation.get("buildDigest"), f"{name} buildDigest")
    require_sha(correlation.get("testFlightBuildDigest"), f"{name} testFlightBuildDigest")
    require_string(correlation.get("checkpointReceiptId"), f"{name} checkpointReceiptId", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
    require_sha_object(
        record.get("inputHashes"),
        {
            "buildProvenanceSHA256",
            "testFlightObservationSHA256",
            "checkpointObservationSHA256",
            "approvalSHA256",
        },
        f"{name} input hashes",
    )
    require_sha_object(record.get("redactedCorrelation"), {"nonceSHA256", "stateSHA256", "callbackSHA256", "actorSHA256"}, f"{name} redacted correlation")
    validations = record.get("validations")
    validation_keys = {
        "issuerValidated",
        "issuerCode",
        "audienceValidated",
        "audienceCode",
        "providerValidated",
        "providerCode",
        "callbackValidated",
        "callbackCode",
        "supabaseSessionIssued",
        "sessionCode",
    }
    if not isinstance(validations, dict) or set(validations) != validation_keys:
        fail(f"{name} has incomplete AUTH-APPLE-STAGING validations")
    for field in ("issuerValidated", "audienceValidated", "providerValidated", "callbackValidated", "supabaseSessionIssued"):
        if validations.get(field) is not True:
            fail(f"{name} has a failed AUTH-APPLE-STAGING validation")
    for field in ("issuerCode", "audienceCode", "providerCode", "callbackCode", "sessionCode"):
        require_string(validations.get(field), f"{name} {field}", re.compile(r"^[A-Z][A-Z0-9_]{0,63}$"))
    checkpoint = record.get("checkpoint")
    if not isinstance(checkpoint, dict) or set(checkpoint) != {"receiptSHA256", "responseSHA256", "signatureSHA256", "completedAt"}:
        fail(f"{name} has an invalid checkpoint")
    for field in ("receiptSHA256", "responseSHA256", "signatureSHA256"):
        require_sha(checkpoint.get(field), f"{name} checkpoint {field}")
    parse_timestamp(checkpoint.get("completedAt"), f"{name} checkpoint completedAt")
    parse_timestamp(record.get("collectedAt"), f"{name} collectedAt")
    output = record.get("output")
    if output != {"path": name, "commitPath": "Evidence/runtime/AUTH-APPLE-STAGING.commit"}:
        fail(f"{name} has an invalid output")


def verify_auth_preflight(record: dict[str, Any], name: str, evidence_id: str) -> None:
    expected = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "correlation",
        "inputHashes",
        "attestations",
        "observation",
        "collectedAt",
        "output",
    }
    if (
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "protected-auth-preflight-evidence"
        or record.get("id") != evidence_id
        or record.get("status") != "passed"
    ):
        fail(f"{name} has an invalid protected auth-preflight schema")
    correlation = record.get("correlation")
    correlation_keys = {"repository", "workflowRunId", "releaseTag", "commitSHA", "buildDigest"}
    if not isinstance(correlation, dict) or set(correlation) != correlation_keys:
        fail(f"{name} has incomplete protected auth-preflight provenance")
    require_string(correlation.get("repository"), f"{name} repository", REPOSITORY_RE)
    require_string(correlation.get("workflowRunId"), f"{name} workflowRunId", RUN_ID_RE)
    require_tag(correlation.get("releaseTag"), f"{name} releaseTag")
    require_commit(correlation.get("commitSHA"), f"{name} commitSHA")
    require_sha(correlation.get("buildDigest"), f"{name} buildDigest")
    parse_timestamp(record.get("collectedAt"), f"{name} collectedAt")
    source_ids = {"AUTH-005-PREFLIGHT-SERVER", "AUTH-005-PREFLIGHT-ARCHIVE"}
    if evidence_id in source_ids:
        require_sha_object(record.get("inputHashes"), {"sourceDocumentSHA256", "sourceSignatureSHA256", "sourcePublicKeySHA256"}, f"{name} input hashes")
        attestations = record.get("attestations")
        if not isinstance(attestations, dict) or set(attestations) != {"githubActionsOIDCVerified", "releaseTagSignatureVerified", "sourceSignatureVerified"} or any(value is not True for value in attestations.values()):
            fail(f"{name} has invalid signed-source attestations")
        commit_path = f"Evidence/runtime/{evidence_id}.commit"
        if record.get("output") != {"path": name, "commitPath": commit_path}:
            fail(f"{name} has an invalid output")
        observation = record.get("observation")
        if evidence_id == "AUTH-005-PREFLIGHT-SERVER":
            expected_observation = {"sourceObservedAt", "wrongIssuerRejected", "wrongAudienceRejected", "testActorRejected"}
            expected_codes = {
                "wrongIssuerRejected": "WRONG_ISSUER_REJECTED",
                "wrongAudienceRejected": "WRONG_AUDIENCE_REJECTED",
                "testActorRejected": "TEST_IDENTITY_REJECTED",
            }
            if not isinstance(observation, dict) or set(observation) != expected_observation:
                fail(f"{name} has an invalid server observation")
            parse_timestamp(observation.get("sourceObservedAt"), f"{name} sourceObservedAt")
            for field, code in expected_codes.items():
                probe = observation.get(field)
                if not isinstance(probe, dict) or set(probe) != {"code", "probeSHA256"} or probe.get("code") != code:
                    fail(f"{name} has an invalid {field} observation")
                require_sha(probe.get("probeSHA256"), f"{name} {field} probeSHA256")
        else:
            expected_observation = {
                "sourceObservedAt",
                "archiveSHA256",
                "linkMapSHA256",
                "codeSigningMetadataSHA256",
                "archiveSignatureSHA256",
                "releaseArchiveSigned",
                "releaseConfiguration",
                "forbiddenSymbols",
            }
            if not isinstance(observation, dict) or set(observation) != expected_observation:
                fail(f"{name} has an invalid archive observation")
            parse_timestamp(observation.get("sourceObservedAt"), f"{name} sourceObservedAt")
            for field in ("archiveSHA256", "linkMapSHA256", "codeSigningMetadataSHA256", "archiveSignatureSHA256"):
                require_sha(observation.get(field), f"{name} {field}")
            if observation.get("releaseArchiveSigned") is not True or observation.get("releaseConfiguration") != "Release":
                fail(f"{name} has an invalid archive release binding")
            if observation.get("forbiddenSymbols") != {
                "bypassSymbolsAbsent": True,
                "testSessionSymbolsAbsent": True,
                "testIssuerSymbolsAbsent": True,
            }:
                fail(f"{name} has invalid forbidden-symbol proof")
    else:
        require_sha_object(record.get("inputHashes"), {"serverEvidenceSHA256", "serverCommitSHA256", "archiveEvidenceSHA256", "archiveCommitSHA256"}, f"{name} input hashes")
        attestations = record.get("attestations")
        if not isinstance(attestations, dict) or set(attestations) != {"githubActionsOIDCVerified", "releaseTagSignatureVerified", "serverPublicationVerified", "archivePublicationVerified"} or any(value is not True for value in attestations.values()):
            fail(f"{name} has invalid aggregate attestations")
        if record.get("output") != {"path": name, "commitPath": f"Evidence/runtime/{evidence_id}.commit"}:
            fail(f"{name} has an invalid output")
        require_sha_object(
            record.get("observation"),
            {"serverEvidenceSHA256", "serverCommitSHA256", "archiveEvidenceSHA256", "archiveCommitSHA256"},
            f"{name} aggregate observation",
        )


def verify_test_record(record: dict[str, Any], name: str, evidence_id: str) -> None:
    if record.get("schemaVersion") != 1 or record.get("id") != evidence_id or record.get("status") != "passed":
        fail(f"{name} is not a passed deterministic test record")
    require_commit(record.get("gitSHA"), f"{name} gitSHA")
    if evidence_id == "EVIDENCE-BIJECTION-NEGATIVE":
        if record.get("output") != name:
            fail(f"{name} has an invalid deterministic test output")
    else:
        output_path(record, name, name)




def verify_passed_record(
    root: Path,
    raw: str,
    evidence_id: str,
    commit: str,
    *,
    tag: str | None = None,
) -> tuple[dict[str, Any], str]:
    record, _content, digest = read_json(root, raw)
    artifact_type = record.get("artifactType")
    bound_commit: str
    bound_tag: str | None = None
    if artifact_type == "runtime-floor-validation":
        verify_runtime_floor_validation(record, raw, evidence_id)
        bound_commit = require_commit(record.get("commit"), f"{raw} commit")
        bound_tag = require_tag(record.get("tag"), f"{raw} tag")
    elif artifact_type == "threshold-ratification" and evidence_id == "OPS-005":
        verify_threshold_ratification(record, raw)
        bound_commit = require_commit(record.get("commit"), f"{raw} commit")
        bound_tag = require_tag(record.get("tag"), f"{raw} tag")
    elif artifact_type == "release-transition-controller":
        verify_transition_controller(record, raw, evidence_id)
        bound_commit = require_commit(record.get("commit"), f"{raw} commit")
        bound_tag = require_tag(record.get("tag"), f"{raw} tag")
    elif evidence_id in PROTECTED_RELEASE_RECORDS:
        verify_protected_release_record(record, raw, evidence_id)
        bound_commit = require_commit(record.get("commit"), f"{raw} commit")
        bound_tag = require_tag(record.get("tag"), f"{raw} tag")
    elif evidence_id == "AUTH-APPLE-STAGING":
        verify_auth_apple_staging(record, raw)
        correlation = record["correlation"]
        bound_commit = require_commit(correlation.get("commitSHA"), f"{raw} commitSHA")
    elif evidence_id in {"AUTH-005-PREFLIGHT-SERVER", "AUTH-005-PREFLIGHT-ARCHIVE", "AUTH-005-PREFLIGHT"}:
        verify_auth_preflight(record, raw, evidence_id)
        correlation = record["correlation"]
        bound_commit = require_commit(correlation.get("commitSHA"), f"{raw} commitSHA")
        bound_tag = require_tag(correlation.get("releaseTag"), f"{raw} releaseTag")
    elif evidence_id == "REL-009":
        bound_tag = require_tag(record.get("tag"), f"{raw} tag")
        bound_commit = require_commit(record.get("commit"), f"{raw} commit")
        verify_switch_drill(
            root,
            raw,
            tag=bound_tag,
            commit=bound_commit,
            previous_event_sha=require_sha(record.get("previousEventSHA256"), f"{raw} previousEventSHA256"),
        )
    elif raw.startswith("Evidence/runtime/"):
        verify_standard_runtime_evidence(record, raw, evidence_id)
        bound_commit = require_commit(record.get("gitSHA"), f"{raw} gitSHA")
    elif raw.startswith("Evidence/tests/"):
        verify_test_record(record, raw, evidence_id)
        bound_commit = require_commit(record.get("gitSHA"), f"{raw} gitSHA")
    else:
        fail(f"{raw} is not a supported protected evidence path")
    if bound_commit != commit:
        fail(f"{raw} is stale or bound to a different commit")
    if tag is not None and bound_tag != tag:
        fail(f"{raw} is bound to a different tag")
    return record, digest


def require_approval_freshness(created_at: Any, approvals: list[dict[str, Any]], name: str) -> None:
    created = parse_timestamp(created_at, f"{name} createdAt")
    now = datetime.now(timezone.utc)
    timestamps = [created]
    for approval in approvals:
        timestamps.append(parse_timestamp(approval.get("createdAt", approval.get("approvedAt")), f"{name} approval createdAt"))
        timestamps.append(parse_timestamp(approval.get("approvedAt"), f"{name} approval approvedAt"))
    for timestamp in timestamps:
        if timestamp > now + timedelta(minutes=5) or now - timestamp > MAX_APPROVAL_AGE:
            fail(f"{name} approval is stale")


def require_release_approval_roles(record: dict[str, Any], name: str) -> list[dict[str, Any]]:
    approvals = record.get("approvals")
    if not isinstance(approvals, list) or len(approvals) != len(ROLES):
        fail(f"{name} must contain exactly three approvals")
    seen_roles: set[str] = set()
    seen_logins: set[str] = set()
    seen_comments: set[int] = set()
    seen_approval_digests: set[str] = set()
    seen_comment_digests: set[str] = set()
    validated: list[dict[str, Any]] = []
    approval_keys = {
        "role",
        "status",
        "commentId",
        "login",
        "createdAt",
        "approvedAt",
        "approvalDigest",
        "commentSHA256",
        "membershipAttestations",
    }
    for approval in approvals:
        if not isinstance(approval, dict) or set(approval) != approval_keys:
            fail(f"{name} contains a malformed approval")
        role = approval.get("role")
        login = approval.get("login")
        comment_id = approval.get("commentId")
        if (
            role not in ROLES
            or role in seen_roles
            or approval.get("status") != "active"
            or not isinstance(login, str)
            or LOGIN_RE.fullmatch(login) is None
            or login.lower() in seen_logins
            or type(comment_id) is not int
            or comment_id <= 0
            or comment_id in seen_comments
        ):
            fail(f"{name} has invalid approval identities")
        approval_digest = require_sha(approval.get("approvalDigest"), f"{name} approvalDigest")
        comment_digest = require_sha(approval.get("commentSHA256"), f"{name} commentSHA256")
        if approval_digest in seen_approval_digests or comment_digest in seen_comment_digests:
            fail(f"{name} reuses approval or comment evidence")
        memberships = approval.get("membershipAttestations")
        if not isinstance(memberships, list) or len(memberships) != len(ROLES):
            fail(f"{name} has incomplete membership attestations")
        membership_roles: set[str] = set()
        active_roles: list[str] = []
        for membership in memberships:
            if not isinstance(membership, dict) or set(membership) != {"role", "teamSlug", "state", "responseSHA256"}:
                fail(f"{name} has malformed membership attestations")
            membership_role = membership.get("role")
            if (
                membership_role not in ROLES
                or membership_role in membership_roles
                or not isinstance(membership.get("teamSlug"), str)
                or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", membership["teamSlug"]) is None
                or membership.get("state") not in {"active", "inactive"}
            ):
                fail(f"{name} has invalid membership attestations")
            require_sha(membership.get("responseSHA256"), f"{name} membership responseSHA256")
            membership_roles.add(membership_role)
            if membership["state"] == "active":
                active_roles.append(membership_role)
        if membership_roles != set(ROLES) or active_roles != [role]:
            fail(f"{name} has an invalid active membership")
        seen_roles.add(role)
        seen_logins.add(login.lower())
        seen_comments.add(comment_id)
        seen_approval_digests.add(approval_digest)
        seen_comment_digests.add(comment_digest)
        validated.append(approval)
    if seen_roles != set(ROLES):
        fail(f"{name} is missing a required approval role")
    return validated


def require_bound_input_hashes(record: dict[str, Any], expected: dict[str, str], name: str) -> None:
    keys = {
        "PERF-001": "perfSHA256",
        "OPS-003": "ops003SHA256",
        "OPS-004": "ops004SHA256",
        "REL-005": "betaSHA256",
        "OPS-005": "thresholdSHA256",
        "AUTH-005-RC": "authSHA256",
    }
    if set(expected) != set(keys):
        fail("internal protected-input binding contract is invalid")
    bindings = record.get("inputHashes")
    if not isinstance(bindings, dict) or set(bindings) != set(keys.values()):
        fail(f"{name} must bind all protected input hashes exactly once")
    for evidence_id, digest in expected.items():
        if require_sha(bindings.get(keys[evidence_id]), f"{name} {evidence_id} SHA-256") != digest:
            fail(f"{name} is not bound to {evidence_id}")


def verify_approval(
    root: Path,
    raw: str,
    expected_gate: str,
    commit: str,
    *,
    tag: str,
    transition: str | None = None,
    manifest_sha: str | None = None,
    metric_sha: str | None = None,
    build_digest: str | None = None,
    fresh: bool = False,
    bound_input_hashes: dict[str, str] | None = None,
) -> str:
    expected_gate_value = {"threshold": "threshold", "m6-exit": "m6-exit"}.get(expected_gate)
    expected_transition = {"threshold": "threshold-ratification", "m6-exit": "m6-exit"}.get(expected_gate)
    if expected_gate_value is None or expected_transition is None:
        fail("internal approval gate contract is invalid")
    if transition is None:
        transition = expected_transition
    record, _content, digest = read_json(root, raw)
    expected_keys = {
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
    if bound_input_hashes is not None:
        expected_keys.add("inputHashes")
    if (
        set(record) != expected_keys
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "release-role-approvals"
        or record.get("gate") != expected_gate_value
        or not isinstance(record.get("issueURL"), str)
        or ISSUE_URL_RE.fullmatch(record["issueURL"]) is None
        or record.get("releaseTag") != tag
        or record.get("commitSHA") != commit
        or record.get("transition") != transition
    ):
        fail(f"{raw} approval is stale or cross-context")
    for field in ("buildDigest", "observedInputSHA256", "predecessorEventSHA256", "issueSnapshotSHA256", "teamSnapshotSHA256"):
        require_sha(record.get(field), f"{raw} {field}")
    require_string(record.get("githubRunId"), f"{raw} githubRunId", RUN_ID_RE)
    if manifest_sha is not None and record["observedInputSHA256"] != manifest_sha:
        fail(f"{raw} approval is bound to a different manifest")
    if metric_sha is not None and record["predecessorEventSHA256"] != metric_sha:
        fail(f"{raw} approval is bound to a different metric")
    if build_digest is not None and record["buildDigest"] != build_digest:
        fail(f"{raw} approval is bound to a different release build")
    teams = record.get("teamSnapshots")
    if not isinstance(teams, list) or len(teams) != len(ROLES):
        fail(f"{raw} approval has incomplete team snapshots")
    team_roles: set[str] = set()
    for team in teams:
        if not isinstance(team, dict) or set(team) != {"role", "teamSlug", "responseSHA256"}:
            fail(f"{raw} approval has malformed team snapshots")
        if (
            team.get("role") not in ROLES
            or team["role"] in team_roles
            or not isinstance(team.get("teamSlug"), str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", team["teamSlug"]) is None
        ):
            fail(f"{raw} approval has invalid team snapshots")
        require_sha(team.get("responseSHA256"), f"{raw} team responseSHA256")
        team_roles.add(team["role"])
    if team_roles != set(ROLES):
        fail(f"{raw} approval has incomplete team snapshots")
    approvals = require_release_approval_roles(record, raw)
    if fresh:
        require_approval_freshness(record.get("createdAt"), approvals, raw)
    if bound_input_hashes is not None:
        require_bound_input_hashes(record, bound_input_hashes, raw)
    return digest


def verify_m2a_approval(root: Path, commit: str) -> str:
    record, _content, digest = read_json(root, M2A_APPROVAL)
    expected = {
        "schemaVersion",
        "artifactType",
        "gate",
        "issueURL",
        "issueSnapshotSHA256",
        "teamSnapshotSHA256",
        "githubRunId",
        "gitSHA",
        "buildDigest",
        "testFlightDigest",
        "pseudonymDomain",
        "collectedAt",
        "teamSnapshots",
        "approvals",
    }
    if (
        set(record) != expected
        or record.get("schemaVersion") != 2
        or record.get("artifactType") != "m2a-role-approvals"
        or record.get("gate") != "M2A"
        or record.get("gitSHA") != commit
        or record.get("pseudonymDomain") != "m2a-approver/v1"
        or not isinstance(record.get("issueURL"), str)
        or ISSUE_URL_RE.fullmatch(record["issueURL"]) is None
    ):
        fail("M2A approval is stale or cross-context")
    for field in ("issueSnapshotSHA256", "teamSnapshotSHA256", "buildDigest", "testFlightDigest"):
        require_sha(record.get(field), f"M2A {field}")
    require_string(record.get("githubRunId"), "M2A githubRunId", RUN_ID_RE)
    parse_timestamp(record.get("collectedAt"), "M2A collectedAt")
    teams = record.get("teamSnapshots")
    if not isinstance(teams, list) or len(teams) != len(ROLES):
        fail("M2A approval has incomplete team snapshots")
    team_roles: set[str] = set()
    for team in teams:
        if not isinstance(team, dict) or set(team) != {"role", "teamId", "teamSlug", "teamResponseSHA256"}:
            fail("M2A approval has malformed team snapshots")
        if (
            team.get("role") not in ROLES
            or team["role"] in team_roles
            or not isinstance(team.get("teamId"), str)
            or RUN_ID_RE.fullmatch(team["teamId"]) is None
            or not isinstance(team.get("teamSlug"), str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", team["teamSlug"]) is None
        ):
            fail("M2A approval has invalid team snapshots")
        require_sha(team.get("teamResponseSHA256"), "M2A teamResponseSHA256")
        team_roles.add(team["role"])
    if team_roles != set(ROLES):
        fail("M2A approval has incomplete team snapshots")
    approvals = record.get("approvals")
    approval_keys = {"role", "status", "subjectPseudonym", "approvedAt", "approvalDigest", "commentSHA256", "membershipAttestations"}
    if not isinstance(approvals, list) or len(approvals) != len(ROLES):
        fail("M2A approval must contain exactly three approvals")
    seen_roles: set[str] = set()
    subjects: set[str] = set()
    comment_hashes: set[str] = set()
    validated: list[dict[str, Any]] = []
    for approval in approvals:
        if not isinstance(approval, dict) or set(approval) != approval_keys:
            fail("M2A approval contains a malformed approval")
        role = approval.get("role")
        subject = approval.get("subjectPseudonym")
        if role not in ROLES or role in seen_roles or approval.get("status") != "active":
            fail("M2A approval has invalid roles")
        subject = require_sha(subject, "M2A subjectPseudonym")
        if subject in subjects:
            fail("M2A approval identities are not distinct")
        require_sha(approval.get("approvalDigest"), "M2A approvalDigest")
        comment_hash = require_sha(approval.get("commentSHA256"), "M2A commentSHA256")
        if comment_hash in comment_hashes:
            fail("M2A approval comments are not distinct")
        comment_hashes.add(comment_hash)
        memberships = approval.get("membershipAttestations")
        if not isinstance(memberships, list) or len(memberships) != len(ROLES):
            fail("M2A approval has incomplete membership attestations")
        membership_roles: set[str] = set()
        active_roles: list[str] = []
        for membership in memberships:
            if not isinstance(membership, dict) or set(membership) != {"role", "teamId", "teamSlug", "state", "responseSHA256"}:
                fail("M2A approval has malformed membership attestations")
            membership_role = membership.get("role")
            if (
                membership_role not in ROLES
                or membership_role in membership_roles
                or not isinstance(membership.get("teamId"), str)
                or RUN_ID_RE.fullmatch(membership["teamId"]) is None
                or not isinstance(membership.get("teamSlug"), str)
                or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", membership["teamSlug"]) is None
                or membership.get("state") not in {"active", "inactive"}
            ):
                fail("M2A approval has invalid membership attestations")
            require_sha(membership.get("responseSHA256"), "M2A membership responseSHA256")
            membership_roles.add(membership_role)
            if membership["state"] == "active":
                active_roles.append(membership_role)
        if membership_roles != set(ROLES) or active_roles != [role]:
            fail("M2A approval has an invalid active membership")
        seen_roles.add(role)
        subjects.add(subject)
        validated.append(approval)
    if seen_roles != set(ROLES):
        fail("M2A approval is missing a required role")
    collected = parse_timestamp(record.get("collectedAt"), "M2A collectedAt")
    now = datetime.now(timezone.utc)
    if collected > now + timedelta(minutes=5) or now - collected > MAX_APPROVAL_AGE:
        fail("M2A approval is stale")
    for approval in validated:
        approved = parse_timestamp(approval.get("approvedAt"), "M2A approval approvedAt")
        if approved > now + timedelta(minutes=5) or now - approved > MAX_APPROVAL_AGE:
            fail("M2A approval is stale")
    return digest


def verify_floor_result(record: dict[str, Any], name: str) -> None:
    if record.get("artifactType") != "runtime-floor-validation":
        fail(f"{name} is not a canonical runtime-floor-validation record")
    verify_runtime_floor_validation(record, name, "REL-005")


def input_entry(evidence_id: str, path: str, digest: str) -> dict[str, str]:
    return {"id": evidence_id, "path": path, "sha256": digest}


def ensure_output_parent(root: Path, raw: str) -> Path:
    path = root_path(root, raw)
    current = root
    for part in valid_relative_path(raw)[:-1]:
        current /= part
        try:
            information = os.lstat(current)
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
                information = os.lstat(current)
            except OSError as error:
                fail(f"could not create output directory: {error}")
        except OSError as error:
            fail(f"could not inspect output directory: {error}")
        if stat.S_ISLNK(information.st_mode) or not stat.S_ISDIR(information.st_mode):
            fail(f"unsafe output directory for {raw}")
    return path




def preflight_output_absent(root: Path, raw: str) -> None:
    path = root_path(root, raw)
    current = root
    for part in valid_relative_path(raw)[:-1]:
        current /= part
        try:
            information = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as error:
            fail(f"could not inspect output directory: {error}")
        if stat.S_ISLNK(information.st_mode) or not stat.S_ISDIR(information.st_mode):
            fail(f"unsafe output directory for {raw}")
    for candidate in (path, Path(f"{path}.sha256")):
        try:
            os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError as error:
            fail(f"could not inspect output path: {error}")
        fail(f"create-once output already exists: {raw}")


def sync_directory(directory: Path, name: str) -> None:
    descriptor = -1
    error: OSError | None = None
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(descriptor)
    except OSError as failure:
        error = failure
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as failure:
                if error is None:
                    error = failure
    if error is not None:
        fail(f"could not sync immutable output directory for {name}: {error}")


def temporary_file(directory: Path, name: str, data: bytes) -> Path:
    descriptor = -1
    temporary: Path | None = None
    error: OSError | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            descriptor = -1
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        return temporary
    except OSError as failure:
        error = failure
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as failure:
                if error is None:
                    error = failure
        if error is not None and temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as failure:
                error = failure
    if error is None:
        fail("could not stage output")
    fail(f"could not stage output: {error}")


def immutable_component_matches(root: Path, raw: str, expected: bytes) -> bool:
    path = root_path(root, raw)
    try:
        information = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        fail(f"could not inspect immutable output {raw}: {error}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail(f"immutable output is not a regular file: {raw}")
    if read_bytes(root, raw, limit=max(len(expected), 512)) != expected:
        fail(f"immutable output does not match its create-once transaction: {raw}")
    return True


def publish_pair(root: Path, raw: str, record: dict[str, Any], *, recover: bool) -> str:
    path = ensure_output_parent(root, raw)
    sidecar_path = Path(f"{path}.sha256")
    content = canonical_bytes(record) + b"\n"
    digest = sha256_bytes(content)
    sidecar = f"{digest}  {raw}\n".encode("ascii")
    content_exists = immutable_component_matches(root, raw, content)
    sidecar_exists = immutable_component_matches(root, f"{raw}.sha256", sidecar)
    if not recover and (content_exists or sidecar_exists):
        fail(f"create-once output already exists: {raw}")
    staged_content = temporary_file(path.parent, path.name, content) if not content_exists else None
    staged_sidecar = temporary_file(path.parent, sidecar_path.name, sidecar) if not sidecar_exists else None
    try:
        if staged_content is not None:
            os.link(staged_content, path, follow_symlinks=False)
        if staged_sidecar is not None:
            os.link(staged_sidecar, sidecar_path, follow_symlinks=False)
        sync_directory(path.parent, raw)
    except OSError as error:
        fail(f"could not create immutable output {raw}: {error}")
    finally:
        for staged in (staged_content, staged_sidecar):
            if staged is not None:
                try:
                    staged.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    fail(f"could not remove staged output for {raw}: {error}")
    if not immutable_component_matches(root, raw, content) or not immutable_component_matches(root, f"{raw}.sha256", sidecar):
        fail(f"could not publish immutable output {raw}")
    return digest


def pair_publication_marker(raw: str) -> str:
    return f"{raw}.publication-intent"


def pair_publication_intent(raw: str, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "artifactType": "immutable-pair-publication-intent",
        "output": raw,
        "record": record,
    }


def read_pair_publication_intent(root: Path, raw: str) -> dict[str, Any] | None:
    marker = pair_publication_marker(raw)
    path = root_path(root, marker)
    try:
        information = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        fail(f"could not inspect immutable output intent {raw}: {error}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail(f"immutable output intent is not a regular file: {raw}")
    document = parse_json(read_bytes(root, marker), marker)
    if (
        type(document) is not dict
        or set(document) != {"schemaVersion", "artifactType", "output", "record"}
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "immutable-pair-publication-intent"
        or document.get("output") != raw
        or type(document.get("record")) is not dict
    ):
        fail(f"immutable output intent is malformed: {raw}")
    return document


def write_pair_once(root: Path, raw: str, record: dict[str, Any]) -> str:
    intent = pair_publication_intent(raw, record)
    published_intent = read_pair_publication_intent(root, raw)
    if published_intent is None:
        preflight_output_absent(root, raw)
        write_commit_marker_once(root, pair_publication_marker(raw), intent)
    elif published_intent != intent:
        fail(f"immutable output intent belongs to a different transaction: {raw}")
    return publish_pair(root, raw, record, recover=True)


def rc_publication_intent(manifest: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "artifactType": "release-candidate-publication-intent",
        "id": "REL-007",
        "tag": manifest["tag"],
        "commit": manifest["commit"],
        "manifest": manifest,
        "receipt": receipt,
    }


def write_commit_marker_once(root: Path, raw: str, record: dict[str, Any]) -> None:
    path = ensure_output_parent(root, raw)
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        fail(f"could not inspect commit marker: {error}")
    else:
        fail(f"create-once commit marker already exists: {raw}")
    staged = temporary_file(path.parent, path.name, canonical_bytes(record) + b"\n")
    try:
        os.link(staged, path, follow_symlinks=False)
        sync_directory(path.parent, raw)
    except OSError as error:
        fail(f"could not create commit marker {raw}: {error}")
    finally:
        try:
            staged.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            fail(f"could not remove staged commit marker for {raw}: {error}")


def read_rc_publication_intent(root: Path) -> dict[str, Any] | None:
    path = root_path(root, RC_PUBLICATION_MARKER)
    try:
        information = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        fail(f"could not inspect RC publication marker: {error}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail("RC publication marker is not a regular file")
    document = parse_json(read_bytes(root, RC_PUBLICATION_MARKER), RC_PUBLICATION_MARKER)
    if type(document) is not dict:
        fail("RC publication marker must be an object")
    return document


def publish_rc_transaction(root: Path, manifest: dict[str, Any], receipt: dict[str, Any]) -> None:
    intent = rc_publication_intent(manifest, receipt)
    published_intent = read_rc_publication_intent(root)
    if published_intent is None:
        preflight_output_absent(root, RC_OUTPUT)
        preflight_output_absent(root, REL007_OUTPUT)
        write_commit_marker_once(root, RC_PUBLICATION_MARKER, intent)
    elif published_intent != intent:
        fail("RC publication marker belongs to a different release transaction")
    publish_pair(root, RC_OUTPUT, manifest, recover=True)
    publish_pair(root, REL007_OUTPUT, receipt, recover=True)


def verify_rc_publication_intent(root: Path, manifest: dict[str, Any], receipt: dict[str, Any]) -> None:
    if read_rc_publication_intent(root) != rc_publication_intent(manifest, receipt):
        fail("RC publication marker is stale or malformed")


def prepare_outputs(root: Path, outputs: Iterable[str]) -> None:
    for output in outputs:
        if read_pair_publication_intent(root, output) is None:
            preflight_output_absent(root, output)


def assemble_readiness(arguments: argparse.Namespace) -> None:
    assert_exact_path(arguments.output, READINESS_OUTPUT, "--output")
    tag = require_tag(arguments.tag, "--tag")
    commit = require_commit(arguments.commit, "--commit")
    root = repository_root()
    verify_tag_commit(root, tag, commit)
    prepare_outputs(root, (READINESS_OUTPUT,))

    inputs: list[dict[str, str]] = []
    for evidence_id in READINESS_TEST_IDS:
        path = f"Evidence/tests/{evidence_id}.json"
        _record, digest = verify_passed_record(root, path, evidence_id, commit)
        inputs.append(input_entry(evidence_id, path, digest))
    m2a_runtime: dict[str, Any] | None = None
    for evidence_id in READINESS_RUNTIME_IDS:
        path = f"Evidence/runtime/{evidence_id}.json"
        runtime_record, digest = verify_passed_record(root, path, evidence_id, commit)
        if evidence_id == "AUTH-APPLE-STAGING":
            m2a_runtime = runtime_record
        inputs.append(input_entry(evidence_id, path, digest))
    approval_digest = verify_m2a_approval(root, commit)
    if not isinstance(m2a_runtime, dict) or not isinstance(m2a_runtime.get("inputHashes"), dict):
        fail("M2A runtime evidence does not bind its approval")
    if require_sha(m2a_runtime["inputHashes"].get("approvalSHA256"), "M2A runtime approval SHA-256") != approval_digest:
        fail("M2A runtime evidence is bound to a different approval")
    m2a_approval, _m2a_content, _m2a_digest = read_json(root, M2A_APPROVAL)
    if (
        not isinstance(m2a_runtime.get("correlation"), dict)
        or m2a_approval.get("buildDigest") != m2a_runtime["correlation"].get("buildDigest")
    ):
        fail("M2A approval is bound to a different staging build")

    record = {
        "schemaVersion": 1,
        "artifactType": "m6-readiness-manifest",
        "id": "REL-001",
        "tag": tag,
        "commit": commit,
        "inputs": inputs,
        "m2aApproval": {"path": M2A_APPROVAL, "sha256": approval_digest},
    }
    write_pair_once(root, READINESS_OUTPUT, record)


def verify_readiness(root: Path, raw: str) -> tuple[dict[str, Any], str]:
    assert_exact_path(raw, READINESS_OUTPUT, "--readiness")
    record, _content, digest = read_json(root, raw)
    expected_keys = {"schemaVersion", "artifactType", "id", "tag", "commit", "inputs", "m2aApproval"}
    if set(record) != expected_keys or record.get("schemaVersion") != 1 or record.get("artifactType") != "m6-readiness-manifest" or record.get("id") != "REL-001":
        fail("readiness manifest has an invalid schema")
    tag = require_tag(record.get("tag"), "readiness tag")
    commit = require_commit(record.get("commit"), "readiness commit")
    verify_tag_commit(root, tag, commit)
    inputs = record.get("inputs")
    expected_ids = READINESS_TEST_IDS + READINESS_RUNTIME_IDS
    if not isinstance(inputs, list) or len(inputs) != len(expected_ids):
        fail("readiness manifest has an incomplete evidence set")
    if [entry.get("id") if isinstance(entry, dict) else None for entry in inputs] != list(expected_ids):
        fail("readiness manifest evidence IDs are not exact")
    m2a_runtime: dict[str, Any] | None = None
    for evidence_id, entry in zip(expected_ids, inputs):
        if not isinstance(entry, dict) or set(entry) != {"id", "path", "sha256"}:
            fail("readiness manifest input is malformed")
        expected_path = f"Evidence/tests/{evidence_id}.json" if evidence_id in READINESS_TEST_IDS else f"Evidence/runtime/{evidence_id}.json"
        if entry["path"] != expected_path:
            fail("readiness manifest input path is invalid")
        current_record, current_digest = verify_passed_record(root, expected_path, evidence_id, commit)
        if evidence_id == "AUTH-APPLE-STAGING":
            m2a_runtime = current_record
        if require_sha(entry["sha256"], "readiness input SHA-256") != current_digest:
            fail("readiness manifest input SHA-256 is stale")
    approval = record.get("m2aApproval")
    if not isinstance(approval, dict) or set(approval) != {"path", "sha256"} or approval.get("path") != M2A_APPROVAL:
        fail("readiness manifest M2A approval is malformed")
    approval_digest = verify_m2a_approval(root, commit)
    if require_sha(approval.get("sha256"), "readiness M2A approval SHA-256") != approval_digest:
        fail("readiness manifest M2A approval is stale")
    if not isinstance(m2a_runtime, dict) or not isinstance(m2a_runtime.get("inputHashes"), dict):
        fail("M2A runtime evidence does not bind its approval")
    if require_sha(m2a_runtime["inputHashes"].get("approvalSHA256"), "M2A runtime approval SHA-256") != approval_digest:
        fail("M2A runtime evidence is bound to a different approval")
    m2a_approval, _m2a_content, _m2a_digest = read_json(root, M2A_APPROVAL)
    if (
        not isinstance(m2a_runtime.get("correlation"), dict)
        or m2a_approval.get("buildDigest") != m2a_runtime["correlation"].get("buildDigest")
    ):
        fail("M2A approval is bound to a different staging build")
    return record, digest


def assemble_rc(arguments: argparse.Namespace) -> None:
    expected_paths = {
        "readiness": READINESS_OUTPUT,
        "rel_002": "Evidence/runtime/REL-002.json",
        "rel_003": "Evidence/runtime/REL-003.json",
        "rel_004": "Evidence/runtime/REL-004.json",
        "rel_005": "Evidence/runtime/REL-005.json",
        "rel_006": "Evidence/runtime/REL-006.json",
        "rel_008": "Evidence/runtime/REL-008.json",
        "rel_009": REL009_OUTPUT,
        "ops_005": "Evidence/runtime/OPS-005.json",
        "perf": "Evidence/tests/PERF-001.json",
        "auth": "Evidence/runtime/AUTH-005-RC.json",
        "approval": "Evidence/runtime/approvals/threshold.json",
    }
    for key, expected in expected_paths.items():
        assert_exact_path(getattr(arguments, key), expected, f"--{key.replace('_', '-')}")
    assert_exact_path(arguments.output_manifest, RC_OUTPUT, "--output-manifest")
    assert_exact_path(arguments.output, REL007_OUTPUT, "--output")
    root = repository_root()
    readiness, readiness_digest = verify_readiness(root, arguments.readiness)
    tag = require_tag(readiness["tag"], "readiness tag")
    commit = require_commit(readiness["commit"], "readiness commit")

    inputs: list[dict[str, str]] = [input_entry("REL-001", READINESS_OUTPUT, readiness_digest)]
    ops_ratification: dict[str, Any] | None = None
    rel002_controller: dict[str, Any] | None = None
    rel003_controller: dict[str, Any] | None = None
    rel004_record: dict[str, Any] | None = None
    rel004_digest = ""
    rel006_record: dict[str, Any] | None = None
    rel008_controller: dict[str, Any] | None = None
    rel009_record: dict[str, Any] | None = None
    auth_record: dict[str, Any] | None = None
    for argument_name, evidence_id in (
        ("rel_002", "REL-002"),
        ("rel_003", "REL-003"),
        ("rel_004", "REL-004"),
        ("rel_005", "REL-005"),
        ("rel_006", "REL-006"),
        ("rel_008", "REL-008"),
        ("rel_009", "REL-009"),
        ("ops_005", "OPS-005"),
        ("perf", "PERF-001"),
        ("auth", "AUTH-005-RC"),
    ):
        path = getattr(arguments, argument_name)
        evidence_tag = None if evidence_id == "PERF-001" else tag
        candidate, digest = verify_passed_record(root, path, evidence_id, commit, tag=evidence_tag)
        if evidence_id == "REL-005":
            verify_floor_result(candidate, path)
        if evidence_id == "REL-002":
            rel002_controller = candidate
        if evidence_id == "REL-003":
            rel003_controller = candidate
        if evidence_id == "REL-004":
            rel004_record = candidate
            rel004_digest = digest
        if evidence_id == "OPS-005":
            ops_ratification = candidate
        if evidence_id == "REL-006":
            rel006_record = candidate
        if evidence_id == "REL-008":
            rel008_controller = candidate
        if evidence_id == "REL-009":
            rel009_record = candidate
        if evidence_id == "AUTH-005-RC":
            auth_record = candidate
        inputs.append(input_entry(evidence_id, path, digest))
    if (
        not isinstance(rel002_controller, dict)
        or not isinstance(rel003_controller, dict)
        or not isinstance(rel004_record, dict)
        or not isinstance(rel006_record, dict)
        or not isinstance(rel008_controller, dict)
        or not isinstance(auth_record, dict)
    ):
        fail("RC is missing protected release evidence")
    verify_pre_rc_transition_lineage(rel002_controller, rel003_controller, rel008_controller, tag=tag, commit=commit)
    require_stable_build_bindings(
        (("REL-004", rel004_record), ("REL-006", rel006_record), ("AUTH-005-RC", auth_record))
    )
    build_digest = protected_build_digest(auth_record, "AUTH-005-RC")
    threshold_digest = verify_approval(
        root,
        arguments.approval,
        "threshold",
        commit,
        tag=tag,
        transition="threshold-ratification",
        manifest_sha=readiness_digest,
        metric_sha=rel004_digest,
        build_digest=build_digest,
    )
    if not isinstance(ops_ratification, dict) or require_sha(ops_ratification.get("approvalSHA256"), "OPS-005 approval SHA-256") != threshold_digest:
        fail("OPS-005 is bound to a different threshold approval")
    if not isinstance(rel008_controller, dict) or not isinstance(rel009_record, dict):
        fail("RC is missing a release transition or switch-drill receipt")
    verify_switch_drill(
        root,
        arguments.rel_009,
        tag=tag,
        commit=commit,
        previous_event_sha=require_sha(rel008_controller.get("eventSHA256"), "REL-008 event SHA-256"),
    )

    manifest = {
        "schemaVersion": 1,
        "artifactType": "release-candidate-manifest",
        "id": "REL-007",
        "tag": tag,
        "commit": commit,
        "buildDigest": build_digest,
        "previousManifestSHA256": readiness_digest,
        "inputs": inputs,
        "thresholdApproval": {"path": arguments.approval, "sha256": threshold_digest},
    }
    rc_digest = sha256_bytes(canonical_bytes(manifest) + b"\n")
    rel007 = {
        "schemaVersion": 1,
        "artifactType": "release-candidate-assembly",
        "id": "REL-007",
        "status": "passed",
        "tag": tag,
        "commit": commit,
        "buildDigest": build_digest,
        "previousManifestSHA256": readiness_digest,
        "manifest": {"path": RC_OUTPUT, "sha256": rc_digest},
        "inputs": inputs,
        "thresholdApproval": {"path": arguments.approval, "sha256": threshold_digest},
        "output": {"path": REL007_OUTPUT},
    }
    publish_rc_transaction(root, manifest, rel007)


def verify_rc(root: Path, raw: str) -> tuple[dict[str, Any], str]:
    assert_exact_path(raw, RC_OUTPUT, "--rc")
    record, _content, digest = read_json(root, raw)
    expected_keys = {"schemaVersion", "artifactType", "id", "tag", "commit", "buildDigest", "previousManifestSHA256", "inputs", "thresholdApproval"}
    if set(record) != expected_keys or record.get("schemaVersion") != 1 or record.get("artifactType") != "release-candidate-manifest" or record.get("id") != "REL-007":
        fail("RC manifest has an invalid schema")
    tag = require_tag(record.get("tag"), "RC tag")
    commit = require_commit(record.get("commit"), "RC commit")
    build_digest = require_sha(record.get("buildDigest"), "RC buildDigest")
    readiness, readiness_digest = verify_readiness(root, READINESS_OUTPUT)
    if readiness.get("tag") != tag or readiness.get("commit") != commit:
        fail("RC manifest is cross-tag or cross-commit")
    if require_sha(record.get("previousManifestSHA256"), "RC predecessor SHA-256") != readiness_digest:
        fail("RC manifest predecessor is stale")
    if record.get("previousManifestSHA256") == digest:
        fail("RC manifest self-references")
    inputs = record.get("inputs")
    expected = (
        ("REL-001", READINESS_OUTPUT),
        ("REL-002", "Evidence/runtime/REL-002.json"),
        ("REL-003", "Evidence/runtime/REL-003.json"),
        ("REL-004", "Evidence/runtime/REL-004.json"),
        ("REL-005", "Evidence/runtime/REL-005.json"),
        ("REL-006", "Evidence/runtime/REL-006.json"),
        ("REL-008", "Evidence/runtime/REL-008.json"),
        ("REL-009", REL009_OUTPUT),
        ("OPS-005", "Evidence/runtime/OPS-005.json"),
        ("PERF-001", "Evidence/tests/PERF-001.json"),
        ("AUTH-005-RC", "Evidence/runtime/AUTH-005-RC.json"),
    )
    ops_ratification: dict[str, Any] | None = None
    rel002_controller: dict[str, Any] | None = None
    rel003_controller: dict[str, Any] | None = None
    rel004_record: dict[str, Any] | None = None
    rel004_digest = ""
    rel006_record: dict[str, Any] | None = None
    rel008_controller: dict[str, Any] | None = None
    rel009_record: dict[str, Any] | None = None
    auth_record: dict[str, Any] | None = None
    if not isinstance(inputs, list) or len(inputs) != len(expected):
        fail("RC manifest evidence set is incomplete")
    for entry, (evidence_id, path) in zip(inputs, expected):
        if not isinstance(entry, dict) or set(entry) != {"id", "path", "sha256"} or entry.get("id") != evidence_id or entry.get("path") != path:
            fail("RC manifest input is malformed")
        evidence_tag = None if evidence_id == "PERF-001" else tag
        candidate, current_digest = verify_passed_record(root, path, evidence_id, commit, tag=evidence_tag)
        if evidence_id == "REL-005":
            verify_floor_result(candidate, path)
        if evidence_id == "REL-002":
            rel002_controller = candidate
        if evidence_id == "REL-003":
            rel003_controller = candidate
        if evidence_id == "REL-004":
            rel004_record = candidate
            rel004_digest = current_digest
        if evidence_id == "OPS-005":
            ops_ratification = candidate
        if evidence_id == "REL-006":
            rel006_record = candidate
        if evidence_id == "REL-008":
            rel008_controller = candidate
        if evidence_id == "REL-009":
            rel009_record = candidate
        if evidence_id == "AUTH-005-RC":
            auth_record = candidate
        if require_sha(entry.get("sha256"), "RC input SHA-256") != current_digest:
            fail("RC manifest input is stale")
    if (
        not isinstance(rel002_controller, dict)
        or not isinstance(rel003_controller, dict)
        or not isinstance(rel004_record, dict)
        or not isinstance(rel006_record, dict)
        or not isinstance(rel008_controller, dict)
        or not isinstance(auth_record, dict)
    ):
        fail("RC is missing protected release evidence")
    verify_pre_rc_transition_lineage(rel002_controller, rel003_controller, rel008_controller, tag=tag, commit=commit)
    require_stable_build_bindings(
        (("REL-004", rel004_record), ("REL-006", rel006_record), ("AUTH-005-RC", auth_record))
    )
    if protected_build_digest(auth_record, "AUTH-005-RC") != build_digest:
        fail("RC manifest is bound to a different release build")
    approval = record.get("thresholdApproval")
    if not isinstance(approval, dict) or set(approval) != {"path", "sha256"} or approval.get("path") != "Evidence/runtime/approvals/threshold.json":
        fail("RC threshold approval is malformed")
    approval_digest = verify_approval(
        root,
        approval["path"],
        "threshold",
        commit,
        tag=tag,
        transition="threshold-ratification",
        manifest_sha=readiness_digest,
        metric_sha=rel004_digest,
        build_digest=build_digest,
    )
    if require_sha(approval.get("sha256"), "RC threshold approval SHA-256") != approval_digest:
        fail("RC threshold approval is stale")
    if not isinstance(ops_ratification, dict) or require_sha(ops_ratification.get("approvalSHA256"), "OPS-005 approval SHA-256") != approval_digest:
        fail("OPS-005 is bound to a different threshold approval")
    if not isinstance(rel008_controller, dict) or not isinstance(rel009_record, dict):
        fail("RC is missing a release transition or switch-drill receipt")
    verify_switch_drill(
        root,
        REL009_OUTPUT,
        tag=tag,
        commit=commit,
        previous_event_sha=require_sha(rel008_controller.get("eventSHA256"), "REL-008 event SHA-256"),
    )
    rel007, _content, rel007_digest = read_json(root, REL007_OUTPUT)
    expected_rel007 = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "tag",
        "commit",
        "buildDigest",
        "previousManifestSHA256",
        "manifest",
        "inputs",
        "thresholdApproval",
        "output",
    }
    if (
        set(rel007) != expected_rel007
        or rel007.get("schemaVersion") != 1
        or rel007.get("artifactType") != "release-candidate-assembly"
        or rel007.get("id") != "REL-007"
        or rel007.get("status") != "passed"
        or rel007.get("tag") != tag
        or rel007.get("commit") != commit
        or rel007.get("buildDigest") != build_digest
        or rel007.get("previousManifestSHA256") != readiness_digest
        or rel007.get("inputs") != inputs
        or rel007.get("thresholdApproval") != approval
    ):
        fail("REL-007 assembly receipt is stale or malformed")
    output_path(rel007, REL007_OUTPUT, "REL-007")
    manifest = rel007.get("manifest")
    if not isinstance(manifest, dict) or set(manifest) != {"path", "sha256"}:
        fail("REL-007 assembly receipt has an invalid RC binding")
    if manifest.get("path") != RC_OUTPUT or require_sha(manifest.get("sha256"), "REL-007 RC SHA-256") != digest:
        fail("REL-007 assembly receipt is bound to a different RC manifest")
    if rel007_digest == digest:
        fail("REL-007 assembly receipt self-references")
    verify_rc_publication_intent(root, record, rel007)
    return record, digest


def assemble_m6_exit(arguments: argparse.Namespace) -> None:
    expected_paths = {
        "rc": RC_OUTPUT,
        "ops_003": "Evidence/runtime/OPS-003.json",
        "ops_004": "Evidence/runtime/OPS-004.json",
        "perf": "Evidence/tests/PERF-001.json",
        "beta": "Evidence/runtime/REL-005.json",
        "threshold": "Evidence/runtime/OPS-005.json",
        "auth": "Evidence/runtime/AUTH-005-RC.json",
        "approval": "Evidence/runtime/approvals/m6-exit.json",
    }
    for key, expected in expected_paths.items():
        assert_exact_path(getattr(arguments, key), expected, f"--{key.replace('_', '-')}")
    assert_exact_path(arguments.output, M6_EXIT_OUTPUT, "--output")
    root = repository_root()
    prepare_outputs(root, (M6_EXIT_OUTPUT,))
    rc, rc_digest = verify_rc(root, arguments.rc)
    tag = require_tag(rc["tag"], "RC tag")
    commit = require_commit(rc["commit"], "RC commit")
    rc_build_digest = require_sha(rc.get("buildDigest"), "RC buildDigest")

    inputs: list[dict[str, str]] = [input_entry("REL-007", RC_OUTPUT, rc_digest)]
    protected_records: dict[str, dict[str, Any]] = {}
    for argument_name, evidence_id in (
        ("ops_003", "OPS-003"),
        ("ops_004", "OPS-004"),
        ("perf", "PERF-001"),
        ("beta", "REL-005"),
        ("threshold", "OPS-005"),
        ("auth", "AUTH-005-RC"),
    ):
        path = getattr(arguments, argument_name)
        evidence_tag = None if evidence_id == "PERF-001" else tag
        record, digest = verify_passed_record(root, path, evidence_id, commit, tag=evidence_tag)
        if evidence_id == "REL-005":
            verify_floor_result(record, path)
        if evidence_id in {"OPS-003", "OPS-004", "AUTH-005-RC"}:
            protected_records[evidence_id] = record
        inputs.append(input_entry(evidence_id, path, digest))
    beta_digest = next(entry["sha256"] for entry in inputs if entry["id"] == "REL-005")
    protected_input_hashes = {
        evidence_id: next(entry["sha256"] for entry in inputs if entry["id"] == evidence_id)
        for evidence_id in ("PERF-001", "OPS-003", "OPS-004", "REL-005", "OPS-005", "AUTH-005-RC")
    }
    if set(protected_records) != {"OPS-003", "OPS-004", "AUTH-005-RC"}:
        fail("M6-EXIT is missing protected build provenance")
    require_stable_build_bindings(tuple(protected_records.items()))
    build_digest = protected_build_digest(protected_records["AUTH-005-RC"], "AUTH-005-RC")
    if build_digest != rc_build_digest:
        fail("M6-EXIT protected evidence is bound to a different RC build")
    approval_digest = verify_approval(
        root,
        arguments.approval,
        "m6-exit",
        commit,
        tag=tag,
        transition="m6-exit",
        manifest_sha=rc_digest,
        metric_sha=beta_digest,
        build_digest=build_digest,
        fresh=True,
        bound_input_hashes=protected_input_hashes,
    )

    record = {
        "schemaVersion": 1,
        "artifactType": "m6-exit-admission",
        "id": "M6-EXIT",
        "status": "passed",
        "tag": tag,
        "commit": commit,
        "buildDigest": build_digest,
        "previousManifestSHA256": rc_digest,
        "inputs": inputs,
        "approval": {"path": arguments.approval, "sha256": approval_digest},
        "output": {"path": M6_EXIT_OUTPUT},
    }
    write_pair_once(root, M6_EXIT_OUTPUT, record)


def verify_m6_exit(root: Path, raw: str) -> tuple[dict[str, Any], str]:
    assert_exact_path(raw, M6_EXIT_OUTPUT, "--m6-exit")
    record, _content, digest = read_json(root, raw)
    expected_keys = {
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
        set(record) != expected_keys
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "m6-exit-admission"
        or record.get("id") != "M6-EXIT"
        or record.get("status") != "passed"
    ):
        fail("M6-EXIT has an invalid schema")
    output_path(record, M6_EXIT_OUTPUT, "M6-EXIT")
    tag = require_tag(record.get("tag"), "M6-EXIT tag")
    commit = require_commit(record.get("commit"), "M6-EXIT commit")
    build_digest = require_sha(record.get("buildDigest"), "M6-EXIT buildDigest")
    verify_tag_commit(root, tag, commit)
    rc, rc_digest = verify_rc(root, RC_OUTPUT)
    if rc.get("tag") != tag or rc.get("commit") != commit:
        fail("M6-EXIT is cross-tag or cross-commit")
    if build_digest != require_sha(rc.get("buildDigest"), "RC buildDigest"):
        fail("M6-EXIT is bound to a different RC build")
    if require_sha(record.get("previousManifestSHA256"), "M6-EXIT predecessor SHA-256") != rc_digest:
        fail("M6-EXIT predecessor is stale")
    if record.get("previousManifestSHA256") == digest:
        fail("M6-EXIT self-references")
    expected_inputs = (
        ("REL-007", RC_OUTPUT),
        ("OPS-003", "Evidence/runtime/OPS-003.json"),
        ("OPS-004", "Evidence/runtime/OPS-004.json"),
        ("PERF-001", "Evidence/tests/PERF-001.json"),
        ("REL-005", "Evidence/runtime/REL-005.json"),
        ("OPS-005", "Evidence/runtime/OPS-005.json"),
        ("AUTH-005-RC", "Evidence/runtime/AUTH-005-RC.json"),
    )
    inputs = record.get("inputs")
    if not isinstance(inputs, list) or len(inputs) != len(expected_inputs):
        fail("M6-EXIT evidence set is incomplete")
    current_hashes: dict[str, str] = {}
    protected_records: dict[str, dict[str, Any]] = {}
    for entry, (evidence_id, path) in zip(inputs, expected_inputs):
        if not isinstance(entry, dict) or set(entry) != {"id", "path", "sha256"} or entry.get("id") != evidence_id or entry.get("path") != path:
            fail("M6-EXIT input is malformed")
        if evidence_id == "REL-007":
            current_digest = rc_digest
        else:
            evidence_tag = None if evidence_id == "PERF-001" else tag
            candidate, current_digest = verify_passed_record(root, path, evidence_id, commit, tag=evidence_tag)
            if evidence_id == "REL-005":
                verify_floor_result(candidate, path)
            if evidence_id in {"OPS-003", "OPS-004", "AUTH-005-RC"}:
                protected_records[evidence_id] = candidate
        if require_sha(entry.get("sha256"), "M6-EXIT input SHA-256") != current_digest:
            fail("M6-EXIT input is stale")
        current_hashes[evidence_id] = current_digest
    if set(protected_records) != {"OPS-003", "OPS-004", "AUTH-005-RC"}:
        fail("M6-EXIT is missing protected build provenance")
    require_stable_build_bindings(tuple(protected_records.items()))
    if protected_build_digest(protected_records["AUTH-005-RC"], "AUTH-005-RC") != build_digest:
        fail("M6-EXIT protected evidence is bound to a different release build")
    approval = record.get("approval")
    if not isinstance(approval, dict) or set(approval) != {"path", "sha256"} or approval.get("path") != "Evidence/runtime/approvals/m6-exit.json":
        fail("M6-EXIT approval is malformed")
    approval_digest = verify_approval(
        root,
        approval["path"],
        "m6-exit",
        commit,
        tag=tag,
        transition="m6-exit",
        manifest_sha=rc_digest,
        metric_sha=current_hashes["REL-005"],
        build_digest=build_digest,
        fresh=False,
        bound_input_hashes={
            "PERF-001": current_hashes["PERF-001"],
            "OPS-003": current_hashes["OPS-003"],
            "OPS-004": current_hashes["OPS-004"],
            "REL-005": current_hashes["REL-005"],
            "OPS-005": current_hashes["OPS-005"],
            "AUTH-005-RC": current_hashes["AUTH-005-RC"],
        },
    )
    if require_sha(approval.get("sha256"), "M6-EXIT approval SHA-256") != approval_digest:
        fail("M6-EXIT approval is stale")
    return record, digest

def switch_observation(root: Path, previous_event_sha: str) -> tuple[dict[str, Any], str]:
    record, _content, digest = read_json(root, SWITCH_OBSERVATION)
    expected = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "tag",
        "commit",
        "previousEventSHA256",
        "sources",
        "checks",
        "output",
    }
    if set(record) != expected or record.get("schemaVersion") != 1 or record.get("artifactType") != "switch-drill-observation" or record.get("id") != "REL-009-OBSERVED" or record.get("status") != "passed":
        fail("switch drill observation has an invalid schema")
    require_tag(record.get("tag"), "switch drill tag")
    require_commit(record.get("commit"), "switch drill commit")
    if require_sha(record.get("previousEventSHA256"), "switch drill predecessor SHA-256") != previous_event_sha:
        fail("switch drill observation is bound to a different predecessor")
    output_path(record, SWITCH_OBSERVATION, SWITCH_OBSERVATION)
    required_codes = {
        "WRITE_PAUSE_PRESERVES_QUEUE",
        "SOCIAL_DISABLE_ZEROIZES",
        "GPS_DISABLE_RETAINS_MANUAL",
        "CODE_LOOKUP_GENERIC_UNAVAILABLE",
        "DIRECT_DML_DENIED",
        "RLS_ENFORCED",
    }
    sources = record.get("sources")
    if not isinstance(sources, list) or len(sources) != len(required_codes):
        fail("switch drill observation sources are incomplete")
    source_hashes: dict[str, str] = {}
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"id", "path", "sha256"}:
            fail("switch drill observation source is malformed")
        source_id = source.get("id")
        source_path = source.get("path")
        if (
            not isinstance(source_id, str)
            or source_id not in required_codes
            or source_id in source_hashes
            or not isinstance(source_path, str)
            or not source_path.startswith("Evidence/")
            or not source_path.endswith(".json")
            or source_path in {SWITCH_OBSERVATION, REL009_OUTPUT}
        ):
            fail("switch drill observation source is invalid")
        valid_relative_path(source_path)
        source_record, _source_content, source_digest = read_json(root, source_path)
        if require_sha(source.get("sha256"), "switch drill source SHA-256") != source_digest:
            fail("switch drill observation source is stale")
        if (
            source_record.get("schemaVersion") != 1
            or source_record.get("id") != source_id
            or source_record.get("status") != "passed"
            or source_record.get("tag") != record.get("tag")
            or source_record.get("commit") != record.get("commit")
        ):
            fail("switch drill source has invalid release provenance")
        output_path(source_record, source_path, source_path)
        source_hashes[source_id] = source_digest
    if set(source_hashes) != required_codes:
        fail("switch drill observation sources are incomplete")
    checks = record.get("checks")
    if not isinstance(checks, list) or len(checks) != len(required_codes):
        fail("switch drill observation checks are incomplete")
    seen: set[str] = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"code", "outcome", "sourceId", "evidenceSHA256"}:
            fail("switch drill observation check is malformed")
        code = check.get("code")
        source_id = check.get("sourceId")
        if code not in required_codes or code in seen or source_id != code or check.get("outcome") != "passed":
            fail("switch drill observation did not preserve authorization")
        if require_sha(check.get("evidenceSHA256"), "switch drill check SHA-256") != source_hashes[source_id]:
            fail("switch drill check is not bound to its declared verified source")
        seen.add(code)
    if seen != required_codes:
        fail("switch drill observation checks are incomplete")
    return record, digest


def produce_switch_drill(arguments: argparse.Namespace) -> None:
    assert_exact_path(arguments.output, REL009_OUTPUT, "--output")
    previous_event_sha = require_sha(arguments.previous_event_sha, "--previous-event-sha")
    root = repository_root()
    prepare_outputs(root, (REL009_OUTPUT,))
    observed, observed_digest = switch_observation(root, previous_event_sha)
    record = {
        "schemaVersion": 1,
        "artifactType": "switch-drill-evidence",
        "id": "REL-009",
        "status": "passed",
        "tag": observed["tag"],
        "commit": observed["commit"],
        "previousEventSHA256": previous_event_sha,
        "observedSource": {"path": SWITCH_OBSERVATION, "sha256": observed_digest},
        "sources": observed["sources"],
        "checks": observed["checks"],
        "output": {"path": REL009_OUTPUT},
    }
    write_pair_once(root, REL009_OUTPUT, record)
def verify_switch_drill(
    root: Path,
    raw: str,
    *,
    tag: str,
    commit: str,
    previous_event_sha: str,
) -> tuple[dict[str, Any], str]:
    assert_exact_path(raw, REL009_OUTPUT, "--rel-009")
    record, _content, digest = read_json(root, raw)
    expected = {
        "schemaVersion",
        "artifactType",
        "id",
        "status",
        "tag",
        "commit",
        "previousEventSHA256",
        "observedSource",
        "sources",
        "checks",
        "output",
    }
    if (
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "switch-drill-evidence"
        or record.get("id") != "REL-009"
        or record.get("status") != "passed"
        or record.get("tag") != tag
        or record.get("commit") != commit
        or record.get("previousEventSHA256") != previous_event_sha
    ):
        fail("REL-009 is stale, cross-release, or malformed")
    output_path(record, REL009_OUTPUT, "REL-009")
    source = record.get("observedSource")
    if not isinstance(source, dict) or set(source) != {"path", "sha256"} or source.get("path") != SWITCH_OBSERVATION:
        fail("REL-009 has an invalid observed source")
    observed, observed_digest = switch_observation(root, previous_event_sha)
    if observed.get("tag") != tag or observed.get("commit") != commit:
        fail("REL-009 observed source is cross-release")
    if require_sha(source.get("sha256"), "REL-009 observed source SHA-256") != observed_digest:
        fail("REL-009 is bound to a stale observed source")
    if record.get("sources") != observed.get("sources") or record.get("checks") != observed.get("checks"):
        fail("REL-009 checks do not match the observed authorization drill")
    return record, digest



def record_predecessor(record: dict[str, Any], name: str) -> str:
    return require_sha(record.get("previousArtifactSHA256"), f"{name} previousArtifactSHA256")
def verify_activate_observed_manifest(
    root: Path,
    *,
    tag: str,
    commit: str,
    build_digest: str,
    release_id: str,
    data_sha: str,
    migration_sha: str,
    expected_event_sha: str,
    m6_exit_sha: str,
    controller_observed_sha: str,
) -> None:
    path = "Evidence/manifests/observed-activate-1pct.json"
    record, _content, digest = read_json(root, path)
    expected = {
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
    if (
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "release-transition-observed-input"
        or record.get("state") != "activate-1pct"
        or record.get("releaseID") != release_id
        or record.get("tag") != tag
        or record.get("commit") != commit
        or record.get("buildDigest") != build_digest
        or record.get("dataSHA256") != data_sha
        or record.get("migrationSHA256") != migration_sha
        or record.get("expectedSequence") != 3
        or record.get("expectedEventSHA256") != expected_event_sha
        or digest != controller_observed_sha
    ):
        fail("REL-010 observed manifest is stale or cross-lineage")
    for field in ("buildDigest", "dataSHA256", "migrationSHA256"):
        require_sha(record.get(field), f"REL-010 observed {field}")
    for field in (
        "inputSHA256",
        "sourceDocumentSHA256",
        "sourceSignatureSHA256",
        "sourcePublicKeySHA256",
        "sourceInputSHA256",
    ):
        require_sha(record.get(field), f"REL-010 observed {field}")
    require_string(record.get("repository"), "REL-010 repository", REPOSITORY_RE)
    require_string(record.get("workflowRunId"), "REL-010 workflowRunId", RUN_ID_RE)
    if not isinstance(record.get("job"), str) or record["job"] != "rollout-1pct":
        fail("REL-010 observed manifest has wrong job provenance")
    parse_timestamp(record.get("sourceObservedAt"), "REL-010 sourceObservedAt")
    if not isinstance(record.get("sourceObservation"), dict) or not record["sourceObservation"]:
        fail("REL-010 observed manifest has invalid source observation")
    parse_timestamp(record.get("observedAt"), "REL-010 observedAt")
    evidence = record.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        fail("REL-010 observed manifest has no evidence")
    m6_entries = [
        entry
        for entry in evidence
        if isinstance(entry, dict) and entry.get("id") == "M6-EXIT"
    ]
    if len(m6_entries) != 1 or set(m6_entries[0]) != {"id", "sha256"}:
        fail("REL-010 observed manifest does not bind M6-EXIT exactly once")
    if require_sha(m6_entries[0].get("sha256"), "REL-010 M6-EXIT SHA-256") != m6_exit_sha:
        fail("REL-010 observed manifest binds a different M6-EXIT")



def _validate_lineage(arguments: argparse.Namespace, *, include_contract: bool) -> None:
    expected_paths = {
        "readiness": READINESS_OUTPUT,
        "rc": RC_OUTPUT,
        "m6_exit": M6_EXIT_OUTPUT,
        "rel_010": "Evidence/runtime/REL-010.json",
        "phase_05": "Evidence/runtime/REL-PHASE-05.json",
        "phase_25": "Evidence/runtime/REL-PHASE-25.json",
        "phase_50": "Evidence/runtime/REL-PHASE-50.json",
        "phase_100": "Evidence/runtime/REL-PHASE-100.json",
        "postrelease": "Evidence/runtime/REL-014.json",
    }
    if include_contract:
        expected_paths["contract"] = "Evidence/runtime/REL-CONTRACT.json"
    for key, expected in expected_paths.items():
        assert_exact_path(getattr(arguments, key), expected, f"--{key.replace('_', '-')}")
    root = repository_root()
    readiness, readiness_digest = verify_readiness(root, arguments.readiness)
    tag = require_tag(readiness["tag"], "readiness tag")
    commit = require_commit(readiness["commit"], "readiness commit")
    rc, rc_digest = verify_rc(root, arguments.rc)
    if rc["tag"] != tag or rc["commit"] != commit:
        fail("lineage RC is cross-tag or cross-commit")

    m6_exit, m6_exit_digest = verify_m6_exit(root, arguments.m6_exit)
    if m6_exit["tag"] != tag or m6_exit["commit"] != commit:
        fail("lineage M6-EXIT is cross-tag or cross-commit")
    if require_sha(m6_exit.get("buildDigest"), "M6-EXIT buildDigest") != require_sha(rc.get("buildDigest"), "RC buildDigest"):
        fail("lineage M6-EXIT is bound to a different RC build")

    rel008, _rel008_digest = verify_passed_record(
        root,
        "Evidence/runtime/REL-008.json",
        "REL-008",
        commit,
        tag=tag,
    )
    if rel008.get("artifactType") != "release-transition-controller":
        fail("REL-008 must be a canonical transition controller receipt")

    rel010, _rel010_digest = verify_passed_record(root, arguments.rel_010, "REL-010", commit, tag=tag)
    if (
        rel010.get("artifactType") != "release-transition-controller"
        or rel010.get("expectedEventSHA256") != rel008.get("eventSHA256")
    ):
        fail("REL-010 does not bind the exact REL-008 predecessor event")
    if rel010.get("rcManifestSHA256") != rc_digest or rel010.get("m6ExitSHA256") != m6_exit_digest:
        fail("REL-010 does not bind the exact RC and M6-EXIT artifacts")
    verify_transition_context((("REL-008", rel008), ("REL-010", rel010)), tag=tag, commit=commit)
    verify_activate_observed_manifest(
        root,
        tag=tag,
        commit=commit,
        build_digest=require_sha(rc.get("buildDigest"), "RC buildDigest"),
        release_id=rel010["releaseID"],
        data_sha=rel010["dataSHA256"],
        migration_sha=rel010["migrationSHA256"],
        expected_event_sha=rel008["eventSHA256"],
        m6_exit_sha=m6_exit_digest,
        controller_observed_sha=rel010["observedInputSHA256"],
    )

    previous_event_sha = rel010["eventSHA256"]
    phase_records: list[tuple[str, str, str]] = [
        ("REL-PHASE-05", arguments.phase_05, "REL-PHASE-05"),
        ("REL-PHASE-25", arguments.phase_25, "REL-PHASE-25"),
        ("REL-PHASE-50", arguments.phase_50, "REL-PHASE-50"),
        ("REL-PHASE-100", arguments.phase_100, "REL-PHASE-100"),
    ]
    final_phase_digest = ""
    for label, path, evidence_id in phase_records:
        phase, phase_digest = verify_passed_record(root, path, evidence_id, commit, tag=tag)
        if phase.get("artifactType") != "release-transition-controller":
            fail(f"{label} must be a canonical transition controller receipt")
        verify_transition_context((("REL-008", rel008), (label, phase)), tag=tag, commit=commit)
        if phase.get("expectedEventSHA256") != previous_event_sha:
            fail(f"{label} does not bind the exact immediate predecessor event")
        if phase.get("eventSHA256") == phase.get("expectedEventSHA256"):
            fail(f"{label} self-references")
        if phase.get("rcManifestSHA256") != rc_digest or phase.get("m6ExitSHA256") != m6_exit_digest:
            fail(f"{label} does not bind the exact RC and M6-EXIT artifacts")
        previous_event_sha = phase["eventSHA256"]
        final_phase_digest = phase_digest

    postrelease, postrelease_digest = verify_passed_record(
        root,
        arguments.postrelease,
        "REL-014",
        commit,
        tag=tag,
    )
    postrelease_predecessor = record_predecessor(postrelease, "REL-014")
    if postrelease_predecessor == postrelease_digest:
        fail("REL-014 self-references")
    if postrelease_predecessor != final_phase_digest:
        fail("REL-014 does not bind the exact REL-PHASE-100 artifact")
    if protected_build_digest(postrelease, "REL-014") != require_sha(rc.get("buildDigest"), "RC buildDigest"):
        fail("REL-014 is bound to a different release build")

    if include_contract:
        contract, _contract_digest = verify_passed_record(
            root,
            arguments.contract,
            "REL-CONTRACT",
            commit,
            tag=tag,
        )
        if contract.get("artifactType") != "release-transition-controller":
            fail("REL-CONTRACT must be a canonical transition controller receipt")
        verify_transition_context((("REL-008", rel008), ("REL-CONTRACT", contract)), tag=tag, commit=commit)
        if contract.get("expectedEventSHA256") != previous_event_sha:
            fail("REL-CONTRACT does not bind the exact REL-PHASE-100 predecessor event")
        if contract.get("rcManifestSHA256") != rc_digest or contract.get("m6ExitSHA256") != m6_exit_digest:
            fail("REL-CONTRACT does not bind the exact RC and M6-EXIT artifacts")
    if readiness_digest == rc_digest:
        fail("readiness and RC manifest hashes must differ")


def validate_pre_contract(arguments: argparse.Namespace) -> None:
    _validate_lineage(arguments, include_contract=False)


def validate_lineage(arguments: argparse.Namespace) -> None:
    _validate_lineage(arguments, include_contract=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Validate or immutably assemble the M6/M7 release evidence lineage.",
        allow_abbrev=False,
    )
    commands = result.add_subparsers(dest="command", required=True)

    readiness = commands.add_parser("assemble-readiness", allow_abbrev=False)
    readiness.add_argument("--tag", required=True)
    readiness.add_argument("--commit", required=True)
    readiness.add_argument("--output", required=True)
    readiness.set_defaults(handler=assemble_readiness)

    rc = commands.add_parser("assemble-rc", allow_abbrev=False)
    rc.add_argument("--readiness", required=True)
    rc.add_argument("--rel-002", dest="rel_002", required=True)
    rc.add_argument("--rel-003", dest="rel_003", required=True)
    rc.add_argument("--rel-004", dest="rel_004", required=True)
    rc.add_argument("--rel-005", dest="rel_005", required=True)
    rc.add_argument("--rel-006", dest="rel_006", required=True)
    rc.add_argument("--rel-008", dest="rel_008", required=True)
    rc.add_argument("--rel-009", dest="rel_009", required=True)
    rc.add_argument("--ops-005", dest="ops_005", required=True)
    rc.add_argument("--perf", required=True)
    rc.add_argument("--auth", required=True)
    rc.add_argument("--approval", required=True)
    rc.add_argument("--output-manifest", dest="output_manifest", required=True)
    rc.add_argument("--output", required=True)
    rc.set_defaults(handler=assemble_rc)

    m6_exit = commands.add_parser("assemble-m6-exit", allow_abbrev=False)
    m6_exit.add_argument("--rc", required=True)
    m6_exit.add_argument("--ops-003", dest="ops_003", required=True)
    m6_exit.add_argument("--ops-004", dest="ops_004", required=True)
    m6_exit.add_argument("--perf", required=True)
    m6_exit.add_argument("--beta", required=True)
    m6_exit.add_argument("--threshold", required=True)
    m6_exit.add_argument("--auth", required=True)
    m6_exit.add_argument("--approval", required=True)
    m6_exit.add_argument("--output", required=True)
    m6_exit.set_defaults(handler=assemble_m6_exit)

    drill = commands.add_parser("produce-switch-drill", allow_abbrev=False)
    drill.add_argument("--previous-event-sha", dest="previous_event_sha", required=True)
    drill.add_argument("--output", required=True)
    drill.set_defaults(handler=produce_switch_drill)

    lineage = commands.add_parser("validate", allow_abbrev=False)
    lineage.add_argument("--readiness", required=True)
    lineage.add_argument("--rc", required=True)
    lineage.add_argument("--m6-exit", dest="m6_exit", required=True)
    lineage.add_argument("--rel-010", dest="rel_010", required=True)
    lineage.add_argument("--phase-05", dest="phase_05", required=True)
    lineage.add_argument("--phase-25", dest="phase_25", required=True)
    lineage.add_argument("--phase-50", dest="phase_50", required=True)
    lineage.add_argument("--phase-100", dest="phase_100", required=True)
    lineage.add_argument("--postrelease", required=True)
    lineage.add_argument("--contract", required=True)
    lineage.set_defaults(handler=validate_lineage)

    pre_contract = commands.add_parser("validate-pre-contract", allow_abbrev=False)
    pre_contract.add_argument("--readiness", required=True)
    pre_contract.add_argument("--rc", required=True)
    pre_contract.add_argument("--m6-exit", dest="m6_exit", required=True)
    pre_contract.add_argument("--rel-010", dest="rel_010", required=True)
    pre_contract.add_argument("--phase-05", dest="phase_05", required=True)
    pre_contract.add_argument("--phase-25", dest="phase_25", required=True)
    pre_contract.add_argument("--phase-50", dest="phase_50", required=True)
    pre_contract.add_argument("--phase-100", dest="phase_100", required=True)
    pre_contract.add_argument("--postrelease", required=True)
    pre_contract.set_defaults(handler=validate_pre_contract)
    return result


def main(argv: list[str]) -> int:
    try:
        arguments = parser().parse_args(argv)
        arguments.handler(arguments)
        print(f"{arguments.command} passed")
        return 0
    except ReleaseError as error:
        print(f"release lineage error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
