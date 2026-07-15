#!/usr/bin/env python3
"""Emit redacted runtime evidence for operational and protected preflight gates."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn, Optional

ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
SHA1_RE = re.compile(r"^[a-f0-9]{40}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
INPUT_HASH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*SHA256$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RELEASE_TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SENSITIVE_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b|"
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    r"(?:authorization|bearer|password|secret|token|cookie|credential)\s*[:=])"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<![0-9])\+[1-9][0-9]{7,14}(?![0-9])")
FORBIDDEN_KEY_RE = re.compile(r"(?i)(?:password|secret|token|credential|authorization|cookie|email|phone|name|login|payload)")
VERSION_RE = r"\d+(?:\.\d+)+"
PROVIDER_INPUT_ENV = "HIKER_PROVIDER_GATE_INPUT"
PREFLIGHT_ENVIRONMENT = "staging"
PREFLIGHT_OIDC_AUDIENCE = "hiker-auth-preflight-v1"
PREFLIGHT_SOURCE_ENV = "HIKER_AUTH_PREFLIGHT_SOURCE_PATH"
PREFLIGHT_SOURCE_SIGNATURE_ENV = "HIKER_AUTH_PREFLIGHT_SOURCE_SIGNATURE_PATH"
PREFLIGHT_SOURCE_PUBLIC_KEY_ENV = "HIKER_AUTH_PREFLIGHT_SOURCE_PUBLIC_KEY_BASE64"
MAX_PREFLIGHT_INPUT_AGE = timedelta(hours=24)
PREFLIGHT_FUTURE_SKEW = timedelta(minutes=5)
PITR_PROTECTED_ENVIRONMENT = "staging"
PITR_PROTECTED_OIDC_AUDIENCE = "hiker-pitr-restore-v1"
PITR_PROTECTED_SOURCE_ENV = "HIKER_PITR_PREFLIGHT_SOURCE_PATH"
PITR_PROTECTED_SOURCE_SIGNATURE_ENV = "HIKER_PITR_PREFLIGHT_SOURCE_SIGNATURE_PATH"
PITR_PROTECTED_SOURCE_PUBLIC_KEY_ENV = "HIKER_PITR_PREFLIGHT_SOURCE_PUBLIC_KEY_BASE64"
PITR_PROTECTED_MIGRATION_SET_ENV = "HIKER_PITR_PREFLIGHT_MIGRATION_SET_SHA256"
PITR_PROTECTED_BACKUP_ENV = "HIKER_PITR_PREFLIGHT_BACKUP_SHA256"
PITR_PROTECTED_DATASET_ENV = "HIKER_PITR_PREFLIGHT_DATASET_SHA256"
PITR_PROTECTED_RELEASE_TAG_SIGNING_FINGERPRINT_ENV = "HIKER_PITR_PREFLIGHT_RELEASE_TAG_SIGNING_FINGERPRINT"
SECURITY_WORKFLOW_PATH = ".github/workflows/ci-security.yml"
RELEASE_WORKFLOW_PATH = ".github/workflows/release-evidence.yml"
RELEASE_WORKFLOW_NAME = "Release Evidence"
RELEASE_OIDC_AUDIENCE = "hiker-release-evidence-v1"
RELEASE_TAG_SIGNING_FINGERPRINT_ENV = "HIKER_RELEASE_TAG_SIGNING_FINGERPRINT"
PREFLIGHT_CONTRACTS = {
    "AUTH-005-PREFLIGHT-SERVER": {
        "checkKind": "protected-auth-preflight-server",
        "output": "Evidence/runtime/AUTH-005-PREFLIGHT-SERVER.json",
        "job": "preflight-auth-server",
    },
    "AUTH-005-PREFLIGHT-ARCHIVE": {
        "checkKind": "protected-auth-preflight-archive",
        "output": "Evidence/runtime/AUTH-005-PREFLIGHT-ARCHIVE.json",
        "job": "preflight-auth-archive",
    },
    "AUTH-005-PREFLIGHT": {
        "checkKind": "protected-auth-preflight-aggregate",
        "output": "Evidence/runtime/AUTH-005-PREFLIGHT.json",
        "job": "preflight-auth-aggregate",
    },
}
PITR_PROTECTED_CONTRACT = {
    "checkKind": "protected-pitr-restore",
    "output": "Evidence/runtime/MIG-005-PROTECTED.json",
    "job": "protected-pitr-restore",
}
RELEASE_EVIDENCE_CONTRACTS = {
    "AUTH-005-RC-SERVER": {"checkKind": "protected-rc-auth-server", "output": "Evidence/runtime/AUTH-005-RC-SERVER.json", "workflow": "release-evidence", "job": "rc-auth-server", "environment": "production", "route": "signed-source"},
    "AUTH-005-RC-ARCHIVE": {"checkKind": "protected-rc-auth-archive", "output": "Evidence/runtime/AUTH-005-RC-ARCHIVE.json", "workflow": "release-evidence", "job": "rc-auth-archive", "environment": "production", "route": "signed-source"},
    "AUTH-005-RC": {"checkKind": "protected-rc-auth-aggregate", "output": "Evidence/runtime/AUTH-005-RC.json", "workflow": "release-evidence", "job": "rc-auth-aggregate", "environment": "production", "route": "rc-auth-aggregate"},
    "OPS-003": {"checkKind": "protected-alert-drill", "output": "Evidence/runtime/OPS-003.json", "workflow": "release-evidence", "job": "alert-drill", "environment": "production", "route": "signed-source"},
    "OPS-004": {"checkKind": "protected-evidence-disposition", "output": "Evidence/runtime/OPS-004.json", "workflow": "release-evidence", "job": "evidence-disposition", "environment": "production", "route": "signed-source"},
    "OPS-005": {"checkKind": "protected-threshold-ratification", "output": "Evidence/runtime/OPS-005.json", "workflow": "release-evidence", "job": "threshold-ratification", "environment": "production", "route": "threshold"},
    "REL-001": {"checkKind": "release-readiness-assembly", "output": "Evidence/manifests/m6-readiness.json", "workflow": "release-evidence", "job": "readiness", "environment": "production", "route": "readiness"},
    "REL-002": {"checkKind": "release-transition-predeploy", "output": "Evidence/runtime/REL-002.json", "workflow": "release-evidence", "job": "migration-predeploy", "environment": "production", "route": "controller-source"},
    "REL-003": {"checkKind": "release-transition-compatibility", "output": "Evidence/runtime/REL-003.json", "workflow": "release-evidence", "job": "compat-synthetics", "environment": "production", "route": "controller-source"},
    "REL-004": {"checkKind": "protected-alpha-observation", "output": "Evidence/runtime/REL-004.json", "workflow": "release-evidence", "job": "internal-alpha", "environment": "staging", "route": "signed-source"},
    "REL-005": {"checkKind": "release-beta-floors", "output": "Evidence/runtime/REL-005.json", "workflow": "release-evidence", "job": "external-beta", "environment": "production", "route": "floors"},
    "REL-006": {"checkKind": "protected-metadata-observation", "output": "Evidence/runtime/REL-006.json", "workflow": "release-evidence", "job": "metadata-review", "environment": "production", "route": "signed-source"},
    "REL-007": {"checkKind": "release-rc-assembly", "output": "Evidence/runtime/REL-007.json", "workflow": "release-evidence", "job": "rc-freeze", "environment": "production", "route": "rc"},
    "REL-008": {"checkKind": "release-transition-pitr", "output": "Evidence/runtime/REL-008.json", "workflow": "release-evidence", "job": "pitr-drill", "environment": "production", "route": "controller-source"},
    "REL-009": {"checkKind": "release-switch-drill", "output": "Evidence/runtime/REL-009.json", "workflow": "release-evidence", "job": "kill-switch-drill", "environment": "production", "route": "switch"},
    "M6-EXIT": {"checkKind": "release-m6-exit-assembly", "output": "Evidence/runtime/M6-EXIT.json", "workflow": "release-evidence", "job": "m6-exit", "environment": "production", "route": "m6-exit"},
    "REL-010": {"checkKind": "release-transition-activate-1pct", "output": "Evidence/runtime/REL-010.json", "workflow": "release-evidence", "job": "rollout-1pct", "environment": "production", "route": "controller-source"},
    "REL-011-05": {"checkKind": "release-phase-floors-05", "output": "Evidence/runtime/REL-011-05.json", "workflow": "release-evidence", "job": "rollout-review-05", "environment": "production", "route": "floors"},
    "REL-PHASE-05": {"checkKind": "release-transition-phase-05", "output": "Evidence/runtime/REL-PHASE-05.json", "workflow": "release-evidence", "job": "rollout-phase-05", "environment": "production", "route": "controller-source"},
    "REL-011-25": {"checkKind": "release-phase-floors-25", "output": "Evidence/runtime/REL-011-25.json", "workflow": "release-evidence", "job": "rollout-review-25", "environment": "production", "route": "floors"},
    "REL-PHASE-25": {"checkKind": "release-transition-phase-25", "output": "Evidence/runtime/REL-PHASE-25.json", "workflow": "release-evidence", "job": "rollout-phase-25", "environment": "production", "route": "controller-source"},
    "REL-011-50": {"checkKind": "release-phase-floors-50", "output": "Evidence/runtime/REL-011-50.json", "workflow": "release-evidence", "job": "rollout-review-50", "environment": "production", "route": "floors"},
    "REL-PHASE-50": {"checkKind": "release-transition-phase-50", "output": "Evidence/runtime/REL-PHASE-50.json", "workflow": "release-evidence", "job": "rollout-phase-50", "environment": "production", "route": "controller-source"},
    "REL-011-100": {"checkKind": "release-phase-floors-100", "output": "Evidence/runtime/REL-011-100.json", "workflow": "release-evidence", "job": "rollout-review-100", "environment": "production", "route": "floors"},
    "REL-PHASE-100": {"checkKind": "release-transition-phase-100", "output": "Evidence/runtime/REL-PHASE-100.json", "workflow": "release-evidence", "job": "rollout-phase-100", "environment": "production", "route": "controller-source"},
    "REL-012": {"checkKind": "protected-tabletop-observation", "output": "Evidence/runtime/REL-012.json", "workflow": "release-evidence", "job": "rollback-tabletop", "environment": "production", "route": "signed-source"},
    "REL-013": {"checkKind": "protected-incident-observation", "output": "Evidence/runtime/REL-013.json", "workflow": "release-evidence", "job": "incident-comms", "environment": "production", "route": "signed-source"},
    "REL-014": {"checkKind": "protected-postrelease-observation", "output": "Evidence/runtime/REL-014.json", "workflow": "release-evidence", "job": "postrelease-review", "environment": "production", "route": "signed-source"},
    "REL-CONTRACT": {"checkKind": "release-transition-contract", "output": "Evidence/runtime/REL-CONTRACT.json", "workflow": "release-evidence", "job": "contract-remove-old", "environment": "production", "route": "controller-source"},
}
RELEASE_PROTECTED_SOURCE_RECEIPT_ENV = "HIKER_RELEASE_PROTECTED_SOURCE_RECEIPT_PATH"
RELEASE_PROTECTED_SOURCE_CONTRACTS = {
    "alert-drill": {"evidenceId": "OPS-003", "artifactBase": "alert-drill-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "contract-remove-old": {"evidenceId": "REL-CONTRACT", "artifactBase": "contract-remove-old-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "evidence-disposition": {"evidenceId": "OPS-004", "artifactBase": "evidence-disposition-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "incident-comms": {"evidenceId": "REL-013", "artifactBase": "incident-comms-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "internal-alpha": {"evidenceId": "REL-004", "artifactBase": "internal-alpha-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "metadata-review": {"evidenceId": "REL-006", "artifactBase": "metadata-review-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "migration-predeploy": {"evidenceId": "REL-002", "artifactBase": "migration-predeploy-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "compat-synthetics": {"evidenceId": "REL-003", "artifactBase": "compat-synthetics-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "pitr-drill": {"evidenceId": "REL-008", "artifactBase": "pitr-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "postrelease-review": {"evidenceId": "REL-014", "artifactBase": "postrelease-review-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rc-auth-archive": {"evidenceId": "AUTH-005-RC-ARCHIVE", "artifactBase": "rc-auth-archive-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rc-auth-server": {"evidenceId": "AUTH-005-RC-SERVER", "artifactBase": "rc-auth-server-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rollback-tabletop": {"evidenceId": "REL-012", "artifactBase": "rollback-tabletop-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rollout-1pct": {"evidenceId": "REL-010", "artifactBase": "rollout-1pct-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rollout-phase-05": {"evidenceId": "REL-PHASE-05", "artifactBase": "rollout-phase-05-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rollout-phase-25": {"evidenceId": "REL-PHASE-25", "artifactBase": "rollout-phase-25-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rollout-phase-50": {"evidenceId": "REL-PHASE-50", "artifactBase": "rollout-phase-50-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "rollout-phase-100": {"evidenceId": "REL-PHASE-100", "artifactBase": "rollout-phase-100-observation", "documentName": "release-observation.json", "signatureName": "release-observation.sig"},
    "threshold-ratification": {"evidenceId": "OPS-005", "artifactBase": "threshold-ratification-source", "documentName": "threshold-ratification.json", "signatureName": "threshold-ratification.sig"},
}
RELEASE_OBSERVATION_CHECKS = {
    "AUTH-005-RC-SERVER": {"issuerVerified", "audienceVerified", "testIdentityRejected"},
    "AUTH-005-RC-ARCHIVE": {"releaseArchiveScanned", "testSessionAbsent", "bypassAbsent", "testIssuerAbsent"},
    "OPS-003": {"alertDelivered", "suppressionVerified"},
    "OPS-004": {"releaseReceiptRetained", "issueReceiptRetained", "wormRetentionVerified", "accessDispositionVerified"},
    "REL-004": {"internalAlphaCompleted", "p0IncidentsAbsent", "p1IncidentsAbsent"},
    "REL-006": {"metadataReviewed", "privacyReviewed"},
    "REL-008": {"restoreCompleted", "grantsVerified", "rpcsVerified", "projectionsVerified", "historyVerified", "auditVerified"},
    "REL-002": {"stateObserved", "predecessorVerified", "thresholdsSatisfied"},
    "REL-003": {"stateObserved", "predecessorVerified", "thresholdsSatisfied"},
    "REL-010": {"stateObserved", "predecessorVerified", "thresholdsSatisfied"},
    "REL-PHASE-05": {"stateObserved", "predecessorVerified", "thresholdsSatisfied"},
    "REL-PHASE-25": {"stateObserved", "predecessorVerified", "thresholdsSatisfied"},
    "REL-PHASE-50": {"stateObserved", "predecessorVerified", "thresholdsSatisfied"},
    "REL-PHASE-100": {"stateObserved", "predecessorVerified", "thresholdsSatisfied"},
    "REL-012": {"containmentVerified", "rollbackVerified"},
    "REL-013": {"incidentCommunicationVerified", "redactionVerified"},
    "REL-014": {"sevenDayReviewCompleted", "thirtyDayReviewCompleted"},
    "REL-CONTRACT": {"retentionVerified", "oldContractRemovalSafe"},
}
CONTROLLER_SOURCE_STATES = {
    "REL-002": ("predeploy-disabled", 0),
    "REL-003": ("compatibility", 1),
    "REL-008": ("pitr-proof", 2),
    "REL-010": ("activate-1pct", 3),
    "REL-PHASE-05": ("phase-5", 4),
    "REL-PHASE-25": ("phase-25", 5),
    "REL-PHASE-50": ("phase-50", 6),
    "REL-PHASE-100": ("phase-100", 7),
    "REL-CONTRACT": ("contract-remove-old", 8),
}
PROFILE_CONTRACTS = {
    "OPS-001": {"checkKind": "toolchain-contract", "output": "Evidence/runtime/OPS-001.json"},
    "OPS-002": {"checkKind": "provider-approval", "output": "Evidence/runtime/OPS-002.json"},
    **{evidence_id: {"checkKind": contract["checkKind"], "output": contract["output"]} for evidence_id, contract in PREFLIGHT_CONTRACTS.items()},
    "MIG-005-PROTECTED": {"checkKind": PITR_PROTECTED_CONTRACT["checkKind"], "output": PITR_PROTECTED_CONTRACT["output"]},
    **{evidence_id: {"checkKind": contract["checkKind"], "output": contract["output"]} for evidence_id, contract in RELEASE_EVIDENCE_CONTRACTS.items()},
}
PROVIDER_APPROVALS = (
    ("region", "REGION", "regionApproved", "regionEvidenceSHA256"),
    ("dpa", "DPA", "dpaApproved", "dpaEvidenceSHA256"),
    ("appleOAuth", "APPLE_OAUTH", "appleOAuthApproved", "appleOAuthEvidenceSHA256"),
    ("privateStream", "PRIVATE_STREAM", "privateStreamApproved", "privateStreamEvidenceSHA256"),
    ("audit", "AUDIT", "auditApproved", "auditEvidenceSHA256"),
    ("rateLimit", "RATE_LIMIT", "rateLimitApproved", "rateLimitEvidenceSHA256"),
    ("pitr", "PITR", "pitrApproved", "pitrEvidenceSHA256"),
)


class EvidenceError(Exception):
    pass


def fail() -> NoReturn:
    raise EvidenceError


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(value: Any) -> str:
    if isinstance(value, bytes):
        data = value
    else:
        data = canonical_bytes(value)
    return hashlib.sha256(data).hexdigest()


def repository_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        fail()
    try:
        root = Path(result.stdout.decode("utf-8", "strict").strip()).resolve(strict=True)
    except (OSError, UnicodeError):
        fail()
    if not root.is_dir():
        fail()
    return root


def repository_file(root: Path, raw_path: str) -> Path:
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or relative.as_posix() != raw_path or any(part in {".", ".."} for part in relative.parts):
        fail()
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            fail()
    try:
        current.relative_to(root)
    except ValueError:
        fail()
    if not current.is_file():
        fail()
    return current


def read_limited(path: Path, limit: int) -> bytes:
    try:
        data = path.read_bytes()
    except OSError:
        fail()
    if not data or len(data) > limit:
        fail()
    return data


def decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail()


def require_git_revision(root: Path) -> str:
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    try:
        revision = head.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        fail()
    if head.returncode != 0 or status.returncode != 0 or status.stdout or not SHA1_RE.fullmatch(revision):
        fail()
    return revision


def source_tool_contract(root: Path) -> tuple[dict[str, str], str]:
    mise = decode_text(read_limited(repository_file(root, ".mise.toml"), 64 * 1024))
    workflow = decode_text(read_limited(repository_file(root, ".github/workflows/ci-security.yml"), 256 * 1024))

    tools: dict[str, str] = {}
    in_tools = False
    assignment = re.compile(rf"^([a-z0-9_-]+)\s*=\s*\"({VERSION_RE})\"\s*(?:#.*)?$")
    for line in mise.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "[tools]":
            if in_tools:
                fail()
            in_tools = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_tools = False
            continue
        if in_tools:
            match = assignment.fullmatch(stripped)
            if match is None:
                fail()
            name, version = match.groups()
            if name in tools:
                fail()
            tools[name] = version

    required_tools = {"supabase", "postgres", "pgtap"}
    if not required_tools.issubset(tools):
        fail()

    developer_dirs = set(
        re.findall(r"DEVELOPER_DIR:\s*(/Applications/Xcode_" + f"({VERSION_RE})" + r"\.app/Contents/Developer)", workflow)
    )
    xcode_assertions = set(re.findall(r"Xcode\s+(" + VERSION_RE + r")\\nBuild version", workflow))
    swift_assertions = set(re.findall(r"Swift version\s+(" + VERSION_RE + r")\s", workflow))
    if len(developer_dirs) != 1 or len(xcode_assertions) != 1 or len(swift_assertions) != 1:
        fail()
    developer_dir, xcode_from_path = next(iter(developer_dirs))
    xcode_version = next(iter(xcode_assertions))
    swift_version = next(iter(swift_assertions))
    if xcode_from_path != xcode_version:
        fail()

    return (
        {
            "xcode": xcode_version,
            "swift": swift_version,
            "supabase": tools["supabase"],
            "postgres": tools["postgres"],
            "pgtap": tools["pgtap"],
        },
        developer_dir,
    )


def run_tool(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail()
    if result.returncode != 0 or len(result.stdout) > 16 * 1024:
        fail()
    return decode_text(result.stdout)


def exact_version(output: str, expression: str) -> str:
    match = re.fullmatch(expression, output)
    if match is None:
        fail()
    return match.group("version")


def pgtap_version() -> str:
    sharedir = run_tool(["pg_config", "--sharedir"])
    match = re.fullmatch(r"(?P<path>/[^\r\n\x00]+)\r?\n?", sharedir)
    if match is None:
        fail()
    control = Path(match.group("path")) / "extension" / "pgtap.control"
    try:
        if control.is_symlink() or not control.is_file():
            fail()
    except OSError:
        fail()
    contents = decode_text(read_limited(control, 64 * 1024))
    versions = re.findall(r"(?m)^\s*default_version\s*=\s*'(" + VERSION_RE + r")'\s*$", contents)
    if len(versions) != 1:
        fail()
    return versions[0]


def toolchain_checks(root: Path) -> tuple[list[dict[str, str]], dict[str, str]]:
    contract, developer_dir = source_tool_contract(root)
    if os.environ.get("DEVELOPER_DIR") != developer_dir:
        fail()

    facts = {
        "xcode": exact_version(
            run_tool(["xcodebuild", "-version"]),
            r"Xcode (?P<version>" + VERSION_RE + r")\r?\nBuild version [A-Za-z0-9._-]+\r?\n?",
        ),
        "swift": exact_version(
            run_tool(["xcrun", "swift", "--version"]),
            r"Swift version (?P<version>" + VERSION_RE + r")(?: [^\r\n]+)?\r?\nTarget: [A-Za-z0-9._-]+\r?\n?",
        ),
        "supabase": exact_version(run_tool(["supabase", "--version"]), r"v?(?P<version>" + VERSION_RE + r")\r?\n?"),
        "postgres": exact_version(
            run_tool(["postgres", "--version"]),
            r"postgres \(PostgreSQL\) (?P<version>" + VERSION_RE + r")(?: [^\r\n]+)?\r?\n?",
        ),
        "pgtap": pgtap_version(),
    }
    checks: list[dict[str, str]] = []
    for name, code in (("xcode", "XCODE_VERSION"), ("swift", "SWIFT_VERSION"), ("supabase", "SUPABASE_VERSION"), ("postgres", "POSTGRES_VERSION"), ("pgtap", "PGTAP_VERSION")):
        if facts[name] != contract[name]:
            fail()
        checks.append(
            {
                "code": code,
                "outcome": "passed",
                "evidenceSHA256": sha256({"expected": contract[name], "observed": facts[name], "outcome": "passed"}),
            }
        )
    return checks, {"toolContractSHA256": sha256(contract), "runtimeFactsSHA256": sha256(facts)}


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail()
        value[key] = item
    return value


def reject_constant(_value: str) -> None:
    fail()


def provider_input(root: Path) -> tuple[list[dict[str, str]], dict[str, str]]:
    raw_path = os.environ.get(PROVIDER_INPUT_ENV)
    if raw_path is None or not raw_path or "\x00" in raw_path or any(ord(character) < 32 for character in raw_path):
        fail()
    candidate = Path(raw_path)
    if not candidate.is_absolute() or candidate.is_symlink():
        fail()
    try:
        source = candidate.resolve(strict=True)
        source.relative_to(root)
    except ValueError:
        pass
    except OSError:
        fail()
    else:
        fail()
    try:
        details = source.stat()
    except OSError:
        fail()
    if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o077:
        fail()
    raw = read_limited(source, 64 * 1024)
    try:
        document = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_object, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()

    expected_fields = {"schemaVersion"}
    for _name, _code, approved_field, digest_field in PROVIDER_APPROVALS:
        expected_fields.add(approved_field)
        expected_fields.add(digest_field)
    if not isinstance(document, dict) or set(document) != expected_fields or type(document.get("schemaVersion")) is not int or document["schemaVersion"] != 1:
        fail()

    checks: list[dict[str, str]] = []
    for _name, code, approved_field, digest_field in PROVIDER_APPROVALS:
        if type(document[approved_field]) is not bool or document[approved_field] is not True:
            fail()
        digest = document[digest_field]
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            fail()
        checks.append({"code": f"PROVIDER_{code}", "outcome": "passed", "evidenceSHA256": digest})

    approval_contract = {
        "schemaVersion": 1,
        "approvals": [
            {"name": name, "approvedField": approved_field, "digestField": digest_field}
            for name, _code, approved_field, digest_field in PROVIDER_APPROVALS
        ],
    }
    return checks, {
        "providerApprovalSHA256": sha256(raw),
        "providerApprovalContractSHA256": sha256(approval_contract),
    }


@dataclass(frozen=True)
class ProtectedContext:
    repository: str
    run_id: str
    release_tag: str
    git_sha: str
    build_digest: str
    job: str

@dataclass(frozen=True)
class PitrProtectedContext(ProtectedContext):
    dataset_sha256: str
    migration_set_sha256: str
    backup_sha256: str

def reject_sensitive_data(value: Any) -> None:
    if isinstance(value, str):
        if (
            not value
            or any(ord(character) < 32 or ord(character) > 126 for character in value)
            or SENSITIVE_RE.search(value) is not None
            or EMAIL_RE.search(value) is not None
            or PHONE_RE.search(value) is not None
        ):
            fail()
        return
    if isinstance(value, list):
        for item in value:
            reject_sensitive_data(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or FORBIDDEN_KEY_RE.search(key) is not None:
                fail()
            reject_sensitive_data(item)
        return
    if type(value) not in {bool, int}:
        fail()


def parse_canonical_document(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        fail()
    reject_sensitive_data(value)
    return value


def parse_preflight_timestamp(value: Any) -> str:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        fail()
    try:
        timestamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail()
    now = datetime.now(timezone.utc)
    if timestamp > now + PREFLIGHT_FUTURE_SKEW or now - timestamp > MAX_PREFLIGHT_INPUT_AGE:
        fail()
    return value


def parse_utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        fail()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail()


def require_sha256(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail()
    return value


def current_git_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    try:
        revision = result.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        fail()
    if result.returncode != 0 or SHA1_RE.fullmatch(revision) is None:
        fail()
    return revision


def verify_signed_release_tag(root: Path, release_tag: str, git_sha: str, fingerprint_environment: str) -> None:
    fingerprint = os.environ.get(fingerprint_environment, "").upper()
    if re.fullmatch(r"[A-F0-9]{40,64}", fingerprint) is None:
        fail()
    resolved = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{release_tag}^{{}}"],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    verified = subprocess.run(
        ["git", "-C", str(root), "verify-tag", "--raw", release_tag],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    try:
        tag_sha = resolved.stdout.decode("ascii", "strict").strip()
        status = (verified.stdout + verified.stderr).decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail()
    if (
        resolved.returncode != 0
        or verified.returncode != 0
        or tag_sha != git_sha
        or f"[GNUPG:] VALIDSIG {fingerprint} " not in status
    ):
        fail()


def github_json(url: str, token: str) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hiker-auth-preflight-evidence",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != url:
                fail()
            raw = response.read(512 * 1024 + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError):
        fail()
    if not raw or len(raw) > 512 * 1024:
        fail()
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_object, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()
    if not isinstance(value, dict):
        fail()
    return value


def require_live_github_job(
    context: ProtectedContext,
    workflow_name: str = "Security CI",
    workflow_path: str = SECURITY_WORKFLOW_PATH,
) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if token is None or not token or any(ord(character) < 33 or ord(character) > 126 for character in token):
        fail()
    base_url = f"https://api.github.com/repos/{context.repository}/actions"
    run = github_json(f"{base_url}/runs/{context.run_id}", token)
    workflow_id = run.get("workflow_id")
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != context.git_sha
        or run.get("head_branch") != context.release_tag
        or run.get("name") != workflow_name
        or run.get("status") != "in_progress"
        or run.get("path") != f"{workflow_path}@{context.release_tag}"
        or type(workflow_id) is not int
        or workflow_id <= 0
    ):
        fail()
    workflow = github_json(f"{base_url}/workflows/{workflow_id}", token)
    if (
        workflow.get("id") != workflow_id
        or workflow.get("name") != workflow_name
        or workflow.get("path") != workflow_path
        or workflow.get("state") != "active"
    ):
        fail()
    jobs = github_json(f"{base_url}/runs/{context.run_id}/jobs?per_page=100", token)
    values = jobs.get("jobs")
    if not isinstance(values, list):
        fail()
    matching = [job for job in values if isinstance(job, dict) and job.get("name") == context.job]
    if len(matching) != 1 or matching[0].get("status") != "in_progress":
        fail()


def base64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        fail()
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        fail()


def jwt_json(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(base64url_decode(value).decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_object, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()
    if not isinstance(decoded, dict):
        fail()
    return decoded


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def der_integer(value: bytes) -> bytes:
    encoded = value.lstrip(b"\x00") or b"\x00"
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + der_length(len(encoded)) + encoded


def der_sequence(*values: bytes) -> bytes:
    body = b"".join(values)
    return b"\x30" + der_length(len(body)) + body


def rsa_public_key_pem(modulus: str, exponent: str) -> bytes:
    body = der_sequence(der_integer(base64url_decode(modulus)), der_integer(base64url_decode(exponent)))
    encoded = base64.encodebytes(body).replace(b"\n", b"")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return b"-----BEGIN RSA PUBLIC KEY-----\n" + b"\n".join(lines) + b"\n-----END RSA PUBLIC KEY-----\n"


def verify_rs256(message: bytes, signature: bytes, modulus: str, exponent: str) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="auth-preflight-oidc-") as directory:
            root = Path(directory)
            key = root / "key.pem"
            body = root / "body"
            signed = root / "signature"
            key.write_bytes(rsa_public_key_pem(modulus, exponent))
            body.write_bytes(message)
            signed.write_bytes(signature)
            for path in (key, body, signed):
                path.chmod(0o600)
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signed), str(body)],
                check=False,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=30,
            )
    except (OSError, subprocess.TimeoutExpired):
        fail()
    if result.returncode != 0:
        fail()


def require_oidc_identity(
    context: ProtectedContext,
    audience: str = PREFLIGHT_OIDC_AUDIENCE,
    environment: str = PREFLIGHT_ENVIRONMENT,
    workflow_name: str = "Security CI",
    workflow_path: str = SECURITY_WORKFLOW_PATH,
) -> None:
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if request_url is None or request_token is None or not request_token:
        fail()
    try:
        parsed = urllib.parse.urlsplit(request_url)
    except ValueError:
        fail()
    if (
        parsed.scheme != "https"
        or parsed.hostname != "pipelines.actions.githubusercontent.com"
        or parsed.username is not None
        or parsed.password is not None
    ):
        fail()
    separator = "&" if parsed.query else "?"
    endpoint = f"{request_url}{separator}{urllib.parse.urlencode({'audience': audience})}"
    request = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {request_token}"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != endpoint:
                fail()
            raw = response.read(32 * 1024 + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError):
        fail()
    if not raw or len(raw) > 32 * 1024:
        fail()
    try:
        issued = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_object, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()
    if not isinstance(issued, dict) or set(issued) != {"value"} or not isinstance(issued["value"], str):
        fail()
    parts = issued["value"].split(".")
    if len(parts) != 3:
        fail()
    header = jwt_json(parts[0])
    claims = jwt_json(parts[1])
    signature = base64url_decode(parts[2])
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str) or not header["kid"]:
        fail()
    configuration = github_json("https://token.actions.githubusercontent.com/.well-known/openid-configuration", "")
    if not {"issuer", "jwks_uri"}.issubset(configuration) or configuration["issuer"] != "https://token.actions.githubusercontent.com":
        fail()
    jwks_url = configuration["jwks_uri"]
    if jwks_url != "https://token.actions.githubusercontent.com/.well-known/jwks":
        fail()
    jwks = github_json(jwks_url, "")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        fail()
    matches = [
        key
        for key in keys
        if isinstance(key, dict)
        and key.get("kid") == header["kid"]
        and key.get("kty") == "RSA"
        and key.get("alg") in {None, "RS256"}
        and isinstance(key.get("n"), str)
        and isinstance(key.get("e"), str)
    ]
    if len(matches) != 1:
        fail()
    verify_rs256(f"{parts[0]}.{parts[1]}".encode("ascii"), signature, matches[0]["n"], matches[0]["e"])
    now = int(time.time())
    if (
        claims.get("iss") != "https://token.actions.githubusercontent.com"
        or claims.get("aud") != audience
        or claims.get("repository") != context.repository
        or claims.get("workflow") != workflow_name
        or claims.get("event_name") != "workflow_dispatch"
        or claims.get("ref") != f"refs/tags/{context.release_tag}"
        or claims.get("ref_type") != "tag"
        or claims.get("sha") != context.git_sha
        or claims.get("run_id") != context.run_id
        or claims.get("environment") != environment
        or claims.get("sub") != f"repo:{context.repository}:environment:{environment}"
        or claims.get("workflow_ref") != f"{context.repository}/{workflow_path}@refs/tags/{context.release_tag}"
        or any(type(claims.get(field)) is not int for field in ("iat", "nbf", "exp"))
        or claims["nbf"] > now + 60
        or claims["iat"] > now + 60
        or claims["exp"] < now - 60
        or claims["exp"] - claims["iat"] > 900
    ):
        fail()


def require_staging_protected_context(
    root: Path,
    contract: dict[str, str],
    protected_environment_variable: str,
    build_digest_variable: str,
    release_tag_fingerprint_variable: str,
    oidc_audience: str,
    environment: str,
) -> ProtectedContext:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_WORKFLOW") != "Security CI"
        or os.environ.get("GITHUB_JOB") != contract["job"]
        or os.environ.get(protected_environment_variable) != environment
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
    ):
        fail()
    run_id = os.environ.get("GITHUB_RUN_ID")
    repository = os.environ.get("GITHUB_REPOSITORY")
    release_tag = os.environ.get("GITHUB_REF_NAME")
    git_sha = os.environ.get("GITHUB_SHA")
    build_digest = os.environ.get(build_digest_variable)
    if (
        run_id is None
        or RUN_ID_RE.fullmatch(run_id) is None
        or repository is None
        or REPOSITORY_RE.fullmatch(repository) is None
        or release_tag is None
        or RELEASE_TAG_RE.fullmatch(release_tag) is None
        or os.environ.get("GITHUB_REF") != f"refs/tags/{release_tag}"
        or git_sha is None
        or SHA1_RE.fullmatch(git_sha) is None
        or build_digest is None
        or SHA256_RE.fullmatch(build_digest) is None
    ):
        fail()
    context = ProtectedContext(repository, run_id, release_tag, git_sha, build_digest, contract["job"])
    if current_git_revision(root) != context.git_sha:
        fail()
    verify_signed_release_tag(root, context.release_tag, context.git_sha, release_tag_fingerprint_variable)
    require_live_github_job(context)
    require_oidc_identity(context, oidc_audience, environment)
    return context


def require_protected_context(root: Path, evidence_id: str) -> ProtectedContext:
    return require_staging_protected_context(
        root,
        PREFLIGHT_CONTRACTS[evidence_id],
        "HIKER_AUTH_PREFLIGHT_PROTECTED_ENVIRONMENT",
        "HIKER_AUTH_PREFLIGHT_BUILD_DIGEST",
        "HIKER_AUTH_PREFLIGHT_RELEASE_TAG_SIGNING_FINGERPRINT",
        PREFLIGHT_OIDC_AUDIENCE,
        PREFLIGHT_ENVIRONMENT,
    )


def require_pitr_protected_context(root: Path) -> PitrProtectedContext:
    context = require_staging_protected_context(
        root,
        PITR_PROTECTED_CONTRACT,
        "HIKER_PITR_PREFLIGHT_PROTECTED_ENVIRONMENT",
        "HIKER_PITR_PREFLIGHT_BUILD_DIGEST",
        PITR_PROTECTED_RELEASE_TAG_SIGNING_FINGERPRINT_ENV,
        PITR_PROTECTED_OIDC_AUDIENCE,
        PITR_PROTECTED_ENVIRONMENT,
    )
    dataset_sha256 = os.environ.get(PITR_PROTECTED_DATASET_ENV)
    migration_set_sha256 = os.environ.get(PITR_PROTECTED_MIGRATION_SET_ENV)
    backup_sha256 = os.environ.get(PITR_PROTECTED_BACKUP_ENV)
    if (
        SHA256_RE.fullmatch(dataset_sha256 or "") is None
        or SHA256_RE.fullmatch(migration_set_sha256 or "") is None
        or SHA256_RE.fullmatch(backup_sha256 or "") is None
    ):
        fail()
    return PitrProtectedContext(
        context.repository,
        context.run_id,
        context.release_tag,
        context.git_sha,
        context.build_digest,
        context.job,
        dataset_sha256,
        migration_set_sha256,
        backup_sha256,
    )


def read_external_input(environment_name: str, limit: int) -> bytes:
    raw_path = os.environ.get(environment_name)
    runner_temp = os.environ.get("RUNNER_TEMP")
    if raw_path is None or runner_temp is None or not raw_path or "\x00" in raw_path:
        fail()
    candidate = Path(raw_path)
    temporary_root = Path(runner_temp)
    if not candidate.is_absolute() or candidate.is_symlink():
        fail()
    try:
        resolved_temporary_root = temporary_root.resolve(strict=True)
        source = candidate.resolve(strict=True)
    except OSError:
        fail()
    if source.parent != resolved_temporary_root or candidate.parent != temporary_root:
        fail()
    try:
        details = source.stat()
    except OSError:
        fail()
    if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o077 or details.st_size <= 0 or details.st_size > limit:
        fail()
    return read_limited(source, limit)


def decode_public_key(environment_name: str = PREFLIGHT_SOURCE_PUBLIC_KEY_ENV) -> bytes:
    encoded = os.environ.get(environment_name)
    if encoded is None or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is None:
        fail()
    try:
        key = base64.b64decode(encoded, validate=True)
    except ValueError:
        fail()
    if len(key) < 64 or len(key) > 32 * 1024 or b"BEGIN PUBLIC KEY" not in key:
        fail()
    return key


def require_ed25519_public_key(path: Path) -> None:
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(path), "-pubout", "-outform", "DER"],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail()
    if (
        result.returncode != 0
        or len(result.stdout) != 44
        or result.stdout[:12] != b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"
    ):
        fail()


def verify_detached_signature(document: bytes, signature: bytes, public_key: bytes) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="auth-preflight-source-") as directory:
            root = Path(directory)
            key = root / "source-public.pem"
            body = root / "source.json"
            signed = root / "source.sig"
            key.write_bytes(public_key)
            body.write_bytes(document)
            signed.write_bytes(signature)
            for path in (key, body, signed):
                path.chmod(0o600)
            require_ed25519_public_key(key)
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin", "-in", str(body), "-sigfile", str(signed)],
                check=False,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=30,
            )
    except (OSError, subprocess.TimeoutExpired):
        fail()
    if result.returncode != 0:
        fail()


def validate_rejection_probe(value: Any, expected_code: str) -> str:
    if (
        not isinstance(value, dict)
        or set(value) != {"outcome", "code", "probeSHA256"}
        or value.get("outcome") != "rejected"
        or value.get("code") != expected_code
    ):
        fail()
    return require_sha256(value["probeSHA256"])


def validate_server_source_document(document: dict[str, Any], context: ProtectedContext) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "artifactType",
        "signatureAlgorithm",
        "repository",
        "releaseTag",
        "commitSHA",
        "buildDigest",
        "workflowRunId",
        "job",
        "observedAt",
        "issuer",
        "audience",
        "testActor",
    }
    if (
        set(document) != required
        or type(document.get("schemaVersion")) is not int
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "staging-auth-preflight-server-observation"
        or document.get("signatureAlgorithm") != "ed25519"
        or document.get("repository") != context.repository
        or document.get("releaseTag") != context.release_tag
        or document.get("commitSHA") != context.git_sha
        or document.get("buildDigest") != context.build_digest
        or document.get("workflowRunId") != context.run_id
        or document.get("job") != context.job
    ):
        fail()
    observed_at = parse_preflight_timestamp(document["observedAt"])
    return {
        "sourceObservedAt": observed_at,
        "wrongIssuerRejected": {
            "code": "WRONG_ISSUER_REJECTED",
            "probeSHA256": validate_rejection_probe(document["issuer"], "WRONG_ISSUER_REJECTED"),
        },
        "wrongAudienceRejected": {
            "code": "WRONG_AUDIENCE_REJECTED",
            "probeSHA256": validate_rejection_probe(document["audience"], "WRONG_AUDIENCE_REJECTED"),
        },
        "testActorRejected": {
            "code": "TEST_IDENTITY_REJECTED",
            "probeSHA256": validate_rejection_probe(document["testActor"], "TEST_IDENTITY_REJECTED"),
        },
    }


def validate_archive_source_document(document: dict[str, Any], context: ProtectedContext) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "artifactType",
        "signatureAlgorithm",
        "repository",
        "releaseTag",
        "commitSHA",
        "buildDigest",
        "workflowRunId",
        "job",
        "observedAt",
        "archiveSHA256",
        "linkMapSHA256",
        "codeSigningMetadataSHA256",
        "archiveSignatureSHA256",
        "releaseConfiguration",
        "releaseArchiveSigned",
        "forbiddenSymbols",
    }
    expected_symbols = {"bypassSymbolsAbsent", "testSessionSymbolsAbsent", "testIssuerSymbolsAbsent"}
    if (
        set(document) != required
        or type(document.get("schemaVersion")) is not int
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "staging-auth-preflight-archive-observation"
        or document.get("signatureAlgorithm") != "ed25519"
        or document.get("repository") != context.repository
        or document.get("releaseTag") != context.release_tag
        or document.get("commitSHA") != context.git_sha
        or document.get("buildDigest") != context.build_digest
        or document.get("workflowRunId") != context.run_id
        or document.get("job") != context.job
        or document.get("archiveSHA256") != context.build_digest
        or document.get("releaseConfiguration") != "Release"
        or document.get("releaseArchiveSigned") is not True
        or not isinstance(document.get("forbiddenSymbols"), dict)
        or set(document["forbiddenSymbols"]) != expected_symbols
        or any(document["forbiddenSymbols"].get(symbol) is not True for symbol in expected_symbols)
    ):
        fail()
    observed_at = parse_preflight_timestamp(document["observedAt"])
    return {
        "sourceObservedAt": observed_at,
        "archiveSHA256": require_sha256(document["archiveSHA256"]),
        "linkMapSHA256": require_sha256(document["linkMapSHA256"]),
        "codeSigningMetadataSHA256": require_sha256(document["codeSigningMetadataSHA256"]),
        "archiveSignatureSHA256": require_sha256(document["archiveSignatureSHA256"]),
        "releaseArchiveSigned": True,
        "releaseConfiguration": "Release",
        "forbiddenSymbols": {
            "bypassSymbolsAbsent": True,
            "testSessionSymbolsAbsent": True,
            "testIssuerSymbolsAbsent": True,
        },
    }
def validate_pitr_source_document(document: dict[str, Any], context: PitrProtectedContext) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "artifactType",
        "signatureAlgorithm",
        "environment",
        "repository",
        "releaseTag",
        "commitSHA",
        "buildDigest",
        "workflowRunId",
        "job",
        "datasetSHA256",
        "migrationSetSHA256",
        "backupSHA256",
        "observedAt",
        "restoredChecks",
    }
    expected_checks = {"grants", "rpc", "projection", "history", "audit"}
    if (
        set(document) != required
        or type(document.get("schemaVersion")) is not int
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "staging-pitr-restore-observation"
        or document.get("signatureAlgorithm") != "ed25519"
        or document.get("environment") != PITR_PROTECTED_ENVIRONMENT
        or document.get("repository") != context.repository
        or document.get("releaseTag") != context.release_tag
        or document.get("commitSHA") != context.git_sha
        or document.get("buildDigest") != context.build_digest
        or document.get("workflowRunId") != context.run_id
        or document.get("job") != context.job
        or document.get("datasetSHA256") != context.dataset_sha256
        or document.get("migrationSetSHA256") != context.migration_set_sha256
        or document.get("backupSHA256") != context.backup_sha256
        or not isinstance(document.get("restoredChecks"), dict)
        or set(document["restoredChecks"]) != expected_checks
        or any(document["restoredChecks"].get(check) is not True for check in expected_checks)
    ):
        fail()
    return {
        "sourceObservedAt": parse_preflight_timestamp(document["observedAt"]),
        "restoredChecks": {
            "grants": True,
            "rpc": True,
            "projection": True,
            "history": True,
            "audit": True,
        },
    }




def validated_signed_source(context: ProtectedContext, evidence_id: str) -> tuple[dict[str, Any], dict[str, str]]:
    raw = read_external_input(PREFLIGHT_SOURCE_ENV, 128 * 1024)
    signature = read_external_input(PREFLIGHT_SOURCE_SIGNATURE_ENV, 16 * 1024)
    public_key = decode_public_key()
    verify_detached_signature(raw, signature, public_key)
    document = parse_canonical_document(raw)
    if evidence_id == "AUTH-005-PREFLIGHT-SERVER":
        observation = validate_server_source_document(document, context)
    elif evidence_id == "AUTH-005-PREFLIGHT-ARCHIVE":
        observation = validate_archive_source_document(document, context)
    else:
        fail()
    return observation, {
        "sourceDocumentSHA256": sha256(raw),
        "sourceSignatureSHA256": sha256(signature),
        "sourcePublicKeySHA256": sha256(public_key),
    }
def validated_pitr_signed_source(context: PitrProtectedContext) -> tuple[dict[str, Any], dict[str, str]]:
    raw = read_external_input(PITR_PROTECTED_SOURCE_ENV, 128 * 1024)
    signature = read_external_input(PITR_PROTECTED_SOURCE_SIGNATURE_ENV, 16 * 1024)
    public_key = decode_public_key(PITR_PROTECTED_SOURCE_PUBLIC_KEY_ENV)
    verify_detached_signature(raw, signature, public_key)
    observation = validate_pitr_source_document(parse_canonical_document(raw), context)
    return observation, {
        "sourceDocumentSHA256": sha256(raw),
        "sourceSignatureSHA256": sha256(signature),
        "sourcePublicKeySHA256": sha256(public_key),
    }




def preflight_output(evidence_id: str) -> tuple[str, str]:
    output = PREFLIGHT_CONTRACTS[evidence_id]["output"]
    return output, f"{output[:-5]}.commit"
def protected_output(evidence_id: str) -> tuple[str, str]:
    if evidence_id in PREFLIGHT_CONTRACTS:
        output = PREFLIGHT_CONTRACTS[evidence_id]["output"]
    elif evidence_id == "MIG-005-PROTECTED":
        output = PITR_PROTECTED_CONTRACT["output"]
    else:
        fail()
    return output, f"{output[:-5]}.commit"


def validate_preflight_correlation(value: Any, context: ProtectedContext) -> None:
    if value != {
        "repository": context.repository,
        "workflowRunId": context.run_id,
        "releaseTag": context.release_tag,
        "commitSHA": context.git_sha,
        "buildDigest": context.build_digest,
    }:
        fail()


def validate_preflight_record(record: dict[str, Any], evidence_id: str, context: ProtectedContext) -> None:
    output, commit_path = preflight_output(evidence_id)
    required = {
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
        set(record) != required
        or type(record.get("schemaVersion")) is not int
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "protected-auth-preflight-evidence"
        or record.get("id") != evidence_id
        or record.get("status") != "passed"
        or record.get("output") != {"path": output, "commitPath": commit_path}
    ):
        fail()
    validate_preflight_correlation(record.get("correlation"), context)
    parse_preflight_timestamp(record.get("collectedAt"))
    input_hashes = record.get("inputHashes")
    attestations = record.get("attestations")
    observation = record.get("observation")
    if not isinstance(input_hashes, dict) or not isinstance(attestations, dict) or not isinstance(observation, dict):
        fail()
    if evidence_id == "AUTH-005-PREFLIGHT-SERVER":
        expected_inputs = {"sourceDocumentSHA256", "sourceSignatureSHA256", "sourcePublicKeySHA256"}
        expected_attestations = {
            "githubActionsOIDCVerified": True,
            "releaseTagSignatureVerified": True,
            "sourceSignatureVerified": True,
        }
        expected_observation = {
            "sourceObservedAt",
            "wrongIssuerRejected",
            "wrongAudienceRejected",
            "testActorRejected",
        }
        probes = (
            ("wrongIssuerRejected", "WRONG_ISSUER_REJECTED"),
            ("wrongAudienceRejected", "WRONG_AUDIENCE_REJECTED"),
            ("testActorRejected", "TEST_IDENTITY_REJECTED"),
        )
        if set(observation) != expected_observation:
            fail()
        parse_preflight_timestamp(observation["sourceObservedAt"])
        for name, code in probes:
            probe = observation[name]
            if not isinstance(probe, dict) or probe != {"code": code, "probeSHA256": probe.get("probeSHA256")}:
                fail()
            require_sha256(probe["probeSHA256"])
    elif evidence_id == "AUTH-005-PREFLIGHT-ARCHIVE":
        expected_inputs = {"sourceDocumentSHA256", "sourceSignatureSHA256", "sourcePublicKeySHA256"}
        expected_attestations = {
            "githubActionsOIDCVerified": True,
            "releaseTagSignatureVerified": True,
            "sourceSignatureVerified": True,
        }
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
        if (
            set(observation) != expected_observation
            or observation.get("releaseArchiveSigned") is not True
            or observation.get("releaseConfiguration") != "Release"
            or observation.get("forbiddenSymbols")
            != {
                "bypassSymbolsAbsent": True,
                "testSessionSymbolsAbsent": True,
                "testIssuerSymbolsAbsent": True,
            }
        ):
            fail()
        parse_preflight_timestamp(observation["sourceObservedAt"])
        for field in ("archiveSHA256", "linkMapSHA256", "codeSigningMetadataSHA256", "archiveSignatureSHA256"):
            require_sha256(observation[field])
    elif evidence_id == "AUTH-005-PREFLIGHT":
        expected_inputs = {
            "serverEvidenceSHA256",
            "serverCommitSHA256",
            "archiveEvidenceSHA256",
            "archiveCommitSHA256",
        }
        expected_attestations = {
            "githubActionsOIDCVerified": True,
            "releaseTagSignatureVerified": True,
            "serverPublicationVerified": True,
            "archivePublicationVerified": True,
        }
        expected_observation = {
            "serverEvidenceSHA256",
            "serverCommitSHA256",
            "archiveEvidenceSHA256",
            "archiveCommitSHA256",
        }
        if set(observation) != expected_observation or observation != input_hashes:
            fail()
    else:
        fail()
    if set(input_hashes) != expected_inputs or any(require_sha256(value) != value for value in input_hashes.values()) or attestations != expected_attestations:
        fail()
    reject_sensitive_data(record)


def make_preflight_record(
    evidence_id: str,
    context: ProtectedContext,
    observation: dict[str, Any],
    input_hashes: dict[str, str],
) -> dict[str, Any]:
    output, commit_path = preflight_output(evidence_id)
    if evidence_id == "AUTH-005-PREFLIGHT":
        attestations = {
            "githubActionsOIDCVerified": True,
            "releaseTagSignatureVerified": True,
            "serverPublicationVerified": True,
            "archivePublicationVerified": True,
        }
    else:
        attestations = {
            "githubActionsOIDCVerified": True,
            "releaseTagSignatureVerified": True,
            "sourceSignatureVerified": True,
        }
    record = {
        "schemaVersion": 1,
        "artifactType": "protected-auth-preflight-evidence",
        "id": evidence_id,
        "status": "passed",
        "correlation": {
            "repository": context.repository,
            "workflowRunId": context.run_id,
            "releaseTag": context.release_tag,
            "commitSHA": context.git_sha,
            "buildDigest": context.build_digest,
        },
        "inputHashes": input_hashes,
        "attestations": attestations,
        "observation": observation,
        "collectedAt": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "output": {"path": output, "commitPath": commit_path},
    }
    validate_preflight_record(record, evidence_id, context)
    return record
def validate_pitr_record(record: dict[str, Any], context: PitrProtectedContext) -> None:
    output, commit_path = protected_output("MIG-005-PROTECTED")
    required = {
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
    expected_correlation = {
        "environment": PITR_PROTECTED_ENVIRONMENT,
        "repository": context.repository,
        "workflowRunId": context.run_id,
        "releaseTag": context.release_tag,
        "commitSHA": context.git_sha,
        "buildDigest": context.build_digest,
        "datasetSHA256": context.dataset_sha256,
        "migrationSetSHA256": context.migration_set_sha256,
        "backupSHA256": context.backup_sha256,
    }
    expected_inputs = {"sourceDocumentSHA256", "sourceSignatureSHA256", "sourcePublicKeySHA256"}
    expected_attestations = {
        "githubActionsOIDCVerified": True,
        "releaseTagSignatureVerified": True,
        "sourceSignatureVerified": True,
        "stagingRestoreSourceVerified": True,
    }
    expected_checks = {"grants", "rpc", "projection", "history", "audit"}
    observation = record.get("observation")
    input_hashes = record.get("inputHashes")
    if (
        set(record) != required
        or type(record.get("schemaVersion")) is not int
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "protected-pitr-restore-evidence"
        or record.get("id") != "MIG-005-PROTECTED"
        or record.get("status") != "passed"
        or record.get("correlation") != expected_correlation
        or record.get("output") != {"path": output, "commitPath": commit_path}
        or not isinstance(input_hashes, dict)
        or set(input_hashes) != expected_inputs
        or any(require_sha256(value) != value for value in input_hashes.values())
        or record.get("attestations") != expected_attestations
        or not isinstance(observation, dict)
        or set(observation) != {"sourceObservedAt", "restoredChecks"}
        or not isinstance(observation.get("restoredChecks"), dict)
        or set(observation["restoredChecks"]) != expected_checks
        or any(observation["restoredChecks"].get(check) is not True for check in expected_checks)
    ):
        fail()
    parse_preflight_timestamp(record.get("collectedAt"))
    parse_preflight_timestamp(observation["sourceObservedAt"])
    reject_sensitive_data(record)


def make_pitr_record(
    context: PitrProtectedContext,
    observation: dict[str, Any],
    input_hashes: dict[str, str],
) -> dict[str, Any]:
    output, commit_path = protected_output("MIG-005-PROTECTED")
    record = {
        "schemaVersion": 1,
        "artifactType": "protected-pitr-restore-evidence",
        "id": "MIG-005-PROTECTED",
        "status": "passed",
        "correlation": {
            "environment": PITR_PROTECTED_ENVIRONMENT,
            "repository": context.repository,
            "workflowRunId": context.run_id,
            "releaseTag": context.release_tag,
            "commitSHA": context.git_sha,
            "buildDigest": context.build_digest,
            "datasetSHA256": context.dataset_sha256,
            "migrationSetSHA256": context.migration_set_sha256,
            "backupSHA256": context.backup_sha256,
        },
        "inputHashes": input_hashes,
        "attestations": {
            "githubActionsOIDCVerified": True,
            "releaseTagSignatureVerified": True,
            "sourceSignatureVerified": True,
            "stagingRestoreSourceVerified": True,
        },
        "observation": observation,
        "collectedAt": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "output": {"path": output, "commitPath": commit_path},
    }
    validate_pitr_record(record, context)
    return record




def read_preflight_publication(root: Path, evidence_id: str, context: ProtectedContext) -> tuple[dict[str, Any], bytes, bytes]:
    output, commit_path = preflight_output(evidence_id)
    evidence = read_limited(repository_file(root, output), 256 * 1024)
    sidecar = read_limited(repository_file(root, f"{output}.sha256"), 512)
    commit_raw = read_limited(repository_file(root, commit_path), 2048)
    expected_sidecar = f"{sha256(evidence)}  {output}\n".encode("ascii")
    if sidecar != expected_sidecar:
        fail()
    commit = parse_canonical_document(commit_raw)
    expected_commit = {
        "schemaVersion": 1,
        "artifactType": "evidence-publication-commit",
        "evidencePath": output,
        "evidenceSHA256": sha256(evidence),
        "sidecarPath": f"{output}.sha256",
        "sidecarSHA256": sha256(sidecar),
    }
    if type(commit.get("schemaVersion")) is not int or commit != expected_commit:
        fail()
    record = parse_canonical_document(evidence)
    validate_preflight_record(record, evidence_id, context)
    return record, evidence, commit_raw


def aggregate_preflight_inputs(root: Path, context: ProtectedContext) -> tuple[dict[str, Any], dict[str, str]]:
    server, server_raw, server_commit = read_preflight_publication(root, "AUTH-005-PREFLIGHT-SERVER", context)
    archive, archive_raw, archive_commit = read_preflight_publication(root, "AUTH-005-PREFLIGHT-ARCHIVE", context)
    if server["correlation"] != archive["correlation"]:
        fail()
    input_hashes = {
        "serverEvidenceSHA256": sha256(server_raw),
        "serverCommitSHA256": sha256(server_commit),
        "archiveEvidenceSHA256": sha256(archive_raw),
        "archiveCommitSHA256": sha256(archive_commit),
    }
    return dict(input_hashes), input_hashes


def protected_output_paths(root: Path, evidence_id: str) -> tuple[Path, Path, Path]:
    output, commit_path = protected_output(evidence_id)
    path, sidecar = output_paths(root, output)
    return path, sidecar, root.joinpath(*PurePosixPath(commit_path).parts)
def write_preflight_publication(path: Path, sidecar: Path, commit: Path, output: str, record: dict[str, Any]) -> None:
    if not isinstance(record.get("output"), dict):
        fail()
    published_record = resolve_publication_record((path, sidecar, commit), output, record)
    evidence = canonical_bytes(published_record) + b"\n"
    sidecar_bytes = f"{sha256(evidence)}  {output}\n".encode("ascii")
    commit_bytes = canonical_bytes(
        {
            "schemaVersion": 1,
            "artifactType": "evidence-publication-commit",
            "evidencePath": output,
            "evidenceSHA256": sha256(evidence),
            "sidecarPath": f"{output}.sha256",
            "sidecarSHA256": sha256(sidecar_bytes),
        }
    ) + b"\n"
    publish_immutable_components(((path, evidence), (sidecar, sidecar_bytes), (commit, commit_bytes)))


def preflight_record(root: Path, evidence_id: str, context: ProtectedContext) -> dict[str, Any]:
    if evidence_id in {"AUTH-005-PREFLIGHT-SERVER", "AUTH-005-PREFLIGHT-ARCHIVE"}:
        observation, input_hashes = validated_signed_source(context, evidence_id)
    elif evidence_id == "AUTH-005-PREFLIGHT":
        observation, input_hashes = aggregate_preflight_inputs(root, context)
    else:
        fail()
    return make_preflight_record(evidence_id, context, observation, input_hashes)
def pitr_record(context: PitrProtectedContext) -> dict[str, Any]:
    observation, input_hashes = validated_pitr_signed_source(context)
    return make_pitr_record(context, observation, input_hashes)




def make_record(evidence_id: str, output: str, revision: str, checks: list[dict[str, str]], input_hashes: dict[str, str]) -> dict[str, Any]:
    record = {
        "schemaVersion": 1,
        "artifactType": "runtime-evidence",
        "id": evidence_id,
        "status": "passed",
        "collectedAt": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gitSHA": revision,
        "output": {"path": output},
        "inputHashes": input_hashes,
        "checks": checks,
    }
    validate_runtime_record(record, evidence_id, output)
    return record


def validate_runtime_record(record: dict[str, Any], evidence_id: str, output: str) -> None:
    required = {"schemaVersion", "artifactType", "id", "status", "collectedAt", "gitSHA", "output", "inputHashes", "checks"}
    if set(record) != required or record["schemaVersion"] != 1 or record["artifactType"] != "runtime-evidence":
        fail()
    if record["id"] != evidence_id or not isinstance(record["id"], str) or ID_RE.fullmatch(record["id"]) is None:
        fail()
    if record["status"] != "passed" or not isinstance(record["collectedAt"], str) or TIMESTAMP_RE.fullmatch(record["collectedAt"]) is None:
        fail()
    if not isinstance(record["gitSHA"], str) or SHA1_RE.fullmatch(record["gitSHA"]) is None:
        fail()
    if record["output"] != {"path": output}:
        fail()
    input_hashes = record["inputHashes"]
    if not isinstance(input_hashes, dict) or not input_hashes:
        fail()
    for name, digest in input_hashes.items():
        if not isinstance(name, str) or INPUT_HASH_RE.fullmatch(name) is None or not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            fail()
    checks = record["checks"]
    if not isinstance(checks, list) or not checks:
        fail()
    seen_checks = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"code", "outcome", "evidenceSHA256"}:
            fail()
        code = check["code"]
        if not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) is None or code in seen_checks:
            fail()
        if check["outcome"] != "passed" or not isinstance(check["evidenceSHA256"], str) or SHA256_RE.fullmatch(check["evidenceSHA256"]) is None:
            fail()
        seen_checks.add(code)


def output_paths(root: Path, output: str) -> tuple[Path, Path]:
    relative = PurePosixPath(output)
    if relative.is_absolute() or relative.as_posix() != output or any(part in {".", ".."} for part in relative.parts):
        fail()
    path = root.joinpath(*relative.parts)
    parent = path.parent
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.exists() and current.is_symlink():
            fail()
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved_parent = parent.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        resolved_parent.relative_to(resolved_root)
    except (OSError, ValueError):
        fail()
    return path, Path(f"{path}.sha256")


def publication_intent_path(path: Path) -> Path:
    return Path(f"{path}.publication-intent")


def publication_transaction(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "collectedAt"}


def publication_intent(output: str, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "artifactType": "immutable-evidence-publication-intent",
        "output": output,
        "transaction": publication_transaction(record),
        "record": record,
    }


def read_publication_intent(path: Path, output: str) -> dict[str, Any] | None:
    intent_path = publication_intent_path(path)
    try:
        information = os.lstat(intent_path)
    except FileNotFoundError:
        return None
    except OSError:
        fail()
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail()
    document = parse_canonical_document(read_limited(intent_path, 256 * 1024))
    if (
        set(document) != {"schemaVersion", "artifactType", "output", "transaction", "record"}
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "immutable-evidence-publication-intent"
        or document.get("output") != output
        or not isinstance(document.get("transaction"), dict)
        or not isinstance(document.get("record"), dict)
        or document["transaction"] != publication_transaction(document["record"])
    ):
        fail()
    return document


def immutable_component_matches(path: Path, expected: bytes) -> bool:
    try:
        information = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        fail()
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail()
    if read_limited(path, len(expected)) != expected:
        fail()
    return True


def preflight_components_absent(components: tuple[Path, ...]) -> None:
    for path in components:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            fail()
        fail()


def temporary_file(directory: Path, name: str, data: bytes) -> Path:
    try:
        descriptor, raw_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
        temporary = Path(raw_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        return temporary
    except OSError:
        fail()


def sync_component_directories(components: tuple[tuple[Path, bytes], ...]) -> None:
    directories: list[Path] = []
    for path, _expected in components:
        if path.parent not in directories:
            directories.append(path.parent)
    for directory in directories:
        descriptor = -1
        try:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            os.fsync(descriptor)
        except OSError:
            fail()
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    fail()


def write_publication_intent_once(path: Path, intent: dict[str, Any]) -> None:
    temporary = temporary_file(path.parent, path.name, canonical_bytes(intent) + b"\n")
    try:
        os.link(temporary, path)
        sync_component_directories(((path, b"intent"),))
    except OSError:
        fail()
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def resolve_publication_record(
    components: tuple[Path, ...],
    output: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    intent = publication_intent(output, record)
    published_intent = read_publication_intent(components[0], output)
    if published_intent is None:
        preflight_components_absent(components)
        write_publication_intent_once(publication_intent_path(components[0]), intent)
        return record
    if published_intent["transaction"] != intent["transaction"]:
        fail()
    return published_intent["record"]


def publish_immutable_components(components: tuple[tuple[Path, bytes], ...]) -> None:
    missing = tuple(
        (path, expected)
        for path, expected in components
        if not immutable_component_matches(path, expected)
    )
    staged: list[tuple[Path, Path]] = []
    try:
        for path, expected in missing:
            staged.append((temporary_file(path.parent, path.name, expected), path))
    except EvidenceError:
        for temporary, _path in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    try:
        for temporary, path in staged:
            os.link(temporary, path)
        sync_component_directories(components)
    except OSError:
        fail()
    finally:
        for temporary, _path in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    for path, expected in components:
        if not immutable_component_matches(path, expected):
            fail()


def write_pair_atomically(path: Path, sidecar: Path, output: str, record: dict[str, Any]) -> None:
    published_record = resolve_publication_record((path, sidecar), output, record)
    evidence = canonical_bytes(published_record) + b"\n"
    sidecar_bytes = f"{sha256(evidence)}  {output}\n".encode("ascii")
    publish_immutable_components(((path, evidence), (sidecar, sidecar_bytes)))


@dataclass(frozen=True)
class ReleaseEvidenceContext:
    repository: str
    run_id: str
    tag: str
    commit: str
    build_digest: str
    input_sha256: str
    job: str
    environment: str

@dataclass(frozen=True)
class ReleaseSignedSource:
    observed_at: str
    observations: dict[str, Any]
    input_hashes: dict[str, str]



def release_env(name: str, expression: re.Pattern[str]) -> str:
    value = os.environ.get(name)
    if value is None or expression.fullmatch(value) is None:
        fail()
    return value


def release_repo_path(value: str, prefix: str, suffix: str) -> str:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or "\\" in value
        or not value.startswith(prefix)
        or not value.endswith(suffix)
        or any(part in {".", ".."} for part in relative.parts)
    ):
        fail()
    return value


def require_release_evidence_context(root: Path, evidence_id: str) -> ReleaseEvidenceContext:
    contract = RELEASE_EVIDENCE_CONTRACTS[evidence_id]
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_WORKFLOW") != "Release Evidence"
        or os.environ.get("GITHUB_JOB") != contract["job"]
        or os.environ.get("RELEASE_PROTECTED_ENVIRONMENT") != contract["environment"]
        or os.environ.get("RELEASE_PROTECTED_INPUTS_CONFIRMED") != "approved"
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
    ):
        fail()
    repository = release_env("GITHUB_REPOSITORY", REPOSITORY_RE)
    run_id = release_env("GITHUB_RUN_ID", RUN_ID_RE)
    tag = release_env("GITHUB_REF_NAME", RELEASE_TAG_RE)
    commit = release_env("GITHUB_SHA", SHA1_RE)
    build_digest = release_env("HIKER_RELEASE_BUILD_DIGEST", SHA256_RE)
    input_sha256 = release_env("HIKER_RELEASE_INPUT_SHA256", SHA256_RE)
    if os.environ.get("GITHUB_REF") != f"refs/tags/{tag}" or current_git_revision(root) != commit:
        fail()
    protected_context = ProtectedContext(repository, run_id, tag, commit, build_digest, contract["job"])
    verify_signed_release_tag(root, tag, commit, RELEASE_TAG_SIGNING_FINGERPRINT_ENV)
    require_live_github_job(protected_context, RELEASE_WORKFLOW_NAME, RELEASE_WORKFLOW_PATH)
    require_oidc_identity(
        protected_context,
        RELEASE_OIDC_AUDIENCE,
        contract["environment"],
        RELEASE_WORKFLOW_NAME,
        RELEASE_WORKFLOW_PATH,
    )
    return ReleaseEvidenceContext(repository, run_id, tag, commit, build_digest, input_sha256, contract["job"], contract["environment"])


def release_protected_source_receipt(
    evidence_id: str,
    context: ReleaseEvidenceContext,
    document: bytes,
    signature: bytes,
) -> tuple[dict[str, Any], bytes]:
    source_contract = RELEASE_PROTECTED_SOURCE_CONTRACTS.get(context.job)
    if source_contract is None or source_contract["evidenceId"] != evidence_id:
        fail()
    runner_temp = os.environ.get("RUNNER_TEMP")
    expected_path = str(Path(runner_temp or "") / "release-protected-source-receipt.json")
    if os.environ.get(RELEASE_PROTECTED_SOURCE_RECEIPT_ENV) != expected_path:
        fail()
    raw = read_external_input(RELEASE_PROTECTED_SOURCE_RECEIPT_ENV, 16 * 1024)
    receipt = parse_canonical_document(raw)
    required = {
        "schemaVersion",
        "artifactType",
        "targetGate",
        "repository",
        "tag",
        "commit",
        "consumerRunId",
        "producerRunId",
        "producerJob",
        "producerJobId",
        "artifactLabel",
        "artifactDigest",
        "documentFile",
        "documentSHA256",
        "signatureFile",
        "signatureSHA256",
    }
    expected_artifact = f"{source_contract['artifactBase']}-{context.commit}"
    if (
        set(receipt) != required
        or receipt.get("schemaVersion") != 1
        or receipt.get("artifactType") != "protected-release-source-receipt"
        or receipt.get("targetGate") != context.job
        or receipt.get("repository") != context.repository
        or receipt.get("tag") != context.tag
        or receipt.get("commit") != context.commit
        or receipt.get("consumerRunId") != context.run_id
        or not isinstance(receipt.get("producerRunId"), str)
        or RUN_ID_RE.fullmatch(receipt["producerRunId"]) is None
        or receipt["producerRunId"] == context.run_id
        or receipt.get("producerJob") != "publish-protected-source"
        or type(receipt.get("producerJobId")) is not int
        or receipt["producerJobId"] <= 0
        or receipt.get("artifactLabel") != expected_artifact
        or not isinstance(receipt.get("artifactDigest"), str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", receipt["artifactDigest"]) is None
        or receipt.get("documentFile") != source_contract["documentName"]
        or receipt.get("documentSHA256") != sha256(document)
        or receipt.get("signatureFile") != source_contract["signatureName"]
        or receipt.get("signatureSHA256") != sha256(signature)
    ):
        fail()
    return receipt, raw


def validate_release_observations(evidence_id: str, observations: Any) -> dict[str, Any]:
    required_checks = RELEASE_OBSERVATION_CHECKS.get(evidence_id)
    controller_source = RELEASE_EVIDENCE_CONTRACTS.get(evidence_id, {}).get("route") == "controller-source"
    expected_keys = {"status", "checks", "manifest"} if controller_source else {"status", "checks"}
    if evidence_id == "REL-014":
        expected_keys.add("reviews")
    if (
        required_checks is None
        or not isinstance(observations, dict)
        or set(observations) != expected_keys
        or observations.get("status") != "passed"
    ):
        fail()
    checks = observations.get("checks")
    if (
        not isinstance(checks, dict)
        or set(checks) != required_checks
        or any(value is not True for value in checks.values())
    ):
        fail()
    if controller_source:
        manifest = observations.get("manifest")
        state = CONTROLLER_SOURCE_STATES.get(evidence_id)
        if (
            state is None
            or not isinstance(manifest, dict)
            or set(manifest) != {
                "releaseID",
                "state",
                "dataSHA256",
                "migrationSHA256",
                "expectedSequence",
                "expectedEventSHA256",
                "observedAt",
                "evidence",
            }
            or not isinstance(manifest.get("releaseID"), str)
            or re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$", manifest["releaseID"]) is None
            or manifest.get("state") != state[0]
            or manifest.get("expectedSequence") != state[1]
            or not isinstance(manifest.get("evidence"), list)
        ):
            fail()
        require_sha256(manifest.get("dataSHA256"))
        require_sha256(manifest.get("migrationSHA256"))
        require_sha256(manifest.get("expectedEventSHA256"))
        parse_preflight_timestamp(manifest.get("observedAt"))
    if evidence_id == "REL-014":
        reviews = observations.get("reviews")
        if not isinstance(reviews, dict) or set(reviews) != {"sevenDayReviewedAt", "thirtyDayReviewedAt"}:
            fail()
        parse_utc_timestamp(reviews.get("sevenDayReviewedAt"))
        parse_utc_timestamp(reviews.get("thirtyDayReviewedAt"))
    reject_sensitive_data(observations)
    return observations
def release_signed_source(
    evidence_id: str,
    context: ReleaseEvidenceContext,
) -> ReleaseSignedSource:
    raw = read_external_input("HIKER_RELEASE_OBSERVATION_PATH", 128 * 1024)
    signature = read_external_input("HIKER_RELEASE_OBSERVATION_SIGNATURE_PATH", 16 * 1024)
    receipt, receipt_raw = release_protected_source_receipt(evidence_id, context, raw, signature)
    public_key = decode_public_key("HIKER_RELEASE_OBSERVATION_PUBLIC_KEY_BASE64")
    verify_detached_signature(raw, signature, public_key)
    document = parse_canonical_document(raw)
    contract = RELEASE_EVIDENCE_CONTRACTS[evidence_id]
    required = {
        "schemaVersion",
        "artifactType",
        "signatureAlgorithm",
        "id",
        "checkKind",
        "repository",
        "releaseTag",
        "commitSHA",
        "buildDigest",
        "inputSHA256",
        "workflowRunId",
        "job",
        "observedAt",
        "observations",
    }
    if (
        set(document) != required
        or type(document.get("schemaVersion")) is not int
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "release-live-observation"
        or document.get("signatureAlgorithm") != "ed25519"
        or document.get("id") != evidence_id
        or document.get("checkKind") != contract["checkKind"]
        or document.get("repository") != context.repository
        or document.get("releaseTag") != context.tag
        or document.get("commitSHA") != context.commit
        or document.get("buildDigest") != context.build_digest
        or document.get("inputSHA256") != context.input_sha256
        or document.get("workflowRunId") != receipt["producerRunId"]
        or document.get("job") != receipt["producerJob"]
        or not isinstance(document.get("observations"), dict)
    ):
        fail()
    observations = validate_release_observations(evidence_id, document["observations"])
    return ReleaseSignedSource(
        parse_preflight_timestamp(document.get("observedAt")),
        observations,
        {
            "sourceDocumentSHA256": sha256(raw),
            "sourceSignatureSHA256": sha256(signature),
            "sourceProducerReceiptSHA256": sha256(receipt_raw),
            "sourcePublicKeySHA256": sha256(public_key),
            "buildDigestSHA256": context.build_digest,
            "inputSHA256": context.input_sha256,
        },
    )



def release_postrelease_predecessor(
    root: Path,
    context: ReleaseEvidenceContext,
    source: ReleaseSignedSource | None = None,
) -> str:
    output = RELEASE_EVIDENCE_CONTRACTS["REL-PHASE-100"]["output"]
    raw = read_limited(repository_file(root, output), 1024 * 1024)
    digest = sha256(raw)
    sidecar = read_limited(repository_file(root, f"{output}.sha256"), 512)
    if sidecar != f"{digest}  {output}\n".encode("ascii"):
        fail()
    record = parse_canonical_document(raw)
    required = {
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
    required.update({"rcManifestSHA256", "m6ExitSHA256", "phaseFloorSHA256"})
    if (
        set(record) != required
        or type(record.get("schemaVersion")) is not int
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "release-transition-controller"
        or not isinstance(record.get("releaseID"), str)
        or re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$", record["releaseID"]) is None
        or record.get("state") != "phase-100"
        or record.get("tag") != context.tag
        or record.get("commit") != context.commit
        or record.get("buildDigest") != context.build_digest
        or record.get("switchState") != "enabled"
        or record.get("expectedSequence") != 7
        or not isinstance(record.get("auditEventId"), str)
        or not record["auditEventId"]
    ):
        fail()
    for name in (
        "expectedEventSHA256",
        "approvalSHA256",
        "observedInputSHA256",
        "dataSHA256",
        "migrationSHA256",
        "actorSHA256",
        "eventSHA256",
        "rpcReceiptSHA256",
    ):
        require_sha256(record.get(name))
    for name in ("rcManifestSHA256", "m6ExitSHA256", "phaseFloorSHA256"):
        require_sha256(record.get(name))
    if record["eventSHA256"] == record["expectedEventSHA256"]:
        fail()
    phase_completed_at = parse_utc_timestamp(record.get("createdAt"))
    reject_sensitive_data(record)
    if source is not None:
        reviews = source.observations.get("reviews")
        if not isinstance(reviews, dict):
            fail()
        seven_day = parse_utc_timestamp(reviews.get("sevenDayReviewedAt"))
        thirty_day = parse_utc_timestamp(reviews.get("thirtyDayReviewedAt"))
        source_observed = parse_utc_timestamp(source.observed_at)
        if (
            seven_day < phase_completed_at + timedelta(days=7)
            or thirty_day < phase_completed_at + timedelta(days=30)
            or thirty_day < seven_day
            or source_observed < thirty_day
        ):
            fail()
    return digest


def release_record(
    evidence_id: str,
    context: ReleaseEvidenceContext,
    observation: dict[str, Any],
    input_hashes: dict[str, str],
    previous_artifact_sha256: Optional[str] = None,
) -> dict[str, Any]:
    contract = RELEASE_EVIDENCE_CONTRACTS[evidence_id]
    record = {
        "schemaVersion": 1,
        "artifactType": "protected-rc-auth-aggregate-evidence" if evidence_id == "AUTH-005-RC" else "protected-release-observation-evidence",
        "id": evidence_id,
        "status": "passed",
        "tag": context.tag,
        "commit": context.commit,
        "collectedAt": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "output": {"path": contract["output"]},
        "correlation": {
            "repository": context.repository,
            "workflowRunId": context.run_id,
            "job": context.job,
            "environment": context.environment,
            "buildDigest": context.build_digest,
            "inputSHA256": context.input_sha256,
        },
        "inputHashes": input_hashes,
        "attestations": {
            "protectedGithubContextVerified": True,
            "sourceSignatureVerified": True,
            "sourceRedactionVerified": True,
        },
        "observation": observation,
    }
    if evidence_id == "REL-014":
        if require_sha256(previous_artifact_sha256) != previous_artifact_sha256:
            fail()
        record["previousArtifactSHA256"] = previous_artifact_sha256
    elif previous_artifact_sha256 is not None:
        fail()
    required = {
        "schemaVersion", "artifactType", "id", "status", "tag", "commit", "collectedAt", "output",
        "correlation", "inputHashes", "attestations", "observation",
    }
    if evidence_id == "REL-014":
        required.add("previousArtifactSHA256")
    if set(record) != required or any(require_sha256(value) != value for value in input_hashes.values()):
        fail()
    parse_preflight_timestamp(record["collectedAt"])
    reject_sensitive_data(record)
    return record


def publish_release_record(root: Path, evidence_id: str, record: dict[str, Any]) -> None:
    output = RELEASE_EVIDENCE_CONTRACTS[evidence_id]["output"]
    path, sidecar = output_paths(root, output)
    write_pair_atomically(path, sidecar, output, record)


def read_release_record(
    root: Path,
    evidence_id: str,
    context: ReleaseEvidenceContext,
) -> tuple[dict[str, Any], bytes]:
    output = RELEASE_EVIDENCE_CONTRACTS[evidence_id]["output"]
    raw = read_limited(repository_file(root, output), 256 * 1024)
    sidecar = read_limited(repository_file(root, f"{output}.sha256"), 512)
    if sidecar != f"{sha256(raw)}  {output}\n".encode("ascii"):
        fail()
    record = parse_canonical_document(raw)
    if (
        set(record) != {
            "schemaVersion", "artifactType", "id", "status", "tag", "commit", "collectedAt", "output",
            "correlation", "inputHashes", "attestations", "observation",
        }
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "protected-release-observation-evidence"
        or record.get("id") != evidence_id
        or record.get("status") != "passed"
        or record.get("tag") != context.tag
        or record.get("commit") != context.commit
        or record.get("output") != {"path": output}
        or not isinstance(record.get("correlation"), dict)
        or record["correlation"].get("repository") != context.repository
        or record["correlation"].get("buildDigest") != context.build_digest
    ):
        fail()
    return record, raw


def rc_auth_aggregate(root: Path, context: ReleaseEvidenceContext) -> None:
    server, server_raw = read_release_record(root, "AUTH-005-RC-SERVER", context)
    archive, archive_raw = read_release_record(root, "AUTH-005-RC-ARCHIVE", context)
    if (
        server["correlation"].get("job") != "rc-auth-server"
        or archive["correlation"].get("job") != "rc-auth-archive"
        or server["correlation"].get("environment") != "production"
        or archive["correlation"].get("environment") != "production"
    ):
        fail()
    evidence_id = "AUTH-005-RC"
    record = release_record(
        evidence_id,
        context,
        {
            "serverEvidenceSHA256": sha256(server_raw),
            "archiveEvidenceSHA256": sha256(archive_raw),
            "serverObservationSHA256": server["observation"]["observationSHA256"],
            "archiveObservationSHA256": archive["observation"]["observationSHA256"],
        },
        {
            "serverEvidenceSHA256": sha256(server_raw),
            "archiveEvidenceSHA256": sha256(archive_raw),
            "buildDigestSHA256": context.build_digest,
            "inputSHA256": context.input_sha256,
        },
    )
    publish_release_record(root, evidence_id, record)


def release_script(root: Path, relative: str, arguments: list[str]) -> None:
    script = repository_file(root, relative)
    try:
        details = script.stat()
        if not stat.S_ISREG(details.st_mode):
            fail()
        result = subprocess.run(
            [str(script), *arguments],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail()
    if result.returncode != 0 or len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
        fail()


def release_readiness(root: Path, context: ReleaseEvidenceContext) -> None:
    release_script(
        root,
        "Scripts/release/assemble-readiness.sh",
        ["--tag", context.tag, "--commit", context.commit, "--output", "Evidence/manifests/m6-readiness.json"],
    )


def release_rc(root: Path) -> None:
    release_script(
        root,
        "Scripts/release/assemble-rc.sh",
        [
            "--readiness", "Evidence/manifests/m6-readiness.json",
            "--rel-002", "Evidence/runtime/REL-002.json",
            "--rel-003", "Evidence/runtime/REL-003.json",
            "--rel-004", "Evidence/runtime/REL-004.json",
            "--rel-005", "Evidence/runtime/REL-005.json",
            "--rel-006", "Evidence/runtime/REL-006.json",
            "--rel-008", "Evidence/runtime/REL-008.json",
            "--rel-009", "Evidence/runtime/REL-009.json",
            "--ops-005", "Evidence/runtime/OPS-005.json",
            "--perf", "Evidence/tests/PERF-001.json",
            "--auth", "Evidence/runtime/AUTH-005-RC.json",
            "--approval", "Evidence/runtime/approvals/threshold.json",
            "--output-manifest", "Evidence/manifests/rc.json",
            "--output", "Evidence/runtime/REL-007.json",
        ],
    )


def release_m6_exit(root: Path) -> None:
    release_script(
        root,
        "Scripts/release/assemble-m6-exit.sh",
        [
            "--rc", "Evidence/manifests/rc.json",
            "--ops-003", "Evidence/runtime/OPS-003.json",
            "--ops-004", "Evidence/runtime/OPS-004.json",
            "--perf", "Evidence/tests/PERF-001.json",
            "--beta", "Evidence/runtime/REL-005.json",
            "--threshold", "Evidence/runtime/OPS-005.json",
            "--auth", "Evidence/runtime/AUTH-005-RC.json",
            "--approval", "Evidence/runtime/approvals/m6-exit.json",
            "--output", "Evidence/runtime/M6-EXIT.json",
        ],
    )


def release_switch_drill(root: Path) -> None:
    release_script(
        root,
        "Scripts/release/produce-switch-drill-evidence.sh",
        [
            "--previous-event-sha",
            release_env("HIKER_RELEASE_PREVIOUS_EVENT_SHA", SHA256_RE),
            "--output",
            "Evidence/runtime/REL-009.json",
        ],
    )


def release_floor_validation(root: Path, evidence_id: str) -> None:
    expected_sources = {
        "REL-005": "Evidence/manifests/floor-beta.json",
        "REL-011-05": "Evidence/manifests/floor-phase-05.json",
        "REL-011-25": "Evidence/manifests/floor-phase-25.json",
        "REL-011-50": "Evidence/manifests/floor-phase-50.json",
        "REL-011-100": "Evidence/manifests/floor-phase-100.json",
    }
    source = release_env("HIKER_RELEASE_FLOOR_SOURCE_MANIFEST", re.compile(r"^Evidence/manifests/[A-Za-z0-9._-]+\.json$"))
    if source != expected_sources[evidence_id]:
        fail()
    release_script(
        root,
        "Scripts/release/validate-runtime-floors.py",
        [
            "--id", evidence_id,
            "--source-manifest", source,
            "--threshold", "Evidence/runtime/OPS-005.json",
            "--schema", "Docs/evidence/schemas/threshold-ratification.schema.json",
            "--output", RELEASE_EVIDENCE_CONTRACTS[evidence_id]["output"],
        ],
    )


def materialize_controller_source_manifest(
    root: Path,
    observed_manifest: str,
    context: ReleaseEvidenceContext,
    source: ReleaseSignedSource,
) -> str:
    manifest = source.observations.get("manifest")
    if not isinstance(manifest, dict):
        fail()
    document = {
        "schemaVersion": 1,
        "artifactType": "release-transition-observed-input",
        **manifest,
        "tag": context.tag,
        "commit": context.commit,
        "repository": context.repository,
        "buildDigest": context.build_digest,
        "inputSHA256": context.input_sha256,
        "workflowRunId": context.run_id,
        "job": context.job,
        "sourceDocumentSHA256": source.input_hashes["sourceDocumentSHA256"],
        "sourceSignatureSHA256": source.input_hashes["sourceSignatureSHA256"],
        "sourcePublicKeySHA256": source.input_hashes["sourcePublicKeySHA256"],
        "sourceInputSHA256": source.input_hashes["inputSHA256"],
        "sourceObservedAt": source.observed_at,
        "sourceObservation": source.observations,
    }
    path, sidecar = output_paths(root, observed_manifest)
    write_pair_atomically(path, sidecar, observed_manifest, document)
    return sha256(read_limited(repository_file(root, observed_manifest), 1024 * 1024))


def validate_controller_source_manifest(
    root: Path,
    observed_manifest: str,
    observed_input_sha: str,
    context: ReleaseEvidenceContext,
    source: ReleaseSignedSource,
) -> None:
    raw = read_limited(repository_file(root, observed_manifest), 1024 * 1024)
    sidecar = read_limited(repository_file(root, f"{observed_manifest}.sha256"), 512)
    if (
        sha256(raw) != observed_input_sha
        or sidecar != f"{observed_input_sha}  {observed_manifest}\n".encode("ascii")
    ):
        fail()
    document = parse_canonical_document(raw)
    required = {
        "schemaVersion",
        "artifactType",
        "releaseID",
        "state",
        "tag",
        "commit",
        "dataSHA256",
        "migrationSHA256",
        "expectedSequence",
        "expectedEventSHA256",
        "observedAt",
        "evidence",
        "repository",
        "buildDigest",
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
        set(document) != required
        or type(document.get("schemaVersion")) is not int
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "release-transition-observed-input"
        or document.get("repository") != context.repository
        or document.get("tag") != context.tag
        or document.get("commit") != context.commit
        or document.get("buildDigest") != context.build_digest
        or document.get("inputSHA256") != context.input_sha256
        or document.get("workflowRunId") != context.run_id
        or document.get("job") != context.job
        or document.get("sourceDocumentSHA256") != source.input_hashes["sourceDocumentSHA256"]
        or document.get("sourceSignatureSHA256") != source.input_hashes["sourceSignatureSHA256"]
        or document.get("sourcePublicKeySHA256") != source.input_hashes["sourcePublicKeySHA256"]
        or document.get("sourceInputSHA256") != source.input_hashes["inputSHA256"]
        or document.get("sourceObservedAt") != source.observed_at
        or not isinstance(document.get("sourceObservation"), dict)
        or canonical_bytes(document["sourceObservation"]) != canonical_bytes(source.observations)
    ):
        fail()


def release_bound_artifact_digest(root: Path, path: str, environment_name: str) -> str:
    raw = read_limited(repository_file(root, path), 1024 * 1024)
    digest = sha256(raw)
    sidecar = read_limited(repository_file(root, f"{path}.sha256"), 512)
    if (
        digest != release_env(environment_name, SHA256_RE)
        or sidecar != f"{digest}  {path}\n".encode("ascii")
    ):
        fail()
    parse_canonical_document(raw)
    return digest


def release_controller(
    root: Path,
    evidence_id: str,
    context: ReleaseEvidenceContext,
    source: Optional[ReleaseSignedSource] = None,
) -> None:
    states = {
        "REL-002": ("predeploy-disabled", "disabled", "0", "Evidence/runtime/approvals/predeploy.json", "Evidence/manifests/observed-predeploy.json"),
        "REL-003": ("compatibility", "disabled", "1", "Evidence/runtime/approvals/compatibility.json", "Evidence/manifests/observed-compatibility.json"),
        "REL-008": ("pitr-proof", "disabled", "2", "Evidence/runtime/approvals/pitr-proof.json", "Evidence/manifests/observed-pitr.json"),
        "REL-010": ("activate-1pct", "enabled", "3", "Evidence/runtime/approvals/activate-1pct.json", "Evidence/manifests/observed-activate-1pct.json"),
        "REL-PHASE-05": ("phase-5", "enabled", "4", "Evidence/runtime/approvals/phase-05.json", "Evidence/manifests/observed-phase-05.json"),
        "REL-PHASE-25": ("phase-25", "enabled", "5", "Evidence/runtime/approvals/phase-25.json", "Evidence/manifests/observed-phase-25.json"),
        "REL-PHASE-50": ("phase-50", "enabled", "6", "Evidence/runtime/approvals/phase-50.json", "Evidence/manifests/observed-phase-50.json"),
        "REL-PHASE-100": ("phase-100", "enabled", "7", "Evidence/runtime/approvals/phase-100.json", "Evidence/manifests/observed-phase-100.json"),
        "REL-CONTRACT": ("contract-remove-old", "enabled", "8", "Evidence/runtime/approvals/contract.json", "Evidence/manifests/observed-contract.json"),
    }
    state, switch_state, sequence, approval, observed_manifest = states[evidence_id]
    configured_manifest = release_env("HIKER_RELEASE_OBSERVED_INPUT_MANIFEST", re.compile(r"^Evidence/manifests/[A-Za-z0-9._-]+\.json$"))
    observed_input_sha = release_env("HIKER_RELEASE_OBSERVED_INPUT_SHA", SHA256_RE)
    if configured_manifest != observed_manifest:
        fail()
    if (RELEASE_EVIDENCE_CONTRACTS[evidence_id]["route"] == "controller-source") != (source is not None):
        fail()
    if source is not None and materialize_controller_source_manifest(
        root, observed_manifest, context, source
    ) != observed_input_sha:
        fail()
    if source is not None:
        validate_controller_source_manifest(root, observed_manifest, observed_input_sha, context, source)
    arguments = [
        "--release-id", release_env("HIKER_RELEASE_ID", re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")),
        "--state", state,
        "--tag", context.tag,
        "--commit", context.commit,
        "--switch-state", switch_state,
        "--expected-sequence", sequence,
        "--expected-event-sha", release_env("HIKER_RELEASE_PREVIOUS_EVENT_SHA", SHA256_RE),
        "--approval", approval,
        "--approval-sha", release_env("HIKER_RELEASE_APPROVAL_SHA", SHA256_RE),
        "--observed-input-manifest", observed_manifest,
        "--observed-input-sha", observed_input_sha,
        "--data-sha", release_env("HIKER_RELEASE_DATASET_SHA", SHA256_RE),
        "--migration-sha", release_env("HIKER_RELEASE_MIGRATION_SHA", SHA256_RE),
        "--actor", release_env("GITHUB_ACTOR", re.compile(r"^[A-Za-z0-9-]{1,39}$")),
        "--output", RELEASE_EVIDENCE_CONTRACTS[evidence_id]["output"],
    ]
    m7_ids = {"REL-010", "REL-PHASE-05", "REL-PHASE-25", "REL-PHASE-50", "REL-PHASE-100", "REL-CONTRACT"}
    if evidence_id in m7_ids:
        rc_path = "Evidence/manifests/rc.json"
        m6_exit_path = "Evidence/runtime/M6-EXIT.json"
        arguments += [
            "--rc-manifest", rc_path,
            "--rc-manifest-sha", release_bound_artifact_digest(root, rc_path, "HIKER_RELEASE_RC_MANIFEST_SHA"),
            "--m6-exit", m6_exit_path,
            "--m6-exit-sha", release_bound_artifact_digest(root, m6_exit_path, "HIKER_RELEASE_M6_EXIT_SHA"),
        ]
    phase_floor_ids = {
        "REL-PHASE-05": "REL-011-05",
        "REL-PHASE-25": "REL-011-25",
        "REL-PHASE-50": "REL-011-50",
        "REL-PHASE-100": "REL-011-100",
    }
    if evidence_id in phase_floor_ids:
        phase_floor_path = f"Evidence/runtime/{phase_floor_ids[evidence_id]}.json"
        arguments += [
            "--phase-floor", phase_floor_path,
            "--phase-floor-sha", release_bound_artifact_digest(root, phase_floor_path, "HIKER_RELEASE_PHASE_FLOOR_SHA"),
        ]
    release_script(root, "Scripts/release/migration-controller.sh", arguments)


def release_threshold(root: Path, context: ReleaseEvidenceContext) -> None:
    raw = read_external_input("HIKER_RELEASE_THRESHOLD_PATH", 128 * 1024)
    signature = read_external_input("HIKER_RELEASE_THRESHOLD_SIGNATURE_PATH", 16 * 1024)
    release_protected_source_receipt("OPS-005", context, raw, signature)
    public_key = decode_public_key("HIKER_RELEASE_THRESHOLD_PUBLIC_KEY_BASE64")
    verify_detached_signature(raw, signature, public_key)
    record = parse_canonical_document(raw)
    expected = {"schemaVersion", "artifactType", "id", "tag", "commit", "approvalSHA256", "createdAt", "thresholds"}
    if (
        set(record) != expected
        or record.get("schemaVersion") != 1
        or record.get("artifactType") != "threshold-ratification"
        or record.get("id") != "OPS-005"
        or record.get("tag") != context.tag
        or record.get("commit") != context.commit
        or not isinstance(record.get("thresholds"), dict)
        or SHA256_RE.fullmatch(record.get("approvalSHA256", "")) is None
    ):
        fail()
    parse_preflight_timestamp(record.get("createdAt"))
    path, sidecar = output_paths(root, "Evidence/runtime/OPS-005.json")
    write_pair_atomically(path, sidecar, "Evidence/runtime/OPS-005.json", record)


def run_release_evidence(root: Path, evidence_id: str) -> None:
    context = require_release_evidence_context(root, evidence_id)
    route = RELEASE_EVIDENCE_CONTRACTS[evidence_id]["route"]
    if route == "signed-source":
        source = release_signed_source(evidence_id, context)
        observation = {
            "sourceObservedAt": source.observed_at,
            "observationSHA256": sha256(source.observations),
        }
        predecessor = release_postrelease_predecessor(root, context, source) if evidence_id == "REL-014" else None
        publish_release_record(
            root,
            evidence_id,
            release_record(evidence_id, context, observation, source.input_hashes, predecessor),
        )
    elif route == "rc-auth-aggregate":
        rc_auth_aggregate(root, context)
    elif route == "threshold":
        release_threshold(root, context)
    elif route == "readiness":
        release_readiness(root, context)
    elif route == "rc":
        release_rc(root)
    elif route == "m6-exit":
        release_m6_exit(root)
    elif route == "switch":
        release_switch_drill(root)
    elif route == "floors":
        release_floor_validation(root, evidence_id)
    elif route == "controller-source":
        source = release_signed_source(evidence_id, context)
        release_controller(root, evidence_id, context, source)
    else:
        fail()

def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--id", required=True)
    parser.add_argument("--check-kind", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def run(arguments: argparse.Namespace) -> None:
    profile = PROFILE_CONTRACTS.get(arguments.id)
    if profile is None or arguments.check_kind != profile["checkKind"] or arguments.output != profile["output"]:
        fail()
    root = repository_root()
    if arguments.id in RELEASE_EVIDENCE_CONTRACTS:
        run_release_evidence(root, arguments.id)
        return
    if arguments.id in PREFLIGHT_CONTRACTS:
        context = require_protected_context(root, arguments.id)
        record = preflight_record(root, arguments.id, context)
        path, sidecar, commit = protected_output_paths(root, arguments.id)
        write_preflight_publication(path, sidecar, commit, arguments.output, record)
        return
    if arguments.id == "MIG-005-PROTECTED":
        context = require_pitr_protected_context(root)
        record = pitr_record(context)
        path, sidecar, commit = protected_output_paths(root, arguments.id)
        write_preflight_publication(path, sidecar, commit, arguments.output, record)
        return
    revision = require_git_revision(root)
    if arguments.id == "OPS-001":
        checks, input_hashes = toolchain_checks(root)
    elif arguments.id == "OPS-002":
        checks, input_hashes = provider_input(root)
    else:
        fail()
    record = make_record(arguments.id, arguments.output, revision, checks, input_hashes)
    path, sidecar = output_paths(root, arguments.output)
    write_pair_atomically(path, sidecar, arguments.output, record)


def main(argv: list[str]) -> int:
    try:
        run(parse_arguments(argv))
        return 0
    except EvidenceError:
        print("error: runtime evidence check failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
