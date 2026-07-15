#!/usr/bin/env python3
"""Write canonical AUTH-APPLE-STAGING evidence from live, attested observations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any, NoReturn


PROFILE_ID = "AUTH-APPLE-STAGING"
OUTPUT = "Evidence/runtime/AUTH-APPLE-STAGING.json"
OUTPUT_COMMIT = "Evidence/runtime/AUTH-APPLE-STAGING.commit"
APPROVAL_PATH = "Evidence/runtime/approvals/m2a.json"
APPROVAL_COMMIT = "Evidence/runtime/approvals/m2a.commit"
BUILD_PATH = "Evidence/runtime/M2A-BUILD.json"
UPLOAD_PATH = "Evidence/runtime/M2A-UPLOAD.json"
ASC_RESPONSE_PATH = "Evidence/runtime/live/M2A-ASC-response.json"
CHECKPOINT_PATH = "Evidence/runtime/AUTH-APPLE-STAGING-source.json"
CHECKPOINT_RESPONSE_PATH = "Evidence/runtime/live/M2A-checkpoint-response.json"
CHECKPOINT_SIGNATURE_PATH = "Evidence/runtime/live/M2A-checkpoint-response.sig"
ARCHIVE_PATH = "Evidence/runtime/live/M2A-release.xcarchive.zip"
IPA_PATH = "Evidence/runtime/live/M2A-release.ipa"
RELEASE_TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SHA1_RE = re.compile(r"^[a-f0-9]{40}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
TEAM_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
VALIDATION_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
SENSITIVE_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b|"
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    r"(?:authorization|bearer|password|secret|token|cookie|credential)\s*[:=])"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<![0-9])\+[1-9][0-9]{7,14}(?![0-9])")
FORBIDDEN_KEY_RE = re.compile(r"(?i)(?:password|secret|token|credential|authorization|cookie|email|phone|name|login|payload)")
ROLES = ("Product", "Security", "Ops")
MAX_INPUT_AGE = timedelta(hours=24)
FUTURE_SKEW = timedelta(minutes=5)
MAX_FILE_BYTES = 64 * 1024 * 1024


class EvidenceError(Exception):
    pass


def fail() -> NoReturn:
    raise EvidenceError


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(value: bytes | Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical_bytes(value)).hexdigest()


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail()
        value[key] = item
    return value


def reject_constant(_value: str) -> None:
    fail()


def parse_json(raw: bytes, *, canonical: bool = False) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_object, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()
    if not isinstance(value, dict) or (canonical and raw != canonical_bytes(value) + b"\n"):
        fail()
    return value


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


def parse_timestamp(value: Any, *, require_fresh: bool = True) -> str:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        fail()
    try:
        timestamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail()
    if require_fresh:
        now = datetime.now(timezone.utc)
        if timestamp > now + FUTURE_SKEW or now - timestamp > MAX_INPUT_AGE:
            fail()
    return value


def repository_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], check=False, capture_output=True, stdin=subprocess.DEVNULL
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


def current_revision(root: Path) -> str:
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


def relative_parts(raw_path: str) -> tuple[str, ...]:
    relative = PurePosixPath(raw_path)
    if (
        not raw_path
        or "\\" in raw_path
        or relative.is_absolute()
        or relative.as_posix() != raw_path
        or not relative.parts
        or any(part in {".", ".."} for part in relative.parts)
    ):
        fail()
    return relative.parts


def open_directory(root: Path, parts: tuple[str, ...], *, create: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError:
        fail()
    try:
        for part in parts:
            try:
                if create:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        os.close(descriptor)
        fail()


def read_relative(root: Path, raw_path: str, *, limit: int = MAX_FILE_BYTES) -> bytes:
    parts = relative_parts(raw_path)
    directory = open_directory(root, parts[:-1], create=False)
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size <= 0 or details.st_size > limit:
                fail()
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) != details.st_size or len(data) > limit:
                fail()
            return bytes(data)
        finally:
            os.close(descriptor)
    except OSError:
        fail()
    finally:
        os.close(directory)


def require_runtime_environment() -> tuple[str, str, str, str, str, str]:
    if (
        os.environ.get("M2A_EVIDENCE_PROFILE_DISPATCH") != PROFILE_ID
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_WORKFLOW") != "Release Evidence"
        or os.environ.get("GITHUB_JOB") != "m2a-auth-shell"
        or os.environ.get("M2A_PROTECTED_ENVIRONMENT") != "staging"
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
    ):
        fail()
    run_id = os.environ.get("GITHUB_RUN_ID")
    git_sha = os.environ.get("GITHUB_SHA")
    repository = os.environ.get("GITHUB_REPOSITORY")
    release_tag = os.environ.get("GITHUB_REF_NAME")
    github_ref = os.environ.get("GITHUB_REF")
    token = os.environ.get("GITHUB_TOKEN")
    if (
        run_id is None
        or RUN_ID_RE.fullmatch(run_id) is None
        or git_sha is None
        or SHA1_RE.fullmatch(git_sha) is None
        or repository is None
        or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
        or release_tag is None
        or RELEASE_TAG_RE.fullmatch(release_tag) is None
        or github_ref != f"refs/tags/{release_tag}"
        or token is None
        or not token
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        fail()
    return run_id, git_sha, repository, release_tag, github_ref, token


def verify_signed_tag(root: Path, tag: str, git_sha: str) -> None:
    resolved = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{tag}^{{}}"],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    try:
        tag_sha = resolved.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        fail()
    fingerprint = os.environ.get("M2A_RELEASE_TAG_SIGNING_FINGERPRINT", "").upper()
    if re.fullmatch(r"[A-F0-9]{40,64}", fingerprint) is None:
        fail()
    verified = subprocess.run(
        ["git", "-C", str(root), "verify-tag", "--raw", tag],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    try:
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


def github_api_json(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hiker-m2a-evidence-writer",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != url:
                fail()
            raw = response.read(512 * 1024 + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError):
        fail()
    if not raw or len(raw) > 512 * 1024:
        fail()
    return parse_json(raw)


def require_live_github_run(repository: str, run_id: str, git_sha: str, tag: str, token: str) -> None:
    run = github_api_json(f"https://api.github.com/repos/{repository}/actions/runs/{run_id}", token)
    workflow_path = run.get("path")
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != git_sha
        or run.get("head_branch") != tag
        or run.get("name") != "Release Evidence"
        or not isinstance(workflow_path, str)
        or not workflow_path.startswith(".github/workflows/release-evidence.yml@")
        or run.get("status") != "in_progress"
    ):
        fail()
    jobs = github_api_json(f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/jobs?per_page=100", token)
    values = jobs.get("jobs")
    if not isinstance(values, list):
        fail()
    matching = [job for job in values if isinstance(job, dict) and job.get("name") == "m2a-auth-shell"]
    if len(matching) != 1 or matching[0].get("status") != "in_progress":
        fail()


def verify_github_attestation(root: Path, raw_path: str, repository: str, tag: str, token: str) -> None:
    artifact = root.joinpath(*relative_parts(raw_path))
    if shutil.which("gh") is None:
        fail()
    environment = {"GH_TOKEN": token, "PATH": os.environ.get("PATH", "")}
    identity = f"https://github.com/{repository}/.github/workflows/release-evidence.yml@refs/tags/{tag}"
    command = [
        "gh",
        "attestation",
        "verify",
        str(artifact),
        "--repo",
        repository,
        "--cert-identity",
        identity,
        "--cert-oidc-issuer",
        "https://token.actions.githubusercontent.com",
    ]
    for _ in range(12):
        result = subprocess.run(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
        if result.returncode == 0:
            return
        time.sleep(5)
    fail()


def validate_build(
    document: dict[str, Any], root: Path, run_id: str, git_sha: str, tag: str, repository: str, token: str
) -> tuple[str, str]:
    expected = {
        "schemaVersion",
        "artifactType",
        "githubRunId",
        "gitSHA",
        "releaseTag",
        "archivePath",
        "archiveSHA256",
        "ipaPath",
        "ipaSHA256",
        "bundleIdentifier",
        "signingTeamId",
        "codeSigningMetadataSHA256",
        "collectedAt",
    }
    if set(document) != expected or document.get("schemaVersion") != 2 or document.get("artifactType") != "m2a-signed-release-archive":
        fail()
    bundle_id = os.environ.get("M2A_BUNDLE_ID")
    signing_team = os.environ.get("M2A_SIGNING_TEAM_ID")
    if (
        document.get("githubRunId") != run_id
        or document.get("gitSHA") != git_sha
        or document.get("releaseTag") != tag
        or document.get("archivePath") != ARCHIVE_PATH
        or document.get("ipaPath") != IPA_PATH
        or not isinstance(bundle_id, str)
        or not re.fullmatch(r"[A-Za-z0-9.-]{3,255}", bundle_id)
        or document.get("bundleIdentifier") != bundle_id
        or not isinstance(signing_team, str)
        or TEAM_ID_RE.fullmatch(signing_team) is None
        or document.get("signingTeamId") != signing_team
        or any(not isinstance(document.get(field), str) or SHA256_RE.fullmatch(document[field]) is None for field in ("archiveSHA256", "ipaSHA256", "codeSigningMetadataSHA256"))
    ):
        fail()
    parse_timestamp(document.get("collectedAt"))
    archive = read_relative(root, ARCHIVE_PATH)
    ipa = read_relative(root, IPA_PATH)
    if sha256(archive) != document["archiveSHA256"] or sha256(ipa) != document["ipaSHA256"]:
        fail()
    verify_github_attestation(root, ARCHIVE_PATH, repository, tag, token)
    verify_github_attestation(root, IPA_PATH, repository, tag, token)
    try:
        with tempfile.TemporaryDirectory(prefix="m2a-archive-") as extraction:
            destination = Path(extraction)
            with zipfile.ZipFile(Path(extraction, "archive.zip"), "w") as _placeholder:
                pass
            archive_file = Path(extraction, "archive.zip")
            archive_file.write_bytes(archive)
            with zipfile.ZipFile(archive_file) as package:
                members = package.infolist()
                if not members or package.testzip() is not None:
                    fail()
                for member in members:
                    name = PurePosixPath(member.filename)
                    if name.is_absolute() or any(part in {"", ".", ".."} for part in name.parts) or stat.S_ISLNK(member.external_attr >> 16):
                        fail()
                package.extractall(destination)
            application = destination / "M2A-release.xcarchive" / "Products" / "Applications" / "HikerApp.app"
            info = application / "Info.plist"
            if not application.is_dir() or not info.is_file():
                fail()
            verified = subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", str(application)],
                check=False,
                capture_output=True,
                stdin=subprocess.DEVNULL,
            )
            details = subprocess.run(
                ["codesign", "-d", "--verbose=4", str(application)],
                check=False,
                capture_output=True,
                stdin=subprocess.DEVNULL,
            )
            identifier = subprocess.run(
                ["plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", str(info)],
                check=False,
                capture_output=True,
                stdin=subprocess.DEVNULL,
            )
            if verified.returncode != 0 or details.returncode != 0 or identifier.returncode != 0:
                fail()
            try:
                observed_identifier = identifier.stdout.decode("utf-8", "strict").strip()
                metadata = details.stdout.decode("utf-8", "strict") + details.stderr.decode("utf-8", "strict")
            except UnicodeDecodeError:
                fail()
            metadata_lines = sorted(
                line.strip() for line in metadata.splitlines() if line.startswith(("Identifier=", "TeamIdentifier=", "Authority="))
            )
            if (
                observed_identifier != bundle_id
                or f"TeamIdentifier={signing_team}" not in metadata_lines
                or not any(line.startswith("Authority=Apple") for line in metadata_lines)
                or sha256("\n".join(metadata_lines).encode("utf-8")) != document["codeSigningMetadataSHA256"]
            ):
                fail()
    except (OSError, zipfile.BadZipFile):
        fail()
    return document["archiveSHA256"], document["ipaSHA256"]


def validate_upload(
    document: dict[str, Any], asc_response: dict[str, Any], run_id: str, git_sha: str, build_digest: str, testflight_digest: str
) -> None:
    expected = {
        "schemaVersion",
        "artifactType",
        "githubRunId",
        "gitSHA",
        "buildDigest",
        "testFlightDigest",
        "ipaPath",
        "appStoreBuildId",
        "appStoreBuildVersion",
        "apiEndpoint",
        "apiResponseSHA256",
        "uploadResponseSHA256",
        "observedAt",
    }
    response_expected = {
        "schemaVersion",
        "artifactType",
        "apiEndpoint",
        "statusCode",
        "appStoreBuildId",
        "appStoreBuildVersion",
        "uploadedDate",
        "querySHA256",
    }
    if (
        set(document) != expected
        or document.get("schemaVersion") != 2
        or document.get("artifactType") != "app-store-connect-testflight-observation"
        or document.get("githubRunId") != run_id
        or document.get("gitSHA") != git_sha
        or document.get("buildDigest") != build_digest
        or document.get("testFlightDigest") != testflight_digest
        or document.get("ipaPath") != IPA_PATH
        or document.get("apiEndpoint") != "https://api.appstoreconnect.apple.com/v1/builds"
        or not isinstance(document.get("appStoreBuildId"), str)
        or not document["appStoreBuildId"].isdigit()
        or not isinstance(document.get("appStoreBuildVersion"), str)
        or not document["appStoreBuildVersion"].isdigit()
        or any(not isinstance(document.get(field), str) or SHA256_RE.fullmatch(document[field]) is None for field in ("apiResponseSHA256", "uploadResponseSHA256"))
        or set(asc_response) != response_expected
        or asc_response.get("schemaVersion") != 1
        or asc_response.get("artifactType") != "app-store-connect-build-response"
        or asc_response.get("apiEndpoint") != document["apiEndpoint"]
        or asc_response.get("statusCode") != 200
        or asc_response.get("appStoreBuildId") != document["appStoreBuildId"]
        or asc_response.get("appStoreBuildVersion") != document["appStoreBuildVersion"]
        or not isinstance(asc_response.get("uploadedDate"), str)
        or not isinstance(asc_response.get("querySHA256"), str)
        or SHA256_RE.fullmatch(asc_response["querySHA256"]) is None
    ):
        fail()
    parse_timestamp(document.get("observedAt"))
    parse_timestamp(asc_response.get("uploadedDate"))
    if sha256(canonical_bytes(asc_response)) != document["apiResponseSHA256"]:
        fail()


def verify_checkpoint_signature(root: Path, response: bytes, signature: bytes) -> None:
    encoded_key = os.environ.get("M2A_CHECKPOINT_RECEIPT_PUBLIC_KEY_BASE64")
    if encoded_key is None or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded_key):
        fail()
    try:
        public_key = base64.b64decode(encoded_key, validate=True)
    except ValueError:
        fail()
    if len(public_key) < 64 or b"BEGIN PUBLIC KEY" not in public_key:
        fail()
    try:
        with tempfile.TemporaryDirectory(prefix="m2a-receipt-key-") as directory:
            key_path = Path(directory, "receipt-public.pem")
            body_path = Path(directory, "response.json")
            signature_path = Path(directory, "response.sig")
            key_path.write_bytes(public_key)
            body_path.write_bytes(response)
            signature_path.write_bytes(signature)
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path), "-rawin", "-in", str(body_path), "-sigfile", str(signature_path)],
                check=False,
                capture_output=True,
                stdin=subprocess.DEVNULL,
            )
            if result.returncode != 0:
                fail()
    except OSError:
        fail()


def validate_checkpoint(
    document: dict[str, Any], response: dict[str, Any], response_raw: bytes, signature: bytes, run_id: str, git_sha: str, build_digest: str, testflight_digest: str, root: Path
) -> None:
    validation_fields = (
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
    )
    required_response = {
        "schemaVersion",
        "receiptId",
        "transactionId",
        "githubRunId",
        "gitSHA",
        "buildDigest",
        "testFlightBuildDigest",
        "actorCorrelationSHA256",
        "nonceSHA256",
        "stateSHA256",
        "callbackSHA256",
        *validation_fields,
        "completedAt",
        "receiptSHA256",
    }
    required_document = required_response | {
        "artifactType",
        "receiptResponseSHA256",
        "responseSignatureSHA256",
        "signatureAlgorithm",
        "observedAt",
    }
    if (
        set(response) != required_response
        or set(document) != required_document
        or response.get("schemaVersion") != 1
        or document.get("schemaVersion") != 1
        or document.get("artifactType") != "m2a-immutable-checkpoint-observation"
        or any(document.get(field) != response.get(field) for field in required_response)
        or document.get("signatureAlgorithm") != "ed25519"
        or not isinstance(document.get("receiptResponseSHA256"), str)
        or document["receiptResponseSHA256"] != sha256(response_raw)
        or not isinstance(document.get("responseSignatureSHA256"), str)
        or document["responseSignatureSHA256"] != sha256(signature)
        or document.get("githubRunId") != run_id
        or document.get("gitSHA") != git_sha
        or document.get("buildDigest") != build_digest
        or document.get("testFlightBuildDigest") != testflight_digest
        or any(not isinstance(document.get(field), str) or UUID_RE.fullmatch(document[field]) is None for field in ("receiptId", "transactionId"))
        or any(not isinstance(document.get(field), str) or SHA256_RE.fullmatch(document[field]) is None for field in ("actorCorrelationSHA256", "nonceSHA256", "stateSHA256", "callbackSHA256", "receiptSHA256"))
        or any(document.get(field) is not True for field in ("issuerValidated", "audienceValidated", "providerValidated", "callbackValidated", "supabaseSessionIssued"))
        or any(not isinstance(document.get(field), str) or VALIDATION_CODE_RE.fullmatch(document[field]) is None for field in ("issuerCode", "audienceCode", "providerCode", "callbackCode", "sessionCode"))
    ):
        fail()
    parse_timestamp(document.get("completedAt"))
    parse_timestamp(document.get("observedAt"))
    verify_checkpoint_signature(root, response_raw, signature)


def read_committed_pair(root: Path, raw_path: str, commit_path: str) -> tuple[dict[str, Any], bytes]:
    raw = read_relative(root, raw_path)
    sidecar = read_relative(root, f"{raw_path}.sha256", limit=512)
    commit = parse_json(read_relative(root, commit_path, limit=1024), canonical=True)
    expected_sidecar = f"{sha256(raw)}  {raw_path}\n".encode("ascii")
    expected_commit = {
        "schemaVersion": 1,
        "artifactType": "evidence-publication-commit",
        "evidencePath": raw_path,
        "evidenceSHA256": sha256(raw),
        "sidecarPath": f"{raw_path}.sha256",
        "sidecarSHA256": sha256(expected_sidecar),
    }
    if sidecar != expected_sidecar or commit != expected_commit:
        fail()
    document = parse_json(raw, canonical=True)
    reject_sensitive_data(document)
    return document, raw


def validate_approvals(
    document: dict[str, Any], run_id: str, git_sha: str, build_digest: str, testflight_digest: str, repository: str
) -> None:
    required = {
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
        set(document) != required
        or document.get("schemaVersion") != 2
        or document.get("artifactType") != "m2a-role-approvals"
        or document.get("gate") != "M2A"
        or document.get("pseudonymDomain") != "m2a-approver/v1"
        or not isinstance(document.get("issueURL"), str)
        or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*", document["issueURL"])
        or not document["issueURL"].startswith(f"https://github.com/{repository}/issues/")
        or document.get("githubRunId") != run_id
        or document.get("gitSHA") != git_sha
        or document.get("buildDigest") != build_digest
        or document.get("testFlightDigest") != testflight_digest
        or any(not isinstance(document.get(field), str) or SHA256_RE.fullmatch(document[field]) is None for field in ("issueSnapshotSHA256", "teamSnapshotSHA256"))
    ):
        fail()
    parse_timestamp(document.get("collectedAt"))
    snapshots = document.get("teamSnapshots")
    approvals = document.get("approvals")
    if not isinstance(snapshots, list) or len(snapshots) != 3 or not isinstance(approvals, list) or len(approvals) != 3:
        fail()
    snapshot_by_role: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        if not isinstance(snapshot, dict) or set(snapshot) != {"role", "teamId", "teamSlug", "teamResponseSHA256"}:
            fail()
        role = snapshot.get("role")
        if (
            role not in ROLES
            or role in snapshot_by_role
            or not isinstance(snapshot.get("teamId"), str)
            or not snapshot["teamId"].isdigit()
            or not isinstance(snapshot.get("teamSlug"), str)
            or TEAM_SLUG_RE.fullmatch(snapshot["teamSlug"]) is None
            or not isinstance(snapshot.get("teamResponseSHA256"), str)
            or SHA256_RE.fullmatch(snapshot["teamResponseSHA256"]) is None
        ):
            fail()
        snapshot_by_role[role] = snapshot
    if set(snapshot_by_role) != set(ROLES) or sha256(snapshots) != document["teamSnapshotSHA256"]:
        fail()
    roles: set[str] = set()
    subjects: set[str] = set()
    for approval in approvals:
        if not isinstance(approval, dict) or set(approval) != {
            "role", "status", "subjectPseudonym", "approvedAt", "approvalDigest", "commentSHA256", "membershipAttestations"
        }:
            fail()
        role = approval.get("role")
        subject = approval.get("subjectPseudonym")
        if (
            role not in ROLES
            or role in roles
            or approval.get("status") != "active"
            or not isinstance(subject, str)
            or SHA256_RE.fullmatch(subject) is None
            or subject in subjects
            or any(not isinstance(approval.get(field), str) or SHA256_RE.fullmatch(approval[field]) is None for field in ("approvalDigest", "commentSHA256"))
        ):
            fail()
        parse_timestamp(approval.get("approvedAt"))
        memberships = approval.get("membershipAttestations")
        if not isinstance(memberships, list) or len(memberships) != 3:
            fail()
        states: dict[str, str] = {}
        for membership in memberships:
            if not isinstance(membership, dict) or set(membership) != {"role", "teamId", "teamSlug", "state", "responseSHA256"}:
                fail()
            membership_role = membership.get("role")
            snapshot = snapshot_by_role.get(membership_role)
            if (
                snapshot is None
                or membership_role in states
                or membership.get("teamId") != snapshot["teamId"]
                or membership.get("teamSlug") != snapshot["teamSlug"]
                or membership.get("state") not in {"active", "inactive"}
                or not isinstance(membership.get("responseSHA256"), str)
                or SHA256_RE.fullmatch(membership["responseSHA256"]) is None
            ):
                fail()
            states[membership_role] = membership["state"]
        if set(states) != set(ROLES) or [item for item, state in states.items() if state == "active"] != [role]:
            fail()
        roles.add(role)
        subjects.add(subject)
    if roles != set(ROLES) or len(subjects) != 3:
        fail()


def temporary_name(prefix: str) -> str:
    return f".{prefix}.{secrets.token_hex(16)}.tmp"


def write_file_once(directory: int, name: str, data: bytes) -> str:
    temporary = temporary_name(name)
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


def unlink_name(directory: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory)
    except OSError:
        pass


def ensure_absent(directory: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        fail()
    fail()


def write_pair_atomically(root: Path, record: dict[str, Any]) -> None:
    output_parts = relative_parts(OUTPUT)
    commit_parts = relative_parts(OUTPUT_COMMIT)
    if output_parts[:-1] != commit_parts[:-1]:
        fail()
    directory = open_directory(root, output_parts[:-1], create=False)
    evidence = canonical_bytes(record) + b"\n"
    sidecar = f"{sha256(evidence)}  {OUTPUT}\n".encode("ascii")
    commit = canonical_bytes(
        {
            "schemaVersion": 1,
            "artifactType": "evidence-publication-commit",
            "evidencePath": OUTPUT,
            "evidenceSHA256": sha256(evidence),
            "sidecarPath": f"{OUTPUT}.sha256",
            "sidecarSHA256": sha256(sidecar),
        }
    ) + b"\n"
    names = (output_parts[-1], f"{output_parts[-1]}.sha256", commit_parts[-1])
    temporary: list[str] = []
    published: list[str] = []
    try:
        for name in names:
            ensure_absent(directory, name)
        temporary.append(write_file_once(directory, names[0], evidence))
        published.append(names[0])
        temporary.append(write_file_once(directory, names[1], sidecar))
        published.append(names[1])
        temporary.append(write_file_once(directory, names[2], commit))
        published.append(names[2])
        try:
            os.fsync(directory)
        except OSError:
            pass
    except EvidenceError:
        for name in reversed(published):
            unlink_name(directory, name)
        fail()
    finally:
        for name in temporary:
            unlink_name(directory, name)
        os.close(directory)


def make_record(
    git_sha: str,
    build_digest: str,
    testflight_digest: str,
    build_raw: bytes,
    upload_raw: bytes,
    checkpoint: dict[str, Any],
    checkpoint_raw: bytes,
    approval_raw: bytes,
) -> dict[str, Any]:
    record = {
        "schemaVersion": 2,
        "artifactType": "runtime-evidence",
        "id": PROFILE_ID,
        "status": "passed",
        "correlation": {
            "runId": checkpoint["transactionId"],
            "commitSHA": git_sha,
            "buildDigest": build_digest,
            "testFlightBuildDigest": testflight_digest,
            "checkpointReceiptId": checkpoint["receiptId"],
        },
        "inputHashes": {
            "buildProvenanceSHA256": sha256(build_raw),
            "testFlightObservationSHA256": sha256(upload_raw),
            "checkpointObservationSHA256": sha256(checkpoint_raw),
            "approvalSHA256": sha256(approval_raw),
        },
        "redactedCorrelation": {
            "nonceSHA256": checkpoint["nonceSHA256"],
            "stateSHA256": checkpoint["stateSHA256"],
            "callbackSHA256": checkpoint["callbackSHA256"],
            "actorSHA256": checkpoint["actorCorrelationSHA256"],
        },
        "validations": {
            "issuerValidated": checkpoint["issuerValidated"],
            "issuerCode": checkpoint["issuerCode"],
            "audienceValidated": checkpoint["audienceValidated"],
            "audienceCode": checkpoint["audienceCode"],
            "providerValidated": checkpoint["providerValidated"],
            "providerCode": checkpoint["providerCode"],
            "callbackValidated": checkpoint["callbackValidated"],
            "callbackCode": checkpoint["callbackCode"],
            "supabaseSessionIssued": checkpoint["supabaseSessionIssued"],
            "sessionCode": checkpoint["sessionCode"],
        },
        "checkpoint": {
            "receiptSHA256": checkpoint["receiptSHA256"],
            "responseSHA256": checkpoint["receiptResponseSHA256"],
            "signatureSHA256": checkpoint["responseSignatureSHA256"],
            "completedAt": checkpoint["completedAt"],
        },
        "collectedAt": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "output": {"path": OUTPUT, "commitPath": OUTPUT_COMMIT},
    }
    reject_sensitive_data(record)
    return record


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def run(arguments: argparse.Namespace) -> None:
    if arguments.profile_id != PROFILE_ID or arguments.output != OUTPUT:
        fail()
    run_id, git_sha, repository, tag, _github_ref, token = require_runtime_environment()
    root = repository_root()
    if current_revision(root) != git_sha:
        fail()
    verify_signed_tag(root, tag, git_sha)
    require_live_github_run(repository, run_id, git_sha, tag, token)
    build, build_raw = read_committed_pair(root, BUILD_PATH, "Evidence/runtime/M2A-BUILD.commit")
    build_digest, testflight_digest = validate_build(build, root, run_id, git_sha, tag, repository, token)
    upload, upload_raw = read_committed_pair(root, UPLOAD_PATH, "Evidence/runtime/M2A-UPLOAD.commit")
    asc_response = parse_json(read_relative(root, ASC_RESPONSE_PATH), canonical=True)
    reject_sensitive_data(asc_response)
    validate_upload(upload, asc_response, run_id, git_sha, build_digest, testflight_digest)
    checkpoint, checkpoint_raw = read_committed_pair(root, CHECKPOINT_PATH, "Evidence/runtime/AUTH-APPLE-STAGING-source.commit")
    response_raw = read_relative(root, CHECKPOINT_RESPONSE_PATH)
    response = parse_json(response_raw)
    reject_sensitive_data(response)
    signature = read_relative(root, CHECKPOINT_SIGNATURE_PATH, limit=4096)
    validate_checkpoint(checkpoint, response, response_raw, signature, run_id, git_sha, build_digest, testflight_digest, root)
    approvals, approval_raw = read_committed_pair(root, APPROVAL_PATH, APPROVAL_COMMIT)
    validate_approvals(approvals, run_id, git_sha, build_digest, testflight_digest, repository)
    write_pair_atomically(
        root,
        make_record(git_sha, build_digest, testflight_digest, build_raw, upload_raw, checkpoint, checkpoint_raw, approval_raw),
    )


def main(argv: list[str]) -> int:
    try:
        run(parse_arguments(argv))
        return 0
    except EvidenceError:
        print("error: live, attested AUTH-APPLE-STAGING evidence is unavailable or invalid", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
