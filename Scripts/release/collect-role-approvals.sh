#!/usr/bin/env bash
# Collect immutable, live GitHub-team role approvals for one release gate.
set -euo pipefail

exec python3 - "$@" <<'PY'
from __future__ import annotations

import base64
import hashlib
import hmac
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
import urllib.error
import urllib.request
from typing import Any, NoReturn


class ApprovalError(Exception):
    pass


def fail() -> NoReturn:
    raise ApprovalError


SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TEAM_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
TEAM_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
GATE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,63}$")
TRANSITION_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
ISSUE_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repository>[A-Za-z0-9_.-]+)/issues/(?P<number>[1-9][0-9]*)$"
)
LOGIN_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
SENSITIVE_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b|"
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    r"(?:authorization|bearer|password|secret|token|cookie|credential)\s*[:=])"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<![0-9])\+[1-9][0-9]{7,14}(?![0-9])")
ROLES = ("Product", "Security", "Ops")
COMMENT_KEYS = (
    "gate",
    "role",
    "status",
    "tag",
    "commit",
    "manifestSHA256",
    "transition",
    "metricSHA256",
    "approvedAt",
    "approvalDigest",
)
MAX_APPROVAL_AGE = timedelta(hours=24)
FUTURE_SKEW = timedelta(minutes=5)
COMMENT_TIME_SKEW = timedelta(minutes=5)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(value: bytes | Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical_bytes(value)).hexdigest()


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            fail()
        result[key] = item
    return result


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
    if not arguments:
        required_environment = {
            "issue_url": "M2A_APPROVAL_ISSUE_URL",
            "manifest_sha": "M2A_BUILD_DIGEST",
            "metric_sha": "M2A_TESTFLIGHT_DIGEST",
        }
        values = {
            "mode": "m2a",
            "gate": "M2A",
            "tag": os.environ.get("GITHUB_REF_NAME", ""),
            "commit": os.environ.get("GITHUB_SHA", ""),
            "transition": "m2a",
            "output": "Evidence/runtime/approvals/m2a.json",
        }
        for key, environment_name in required_environment.items():
            values[key] = os.environ.get(environment_name, "")
        return values
    required = {
        "--gate": "gate",
        "--issue-url": "issue_url",
        "--tag": "tag",
        "--commit": "commit",
        "--manifest-sha": "manifest_sha",
        "--transition": "transition",
        "--metric-sha": "metric_sha",
        "--output": "output",
        "--input-hashes-json": "input_hashes_json",
    }
    values: dict[str, str] = {"mode": "release"}
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option not in required or index + 1 >= len(arguments):
            fail()
        value = arguments[index + 1]
        key = required[option]
        if key in values or not value or value.startswith("--"):
            fail()
        values[key] = value
        index += 2
    required_keys = set(required.values()) - {"input_hashes_json"}
    if not required_keys.issubset(values) or set(values) - {"mode"} - set(required.values()):
        fail()
    values.setdefault("input_hashes_json", "")
    return values


def require_environment_value(name: str, expression: re.Pattern[str]) -> str:
    value = os.environ.get(name)
    if value is None or expression.fullmatch(value) is None:
        fail()
    return value


def require_environment(gate: str, tag: str, commit: str) -> tuple[str, str, str, dict[str, tuple[str, str]]]:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_WORKFLOW") != "Release Evidence"
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
        or os.environ.get("GITHUB_REF_NAME") != tag
        or os.environ.get("GITHUB_SHA") != commit
    ):
        fail()
    repository = os.environ.get("GITHUB_REPOSITORY")
    if repository is None or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        fail()
    run_id = require_environment_value("GITHUB_RUN_ID", RUN_ID_RE)
    prefix = "M2A" if gate.upper() == "M2A" else "RELEASE"
    expected_environment = "staging" if prefix == "M2A" else "production"
    if os.environ.get(f"{prefix}_PROTECTED_ENVIRONMENT") != expected_environment:
        fail()
    token = os.environ.get(f"{prefix}_APPROVALS_TOKEN")
    if token is None or not token or any(ord(character) < 33 or ord(character) > 126 for character in token):
        fail()
    teams: dict[str, tuple[str, str]] = {}
    for role in ROLES:
        base = f"{prefix}_{role.upper()}_TEAM"
        team_id = require_environment_value(f"{base}_ID", TEAM_ID_RE)
        team_slug = require_environment_value(f"{base}_SLUG", TEAM_SLUG_RE)
        if team_id in {configured[0] for configured in teams.values()} or team_slug in {configured[1] for configured in teams.values()}:
            fail()
        teams[role] = (team_id, team_slug)
    return repository, run_id, token, teams


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


def validate_checkout(root: Path, tag: str, commit: str) -> None:
    if git_output(root, "rev-parse", "--verify", "HEAD") != commit:
        fail()
    if git_output(root, "rev-parse", "--verify", f"{tag}^{{commit}}") != commit:
        fail()


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        fail()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail()


def reject_sensitive_text(value: str) -> None:
    if (
        not value
        or len(value) > 8192
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
        or SENSITIVE_RE.search(value) is not None
        or EMAIL_RE.search(value) is not None
        or PHONE_RE.search(value) is not None
    ):
        fail()


def api_response(url: str, token: str, *, allow_not_found: bool = False) -> tuple[int, Any, str]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hiker-release-role-approval-collector",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
            if status != 200 or response.geturl() != url:
                fail()
            raw = response.read(512 * 1024 + 1)
    except urllib.error.HTTPError as error:
        if not allow_not_found or error.code != 404:
            fail()
        status = error.code
        try:
            raw = error.read(512 * 1024 + 1)
        except OSError:
            fail()
    except (OSError, urllib.error.URLError):
        fail()
    if not raw or len(raw) > 512 * 1024:
        fail()
    value = parse_json(raw)
    return status, value, sha256(canonical_bytes(value))


def comment_fields(body: Any) -> dict[str, str] | None:
    if not isinstance(body, str):
        fail()
    if "ROLE-APPROVAL" not in body:
        return None
    reject_sensitive_text(body)
    if body.endswith("\n") or "\r" in body:
        fail()
    lines = body.split("\n")
    if len(lines) != len(COMMENT_KEYS) + 1 or lines[0] != "ROLE-APPROVAL v1":
        fail()
    values: dict[str, str] = {}
    for key, line in zip(COMMENT_KEYS, lines[1:]):
        prefix = f"{key}: "
        if not line.startswith(prefix):
            fail()
        value = line[len(prefix) :]
        reject_sensitive_text(value)
        values[key] = value
    if set(values) != set(COMMENT_KEYS):
        fail()
    return values


def collect_comments(repository: str, issue_number: str, token: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    page = 1
    while True:
        status, data, _digest = api_response(
            f"https://api.github.com/repos/{repository}/issues/{issue_number}/comments?per_page=100&page={page}", token
        )
        if status != 200 or not isinstance(data, list) or len(data) > 100 or any(not isinstance(item, dict) for item in data):
            fail()
        comments.extend(data)
        if len(data) < 100:
            return comments
        page += 1
        if page > 1000:
            fail()


def validate_issue(issue: Any, issue_url: str) -> None:
    if not isinstance(issue, dict) or (
        issue.get("html_url") != issue_url
        or issue.get("state") != "open"
        or issue.get("locked") is not False
        or "pull_request" in issue
    ):
        fail()


def team_snapshots(owner: str, token: str, teams: dict[str, tuple[str, str]]) -> list[dict[str, str]]:
    snapshots: list[dict[str, str]] = []
    for role in ROLES:
        configured_id, slug = teams[role]
        status, team, digest = api_response(f"https://api.github.com/orgs/{owner}/teams/{slug}", token)
        if (
            status != 200
            or not isinstance(team, dict)
            or type(team.get("id")) is not int
            or team["id"] <= 0
            or str(team["id"]) != configured_id
            or team.get("slug") != slug
        ):
            fail()
        snapshots.append({"role": role, "teamSlug": slug, "responseSHA256": digest})
    return snapshots


def membership_attestations(
    owner: str, login: str, token: str, teams: dict[str, tuple[str, str]]
) -> list[dict[str, str]]:
    attestations: list[dict[str, str]] = []
    for role in ROLES:
        _team_id, slug = teams[role]
        status, membership, digest = api_response(
            f"https://api.github.com/orgs/{owner}/teams/{slug}/memberships/{login}", token, allow_not_found=True
        )
        if status == 200:
            if not isinstance(membership, dict) or membership.get("state") != "active" or membership.get("role") not in {"member", "maintainer"}:
                fail()
            state = "active"
        elif status == 404:
            if not isinstance(membership, dict):
                fail()
            state = "inactive"
        else:
            fail()
        attestations.append({"role": role, "teamSlug": slug, "state": state, "responseSHA256": digest})
    return attestations


def approval_records(
    comments: list[dict[str, Any]],
    owner: str,
    token: str,
    teams: dict[str, tuple[str, str]],
    context: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    now = datetime.now(timezone.utc)
    records: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    seen_roles: set[str] = set()
    seen_logins: set[str] = set()
    seen_comment_ids: set[int] = set()
    seen_approval_digests: set[str] = set()
    seen_comment_digests: set[str] = set()
    for comment in comments:
        fields = comment_fields(comment.get("body"))
        if fields is None:
            continue
        if fields["gate"] != context["gate"]:
            continue
        if (
            fields["role"] not in ROLES
            or fields["status"] != "active"
            or fields["tag"] != context["tag"]
            or fields["commit"] != context["commit"]
            or fields["manifestSHA256"] != context["manifest_sha"]
            or fields["transition"] != context["transition"]
            or fields["metricSHA256"] != context["metric_sha"]
            or SHA256_RE.fullmatch(fields["approvalDigest"]) is None
        ):
            fail()
        approved_at = parse_timestamp(fields["approvedAt"])
        created_at = parse_timestamp(comment.get("created_at"))
        if (
            approved_at > now + FUTURE_SKEW
            or created_at > now + FUTURE_SKEW
            or now - approved_at > MAX_APPROVAL_AGE
            or now - created_at > MAX_APPROVAL_AGE
            or abs(created_at - approved_at) > COMMENT_TIME_SKEW
        ):
            fail()
        user = comment.get("user")
        comment_id = comment.get("id")
        association = comment.get("author_association")
        if (
            not isinstance(user, dict)
            or type(user.get("id")) is not int
            or user["id"] <= 0
            or not isinstance(user.get("login"), str)
            or LOGIN_RE.fullmatch(user["login"]) is None
            or user.get("type") != "User"
            or association not in {"OWNER", "MEMBER", "COLLABORATOR"}
            or type(comment_id) is not int
            or comment_id <= 0
        ):
            fail()
        role = fields["role"]
        login = user["login"]
        attestations = membership_attestations(owner, login, token, teams)
        active_roles = [entry["role"] for entry in attestations if entry["state"] == "active"]
        comment_digest = sha256(comment["body"].encode("ascii"))
        if (
            role in seen_roles
            or login.lower() in seen_logins
            or comment_id in seen_comment_ids
            or fields["approvalDigest"] in seen_approval_digests
            or comment_digest in seen_comment_digests
            or active_roles != [role]
        ):
            fail()
        seen_roles.add(role)
        seen_logins.add(login.lower())
        seen_comment_ids.add(comment_id)
        seen_approval_digests.add(fields["approvalDigest"])
        seen_comment_digests.add(comment_digest)
        body = comment["body"]
        records.append(
            {
                "role": role,
                "status": "active",
                "commentId": comment_id,
                "login": login,
                "createdAt": comment["created_at"],
                "approvedAt": fields["approvedAt"],
                "approvalDigest": fields["approvalDigest"],
                "commentSHA256": comment_digest,
                "membershipAttestations": attestations,
            }
        )
        snapshots.append(
            {"commentId": comment_id, "createdAt": comment["created_at"], "login": login, "commentSHA256": comment_digest}
        )
    if len(records) != 3 or seen_roles != set(ROLES) or len(seen_logins) != 3:
        fail()
    records.sort(key=lambda item: ROLES.index(item["role"]))
    snapshots.sort(key=lambda item: item["commentId"])
    return records, snapshots


def relative_parts(raw_path: str) -> tuple[str, ...]:
    path = PurePosixPath(raw_path)
    if (
        not raw_path
        or "\\" in raw_path
        or path.is_absolute()
        or path.as_posix() != raw_path
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
    ):
        fail()
    return path.parts


def validate_output(gate: str, output: str) -> None:
    expected = f"Evidence/runtime/approvals/{gate.lower()}.json"
    if output != expected:
        fail()
    relative_parts(output)


def open_directory(root: Path, parts: tuple[str, ...]) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError:
        fail()
    try:
        for part in parts:
            try:
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


def ensure_absent(directory: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        fail()
    fail()


def unlink_name(directory: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory)
    except OSError:
        pass


def write_file_once(directory: int, name: str, data: bytes) -> str:
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
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


def write_pair(root: Path, output: str, record: dict[str, Any]) -> None:
    parts = relative_parts(output)
    directory = open_directory(root, parts[:-1])
    evidence = canonical_bytes(record) + b"\n"
    sidecar = f"{sha256(evidence)}  {output}\n".encode("ascii")
    names = (parts[-1], f"{parts[-1]}.sha256")
    temporary: list[str] = []
    published: list[str] = []
    try:
        for name in names:
            ensure_absent(directory, name)
        for name, data in zip(names, (evidence, sidecar)):
            temporary.append(write_file_once(directory, name, data))
            published.append(name)
        os.fsync(directory)
    except (ApprovalError, OSError):
        for name in reversed(published):
            unlink_name(directory, name)
        fail()
    finally:
        for name in temporary:
            unlink_name(directory, name)
        os.close(directory)


def run() -> None:
    context = parse_arguments(sys.argv[1:])
    if (
        GATE_RE.fullmatch(context["gate"]) is None
        or ISSUE_URL_RE.fullmatch(context["issue_url"]) is None
        or TAG_RE.fullmatch(context["tag"]) is None
        or COMMIT_RE.fullmatch(context["commit"]) is None
        or SHA256_RE.fullmatch(context["manifest_sha"]) is None
        or TRANSITION_RE.fullmatch(context["transition"]) is None
        or SHA256_RE.fullmatch(context["metric_sha"]) is None
    ):
        fail()
    for value in context.values():
        reject_sensitive_text(value)
    validate_output(context["gate"], context["output"])
    repository, run_id, token, teams = require_environment(context["gate"], context["tag"], context["commit"])
    root = repository_root()
    validate_checkout(root, context["tag"], context["commit"])
    issue_match = ISSUE_URL_RE.fullmatch(context["issue_url"])
    if issue_match is None or f"{issue_match['owner']}/{issue_match['repository']}" != repository:
        fail()
    status, issue, _issue_digest = api_response(
        f"https://api.github.com/repos/{repository}/issues/{issue_match['number']}", token
    )
    if status != 200:
        fail()
    validate_issue(issue, context["issue_url"])
    teams_observed = team_snapshots(issue_match["owner"], token, teams)
    approvals, comments = approval_records(
        collect_comments(repository, issue_match["number"], token),
        issue_match["owner"],
        token,
        teams,
        context,
    )
    collected_at = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    if context["mode"] == "m2a":
        try:
            pseudonym_key = base64.b64decode(os.environ.get("M2A_APPROVER_PSEUDONYM_KEY_BASE64", ""), validate=True)
        except ValueError:
            fail()
        if len(pseudonym_key) < 32:
            fail()
        m2a_teams = [
            {
                "role": team["role"],
                "teamId": teams[team["role"]][0],
                "teamSlug": team["teamSlug"],
                "teamResponseSHA256": team["responseSHA256"],
            }
            for team in teams_observed
        ]
        m2a_approvals = []
        for approval in approvals:
            memberships = [
                {
                    **membership,
                    "teamId": teams[membership["role"]][0],
                }
                for membership in approval["membershipAttestations"]
            ]
            m2a_approvals.append(
                {
                    "role": approval["role"],
                    "status": approval["status"],
                    "subjectPseudonym": hmac.new(
                        pseudonym_key,
                        approval["login"].lower().encode("ascii"),
                        hashlib.sha256,
                    ).hexdigest(),
                    "approvedAt": approval["approvedAt"],
                    "approvalDigest": approval["approvalDigest"],
                    "commentSHA256": approval["commentSHA256"],
                    "membershipAttestations": memberships,
                }
            )
        record = {
            "schemaVersion": 2,
            "artifactType": "m2a-role-approvals",
            "gate": "M2A",
            "issueURL": context["issue_url"],
            "issueSnapshotSHA256": sha256(
                {"issueURL": context["issue_url"], "state": "open", "locked": False, "approvals": comments}
            ),
            "teamSnapshotSHA256": sha256(m2a_teams),
            "githubRunId": run_id,
            "gitSHA": context["commit"],
            "buildDigest": context["manifest_sha"],
            "testFlightDigest": context["metric_sha"],
            "pseudonymDomain": "m2a-approver/v1",
            "collectedAt": collected_at,
            "teamSnapshots": m2a_teams,
            "approvals": m2a_approvals,
        }
    else:
        record = {
            "schemaVersion": 1,
            "artifactType": "release-role-approvals",
            "gate": context["gate"],
            "issueURL": context["issue_url"],
            "releaseTag": context["tag"],
            "commitSHA": context["commit"],
            "buildDigest": require_environment_value("HIKER_RELEASE_BUILD_DIGEST", SHA256_RE),
            "observedInputSHA256": context["manifest_sha"],
            "transition": context["transition"],
            "predecessorEventSHA256": context["metric_sha"],
            "githubRunId": run_id,
            "createdAt": collected_at,
            "issueSnapshotSHA256": sha256(
                {"issueURL": context["issue_url"], "state": "open", "locked": False, "approvals": comments}
            ),
            "teamSnapshotSHA256": sha256(teams_observed),
            "teamSnapshots": teams_observed,
            "approvals": approvals,
        }
        if context["transition"] in {"activate-1pct", "phase-5", "phase-25", "phase-50", "phase-100", "contract-remove-old"}:
            record["rcManifestSHA256"] = require_environment_value("HIKER_RELEASE_RC_MANIFEST_SHA", SHA256_RE)
            record["m6ExitSHA256"] = require_environment_value("HIKER_RELEASE_M6_EXIT_SHA", SHA256_RE)
        if context["transition"] in {"phase-5", "phase-25", "phase-50", "phase-100"}:
            record["phaseFloorSHA256"] = require_environment_value("HIKER_RELEASE_PHASE_FLOOR_SHA", SHA256_RE)
        if context["input_hashes_json"]:
            try:
                input_hashes = parse_json(context["input_hashes_json"].encode("utf-8", "strict"))
            except UnicodeError:
                fail()
            required_hashes = {
                "perfSHA256",
                "ops003SHA256",
                "ops004SHA256",
                "betaSHA256",
                "thresholdSHA256",
                "authSHA256",
            }
            if (
                not isinstance(input_hashes, dict)
                or set(input_hashes) != required_hashes
                or any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in input_hashes.values())
            ):
                fail()
            record["inputHashes"] = input_hashes
    write_pair(root, context["output"], record)


def main() -> int:
    try:
        run()
        return 0
    except ApprovalError:
        print("error: current protected role approvals are unavailable or invalid", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
PY
