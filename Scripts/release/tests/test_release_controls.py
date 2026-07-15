#!/usr/bin/env python3
"""Hermetic negative coverage for local release-control validation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_FLOORS = REPOSITORY_ROOT / "Scripts" / "release" / "validate-runtime-floors.py"
LINEAGE_SCRIPT = REPOSITORY_ROOT / "Scripts" / "release" / "validate-release-lineage.py"
MIGRATION_CONTROLLER = REPOSITORY_ROOT / "Scripts" / "release" / "migration-controller.sh"
SWITCH_DRILL = REPOSITORY_ROOT / "Scripts" / "release" / "produce-switch-drill-evidence.sh"
THRESHOLD_SCHEMA = REPOSITORY_ROOT / "Docs" / "evidence" / "schemas" / "threshold-ratification.schema.json"

SPEC = importlib.util.spec_from_file_location("release_lineage_controls_under_test", LINEAGE_SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not import release lineage validator from {LINEAGE_SCRIPT}")
LINEAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LINEAGE
SPEC.loader.exec_module(LINEAGE)

TAG = "v1.2.3"
COMMIT = "a" * 40
SHA = "b" * 64


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(value: bytes | object) -> str:
    data = value if isinstance(value, bytes) else canonical_bytes(value)
    return hashlib.sha256(data).hexdigest()


def timestamp(value: datetime) -> str:
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_document(root: Path, relative: str, document: object) -> str:
    raw = canonical_bytes(document) + b"\n"
    return write_raw(root, relative, raw)


def write_raw(root: Path, relative: str, raw: bytes) -> str:
    path = root.joinpath(*Path(relative).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    digest = sha256(raw)
    Path(f"{path}.sha256").write_bytes(f"{digest}  {relative}\n".encode("ascii"))
    return digest


def tree_snapshot(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def initialize_repository(root: Path) -> None:
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, stdin=subprocess.DEVNULL)


class RuntimeFloorControlsTests(unittest.TestCase):
    def make_fixture(
        self,
        identifier: str = "REL-005",
        *,
        duration_hours: float | None = None,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, object], dict[str, object]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        initialize_repository(root)
        schema_path = root / "Docs" / "evidence" / "schemas" / "threshold-ratification.schema.json"
        schema_path.parent.mkdir(parents=True)
        schema_path.write_bytes(THRESHOLD_SCHEMA.read_bytes())

        thresholds: dict[str, dict[str, float | int]] = {
            "beta": {
                "minimumWindowHours": 168.0,
                "crashFreeSessionsPercent": 99.5,
                "authSuccessPercent": 99.0,
                "bootstrapSuccessPercent": 99.0,
                "manualMutationSuccessPercent": 99.0,
                "mapP95Seconds": 2.5,
                "bootstrapP95Seconds": 3.0,
                "p0Count": 0,
                "unresolvedP1Count": 0,
                "authBypassCount": 0,
                "rawGPSPersistenceCount": 0,
            },
            "production": {
                "minimumWindowHours": 24.0,
                "crashFreeSessionsPercent": 99.7,
                "crashFreeUsersPercent": 99.5,
                "mutationSuccessPercent": 99.5,
                "server5xxPercent": 0.5,
                "manualOnlineAckP95Seconds": 2.0,
                "revokeEventP95Seconds": 5.0,
                "failClosedLeaseSeconds": 30.0,
                "p0Count": 0,
                "unresolvedP1Count": 0,
                "directDMLExposureCount": 0,
                "privacyExposureCount": 0,
                "authBypassCount": 0,
                "revocationExposureCount": 0,
                "rawGPSPersistenceCount": 0,
            },
        }
        threshold = {
            "schemaVersion": 1,
            "artifactType": "threshold-ratification",
            "id": "OPS-005",
            "tag": TAG,
            "commit": COMMIT,
            "approvalSHA256": SHA,
            "createdAt": "2026-07-14T00:00:00Z",
            "thresholds": thresholds,
        }
        now = datetime.now(timezone.utc).replace(microsecond=0)
        is_beta = identifier == "REL-005"
        hours = duration_hours if duration_hours is not None else (168.0 if is_beta else 24.0)
        started = now - timedelta(hours=hours)
        minimums = (
            {
                "crashFreeSessionsPercent": 99.5,
                "authSuccessPercent": 99.0,
                "bootstrapSuccessPercent": 99.0,
                "manualMutationSuccessPercent": 99.0,
            }
            if is_beta
            else {
                "crashFreeSessionsPercent": 99.7,
                "crashFreeUsersPercent": 99.5,
                "mutationSuccessPercent": 99.5,
            }
        )
        maximums = (
            {"mapP95Seconds": 2.5, "bootstrapP95Seconds": 3.0}
            if is_beta
            else {
                "server5xxPercent": 0.4,
                "manualOnlineAckP95Seconds": 2.0,
                "revokeEventP95Seconds": 5.0,
                "failClosedLeaseSeconds": 30.0,
            }
        )
        zeroes = (
            {"authBypassCount": 0, "rawGPSPersistenceCount": 0}
            if is_beta
            else {
                "directDMLExposureCount": 0,
                "privacyExposureCount": 0,
                "authBypassCount": 0,
                "revocationExposureCount": 0,
                "rawGPSPersistenceCount": 0,
            }
        )
        metrics = {**minimums, **maximums}
        source = {
            "schemaVersion": 1,
            "artifactType": "runtime-floor-source",
            "id": identifier,
            "tag": TAG,
            "commit": COMMIT,
            "collectedAt": timestamp(now),
            "source": {
                "providers": ["telemetry"],
                "querySHA256": SHA,
                "queryStartedAt": timestamp(started),
                "queryEndedAt": timestamp(now),
            },
            "window": {
                "startedAt": timestamp(started),
                "endedAt": timestamp(now),
                "durationHours": hours,
            },
            "denominators": {field: 100 for field in metrics},
            "exclusions": {
                "userCancelled": 0,
                "intentionalOfflinePending": 0,
                "genericBlockDenial": 0,
                "intendedFailClosedUnavailable": 0,
            },
            "findings": {"p0Count": 0, "unresolvedP1Count": 0},
            "metrics": metrics,
            "zeroTolerance": zeroes,
        }
        write_document(root, "Evidence/runtime/threshold-ratification.json", threshold)
        write_document(root, "Evidence/runtime/source.json", source)
        return temporary, root, threshold, source

    def run_floor(self, root: Path, identifier: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(RUNTIME_FLOORS),
                "--id",
                identifier,
                "--source-manifest",
                "Evidence/runtime/source.json",
                "--threshold",
                "Evidence/runtime/threshold-ratification.json",
                "--schema",
                "Docs/evidence/schemas/threshold-ratification.schema.json",
                "--output",
                f"Evidence/runtime/{identifier}.json",
            ],
            cwd=root,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )

    def assert_floor_rejected_without_output(self, root: Path, identifier: str) -> None:
        result = self.run_floor(root, identifier)
        self.assertNotEqual(result.returncode, 0)
        output = root / "Evidence" / "runtime" / f"{identifier}.json"
        self.assertFalse(output.exists())
        self.assertFalse(Path(f"{output}.sha256").exists())

    def test_strict_json_rejects_duplicate_unknown_and_nonfinite_without_output(self) -> None:
        malformed = {
            "duplicate": b'{"schemaVersion":1,"schemaVersion":1}\n',
            "unknown": canonical_bytes({"unexpected": True}) + b"\n",
            "nonfinite": b'{"schemaVersion":NaN}\n',
        }
        for name, raw in malformed.items():
            with self.subTest(name=name):
                temporary, root, _threshold, _source = self.make_fixture()
                with temporary:
                    write_raw(root, "Evidence/runtime/threshold-ratification.json", raw)
                    self.assert_floor_rejected_without_output(root, "REL-005")

    def test_threshold_cannot_weaken_without_output(self) -> None:
        mutations = (
            ("beta-minimum", "beta", "minimumWindowHours", 167.99),
            ("production-maximum", "production", "server5xxPercent", 0.6),
        )
        for name, period, field, value in mutations:
            with self.subTest(name=name):
                temporary, root, threshold, _source = self.make_fixture()
                with temporary:
                    threshold["thresholds"][period][field] = value  # type: ignore[index]
                    write_document(root, "Evidence/runtime/threshold-ratification.json", threshold)
                    self.assert_floor_rejected_without_output(root, "REL-005")

    def test_beta_under_seven_days_and_phase_under_one_day_fail_without_output(self) -> None:
        for identifier, hours in (("REL-005", 167.99), ("REL-011-05", 23.99)):
            with self.subTest(identifier=identifier):
                temporary, root, _threshold, _source = self.make_fixture(identifier, duration_hours=hours)
                with temporary:
                    self.assert_floor_rejected_without_output(root, identifier)

    def test_lineage_rejects_runtime_floor_duration_mismatch(self) -> None:
        record = {
            "schemaVersion": 1,
            "artifactType": "runtime-floor-validation",
            "id": "REL-005",
            "status": "passed",
            "tag": TAG,
            "commit": COMMIT,
            "sourceManifestSHA256": "1" * 64,
            "thresholdSHA256": "2" * 64,
            "schemaSHA256": "3" * 64,
            "windowStartedAt": "2026-07-01T00:00:00Z",
            "windowEndedAt": "2026-07-08T00:00:00Z",
            "windowHours": 168.0,
            "validatedAt": "2026-07-08T00:00:01Z",
        }

        LINEAGE.verify_runtime_floor_validation(record, "beta floor", "REL-005")
        record["windowHours"] = 169.0
        with self.assertRaises(LINEAGE.ReleaseError):
            LINEAGE.verify_runtime_floor_validation(record, "beta floor", "REL-005")
    def test_runtime_floor_p0_p1_and_zero_tolerance_fail_without_output(self) -> None:
        mutations = {
            "below-floor": lambda source: source["metrics"].__setitem__("authSuccessPercent", 98.99),
            "p0": lambda source: source["findings"].__setitem__("p0Count", 1),
            "p1": lambda source: source["findings"].__setitem__("unresolvedP1Count", 1),
            "zero-tolerance": lambda source: source["zeroTolerance"].__setitem__("authBypassCount", 1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                temporary, root, _threshold, source = self.make_fixture()
                with temporary:
                    mutate(source)
                    write_document(root, "Evidence/runtime/source.json", source)
                    self.assert_floor_rejected_without_output(root, "REL-005")


class ApprovalAndMigrationControlsTests(unittest.TestCase):
    def approval_record(
        self,
        *,
        tag: str = TAG,
        commit: str = COMMIT,
        gate: str = "threshold",
        created_at: str = "2026-07-14T00:00:00Z",
        manifest_sha: str | None = None,
        metric_sha: str | None = None,
    ) -> dict[str, object]:
        roles = LINEAGE.ROLES
        team_snapshots = [
            {"role": role, "teamSlug": role.lower(), "responseSHA256": sha256(f"team:{role}".encode("ascii"))}
            for role in roles
        ]
        approvals = []
        for index, role in enumerate(roles, start=1):
            approvals.append(
                {
                    "role": role,
                    "status": "active",
                    "commentId": index,
                    "login": f"{role.lower()}-reviewer",
                    "createdAt": created_at,
                    "approvedAt": created_at,
                    "approvalDigest": sha256(f"approval:{role}".encode("ascii")),
                    "commentSHA256": sha256(f"comment:{role}".encode("ascii")),
                    "membershipAttestations": [
                        {
                            "role": candidate,
                            "teamSlug": candidate.lower(),
                            "state": "active" if candidate == role else "inactive",
                            "responseSHA256": sha256(f"membership:{role}:{candidate}".encode("ascii")),
                        }
                        for candidate in roles
                    ],
                }
            )
        return {
            "schemaVersion": 1,
            "artifactType": "release-role-approvals",
            "gate": gate,
            "issueURL": "https://github.com/example/hiker/issues/1",
            "releaseTag": tag,
            "commitSHA": commit,
            "buildDigest": sha256(b"build"),
            "observedInputSHA256": manifest_sha or sha256(b"manifest"),
            "transition": "threshold-ratification" if gate == "threshold" else gate,
            "predecessorEventSHA256": metric_sha or sha256(b"metric"),
            "githubRunId": "1",
            "createdAt": created_at,
            "issueSnapshotSHA256": sha256(b"issue"),
            "teamSnapshotSHA256": sha256(b"teams"),
            "teamSnapshots": team_snapshots,
            "approvals": approvals,
        }

    def test_approval_control_fixture_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = self.approval_record()
            write_document(root, "approval.json", record)
            digest = LINEAGE.verify_approval(
                root,
                "approval.json",
                "threshold",
                COMMIT,
                tag=TAG,
                transition="threshold-ratification",
                manifest_sha=record["observedInputSHA256"],
                metric_sha=record["predecessorEventSHA256"],
                build_digest=record["buildDigest"],
            )
            self.assertEqual(digest, sha256(canonical_bytes(record) + b"\n"))
    def test_approval_identity_binding_and_freshness_negatives_leave_no_writes(self) -> None:
        cases: list[tuple[str, dict[str, object], bool, str | None, str | None]] = []
        duplicate_role = self.approval_record()
        duplicate_role["approvals"][1]["role"] = "Product"  # type: ignore[index]
        cases.append(("duplicate-role", duplicate_role, False, None, None))
        duplicate_login = self.approval_record()
        duplicate_login["approvals"][1]["login"] = "product-reviewer"  # type: ignore[index]
        cases.append(("duplicate-login", duplicate_login, False, None, None))
        duplicate_comment_id = self.approval_record()
        duplicate_comment_id["approvals"][1]["commentId"] = 1  # type: ignore[index]
        cases.append(("duplicate-comment-id", duplicate_comment_id, False, None, None))
        duplicate_comment_digest = self.approval_record()
        duplicate_comment_digest["approvals"][1]["commentSHA256"] = duplicate_comment_digest["approvals"][0]["commentSHA256"]  # type: ignore[index]
        cases.append(("duplicate-comment-digest", duplicate_comment_digest, False, None, None))
        stale = self.approval_record(created_at="2020-01-01T00:00:00Z")
        cases.append(("stale", stale, True, None, None))
        cross_tag = self.approval_record(tag="v9.9.9")
        cases.append(("cross-tag", cross_tag, False, None, None))
        cross_commit = self.approval_record(commit="c" * 40)
        cases.append(("cross-commit", cross_commit, False, None, None))
        wrong_gate = self.approval_record(gate="m6-exit")
        cases.append(("wrong-gate", wrong_gate, False, None, None))
        cross_manifest = self.approval_record(manifest_sha="d" * 64)
        cases.append(("cross-manifest", cross_manifest, False, "e" * 64, None))
        cross_build_metric = self.approval_record(metric_sha="f" * 64)
        cases.append(("cross-build-metric", cross_build_metric, False, None, "0" * 64))

        for name, record, fresh, manifest_sha, metric_sha in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_document(root, "approval.json", record)
                before = tree_snapshot(root)
                with self.assertRaises(LINEAGE.ReleaseError):
                    LINEAGE.verify_approval(
                        root,
                        "approval.json",
                        "threshold",
                        COMMIT,
                        tag=TAG,
                        manifest_sha=manifest_sha,
                        metric_sha=metric_sha,
                        fresh=fresh,
                    )
                self.assertEqual(tree_snapshot(root), before)

    def controller_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, str], dict[str, str]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        initialize_repository(root)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "release-tests@example.invalid"], check=True, stdin=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Release Tests"], check=True, stdin=subprocess.DEVNULL)
        (root / "seed").write_text("release controls\n", encoding="ascii")
        subprocess.run(["git", "-C", str(root), "add", "seed"], check=True, stdin=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(root), "commit", "--quiet", "-m", "seed"], check=True, stdin=subprocess.DEVNULL)
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(["git", "-C", str(root), "tag", TAG, commit], check=True, stdin=subprocess.DEVNULL)

        values = {
            "release_id": "REL-002",
            "state": "predeploy-disabled",
            "gate": "predeploy",
            "tag": TAG,
            "commit": commit,
            "switch_state": "disabled",
            "expected_sequence": "0",
            "approval_path": "Evidence/runtime/approvals/predeploy.json",
            "observed_input_manifest": "Evidence/manifests/observed.json",
            "output": "Evidence/runtime/REL-002.json",
            "data_sha": "d" * 64,
            "migration_sha": "e" * 64,
            "actor": "release-bot",
            "build_digest": "a" * 64,
        }
        sentinel_payload = (
            '{"commit":' + json.dumps(values["commit"], separators=(",", ":"))
            + ',"datasetSHA":' + json.dumps(values["data_sha"], separators=(",", ":"))
            + ',"migrationSHA":' + json.dumps(values["migration_sha"], separators=(",", ":"))
            + ',"releaseID":' + json.dumps(values["release_id"], separators=(",", ":"))
            + ',"schemaVersion":"m6-release-transition-v1","tag":'
            + json.dumps(values["tag"], separators=(",", ":"))
            + "}"
        )
        values["expected_event_sha"] = sha256(sentinel_payload.encode("utf-8"))
        values["observed_input_sha"] = write_document(
            root,
            values["observed_input_manifest"],
            self.controller_observed(values),
        )
        approval = self.controller_approval(values, values["observed_input_sha"])
        values["approval_sha"] = write_document(root, values["approval_path"], approval)
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW": "Release Evidence",
            "RELEASE_PROTECTED_ENVIRONMENT": "production",
            "RELEASE_PROTECTED_INPUTS_CONFIRMED": "approved",
            "GITHUB_REF_TYPE": "tag",
            "GITHUB_REF_NAME": values["tag"],
            "GITHUB_SHA": values["commit"],
            "GITHUB_ACTOR": values["actor"],
            "GITHUB_REPOSITORY": "example/hiker",
            "GITHUB_RUN_ID": "100",
            "GITHUB_JOB": "migration-predeploy",
            "HIKER_RELEASE_BUILD_DIGEST": values["build_digest"],
            "HIKER_RELEASE_INPUT_SHA256": "9" * 64,
        }
        return temporary, root, values, environment

    def controller_observed(self, values: dict[str, str]) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "artifactType": "release-transition-observed-input",
            "releaseID": values["release_id"],
            "state": values["state"],
            "tag": values["tag"],
            "commit": values["commit"],
            "buildDigest": values["build_digest"],
            "dataSHA256": values["data_sha"],
            "migrationSHA256": values["migration_sha"],
            "expectedSequence": int(values["expected_sequence"]),
            "expectedEventSHA256": values["expected_event_sha"],
            "observedAt": "2026-07-14T00:00:00Z",
            "evidence": [{"id": "MIG-001", "sha256": "f" * 64}],
            "repository": "example/hiker",
            "inputSHA256": "9" * 64,
            "workflowRunId": "100",
            "job": "migration-predeploy",
            "sourceDocumentSHA256": "3" * 64,
            "sourceSignatureSHA256": "4" * 64,
            "sourcePublicKeySHA256": "5" * 64,
            "sourceInputSHA256": "9" * 64,
            "sourceObservedAt": "2026-07-14T00:00:00Z",
            "sourceObservation": {"status": "passed"},
        }

    def controller_approval(self, values: dict[str, str], observed_sha: str) -> dict[str, object]:
        roles = ("Product", "Security", "Ops")
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        team_snapshots = [
            {"role": role, "teamSlug": role.lower(), "responseSHA256": "1" * 64}
            for role in roles
        ]
        approvals = []
        for index, role in enumerate(roles, start=1):
            memberships = [
                {
                    "role": candidate,
                    "teamSlug": candidate.lower(),
                    "state": "active" if candidate == role else "inactive",
                    "responseSHA256": "2" * 64,
                }
                for candidate in roles
            ]
            approvals.append(
                {
                    "role": role,
                    "status": "active",
                    "commentId": index,
                    "login": f"{role.lower()}-bot",
                    "createdAt": timestamp,
                    "approvedAt": timestamp,
                    "approvalDigest": sha256(f"approval:{role}".encode("ascii")),
                    "commentSHA256": sha256(f"comment:{role}".encode("ascii")),
                    "membershipAttestations": memberships,
                }
            )
        return {
            "schemaVersion": 1,
            "artifactType": "release-role-approvals",
            "gate": values["gate"],
            "issueURL": "https://github.com/example/hiker/issues/1",
            "releaseTag": values["tag"],
            "commitSHA": values["commit"],
            "buildDigest": values["build_digest"],
            "observedInputSHA256": observed_sha,
            "transition": values["state"],
            "predecessorEventSHA256": values["expected_event_sha"],
            "githubRunId": "100",
            "createdAt": timestamp,
            "issueSnapshotSHA256": "6" * 64,
            "teamSnapshotSHA256": "7" * 64,
            "teamSnapshots": team_snapshots,
            "approvals": approvals,
        }

    def controller_arguments(self, values: dict[str, str], **overrides: str) -> list[str]:
        arguments = {
            "--release-id": values["release_id"],
            "--state": values["state"],
            "--tag": values["tag"],
            "--commit": values["commit"],
            "--switch-state": values["switch_state"],
            "--expected-sequence": values["expected_sequence"],
            "--expected-event-sha": values["expected_event_sha"],
            "--approval": values["approval_path"],
            "--approval-sha": values["approval_sha"],
            "--observed-input-manifest": values["observed_input_manifest"],
            "--observed-input-sha": values["observed_input_sha"],
            "--data-sha": values["data_sha"],
            "--migration-sha": values["migration_sha"],
            "--actor": values["actor"],
            "--output": values["output"],
        }
        arguments.update(overrides)
        return [item for pair in arguments.items() for item in pair]

    def run_controller(
        self,
        root: Path,
        arguments: list[str],
        environment: dict[str, str],
        controller: Path = MIGRATION_CONTROLLER,
    ) -> subprocess.CompletedProcess[bytes]:
        env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", str(root))}
        env.update(environment)
        return subprocess.run(
            ["bash", str(controller), *arguments],
            cwd=root,
            env=env,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )

    def assert_controller_rejected_without_write(
        self,
        root: Path,
        arguments: list[str],
        environment: dict[str, str],
        *,
        controller: Path = MIGRATION_CONTROLLER,
    ) -> None:
        before = tree_snapshot(root / "Evidence")
        result = self.run_controller(root, arguments, environment, controller)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(tree_snapshot(root / "Evidence"), before)


    def test_migration_controller_rejects_local_unprotected_unsafe_path_and_traversal_without_write(self) -> None:
        temporary, root, values, environment = self.controller_fixture()
        with temporary:
            arguments = self.controller_arguments(values)
            self.assert_controller_rejected_without_write(root, arguments, {})
            self.assert_controller_rejected_without_write(
                root,
                arguments,
                {**environment, "MIGRATION_APPROVED_RPC_COMMAND": "/tmp/not-an-approved-release-rpc"},
            )
            self.assert_controller_rejected_without_write(
                root,
                self.controller_arguments(values, **{"--observed-input-manifest": "/tmp/observed.json"}),
                environment,
            )
            self.assert_controller_rejected_without_write(
                root,
                self.controller_arguments(values, **{"--observed-input-manifest": "Evidence/manifests/../observed.json"}),
                environment,
            )

    def test_migration_controller_rejects_wrong_sentinel_state_and_approval_without_write(self) -> None:
        temporary, root, values, environment = self.controller_fixture()
        with temporary:
            self.assert_controller_rejected_without_write(
                root,
                self.controller_arguments(values, **{"--expected-event-sha": "9" * 64}),
                environment,
            )
            self.assert_controller_rejected_without_write(
                root,
                self.controller_arguments(values, **{"--switch-state": "enabled"}),
                environment,
            )
            invalid_approval = self.controller_approval(values, values["observed_input_sha"])
            invalid_approval["approvals"][1]["role"] = "Product"  # type: ignore[index]
            values["approval_sha"] = write_document(root, values["approval_path"], invalid_approval)
            self.assert_controller_rejected_without_write(root, self.controller_arguments(values), environment)

    def test_migration_controller_rejects_nonmember_approval_without_write(self) -> None:
        temporary, root, values, environment = self.controller_fixture()
        with temporary:
            invalid_approval = self.controller_approval(values, values["observed_input_sha"])
            invalid_approval["approvals"][0]["membershipAttestations"][1]["state"] = "active"  # type: ignore[index]
            values["approval_sha"] = write_document(root, values["approval_path"], invalid_approval)
            self.assert_controller_rejected_without_write(root, self.controller_arguments(values), environment)

    def controller_with_rpc(self, root: Path, rpc: Path) -> Path:
        controller = root / "migration-controller-under-test.sh"
        source = MIGRATION_CONTROLLER.read_text(encoding="ascii")
        allowed_rpc = "/usr/local/bin/hiker-release-rpc"
        self.assertIn(allowed_rpc, source)
        source = source.replace(allowed_rpc, rpc.as_posix())
        source = source.replace("metadata.st_uid != 0", f"metadata.st_uid != {os.getuid()}")
        source = source.replace(
            '    except ControllerError:\n        print("migration controller error: protected release transition was not invoked", file=sys.stderr)\n        return 1',
            "    except ControllerError:\n        raise",
        )
        controller.write_text(source, encoding="ascii")
        controller.chmod(0o700)
        return controller

    def invocation_trap_controller(self, root: Path) -> tuple[Path, Path, Path]:
        marker = root / "rpc-invoked"
        rpc = root / "invocation-trap-rpc"
        rpc.write_text("#!/bin/sh\n: > \"$HIKER_RPC_MARKER\"\nexit 1\n", encoding="ascii")
        rpc.chmod(0o700)
        return self.controller_with_rpc(root, rpc), rpc, marker

    def test_migration_controller_rejects_duplicate_approval_identity_and_digests_without_write(self) -> None:
        mutations = (
            ("duplicate-login", "login", "PRODUCT-BOT"),
            ("duplicate-comment-id", "commentId", 1),
            ("duplicate-comment-digest", "commentSHA256", sha256(b"comment:Product")),
            ("reused-approval-digest", "approvalDigest", sha256(b"approval:Product")),
        )
        for name, field, value in mutations:
            with self.subTest(name=name):
                temporary, root, values, environment = self.controller_fixture()
                with temporary:
                    controller, rpc, marker = self.invocation_trap_controller(root)
                    invalid_approval = self.controller_approval(values, values["observed_input_sha"])
                    invalid_approval["approvals"][1][field] = value  # type: ignore[index]
                    values["approval_sha"] = write_document(root, values["approval_path"], invalid_approval)
                    self.assert_controller_rejected_without_write(
                        root,
                        self.controller_arguments(values),
                        {
                            **environment,
                            "HIKER_RPC_MARKER": str(marker),
                        },
                        controller=controller,
                    )
                    self.assertFalse(marker.exists())

    def test_migration_controller_rejects_wrong_approval_bindings_without_write(self) -> None:
        mutations = (
            ("wrong-gate", "gate", "compatibility"),
            ("wrong-transition", "transition", "compatibility"),
            ("wrong-manifest", "observedInputSHA256", "8" * 64),
            ("cross-commit", "commitSHA", "c" * 40),
            ("cross-tag", "releaseTag", "v9.9.9"),
            ("cross-build", "buildDigest", "7" * 64),
            ("wrong-predecessor", "predecessorEventSHA256", "6" * 64),
        )
        for name, field, value in mutations:
            with self.subTest(name=name):
                temporary, root, values, environment = self.controller_fixture()
                with temporary:
                    controller, rpc, marker = self.invocation_trap_controller(root)
                    invalid_approval = self.controller_approval(values, values["observed_input_sha"])
                    invalid_approval[field] = value
                    values["approval_sha"] = write_document(root, values["approval_path"], invalid_approval)
                    self.assert_controller_rejected_without_write(
                        root,
                        self.controller_arguments(values),
                        {
                            **environment,
                            "HIKER_RPC_MARKER": str(marker),
                        },
                        controller=controller,
                    )
                    self.assertFalse(marker.exists())

    def test_migration_controller_rejects_wrong_run_stale_future_and_incoherent_approvals(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        stale = (now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future = (now + timedelta(minutes=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        mutations = (
            ("cross-run", lambda approval: approval.__setitem__("githubRunId", "99")),
            ("stale-document", lambda approval: approval.__setitem__("createdAt", stale)),
            (
                "future-role-approval",
                lambda approval: approval["approvals"][0].__setitem__("approvedAt", future),
            ),
            (
                "approval-before-comment",
                lambda approval: approval["approvals"][0].__setitem__(
                    "createdAt",
                    (now + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                temporary, root, values, environment = self.controller_fixture()
                with temporary:
                    controller, _rpc, marker = self.invocation_trap_controller(root)
                    invalid_approval = self.controller_approval(values, values["observed_input_sha"])
                    mutate(invalid_approval)
                    values["approval_sha"] = write_document(
                        root,
                        values["approval_path"],
                        invalid_approval,
                    )
                    self.assert_controller_rejected_without_write(
                        root,
                        self.controller_arguments(values),
                        {**environment, "HIKER_RPC_MARKER": str(marker)},
                        controller=controller,
                    )
                    self.assertFalse(marker.exists())
    def test_migration_controller_rejects_reused_predeploy_approval_without_write(self) -> None:
        temporary, root, values, environment = self.controller_fixture()
        with temporary:
            controller, rpc, marker = self.invocation_trap_controller(root)
            compatibility = {
                **values,
                "state": "compatibility",
                "gate": "compatibility",
                "expected_sequence": "1",
                "expected_event_sha": "1" * 64,
                "approval_path": "Evidence/runtime/approvals/compatibility.json",
                "observed_input_manifest": "Evidence/manifests/compatibility.json",
                "output": "Evidence/runtime/REL-003.json",
            }
            compatibility["observed_input_sha"] = write_document(
                root,
                compatibility["observed_input_manifest"],
                self.controller_observed(compatibility),
            )
            copied_predeploy_approval = self.controller_approval(values, values["observed_input_sha"])
            compatibility["approval_sha"] = write_document(
                root,
                compatibility["approval_path"],
                copied_predeploy_approval,
            )
            self.assert_controller_rejected_without_write(
                root,
                self.controller_arguments(compatibility),
                {
                    **environment,
                    "HIKER_RPC_MARKER": str(marker),
                },
                controller=controller,
            )
            self.assertFalse(marker.exists())

    def stateful_controller(self, root: Path) -> tuple[Path, Path, Path, Path]:
        marker = root / "rpc-invoked"
        state = root / "rpc-state.json"
        rpc = root / "stateful-rpc"
        rpc.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
if len(arguments) != 28 or len(arguments) % 2:
    sys.exit(2)
values = dict(zip(arguments[::2], arguments[1::2]))
state_path = Path(os.environ["HIKER_RPC_STATE"])
marker_path = Path(os.environ["HIKER_RPC_MARKER"])
operation = values["--operation"]
operation_key = values["--operation-key"]
expected_sequence = int(values["--expected-sequence"])
expected_event = values["--expected-event-sha"]

if operation == "read-back":
    if not state_path.exists():
        sys.exit(3)
    prior = json.loads(state_path.read_text(encoding="ascii"))
    if prior["operationKey"] != operation_key:
        sys.exit(3)
    if os.environ.get("HIKER_RPC_FAIL_READBACK_ONCE") == "true" and not prior["readBackFailed"]:
        prior["readBackFailed"] = True
        state_path.write_text(
            json.dumps(prior, sort_keys=True, separators=(",", ":")) + "\\n",
            encoding="ascii",
        )
        sys.exit(2)
    print(json.dumps(prior["receipt"], sort_keys=True, separators=(",", ":")))
    sys.exit(0)

if operation != "append":
    sys.exit(2)
if state_path.exists():
    sys.exit(1)
if values["--state"] != "predeploy-disabled" or expected_sequence != 0:
    sys.exit(1)

event_sha = f"{expected_sequence + 1:x}" * 64
receipt = {
    "schemaVersion": 1,
    "artifactType": "release-transition-rpc-receipt",
    "operationKey": operation_key,
    "releaseID": values["--release-id"],
    "state": values["--state"],
    "tag": values["--tag"],
    "commit": values["--commit"],
    "sequence": expected_sequence + 1,
    "previousEventSHA256": expected_event,
    "eventSHA256": event_sha,
    "auditEventId": f"fake-transition-{expected_sequence + 1}",
    "createdAt": "2026-07-14T00:00:00Z",
}
state_path.write_text(
    json.dumps(
        {"operationKey": operation_key, "readBackFailed": False, "receipt": receipt},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\\n",
    encoding="ascii",
)
with marker_path.open("a", encoding="ascii") as marker:
    marker.write("append\\n")
response = os.environ.get("HIKER_RPC_APPEND_RESPONSE", "valid")
if response == "lost":
    sys.exit(0)
if response == "malformed":
    print("{}")
    sys.exit(0)
if response != "valid":
    sys.exit(2)
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
""",
            encoding="ascii",
        )
        rpc.chmod(0o700)
        return self.controller_with_rpc(root, rpc), rpc, state, marker

    def test_stateful_controller_rejects_replay_and_conflicting_predecessor_without_write(self) -> None:
        temporary, root, values, environment = self.controller_fixture()
        with temporary:
            controller, rpc, state, marker = self.stateful_controller(root)
            protected_environment = {
                **environment,
                "HIKER_RPC_STATE": str(state),
                "HIKER_RPC_MARKER": str(marker),
            }
            result = self.run_controller(root, self.controller_arguments(values), protected_environment, controller)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            state_before = state.read_bytes()
            self.assert_controller_rejected_without_write(
                root,
                self.controller_arguments(values),
                protected_environment,
                controller=controller,
            )
            self.assertEqual(state.read_bytes(), state_before)
            self.assertEqual(marker.read_text(encoding="ascii"), "append\n")

            compatibility = {
                **values,
                "state": "compatibility",
                "gate": "compatibility",
                "expected_sequence": "1",
                "expected_event_sha": "f" * 64,
                "approval_path": "Evidence/runtime/approvals/compatibility.json",
                "observed_input_manifest": "Evidence/manifests/compatibility.json",
                "output": "Evidence/runtime/REL-003.json",
            }
            compatibility["observed_input_sha"] = write_document(
                root,
                compatibility["observed_input_manifest"],
                self.controller_observed(compatibility),
            )
            compatibility["approval_sha"] = write_document(
                root,
                compatibility["approval_path"],
                self.controller_approval(compatibility, compatibility["observed_input_sha"]),
            )
            self.assert_controller_rejected_without_write(
                root,
                self.controller_arguments(compatibility),
                protected_environment,
                controller=controller,
            )
            self.assertEqual(state.read_bytes(), state_before)
            self.assertEqual(marker.read_text(encoding="ascii"), "append\n")

    def test_migration_controller_preflights_output_and_sidecar_collisions_without_rpc(self) -> None:
        for collision in ("output", "sidecar"):
            with self.subTest(collision=collision):
                temporary, root, values, environment = self.controller_fixture()
                with temporary:
                    controller, _rpc, marker = self.invocation_trap_controller(root)
                    output = root.joinpath(*Path(values["output"]).parts)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    collision_path = output if collision == "output" else Path(f"{output}.sha256")
                    collision_path.write_bytes(b"pre-existing\n")
                    before = tree_snapshot(root / "Evidence")

                    result = self.run_controller(root, self.controller_arguments(values), environment, controller)

                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())
                    self.assertEqual(tree_snapshot(root / "Evidence"), before)

    def test_migration_controller_recovers_lost_or_malformed_append_response(self) -> None:
        for response in ("lost", "malformed"):
            with self.subTest(response=response):
                temporary, root, values, environment = self.controller_fixture()
                with temporary:
                    controller, _rpc, state, marker = self.stateful_controller(root)
                    protected_environment = {
                        **environment,
                        "HIKER_RPC_STATE": str(state),
                        "HIKER_RPC_MARKER": str(marker),
                        "HIKER_RPC_APPEND_RESPONSE": response,
                    }

                    result = self.run_controller(root, self.controller_arguments(values), protected_environment, controller)

                    self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
                    remote = json.loads(state.read_text(encoding="ascii"))
                    record = json.loads(root.joinpath(*Path(values["output"]).parts).read_text(encoding="ascii"))
                    self.assertEqual(record["eventSHA256"], remote["receipt"]["eventSHA256"])
                    self.assertEqual(
                        record["rpcReceiptSHA256"],
                        sha256(canonical_bytes(remote["receipt"]) + b"\n"),
                    )
                    self.assertEqual(marker.read_text(encoding="ascii"), "append\n")

    def test_migration_controller_recovers_interrupted_local_pair_without_second_append(self) -> None:
        temporary, root, values, environment = self.controller_fixture()
        with temporary:
            controller, _rpc, state, marker = self.stateful_controller(root)
            protected_environment = {
                **environment,
                "HIKER_RPC_STATE": str(state),
                "HIKER_RPC_MARKER": str(marker),
            }

            first = self.run_controller(root, self.controller_arguments(values), protected_environment, controller)

            self.assertEqual(first.returncode, 0, first.stderr.decode("utf-8", "replace"))
            output = root.joinpath(*Path(values["output"]).parts)
            sidecar = Path(f"{output}.sha256")
            original_output = output.read_bytes()
            sidecar.unlink()

            recovered = self.run_controller(
                root,
                self.controller_arguments(values),
                protected_environment,
                controller,
            )

            self.assertEqual(recovered.returncode, 0, recovered.stderr.decode("utf-8", "replace"))
            self.assertEqual(output.read_bytes(), original_output)
            self.assertEqual(
                sidecar.read_text(encoding="ascii").strip(),
                f"{sha256(original_output)}  {values['output']}",
            )
            self.assertEqual(marker.read_text(encoding="ascii"), "append\n")
    def test_migration_controller_retry_recovers_only_the_exact_committed_operation(self) -> None:
        temporary, root, values, environment = self.controller_fixture()
        with temporary:
            controller, _rpc, state, marker = self.stateful_controller(root)
            protected_environment = {
                **environment,
                "HIKER_RPC_STATE": str(state),
                "HIKER_RPC_MARKER": str(marker),
                "HIKER_RPC_APPEND_RESPONSE": "lost",
                "HIKER_RPC_FAIL_READBACK_ONCE": "true",
            }

            first = self.run_controller(root, self.controller_arguments(values), protected_environment, controller)

            self.assertNotEqual(first.returncode, 0)
            self.assertFalse(root.joinpath(*Path(values["output"]).parts).exists())
            state_before = state.read_bytes()
            self.assertEqual(marker.read_text(encoding="ascii"), "append\n")

            conflicting = {**values, "actor": "recovery-bot"}
            foreign = self.run_controller(
                root,
                self.controller_arguments(conflicting),
                {**protected_environment, "GITHUB_ACTOR": conflicting["actor"]},
                controller,
            )

            self.assertNotEqual(foreign.returncode, 0)
            self.assertEqual(state.read_bytes(), state_before)
            self.assertFalse(root.joinpath(*Path(values["output"]).parts).exists())
            self.assertEqual(marker.read_text(encoding="ascii"), "append\n")

            recovered = self.run_controller(root, self.controller_arguments(values), protected_environment, controller)

            self.assertEqual(recovered.returncode, 0, recovered.stderr.decode("utf-8", "replace"))
            self.assertEqual(state.read_bytes(), state_before)
            remote = json.loads(state.read_text(encoding="ascii"))
            record = json.loads(root.joinpath(*Path(values["output"]).parts).read_text(encoding="ascii"))
            self.assertEqual(record["eventSHA256"], remote["receipt"]["eventSHA256"])
            self.assertEqual(
                record["rpcReceiptSHA256"],
                sha256(canonical_bytes(remote["receipt"]) + b"\n"),
            )
            self.assertEqual(marker.read_text(encoding="ascii"), "append\n")

    def test_switch_drill_never_invokes_migration_rpc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "rpc-invoked"
            fake_rpc = root / "fake-rpc"
            fake_rpc.write_text("#!/bin/sh\n: > \"$HIKER_RPC_MARKER\"\n", encoding="ascii")
            fake_rpc.chmod(0o700)
            release_directory = root / "Scripts" / "release"
            release_directory.mkdir(parents=True)
            temporary_switch_drill = release_directory / SWITCH_DRILL.name
            temporary_lineage = release_directory / LINEAGE_SCRIPT.name
            shutil.copyfile(SWITCH_DRILL, temporary_switch_drill)
            shutil.copyfile(LINEAGE_SCRIPT, temporary_lineage)
            before = tree_snapshot(root / "Evidence")
            result = subprocess.run(
                [
                    "bash",
                    str(temporary_switch_drill),
                    "--previous-event-sha",
                    "8" * 64,
                    "--output",
                    "Evidence/runtime/REL-009.json",
                ],
                cwd=root,
                env={
                    "PATH": os.environ["PATH"],
                    "HOME": os.environ.get("HOME", str(root)),
                    "HIKER_RPC_MARKER": str(marker),
                    "MIGRATION_APPROVED_RPC_COMMAND": str(fake_rpc),
                },
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertEqual(tree_snapshot(root / "Evidence"), before)


if __name__ == "__main__":
    unittest.main()
