#!/usr/bin/env python3
"""Local fail-closed checks for protected runtime evidence dispatch."""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import os
import subprocess
import sys
import re
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DISPATCHER = REPOSITORY_ROOT / "Scripts" / "ci" / "run-runtime-evidence.py"
SPEC = importlib.util.spec_from_file_location("runtime_dispatcher_under_test", RUNTIME_DISPATCHER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not import runtime dispatcher from {RUNTIME_DISPATCHER}")
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME
SPEC.loader.exec_module(RUNTIME)
EXPECTED_G008_PROTECTED_ID_CHECK_KINDS = frozenset(
    {
        ("AUTH-005-PREFLIGHT-SERVER", "protected-auth-preflight-server"),
        ("AUTH-005-PREFLIGHT-ARCHIVE", "protected-auth-preflight-archive"),
        ("AUTH-005-PREFLIGHT", "protected-auth-preflight-aggregate"),
        ("MIG-005-PROTECTED", "protected-pitr-restore"),
        ("AUTH-005-RC-SERVER", "protected-rc-auth-server"),
        ("AUTH-005-RC-ARCHIVE", "protected-rc-auth-archive"),
        ("AUTH-005-RC", "protected-rc-auth-aggregate"),
        ("OPS-003", "protected-alert-drill"),
        ("OPS-004", "protected-evidence-disposition"),
        ("OPS-005", "protected-threshold-ratification"),
        ("REL-004", "protected-alpha-observation"),
        ("REL-006", "protected-metadata-observation"),
        ("REL-012", "protected-tabletop-observation"),
        ("REL-013", "protected-incident-observation"),
        ("REL-014", "protected-postrelease-observation"),
    }
)
FORGED_ED25519_PRIVATE_KEY_DER_BASE64 = "MC4CAQAwBQYDK2VwBCIEIMxoHfc8+PtY4Zly/sGY/WtpFQ18uc1EA9FFtQSgr/rX"


def evidence_snapshot(root: Path = REPOSITORY_ROOT) -> dict[str, bytes]:
    evidence = root / "Evidence"
    if not evidence.exists():
        return {}
    return {
        path.relative_to(evidence).as_posix(): path.read_bytes()
        for path in evidence.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


class ProtectedRuntimeNoWriteTests(unittest.TestCase):
    def profile_contract(self, evidence_id: str, check_kind: str) -> dict[str, str]:
        contract = RUNTIME.PROFILE_CONTRACTS.get(evidence_id)
        if contract is None:
            self.fail(f"missing protected profile contract: {evidence_id}")
        self.assertEqual(contract["checkKind"], check_kind)
        return contract

    def run_dispatcher(
        self,
        root: Path,
        evidence_id: str,
        check_kind: str,
        output: str,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        env = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", str(root)),
        }
        env.update(environment)
        return subprocess.run(
            [
                sys.executable,
                str(RUNTIME_DISPATCHER),
                "--id",
                evidence_id,
                "--check-kind",
                check_kind,
                "--output",
                output,
            ],
            cwd=root,
            env=env,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )

    def assert_rejected_without_evidence_write(
        self,
        root: Path,
        evidence_id: str,
        check_kind: str,
        output: str,
        environment: dict[str, str],
    ) -> None:
        before = evidence_snapshot(root)
        repository_before = evidence_snapshot()
        result = self.run_dispatcher(root, evidence_id, check_kind, output, environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(evidence_snapshot(root), before)
        self.assertEqual(evidence_snapshot(), repository_before)

    def temporary_repository(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "repository"
        root.mkdir()
        fixture = root / "fixture.txt"
        fixture.write_bytes(b"protected runtime no-write fixture\n")
        subprocess.run(
            ["git", "init", "--quiet", str(root)],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            ["git", "-C", str(root), "add", fixture.name],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )
        environment = {
            **os.environ,
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        }
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Protected Runtime Test",
                "-c",
                "user.email=protected-runtime-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            env=environment,
        )
        return temporary, root

    def forged_signed_source(self, root: Path, document: dict[str, object]) -> tuple[Path, Path, str]:
        source = root / "observation.json"
        signature = root / "observation.sig"
        private_key = root / "forged-private-key.der"
        source.write_bytes(RUNTIME.canonical_bytes(document) + b"\n")
        private_key.write_bytes(base64.b64decode(FORGED_ED25519_PRIVATE_KEY_DER_BASE64, validate=True))
        source.chmod(0o600)
        private_key.chmod(0o600)
        public_key = subprocess.run(
            ["openssl", "pkey", "-inform", "DER", "-in", str(private_key), "-pubout"],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        ).stdout
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-keyform",
                "DER",
                "-inkey",
                str(private_key),
                "-in",
                str(source),
                "-out",
                str(signature),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )
        signature.chmod(0o600)
        return source, signature, base64.b64encode(public_key).decode("ascii")
    def protected_source_receipt(
        self,
        context: object,
        document: bytes,
        signature: bytes,
        *,
        consumer_run_id: str,
        producer_run_id: str,
    ) -> dict[str, object]:
        source_contract = RUNTIME.RELEASE_PROTECTED_SOURCE_CONTRACTS[context.job]
        return {
            "schemaVersion": 1,
            "artifactType": "protected-release-source-receipt",
            "targetGate": context.job,
            "repository": context.repository,
            "tag": context.tag,
            "commit": context.commit,
            "consumerRunId": consumer_run_id,
            "producerRunId": producer_run_id,
            "producerJob": "publish-protected-source",
            "producerJobId": 1,
            "artifactLabel": f"{source_contract['artifactBase']}-{context.commit}",
            "artifactDigest": f"sha256:{'a' * 64}",
            "documentFile": source_contract["documentName"],
            "documentSHA256": RUNTIME.sha256(document),
            "signatureFile": source_contract["signatureName"],
            "signatureSHA256": RUNTIME.sha256(signature),
        }

    def test_release_workflow_references_an_executable_fail_closed_tag_verifier(self) -> None:
        verifier = REPOSITORY_ROOT / "Scripts" / "release" / "verify-release-tag.sh"
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "release-evidence.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'Scripts/release/verify-release-tag.sh --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA"',
            workflow,
        )
        self.assertTrue(verifier.is_file())
        self.assertTrue(os.access(verifier, os.X_OK))
        result = subprocess.run(
            [str(verifier)],
            cwd=REPOSITORY_ROOT,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
    def test_live_github_job_requires_exact_tag_qualified_run_path(self) -> None:
        context = RUNTIME.ProtectedContext(
            repository="example/hiker",
            run_id="101",
            release_tag="v1.2.3",
            git_sha="a" * 40,
            build_digest="b" * 64,
            job="internal-alpha",
        )
        workflow_name = "Release Evidence"
        workflow_path = ".github/workflows/release-evidence.yml"
        valid_responses = [
            {
                "event": "workflow_dispatch",
                "head_sha": context.git_sha,
                "head_branch": context.release_tag,
                "name": workflow_name,
                "status": "in_progress",
                "path": f"{workflow_path}@{context.release_tag}",
                "workflow_id": 42,
            },
            {
                "id": 42,
                "name": workflow_name,
                "path": workflow_path,
                "state": "active",
            },
            {"jobs": [{"name": context.job, "status": "in_progress"}]},
        ]

        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False):
            with mock.patch.object(RUNTIME, "github_json", side_effect=valid_responses):
                RUNTIME.require_live_github_job(context, workflow_name, workflow_path)

            wrong_ref = [
                {**valid_responses[0], "path": f"{workflow_path}@v9.9.9"},
                valid_responses[1],
                valid_responses[2],
            ]
            with mock.patch.object(RUNTIME, "github_json", side_effect=wrong_ref):
                with self.assertRaises(RUNTIME.EvidenceError):
                    RUNTIME.require_live_github_job(context, workflow_name, workflow_path)
    def test_release_protected_source_contracts_cover_every_source_route_and_workflow_gate(self) -> None:
        source_routes = {"signed-source", "controller-source", "threshold"}
        expected_contracts = {
            contract["job"]: {
                "evidenceId": evidence_id,
                "artifactBase": RUNTIME.RELEASE_PROTECTED_SOURCE_CONTRACTS[contract["job"]]["artifactBase"],
                "documentName": RUNTIME.RELEASE_PROTECTED_SOURCE_CONTRACTS[contract["job"]]["documentName"],
                "signatureName": RUNTIME.RELEASE_PROTECTED_SOURCE_CONTRACTS[contract["job"]]["signatureName"],
            }
            for evidence_id, contract in RUNTIME.RELEASE_EVIDENCE_CONTRACTS.items()
            if contract["route"] in source_routes
        }
        workflow_floor_contracts = {
            "external-beta": ("external-beta-observation", "observed-beta.json", "observed-beta.sig"),
            "rollout-review-05": ("rollout-review-05-observation", "observed-phase-05.json", "observed-phase-05.sig"),
            "rollout-review-25": ("rollout-review-25-observation", "observed-phase-25.json", "observed-phase-25.sig"),
            "rollout-review-50": ("rollout-review-50-observation", "observed-phase-50.json", "observed-phase-50.sig"),
            "rollout-review-100": ("rollout-review-100-observation", "observed-phase-100.json", "observed-phase-100.sig"),
        }
        self.assertEqual(RUNTIME.RELEASE_PROTECTED_SOURCE_CONTRACTS, expected_contracts)

        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "release-evidence.yml").read_text(encoding="utf-8")
        mapping_start = workflow.index("          expected_sources = {")
        mapping_end = workflow.index("          }\n", mapping_start) + len("          }")
        mapping = ast.literal_eval(textwrap.dedent(workflow[mapping_start:mapping_end].split("=", 1)[1]))
        self.assertEqual(
            mapping,
            {
                **{
                    gate: (
                        contract["artifactBase"],
                        contract["documentName"],
                        contract["signatureName"],
                    )
                    for gate, contract in RUNTIME.RELEASE_PROTECTED_SOURCE_CONTRACTS.items()
                },
                **workflow_floor_contracts,
            },
        )
        publisher = workflow[
            workflow.index("\n  publish-protected-source:\n"):
            workflow.index("\n  release-tag-admission:\n")
        ]
        self.assertIn('if gate == "threshold-ratification"', publisher)
        self.assertIn('else "OBSERVATION_SOURCE_SIGNING_KEY_BASE64"', publisher)
        self.assertNotIn('if target_gate == "threshold-ratification"', publisher)
        for gate in expected_contracts:
            section_start = workflow.index(f"\n  {gate}:\n") + 1
            following_section = re.search(r"(?m)^  [a-z0-9][a-z0-9-]*:\n", workflow[section_start + 1:])
            section_end = section_start + 1 + following_section.start() if following_section is not None else len(workflow)
            section = workflow[section_start:section_end]
            source_step = "- &verify_protected_source" if gate == "internal-alpha" else "- *verify_protected_source"
            self.assertIn(source_step, section)
        for gate in workflow_floor_contracts:
            section_start = workflow.index(f"\n  {gate}:\n") + 1
            following_section = re.search(r"(?m)^  [a-z0-9][a-z0-9-]*:\n", workflow[section_start + 1:])
            section_end = section_start + 1 + following_section.start() if following_section is not None else len(workflow)
            self.assertIn("- *verify_protected_source", workflow[section_start:section_end])

    def test_release_observation_contracts_reject_semantically_incomplete_sources(self) -> None:
        controller_routes = {
            evidence_id
            for evidence_id, contract in RUNTIME.RELEASE_EVIDENCE_CONTRACTS.items()
            if contract["route"] == "controller-source"
        }
        for evidence_id, required_checks in RUNTIME.RELEASE_OBSERVATION_CHECKS.items():
            with self.subTest(evidence_id=evidence_id):
                observations: dict[str, object] = {
                    "status": "passed",
                    "checks": {check: True for check in required_checks},
                }
                if evidence_id == "REL-014":
                    observations["reviews"] = {
                        "sevenDayReviewedAt": "2026-07-21T00:00:00Z",
                        "thirtyDayReviewedAt": "2026-08-13T00:00:00Z",
                    }
                if evidence_id in controller_routes:
                    state, sequence = RUNTIME.CONTROLLER_SOURCE_STATES[evidence_id]
                    observations["manifest"] = {
                        "releaseID": "release-build-20260714",
                        "state": state,
                        "dataSHA256": "a" * 64,
                        "migrationSHA256": "b" * 64,
                        "expectedSequence": sequence,
                        "expectedEventSHA256": "c" * 64,
                        "observedAt": "2026-07-14T00:00:00Z",
                        "evidence": [],
                    }
                self.assertEqual(RUNTIME.validate_release_observations(evidence_id, observations), observations)
                incomplete = dict(observations)
                incomplete["checks"] = {"result": True}
                with self.assertRaises(RUNTIME.EvidenceError):
                    RUNTIME.validate_release_observations(evidence_id, incomplete)
    def test_release_signed_source_rejects_consumer_and_producer_receipt_mismatches(self) -> None:
        temporary, root = self.temporary_repository()
        with temporary:
            commit = RUNTIME.current_git_revision(root)
            observed_at = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
            context = RUNTIME.ReleaseEvidenceContext(
                "example/repository",
                "100",
                "v1.2.3",
                commit,
                "b" * 64,
                "c" * 64,
                "alert-drill",
                "production",
            )
            document = {
                "schemaVersion": 1,
                "artifactType": "release-live-observation",
                "signatureAlgorithm": "ed25519",
                "id": "OPS-003",
                "checkKind": "protected-alert-drill",
                "repository": context.repository,
                "releaseTag": context.tag,
                "commitSHA": context.commit,
                "buildDigest": context.build_digest,
                "inputSHA256": context.input_sha256,
                "workflowRunId": "99",
                "job": context.job,
                "observedAt": observed_at,
                "observations": {"result": "confirmed"},
            }
            fixture_root = Path(temporary.name) / "runner-temp"
            fixture_root.mkdir()
            source, signature, public_key = self.forged_signed_source(fixture_root, document)
            receipt_path = fixture_root / "release-protected-source-receipt.json"
            environment = {
                "RUNNER_TEMP": str(fixture_root),
                "HIKER_RELEASE_OBSERVATION_PATH": str(source),
                "HIKER_RELEASE_OBSERVATION_SIGNATURE_PATH": str(signature),
                "HIKER_RELEASE_OBSERVATION_PUBLIC_KEY_BASE64": public_key,
                RUNTIME.RELEASE_PROTECTED_SOURCE_RECEIPT_ENV: str(receipt_path),
            }
            cases = (
                ("consumer", "101", "99"),
                ("producer", context.run_id, "98"),
            )
            for mismatch, consumer_run_id, producer_run_id in cases:
                with self.subTest(mismatch=mismatch):
                    receipt = self.protected_source_receipt(
                        context,
                        source.read_bytes(),
                        signature.read_bytes(),
                        consumer_run_id=consumer_run_id,
                        producer_run_id=producer_run_id,
                    )
                    receipt_path.write_bytes(RUNTIME.canonical_bytes(receipt) + b"\n")
                    receipt_path.chmod(0o600)
                    before = evidence_snapshot(root)
                    with mock.patch.dict(os.environ, environment, clear=False):
                        with self.assertRaises(RUNTIME.EvidenceError):
                            RUNTIME.release_signed_source("OPS-003", context)
                    self.assertEqual(evidence_snapshot(root), before)

    def test_release_signed_source_rejects_malformed_sources_after_receipt_admission(self) -> None:
        temporary, root = self.temporary_repository()
        with temporary:
            commit = RUNTIME.current_git_revision(root)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            context = RUNTIME.ReleaseEvidenceContext(
                "example/repository",
                "100",
                "v1.2.3",
                commit,
                "b" * 64,
                "c" * 64,
                "alert-drill",
                "production",
            )
            baseline = {
                "schemaVersion": 1,
                "artifactType": "release-live-observation",
                "signatureAlgorithm": "ed25519",
                "id": "OPS-003",
                "checkKind": "protected-alert-drill",
                "repository": context.repository,
                "releaseTag": context.tag,
                "commitSHA": context.commit,
                "buildDigest": context.build_digest,
                "inputSHA256": context.input_sha256,
                "workflowRunId": "99",
                "job": "publish-protected-source",
                "observedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "observations": {
                    "status": "passed",
                    "checks": {
                        check: True
                        for check in RUNTIME.RELEASE_OBSERVATION_CHECKS["OPS-003"]
                    },
                },
            }
            fixture_root = Path(temporary.name) / "runner-temp"
            fixture_root.mkdir()
            receipt_path = fixture_root / "release-protected-source-receipt.json"

            def install_source(
                document: dict[str, object],
                *,
                noncanonical: bool = False,
                invalid_signature: bool = False,
            ) -> dict[str, str]:
                source, signature, public_key = self.forged_signed_source(fixture_root, document)
                if noncanonical:
                    source.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
                    subprocess.run(
                        [
                            "openssl",
                            "pkeyutl",
                            "-sign",
                            "-rawin",
                            "-keyform",
                            "DER",
                            "-inkey",
                            str(fixture_root / "forged-private-key.der"),
                            "-in",
                            str(source),
                            "-out",
                            str(signature),
                        ],
                        check=True,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        timeout=10,
                    )
                if invalid_signature:
                    signature.write_bytes(b"x" * 64)
                receipt = self.protected_source_receipt(
                    context,
                    source.read_bytes(),
                    signature.read_bytes(),
                    consumer_run_id=context.run_id,
                    producer_run_id="99",
                )
                receipt_path.write_bytes(RUNTIME.canonical_bytes(receipt) + b"\n")
                receipt_path.chmod(0o600)
                return {
                    "RUNNER_TEMP": str(fixture_root),
                    "HIKER_RELEASE_OBSERVATION_PATH": str(source),
                    "HIKER_RELEASE_OBSERVATION_SIGNATURE_PATH": str(signature),
                    "HIKER_RELEASE_OBSERVATION_PUBLIC_KEY_BASE64": public_key,
                    RUNTIME.RELEASE_PROTECTED_SOURCE_RECEIPT_ENV: str(receipt_path),
                }

            with mock.patch.dict(os.environ, install_source(baseline), clear=False):
                accepted = RUNTIME.release_signed_source("OPS-003", context)
                self.assertEqual(accepted.observations, baseline["observations"])

            stale = json.loads(json.dumps(baseline))
            stale["observedAt"] = (now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
            wrong_commit = json.loads(json.dumps(baseline))
            wrong_commit["commitSHA"] = "d" * 40
            unknown = json.loads(json.dumps(baseline))
            unknown["unexpected"] = True
            cases = (
                ("noncanonical", baseline, True, False),
                ("invalid-signature", baseline, False, True),
                ("stale", stale, False, False),
                ("wrong-commit", wrong_commit, False, False),
                ("unknown-field", unknown, False, False),
            )
            for name, document, noncanonical, invalid_signature in cases:
                with self.subTest(name=name):
                    before = evidence_snapshot(root)
                    environment = install_source(
                        document,
                        noncanonical=noncanonical,
                        invalid_signature=invalid_signature,
                    )
                    with mock.patch.dict(os.environ, environment, clear=False):
                        with self.assertRaises(RUNTIME.EvidenceError):
                            RUNTIME.release_signed_source("OPS-003", context)
                    self.assertEqual(evidence_snapshot(root), before)
    def test_expected_g008_protected_profiles_are_registered(self) -> None:
        actual = frozenset(
            (evidence_id, contract["checkKind"])
            for evidence_id, contract in RUNTIME.PROFILE_CONTRACTS.items()
            if contract["checkKind"].startswith("protected-")
        )
        self.assertEqual(actual, EXPECTED_G008_PROTECTED_ID_CHECK_KINDS)

    def test_every_protected_check_kind_fails_closed_without_writing_evidence(self) -> None:
        for evidence_id, check_kind in sorted(EXPECTED_G008_PROTECTED_ID_CHECK_KINDS):
            with self.subTest(check_kind=check_kind):
                contract = self.profile_contract(evidence_id, check_kind)
                self.assert_rejected_without_evidence_write(
                    REPOSITORY_ROOT,
                    evidence_id,
                    check_kind,
                    contract["output"],
                    {},
                )

    def test_forged_local_ci_and_protected_environment_fail_without_evidence_write(self) -> None:
        temporary, root = self.temporary_repository()
        with temporary:
            commit = RUNTIME.current_git_revision(root)
            cases = (
                (
                    "AUTH-005-PREFLIGHT-SERVER",
                    "protected-auth-preflight-server",
                    {
                        "GITHUB_ACTIONS": "true",
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_WORKFLOW": "Security CI",
                        "GITHUB_JOB": "preflight-auth-server",
                        "HIKER_AUTH_PREFLIGHT_PROTECTED_ENVIRONMENT": "staging",
                        "HIKER_AUTH_PREFLIGHT_BUILD_DIGEST": "a" * 64,
                        "HIKER_AUTH_PREFLIGHT_RELEASE_TAG_SIGNING_FINGERPRINT": "A" * 40,
                        "GITHUB_REF_TYPE": "tag",
                        "GITHUB_RUN_ID": "1",
                        "GITHUB_REPOSITORY": "local/forgery",
                        "GITHUB_REF_NAME": "v1.2.3",
                        "GITHUB_REF": "refs/tags/v1.2.3",
                        "GITHUB_SHA": commit,
                        "GITHUB_TOKEN": "forged-local-token",
                        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://localhost.invalid/oidc",
                        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "forged-local-token",
                    },
                ),
                (
                    "OPS-003",
                    "protected-alert-drill",
                    {
                        "GITHUB_ACTIONS": "true",
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_WORKFLOW": "Release Evidence",
                        "GITHUB_JOB": "alert-drill",
                        "RELEASE_PROTECTED_ENVIRONMENT": "production",
                        "RELEASE_PROTECTED_INPUTS_CONFIRMED": "approved",
                        "GITHUB_REF_TYPE": "tag",
                        "GITHUB_RUN_ID": "1",
                        "GITHUB_REPOSITORY": "local/forgery",
                        "GITHUB_REF_NAME": "v1.2.3",
                        "GITHUB_REF": "refs/tags/v1.2.3",
                        "GITHUB_SHA": commit,
                        "HIKER_RELEASE_BUILD_DIGEST": "a" * 64,
                        "HIKER_RELEASE_INPUT_SHA256": "b" * 64,
                    },
                ),
            )
            for evidence_id, check_kind, environment in cases:
                with self.subTest(evidence_id=evidence_id):
                    contract = self.profile_contract(evidence_id, check_kind)
                    self.assert_rejected_without_evidence_write(
                        root,
                        evidence_id,
                        check_kind,
                        contract["output"],
                        environment,
                    )

    def test_local_canonical_source_substitution_fails_without_evidence_write(self) -> None:
        temporary, root = self.temporary_repository()
        with temporary:
            commit = RUNTIME.current_git_revision(root)
            observed_at = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
            source_cases = (
                (
                    "AUTH-005-PREFLIGHT-SERVER",
                    "protected-auth-preflight-server",
                    {
                        "schemaVersion": 1,
                        "artifactType": "staging-auth-preflight-server-observation",
                        "signatureAlgorithm": "ed25519",
                        "repository": "local/forgery",
                        "releaseTag": "v1.2.3",
                        "commitSHA": commit,
                        "buildDigest": "a" * 64,
                        "workflowRunId": "1",
                        "job": "preflight-auth-server",
                        "observedAt": observed_at,
                        "issuer": {
                            "outcome": "rejected",
                            "code": "WRONG_ISSUER_REJECTED",
                            "probeSHA256": "c" * 64,
                        },
                        "audience": {
                            "outcome": "rejected",
                            "code": "WRONG_AUDIENCE_REJECTED",
                            "probeSHA256": "d" * 64,
                        },
                        "testActor": {
                            "outcome": "rejected",
                            "code": "TEST_IDENTITY_REJECTED",
                            "probeSHA256": "e" * 64,
                        },
                    },
                    {
                        "GITHUB_ACTIONS": "true",
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_WORKFLOW": "Security CI",
                        "GITHUB_JOB": "preflight-auth-server",
                        "HIKER_AUTH_PREFLIGHT_PROTECTED_ENVIRONMENT": "staging",
                        "HIKER_AUTH_PREFLIGHT_BUILD_DIGEST": "a" * 64,
                        "HIKER_AUTH_PREFLIGHT_RELEASE_TAG_SIGNING_FINGERPRINT": "A" * 40,
                        "GITHUB_REF_TYPE": "tag",
                        "GITHUB_RUN_ID": "1",
                        "GITHUB_REPOSITORY": "local/forgery",
                        "GITHUB_REF_NAME": "v1.2.3",
                        "GITHUB_REF": "refs/tags/v1.2.3",
                        "GITHUB_SHA": commit,
                        "GITHUB_TOKEN": "forged-local-token",
                        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://localhost.invalid/oidc",
                        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "forged-local-token",
                    },
                    (
                        "HIKER_AUTH_PREFLIGHT_SOURCE_PATH",
                        "HIKER_AUTH_PREFLIGHT_SOURCE_SIGNATURE_PATH",
                        "HIKER_AUTH_PREFLIGHT_SOURCE_PUBLIC_KEY_BASE64",
                    ),
                ),
                (
                    "OPS-003",
                    "protected-alert-drill",
                    {
                        "schemaVersion": 1,
                        "artifactType": "release-live-observation",
                        "signatureAlgorithm": "ed25519",
                        "id": "OPS-003",
                        "checkKind": "protected-alert-drill",
                        "repository": "local/forgery",
                        "releaseTag": "v1.2.3",
                        "commitSHA": commit,
                        "buildDigest": "a" * 64,
                        "inputSHA256": "b" * 64,
                        "workflowRunId": "1",
                        "job": "alert-drill",
                        "observedAt": observed_at,
                        "observations": {"result": "forged-local-source"},
                    },
                    {
                        "GITHUB_ACTIONS": "true",
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_WORKFLOW": "Release Evidence",
                        "GITHUB_JOB": "alert-drill",
                        "RELEASE_PROTECTED_ENVIRONMENT": "production",
                        "RELEASE_PROTECTED_INPUTS_CONFIRMED": "approved",
                        "GITHUB_REF_TYPE": "tag",
                        "GITHUB_RUN_ID": "1",
                        "GITHUB_REPOSITORY": "local/forgery",
                        "GITHUB_REF_NAME": "v1.2.3",
                        "GITHUB_REF": "refs/tags/v1.2.3",
                        "GITHUB_SHA": commit,
                        "HIKER_RELEASE_BUILD_DIGEST": "a" * 64,
                        "HIKER_RELEASE_INPUT_SHA256": "b" * 64,
                    },
                    (
                        "HIKER_RELEASE_OBSERVATION_PATH",
                        "HIKER_RELEASE_OBSERVATION_SIGNATURE_PATH",
                        "HIKER_RELEASE_OBSERVATION_PUBLIC_KEY_BASE64",
                    ),
                ),
                (
                    "MIG-005-PROTECTED",
                    "protected-pitr-restore",
                    {
                        "schemaVersion": 1,
                        "artifactType": "staging-pitr-restore-observation",
                        "signatureAlgorithm": "ed25519",
                        "environment": "staging",
                        "repository": "local/forgery",
                        "releaseTag": "v1.2.3",
                        "commitSHA": commit,
                        "buildDigest": "a" * 64,
                        "workflowRunId": "1",
                        "job": "protected-pitr-restore",
                        "datasetSHA256": "b" * 64,
                        "migrationSetSHA256": "c" * 64,
                        "backupSHA256": "d" * 64,
                        "observedAt": observed_at,
                        "restoredChecks": {
                            "grants": True,
                            "rpc": True,
                            "projection": True,
                            "history": True,
                            "audit": True,
                        },
                    },
                    {
                        "GITHUB_ACTIONS": "true",
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_WORKFLOW": "Security CI",
                        "GITHUB_JOB": "protected-pitr-restore",
                        "HIKER_PITR_PREFLIGHT_PROTECTED_ENVIRONMENT": "staging",
                        "HIKER_PITR_PREFLIGHT_BUILD_DIGEST": "a" * 64,
                        "HIKER_PITR_PREFLIGHT_DATASET_SHA256": "b" * 64,
                        "HIKER_PITR_PREFLIGHT_MIGRATION_SET_SHA256": "c" * 64,
                        "HIKER_PITR_PREFLIGHT_BACKUP_SHA256": "d" * 64,
                        "HIKER_PITR_PREFLIGHT_RELEASE_TAG_SIGNING_FINGERPRINT": "A" * 40,
                        "GITHUB_REF_TYPE": "tag",
                        "GITHUB_RUN_ID": "1",
                        "GITHUB_REPOSITORY": "local/forgery",
                        "GITHUB_REF_NAME": "v1.2.3",
                        "GITHUB_REF": "refs/tags/v1.2.3",
                        "GITHUB_SHA": commit,
                        "GITHUB_TOKEN": "forged-local-token",
                        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://localhost.invalid/oidc",
                        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "forged-local-token",
                    },
                    (
                        "HIKER_PITR_PREFLIGHT_SOURCE_PATH",
                        "HIKER_PITR_PREFLIGHT_SOURCE_SIGNATURE_PATH",
                        "HIKER_PITR_PREFLIGHT_SOURCE_PUBLIC_KEY_BASE64",
                    ),
                ),
            )
            for evidence_id, check_kind, document, environment, source_variables in source_cases:
                with self.subTest(evidence_id=evidence_id):
                    fixture_root = Path(temporary.name) / "runner-temp" / evidence_id
                    fixture_root.mkdir(parents=True)
                    source, signature, public_key = self.forged_signed_source(fixture_root, document)
                    source_path, signature_path, public_key_value = source_variables
                    contract = self.profile_contract(evidence_id, check_kind)
                    self.assert_rejected_without_evidence_write(
                        root,
                        evidence_id,
                        check_kind,
                        contract["output"],
                        {
                            **environment,
                            "RUNNER_TEMP": str(fixture_root),
                            source_path: str(source),
                            signature_path: str(signature),
                            public_key_value: public_key,
                        },
                    )


if __name__ == "__main__":
    unittest.main()
