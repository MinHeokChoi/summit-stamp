#!/usr/bin/env python3
"""Deterministic negative coverage for protected AUTH-005 and PITR evidence."""

from __future__ import annotations

import base64
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]
WRITER_PATH = ROOT / "Scripts/ci/run-runtime-evidence.py"
SPEC = importlib.util.spec_from_file_location("runtime_evidence", WRITER_PATH)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load runtime evidence writer")
writer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = writer
SPEC.loader.exec_module(writer)


def expect_failure(label: str, operation, *arguments) -> None:
    try:
        operation(*arguments)
    except writer.EvidenceError:
        return
    raise AssertionError(f"{label} unexpectedly succeeded")


def snapshot(path: Path):
    try:
        details = path.lstat()
    except FileNotFoundError:
        return None
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns


def timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def server_document(context: writer.ProtectedContext) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "artifactType": "staging-auth-preflight-server-observation",
        "signatureAlgorithm": "ed25519",
        "repository": context.repository,
        "releaseTag": context.release_tag,
        "commitSHA": context.git_sha,
        "buildDigest": context.build_digest,
        "workflowRunId": context.run_id,
        "job": context.job,
        "observedAt": timestamp(),
        "issuer": {"outcome": "rejected", "code": "WRONG_ISSUER_REJECTED", "probeSHA256": "1" * 64},
        "audience": {"outcome": "rejected", "code": "WRONG_AUDIENCE_REJECTED", "probeSHA256": "2" * 64},
        "testActor": {"outcome": "rejected", "code": "TEST_IDENTITY_REJECTED", "probeSHA256": "3" * 64},
    }
def pitr_document(context: writer.PitrProtectedContext) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "artifactType": "staging-pitr-restore-observation",
        "signatureAlgorithm": "ed25519",
        "environment": "staging",
        "repository": context.repository,
        "releaseTag": context.release_tag,
        "commitSHA": context.git_sha,
        "buildDigest": context.build_digest,
        "workflowRunId": context.run_id,
        "job": context.job,
        "datasetSHA256": context.dataset_sha256,
        "migrationSetSHA256": context.migration_set_sha256,
        "backupSHA256": context.backup_sha256,
        "observedAt": timestamp(),
        "restoredChecks": {
            "grants": True,
            "rpc": True,
            "projection": True,
            "history": True,
            "audit": True,
        },
    }




def test_local_invocation_has_no_output() -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GITHUB_", "ACTIONS_", "HIKER_AUTH_PREFLIGHT_", "HIKER_PITR_PREFLIGHT_"))
    }
    cases = (
        (
            "AUTH-005-PREFLIGHT-SERVER",
            "protected-auth-preflight-server",
            "Evidence/runtime/AUTH-005-PREFLIGHT-SERVER.json",
        ),
        (
            "AUTH-005-PREFLIGHT-ARCHIVE",
            "protected-auth-preflight-archive",
            "Evidence/runtime/AUTH-005-PREFLIGHT-ARCHIVE.json",
        ),
        (
            "AUTH-005-PREFLIGHT",
            "protected-auth-preflight-aggregate",
            "Evidence/runtime/AUTH-005-PREFLIGHT.json",
        ),
        (
            "MIG-005-PROTECTED",
            "protected-pitr-restore",
            "Evidence/runtime/MIG-005-PROTECTED.json",
        ),
    )
    for evidence_id, check_kind, output_name in cases:
        output = ROOT / output_name
        paths = (output, Path(f"{output}.sha256"), output.with_suffix(".commit"))
        before = tuple(snapshot(path) for path in paths)
        result = subprocess.run(
            [
                sys.executable,
                str(WRITER_PATH),
                "--id",
                evidence_id,
                "--check-kind",
                check_kind,
                "--output",
                output_name,
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode == 0 or tuple(snapshot(path) for path in paths) != before:
            raise AssertionError(f"local invocation created or changed protected evidence for {evidence_id}")


def test_mismatched_build_and_stale_source_are_rejected() -> None:
    context = writer.ProtectedContext(
        "example/hiker",
        "123456",
        "v1.2.3",
        "a" * 40,
        "b" * 64,
        "preflight-auth-server",
    )
    mismatched = server_document(context)
    mismatched["buildDigest"] = "c" * 64
    expect_failure("mismatched build", writer.validate_server_source_document, mismatched, context)
    stale = server_document(context)
    stale["observedAt"] = "2000-01-01T00:00:00Z"
    expect_failure("stale source", writer.validate_server_source_document, stale, context)
def test_pitr_source_requires_exact_restore_correlation() -> None:
    context = writer.PitrProtectedContext(
        "example/hiker",
        "123456",
        "v1.2.3",
        "a" * 40,
        "b" * 64,
        "preflight-pitr-restore",
        "f" * 64,
        "c" * 64,
        "d" * 64,
    )
    document = pitr_document(context)
    observation = writer.validate_pitr_source_document(document, context)
    if observation["restoredChecks"] != {"grants": True, "rpc": True, "projection": True, "history": True, "audit": True}:
        raise AssertionError("valid protected PITR source did not retain all restored checks")
    mismatches = (
        ("environment", "environment", "production"),
        ("commit", "commitSHA", "e" * 40),
        ("build", "buildDigest", "e" * 64),
        ("dataset", "datasetSHA256", "e" * 64),
        ("migration set", "migrationSetSHA256", "e" * 64),
        ("backup", "backupSHA256", "e" * 64),
    )
    for label, field, value in mismatches:
        invalid = pitr_document(context)
        invalid[field] = value
        expect_failure(f"mismatched {label}", writer.validate_pitr_source_document, invalid, context)
    incomplete = pitr_document(context)
    incomplete["restoredChecks"]["audit"] = False
    expect_failure("incomplete restore checks", writer.validate_pitr_source_document, incomplete, context)




def test_unsigned_and_sensitive_sources_are_rejected() -> None:
    malformed_public_key = b"-----BEGIN PUBLIC KEY-----\nnot-a-real-public-key-material-that-cannot-verify\n-----END PUBLIC KEY-----\n"
    expect_failure("unsigned source", writer.verify_detached_signature, b"{}\n", b"", malformed_public_key)
    expect_failure("secret source value", writer.reject_sensitive_data, {"probeSHA256": "authorization=Bearer retained"})
    expect_failure("PII source value", writer.reject_sensitive_data, {"probeSHA256": "operator@example.com"})
def test_non_ed25519_public_key_is_rejected_before_signature_verification() -> None:
    modulus = base64.urlsafe_b64encode(b"\x80" + b"\x00" * 254 + b"\x01").decode("ascii").rstrip("=")
    exponent = base64.urlsafe_b64encode(b"\x01\x00\x01").decode("ascii").rstrip("=")
    rsa_public_key = writer.rsa_public_key_pem(modulus, exponent)
    original_run = writer.subprocess.run
    commands = []

    def record_command(arguments, *args, **keywords):
        result = original_run(arguments, *args, **keywords)
        commands.append((arguments, result.returncode))
        return result

    writer.subprocess.run = record_command
    try:
        expect_failure("non-Ed25519 source key", writer.verify_detached_signature, b"{}\n", b"", rsa_public_key)
    finally:
        writer.subprocess.run = original_run
    if not any(command[:2] == ["openssl", "pkey"] and returncode == 0 for command, returncode in commands):
        raise AssertionError("generated RSA public key was not a valid public key")
    if any(command[:2] == ["openssl", "pkeyutl"] for command, _returncode in commands):
        raise AssertionError("non-Ed25519 key reached pkeyutl verification")


def test_rest_workflow_identity_uses_native_id_and_path() -> None:
    context = writer.ProtectedContext(
        "example/hiker",
        "123456",
        "v1.2.3",
        "a" * 40,
        "b" * 64,
        "preflight-auth-server",
    )
    base_url = f"https://api.github.com/repos/{context.repository}/actions"
    original_github_json = writer.github_json
    original_token = os.environ.get("GITHUB_TOKEN")

    def mocked_github_json(workflow_path: str):
        def response(url: str, token: str):
            if token != "mock-token":
                raise AssertionError("REST workflow identity used an unexpected token")
            if url == f"{base_url}/runs/{context.run_id}":
                return {
                    "event": "workflow_dispatch",
                    "head_sha": context.git_sha,
                    "head_branch": context.release_tag,
                    "name": "Security CI",
                    "status": "in_progress",
                    "path": ".github/workflows/ci-security.yml",
                    "workflow_id": 987654,
                }
            if url == f"{base_url}/workflows/987654":
                return {
                    "id": 987654,
                    "name": "Security CI",
                    "path": workflow_path,
                    "state": "active",
                }
            if url == f"{base_url}/runs/{context.run_id}/jobs?per_page=100":
                return {"jobs": [{"name": context.job, "status": "in_progress"}]}
            raise AssertionError(f"unexpected REST URL: {url}")

        return response

    os.environ["GITHUB_TOKEN"] = "mock-token"
    try:
        writer.github_json = mocked_github_json(".github/workflows/ci-security.yml")
        writer.require_live_github_job(context)
        writer.github_json = mocked_github_json(".github/workflows/other-security.yml")
        expect_failure("another workflow REST identity", writer.require_live_github_job, context)
    finally:
        writer.github_json = original_github_json
        if original_token is None:
            os.environ.pop("GITHUB_TOKEN", None)
        else:
            os.environ["GITHUB_TOKEN"] = original_token




def test_partial_publication_is_cleaned_up() -> None:
    with tempfile.TemporaryDirectory(prefix="auth-preflight-negative-") as directory:
        root = Path(directory)
        path = root / "AUTH-005-PREFLIGHT-SERVER.json"
        sidecar = Path(f"{path}.sha256")
        commit = root / "AUTH-005-PREFLIGHT-SERVER.commit"
        original_link = writer.os.link
        calls = 0

        def fail_second_link(source, destination, *arguments, **keywords):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected sidecar publication failure")
            return original_link(source, destination, *arguments, **keywords)

        writer.os.link = fail_second_link
        try:
            expect_failure(
                "partial publication",
                writer.write_preflight_publication,
                path,
                sidecar,
                commit,
                "Evidence/runtime/AUTH-005-PREFLIGHT-SERVER.json",
                {"negative": True},
            )
        finally:
            writer.os.link = original_link
        if any(root.iterdir()):
            raise AssertionError("partial protected publication left evidence or temporary files")


def test_signed_sources_are_bound_to_current_run_and_job() -> None:
    context = writer.ProtectedContext(
        "example/hiker",
        "123456",
        "v1.2.3",
        "a" * 40,
        "b" * 64,
        "preflight-auth-server",
    )
    document = server_document(context)
    document["workflowRunId"] = "654321"
    expect_failure(
        "cross-run signed source replay",
        writer.validate_server_source_document,
        document,
        context,
    )
    document = server_document(context)
    document["job"] = "preflight-auth-archive"
    expect_failure(
        "cross-job signed source replay",
        writer.validate_server_source_document,
        document,
        context,
    )


def main() -> int:
    test_local_invocation_has_no_output()
    test_mismatched_build_and_stale_source_are_rejected()
    test_unsigned_and_sensitive_sources_are_rejected()
    test_pitr_source_requires_exact_restore_correlation()
    test_non_ed25519_public_key_is_rejected_before_signature_verification()
    test_rest_workflow_identity_uses_native_id_and_path()
    test_signed_sources_are_bound_to_current_run_and_job()
    test_partial_publication_is_cleaned_up()
    return 0


if __name__ == "__main__":
    sys.exit(main())
