#!/usr/bin/env python3
"""Synthetic, read-only lineage tests for M6/M7 release assembly contracts."""

from __future__ import annotations

import argparse
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
LINEAGE_SCRIPT = REPOSITORY_ROOT / "Scripts" / "release" / "validate-release-lineage.py"
SPEC = importlib.util.spec_from_file_location("release_lineage_under_test", LINEAGE_SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not import release lineage validator from {LINEAGE_SCRIPT}")
LINEAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LINEAGE
SPEC.loader.exec_module(LINEAGE)
RUNTIME_EVIDENCE_SCRIPT = REPOSITORY_ROOT / "Scripts" / "ci" / "run-runtime-evidence.py"
RUNTIME_SPEC = importlib.util.spec_from_file_location("runtime_evidence_under_test", RUNTIME_EVIDENCE_SCRIPT)
if RUNTIME_SPEC is None or RUNTIME_SPEC.loader is None:
    raise RuntimeError(f"could not import runtime evidence producer from {RUNTIME_EVIDENCE_SCRIPT}")
RUNTIME = importlib.util.module_from_spec(RUNTIME_SPEC)
sys.modules[RUNTIME_SPEC.name] = RUNTIME
RUNTIME_SPEC.loader.exec_module(RUNTIME)

TAG = "v1.2.3"
COMMIT = "a" * 40


def sha(character: str) -> str:
    return character * 64


def absent(root: Path, *relative_paths: str) -> None:
    for relative_path in relative_paths:
        path = root / relative_path
        if path.exists() or path.is_symlink():
            raise AssertionError(f"unexpected output exists: {path}")


def snapshot(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def write_document(root: Path, relative_path: str, document: object) -> str:
    raw = LINEAGE.canonical_bytes(document) + b"\n"
    path = root.joinpath(*Path(relative_path).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    digest = LINEAGE.sha256_bytes(raw)
    Path(f"{path}.sha256").write_bytes(f"{digest}  {relative_path}\n".encode("ascii"))
    return digest


class AssemblyNoWriteTests(unittest.TestCase):
    def test_readiness_missing_input_fails_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = argparse.Namespace(tag=TAG, commit=COMMIT, output=LINEAGE.READINESS_OUTPUT)
            with (
                mock.patch.object(LINEAGE, "repository_root", return_value=root),
                mock.patch.object(LINEAGE, "verify_tag_commit"),
                self.assertRaises(LINEAGE.ReleaseError),
            ):
                LINEAGE.assemble_readiness(arguments)
            absent(root, LINEAGE.READINESS_OUTPUT, f"{LINEAGE.READINESS_OUTPUT}.sha256")

    def test_rc_missing_input_fails_without_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = argparse.Namespace(
                readiness=LINEAGE.READINESS_OUTPUT,
                rel_002="Evidence/runtime/REL-002.json",
                rel_003="Evidence/runtime/REL-003.json",
                rel_004="Evidence/runtime/REL-004.json",
                rel_005="Evidence/runtime/REL-005.json",
                rel_006="Evidence/runtime/REL-006.json",
                rel_008="Evidence/runtime/REL-008.json",
                rel_009=LINEAGE.REL009_OUTPUT,
                ops_005="Evidence/runtime/OPS-005.json",
                perf="Evidence/tests/PERF-001.json",
                auth="Evidence/runtime/AUTH-005-RC.json",
                approval="Evidence/runtime/approvals/threshold.json",
                output_manifest=LINEAGE.RC_OUTPUT,
                output=LINEAGE.REL007_OUTPUT,
            )
            with (
                mock.patch.object(LINEAGE, "repository_root", return_value=root),
                self.assertRaises(LINEAGE.ReleaseError),
            ):
                LINEAGE.assemble_rc(arguments)
            absent(root, LINEAGE.RC_OUTPUT, f"{LINEAGE.RC_OUTPUT}.sha256", LINEAGE.REL007_OUTPUT, f"{LINEAGE.REL007_OUTPUT}.sha256")

    def test_m6_exit_missing_input_fails_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = argparse.Namespace(
                rc=LINEAGE.RC_OUTPUT,
                ops_003="Evidence/runtime/OPS-003.json",
                ops_004="Evidence/runtime/OPS-004.json",
                perf="Evidence/tests/PERF-001.json",
                beta="Evidence/runtime/REL-005.json",
                threshold="Evidence/runtime/OPS-005.json",
                auth="Evidence/runtime/AUTH-005-RC.json",
                approval="Evidence/runtime/approvals/m6-exit.json",
                output=LINEAGE.M6_EXIT_OUTPUT,
            )
            with (
                mock.patch.object(LINEAGE, "repository_root", return_value=root),
                self.assertRaises(LINEAGE.ReleaseError),
            ):
                LINEAGE.assemble_m6_exit(arguments)
            absent(root, LINEAGE.M6_EXIT_OUTPUT, f"{LINEAGE.M6_EXIT_OUTPUT}.sha256")


class PublicationReplayTests(unittest.TestCase):
    def test_write_pair_once_replays_only_the_same_transaction(self) -> None:
        relative_path = "Evidence/manifests/replay.json"
        first_record = {"stage": "first"}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = LINEAGE.write_pair_once(root, relative_path, first_record)
            first = snapshot(root)
            self.assertEqual(digest, LINEAGE.sha256_bytes(LINEAGE.canonical_bytes(first_record) + b"\n"))

            self.assertEqual(LINEAGE.write_pair_once(root, relative_path, first_record), digest)
            self.assertEqual(snapshot(root), first)
            with self.assertRaises(LINEAGE.ReleaseError):
                LINEAGE.write_pair_once(root, relative_path, {"stage": "conflict"})
            self.assertEqual(snapshot(root), first)

            for name, suffix in (("output", ""), ("sidecar", ".sha256")):
                with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    conflict = root / f"{relative_path}{suffix}"
                    conflict.parent.mkdir(parents=True)
                    conflict.write_bytes(b"foreign\n")
                    before = snapshot(root)

                    with self.assertRaises(LINEAGE.ReleaseError):
                        LINEAGE.write_pair_once(root, relative_path, first_record)

                    self.assertEqual(snapshot(root), before)
                    if suffix:
                        absent(root, relative_path)
                    else:
                        absent(root, f"{relative_path}.sha256")
    def test_canonical_pair_recovery_rejects_conflicting_bytes(self) -> None:
        cases = (
            ("readiness", LINEAGE.READINESS_OUTPUT),
            ("m6-exit", LINEAGE.M6_EXIT_OUTPUT),
            ("rel-009", LINEAGE.REL009_OUTPUT),
        )
        for name, output in cases:
            with self.subTest(writer=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record = {"writer": name}
                path = root / output
                sidecar = Path(f"{path}.sha256")
                original_link = LINEAGE.os.link

                def interrupt_sidecar(source: Path, destination: Path, *arguments: object, **keywords: object) -> None:
                    if destination == sidecar:
                        raise OSError("injected sidecar failure")
                    original_link(source, destination, *arguments, **keywords)

                with mock.patch.object(LINEAGE.os, "link", side_effect=interrupt_sidecar):
                    with self.assertRaises(LINEAGE.ReleaseError):
                        LINEAGE.write_pair_once(root, output, record)

                partial = snapshot(root)
                self.assertIn(LINEAGE.pair_publication_marker(output), partial)
                self.assertEqual(partial[output], LINEAGE.canonical_bytes(record) + b"\n")
                absent(root, f"{output}.sha256")

                LINEAGE.write_pair_once(root, output, record)
                complete = snapshot(root)
                self.assertEqual(complete[output], partial[output])
                self.assertIn(f"{output}.sha256", complete)
                LINEAGE.write_pair_once(root, output, record)
                self.assertEqual(snapshot(root), complete)

                with self.assertRaises(LINEAGE.ReleaseError):
                    LINEAGE.write_pair_once(root, output, {"writer": "conflict"})
                self.assertEqual(snapshot(root), complete)

                path.write_bytes(b"foreign\n")
                foreign = snapshot(root)
                with self.assertRaises(LINEAGE.ReleaseError):
                    LINEAGE.write_pair_once(root, output, record)
                self.assertEqual(snapshot(root), foreign)

    def test_runtime_protected_pair_recovers_only_its_transaction(self) -> None:
        evidence_id = "AUTH-005-RC-SERVER"
        output = RUNTIME.RELEASE_EVIDENCE_CONTRACTS[evidence_id]["output"]
        first_record = {
            "id": evidence_id,
            "output": {"path": output},
            "collectedAt": "2026-07-14T00:00:00Z",
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, sidecar = RUNTIME.output_paths(root, output)
            original_link = RUNTIME.os.link

            def interrupt_sidecar(source: Path, destination: Path, *arguments: object, **keywords: object) -> None:
                if destination == sidecar:
                    raise OSError("injected sidecar failure")
                original_link(source, destination, *arguments, **keywords)

            with mock.patch.object(RUNTIME.os, "link", side_effect=interrupt_sidecar):
                with self.assertRaises(RUNTIME.EvidenceError):
                    RUNTIME.publish_release_record(root, evidence_id, first_record)

            partial = snapshot(root)
            self.assertIn(f"{output}.publication-intent", partial)
            self.assertEqual(partial[output], RUNTIME.canonical_bytes(first_record) + b"\n")
            absent(root, f"{output}.sha256")

            replay_record = dict(first_record, collectedAt="2026-07-14T00:01:00Z")
            RUNTIME.publish_release_record(root, evidence_id, replay_record)
            complete = snapshot(root)
            self.assertEqual(complete[output], partial[output])
            RUNTIME.publish_release_record(root, evidence_id, replay_record)
            self.assertEqual(snapshot(root), complete)

            with self.assertRaises(RUNTIME.EvidenceError):
                RUNTIME.publish_release_record(root, evidence_id, dict(first_record, id="OPS-003"))
            self.assertEqual(snapshot(root), complete)

            sidecar.write_bytes(b"foreign\n")
            foreign = snapshot(root)
            with self.assertRaises(RUNTIME.EvidenceError):
                RUNTIME.publish_release_record(root, evidence_id, replay_record)
            self.assertEqual(snapshot(root), foreign)
    def test_runtime_preflight_publication_recovers_its_committed_record(self) -> None:
        output = "Evidence/runtime/AUTH-005-PREFLIGHT-SERVER.json"
        commit_path = "Evidence/runtime/AUTH-005-PREFLIGHT-SERVER.commit"
        first_record = {
            "id": "AUTH-005-PREFLIGHT-SERVER",
            "output": {"path": output, "commitPath": commit_path},
            "collectedAt": "2026-07-14T00:00:00Z",
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, sidecar = RUNTIME.output_paths(root, output)
            commit = root / commit_path
            original_link = RUNTIME.os.link

            def interrupt_sidecar(source: Path, destination: Path, *arguments: object, **keywords: object) -> None:
                if destination == sidecar:
                    raise OSError("injected sidecar failure")
                original_link(source, destination, *arguments, **keywords)

            with mock.patch.object(RUNTIME.os, "link", side_effect=interrupt_sidecar):
                with self.assertRaises(RUNTIME.EvidenceError):
                    RUNTIME.write_preflight_publication(path, sidecar, commit, output, first_record)

            partial = snapshot(root)
            self.assertIn(f"{output}.publication-intent", partial)
            self.assertEqual(partial[output], RUNTIME.canonical_bytes(first_record) + b"\n")
            absent(root, f"{output}.sha256", commit_path)

            replay_record = dict(first_record, collectedAt="2026-07-14T00:01:00Z")
            RUNTIME.write_preflight_publication(path, sidecar, commit, output, replay_record)
            complete = snapshot(root)
            self.assertEqual(complete[output], partial[output])
            self.assertIn(f"{output}.sha256", complete)
            self.assertIn(commit_path, complete)

            sidecar.write_bytes(b"foreign\n")
            foreign = snapshot(root)
            with self.assertRaises(RUNTIME.EvidenceError):
                RUNTIME.write_preflight_publication(path, sidecar, commit, output, replay_record)
            self.assertEqual(snapshot(root), foreign)

    def test_assemblers_reject_conflicting_preexisting_outputs_without_changes(self) -> None:
        cases = (
            (
                "readiness",
                LINEAGE.assemble_readiness,
                argparse.Namespace(tag=TAG, commit=COMMIT, output=LINEAGE.READINESS_OUTPUT),
                (LINEAGE.READINESS_OUTPUT,),
            ),
            (
                "rc",
                LINEAGE.assemble_rc,
                argparse.Namespace(
                    readiness=LINEAGE.READINESS_OUTPUT,
                    rel_002="Evidence/runtime/REL-002.json",
                    rel_003="Evidence/runtime/REL-003.json",
                    rel_004="Evidence/runtime/REL-004.json",
                    rel_005="Evidence/runtime/REL-005.json",
                    rel_006="Evidence/runtime/REL-006.json",
                    rel_008="Evidence/runtime/REL-008.json",
                    rel_009=LINEAGE.REL009_OUTPUT,
                    ops_005="Evidence/runtime/OPS-005.json",
                    perf="Evidence/tests/PERF-001.json",
                    auth="Evidence/runtime/AUTH-005-RC.json",
                    approval="Evidence/runtime/approvals/threshold.json",
                    output_manifest=LINEAGE.RC_OUTPUT,
                    output=LINEAGE.REL007_OUTPUT,
                ),
                (LINEAGE.RC_OUTPUT, LINEAGE.REL007_OUTPUT),
            ),
            (
                "m6-exit",
                LINEAGE.assemble_m6_exit,
                argparse.Namespace(
                    rc=LINEAGE.RC_OUTPUT,
                    ops_003="Evidence/runtime/OPS-003.json",
                    ops_004="Evidence/runtime/OPS-004.json",
                    perf="Evidence/tests/PERF-001.json",
                    beta="Evidence/runtime/REL-005.json",
                    threshold="Evidence/runtime/OPS-005.json",
                    auth="Evidence/runtime/AUTH-005-RC.json",
                    approval="Evidence/runtime/approvals/m6-exit.json",
                    output=LINEAGE.M6_EXIT_OUTPUT,
                ),
                (LINEAGE.M6_EXIT_OUTPUT,),
            ),
        )

        for name, assemble, arguments, outputs in cases:
            for output in outputs:
                for suffix in ("", ".sha256"):
                    with self.subTest(assembler=name, output=output, suffix=suffix), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        conflict = root / f"{output}{suffix}"
                        conflict.parent.mkdir(parents=True)
                        conflict.write_bytes(b"foreign\n")
                        before = snapshot(root)

                        with (
                            mock.patch.object(LINEAGE, "repository_root", return_value=root),
                            mock.patch.object(LINEAGE, "verify_tag_commit"),
                            self.assertRaises(LINEAGE.ReleaseError),
                        ):
                            assemble(arguments)

                        self.assertEqual(snapshot(root), before)
                        for expected in outputs:
                            for candidate in (expected, f"{expected}.sha256"):
                                if candidate != f"{output}{suffix}":
                                    absent(root, candidate)

    def test_rc_transaction_recovers_after_interrupted_second_publication(self) -> None:
        manifest = {
            "schemaVersion": 1,
            "artifactType": "release-candidate-manifest",
            "id": "RC",
            "tag": TAG,
            "commit": COMMIT,
        }
        receipt = {"schemaVersion": 1, "artifactType": "release-candidate-assembly", "id": "REL-007"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            publish_pair = LINEAGE.publish_pair

            def interrupt_second(
                candidate_root: Path,
                path: str,
                document: dict[str, object],
                *,
                recover: bool = False,
            ) -> str:
                if path == LINEAGE.REL007_OUTPUT:
                    raise LINEAGE.ReleaseError("injected second-publication failure")
                return publish_pair(candidate_root, path, document, recover=recover)

            with mock.patch.object(LINEAGE, "publish_pair", side_effect=interrupt_second):
                with self.assertRaisesRegex(LINEAGE.ReleaseError, "injected"):
                    LINEAGE.publish_rc_transaction(root, manifest, receipt)

            partial = snapshot(root)
            self.assertIn(LINEAGE.RC_PUBLICATION_MARKER, partial)
            self.assertIn(LINEAGE.RC_OUTPUT, partial)
            self.assertIn(f"{LINEAGE.RC_OUTPUT}.sha256", partial)
            absent(root, LINEAGE.REL007_OUTPUT, f"{LINEAGE.REL007_OUTPUT}.sha256")

            LINEAGE.publish_rc_transaction(root, manifest, receipt)
            complete = snapshot(root)
            self.assertEqual(complete[LINEAGE.RC_PUBLICATION_MARKER], partial[LINEAGE.RC_PUBLICATION_MARKER])
            self.assertEqual(complete[LINEAGE.RC_OUTPUT], partial[LINEAGE.RC_OUTPUT])
            self.assertIn(LINEAGE.REL007_OUTPUT, complete)
            self.assertIn(f"{LINEAGE.REL007_OUTPUT}.sha256", complete)
            LINEAGE.publish_rc_transaction(root, manifest, receipt)
            self.assertEqual(snapshot(root), complete)


class ManifestBindingTests(unittest.TestCase):
    def test_readiness_stale_and_cross_commit_inputs_are_rejected_without_write(self) -> None:
        for name, input_commit, input_sha in (
            ("stale", COMMIT, sha("f")),
            ("cross-commit", sha("b")[:40], sha("b")),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                input_path = "Evidence/tests/ARCH-001.json"
                input_record = {
                    "schemaVersion": 1,
                    "id": "ARCH-001",
                    "status": "passed",
                    "commit": input_commit,
                    "output": {"path": input_path},
                }
                input_raw = LINEAGE.canonical_bytes(input_record) + b"\n"
                input_file = root / input_path
                input_file.parent.mkdir(parents=True)
                input_file.write_bytes(input_raw)
                input_digest = LINEAGE.sha256_bytes(input_raw)
                Path(f"{input_file}.sha256").write_bytes(
                    f"{input_digest}  {input_path}\n".encode("ascii")
                )
                readiness = {
                    "schemaVersion": 1,
                    "artifactType": "m6-readiness-manifest",
                    "id": "REL-001",
                    "tag": TAG,
                    "commit": COMMIT,
                    "inputs": [{"id": "ARCH-001", "path": input_path, "sha256": input_sha}],
                    "m2aApproval": {"path": LINEAGE.M2A_APPROVAL, "sha256": sha("c")},
                }
                readiness_raw = LINEAGE.canonical_bytes(readiness) + b"\n"
                readiness_file = root / LINEAGE.READINESS_OUTPUT
                readiness_file.parent.mkdir(parents=True)
                readiness_file.write_bytes(readiness_raw)
                readiness_digest = LINEAGE.sha256_bytes(readiness_raw)
                Path(f"{readiness_file}.sha256").write_bytes(
                    f"{readiness_digest}  {LINEAGE.READINESS_OUTPUT}\n".encode("ascii")
                )
                before = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file()
                }
                with (
                    mock.patch.object(LINEAGE, "READINESS_TEST_IDS", ("ARCH-001",)),
                    mock.patch.object(LINEAGE, "READINESS_RUNTIME_IDS", ()),
                    mock.patch.object(LINEAGE, "verify_tag_commit"),
                    self.assertRaises(LINEAGE.ReleaseError),
                ):
                    LINEAGE.verify_readiness(root, LINEAGE.READINESS_OUTPUT)
                after = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(after, before)
    def rc_record(self, predecessor: str) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "artifactType": "release-candidate-manifest",
            "id": "REL-007",
            "tag": TAG,
            "commit": COMMIT,
            "previousManifestSHA256": predecessor,
            "inputs": [],
            "thresholdApproval": {"path": "Evidence/runtime/approvals/threshold.json", "sha256": sha("b")},
        }

    def m6_record(self, predecessor: str) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "artifactType": "m6-exit-admission",
            "id": "M6-EXIT",
            "status": "passed",
            "tag": TAG,
            "commit": COMMIT,
            "previousManifestSHA256": predecessor,
            "inputs": [],
            "approval": {"path": "Evidence/runtime/approvals/m6-exit.json", "sha256": sha("c")},
            "output": {"path": LINEAGE.M6_EXIT_OUTPUT},
        }

    def assert_rc_rejected(
        self,
        record: dict[str, object],
        readiness: dict[str, object],
        digest: str,
        readiness_digest: str = sha("r"),
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(LINEAGE, "read_json", return_value=(record, b"", digest)),
                mock.patch.object(LINEAGE, "verify_readiness", return_value=(readiness, readiness_digest)),
                self.assertRaises(LINEAGE.ReleaseError),
            ):
                LINEAGE.verify_rc(root, LINEAGE.RC_OUTPUT)
            absent(root, LINEAGE.RC_OUTPUT, LINEAGE.REL007_OUTPUT)

    def test_rc_stale_self_and_cross_commit_inputs_are_rejected_without_output(self) -> None:
        readiness = {"tag": TAG, "commit": COMMIT}
        self.assert_rc_rejected(self.rc_record(sha("x")), readiness, sha("m"))
        self.assert_rc_rejected(self.rc_record(sha("m")), readiness, sha("m"), sha("m"))
        self.assert_rc_rejected(self.rc_record(sha("r")), {"tag": TAG, "commit": sha("a")[:40]}, sha("m"))

    def assert_m6_rejected(
        self,
        record: dict[str, object],
        rc: dict[str, object],
        digest: str,
        rc_digest: str = sha("r"),
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(LINEAGE, "read_json", return_value=(record, b"", digest)),
                mock.patch.object(LINEAGE, "verify_tag_commit"),
                mock.patch.object(LINEAGE, "verify_rc", return_value=(rc, rc_digest)),
                self.assertRaises(LINEAGE.ReleaseError),
            ):
                LINEAGE.verify_m6_exit(root, LINEAGE.M6_EXIT_OUTPUT)
            absent(root, LINEAGE.M6_EXIT_OUTPUT)

    def test_m6_exit_stale_self_and_cross_commit_inputs_are_rejected_without_output(self) -> None:
        rc = {"tag": TAG, "commit": COMMIT}
        self.assert_m6_rejected(self.m6_record(sha("x")), rc, sha("m"))
        self.assert_m6_rejected(self.m6_record(sha("m")), rc, sha("m"), sha("m"))
        self.assert_m6_rejected(self.m6_record(sha("r")), {"tag": TAG, "commit": sha("a")[:40]}, sha("m"))



class RealM7LineageMutationTests(unittest.TestCase):
    release_id = "release-build-20260714"
    m6_exit_digest = sha("f")
    build_digest = sha("8")

    def arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            readiness=LINEAGE.READINESS_OUTPUT,
            rc=LINEAGE.RC_OUTPUT,
            m6_exit=LINEAGE.M6_EXIT_OUTPUT,
            rel_010="Evidence/runtime/REL-010.json",
            phase_05="Evidence/runtime/REL-PHASE-05.json",
            phase_25="Evidence/runtime/REL-PHASE-25.json",
            phase_50="Evidence/runtime/REL-PHASE-50.json",
            phase_100="Evidence/runtime/REL-PHASE-100.json",
            postrelease="Evidence/runtime/REL-014.json",
            contract="Evidence/runtime/REL-CONTRACT.json",
        )

    def transition(self, evidence_id: str, predecessor: str, event: str) -> dict[str, object]:
        state, sequence, switch_state = LINEAGE.TRANSITION_EVIDENCE[evidence_id]
        record: dict[str, object] = {
            "schemaVersion": 1,
            "artifactType": "release-transition-controller",
            "releaseID": self.release_id,
            "state": state,
            "tag": TAG,
            "commit": COMMIT,
            "buildDigest": self.build_digest,
            "switchState": switch_state,
            "expectedSequence": sequence,
            "expectedEventSHA256": predecessor,
            "approvalSHA256": sha("a"),
            "observedInputSHA256": sha("b"),
            "dataSHA256": sha("c"),
            "migrationSHA256": sha("d"),
            "actorSHA256": sha("e"),
            "eventSHA256": event,
            "auditEventId": f"audit-{evidence_id.lower()}",
            "rpcReceiptSHA256": sha("f"),
            "createdAt": "2026-07-14T00:00:00Z",
        }
        if evidence_id in {
            "REL-010",
            "REL-PHASE-05",
            "REL-PHASE-25",
            "REL-PHASE-50",
            "REL-PHASE-100",
            "REL-CONTRACT",
        }:
            record["rcManifestSHA256"] = sha("b")
            record["m6ExitSHA256"] = self.m6_exit_digest
        if evidence_id in {"REL-PHASE-05", "REL-PHASE-25", "REL-PHASE-50", "REL-PHASE-100"}:
            record["phaseFloorSHA256"] = sha("9")
        return record

    def fixture(self, root: Path) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
        paths = {
            "REL-008": "Evidence/runtime/REL-008.json",
            "REL-010": "Evidence/runtime/REL-010.json",
            "REL-PHASE-05": "Evidence/runtime/REL-PHASE-05.json",
            "REL-PHASE-25": "Evidence/runtime/REL-PHASE-25.json",
            "REL-PHASE-50": "Evidence/runtime/REL-PHASE-50.json",
            "REL-PHASE-100": "Evidence/runtime/REL-PHASE-100.json",
            "activation": "Evidence/manifests/observed-activate-1pct.json",
            "REL-014": "Evidence/runtime/REL-014.json",
            "REL-CONTRACT": "Evidence/runtime/REL-CONTRACT.json",
        }
        events = {
            "REL-008": sha("1"),
            "REL-010": sha("2"),
            "REL-PHASE-05": sha("3"),
            "REL-PHASE-25": sha("4"),
            "REL-PHASE-50": sha("5"),
            "REL-PHASE-100": sha("6"),
            "REL-CONTRACT": sha("7"),
        }
        records = {
            "REL-008": self.transition("REL-008", sha("0"), events["REL-008"]),
            "REL-010": self.transition("REL-010", events["REL-008"], events["REL-010"]),
            "REL-PHASE-05": self.transition("REL-PHASE-05", events["REL-010"], events["REL-PHASE-05"]),
            "REL-PHASE-25": self.transition("REL-PHASE-25", events["REL-PHASE-05"], events["REL-PHASE-25"]),
            "REL-PHASE-50": self.transition("REL-PHASE-50", events["REL-PHASE-25"], events["REL-PHASE-50"]),
            "REL-PHASE-100": self.transition("REL-PHASE-100", events["REL-PHASE-50"], events["REL-PHASE-100"]),
            "REL-CONTRACT": self.transition("REL-CONTRACT", events["REL-PHASE-100"], events["REL-CONTRACT"]),
        }
        activation = {
            "schemaVersion": 1,
            "artifactType": "release-transition-observed-input",
            "releaseID": self.release_id,
            "state": "activate-1pct",
            "tag": TAG,
            "commit": COMMIT,
            "buildDigest": self.build_digest,
            "dataSHA256": sha("c"),
            "migrationSHA256": sha("d"),
            "expectedSequence": 3,
            "expectedEventSHA256": events["REL-008"],
            "observedAt": "2026-07-14T00:00:00Z",
            "evidence": [{"id": "M6-EXIT", "sha256": self.m6_exit_digest}],
            "repository": "example/hiker",
            "inputSHA256": sha("9"),
            "workflowRunId": "1",
            "job": "rollout-1pct",
            "sourceDocumentSHA256": sha("a"),
            "sourceSignatureSHA256": sha("b"),
            "sourcePublicKeySHA256": sha("c"),
            "sourceInputSHA256": sha("9"),
            "sourceObservedAt": "2026-07-14T00:00:00Z",
            "sourceObservation": {"status": "passed"},
        }
        records["activation"] = activation
        activation_digest = write_document(root, paths["activation"], activation)
        records["REL-010"]["observedInputSHA256"] = activation_digest

        for evidence_id in (
            "REL-008",
            "REL-010",
            "REL-PHASE-05",
            "REL-PHASE-25",
            "REL-PHASE-50",
            "REL-PHASE-100",
        ):
            write_document(root, paths[evidence_id], records[evidence_id])
        context = RUNTIME.ReleaseEvidenceContext(
            "example/hiker",
            "1",
            TAG,
            COMMIT,
            self.build_digest,
            sha("9"),
            "postrelease-review",
            "production",
        )
        postrelease = RUNTIME.release_record(
            "REL-014",
            context,
            {
                "sourceObservedAt": "2026-07-14T00:00:00Z",
                "observationSHA256": sha("d"),
            },
            {
                "sourceDocumentSHA256": sha("a"),
                "sourceSignatureSHA256": sha("b"),
                "sourcePublicKeySHA256": sha("c"),
                "sourceProducerReceiptSHA256": sha("e"),
                "buildDigestSHA256": self.build_digest,
                "inputSHA256": sha("9"),
            },
            RUNTIME.release_postrelease_predecessor(root, context),
        )
        records["REL-014"] = postrelease
        write_document(root, paths["REL-014"], postrelease)
        write_document(root, paths["REL-CONTRACT"], records["REL-CONTRACT"])
        return records, paths

    def validate(self, root: Path) -> None:
        readiness = {"tag": TAG, "commit": COMMIT}
        rc = {"tag": TAG, "commit": COMMIT, "buildDigest": self.build_digest}
        m6_exit = {"tag": TAG, "commit": COMMIT, "buildDigest": self.build_digest}
        with (
            mock.patch.object(LINEAGE, "repository_root", return_value=root),
            mock.patch.object(LINEAGE, "verify_readiness", return_value=(readiness, sha("a"))),
            mock.patch.object(LINEAGE, "verify_rc", return_value=(rc, sha("b"))),
            mock.patch.object(LINEAGE, "verify_m6_exit", return_value=(m6_exit, self.m6_exit_digest)),
        ):
            LINEAGE.validate_lineage(self.arguments())

    def mutate(
        self,
        root: Path,
        records: dict[str, dict[str, object]],
        paths: dict[str, str],
        mutation: str,
    ) -> None:
        if mutation == "tag":
            records["REL-010"]["tag"] = "v9.9.9"
            write_document(root, paths["REL-010"], records["REL-010"])
        elif mutation == "commit":
            records["REL-PHASE-05"]["commit"] = "b" * 40
            write_document(root, paths["REL-PHASE-05"], records["REL-PHASE-05"])
        elif mutation == "build":
            records["REL-PHASE-25"]["buildDigest"] = sha("f")
            write_document(root, paths["REL-PHASE-25"], records["REL-PHASE-25"])
        elif mutation == "predecessor":
            records["REL-PHASE-25"]["expectedEventSHA256"] = sha("f")
            write_document(root, paths["REL-PHASE-25"], records["REL-PHASE-25"])
        elif mutation == "sequence":
            records["REL-PHASE-50"]["expectedSequence"] = 5
            write_document(root, paths["REL-PHASE-50"], records["REL-PHASE-50"])
        elif mutation == "event-replay":
            records["REL-PHASE-25"]["eventSHA256"] = records["REL-PHASE-25"]["expectedEventSHA256"]
            write_document(root, paths["REL-PHASE-25"], records["REL-PHASE-25"])
        elif mutation == "activation-manifest":
            activation = records["activation"]
            activation["evidence"] = [{"id": "M6-EXIT", "sha256": sha("e")}]
            records["REL-010"]["observedInputSHA256"] = write_document(root, paths["activation"], activation)
            write_document(root, paths["REL-010"], records["REL-010"])
        elif mutation == "rel-014":
            records["REL-014"]["previousArtifactSHA256"] = sha("a")
            write_document(root, paths["REL-014"], records["REL-014"])
        elif mutation == "contract-retention":
            records["REL-CONTRACT"]["expectedEventSHA256"] = records["REL-PHASE-50"]["eventSHA256"]
            write_document(root, paths["REL-CONTRACT"], records["REL-CONTRACT"])
        else:
            raise AssertionError(f"unknown mutation: {mutation}")
    def test_runtime_rel_014_producer_binds_phase_100_for_final_validator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records, paths = self.fixture(root)

            self.assertEqual(
                records["REL-014"]["previousArtifactSHA256"],
                RUNTIME.sha256((root / paths["REL-PHASE-100"]).read_bytes()),
            )
            self.validate(root)

    def test_runtime_rel_014_producer_rejects_missing_wrong_and_cross_build_predecessors(self) -> None:
        context = RUNTIME.ReleaseEvidenceContext(
            "example/hiker",
            "1",
            TAG,
            COMMIT,
            self.build_digest,
            sha("9"),
            "postrelease-review",
            "production",
        )
        path = "Evidence/runtime/REL-PHASE-100.json"
        for case in ("missing", "wrong", "cross-build"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if case != "missing":
                    predecessor = self.transition("REL-PHASE-100", sha("5"), sha("6"))
                    if case == "cross-build":
                        predecessor["buildDigest"] = sha("f")
                    write_document(root, path, predecessor)
                    if case == "wrong":
                        Path(f"{root / path}.sha256").write_bytes(f"{sha('e')}  {path}\n".encode("ascii"))

                before = snapshot(root)
                source = RUNTIME.ReleaseSignedSource("2026-07-14T00:00:00Z", {"review": "complete"}, {})
                with (
                    mock.patch.object(RUNTIME, "require_release_evidence_context", return_value=context),
                    mock.patch.object(RUNTIME, "release_signed_source", return_value=source),
                    mock.patch.object(RUNTIME, "publish_release_record") as publish,
                    self.assertRaises(RUNTIME.EvidenceError),
                ):
                    RUNTIME.run_release_evidence(root, "REL-014")
                publish.assert_not_called()
                self.assertEqual(snapshot(root), before)
                absent(root, "Evidence/runtime/REL-014.json", "Evidence/runtime/REL-014.json.sha256")

    def test_real_m7_validators_reject_compact_lineage_mutation_matrix_without_writes(self) -> None:
        mutations = (
            "tag",
            "commit",
            "build",
            "predecessor",
            "sequence",
            "event-replay",
            "activation-manifest",
            "rel-014",
            "contract-retention",
        )

        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                records, paths = self.fixture(root)
                valid_before = snapshot(root)
                self.validate(root)
                self.assertEqual(snapshot(root), valid_before)

                self.mutate(root, records, paths, mutation)
                before_failure = snapshot(root)
                with self.assertRaises(LINEAGE.ReleaseError):
                    self.validate(root)
                self.assertEqual(snapshot(root), before_failure)


class ExactLineageTests(unittest.TestCase):
    def arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            readiness=LINEAGE.READINESS_OUTPUT,
            rc=LINEAGE.RC_OUTPUT,
            m6_exit=LINEAGE.M6_EXIT_OUTPUT,
            rel_010="Evidence/runtime/REL-010.json",
            phase_05="Evidence/runtime/REL-PHASE-05.json",
            phase_25="Evidence/runtime/REL-PHASE-25.json",
            phase_50="Evidence/runtime/REL-PHASE-50.json",
            phase_100="Evidence/runtime/REL-PHASE-100.json",
            postrelease="Evidence/runtime/REL-014.json",
            contract="Evidence/runtime/REL-CONTRACT.json",
        )

    def records(self, *, wrong_predecessor: bool = False, self_reference: bool = False) -> dict[str, tuple[dict[str, object], str]]:
        event_008 = sha("1")
        event_010 = sha("2")
        event_05 = sha("3")
        event_25 = event_05 if self_reference else sha("4")
        event_50 = sha("5")
        event_100 = sha("6")
        phase_25_predecessor = sha("f") if wrong_predecessor else event_05
        return {
            "REL-008": ({"artifactType": "release-transition-controller", "eventSHA256": event_008, "buildDigest": sha("8")}, sha("8")),
            "REL-010": (
                {
                    "artifactType": "release-transition-controller",
                    "expectedEventSHA256": event_008,
                    "eventSHA256": event_010,
                    "observedInputSHA256": sha("o"),
                    "buildDigest": sha("8"),
                },
                sha("0"),
            ),
            "REL-PHASE-05": (
                {
                    "artifactType": "release-transition-controller",
                    "expectedEventSHA256": event_010,
                    "eventSHA256": event_05,
                    "buildDigest": sha("8"),
                },
                sha("a"),
            ),
            "REL-PHASE-25": (
                {
                    "artifactType": "release-transition-controller",
                    "expectedEventSHA256": phase_25_predecessor,
                    "eventSHA256": event_25,
                    "buildDigest": sha("8"),
                },
                sha("b"),
            ),
            "REL-PHASE-50": (
                {
                    "artifactType": "release-transition-controller",
                    "expectedEventSHA256": event_25,
                    "eventSHA256": event_50,
                    "buildDigest": sha("8"),
                },
                sha("c"),
            ),
            "REL-PHASE-100": (
                {
                    "artifactType": "release-transition-controller",
                    "expectedEventSHA256": event_50,
                    "eventSHA256": event_100,
                    "buildDigest": sha("8"),
                },
                sha("d"),
            ),
            "REL-014": ({"previousArtifactSHA256": sha("d"), "correlation": {"buildDigest": sha("8")}}, sha("e")),
            "REL-CONTRACT": (
                {
                    "artifactType": "release-transition-controller",
                    "expectedEventSHA256": event_100,
                    "eventSHA256": sha("7"),
                    "buildDigest": sha("8"),
                },
                sha("f"),
            ),
        }

    def validate(self, records: dict[str, tuple[dict[str, object], str]]) -> None:
        def passed_record(
            _root: Path,
            _path: str,
            evidence_id: str,
            _commit: str,
            *,
            tag: str | None = None,
        ) -> tuple[dict[str, object], str]:
            self.assertEqual(tag, TAG)
            record, digest = records[evidence_id]
            if record.get("artifactType") == "release-transition-controller":
                record = dict(record)
                record.setdefault("releaseID", "release-build-20260714")
                record.setdefault("tag", TAG)
                record.setdefault("commit", COMMIT)
                record.setdefault("buildDigest", sha("8"))
                record.setdefault("dataSHA256", sha("c"))
                record.setdefault("migrationSHA256", sha("d"))
                if evidence_id in {
                    "REL-010",
                    "REL-PHASE-05",
                    "REL-PHASE-25",
                    "REL-PHASE-50",
                    "REL-PHASE-100",
                    "REL-CONTRACT",
                }:
                    record.setdefault("rcManifestSHA256", sha("c"))
                    record.setdefault("m6ExitSHA256", sha("m"))
                if evidence_id in {"REL-PHASE-05", "REL-PHASE-25", "REL-PHASE-50", "REL-PHASE-100"}:
                    record.setdefault("phaseFloorSHA256", sha("9"))
            return record, digest

        readiness = {"tag": TAG, "commit": COMMIT}
        rc = {"tag": TAG, "commit": COMMIT, "buildDigest": sha("8")}
        m6_exit = {"tag": TAG, "commit": COMMIT, "buildDigest": sha("8")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(LINEAGE, "repository_root", return_value=root),
                mock.patch.object(LINEAGE, "verify_readiness", return_value=(readiness, sha("r"))),
                mock.patch.object(LINEAGE, "verify_rc", return_value=(rc, sha("c"))),
                mock.patch.object(LINEAGE, "verify_m6_exit", return_value=(m6_exit, sha("m"))),
                mock.patch.object(LINEAGE, "verify_passed_record", side_effect=passed_record),
                mock.patch.object(LINEAGE, "verify_activate_observed_manifest"),
            ):
                LINEAGE.validate_lineage(self.arguments())
            absent(root, LINEAGE.READINESS_OUTPUT, LINEAGE.RC_OUTPUT, LINEAGE.M6_EXIT_OUTPUT)

    def test_lineage_accepts_the_exact_predecessor_chain(self) -> None:
        self.validate(self.records())

    def test_lineage_rejects_wrong_immediate_predecessor(self) -> None:
        with self.assertRaises(LINEAGE.ReleaseError):
            self.validate(self.records(wrong_predecessor=True))

    def test_lineage_rejects_self_referential_phase(self) -> None:
        with self.assertRaises(LINEAGE.ReleaseError):
            self.validate(self.records(self_reference=True))


if __name__ == "__main__":
    unittest.main()
