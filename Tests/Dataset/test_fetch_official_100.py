#!/usr/bin/env python3
"""Regression coverage for the official 100-mountain dataset fetcher."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "Scripts" / "dataset" / "fetch-official-100.py"
)
SPEC = importlib.util.spec_from_file_location("fetch_official_100_under_test", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not import dataset fetcher from {SCRIPT_PATH}")
FETCHER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FETCHER
SPEC.loader.exec_module(FETCHER)

RETRIEVED_AT = "2026-07-14T00:00:00Z"


def make_feature(official_id: int, elevation: str) -> dict[str, object]:
    return {
        "fieldNames": list(FETCHER.EXPECTED_FIELDS),
        "fieldValues": [
            official_id,
            f"user-{official_id}",
            "POINT",
            official_id,
            str(official_id),
            f"Mountain {official_id}",
            elevation,
            f"photo-{official_id}",
            f"{official_id:08d}",
            f"District {official_id}",
        ],
        "geometry": {"points": [{"x": 127.0, "y": 37.0}]},
    }


def make_payload(first_elevation: str = "1234.5") -> bytes:
    features = [
        make_feature(
            official_id,
            first_elevation if official_id == 1 else "1000.0",
        )
        for official_id in range(1, 101)
    ]
    return json.dumps(
        {"featureCount": 100, "features": features},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


class FetchOfficial100Tests(unittest.TestCase):
    def test_exact_elevation_normalizes_to_float(self) -> None:
        normalized = FETCHER.normalize(make_payload("1234.5"), RETRIEVED_AT)

        elevation = normalized["records"][0]["elevationMeters"]
        self.assertIs(type(elevation), float)
        self.assertEqual(elevation, 1234.5)

    def test_precision_losing_elevation_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"feature 1 elevation cannot be represented exactly",
        ):
            FETCHER.normalize(make_payload("9007199254740993"), RETRIEVED_AT)

    def test_main_preserves_existing_outputs_when_normalization_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            raw_output = directory / "official.raw.json"
            normalized_output = directory / "official.json"
            previous_raw = b"previous raw bytes\n"
            previous_normalized = b"previous normalized bytes\n"
            raw_output.write_bytes(previous_raw)
            normalized_output.write_bytes(previous_normalized)
            arguments = argparse.Namespace(
                output=normalized_output,
                raw_output=raw_output,
                retrieved_at=RETRIEVED_AT,
                timeout=1.0,
            )

            with (
                mock.patch.object(FETCHER, "parse_args", return_value=arguments),
                mock.patch.object(
                    FETCHER,
                    "fetch",
                    return_value=make_payload("9007199254740993"),
                ),
                self.assertRaisesRegex(
                    ValueError,
                    r"feature 1 elevation cannot be represented exactly",
                ),
            ):
                FETCHER.main()

            self.assertEqual(raw_output.read_bytes(), previous_raw)
            self.assertEqual(normalized_output.read_bytes(), previous_normalized)

    def test_second_publish_failure_restores_both_previous_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            raw_output = directory / "official.raw.json"
            normalized_output = directory / "official.json"
            previous_raw = b"previous raw bytes\n"
            previous_normalized = b"previous normalized bytes\n"
            raw_output.write_bytes(previous_raw)
            normalized_output.write_bytes(previous_normalized)
            raw_staged = FETCHER.stage_bytes(raw_output, b"new raw bytes\n")
            normalized_staged = FETCHER.stage_bytes(
                normalized_output,
                b"new normalized bytes\n",
            )
            real_replace = os.replace

            def fail_normalized_publish(source: object, destination: object) -> None:
                if (
                    Path(source) == normalized_staged
                    and Path(destination) == normalized_output
                ):
                    raise OSError("injected second publish failure")
                real_replace(source, destination)

            with (
                mock.patch.object(FETCHER.os, "replace", side_effect=fail_normalized_publish),
                self.assertRaisesRegex(OSError, "injected second publish failure"),
            ):
                FETCHER.publish_generation(
                    raw_output,
                    raw_staged,
                    normalized_output,
                    normalized_staged,
                )

            self.assertEqual(raw_output.read_bytes(), previous_raw)
            self.assertEqual(normalized_output.read_bytes(), previous_normalized)
            self.assertFalse(raw_staged.exists())
            self.assertFalse(normalized_staged.exists())

    def test_successful_paired_publish_replaces_both_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            raw_output = directory / "official.raw.json"
            normalized_output = directory / "official.json"
            raw_output.write_bytes(b"previous raw bytes\n")
            normalized_output.write_bytes(b"previous normalized bytes\n")
            next_raw = b"new raw bytes\n"
            next_normalized = b"new normalized bytes\n"
            raw_staged = FETCHER.stage_bytes(raw_output, next_raw)
            normalized_staged = FETCHER.stage_bytes(normalized_output, next_normalized)

            FETCHER.publish_generation(
                raw_output,
                raw_staged,
                normalized_output,
                normalized_staged,
            )

            self.assertEqual(raw_output.read_bytes(), next_raw)
            self.assertEqual(normalized_output.read_bytes(), next_normalized)
            self.assertFalse(raw_staged.exists())
            self.assertFalse(normalized_staged.exists())


if __name__ == "__main__":
    unittest.main()
